// Офлайн-перевірка buildAccountExport: функція береться З БОЙОВОГО server.js,
// а не переписується в тесті — інакше тест проходив би й зі зламаним кодом.
import fs from 'node:fs';
import assert from 'node:assert';

const src = fs.readFileSync(process.env.SERVER_JS || new URL('../server.js', import.meta.url), 'utf-8');
const start = src.indexOf('async function buildAccountExport(nick) {');
assert.ok(start > 0, 'функцію не знайдено');
// кінець — за балансом фігурних дужок (простий скан, рядків/коментарів у тілі
// з незбалансованими дужками там немає — перевіряється тим, що код виконується)
let depth = 0, end = -1;
for (let i = src.indexOf('{', start); i < src.length; i++) {
  if (src[i] === '{') depth++;
  else if (src[i] === '}') { depth--; if (depth === 0) { end = i + 1; break; } }
}
const body = src.slice(start, end);

// ── підставні дані ───────────────────────────────────────────────────────────
let TABLES = {};
let FAIL = new Set();
const chain = (table, cols) => {
  const q = {
    _col: null, _val: null,
    eq(col, val) { this._col = col; this._val = val; return this; },
    limit(n) { return this._run(n); },
    single() { return this._run(1).then(r => ({ data: r.data[0] || null, error: r.error })); },
    _run(n) {
      if (FAIL.has(table)) return Promise.resolve({ data: null, error: { message: 'boom' } });
      let rows = (TABLES[table] || []).filter(r => r[this._col] === this._val).slice(0, n);
      // Заглушка ПОВАЖАЄ перелік колонок — інакше перевірка «секрети не
      // потрапили в архів» була б фікцією: вона проходила б і з select('*').
      if (cols && cols.trim() !== '*') {
        const want = cols.split(',').map(c => c.trim()).filter(Boolean);
        rows = rows.map(r => Object.fromEntries(want.filter(k => k in r).map(k => [k, r[k]])));
      }
      return Promise.resolve({ data: rows, error: null });
    },
    then(res, rej) { return this._run(100000).then(res, rej); },
  };
  return q;
};
const supabase = { from: (t) => ({ select: (cols) => chain(t, cols) }) };
const errorsSeen = [];
// константи теж беремо з server.js — тест має перевіряти бойові числа
const consts = src.match(/const EXPORT_ROW_LIMIT = \d+;/)[0];
const run = new Function('supabase', `${consts}\n${body}; return buildAccountExport;`)(supabase);

// ── випадок 1: профіль без секретів, дедуп, encrypted ────────────────────────
TABLES = {
  users: [{ nick: 'ann', coins: 10, password_hash: 'SECRET-HASH', fcm_token: 'SECRET-FCM' }],
  messages: [
    { id: 1, from_nick: 'ann', to_nick: 'ann', content: 'нотатка собі', timestamp: 3 },
    { id: 2, from_nick: 'bob', to_nick: 'ann', content: '[e2e1]abc.def', timestamp: 1 },
    { id: 3, from_nick: 'ann', to_nick: 'bob', content: 'привіт', timestamp: 2,
      reply_to_msg_id: 'm9', reply_to_from: 'bob', reply_to_text: '[e2e1]xyz' },
  ],
  group_messages: [
    { id: 7, from_nick: 'ann', content: 'моє в групі' },
    { id: 8, from_nick: 'bob', content: 'чуже в групі' },
  ],
};
let out = await run('ann');

const profileJson = JSON.stringify(out.profile);
assert.ok(!profileJson.includes('SECRET-HASH'), '🔴 password_hash потрапив в архів');
assert.ok(!profileJson.includes('SECRET-FCM'), '🔴 fcm_token потрапив в архів');
console.log('✓ профіль без password_hash і fcm_token');

assert.strictEqual(out.messages.direct.length, 3, 'нотатка собі задвоїлась при дедупі');
console.log('✓ дедуп: повідомлення собі не задвоюється');

const ts = out.messages.direct.map(m => m.timestamp);
assert.deepStrictEqual(ts, [1, 2, 3], 'не відсортовано за часом');
console.log('✓ відсортовано за часом');

const sealed = out.messages.direct.find(m => m.id === 2);
const plain = out.messages.direct.find(m => m.id === 3);
assert.strictEqual(sealed.encrypted, true, 'конверт [e2e1] не позначено encrypted');
assert.strictEqual(plain.encrypted, false, 'відкритий текст позначено encrypted');
assert.strictEqual(plain.reply_to.encrypted, true, 'зашифрована цитата не позначена');
console.log('✓ encrypted проставляється і в тілі, і в цитаті');

assert.strictEqual(out.messages.group_own.length, 1, 'у групових потрапило чуже');
assert.strictEqual(out.messages.group_own[0].from_nick, 'ann');
console.log('✓ групові — лише власні');

// ── випадок 2: ліміт рядків ─────────────────────────────────────────────────
TABLES = { users: [{ nick: 'ann' }], messages: [] };
for (let i = 0; i < 5001; i++) TABLES.messages.push({ id: i, from_nick: 'ann', to_nick: 'bob', timestamp: i });
out = await run('ann');
assert.strictEqual(out.messages.direct.length, 5000, `обрізано до ${out.messages.direct.length}, очікували 5000`);
assert.ok(out.limits.truncated.includes('messages.from_nick'), 'обрізання не позначене');
console.log('✓ ліміт 5000 рядків + позначка truncated');

// ── випадок 3: збій запиту не валить експорт ────────────────────────────────
TABLES = { users: [{ nick: 'ann' }], messages: [{ id: 1, from_nick: 'ann', timestamp: 1 }] };
FAIL = new Set(['coin_transactions']);
out = await run('ann');
assert.ok(out.errors.some(e => e.includes('coin_transactions')), 'збій не потрапив у errors');
assert.strictEqual(out.messages.direct.length, 1, 'решта даних загубилась через один збій');
console.log('✓ збій однієї таблиці не валить архів, іде в errors');

console.log('\nусі перевірки пройдено');
