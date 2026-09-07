// Офлайн-перевірка UGC-логіки ПРОТИ БОЙОВОГО КОДУ: функції витягуються з
// server.js, а не переписуються тут — інакше тест пройшов би й з помилкою в
// сервері (урок e2ee-тестів).
import fs from 'fs';

const src = fs.readFileSync(process.env.EION_SERVER || new URL('../server.js', import.meta.url).pathname, 'utf8');

function extract(name, kind = 'function') {
  const start = src.indexOf(`${kind} ${name}(`);
  if (start === -1) throw new Error(`не знайшов ${name}`);
  let i = src.indexOf('{', start), depth = 0;
  for (let j = i; j < src.length; j++) {
    if (src[j] === '{') depth++;
    else if (src[j] === '}') { depth--; if (depth === 0) return src.slice(start, j + 1); }
  }
  throw new Error(`не закрився ${name}`);
}

// Бойові функції.
const TITLE_MAX = /const UGC_PACK_TITLE_MAX = (\d+)/.exec(src)[1];
const code = [
  `const UGC_PACK_TITLE_MAX = ${TITLE_MAX};`,
  extract('storagePathFromUrl'), extract('ugcCleanTitle'),
].join('\n');
const mod = new Function(`${code}; return { storagePathFromUrl, ugcCleanTitle };`)();
const { storagePathFromUrl, ugcCleanTitle } = mod;

// Бойові константи (читаємо з файлу, щоб тест не розійшовся зі сервером).
const SHARE = Number(/const UGC_AUTHOR_SHARE_PCT = (\d+)/.exec(src)[1]);
const PRICES = JSON.parse(/const UGC_PACK_PRICES = (\[[^\]]+\])/.exec(src)[1]);

// Умова володіння — дослівно та сама, що в /stickers/pack/submit.
const ownCheck = /if \(!path \|\| !path\.startsWith\(`stickers\/\$\{nick\}\/`\) \|\| path\.split\('\/'\)\.includes\('\.\.'\)\)/.test(src);
if (!ownCheck) throw new Error('перевірка володіння в submit змінилась — тест застарів');
const owns = (url, nick) => {
  const path = storagePathFromUrl(url);
  return !(!path || !path.startsWith(`stickers/${nick}/`) || path.split('/').includes('..'));
};

let fail = 0;
const eq = (name, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) { fail++; console.log(`✗ ${name}: ${JSON.stringify(got)} != ${JSON.stringify(want)}`); }
  else console.log(`✓ ${name}`);
};

const S = 'https://x.supabase.co/storage/v1/object/sign/files/';
const P = 'https://x.supabase.co/storage/v1/object/public/files/';

// ── Володіння ────────────────────────────────────────────────────────────
eq('своя наліпка', owns(`${S}stickers/void/1.png?token=abc`, 'void'), true);
eq('своя, публічний URL', owns(`${P}stickers/void/1.png`, 'void'), true);
eq('своя, реф eion://', owns('eion://files/stickers/void/1.png', 'void'), true);
eq('чужа наліпка', owns(`${S}stickers/Rumpel/1.png`, 'void'), false);
eq('нік — префікс чужого (void vs void2)', owns(`${S}stickers/void2/1.png`, 'void'), false);
eq('обхід через ..', owns(`${S}stickers/void/../Rumpel/1.png`, 'void'), false);
eq('обхід через %2E%2E', owns(`${S}stickers/void/%2E%2E/Rumpel/1.png`, 'void'), false);
eq('не наліпка, а фото з чату', owns(`${S}direct/void/123/photo.png`, 'void'), false);
eq('чужий хост', owns('https://evil.example/stickers/void/1.png', 'void'), false);
eq('порожньо', owns('', 'void'), false);

// ── Назва набору ─────────────────────────────────────────────────────────
eq('звичайна назва', ugcCleanTitle('  Мої коти  '), 'Мої коти');
eq('одна літера — відмова', ugcCleanTitle('к'), null);
eq('порожня — відмова', ugcCleanTitle('   '), null);
eq('41 символ — відмова', ugcCleanTitle('x'.repeat(41)), null);
eq('40 символів — межа проходить', ugcCleanTitle('x'.repeat(40)), 'x'.repeat(40));
eq('керівні символи вирізаються', ugcCleanTitle('Ко\u0000ти\u001b'), 'Коти');
eq('лише керівні — відмова', ugcCleanTitle('\u0000\u0001'), null);
eq('емодзі лишається', ugcCleanTitle('Коти 🐱'), 'Коти 🐱');

// ── Розподіл 70/30 на всій сітці цін ─────────────────────────────────────
for (const price of PRICES.filter(p => p > 0)) {
  const author = Math.floor(price * SHARE / 100);
  const company = price - author;
  eq(`розподіл ${price} → автор ${author} + платформа ${company}`,
     [author + company, author >= company], [price, true]);
}
eq('безкоштовний не ділиться', PRICES.includes(0), true);

// ── Кроп наліпки: межі ───────────────────────────────────────────────────
// Мапер лежить усередині endpoint, тож звіряємо, що код не змінився, і
// перевіряємо ту саму формулу на межових значеннях.
const cropGuard = /scale: Math\.min\(4, Math\.max\(1, num\(it\.cropScale, 1\)\)\)/.test(src)
  && /dx: Math\.min\(1, Math\.max\(-1, num\(it\.cropDx, 0\)\)\)/.test(src);
if (!cropGuard) throw new Error('обмеження кропу в submit змінились — тест застарів');
const num = (v, def) => (Number.isFinite(Number(v)) ? Number(v) : def);
const clampScale = v => Math.min(4, Math.max(1, num(v, 1)));
const clampShift = v => Math.min(1, Math.max(-1, num(v, 0)));

eq('масштаб у межах', clampScale(2.5), 2.5);
eq('масштаб нижче 1 підтягується', clampScale(0.1), 1);
eq('масштаб вище 4 обрізається', clampScale(99), 4);
eq('масштаб не число → 1', clampScale('abc'), 1);
eq('масштаб NaN → 1', clampScale(NaN), 1);
eq('зсув у межах', clampShift(-0.3), -0.3);
eq('зсув поза межами обрізається', [clampShift(50), clampShift(-50)], [1, -1]);
eq('зсув не число → 0', clampShift(null), 0);

console.log(fail === 0 ? '\nУСІ ПРОЙШЛИ' : `\nПРОВАЛЕНО: ${fail}`);
process.exit(fail === 0 ? 0 : 1);
