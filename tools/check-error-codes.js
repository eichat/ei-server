#!/usr/bin/env node
// Звіряє коди помилок сервера з локалями.
//
// Ловить дві вади, які видно лише іншою мовою — тобто ніколи при звичайному тесті:
//
//   1. Сервер шле `code`, якого немає в локалях. Клієнт не ламається
//      (`eServerError` бачить, що `t(code)` повернув сам ключ, і відкочується на
//      текст), але текст той — український, і його побачать усі 21 мова.
//
//   2. Ключ під кодом МІСТИТЬ плейсхолдер `{n}`. `eServerError` кличе `t(code)`
//      БЕЗ аргументів, тож користувач побачив би дужки буквально:
//      «Недостатньо монет (потрібно {n} EION)». Це гірше за українську.
//      Виняток — коди зі списку ARGS_CODES: для них клієнт явно передає
//      `args` у місці виклику. Список тримається тут, бо клієнт лежить в
//      іншому репозиторії й CI його не бачить: додаючи сюди код, треба
//      ОДРАЗУ дописати args на клієнті, інакше дужки покажуться буквально.
//
// Запуск: node tools/check-error-codes.js

const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..');

const server = fs.readFileSync(path.join(root, 'server.js'), 'utf8');
const strings = JSON.parse(fs.readFileSync(path.join(root, 'locales-source.json'), 'utf8')).strings;

const codes = [...new Set([...server.matchAll(/code\s*:\s*['"]([a-z0-9_]+)['"]/g)].map(m => m[1]))].sort();

// Коди, ключ яких МАЄ плейсхолдер, і клієнт для них передає args:
//   err_user_offline      → live_chat, case 'error'  ({nick})
//   err_kick_banned_reason → live_chat, case 'kicked' ({reason})
const ARGS_CODES = ['err_user_offline', 'err_kick_banned_reason'];

const missing = codes.filter(c => !strings[c]);
const withPlaceholder = codes.filter(c =>
  !ARGS_CODES.includes(c) && strings[c] && /\{[a-z_]+\}/i.test(strings[c].uk || ''));
const staleArgs = ARGS_CODES.filter(c => !strings[c] || !/\{[a-z_]+\}/i.test(strings[c].uk || ''));

let bad = false;
if (missing.length) {
  bad = true;
  console.error(`✗ коди без ключа в локалях (${missing.length}) — покажуть українську всім мовам:`);
  for (const c of missing) console.error(`    ${c}`);
}
if (withPlaceholder.length) {
  bad = true;
  console.error(`✗ ключі з плейсхолдером під кодом (${withPlaceholder.length}) — дужки покажуться буквально:`);
  for (const c of withPlaceholder) console.error(`    ${c} → ${strings[c].uk}`);
}
if (staleArgs.length) {
  bad = true;
  console.error(`✗ ARGS_CODES без плейсхолдера в ключі (${staleArgs.length}) — прибери зі списку:`);
  for (const c of staleArgs) console.error(`    ${c}`);
}
if (bad) process.exit(1);

const unused = Object.keys(strings).filter(k => k.startsWith('err_') && !codes.includes(k));
console.log(`✓ ${codes.length} кодів помилок, усі мають ключ і жоден не з плейсхолдером`);
if (unused.length) console.log(`  ℹ️ err_* ключів без коду в сервері: ${unused.length} (${unused.join(', ')})`);
