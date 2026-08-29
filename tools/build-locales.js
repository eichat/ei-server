#!/usr/bin/env node
/**
 * Генерує locales/<мова>.json із єдиного джерела locales-source.json.
 *
 * Навіщо джерело окремо: правити 21 файл руками означає щоразу звіряти набори
 * ключів і легко забути мову. У джерелі всі переклади ключа лежать поруч, тож
 * пропуск видно одразу.
 *
 * Навіщо роздача все одно по файлах: застосунок тягне переклади з GitHub при
 * старті й бере ЛИШЕ свою мову (~45 КБ). Один спільний файл означав би ~900 КБ
 * на кожен запуск.
 *
 * Запуск:  node tools/build-locales.js         — згенерувати
 *          node tools/build-locales.js --check — лише перевірити, нічого не писати
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SRC = path.join(ROOT, 'locales-source.json');
const OUT = path.join(ROOT, 'locales');
const checkOnly = process.argv.includes('--check');

const src = JSON.parse(fs.readFileSync(SRC, 'utf8'));
const langs = src.langs;
const strings = src.strings;
const keys = Object.keys(strings);

// ── Перевірки, які раніше робились руками ────────────────────────────────
const problems = [];
const ph = (s) => (String(s).match(/{(\w+)}/g) || []).sort().join(',');

for (const k of keys) {
  const row = strings[k];
  for (const l of langs) {
    if (typeof row[l] !== 'string' || row[l].trim() === '') {
      problems.push(`${k}: немає перекладу для «${l}»`);
    }
  }
  // Плейсхолдери {name} мають збігатися з англійською: інакше підстановка
  // мовчки не спрацює саме тією мовою, і користувач побачить «{nick}».
  const base = ph(row.en);
  for (const l of langs) {
    if (l !== 'en' && typeof row[l] === 'string' && ph(row[l]) !== base) {
      problems.push(`${k} [${l}]: плейсхолдери «${ph(row[l]) || '—'}» ≠ «${base || '—'}»`);
    }
  }
}

if (problems.length) {
  console.error(`✗ знайдено ${problems.length} проблем:`);
  for (const p of problems.slice(0, 30)) console.error('   ' + p);
  if (problems.length > 30) console.error(`   … ще ${problems.length - 30}`);
  process.exit(1);
}
console.log(`✓ перевірка пройдена: ${keys.length} ключів × ${langs.length} мов`);

if (checkOnly) process.exit(0);

for (const l of langs) {
  const out = {};
  for (const k of keys) out[k] = strings[k][l];
  fs.writeFileSync(path.join(OUT, `${l}.json`), JSON.stringify(out, null, 2) + '\n');
}
console.log(`✓ згенеровано ${langs.length} файлів у locales/`);
