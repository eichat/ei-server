#!/usr/bin/env node
/**
 * Завантажити пак наліпок у магазин — без нової збірки застосунку.
 *
 *   node tools/upload-sticker-pack.js <тека> --id=cats --title="Коти" --price=200
 *
 * Тека має містити файли наліпок:
 *   *.json          — Lottie (анімовані, як наявні tech01 / bee)
 *   *.webp *.png    — растрові
 * Ім'я файла стає stickerId; порядок — за іменем.
 *
 * Секрет береться з ~/.eion-admin-secret (або env EION_ADMIN_SECRET).
 */
const fs = require('fs');
const path = require('path');
const os = require('os');

const args = process.argv.slice(2);
const dir = args.find(a => !a.startsWith('--'));
const opt = (name, def) => {
  const a = args.find(x => x.startsWith(`--${name}=`));
  return a ? a.slice(name.length + 3) : def;
};

if (!dir) {
  console.error('Вкажи теку з наліпками. Приклад:\n  node tools/upload-sticker-pack.js ~/стікери/коти --id=cats --title="Коти" --price=200');
  process.exit(1);
}

const id = opt('id');
const title = opt('title');
const price = Number(opt('price', '0'));
const sortOrder = Number(opt('sort', '0'));
const server = opt('server', 'https://ei-server.onrender.com');
if (!id || !title) { console.error('Потрібні --id і --title'); process.exit(1); }

let secret = process.env.EION_ADMIN_SECRET;
if (!secret) {
  try { secret = fs.readFileSync(path.join(os.homedir(), '.eion-admin-secret'), 'utf8').trim(); } catch {}
}
if (!secret) { console.error('Немає секрету: створи ~/.eion-admin-secret або задай EION_ADMIN_SECRET'); process.exit(1); }

const KINDS = { '.json': ['lottie', 'json'], '.webp': ['image', 'webp'], '.png': ['image', 'png'] };
const files = fs.readdirSync(dir)
  .filter(f => KINDS[path.extname(f).toLowerCase()])
  .sort();

if (!files.length) { console.error('У теці немає .json / .webp / .png'); process.exit(1); }

const items = files.map(f => {
  const [kind, ext] = KINDS[path.extname(f).toLowerCase()];
  const buf = fs.readFileSync(path.join(dir, f));
  return { stickerId: path.basename(f, path.extname(f)), kind, ext, dataBase64: buf.toString('base64'), _size: buf.length };
});

const total = items.reduce((s, i) => s + i._size, 0);
console.log(`пак «${title}» (${id}): ${items.length} наліпок, ${Math.round(total / 1024)} КБ`);
for (const i of items) console.log(`   ${i.stickerId.padEnd(16)} ${i.kind.padEnd(7)} ${String(Math.round(i._size / 1024)).padStart(4)} КБ`);
if (total > 3.5 * 1024 * 1024) {
  console.error('\n✗ Разом понад 3,5 МБ — сервер приймає тіло до 4 МБ. Розбий на два паки або стисни файли.');
  process.exit(1);
}

(async () => {
  const res = await fetch(`${server}/admin/sticker-pack`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Admin-Secret': secret },
    body: JSON.stringify({
      id, title, price, sortOrder,
      previewSticker: items[0].stickerId,
      items: items.map(({ stickerId, kind, ext, dataBase64 }) => ({ stickerId, kind, ext, dataBase64 })),
    }),
  });
  const data = await res.json().catch(() => ({}));
  if (data.ok) {
    console.log(`\n✓ Готово: пак «${id}» у магазині, ${data.items} наліпок, ціна ${price}`);
    console.log('  Застосунок підхопить його при наступному відкритті магазину — без оновлення.');
  } else {
    console.error(`\n✗ ${data.error || res.status}`);
    process.exit(1);
  }
})();
