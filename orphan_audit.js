// orphan_audit.js — РАЗОВИЙ аудит осиротілих файлів у Supabase Storage (бакет 'files').
// ─────────────────────────────────────────────────────────────────────────────
// Знаходить файли, на які НЕ посилається жоден рядок у БД (залишки старого бага),
// і (за бажанням) видаляє їх. НЕ чіпає файли, на які є посилання.
//
// БЕЗПЕКА:
//   • DRY_RUN за замовчуванням = true → лише друкує список орфанів і обсяг, НІЧОГО не видаляє.
//   • Збирає посилання з УСІХ таблиць (messages, group_messages, channel_messages,
//     channel_comments) і сканує ВСІ текстові поля кожного рядка — щоб не проґавити
//     жодну колонку (file_data, image_url, reply_to_image тощо).
//   • Якщо будь-яка таблиця дала помилку читання → видалення ЗАБОРОНЕНО (бо неповний
//     набір посилань = ризик стерти живий файл).
//
// ЗАПУСК (Render Job / Shell на сервері — env SUPABASE_URL і SUPABASE_KEY вже є):
//   node orphan_audit.js                     # DRY-RUN: показати, що знайшло
//   AUDIT_DRY_RUN=false node orphan_audit.js # реальне видалення (після перегляду списку!)
// ─────────────────────────────────────────────────────────────────────────────

const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const BUCKET = 'files';
const DRY_RUN = (process.env.AUDIT_DRY_RUN || 'true') !== 'false';
const MARKER = '/object/public/files/';

// Таблиці, що можуть посилатися на файли в бакеті.
const TABLES = ['messages', 'group_messages', 'channel_messages', 'channel_comments'];
// Відомі префікси storage-шляхів (на випадок, якщо десь зберігається "голий" шлях без повного URL).
const PATH_PREFIXES = ['direct/', 'group/', 'channel/', 'channels/'];

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('[audit] Потрібні env-змінні SUPABASE_URL і SUPABASE_KEY'); process.exit(1);
}
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// З рядка дістає decoded storage-шлях: або з повного публічного URL (через MARKER),
// або якщо рядок САМ є шляхом із відомим префіксом.
function pathFromValue(val) {
  if (!val || typeof val !== 'string') return null;
  const i = val.indexOf(MARKER);
  if (i !== -1) {
    const tail = val.slice(i + MARKER.length).split('?')[0];
    try { return decodeURIComponent(tail); } catch (_) { return tail; }
  }
  const trimmed = val.trim();
  if (PATH_PREFIXES.some(p => trimmed.startsWith(p))) {
    try { return decodeURIComponent(trimmed.split('?')[0]); } catch (_) { return trimmed.split('?')[0]; }
  }
  return null;
}

// Збирає множину всіх шляхів, на які є посилання. Повертає {refs, hadError}.
async function collectReferencedPaths() {
  const refs = new Set();
  let hadError = false;
  for (const table of TABLES) {
    let from = 0; const page = 1000;
    while (true) {
      const { data, error } = await supabase.from(table).select('*').range(from, from + page - 1);
      if (error) {
        console.error(`[audit] ПОМИЛКА читання ${table}: ${error.message}`);
        hadError = true;
        break;
      }
      if (!data || !data.length) break;
      for (const row of data) {
        for (const v of Object.values(row)) {
          const p = pathFromValue(v);
          if (p) refs.add(p);
        }
      }
      if (data.length < page) break;
      from += page;
    }
  }
  return { refs, hadError };
}

// Рекурсивний обхід бакета (Supabase list НЕ рекурсивний → обходимо теки вручну).
async function walk(prefix, out) {
  let offset = 0; const limit = 100;
  while (true) {
    const { data, error } = await supabase.storage.from(BUCKET)
      .list(prefix, { limit, offset, sortBy: { column: 'name', order: 'asc' } });
    if (error) { console.error(`[audit] list "${prefix}": ${error.message}`); break; }
    if (!data || !data.length) break;
    for (const item of data) {
      const full = prefix ? `${prefix}/${item.name}` : item.name;
      const isFolder = item.id === null && !item.metadata; // теки не мають id/metadata
      if (isFolder) {
        await walk(full, out);
      } else {
        out.push({ path: full, size: (item.metadata && item.metadata.size) || 0 });
      }
    }
    if (data.length < limit) break;
    offset += limit;
  }
}

function human(bytes) {
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; let n = bytes;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(1)}${u[i]}`;
}

(async () => {
  console.log(`[audit] режим: ${DRY_RUN ? 'DRY-RUN (нічого не видаляється)' : 'РЕАЛЬНЕ ВИДАЛЕННЯ'}`);

  console.log('[audit] збираю посилання з усіх таблиць...');
  const { refs, hadError } = await collectReferencedPaths();
  console.log(`[audit] унікальних посилань на файли: ${refs.size}`);

  console.log('[audit] обходжу бакет files...');
  const files = [];
  await walk('', files);
  console.log(`[audit] усього файлів у Storage: ${files.length}`);

  const orphans = files.filter(f => !refs.has(f.path));
  const totalOrphanSize = orphans.reduce((s, f) => s + (f.size || 0), 0);
  console.log(`[audit] ───────────────────────────────────────────`);
  console.log(`[audit] ОРФАНІВ (без посилань): ${orphans.length}, обсяг ≈ ${human(totalOrphanSize)}`);
  console.log(`[audit] ───────────────────────────────────────────`);
  for (const o of orphans) console.log(`  orphan: ${o.path} (${human(o.size || 0)})`);

  // Запобіжник: якщо читання таблиць було неповним — НЕ видаляємо.
  if (hadError) {
    console.error('[audit] ⚠ Були помилки читання таблиць → набір посилань НЕПОВНИЙ.');
    console.error('[audit] ⚠ Видалення СКАСОВАНО, щоб не стерти живі файли. Виправ доступ і повтори.');
    return;
  }

  if (DRY_RUN) {
    console.log('[audit] DRY-RUN — нічого не видалено.');
    console.log('[audit] Переглянь список вище. Якщо все коректно (немає живих файлів каналів/чатів),');
    console.log('[audit] запусти реальне видалення: AUDIT_DRY_RUN=false node orphan_audit.js');
    return;
  }

  if (!orphans.length) { console.log('[audit] Орфанів немає — нічого видаляти.'); return; }

  // Реальне видалення пачками по 100.
  let removed = 0;
  for (let i = 0; i < orphans.length; i += 100) {
    const batch = orphans.slice(i, i + 100).map(o => o.path);
    const { error } = await supabase.storage.from(BUCKET).remove(batch);
    if (error) { console.error(`[audit] remove error: ${error.message}`); continue; }
    removed += batch.length;
    console.log(`[audit] видалено ${removed}/${orphans.length}`);
  }
  console.log(`[audit] ГОТОВО. Видалено ${removed} орфанів, звільнено ≈ ${human(totalOrphanSize)}`);
})();
