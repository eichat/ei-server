-- ═══════════════════════════════════════════════════════════════════
--  Аудит безпеки — закрити file_objects (і три хвости того ж класу)
--
--  Знайдено 26.08.2026 при звірці SETUP.sql. Продовження #11
--  (revoke_anon_grants.sql, 28.07) — тоді закрили чотири таблиці,
--  але ті, що з'явились пізніше, успадкували стару інструкцію
--  «GRANT ALL … TO postgres, anon, authenticated, service_role».
--
--  Виконати в Supabase → SQL Editor. Прод це не зачіпає: сервер
--  ходить secret-ключем (service_role), який обходить і гранти
--  anon, і RLS. Перевірено grep'ом по ~/ei/lib — клієнт у ці
--  таблиці НЕ звертається напряму (єдина пряма таблиця клієнта —
--  users, і вона для anon уже закрита).
-- ═══════════════════════════════════════════════════════════════════

-- ─── 1. ГОЛОВНЕ: file_objects ──────────────────────────────────────
-- Єдина таблиця з комбінацією «RLS ВИМКНЕНО + anon має повний CRUD»:
--   alter table public.file_objects disable row level security;
--   grant delete, insert, ... , select, ... , update ... to anon;
-- Вміст: storage_path, recipients, downloaded_by, expires_at.
--
-- Чим це небезпечно: Фаза 2.1 (28.07) закривала саме ПЕРЕЛІК файлів —
-- прибрали SELECT-політики Storage, щоб anon не витягав структуру
-- direct/<нік>/… . Але ті самі шляхи лежать тут, у звичайній таблиці,
-- і anon-ключ (він у APK, тобто доступний кожному) читав її напряму.
-- Тобто перелік файлів лишався відкритим через інші двері.
-- Додатково: запис у downloaded_by прискорює чистку чужих файлів
-- (механізм removeOrphanFile, аудит #19).
alter table public.file_objects enable row level security;
revoke all on table public.file_objects from anon, authenticated;

-- ─── 2. Хвости: гранти є, але RLS уже прикриває ────────────────────
-- Тут RLS увімкнено й політик немає (== доступ заборонено), тож
-- діри не було. Прибираємо гранти, щоб захист не тримався на одному
-- шарі: якщо колись до такої таблиці додадуть політику для anon,
-- зайвий грант тихо перетвориться на дірку.
revoke all on table public.channel_post_views from anon, authenticated;
revoke all on table public.chat_reads         from anon, authenticated;
revoke all on table public.phone_codes        from anon, authenticated;

-- ─── 3. blocked_contacts — увімкнути RLS ───────────────────────────
-- Друга (і остання) таблиця без RLS. Даних anon не бачить — має лише
-- references/trigger/truncate — тож витоку немає. Вмикаємо для
-- однорідності: «без RLS» не має бути винятків, які треба пам'ятати.
alter table public.blocked_contacts enable row level security;
revoke all on table public.blocked_contacts from anon, authenticated;

-- ─── ПЕРЕВІРКА (виконати після; має бути порожньо) ─────────────────
-- Таблиці, де anon/authenticated досі мають доступ до даних:
--
--   select table_name, grantee, privilege_type
--   from information_schema.role_table_grants
--   where table_schema = 'public'
--     and grantee in ('anon','authenticated')
--     and privilege_type in ('SELECT','INSERT','UPDATE','DELETE')
--   order by table_name;
--
-- Таблиці public без RLS (має бути порожньо):
--
--   select relname from pg_class c
--   join pg_namespace n on n.oid = c.relnamespace
--   where n.nspname = 'public' and c.relkind = 'r' and not c.relrowsecurity;
