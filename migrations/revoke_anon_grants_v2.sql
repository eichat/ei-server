-- Аудит безпеки #11, друге коло — зняти anon/authenticated-гранти в НОВОМУ проєкті.
--
-- ЩО СТАЛОСЬ. 28.07 гранти зняли (revoke_anon_grants.sql), anon почав отримувати
-- 401. Але 29.08 ми переїхали на новий проєкт Supabase, розгорнутий із SETUP.sql,
-- і дірка відкрилась знову.
--
-- ФАКТИ (діагностика в SQL Editor + проби ззовні anon-ключем, 30.08.2026):
--   • 78 грантів = 39 таблиць × (anon + authenticated), кожен повний:
--     DELETE, INSERT, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE;
--   • ззовні: select → 200 [], delete → 204, patch → 204, rpc add_coins → 200;
--   • RLS увімкнено на всіх 39 таблицях, політик для anon/public — 0.
-- Тобто дані не текли, але захист тримався на ОДНОМУ шарі: перша ж помилкова
-- політика на будь-якій таблиці = відкрита база.
--
-- ЧОМУ SETUP.sql ЦЬОГО НЕ ЗУПИНИВ. Він явно дає anon лише
-- `references, trigger, truncate`. Решту додає САМ SUPABASE — у pg_default_acl
-- лежить `grant all on tables to anon, authenticated` для схеми public,
-- і то ДВІЧІ: від ролі postgres і від ролі supabase_admin. Кожна створена
-- таблиця отримує повні права автоматично.
--
-- Ця схема («ключ у клієнті + RLS як єдиний захист») розрахована на застосунки
-- БЕЗ власного бекенда. У нас бекенд є, тож anon не потрібні жодні права.
-- Найсильнішу пораду документації Supabase — вимкнути Data API цілком — нам
-- застосувати НЕ можна: сервер ходить у базу теж через PostgREST
-- (@supabase/supabase-js), прямого підключення до Postgres немає.
--
-- БЕЗПЕЧНІСТЬ. Сервер ходить service-ключем (має власні явні гранти й обходить
-- RLS). Клієнт із Supabase не спілкується ВЗАГАЛІ з 29.08: supabase_flutter
-- прибрано, у ~/ei/lib немає жодної згадки, .env більше не пакується в APK
-- (перевірено: у поточному APK ані файла, ані рядка з адресою проєкту).
-- Ламати цьому revoke нічого. Білд не потрібен.
--
-- Виконати в Supabase → SQL Editor.

-- ─────────────────────────────────────────────────────────────────
-- 1. Забрати права на ВСІХ обʼєктах схеми public
--    Циклом, а не переліком: нові таблиці зʼявляються постійно, і саме
--    відсталий перелік дав би дірці повернутись утретє.
-- ─────────────────────────────────────────────────────────────────
DO $$
DECLARE
  r record;
  n_tab int := 0;
  n_seq int := 0;
  n_fun int := 0;
  n_skip int := 0;
BEGIN
  FOR r IN
    SELECT c.relname, c.relkind
      FROM pg_class c
      JOIN pg_namespace ns ON ns.oid = c.relnamespace
     WHERE ns.nspname = 'public'
       AND c.relkind IN ('r','p','v','m','S')   -- таблиці, партиції, вʼюхи, sequence
  LOOP
    -- ⚠️ Кожен REVOKE окремо в BEGIN/EXCEPTION. Його може виконати лише ВЛАСНИК
    -- обʼєкта; чуже кинуло б "must be owner" і обірвало весь блок на середині,
    -- лишивши роботу зробленою наполовину. Діагностика: усі 63 таблиці належать
    -- postgres, тож тут пропусків не очікується — перехоплення на майбутнє.
    BEGIN
      IF r.relkind = 'S' THEN
        EXECUTE format('REVOKE ALL ON SEQUENCE public.%I FROM anon, authenticated', r.relname);
        n_seq := n_seq + 1;
      ELSE
        EXECUTE format('REVOKE ALL ON TABLE public.%I FROM anon, authenticated', r.relname);
        n_tab := n_tab + 1;
      END IF;
    EXCEPTION WHEN insufficient_privilege OR wrong_object_type THEN
      n_skip := n_skip + 1;
      RAISE NOTICE 'пропущено (не власник): %', r.relname;
    END;
  END LOOP;

  -- Функції.
  --
  -- 🔴 ОБОВʼЯЗКОВО РАЗОМ ІЗ PUBLIC. Postgres за замовчуванням дає EXECUTE ролі
  -- PUBLIC — у діагностиці це видно як `=X/postgres` на початку acl. Забрати
  -- права лише в anon було б косметикою: anon успадкував би EXECUTE через
  -- PUBLIC і далі міг би кликати функції монет. service_role і postgres мають
  -- ЯВНІ гранти (`service_role=X`, `postgres=X`), тож їх це не зачіпає.
  --
  -- Сьогодні всі функції SECURITY INVOKER (діагностика: SECURITY DEFINER — 0),
  -- тож RLS їх стримує: add_coins('EION',0) від anon повертає null. Але щойно
  -- атомарну операцію з монетами зроблять SECURITY DEFINER — а це природна
  -- думка — відкритий EXECUTE стане прямим друком монет.
  FOR r IN
    SELECT p.oid::regprocedure AS sig
      FROM pg_proc p
      JOIN pg_namespace ns ON ns.oid = p.pronamespace
     WHERE ns.nspname = 'public'
  LOOP
    BEGIN
      EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC, anon, authenticated', r.sig);
      n_fun := n_fun + 1;
    EXCEPTION WHEN insufficient_privilege OR wrong_object_type THEN
      -- Очікувано ~149 разів: pg_trgm і vector стоять у public, їхні функції
      -- належать supabase_admin. Вони не наші — не чіпаємо.
      n_skip := n_skip + 1;
    END;
  END LOOP;

  RAISE NOTICE 'revoke: таблиць/вʼюх %, sequence %, функцій %, пропущено % (очікувано ~149 — розширення)',
    n_tab, n_seq, n_fun, n_skip;
END $$;

-- ─────────────────────────────────────────────────────────────────
-- 2. Перекрити ДЖЕРЕЛО — дефолтні привілеї
--    Без цього наступна ж `create table` знову видасть anon повні права.
--    Діагностика знайшла записи для public від ДВОХ ролей: postgres і
--    supabase_admin. Другий, найімовірніше, не наш — postgres у Supabase не
--    суперкористувач і членом supabase_admin зазвичай не є, тож ALTER для
--    нього кине "permission denied". Тому кожен — у своєму перехопленні:
--    невдача на чужій ролі не має скасовувати роботу на своїй.
-- ─────────────────────────────────────────────────────────────────
DO $$
DECLARE
  owner_role text;
  obj        text;
  n_ok   int := 0;
  n_fail int := 0;
BEGIN
  FOREACH owner_role IN ARRAY ARRAY['postgres','supabase_admin'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = owner_role) THEN
      CONTINUE;
    END IF;
    FOREACH obj IN ARRAY ARRAY['TABLES','SEQUENCES','FUNCTIONS'] LOOP
      BEGIN
        EXECUTE format(
          'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public '
          'REVOKE ALL ON %s FROM anon, authenticated', owner_role, obj);
        n_ok := n_ok + 1;
      EXCEPTION WHEN insufficient_privilege OR undefined_object THEN
        n_fail := n_fail + 1;
        RAISE NOTICE 'дефолтні привілеї: немає прав на роль % (%) — пропущено', owner_role, obj;
      END;
    END LOOP;
  END LOOP;
  RAISE NOTICE 'дефолтні привілеї: змінено %, пропущено %', n_ok, n_fail;
END $$;

-- ℹ️ Записи для схем storage / graphql / graphql_public теж дають anon повні
--    права на МАЙБУТНІ обʼєкти. Не чіпаємо свідомо: ми в цих схемах нічого не
--    створюємо, а storage має власну рольову модель (див. нижче).

-- ⚠️ storage.objects СВІДОМО НЕ ЧІПАЄМО. Діагностика: бакети files і avatars
--    приватні, політик лише дві — service_all_objects (service_role) і
--    stickers_public_read (public, і це навмисно: магазин наліпок). Ззовні
--    заливка від anon → 403 RLS, list → [], публічне скачування → 400.
--    А підписані download-URL обслуговує storage-api зі своєю рольовою
--    моделлю: revoke міг би тихо зламати ВСЕ медіа. Виграш малий, ризик великий.

-- ─────────────────────────────────────────────────────────────────
-- 3. Перевірка. Обидва запити мають дати 0 рядків.
-- ─────────────────────────────────────────────────────────────────

-- 3a. Гранти на таблицях (було 78):
SELECT grantee, table_name, string_agg(privilege_type, ',' ORDER BY privilege_type) AS lishylos
  FROM information_schema.role_table_grants
 WHERE table_schema = 'public'
   AND grantee IN ('anon','authenticated','PUBLIC')
 GROUP BY grantee, table_name
 ORDER BY table_name, grantee;

-- 3b. EXECUTE на НАШИХ функціях (розширення не рахуємо — вони не наші):
-- Запис для PUBLIC у proacl не має імені грантованого: він починається з '='.
-- Саме тому тут unnest, а не LIKE '%=X/%' по склеєному рядку — той збігався б
-- і з 'postgres=X/postgres', тобто «брудно» показувало б завжди.
SELECT p.proname, array_to_string(p.proacl, ' ') AS acl
  FROM pg_proc p
  JOIN pg_namespace ns ON ns.oid = p.pronamespace
 WHERE ns.nspname = 'public'
   AND pg_get_userbyid(p.proowner) = 'postgres'
   AND EXISTS (
     SELECT 1 FROM unnest(p.proacl) a
      WHERE a::text LIKE '=%'              -- PUBLIC
         OR a::text LIKE 'anon=%'
         OR a::text LIKE 'authenticated=%'
   );

-- Далі перевірю ЗЗОВНІ anon-ключем — має стати 401 замість 200/204.
