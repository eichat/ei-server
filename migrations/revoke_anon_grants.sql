-- Аудит безпеки #11 — зняти зайві anon/authenticated-гранти.
-- Сервер ходить service_role-ключем (обходить RLS + має власні гранти), тож ці
-- таблиці мають бути ПОВНІСТЮ недоступні клієнтському anon-ключу (він лежить у
-- APK, і будь-хто, хто розпакував APK, ним володіє). Перевірено: клієнт у ці
-- таблиці напряму НЕ ходить — усе через сервер. Зараз anon отримує 200 []
-- (гранти є, тримається лише на RLS) — після цього має бути 401.
--
-- Виконати в Supabase → SQL Editor. Прод це не зачіпає (сервер = service_role).

-- sessions більше не потрібна (перейшли на stateless HMAC-токени) — прибираємо
-- цілком. Заодно закриває те, що anon міг її читати.
DROP TABLE IF EXISTS sessions;

-- Решта таблиць: забрати всі права в anon та authenticated.
-- Лишаються postgres (SQL Editor) і service_role (сервер).
REVOKE ALL ON TABLE coin_transactions FROM anon, authenticated;
REVOKE ALL ON TABLE sticker_packs      FROM anon, authenticated;
REVOKE ALL ON TABLE user_sticker_packs FROM anon, authenticated;
REVOKE ALL ON TABLE block_allowlist    FROM anon, authenticated;

-- Пов'язані sequence (BIGSERIAL/BIGINT id) — прибрати USAGE/SELECT у anon,
-- інакше anon міг би тягнути наступні id. Best-effort: якщо якоїсь sequence
-- немає (інша схема іменування / id не serial) — пропускаємо без помилки.
DO $$
DECLARE s text;
BEGIN
  FOREACH s IN ARRAY ARRAY[
    'coin_transactions_id_seq',
    'sticker_packs_id_seq',
    'user_sticker_packs_id_seq',
    'block_allowlist_id_seq'
  ] LOOP
    BEGIN
      EXECUTE format('REVOKE ALL ON SEQUENCE %I FROM anon, authenticated', s);
    EXCEPTION WHEN undefined_table THEN
      -- sequence немає — не критично
      NULL;
    END;
  END LOOP;
END $$;
