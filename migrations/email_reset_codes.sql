-- Коди відновлення пароля пережили рестарт сервера.
--
-- Було: resetCodes — звичайна Map у пам'яті процесу. Render на безкоштовному
-- тарифі присипляє інстанс після ~15 хв бездіяльності, а код дійсний рівно
-- 15 хв. Реальний сценарій втрати: користувач запросив код → пішов у пошту →
-- повернувся через 10 хв → інстанс тим часом заснув → «Код не знайдено».
-- Той самий клас вади, що з FCM-токенами (fcm_tokens_persist.sql).
--
-- Стало: код лежить у БД, як уже зроблено для телефонних (phone_codes).
-- Звідти ж узято attempts і last_sent_at: rate-limit по IP (authLimiter)
-- обходиться зміною IP, а ці два поля прив'язані до самої адреси.
--
-- GRANT — лише service_role (аудит #21: новим таблицям anon не треба).
create table if not exists public.email_codes (
  email        text primary key,
  code         text not null,
  nick         text not null,
  expires_at   timestamptz not null,
  attempts     int not null default 0,
  last_sent_at timestamptz
);

alter table public.email_codes enable row level security;

revoke all on table public.email_codes from anon, authenticated;
grant all on table public.email_codes to postgres, service_role;
