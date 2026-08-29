-- Власні ключі користувачів до постачальників AI (BYOK).
--
-- Навіщо: наш ключ один на всіх, і його безкоштовна норма — спільна стеля,
-- яку впирає зростання кількості користувачів. Коли людина підключає свій
-- ключ, її запити йдуть за ЇЇ безкоштовною нормою: система масштабується без
-- нашої участі й без наших витрат.
--
-- 🔴 Тут лежать ЧУЖІ СЕКРЕТИ. Тому:
--   • key_enc — AES-256-GCM, ключ шифрування живе лише в env (AI_KEY_SECRET),
--     не в базі. Дамп бази без env не дає нічого;
--   • key_hint — лише останні символи, щоб людина впізнала свій ключ у списку;
--   • назовні ключ НЕ повертається жодним endpoint, тільки hint;
--   • RLS увімкнено, гранти лише service_role (урок аудиту #21: нові таблиці
--     не грантувати anon/authenticated).
create table if not exists public.user_ai_keys (
  nick        text not null,
  provider    text not null,
  key_enc     text not null,
  key_hint    text not null,
  model_base  text,
  model_pro   text,
  disabled    boolean not null default false,
  last_error  text,
  added_at    bigint not null,
  primary key (nick, provider)
);
create index if not exists user_ai_keys_nick_idx on public.user_ai_keys (nick);

alter table public.user_ai_keys enable row level security;

grant delete, insert, references, select, trigger, truncate, update on table public.user_ai_keys to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.user_ai_keys to service_role;
