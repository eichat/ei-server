-- Памʼять відповідей асистента.
--
-- Питання, що повторюються («як створити канал», «скільки коштує преміум»),
-- не мають щоразу коштувати виклику моделі. Відповідь на таке питання
-- зберігається і віддається наступному, хто спитав те саме.
--
-- ⚠️ Кеш СПІЛЬНИЙ для всіх користувачів, тому в нього потрапляє лише те, що
-- не може містити приватного: перше питання розмови, без цифр, пошти й
-- посилань, відповідь без жодного виклику інструментів і без ніка того, хто
-- питав. Правила — у server.js, `cacheEligible`.
create table if not exists public.ai_cache (
  key        text primary key,     -- відбиток мови + нормалізоване питання
  question   text not null,
  answer     text not null,
  model      text,
  hits       integer not null default 0,
  created_at bigint  not null,
  last_used  bigint  not null
);
create index if not exists ai_cache_last_used_idx on public.ai_cache (last_used);

alter table public.ai_cache enable row level security;

grant delete, insert, references, select, trigger, truncate, update on table public.ai_cache to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.ai_cache to service_role;
