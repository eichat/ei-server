-- База знань асистента: наш шар відповідей перед провайдером.
--
-- Було: точний збіг питання (`ai_cache`). Інакше сформульоване питання
-- («як мені зробити канал» проти «як створити канал») вважалось новим і знову
-- йшло в модель.
--
-- Стало три джерела в одній таблиці:
--   source='model'   — відповідь, яку колись дала модель. Віддається дослівно
--                      лише при дуже високій схожості й лише в межах тієї
--                      самої мови інтерфейсу (lang_fp).
--   source='curated' — відповідь, написана НАМИ. Дослівно не віддається
--                      ніколи: підмішується в контекст, щоб модель відповіла
--                      нашими фактами й мовою користувача.
--
-- Пошук — по триграмах (pg_trgm, усередині Postgres, без зовнішніх сервісів).
-- ⚠️ Триграми порівнюють ЛІТЕРИ, а не зміст: «видалити акаунт» і «стерти
-- профіль» вони не зіставлять. Тому поріг прямої видачі високий, а середні
-- збіги йдуть лише в контекст. Смисловий пошук — це ембединги + pgvector,
-- окремий крок.
create extension if not exists pg_trgm;
-- ⚠️ Supabase ставить розширення в схему `extensions`, а не в `public`. Без
-- цього рядка `gin_trgm_ops` і оператор `%` можуть не знайтись при створенні
-- індексу — помилка була б на рівному місці.
set search_path = public, extensions;

alter table public.ai_cache add column if not exists lang_fp text not null default '';
alter table public.ai_cache add column if not exists source  text not null default 'model';
alter table public.ai_cache add column if not exists enabled boolean not null default true;

create index if not exists ai_cache_question_trgm on public.ai_cache using gin (question gin_trgm_ops);
create index if not exists ai_cache_source_idx on public.ai_cache (source);

-- Пошук схожого. Повертає і наші записи (будь-яка мова), і модельні —
-- але лише тієї самої мови інтерфейсу, бо їх можна віддати дослівно.
create or replace function public.ai_kb_search(p_fp text, p_query text, p_limit int default 4)
returns table (key text, question text, answer text, source text, same_lang boolean, sim real)
language sql stable
set search_path = public, extensions
as $$
  select c.key, c.question, c.answer, c.source,
         (c.lang_fp = p_fp) as same_lang,
         similarity(c.question, p_query) as sim
    from public.ai_cache c
   where c.enabled
     and (c.source = 'curated' or c.lang_fp = p_fp)
     and c.question % p_query
   order by sim desc
   limit p_limit;
$$;

grant execute on function public.ai_kb_search(text, text, int) to postgres, service_role;
