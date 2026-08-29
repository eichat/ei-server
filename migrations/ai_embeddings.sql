-- Смисловий пошук по базі знань (ембединги + pgvector).
--
-- Навіщо: `pg_trgm` порівнює ЛІТЕРИ. На живому тесті 30.08 «не працює відео
-- на лінуксі» не зіставилось із «Чому відео не відкривається на Linux» —
-- різні слова, ще й кирилиця проти латиниці. Обхід був у тому, щоб писати
-- кілька формулювань на одну відповідь; ембединги знімають потребу.
--
-- Триграми при цьому НЕ прибираємо: вони працюють без жодного ключа й
-- лишаються запасним шляхом, якщо постачальник ембедингів недоступний.
create extension if not exists vector;
-- ⚠️ Supabase тримає розширення поза `public` — без цього рядка ні тип
-- `vector`, ні оператор `<=>` можуть не знайтись (та сама пастка, що з pg_trgm).
set search_path = public, extensions;

-- 768 — розмірність Gemini text-embedding-004. Модель з іншою розмірністю
-- писатиме сюди помилку, і це навмисно: мовчазна невідповідність гірша.
alter table public.ai_cache add column if not exists embedding vector(768);

create index if not exists ai_cache_embedding_idx
  on public.ai_cache using hnsw (embedding vector_cosine_ops);

-- ⚠️ Вектор приймаємо ТЕКСТОМ і кастимо всередині: через PostgREST масив
-- чисел не приводиться до `vector` автоматично.
create or replace function public.ai_kb_search_vec(p_fp text, p_vec text, p_limit int default 4)
returns table (key text, question text, answer text, source text, same_lang boolean, sim real)
language sql stable
set search_path = public, extensions
as $$
  select c.key, c.question, c.answer, c.source,
         (c.lang_fp = p_fp) as same_lang,
         (1 - (c.embedding <=> p_vec::vector(768)))::real as sim
    from public.ai_cache c
   where c.enabled
     and c.embedding is not null
     and (c.source = 'curated' or c.lang_fp = p_fp)
   order by c.embedding <=> p_vec::vector(768)
   limit p_limit;
$$;

grant execute on function public.ai_kb_search_vec(text, text, int) to postgres, service_role;
