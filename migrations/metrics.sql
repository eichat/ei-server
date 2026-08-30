-- Метрики: лічильник завантажень + дві колонки, без яких активність не порахувати.
--
-- Навіщо власний лічильник: GitHub рахує завантаження НА ФАЙЛ, а ми при кожній
-- збірці замінюємо asset у релізі — старий видаляється разом зі своїм
-- лічильником. Тобто статистики завантажень у нас не було взагалі.
--
-- Навіщо колонки в users: таблиця не мала ні дати створення, ні останньої
-- активності. «Скільки нових за тиждень» і «скільки живих» не рахувалось
-- нічим — лише «скільки всього», що нічого не каже.

alter table public.users add column if not exists created_at timestamptz;
alter table public.users add column if not exists last_seen timestamptz;
-- У наявних рядків обидві null і лишаються null: підставити «зараз» означало б
-- вигадати дату реєстрації. Overview показує, скільки рядків без неї.

create table if not exists public.download_counts (
  day date not null,
  kind text not null,     -- apk | appimage
  source text not null,   -- site | other
  count bigint not null default 0,
  primary key (day, kind, source)
);
alter table public.download_counts enable row level security;
-- Політик немає = доступ лише службовій ролі (аудит #21: anon більше не грантуємо).
revoke all on table public.download_counts from anon, authenticated;
grant all on table public.download_counts to postgres, service_role;

-- Інкремент атомарний: без нього два одночасні завантаження прочитали б те саме
-- значення і одне з них загубилось би.
create or replace function public.bump_download(p_kind text, p_source text)
returns void language plpgsql security definer
set search_path = public
as $$
begin
  insert into public.download_counts (day, kind, source, count)
  values (current_date, p_kind, p_source, 1)
  on conflict (day, kind, source) do update set count = public.download_counts.count + 1;
end;
$$;
revoke all on function public.bump_download(text, text) from public, anon, authenticated;
grant execute on function public.bump_download(text, text) to postgres, service_role;
