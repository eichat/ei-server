-- Посилання-запрошення в групи й канали (15.09.2026).
--
-- Навіщо токен, а не числовий id у посиланні: id груп і каналів послідовні,
-- тож «eion.network/g/5» означало б, що перебором можна перелічити всі групи
-- застосунку. Токен непередбачуваний (10 символів base62 ≈ 8,4·10^17), і його
-- можна відкликати, не чіпаючи саму групу.
--
-- Токен їде у ФРАГМЕНТІ посилання (eion.network/i/#<token>), бо фрагмент
-- браузер серверу не надсилає — він не потрапляє ні в логи веб-сервера, ні в
-- Referer, ні в аналітику. Так само зроблено в Signal (signal.group/#...).
create table if not exists public.invite_links (
  token text primary key,
  kind text not null check (kind in ('group', 'channel')),
  target_id bigint not null,
  created_by text not null,
  created_at bigint not null,
  -- null = безстрокове / без обмеження кількості. Поля закладені одразу, щоб
  -- посилання «на добу» чи «на 10 людей» не вимагали зміни схеми.
  expires_at bigint,
  max_uses integer,
  uses integer not null default 0,
  revoked boolean not null default false
);
-- Пошук чинного посилання цілі: саме його віддає /invite/create, щоб у групи
-- було одне стабільне посилання, а не нове на кожен тап «Поділитися».
create index if not exists invite_links_target_idx
  on public.invite_links (kind, target_id) where revoked = false;

-- Перевірка й лічильник — однією транзакцією. Без цього два одночасні переходи
-- за посиланням «на одну людину» впустили б обох: read-modify-write без
-- атомарності вже давав подвійне списання в магазині (13.09).
create or replace function public.use_invite(p_token text)
returns table (ok boolean, reason text, kind text, target_id bigint)
language plpgsql
as $$
declare
  r public.invite_links%rowtype;
  now_ms bigint := (extract(epoch from now())::bigint * 1000);
begin
  select * into r from public.invite_links where token = p_token for update;
  if not found then
    return query select false, 'not_found', null::text, null::bigint; return;
  end if;
  if r.revoked then
    return query select false, 'revoked', r.kind, r.target_id; return;
  end if;
  if r.expires_at is not null and r.expires_at < now_ms then
    return query select false, 'expired', r.kind, r.target_id; return;
  end if;
  if r.max_uses is not null and r.uses >= r.max_uses then
    return query select false, 'used_up', r.kind, r.target_id; return;
  end if;
  update public.invite_links set uses = uses + 1 where token = p_token;
  return query select true, null::text, r.kind, r.target_id;
end
$$;

alter table public.invite_links enable row level security;
revoke all on table public.invite_links from anon, authenticated;
grant all on table public.invite_links to postgres, service_role;
-- PUBLIC має EXECUTE на функціях за замовчуванням — revoke лише від anon був би
-- косметикою (аудит #11, друге коло).
revoke all on function public.use_invite(text) from public, anon, authenticated;
grant execute on function public.use_invite(text) to postgres, service_role;
