-- Забезпечення монет токеном (03.09.2026)
--
-- Досі монети могли з'явитись із повітря: бонус новачка створювався просто
-- полем `coins: 200` при вставці користувача, і жодне число ніде не зменшувалось.
-- Скарбниця EION при цьому лише зростала й нічого не обмежувала — тобто була
-- бухгалтерським записом, а не фондом.
--
-- Нове правило: **монета потрапляє в обіг ЛИШЕ тоді, коли в мості замкнено
-- токен**. Джерел два, обидва з фіксованої емісії 10 млрд:
--   • поповнення користувача (він сам вніс токени)   → deposited
--   • поповнення скарбниці з фондів проєкту           → float_in
-- Виходи: виплата в токен (released) і спалювання комісій (burned).
-- Роздачі (бонус новачка, майбутні нагороди) більше не створюють монети —
-- вони переносять їх зі скарбниці, і коли вона порожня, роздавати нічого.

alter table public.coin_supply add column if not exists deposited bigint not null default 0;
alter table public.coin_supply add column if not exists released  bigint not null default 0;
alter table public.coin_supply add column if not exists float_in  bigint not null default 0;

-- Скільки монет існує зараз. Це те число, яке має бути забезпечене токенами
-- на гаманці обміну; порівняння робить сервер (`/admin/reserve`).
create or replace function public.coins_circulating()
returns bigint
language sql
stable
as $$
  select coalesce(sum(coins), 0)::bigint from public.users;
$$;

-- Один лічильник потоку. Окрема функція, а не update із сервера: рядок у
-- coin_supply один, і паралельні записи інакше затирали б одне одного.
create or replace function public.note_coin_flow(p_kind text, p_amount bigint)
returns void
language plpgsql
as $$
begin
  if p_amount is null or p_amount <= 0 then return; end if;
  if p_kind = 'deposited' then
    update public.coin_supply set deposited = deposited + p_amount, updated_at = now() where id = 1;
  elsif p_kind = 'released' then
    update public.coin_supply set released = released + p_amount, updated_at = now() where id = 1;
  elsif p_kind = 'float_in' then
    update public.coin_supply set float_in = float_in + p_amount, updated_at = now() where id = 1;
  end if;
end;
$$;

grant execute on function public.coins_circulating() to postgres, service_role;
grant execute on function public.note_coin_flow(text, bigint) to postgres, service_role;
