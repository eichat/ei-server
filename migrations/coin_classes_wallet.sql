-- Економіка: два класи монет + плата за відкриття гаманця (01.09.2026)
--
-- Причина: міст працює 1:1 (TOKEN_PAYOUT_RATE=1), тому будь-яка роздача монет
-- є фактичною емісією токена. Бонус новачка (200) більший за мінімум виводу
-- (100) — тобто реєстрація була краном: зареєструвався → вивів 200 токенів.
--
-- Рішення: виводиться ЛИШЕ те, за що хтось уже заплатив (частка автора з
-- платної підписки, звернення до власника каналу, переказ від людини).
-- Усе, що даємо ми самі, лишається внутрішнім: ним можна платити всередині
-- EION, і воно повертається до нас.

alter table users add column if not exists coins_earned integer not null default 0;
alter table users add column if not exists wallet_opened boolean not null default false;

comment on column users.coins_earned is
  'Частина coins, яку дозволено виводити в токен. Зростає лише від платежів інших людей.';
comment on column users.wallet_opened is
  'Плату за відкриття токен-рахунку вже стягнуто — вдруге не беремо.';

-- Нарахування «зароблених» монет: зростають обидва лічильники.
create or replace function add_coins_earned(p_nick text, p_amount integer)
returns integer
language plpgsql
as $$
declare new_balance int;
begin
  update users
     set coins = coins + p_amount,
         coins_earned = coins_earned + p_amount
   where nick = p_nick
   returning coins into new_balance;
  return coalesce(new_balance, -1);
end;
$$;

-- Списання зменшує «зароблене» лише тоді, коли інакше воно перевищило б
-- загальний баланс. Тобто витрачається спершу внутрішнє — виведене
-- зберігається за користувачем.
create or replace function spend_coins(p_nick text, p_amount integer)
returns integer
language plpgsql
as $$
declare new_balance int;
begin
  update users
     set coins = coins - p_amount
   where nick = p_nick and coins >= p_amount
   returning coins into new_balance;
  if new_balance is null then
    return -1;
  end if;
  update users
     set coins_earned = least(coins_earned, new_balance)
   where nick = p_nick;
  return new_balance;
end;
$$;

-- Списання саме з виведеної частини (виплата в токен).
create or replace function spend_coins_earned(p_nick text, p_amount integer)
returns integer
language plpgsql
as $$
declare new_balance int;
begin
  update users
     set coins = coins - p_amount,
         coins_earned = coins_earned - p_amount
   where nick = p_nick and coins >= p_amount and coins_earned >= p_amount
   returning coins into new_balance;
  return coalesce(new_balance, -1);
end;
$$;

revoke all on function add_coins_earned(text, integer) from public, anon, authenticated;
revoke all on function spend_coins_earned(text, integer) from public, anon, authenticated;
grant execute on function add_coins_earned(text, integer) to service_role;
grant execute on function spend_coins_earned(text, integer) to service_role;
