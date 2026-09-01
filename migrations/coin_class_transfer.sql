-- Переказ монет має ПЕРЕНОСИТИ клас, а не створювати «зароблене» (02.09.2026)
--
-- 🔴 Діра, яку це закриває. `spend_coins` списував будь-які монети, а
-- отримувач у /transfer-coins завжди діставав їх через `add_coins_earned` —
-- тобто ВИВЕДЕНИМИ. Отже бонус новачка знову ставав краном токена, лише через
-- один зайвий крок:
--    зареєструвати акаунт → 200 внутрішніх → переказати на основний →
--    там 198 «зароблених» → вивести 198 токенів.
-- Те саме давали платні канали: заплатив внутрішніми 100 → власник отримав 70
-- виведених. Саме проти цього й вводились два класи (migrations/coin_classes_wallet).
--
-- Рішення: списання повідомляє, СКІЛЬКИ з витраченого було «зароблене», і
-- отримувач дістає виведеними рівно цю частину, решту — внутрішніми.
-- Внутрішнє й далі витрачається першим, тож виведене лишається за власником.

create or replace function spend_coins_split(p_nick text, p_amount integer)
returns json
language plpgsql
as $$
declare
  cur_coins   int;
  cur_earned  int;
  internal    int;
  spent_earned int;
  new_balance int;
begin
  -- for update: два паралельні запити не мають прочитати один і той самий
  -- стан і списати двічі — саме заради цього списання й живе в БД.
  select coins, coins_earned into cur_coins, cur_earned
    from users where nick = p_nick for update;
  if cur_coins is null or p_amount <= 0 or cur_coins < p_amount then
    return json_build_object('balance', -1, 'earned_spent', 0);
  end if;
  internal := greatest(0, cur_coins - cur_earned);
  spent_earned := greatest(0, p_amount - internal);
  update users
     set coins = coins - p_amount,
         coins_earned = greatest(0, coins_earned - spent_earned)
   where nick = p_nick
   returning coins into new_balance;
  return json_build_object('balance', new_balance, 'earned_spent', spent_earned);
end;
$$;

revoke all on function spend_coins_split(text, integer) from public, anon, authenticated;
grant execute on function spend_coins_split(text, integer) to service_role;
