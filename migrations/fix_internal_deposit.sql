-- Відкат помилкового нарахування 31.08.2026.
--
-- Що сталося: адреса фонду винагород була прив'язана до акаунта EION (її
-- вставили, щоб подивитись баланс токена), і службовий переказ 5 млн токенів
-- із фонду на гаманець обміну сканер зарахував як поповнення — 5 000 000 балів.
-- Код виправлено окремо (`5214d0d`): внутрішні адреси не зараховуються, є
-- стеля на надходження, службову адресу не можна прив'язати до профілю.
--
-- ⚠️ Ідемпотентно: спирається на стан самого запису депозиту, тож повторний
-- запуск нічого не змінить. Просте `coins - 5000000` цього не давало б —
-- другий прогін забрав би ще п'ять мільйонів.
do $$
declare
  v_sig text;
  v_nick text;
  v_coins integer;
begin
  select signature, nick, coins into v_sig, v_nick, v_coins
    from public.token_deposits
   where status = 'credited'
     and address = 'GZZGs8c75cSvLH55LBWkmjRUdXweUmjzwvHE1tkd5rZA'
   limit 1;

  if v_sig is null then
    raise notice 'нічого відкочувати: запис уже виправлено або його немає';
    return;
  end if;

  update public.users set coins = greatest(0, coins - v_coins) where nick = v_nick;

  update public.token_deposits
     set status = 'unmatched', nick = null, coins = 0,
         -- лишаємо слід, чому запис нерозпізнаний
         address = address
   where signature = v_sig;

  delete from public.coin_transactions
   where kind = 'token_deposit' and ref = v_sig;

  raise notice 'відкочено % балів у %', v_coins, v_nick;
end $$;

-- Службова адреса не має лишатись прив'язаною до жодного акаунта.
update public.users
   set solana_address = null
 where solana_address in (
   'GZZGs8c75cSvLH55LBWkmjRUdXweUmjzwvHE1tkd5rZA',  -- rewards
   'ECL11kBykUp6T7Fhu65jfeqNby6wpQ17Cii2hPTMTUMY',  -- team
   '3n6Rw2iicbp3csK52kCN2BdZAmpdEdeByB9S7njrz5tk',  -- liquidity
   '9TCz77axdC6XgiSyojf6UGnD8vbLmt9LZ6DSS9ZmH1VC',  -- ecosystem
   'DTooba8HSaRRio5ryx1nZrpF4LjNhKvPsCS92F9D2w2S',  -- reserve
   'H8dVoU7FoeQLanccKENkfSY5buTtLHcN6aVqa4R1e48Z',  -- payer
   'HurDszaTUiYt2qFhwsZcz3DirWyhRr4EWZMA9QWR3agB'   -- гаманець обміну
 );

select nick, coins, solana_address from public.users where nick = 'EION';
