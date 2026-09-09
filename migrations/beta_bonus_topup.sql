-- Разове донарахування бонусу тестового періоду (рішення 09.09.2026).
--
-- Навіщо: бонус новачка піднято 200 → 2000 на час бети, і ті, хто
-- зареєструвався раніше, мають отримати ту саму суму — інакше ранні
-- тестувальники опиняються в гіршому становищі, ніж пізніші.
--
-- 🔴 Монети беруться ЗІ СКАРБНИЦІ (акаунт EION), а не створюються з повітря:
-- з 03.09 кожна монета в обігу забезпечена токеном, замкненим у мості
-- (див. CLAUDE.md, розділ 64). Пряме `update users set coins = coins + 2000`
-- зламало б це співвідношення і зробило б обіг більшим за забезпечення.
--
-- 🔴 Нараховується ВНУТРІШНІМИ (add_coins, не add_coins_earned): виводити в
-- токен можна лише те, за що заплатила інша людина. Інакше 2000 × фальшиві
-- акаунти = прямий кран емісії.
--
-- Ідемпотентно: повторний запуск нічого не додасть — ознакою слугує запис
-- kind='beta_topup' у журналі. Тому файл безпечно виконати двічі.

do $$
declare
  u record;
  amt integer := 2000;
  left_after integer;
  done integer := 0;
  skipped integer := 0;
begin
  for u in select nick from public.users where nick <> 'EION' order by created_at nulls first loop
    if exists (select 1 from public.coin_transactions
               where to_nick = u.nick and kind = 'beta_topup') then
      skipped := skipped + 1;
      continue;
    end if;

    -- Умовне атомарне списання: -1 означає «недостатньо».
    select public.spend_coins('EION', amt) into left_after;
    if left_after = -1 or left_after is null then
      raise notice 'СКАРБНИЦЯ ПОРОЖНЯ — зупинено перед %', u.nick;
      exit;
    end if;

    perform public.add_coins(u.nick, amt);
    insert into public.coin_transactions (from_nick, to_nick, amount, kind)
    values ('EION', u.nick, amt, 'beta_topup');
    done := done + 1;
  end loop;

  raise notice 'нараховано: % акаунтам, пропущено (вже мали): %', done, skipped;
end $$;

-- Звірка після виконання:
--   select nick, coins, coins_earned from public.users order by created_at nulls first;
--   select to_nick, amount, kind, created_at from public.coin_transactions
--     where kind = 'beta_topup' order by created_at;
