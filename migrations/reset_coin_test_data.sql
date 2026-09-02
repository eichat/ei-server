-- Обнулення слідів наших власних перевірок у монеті (02.09.2026)
--
-- Числа «спалено 110 / у скарбниці 505 / 44 транзакції за тиждень» — це не
-- користувачі, а комісії й плата за гаманці з тестових прогонів: перевірки
-- пароля на грошових шляхах, класів монет, мосту й видалення акаунта. Тестові
-- акаунти вже видалені, але журнал і лічильники емісії їх пам'ятають.
--
-- Робимо ДО перших живих людей, бо потім ці числа стануть публічними:
-- блок «Монета зараз» на сайті читає саме їх (зараз вимкнений прапорцем
-- SUPPLY_ENABLED, вмикається при запуску токена).
--
-- ⚠️ Баланси РЕАЛЬНИХ акаунтів (void, Rumpel, ab) НЕ чіпаємо — ними ви
-- тестуєте. Обнуляється лише скарбниця EION, лічильники емісії та журнал.

begin;

-- 1. Журнал транзакцій — увесь наш, реальних платежів там немає.
delete from public.coin_transactions;

-- 2. Лічильники емісії та спалювання.
update public.coin_supply
   set minted = 0, burned = 0, updated_at = now()
 where id = 1;

-- 3. Скарбниця — це просто баланс системного акаунта EION.
update public.users set coins = 0, coins_earned = 0 where nick = 'EION';

commit;

-- Перевірка (має бути 0 / 0 / 0 / 0):
select (select count(*) from public.coin_transactions)                as journal,
       (select minted from public.coin_supply where id = 1)           as minted,
       (select burned from public.coin_supply where id = 1)           as burned,
       (select coins  from public.users where nick = 'EION')          as treasury;
