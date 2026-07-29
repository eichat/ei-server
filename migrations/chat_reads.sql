-- Фіча: лічильники непрочитаного для груп і каналів, що ПЕРЕЖИВАЮТЬ рестарт/офлайн.
-- Проблема: /group/list і /channel/list не віддавали unread; клієнт нараховував його
-- лише з живих WS-подій, які на login гоняться з _loadGroups (той скидав unread:0),
-- а для каналів пропущені пости взагалі не досилались. Результат — при вході на
-- Android бейджі груп/каналів зникали.
--
-- Рішення: єдиний вказівник "останнє прочитане" на (нік, тип, id). Обидва списки
-- рахують unread = кількість чужих повідомлень з timestamp > last_read_ts.
--
-- Виконати в Supabase → SQL Editor.

create table if not exists chat_reads (
  nick         text   not null,
  chat_type    text   not null,          -- 'group' | 'channel'
  chat_id      bigint not null,
  last_read_ts bigint not null default 0,
  primary key (nick, chat_type, chat_id)
);

-- Сервер ходить service_role — клієнтський anon-ключ у цю таблицю НЕ повинен мати
-- доступу (аудит #11). Тому НЕ грантимо anon/authenticated, лише postgres+service_role.
grant all on table chat_reads to postgres, service_role;

-- Прискорює перелік вказівників юзера у /group/list та /channel/list.
create index if not exists chat_reads_nick_type_idx on chat_reads (nick, chat_type);
