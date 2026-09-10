-- Синхронізація ВИДАЛЕНЬ між пристроями одного акаунта.
--
-- Навіщо. Видалення жило одним рядком у `deleted_messages` і при вході
-- адресата ЗНИЩУВАЛОСЬ (`delete().eq('to_nick', …)`). З одним пристроєм на
-- акаунт це працювало; з кількома — перший, хто зайшов, «спалював» видалення
-- для решти, і на другому пристрої повідомлення лишалось назавжди. Та сама
-- вада, що колись була з `messages.delivered`.
--
-- А «видалити для себе» серверу не повідомлялось узагалі, тож на інших
-- пристроях власника воно просто не зникало.
--
-- Модель — журнал із позначкою часу, як `messages.edited_at` для правок
-- (`/edits?since=`): пристрій питає «що видалено після мого останнього
-- візиту» і сам зсуває позначку. Журнал самовідновний: пропущені кілька
-- входів наздоганяються одним запитом, нічого не треба доставляти й прибирати.
create table if not exists message_deletions (
  id         bigint generated always as identity primary key,
  nick       text   not null,          -- КОМУ адресоване видалення (усі його пристрої)
  msg_id     text   not null,
  peer_nick  text,                     -- з ким чат: клієнт одразу знає, де шукати
  scope      text   not null default 'all',  -- 'all' (для всіх) | 'me' (лише в себе)
  created_at bigint not null
);

-- Догін завжди читає «мої записи, новіші за позначку».
create index if not exists message_deletions_nick_ts_idx
  on message_deletions (nick, created_at);

alter table message_deletions enable row level security;
grant all on table message_deletions to postgres, service_role;

comment on table message_deletions is
  'Журнал видалень для догону на всі пристрої акаунта. Читається за '
  '(nick, created_at > позначка пристрою); рядки НЕ видаляються при читанні.';
