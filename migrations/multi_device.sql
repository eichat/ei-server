-- Багатопристроєвість: реєстр пристроїв акаунта.
--
-- Навіщо. Досі акаунт = один пристрій: вхід із другого вибивав перший
-- (`kicked`), ключ E2EE перезаписувався, а `messages.delivered` рахувався на
-- НІК. Наслідок був такий: усе, що прийшло на телефон, для десктопа зникало
-- назавжди, а запечатане для ключа одного пристрою не читалось на іншому.
--
-- Пристрій стає сутністю: власний ключ шифрування, власна черга доставки,
-- власний токен пушів. Модель узята з WhatsApp (список пристроїв на акаунт +
-- шифрування для кожного), але БЕЗ «головного = телефон»: у нас акаунт це нік
-- і пароль, і сесія лише на десктопі — нормальний випадок.

create table if not exists user_devices (
  nick        text not null,
  device_id   text not null,
  platform    text,
  e2ee_pubkey text,                 -- відкритий ключ САМЕ цього пристрою
  fcm_token   text,                 -- пуш теж на пристрій, а не на нік
  created_at  timestamptz not null default now(),
  last_seen   bigint,
  revoked_at  bigint,               -- «відключити пристрій» у налаштуваннях
  primary key (nick, device_id)
);

create index if not exists user_devices_nick_idx on user_devices (nick);

alter table user_devices enable row level security;
grant all on table user_devices to postgres, service_role;

comment on table user_devices is
  'Пристрої акаунта: ключ E2EE, токен пушів і час останньої появи на кожен. '
  'Відправник шифрує для КОЖНОГО непозбавленого прав пристрою отримувача.';

-- Доставка на пристрій. Було булеве `delivered` на повідомлення (тобто на
-- акаунт): хто перший підтвердив, для того й «доставлено», а другий пристрій
-- повідомлення вже не отримував. Масив — той самий взірець, що в групах
-- (`group_messages.delivered_to`), лише на рівень глибше: не учасники, а
-- пристрої.
alter table messages add column if not exists delivered_devices text[] default '{}';

comment on column messages.delivered_devices is
  'Пристрої, які підтвердили отримання. `delivered` лишається як є — на ньому '
  'тримаються галочки відправника й чистка через 7 днів.';
