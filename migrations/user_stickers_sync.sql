-- «Мої наліпки» на всіх пристроях акаунта.
--
-- Навіщо. Список жив ЛИШЕ в SharedPreferences (`user_stickers_v1`), тож
-- наліпка, зроблена на телефоні, на десктопі не існувала взагалі — людина не
-- розуміла, куди вона зникла. Самі зображення давно в Storage (їх треба
-- надсилати співрозмовнику), тож бракувало саме списку.
--
-- Модель. Один рядок на наліпку, `deleted_at` замість фізичного видалення:
-- без надгробка злиття неоднозначне — «немає на сервері» означало б і
-- «створено офлайн», і «видалено на іншому пристрої», а це протилежні дії.
-- `updated_at` дає догін одним запитом (`?since=`), як у /deletions.
create table if not exists user_stickers (
  nick       text   not null,
  sticker_id text   not null,
  image_url  text   not null,
  crop_scale double precision not null default 1,
  crop_dx    double precision not null default 0,
  crop_dy    double precision not null default 0,
  created_at bigint not null,
  updated_at bigint not null,
  deleted_at bigint,
  primary key (nick, sticker_id)
);

create index if not exists user_stickers_sync_idx
  on user_stickers (nick, updated_at);

alter table user_stickers enable row level security;
grant all on table user_stickers to postgres, service_role;

comment on table user_stickers is
  'Список власних наліпок акаунта (UGC). Файли лежать у Storage; тут лише '
  'метадані й кроп. deleted_at — надгробок, рядки не видаляються, інакше '
  'видалене поверталося б із пристрою, який його ще не бачив.';
