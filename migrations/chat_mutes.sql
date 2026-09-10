-- Вимкнені сповіщення груп і каналів — на сервері, а не в prefs.
--
-- Навіщо. Перемикач «Вимкнути сповіщення» був порожнім: `grp_mute_<id>` ніде
-- не читався взагалі, `ch_mute_<id>` лише малював іконку в меню. Керувати не
-- було чим — сповіщень для груп і каналів не існувало (ні пушів, ні
-- локальних), тож перемикач вимикав порожнечу.
--
-- Тепер сповіщення зʼявляються, і рішення «не турбувати» має ухвалювати той,
-- хто їх шле, тобто СЕРВЕР: інакше пуш однаково прилетить, а клієнт лише
-- сховає його вже після вібрації. Побічно це й дає однаковий стан на всіх
-- пристроях акаунта.
create table if not exists chat_mutes (
  nick       text   not null,
  chat_type  text   not null,           -- 'group' | 'channel'
  chat_id    text   not null,           -- текстом: id груп і каналів різних типів
  updated_at bigint not null,
  primary key (nick, chat_type, chat_id)
);

-- Рядок = замучено. Знімають зняттям рядка: надгробок тут не потрібен, бо
-- «немає запису» і «сповіщення увімкнені» — це одне й те саме, а не
-- протилежні стани (на відміну від наліпок).
create index if not exists chat_mutes_nick_idx on chat_mutes (nick, updated_at);

alter table chat_mutes enable row level security;
grant all on table chat_mutes to postgres, service_role;

comment on table chat_mutes is
  'Замучені групи й канали. Наявність рядка = сповіщення вимкнені.';
