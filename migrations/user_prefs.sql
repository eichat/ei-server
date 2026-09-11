-- Дрібні налаштування акаунта, які мають бути однакові на всіх пристроях.
--
-- Навіщо спільна таблиця, а не ще одна вузька. Таких речей ціла низка —
-- позначка «очищено історію каналу» (`ch_clear_<id>`), «недавні» наліпки й
-- емодзі, позиція в стрічці. Усі вони однакові за природою: мала пара
-- ключ-значення на акаунт, яку треба доганяти при вході. Пʼять окремих
-- таблиць означали б пʼять endpoint і пʼять шляхів догону з тією самою
-- логікою.
--
-- ⚠️ Сюди НЕ йдуть налаштування ПРИСТРОЮ: тема, мова інтерфейсу, рінгтон,
-- автопереклад. Вони свідомо лишаються локальними — на телефоні й десктопі
-- людина цілком може хотіти різного.
create table if not exists user_prefs (
  nick       text   not null,
  key        text   not null,
  value      text,                  -- json-рядок: число, рядок або список
  updated_at bigint not null,
  primary key (nick, key)
);

-- Догін читає «моє, новіше за позначку» — той самий взірець, що /deletions.
create index if not exists user_prefs_sync_idx on user_prefs (nick, updated_at);

alter table user_prefs enable row level security;
grant all on table user_prefs to postgres, service_role;

comment on table user_prefs is
  'Дрібні налаштування акаунта (не пристрою) для синхронізації між пристроями: '
  'ch_clear_<id>, недавні наліпки тощо. Значення — json-рядок.';
