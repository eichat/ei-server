-- Журнал підписок і відписок каналів (14.09.2026).
-- channel_members зберігає лише ПОТОЧНИХ учасників: відписка видаляє рядок, і
-- статистика не мала з чого рахувати чистий приріст. Тут — лише факт і час,
-- без ніка: для статистики нік не потрібен, і видалення акаунта нічого тут не
-- лишає по собі.
create table if not exists public.channel_member_events (
  id bigint generated always as identity primary key,
  channel_id bigint not null,
  kind text not null check (kind in ('join', 'leave')),
  via text,
  created_at bigint not null
);
create index if not exists channel_member_events_ch_idx
  on public.channel_member_events (channel_id, created_at);
alter table public.channel_member_events enable row level security;
revoke all on table public.channel_member_events from anon, authenticated;
grant all on table public.channel_member_events to postgres, service_role;
