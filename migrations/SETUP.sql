-- ═══════════════════════════════════════════════════════════════════
--  EION — повне розгортання схеми БД з нуля (SETUP.sql)
--
--  Згенеровано з дампа реальної схеми робочої бази (не з коду), тож
--  типи, дефолти, індекси та права відповідають проду 1:1.
--
--  ЯК КОРИСТУВАТИСЬ: створити новий проєкт Supabase → SQL Editor →
--  виконати цей файл цілком. Скрипт ідемпотентний (IF NOT EXISTS),
--  тож повторний запуск нічого не зламає.
--
--  ПІСЛЯ ЗАПУСКУ: оновити SUPABASE_URL / ключі в ~/ei/.env і в Render.
--
--  ╔═══════════════════════════════════════════════════════════════╗
--  ║  ⚠️  STORAGE ЗАКРИТО (Фаза 2.3 плану безпеки)                  ║
--  ╚═══════════════════════════════════════════════════════════════╝
--  Бакети files/avatars створюються ПРИВАТНИМИ, публічних політик
--  немає. Що це означає:
--
--   • ЗАЛИВКА працює вже зараз — клієнт ходить через
--     POST /storage/signed-upload, а підписані URL обходять RLS.
--
--   • ЗАВАНТАЖЕННЯ ЗЛАМАЄТЬСЯ, доки клієнт не оновлено: зараз
--     eUploadToStorage (services.dart) повертає getPublicUrl(), а на
--     приватному бакеті такий URL не працює. Потрібен крок 2b —
--     повертати реф 'eion://<bucket>/<path>'; сервер підписує його на
--     віддачі (інфраструктура вже в проді, коміт 0ca913b).
--
--  ТОМУ ПОРЯДОК ТАКИЙ:
--    1) розгорнути цю схему на НОВОМУ проєкті Supabase;
--    2) оновити клієнт (2b) + зібрати білд;
--    3) перемкнути .env/Render на нову базу.
--  Якщо медіа зламалось — аварійний відкат у розділі 8.
-- ═══════════════════════════════════════════════════════════════════

-- ─────────────────────────────────────────────────────────────────
-- 1. ТАБЛИЦІ
-- ─────────────────────────────────────────────────────────────────

create table if not exists public.block_allowlist (
  allowed_nick text NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  owner_nick text NOT NULL,
  primary key (owner_nick, allowed_nick)
);

create table if not exists public.blocked_contacts (
  blocked_at bigint NOT NULL,
  blocked_nick text NOT NULL,
  blocker_nick text NOT NULL,
  id bigserial,
  primary key (id),
  constraint blocked_contacts_blocker_nick_blocked_nick_key unique (blocker_nick, blocked_nick)
);

create table if not exists public.call_logs (
  created_at timestamp without time zone DEFAULT now(),
  duration_seconds integer,
  from_nick text NOT NULL,
  has_video boolean DEFAULT false,
  id integer generated always as identity,
  started_at bigint NOT NULL,
  status text NOT NULL,
  to_nick text NOT NULL,
  primary key (id)
);

create table if not exists public.channel_blocked (
  blocked_at bigint NOT NULL DEFAULT ((EXTRACT(epoch FROM now()))::bigint * 1000),
  channel_id bigint NOT NULL,
  id bigint generated always as identity,
  nick text NOT NULL,
  primary key (id)
);

create table if not exists public.channel_comment_reactions (
  comment_id bigint NOT NULL,
  created_at timestamp with time zone DEFAULT now(),
  emoji text NOT NULL,
  id bigserial,
  nick text NOT NULL,
  primary key (id),
  constraint channel_comment_reactions_comment_id_nick_emoji_key unique (comment_id, nick, emoji)
);

create table if not exists public.channel_comments (
  channel_id bigint NOT NULL,
  content text NOT NULL,
  duration_sec integer,
  edited boolean DEFAULT false,
  edited_at bigint,
  file_data text,
  file_name text,
  from_nick text NOT NULL,
  id bigint generated always as identity,
  post_id bigint NOT NULL,
  read_by text[] NOT NULL DEFAULT '{}'::text[],
  reply_to_id bigint,
  reply_to_image text,
  reply_to_nick text,
  reply_to_text text,
  timestamp bigint NOT NULL DEFAULT ((EXTRACT(epoch FROM now()))::bigint * 1000),
  waveform text,
  primary key (id)
);

create table if not exists public.channel_members (
  channel_id bigint NOT NULL,
  id bigint generated always as identity,
  joined_at bigint NOT NULL DEFAULT ((EXTRACT(epoch FROM now()))::bigint * 1000),
  nick text NOT NULL,
  role text NOT NULL DEFAULT 'subscriber'::text,
  primary key (id)
);

create table if not exists public.channel_messages (
  channel_id bigint NOT NULL,
  comments_enabled boolean DEFAULT true,
  content text,
  duration_sec integer,
  edited boolean DEFAULT false,
  edited_at bigint,
  file_data text,
  file_name text,
  forwarded_from text,
  from_nick text NOT NULL,
  id bigint generated always as identity,
  image_url text,
  msg_id text,
  timestamp bigint NOT NULL,
  type text NOT NULL DEFAULT 'text'::text,
  view_count integer DEFAULT 0,
  waveform text,
  primary key (id)
);

create table if not exists public.channel_paid_subs (
  channel_id bigint NOT NULL,
  expires_at bigint NOT NULL,
  nick text NOT NULL,
  primary key (channel_id, nick)
);

create table if not exists public.channel_post_views (
  created_at timestamp with time zone DEFAULT now(),
  id bigint generated always as identity,
  nick text NOT NULL,
  post_id bigint NOT NULL,
  primary key (id),
  constraint channel_post_views_post_id_nick_key unique (post_id, nick)
);

create table if not exists public.channel_reactions (
  emoji text NOT NULL,
  id bigint generated always as identity,
  nick text NOT NULL,
  post_id bigint NOT NULL,
  primary key (id)
);

create table if not exists public.channels (
  avatar_url text,
  comments_allow_media boolean DEFAULT true,
  contact_price integer DEFAULT 100,
  created_at bigint NOT NULL DEFAULT ((EXTRACT(epoch FROM now()))::bigint * 1000),
  description text,
  id bigint generated always as identity,
  is_paid boolean DEFAULT false,
  last_post_at bigint,
  last_post_text text,
  live_active boolean NOT NULL DEFAULT false,
  live_post_id bigint,
  live_started_at bigint,
  live_url text,
  name text NOT NULL,
  owner_nick text NOT NULL,
  pinned_at bigint,
  pinned_from text,
  pinned_post_id text,
  pinned_text text,
  price integer DEFAULT 0,
  sub_days integer DEFAULT 30,
  type text NOT NULL DEFAULT 'public'::text,
  primary key (id)
);

create table if not exists public.chat_reads (
  chat_id bigint NOT NULL,
  chat_type text NOT NULL,
  last_read_ts bigint NOT NULL DEFAULT 0,
  nick text NOT NULL,
  primary key (nick, chat_type, chat_id)
);

create table if not exists public.coin_transactions (
  amount integer NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  from_nick text,
  id bigserial,
  kind text NOT NULL,
  ref text,
  to_nick text,
  primary key (id)
);

create table if not exists public.deleted_messages (
  created_at timestamp with time zone DEFAULT now(),
  from_nick text NOT NULL,
  id bigint generated always as identity,
  msg_id text NOT NULL,
  to_nick text NOT NULL,
  primary key (id)
);

create table if not exists public.direct_message_reactions (
  created_at timestamp with time zone DEFAULT now(),
  emoji text NOT NULL,
  from_nick text NOT NULL,
  id bigserial,
  msg_id text NOT NULL,
  pair_key text NOT NULL,
  primary key (id),
  constraint direct_message_reactions_msg_id_from_nick_emoji_key unique (msg_id, from_nick, emoji)
);

create table if not exists public.email_codes (
  attempts integer NOT NULL DEFAULT 0,
  code text NOT NULL,
  email text NOT NULL,
  expires_at timestamp with time zone NOT NULL,
  last_sent_at timestamp with time zone,
  nick text NOT NULL,
  primary key (email)
);

create table if not exists public.file_objects (
  created_at bigint NOT NULL,
  downloaded_by text[] NOT NULL DEFAULT '{}'::text[],
  expires_at bigint NOT NULL,
  recipients text[] NOT NULL DEFAULT '{}'::text[],
  storage_path text NOT NULL,
  primary key (storage_path)
);

create table if not exists public.group_bans (
  group_id bigint NOT NULL,
  nick text NOT NULL,
  primary key (group_id, nick)
);

create table if not exists public.group_history_cleared (
  cleared_at bigint NOT NULL DEFAULT 0,
  group_id bigint NOT NULL,
  nick text NOT NULL,
  primary key (nick, group_id)
);

create table if not exists public.group_join_requests (
  created_at timestamp with time zone DEFAULT now(),
  group_id bigint NOT NULL,
  id bigint generated always as identity,
  nick text NOT NULL,
  status text NOT NULL DEFAULT 'pending'::text,
  primary key (id)
);

create table if not exists public.group_members (
  group_id bigint NOT NULL,
  joined_at timestamp with time zone DEFAULT now(),
  nick text NOT NULL,
  role text NOT NULL DEFAULT 'member'::text,
  primary key (group_id, nick)
);

create table if not exists public.group_message_reactions (
  created_at timestamp with time zone DEFAULT now(),
  emoji text NOT NULL,
  group_id bigint NOT NULL,
  id bigserial,
  msg_id text NOT NULL,
  nick text NOT NULL,
  primary key (id),
  constraint group_message_reactions_msg_id_nick_emoji_key unique (msg_id, nick, emoji)
);

create table if not exists public.group_messages (
  content text NOT NULL,
  delivered_to text[] NOT NULL DEFAULT '{}'::text[],
  duration_sec integer,
  file_data text,
  file_name text,
  from_nick text NOT NULL,
  fully_read boolean NOT NULL DEFAULT false,
  group_id bigint NOT NULL,
  id bigint generated always as identity,
  msg_id text,
  read_by text[] NOT NULL DEFAULT '{}'::text[],
  reply_to_from text,
  reply_to_image text,
  reply_to_msg_id text,
  reply_to_text text,
  timestamp bigint NOT NULL,
  type text DEFAULT 'text'::text,
  waveform jsonb,
  primary key (id)
);

create table if not exists public.groups (
  avatar_url text,
  created_at timestamp with time zone DEFAULT now(),
  creator_nick text NOT NULL,
  id bigint generated always as identity,
  name text NOT NULL,
  pinned_at bigint,
  pinned_from text,
  pinned_msg_id text,
  pinned_text text,
  type text NOT NULL DEFAULT 'closed'::text,
  primary key (id)
);

create table if not exists public.messages (
  content text NOT NULL,
  delivered boolean NOT NULL DEFAULT false,
  duration_sec integer,
  file_data text,
  file_name text,
  from_nick text NOT NULL,
  id bigint generated always as identity,
  msg_id text,
  reply_to_from text,
  reply_to_image text,
  reply_to_msg_id text,
  reply_to_text text,
  status text NOT NULL DEFAULT 'sent'::text,
  timestamp bigint NOT NULL DEFAULT ((EXTRACT(epoch FROM now()))::bigint * 1000),
  to_nick text NOT NULL,
  type text NOT NULL DEFAULT 'text'::text,
  waveform text,
  primary key (id)
);

create table if not exists public.pending_channel_invites (
  channel_id bigint NOT NULL,
  id bigint generated always as identity,
  inviter_nick text NOT NULL,
  target_nick text NOT NULL,
  primary key (id)
);

create table if not exists public.pending_group_invites (
  group_id bigint NOT NULL,
  id bigint generated always as identity,
  inviter_nick text NOT NULL,
  target_nick text NOT NULL,
  primary key (id)
);

create table if not exists public.pending_reactions (
  chat_nick text,
  emoji text,
  from_nick text,
  group_id bigint,
  id bigint generated always as identity,
  msg_id text,
  to_nick text,
  primary key (id)
);

create table if not exists public.phone_codes (
  attempts integer NOT NULL DEFAULT 0,
  code text NOT NULL,
  expires_at timestamp with time zone NOT NULL,
  last_sent_at timestamp with time zone NOT NULL DEFAULT now(),
  phone text NOT NULL,
  primary key (phone)
);

create table if not exists public.platform_bans (
  banned_at bigint,
  banned_by text,
  id bigint generated always as identity,
  nick text NOT NULL,
  reason text,
  primary key (id),
  constraint platform_bans_nick_key unique (nick)
);

create table if not exists public.reports (
  context text,
  created_at bigint,
  id bigint generated always as identity,
  reason text,
  reporter_nick text,
  status text DEFAULT 'pending'::text,
  target_nick text,
  primary key (id)
);

create table if not exists public.sticker_packs (
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  id text NOT NULL,
  is_active boolean NOT NULL DEFAULT true,
  preview_sticker text,
  price integer NOT NULL DEFAULT 0,
  sort_order integer NOT NULL DEFAULT 0,
  title text NOT NULL,
  primary key (id)
);

create table if not exists public.user_sticker_packs (
  acquired_at timestamp with time zone NOT NULL DEFAULT now(),
  nick text NOT NULL,
  pack_id text NOT NULL,
  primary key (nick, pack_id)
);

create table if not exists public.users (
  avatar_url text,
  block_incoming boolean NOT NULL DEFAULT false,
  coins integer DEFAULT 50,
  color bigint DEFAULT '4280391411'::bigint,
  email text,
  fcm_device_id text,
  fcm_token text,
  id bigint generated always as identity,
  invisible boolean NOT NULL DEFAULT false,
  nick text NOT NULL,
  nick_color text,
  nick_lower text NOT NULL,
  password_hash text NOT NULL,
  phone text,
  phone_normalized text,
  phone_verified boolean NOT NULL DEFAULT false,
  premium_expires_at timestamp with time zone,
  premium_plan text,
  status text,
  tokens_valid_from bigint,
  primary key (id),
  constraint users_nick_lower_key unique (nick_lower)
);

-- ─────────────────────────────────────────────────────────────────
-- 2. ЗОВНІШНІ КЛЮЧІ (окремо — щоб порядок створення таблиць не заважав)
-- ─────────────────────────────────────────────────────────────────

alter table public.channel_comment_reactions drop constraint if exists channel_comment_reactions_comment_id_fkey;
alter table public.channel_comment_reactions add constraint channel_comment_reactions_comment_id_fkey foreign key (comment_id) references public.channel_comments(id);
alter table public.user_sticker_packs drop constraint if exists user_sticker_packs_pack_id_fkey;
alter table public.user_sticker_packs add constraint user_sticker_packs_pack_id_fkey foreign key (pack_id) references public.sticker_packs(id);

-- ─────────────────────────────────────────────────────────────────
-- 3. ІНДЕКСИ (без тих, що створюються автоматично для PK/UNIQUE)
-- ─────────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_blocked_contacts_blocker ON public.blocked_contacts USING btree (blocker_nick);
CREATE INDEX IF NOT EXISTS idx_call_logs_from_to_ts ON public.call_logs USING btree (from_nick, to_nick, started_at);
CREATE INDEX IF NOT EXISTS idx_call_logs_to_from_ts ON public.call_logs USING btree (to_nick, from_nick, started_at);
CREATE INDEX IF NOT EXISTS idx_ccr_comment ON public.channel_comment_reactions USING btree (comment_id);
CREATE INDEX IF NOT EXISTS idx_ccr_nick ON public.channel_comment_reactions USING btree (nick);
CREATE INDEX IF NOT EXISTS idx_channel_members_channel ON public.channel_members USING btree (channel_id);
CREATE INDEX IF NOT EXISTS idx_channel_members_nick ON public.channel_members USING btree (nick);
CREATE INDEX IF NOT EXISTS chat_reads_nick_type_idx ON public.chat_reads USING btree (nick, chat_type);
CREATE INDEX IF NOT EXISTS idx_coin_tx_kind ON public.coin_transactions USING btree (kind, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_coin_tx_to ON public.coin_transactions USING btree (to_nick, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dmr_pair ON public.direct_message_reactions USING btree (pair_key, msg_id);
CREATE INDEX IF NOT EXISTS idx_group_members_group ON public.group_members USING btree (group_id);
CREATE INDEX IF NOT EXISTS idx_group_members_nick ON public.group_members USING btree (nick);
CREATE INDEX IF NOT EXISTS idx_gmr_group_msg ON public.group_message_reactions USING btree (group_id, msg_id);
CREATE INDEX IF NOT EXISTS idx_group_messages_group_ts ON public.group_messages USING btree (group_id, "timestamp");
CREATE INDEX IF NOT EXISTS idx_group_messages_msg_id ON public.group_messages USING btree (msg_id);
CREATE INDEX IF NOT EXISTS idx_messages_from_nick ON public.messages USING btree (from_nick);
CREATE INDEX IF NOT EXISTS idx_messages_msg_id ON public.messages USING btree (msg_id);
CREATE INDEX IF NOT EXISTS idx_messages_pair_ts ON public.messages USING btree (from_nick, to_nick, "timestamp");
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON public.messages USING btree ("timestamp");
CREATE INDEX IF NOT EXISTS idx_messages_to_delivered ON public.messages USING btree (to_nick, delivered);
CREATE INDEX IF NOT EXISTS idx_messages_to_nick ON public.messages USING btree (to_nick);
CREATE INDEX IF NOT EXISTS idx_users_nick_lower ON public.users USING btree (nick_lower);

-- ─────────────────────────────────────────────────────────────────
-- 4. SQL-ФУНКЦІЇ (атомарні операції з монетами)
-- ─────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION public.add_coins(p_nick text, p_amount integer)
 RETURNS integer
 LANGUAGE plpgsql
AS $function$
declare
  new_balance int;
begin
  update users
    set coins = coins + p_amount
    where nick = p_nick
    returning coins into new_balance;
  -- null якщо користувача нема (напр. неіснуючий eion_company)
  return new_balance;
end;
$function$
;

CREATE OR REPLACE FUNCTION public.spend_coins(p_nick text, p_amount integer)
 RETURNS integer
 LANGUAGE plpgsql
AS $function$
declare
  new_balance int;
begin
  -- Атомарно: списуємо тільки якщо монет достатньо.
  -- Рядок блокується на час операції, тож паралельні виклики не зіпсують баланс.
  update users
    set coins = coins - p_amount
    where nick = p_nick
      and coins >= p_amount
    returning coins into new_balance;

  if new_balance is null then
    -- або користувача нема, або недостатньо монет
    return -1;
  end if;

  return new_balance;
end;
$function$
;

-- ─────────────────────────────────────────────────────────────────
-- 5. ROW LEVEL SECURITY
-- ─────────────────────────────────────────────────────────────────

alter table public.block_allowlist enable row level security;
alter table public.blocked_contacts enable row level security;
alter table public.call_logs enable row level security;
alter table public.channel_blocked enable row level security;
alter table public.channel_comment_reactions enable row level security;
alter table public.channel_comments enable row level security;
alter table public.channel_members enable row level security;
alter table public.channel_messages enable row level security;
alter table public.channel_paid_subs enable row level security;
alter table public.channel_post_views enable row level security;
alter table public.channel_reactions enable row level security;
alter table public.channels enable row level security;
alter table public.chat_reads enable row level security;
alter table public.coin_transactions enable row level security;
alter table public.deleted_messages enable row level security;
alter table public.direct_message_reactions enable row level security;
alter table public.email_codes enable row level security;
alter table public.file_objects enable row level security;
alter table public.group_bans enable row level security;
alter table public.group_history_cleared enable row level security;
alter table public.group_join_requests enable row level security;
alter table public.group_members enable row level security;
alter table public.group_message_reactions enable row level security;
alter table public.group_messages enable row level security;
alter table public.groups enable row level security;
alter table public.messages enable row level security;
alter table public.pending_channel_invites enable row level security;
alter table public.pending_group_invites enable row level security;
alter table public.pending_reactions enable row level security;
alter table public.phone_codes enable row level security;
alter table public.platform_bans enable row level security;
alter table public.reports enable row level security;
alter table public.sticker_packs enable row level security;
alter table public.user_sticker_packs enable row level security;
alter table public.users enable row level security;

-- ─────────────────────────────────────────────────────────────────
-- 6. ПОЛІТИКИ RLS (public + storage)
-- ─────────────────────────────────────────────────────────────────

drop policy if exists "service_all" on public.call_logs;
create policy "service_all" on public.call_logs
  for all
  to service_role
  using (true)
  with check (true);

drop policy if exists "service_all" on public.channel_blocked;
create policy "service_all" on public.channel_blocked
  for all
  to service_role
  using (true)
  with check (true);

drop policy if exists "service_all" on public.channel_comments;
create policy "service_all" on public.channel_comments
  for all
  to service_role
  using (true)
  with check (true);

drop policy if exists "service_all" on public.channel_members;
create policy "service_all" on public.channel_members
  for all
  to service_role
  using (true)
  with check (true);

drop policy if exists "service_all" on public.channel_messages;
create policy "service_all" on public.channel_messages
  for all
  to service_role
  using (true)
  with check (true);

drop policy if exists "service_all" on public.channel_reactions;
create policy "service_all" on public.channel_reactions
  for all
  to service_role
  using (true)
  with check (true);

drop policy if exists "service_all" on public.channels;
create policy "service_all" on public.channels
  for all
  to service_role
  using (true)
  with check (true);

drop policy if exists "service_all" on public.deleted_messages;
create policy "service_all" on public.deleted_messages
  for all
  to service_role
  using (true)
  with check (true);

drop policy if exists "service_all" on public.group_bans;
create policy "service_all" on public.group_bans
  for all
  to service_role
  using (true)
  with check (true);

drop policy if exists "service_all" on public.group_join_requests;
create policy "service_all" on public.group_join_requests
  for all
  to service_role
  using (true)
  with check (true);

drop policy if exists "service_all" on public.group_members;
create policy "service_all" on public.group_members
  for all
  to service_role
  using (true)
  with check (true);

drop policy if exists "service_all" on public.group_messages;
create policy "service_all" on public.group_messages
  for all
  to service_role
  using (true)
  with check (true);

drop policy if exists "service_all" on public.groups;
create policy "service_all" on public.groups
  for all
  to service_role
  using (true)
  with check (true);

drop policy if exists "service_all" on public.messages;
create policy "service_all" on public.messages
  for all
  to service_role
  using (true)
  with check (true);

drop policy if exists "service_all" on public.pending_channel_invites;
create policy "service_all" on public.pending_channel_invites
  for all
  to service_role
  using (true)
  with check (true);

drop policy if exists "service_all" on public.pending_group_invites;
create policy "service_all" on public.pending_group_invites
  for all
  to service_role
  using (true)
  with check (true);

drop policy if exists "service_all" on public.pending_reactions;
create policy "service_all" on public.pending_reactions
  for all
  to service_role
  using (true)
  with check (true);

drop policy if exists "service_all" on public.platform_bans;
create policy "service_all" on public.platform_bans
  for all
  to service_role
  using (true)
  with check (true);

drop policy if exists "service_all" on public.reports;
create policy "service_all" on public.reports
  for all
  to service_role
  using (true)
  with check (true);

drop policy if exists "service_all" on public.users;
create policy "service_all" on public.users
  for all
  to service_role
  using (true)
  with check (true);

-- пропущено (захищений режим): "Auth update avatars" on storage.objects — була "to public"
-- пропущено (захищений режим): "Auth upload avatars" on storage.objects — була "to public"
-- пропущено (захищений режим): "Auth upload files" on storage.objects — була "to public"
-- ─────────────────────────────────────────────────────────────────
-- 7. ПРАВА (GRANT)
--    Сервер ходить service-ключем. anon/authenticated навмисно без прав
--    на службові таблиці — див. аудит #11 (revoke_anon_grants).
-- ─────────────────────────────────────────────────────────────────

grant delete, insert, references, select, trigger, truncate, update on table public.block_allowlist to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.block_allowlist to service_role;
grant delete, insert, references, select, trigger, truncate, update on table public.blocked_contacts to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.blocked_contacts to service_role;
grant references, trigger, truncate on table public.call_logs to anon;
grant references, trigger, truncate on table public.call_logs to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.call_logs to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.call_logs to service_role;
grant references, trigger, truncate on table public.channel_blocked to anon;
grant references, trigger, truncate on table public.channel_blocked to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.channel_blocked to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.channel_blocked to service_role;
grant references, trigger, truncate on table public.channel_comment_reactions to anon;
grant references, trigger, truncate on table public.channel_comment_reactions to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.channel_comment_reactions to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.channel_comment_reactions to service_role;
grant references, trigger, truncate on table public.channel_comments to anon;
grant references, trigger, truncate on table public.channel_comments to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.channel_comments to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.channel_comments to service_role;
grant references, trigger, truncate on table public.channel_members to anon;
grant references, trigger, truncate on table public.channel_members to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.channel_members to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.channel_members to service_role;
grant references, trigger, truncate on table public.channel_messages to anon;
grant references, trigger, truncate on table public.channel_messages to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.channel_messages to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.channel_messages to service_role;
grant references, trigger, truncate on table public.channel_paid_subs to anon;
grant references, trigger, truncate on table public.channel_paid_subs to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.channel_paid_subs to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.channel_paid_subs to service_role;
grant delete, insert, references, select, trigger, truncate, update on table public.channel_post_views to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.channel_post_views to service_role;
grant references, trigger, truncate on table public.channel_reactions to anon;
grant references, trigger, truncate on table public.channel_reactions to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.channel_reactions to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.channel_reactions to service_role;
grant references, trigger, truncate on table public.channels to anon;
grant references, trigger, truncate on table public.channels to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.channels to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.channels to service_role;
grant delete, insert, references, select, trigger, truncate, update on table public.chat_reads to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.chat_reads to service_role;
grant delete, insert, references, select, trigger, truncate, update on table public.coin_transactions to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.coin_transactions to service_role;
grant references, trigger, truncate on table public.deleted_messages to anon;
grant references, trigger, truncate on table public.deleted_messages to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.deleted_messages to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.deleted_messages to service_role;
grant references, trigger, truncate on table public.direct_message_reactions to anon;
grant references, trigger, truncate on table public.direct_message_reactions to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.direct_message_reactions to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.direct_message_reactions to service_role;
grant delete, insert, references, select, trigger, truncate, update on table public.email_codes to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.email_codes to service_role;
grant delete, insert, references, select, trigger, truncate, update on table public.file_objects to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.file_objects to service_role;
grant references, trigger, truncate on table public.group_bans to anon;
grant references, trigger, truncate on table public.group_bans to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.group_bans to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.group_bans to service_role;
grant references, trigger, truncate on table public.group_history_cleared to anon;
grant references, trigger, truncate on table public.group_history_cleared to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.group_history_cleared to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.group_history_cleared to service_role;
grant references, trigger, truncate on table public.group_join_requests to anon;
grant references, trigger, truncate on table public.group_join_requests to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.group_join_requests to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.group_join_requests to service_role;
grant references, trigger, truncate on table public.group_members to anon;
grant references, trigger, truncate on table public.group_members to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.group_members to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.group_members to service_role;
grant references, trigger, truncate on table public.group_message_reactions to anon;
grant references, trigger, truncate on table public.group_message_reactions to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.group_message_reactions to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.group_message_reactions to service_role;
grant references, trigger, truncate on table public.group_messages to anon;
grant references, trigger, truncate on table public.group_messages to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.group_messages to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.group_messages to service_role;
grant references, trigger, truncate on table public.groups to anon;
grant references, trigger, truncate on table public.groups to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.groups to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.groups to service_role;
grant references, trigger, truncate on table public.messages to anon;
grant references, trigger, truncate on table public.messages to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.messages to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.messages to service_role;
grant references, trigger, truncate on table public.pending_channel_invites to anon;
grant references, trigger, truncate on table public.pending_channel_invites to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.pending_channel_invites to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.pending_channel_invites to service_role;
grant references, trigger, truncate on table public.pending_group_invites to anon;
grant references, trigger, truncate on table public.pending_group_invites to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.pending_group_invites to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.pending_group_invites to service_role;
grant references, trigger, truncate on table public.pending_reactions to anon;
grant references, trigger, truncate on table public.pending_reactions to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.pending_reactions to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.pending_reactions to service_role;
grant delete, insert, references, select, trigger, truncate, update on table public.phone_codes to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.phone_codes to service_role;
grant references, trigger, truncate on table public.platform_bans to anon;
grant references, trigger, truncate on table public.platform_bans to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.platform_bans to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.platform_bans to service_role;
grant references, trigger, truncate on table public.reports to anon;
grant references, trigger, truncate on table public.reports to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.reports to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.reports to service_role;
grant delete, insert, references, select, trigger, truncate, update on table public.sticker_packs to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.sticker_packs to service_role;
grant delete, insert, references, select, trigger, truncate, update on table public.user_sticker_packs to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.user_sticker_packs to service_role;
grant references, trigger, truncate on table public.users to anon;
grant references, trigger, truncate on table public.users to authenticated;
grant delete, insert, references, select, trigger, truncate, update on table public.users to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.users to service_role;

-- ─────────────────────────────────────────────────────────────────
-- 8. STORAGE — бакети
-- ─────────────────────────────────────────────────────────────────

insert into storage.buckets (id, name, public) values ('avatars', 'avatars', false)
  on conflict (id) do update set public = false;
insert into storage.buckets (id, name, public) values ('files', 'files', false)
  on conflict (id) do update set public = false;

-- Явна політика для сервера. service_role і так обходить RLS — тримаємо
-- її заради читабельності: видно, що доступ має ЛИШЕ сервер.
drop policy if exists "service_all_objects" on storage.objects;
create policy "service_all_objects" on storage.objects
  for all to service_role using (true) with check (true);

-- ⚠️ АВАРІЙНИЙ ВІДКАТ (якщо медіа зламалось, а клієнт ще не оновлено).
--    Повертає стару, НЕБЕЗПЕЧНУ поведінку — публічні бакети:
-- update storage.buckets set public = true where id in ('files','avatars');

-- ─────────────────────────────────────────────────────────────────
-- 9. SEED — системний акаунт EION
--    Пароль НЕ задається тут: зареєструвати EION через застосунок,
--    після чого виконати update нижче (невидимість + блок вхідних).
-- ─────────────────────────────────────────────────────────────────

-- update public.users set invisible = true, block_incoming = true
--   where nick = 'EION';

-- Памʼять відповідей асистента.
--
-- Питання, що повторюються («як створити канал», «скільки коштує преміум»),
-- не мають щоразу коштувати виклику моделі. Відповідь на таке питання
-- зберігається і віддається наступному, хто спитав те саме.
--
-- ⚠️ Кеш СПІЛЬНИЙ для всіх користувачів, тому в нього потрапляє лише те, що
-- не може містити приватного: перше питання розмови, без цифр, пошти й
-- посилань, відповідь без жодного виклику інструментів і без ніка того, хто
-- питав. Правила — у server.js, `cacheEligible`.
create table if not exists public.ai_cache (
  key        text primary key,     -- відбиток мови + нормалізоване питання
  question   text not null,
  answer     text not null,
  model      text,
  hits       integer not null default 0,
  created_at bigint  not null,
  last_used  bigint  not null
);
create index if not exists ai_cache_last_used_idx on public.ai_cache (last_used);

alter table public.ai_cache enable row level security;

grant delete, insert, references, select, trigger, truncate, update on table public.ai_cache to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.ai_cache to service_role;

-- База знань асистента: наш шар відповідей перед провайдером.
--
-- Було: точний збіг питання (`ai_cache`). Інакше сформульоване питання
-- («як мені зробити канал» проти «як створити канал») вважалось новим і знову
-- йшло в модель.
--
-- Стало три джерела в одній таблиці:
--   source='model'   — відповідь, яку колись дала модель. Віддається дослівно
--                      лише при дуже високій схожості й лише в межах тієї
--                      самої мови інтерфейсу (lang_fp).
--   source='curated' — відповідь, написана НАМИ. Дослівно не віддається
--                      ніколи: підмішується в контекст, щоб модель відповіла
--                      нашими фактами й мовою користувача.
--
-- Пошук — по триграмах (pg_trgm, усередині Postgres, без зовнішніх сервісів).
-- ⚠️ Триграми порівнюють ЛІТЕРИ, а не зміст: «видалити акаунт» і «стерти
-- профіль» вони не зіставлять. Тому поріг прямої видачі високий, а середні
-- збіги йдуть лише в контекст. Смисловий пошук — це ембединги + pgvector,
-- окремий крок.
create extension if not exists pg_trgm;

alter table public.ai_cache add column if not exists lang_fp text not null default '';
alter table public.ai_cache add column if not exists source  text not null default 'model';
alter table public.ai_cache add column if not exists enabled boolean not null default true;

create index if not exists ai_cache_question_trgm on public.ai_cache using gin (question gin_trgm_ops);
create index if not exists ai_cache_source_idx on public.ai_cache (source);

-- Пошук схожого. Повертає і наші записи (будь-яка мова), і модельні —
-- але лише тієї самої мови інтерфейсу, бо їх можна віддати дослівно.
create or replace function public.ai_kb_search(p_fp text, p_query text, p_limit int default 4)
returns table (key text, question text, answer text, source text, same_lang boolean, sim real)
language sql stable as $$
  select c.key, c.question, c.answer, c.source,
         (c.lang_fp = p_fp) as same_lang,
         similarity(c.question, p_query) as sim
    from public.ai_cache c
   where c.enabled
     and (c.source = 'curated' or c.lang_fp = p_fp)
     and c.question % p_query
   order by sim desc
   limit p_limit;
$$;

grant execute on function public.ai_kb_search(text, text, int) to postgres, service_role;
