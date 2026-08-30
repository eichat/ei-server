-- Надходження токена: людина надсилає токени на гаманець обміну, ми зараховуємо бали.
--
-- Ідентифікація без memo: відправника впізнаємо за адресою, яку він сам вказав
-- у профілі. Це і робить прив'язку адреси осмисленою — вона потрібна для обох
-- напрямків, а не лише для показу балансу.
--
-- signature — первинний ключ, і саме він дає ідемпотентність: сканер може
-- бачити ту саму транзакцію скільки завгодно разів, зарахування станеться раз.
create table if not exists public.token_deposits (
  signature text primary key,
  nick text,                      -- null = відправник не впізнаний (адреса не прив'язана)
  address text not null,          -- звідки прийшло
  tokens numeric not null,
  coins integer not null default 0,
  slot bigint,
  status text not null default 'credited',   -- credited | unmatched
  created_at timestamptz not null default now()
);
create index if not exists token_deposits_nick_idx on public.token_deposits (nick, created_at desc);

alter table public.token_deposits enable row level security;
revoke all on table public.token_deposits from anon, authenticated;
grant all on table public.token_deposits to postgres, service_role;
