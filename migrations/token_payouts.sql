-- Заявки на виплату токена за внутрішні бали.
--
-- Навіщо окрема таблиця, а не просто «списали й надіслали»: між списанням балів
-- і підтвердженням транзакції в мережі є проміжок, у якому процес може впасти.
-- Без запису ми не знали б, чи гроші пішли — і при повторі надіслали б удвічі
-- або мовчки з'їли б бали. Тут кожна заявка має стан і підпис транзакції, тож
-- незавершену завжди можна доперевірити в блокчейні.
create table if not exists public.token_payouts (
  id bigserial primary key,
  nick text not null,
  address text not null,          -- куди надсилали (фіксуємо: адресу можна змінити пізніше)
  coins integer not null,         -- скільки балів списано
  tokens numeric not null,        -- скільки токенів має піти
  status text not null default 'pending',  -- pending | sent | failed | refunded
  signature text,                 -- підпис транзакції: з ним стан перевіряється в мережі
  error text,
  created_at timestamptz not null default now(),
  sent_at timestamptz
);
create index if not exists token_payouts_nick_idx on public.token_payouts (nick, created_at desc);
create index if not exists token_payouts_pending_idx on public.token_payouts (status) where status = 'pending';

alter table public.token_payouts enable row level security;
revoke all on table public.token_payouts from anon, authenticated;
grant all on table public.token_payouts to postgres, service_role;
grant usage, select on sequence public.token_payouts_id_seq to postgres, service_role;
