-- Сінки, що покривають реальні витрати (токеноміка §4-A), і облік спалювання.
--
-- Досі монети могли лише текти на службовий рахунок і накопичуватись там.
-- Тепер частина кожного платежу знищується: пропозиція зменшується, а рахунок
-- компанії не перетворюється з часом на власника більшості монет.

-- ── Облік пропозиції ──────────────────────────────────────────────────────
create table if not exists public.coin_supply (
  id         int  primary key default 1,
  minted     bigint not null default 0,   -- видано з фондів (нагороди тощо)
  burned     bigint not null default 0,   -- знищено назавжди
  updated_at timestamptz not null default now(),
  constraint coin_supply_single_row check (id = 1)
);
insert into public.coin_supply (id) values (1) on conflict (id) do nothing;

-- Спалювання: атомарно збільшує лічильник. Самі монети вже списані зі
-- спендера — сюди вони просто не доходять до жодного рахунку.
create or replace function public.burn_coins(p_amount integer)
returns bigint
language plpgsql
as $$
declare v_total bigint;
begin
  if p_amount is null or p_amount <= 0 then
    select burned into v_total from public.coin_supply where id = 1;
    return v_total;
  end if;
  update public.coin_supply
     set burned = burned + p_amount, updated_at = now()
   where id = 1
  returning burned into v_total;
  return v_total;
end;
$$;

-- ── Денні квоти на дорогі операції ────────────────────────────────────────
-- AI-запити коштують нам грошей у Groq, тож понад безкоштовну норму платні.
create table if not exists public.usage_counters (
  nick   text    not null,
  kind   text    not null,          -- 'ai' | 'storage' | 'turn'
  day    date    not null,
  used   integer not null default 0,
  primary key (nick, kind, day)
);
create index if not exists usage_counters_day_idx on public.usage_counters (day);

alter table public.coin_supply enable row level security;
alter table public.usage_counters enable row level security;

grant delete, insert, references, select, trigger, truncate, update on table public.coin_supply to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.coin_supply to service_role;
grant delete, insert, references, select, trigger, truncate, update on table public.usage_counters to postgres;
grant delete, insert, references, select, trigger, truncate, update on table public.usage_counters to service_role;
grant execute on function public.burn_coins(integer) to postgres, service_role;
