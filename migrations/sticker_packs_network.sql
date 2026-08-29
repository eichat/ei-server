-- Наліпки з мережі замість вбудованих у застосунок.
--
-- Було: мапа packId → шлях до asset у коді клієнта. Тобто новий пак вимагав
-- нової збірки й оновлення в усіх; магазин міг показувати пак, якого в
-- застосунку немає, і куплений пак виглядав би як «зображення недоступне».
--
-- Стало: файли в бакеті `stickers`, склад пака — у цій таблиці.
create table if not exists public.sticker_pack_items (
  pack_id      text    not null,
  sticker_id   text    not null,
  storage_path text    not null,               -- шлях у бакеті stickers
  kind         text    not null default 'lottie', -- 'lottie' (json) | 'image' (webp/png)
  sort_order   integer not null default 0,
  created_at   timestamptz not null default now(),
  primary key (pack_id, sticker_id)
);

alter table public.sticker_pack_items
  drop constraint if exists sticker_pack_items_pack_fkey;
alter table public.sticker_pack_items
  add constraint sticker_pack_items_pack_fkey
  foreign key (pack_id) references public.sticker_packs(id) on delete cascade;

create index if not exists sticker_pack_items_pack_idx
  on public.sticker_pack_items (pack_id, sort_order);

-- RLS: клієнт до таблиці не ходить, усе через сервер (service_role обходить RLS).
alter table public.sticker_pack_items enable row level security;

-- Гранти лише службові — anon/authenticated не потрібні (урок аудиту #21).
grant delete, insert, references, select, trigger, truncate, update
  on table public.sticker_pack_items to postgres;
grant delete, insert, references, select, trigger, truncate, update
  on table public.sticker_pack_items to service_role;

-- Бакет наліпок ПУБЛІЧНИЙ, на відміну від files/avatars: це статичний контент
-- магазину, однаковий для всіх і без персональних даних. Публічність дає
-- кешування на боці клієнта й прибирає потребу підписувати кожен файл.
insert into storage.buckets (id, name, public) values ('stickers', 'stickers', true)
  on conflict (id) do update set public = true;

-- Читання — усім; запис — лише service_role (сервер).
drop policy if exists "stickers_public_read" on storage.objects;
create policy "stickers_public_read" on storage.objects
  for select using (bucket_id = 'stickers');
