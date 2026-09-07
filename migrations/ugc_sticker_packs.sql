-- Користувацькі набори наліпок із винагородою автору.
--
-- UGC-паки живуть у ТІЙ САМІЙ таблиці, що й офіційні (`sticker_packs`), а не в
-- окремій: магазин, купівля, володіння й склад (`sticker_pack_items`) уже
-- працюють із нею. Друга таблиця означала б два кодових шляхи в кожному з цих
-- місць — тобто рівно те, через що в нас уже розходились чотири екрани чатів.
--
-- Відрізняє UGC від офіційного лише `author_nick`: not null → пак створив
-- користувач, і 70% ціни йдуть йому.

alter table public.sticker_packs
  add column if not exists author_nick   text,
  -- 'approved' | 'pending' | 'rejected'. Дефолт 'approved' — щоб наявні
  -- офіційні паки лишились у магазині без окремого UPDATE.
  add column if not exists status        text not null default 'approved',
  add column if not exists reject_reason text,
  add column if not exists submitted_at  bigint,
  add column if not exists reviewed_at   bigint,
  add column if not exists reviewed_by   text;

-- Лічильника продажів тут навмисно НЕМАЄ: він рахується з `user_sticker_packs`
-- (кількість власників пака). Інкремент при купівлі був би зайвим станом, який
-- може розійтися з дійсністю при гонці двох паралельних покупок.

-- Черга модерації: беремо pending за часом подачі.
create index if not exists sticker_packs_status_idx
  on public.sticker_packs (status, submitted_at);
-- «Мої паки» автора.
create index if not exists sticker_packs_author_idx
  on public.sticker_packs (author_nick);

-- Гранти НЕ додаємо: таблиця вже існує, а розширення колонок прав не міняє.
-- Для anon/authenticated їх тут немає й бути не повинно (аудит #21).

-- Кроп наліпки. UGC-наліпку роблять із фото, обрізаючи його рамкою, і сам
-- кроп — це три числа (масштаб + зсув у ДОЛЯХ розміру), а не растрове
-- вирізання: та сама формула дає однаковий вигляд при будь-якому розмірі
-- показу. Без цих колонок покупець бачив би НЕОБРІЗАНЕ вихідне фото, тобто
-- не те, що автор поклав у набір.
alter table public.sticker_pack_items
  add column if not exists crop_scale real not null default 1,
  add column if not exists crop_dx    real not null default 0,
  add column if not exists crop_dy    real not null default 0;
