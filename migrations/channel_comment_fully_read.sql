-- Сині ✓✓ у коментарях каналу: коментар бачили всі теперішні підписники,
-- крім автора. Ставиться один раз і не знімається.
alter table public.channel_comments
  add column if not exists fully_read boolean not null default false;
