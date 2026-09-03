-- Догін правок повідомлень для того, хто був офлайн.
--
-- Причина: сервер оновлював текст у себе, але сповіщав адресата ЛИШЕ наживо
-- (`sendToUser`). Якщо той був офлайн, правка не доходила вже ніколи — у нього
-- назавжди лишався старий текст, а надто помітно це стало з підписами до
-- медіа, які можна редагувати.
--
-- Позначка часу правки, а не окрема черга: черга потребувала б доставки й
-- прибирання, а часова мітка самовідновлювана — клієнт питає «що змінилось
-- після ts» і наздоганяє навіть кілька пропущених входів.
alter table public.messages       add column if not exists edited_at bigint;
alter table public.group_messages add column if not exists edited_at bigint;

-- Часткові індекси: рядків із правками одиниці на тисячі звичайних, тож повний
-- індекс був би платою за те, чого майже немає.
create index if not exists messages_edited_idx
  on public.messages (to_nick, edited_at) where edited_at is not null;
create index if not exists group_messages_edited_idx
  on public.group_messages (group_id, edited_at) where edited_at is not null;
