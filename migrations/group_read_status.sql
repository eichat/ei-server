-- Групові read-статуси («переглянуто лише коли ВСІ учасники прочитали»).
-- read_by  — ніки учасників, що вже прочитали повідомлення.
-- fully_read — true, коли прочитали ВСІ, крім автора (кешований прапорець
--              для дешевого читання в історії, щоб не рахувати щоразу).
-- Нових таблиць немає → окремий GRANT не потрібен (стовпці успадковують права).
ALTER TABLE group_messages ADD COLUMN IF NOT EXISTS read_by text[] NOT NULL DEFAULT '{}';
ALTER TABLE group_messages ADD COLUMN IF NOT EXISTS fully_read boolean NOT NULL DEFAULT false;
