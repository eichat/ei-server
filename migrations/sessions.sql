-- Фаза 1 аудиту безпеки: сесійні токени (замість довіри ніку з тіла запиту).
-- Токен — непрозорий crypto.randomBytes(32).hex, видається /login, зберігається
-- тут для персистентності між рестартами сервера (в пам'яті — Map sessions).
-- ГРАНТИ навмисно ЛИШЕ service_role (+postgres для SQL Editor): токени — секрет,
-- anon/authenticated НЕ повинні їх бачити (на відміну від старої інструкції
-- «GRANT ALL … TO anon» — див. аудит #11). Сервер ходить service-ключем.
CREATE TABLE IF NOT EXISTS sessions (
  token       text PRIMARY KEY,
  nick        text NOT NULL,
  device_id   text,
  created_at  bigint NOT NULL,
  last_seen   bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_nick_idx ON sessions(nick);
GRANT ALL ON TABLE sessions TO postgres, service_role;
