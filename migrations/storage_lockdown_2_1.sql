-- Аудит безпеки #2, крок 2.1 — прибрати перелік (list) файлів anon-ключем.
-- Виконано в Supabase → SQL Editor 28.07.2026.
--
-- Було: політики "Public read files"/"Public read avatars" (cmd=SELECT, role=public)
-- дозволяли anon-ключу (він у APK) робити POST /storage/v1/object/list/<bucket>
-- і перелічувати структуру direct/<нік>/…, group/…, channel/… — мапа всіх файлів
-- усіх користувачів (звідти масове скачування за публічними URL).
--
-- Клієнт НІКОЛИ не списує Storage (лише uploadBinary + getPublicUrl) — перевірено,
-- тож прибрати SELECT безпечно. Публічне скачування (getPublicUrl) НЕ залежить від
-- цієї політики — воно йде через bucket.public=true (окремий механізм), лишається.
--
-- Перевірено з прода anon-ключем: до — list вертав структуру; після — list вертає [].
-- Заливка (INSERT) і upsert аватара (UPDATE) не зачеплені (їх політики лишились).

DROP POLICY IF EXISTS "Public read files"   ON storage.objects;
DROP POLICY IF EXISTS "Public read avatars" ON storage.objects;

-- ЩЕ НЕ ЗРОБЛЕНО (потребують білду клієнта):
--  2.2 — заливка через підписані upload-URL (сервер, service-ключ) → тоді
--        видалити INSERT-політики "Auth upload files/avatars" (зараз anon може
--        заливати довільні файли).
--  2.3 — bucket.public=false + підписані download-URL з TTL (зараз, знаючи точний
--        шлях, файл качається публічно без ключа; перелік уже закрито, тож шлях
--        треба вгадати: direct/<нік>/<ts_ms>/<файл>).
