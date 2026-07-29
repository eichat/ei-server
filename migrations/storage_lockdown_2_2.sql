-- Аудит безпеки #2, крок 2.2 — заборонити anon-ключу ЗАЛИВАТИ файли.
--
-- ⚠️ ЗАПУСКАТИ ЛИШЕ ПІСЛЯ того, як НОВИЙ клієнт (з eUploadToStorage → підписані
--    upload-URL) зібрано, встановлено й перевірено. Старий клієнт заливає напряму
--    anon-ключем — цей revoke ЗЛАМАЄ йому надсилання файлів/аватарів/наліпок.
--
-- Контекст: раніше клієнт робив supabase.storage.from(b).uploadBinary() напряму
-- anon-ключем (він у APK). Це дозволяло будь-кому заливати/перезаписувати довільні
-- файли. Тепер заливка йде через POST /storage/signed-upload (сервер, service-ключ)
-- → uploadBinaryToSignedUrl. Підписаний токен авторизується service-роллю й ОБХОДИТЬ
-- RLS, тож прибирання anon INSERT-політик НЕ ламає новий шлях заливки.
--
-- Перелік (list) уже закрито в storage_lockdown_2_1.sql. Публічне скачування
-- (getPublicUrl / bucket.public=true) лишається — це крок 2.3 (приватні бакети +
-- підписані download-URL), окремо, теж потребує клієнта.
--
-- ⚠️ НАЗВИ ПОЛІТИК: підставлені орієнтовні. ПЕРЕД запуском звірити фактичні назви
--    у Supabase → Storage → Policies (cmd = INSERT, roles = anon/authenticated/public)
--    і за потреби виправити рядки нижче.

-- INSERT-політики, що дозволяли заливку anon-ключем:
DROP POLICY IF EXISTS "Auth upload files"   ON storage.objects;
DROP POLICY IF EXISTS "Auth upload avatars" ON storage.objects;

-- Якщо існують окремі UPDATE-політики для upsert (перезапис) anon-ключем —
-- їх теж прибрати (upsert підписаного URL іде через service-роль, не через них):
-- DROP POLICY IF EXISTS "Auth update files"   ON storage.objects;
-- DROP POLICY IF EXISTS "Auth update avatars" ON storage.objects;

-- Перевірка після запуску (з прода, anon-ключем):
--   POST /storage/v1/object/files/<будь-який шлях> з anon → має бути 403.
--   Заливка через новий клієнт (підписаний URL) → має працювати.
