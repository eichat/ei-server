-- FCM-токени пережили рестарт сервера.
--
-- Було: fcmTokens/nickDevices — звичайні Map у пам'яті процесу. Кожен деплой
-- на Render (а він трапляється й від правки локалей) обнуляв їх, і пуші
-- замовкали. Відновити токен міг лише сам клієнт при WS-логіні — але клієнт,
-- якому потрібен пуш, за визначенням офлайн і залогінитись не може.
--
-- Стало: токен лежить у users і читається на вимогу, а пам'ять лишається
-- кешем. GRANT — лише service_role (аудит #21: новим колонкам anon не треба).
alter table public.users add column if not exists fcm_token text;
alter table public.users add column if not exists fcm_device_id text;
