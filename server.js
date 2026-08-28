const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');
const admin = require('firebase-admin');
const https = require('https');
const httpModule = require('http');
const crypto = require('crypto');
const net = require('net');
const dnsp = require('dns').promises;

const app = express();
// Системний акаунт компанії — сюди надходить комісія з платних операцій
// (контакти власників каналів, платні підписки). Єдина точка істини, щоб
// різні endpoint не розходились. Має відповідати реальному ніку в таблиці users.
const COMPANY_NICK = 'EION';

// Перевірка адмін-привілею: секрет із заголовка X-Admin-Secret проти
// EION_ADMIN_SECRET (змінна оточення Render — НЕ в коді, НЕ в БД). Нік
// підробити легко, секрет — ні. Якщо секрет не налаштовано → нікому не адмін
// (безпечний дефолт). Це єдине джерело правди для всіх привілейованих дій.
function isAdmin(req) {
  const secret = process.env.EION_ADMIN_SECRET;
  if (!secret) return false;
  const provided = req.headers['x-admin-secret'];
  return typeof provided === 'string' && provided.length > 0 && provided === secret;
}
// Комісія за переказ монет між користувачами (%). Відраховується ІЗ суми
// (отримувач отримує менше), решта → COMPANY_NICK. Керований параметр:
// 0 = без комісії. На малих сумах Math.floor може дати 0 (це нормально для 1%).
// При запуску токена підняти за потреби (покриття газу мережі).
const TRANSFER_FEE_PCT = 1;
// Render стоїть за балансувальником: реальний IP клієнта — у X-Forwarded-For.
// Без цього rate-limit бачив би один IP проксі для всіх і різав би всіх гуртом.
app.set('trust proxy', 1);
const server = http.createServer(app);
// maxPayload (аудит #8): без нього ws приймає до 100 МБ на кадр. Реально
// найбільше, що йде через WS, — голосове як base64-запасний шлях, коли
// заливка у Storage не вдалась: 2 хв WAV 16 кГц ≈ 3,8 МБ → ≈5,1 МБ у base64.
// 16 МБ лишає запас і водночас закриває найдешевший спосіб покласти інстанс.
const wss = new WebSocket.Server({ server, maxPayload: 16 * 1024 * 1024 });
// 60 МБ лишались із часів, коли файли йшли base64 всередині JSON. Після
// переходу на підписані upload-URL (Storage 2.2) байти в HTTP більше не
// потрапляють: найбільші тіла тепер — список телефонів (до 2000 номерів,
// ≈30 КБ) і переписка для /ai/chat. 4 МБ — із великим запасом.
app.use(express.json({ limit: '4mb' }));

// ── Storage 2.3: підпис медіа-рефів у ВСІХ JSON-відповідях (чокпойнт HTTP) ───
// Обгортає res.json так, що будь-який `eion://<bucket>/<path>` у тілі відповіді
// (історія, аватари, списки) замінюється на підписаний URL. signDeep — no-op для
// повних http-URL і не-рефів, тож поки в БД лише публічні URL, це нічого не змінює.
// Швидкий відсів через includes('eion://'), щоб не перебудовувати відповіді дарма.
app.use((req, res, next) => {
  const orig = res.json.bind(res);
  res.json = (body) => {
    let hasRef = false;
    try { hasRef = JSON.stringify(body).includes('eion://'); } catch (_) {}
    if (!hasRef) return orig(body);
    signDeep(body).then(orig).catch(() => orig(body));
    return res;
  };
  next();
});

// ── Простий in-memory rate-limit (без зовнішніх залежностей) ──────────────
// Один інстанс → лічильники в пам'яті достатньо. Коли буде кілька інстансів —
// винести в Redis (як і sendToUser). Ключ — IP клієнта.
// Декодує content-рядок стікера у поля JSON для клієнта. Формат узгоджений
// з клієнтом (services.dart eDecodeStickerContent), роздільник ~|~:
//   'packId:stickerId'                             — офіційний пак
//   'user:id~|~url~|~scale~|~dx~|~dy'  — UGC-наліпка
function decodeStickerContent(content) {
  content = content || '';
  const SEP = '~|~';
  if (content.includes(SEP)) {
    const parts = content.split(SEP);
    const head = parts[0];
    const sep = head.indexOf(':');
    const num = (i) => (i < parts.length && parts[i] !== '' && !isNaN(parseFloat(parts[i]))) ? parseFloat(parts[i]) : undefined;
    const out = {
      packId: sep > 0 ? head.slice(0, sep) : 'user',
      stickerId: sep > 0 ? head.slice(sep + 1) : head,
    };
    if (parts[1]) out.stickerUrl = parts[1];
    if (num(2) !== undefined) out.cropScale = num(2);
    if (num(3) !== undefined) out.cropDx = num(3);
    if (num(4) !== undefined) out.cropDy = num(4);
    return out;
  }
  const sep = content.indexOf(':');
  return {
    packId: sep > 0 ? content.slice(0, sep) : 'tech01',
    stickerId: sep > 0 ? content.slice(sep + 1) : content,
  };
}

function makeRateLimiter({ windowMs, max }) {
  const hits = new Map(); // ip -> { count, resetAt }
  // періодичне прибирання застарілих записів, щоб мапа не росла
  setInterval(() => {
    const now = Date.now();
    for (const [ip, rec] of hits) if (now > rec.resetAt) hits.delete(ip);
  }, windowMs).unref?.();
  return (req, res, next) => {
    const ip = req.ip || req.connection?.remoteAddress || 'unknown';
    const now = Date.now();
    let rec = hits.get(ip);
    if (!rec || now > rec.resetAt) { rec = { count: 0, resetAt: now + windowMs }; hits.set(ip, rec); }
    rec.count++;
    if (rec.count > max) {
      const retry = Math.ceil((rec.resetAt - now) / 1000);
      res.set('Retry-After', String(retry));
      return res.status(429).json({ ok: false, error: 'Забагато запитів, спробуйте пізніше' });
    }
    next();
  };
}

// Загальний помірний ліміт на всі HTTP-запити
app.use(makeRateLimiter({ windowMs: 60 * 1000, max: 120 }));
// Суворіший ліміт на чутливе (вхід/реєстрація/скидання) — проти brute-force.
// ВИПРАВЛЕНО (аудит #4): раніше тут були неіснуючі /request-reset,/reset-password —
// реальні шляхи це /forgot,/reset. Плюс телефонні коди (SMS — дорого, брутфорс коду).
const authLimiter = makeRateLimiter({ windowMs: 15 * 60 * 1000, max: 20 });
app.use(['/login', '/register', '/forgot', '/reset', '/verify-email', '/phone/request-code', '/phone/verify-code'], authLimiter);

// ── Автентифікація (Фаза 1 аудиту): ЖОРСТКИЙ режим ──────────────────────────
// Кожен непублічний HTTP-запит вимагає валідний сесійний токен (Bearer),
// інакше 401. req.nick береться ЛИШЕ з токена — тілу запиту більше не довіряємо
// (це основа виправлення #1). Публічні: auth-флоу до отримання токена + health/
// моніторинг + /admin/* (свій захист секретом X-Admin-Secret). WS автентифікується
// окремо в login-хендлері.
const PUBLIC_PATHS = new Set([
  '/health', '/stats', '/ping', '/keepalive',
  '/login', '/register', '/forgot', '/reset', '/verify-email',
  '/phone/request-code', '/phone/verify-code',
]);
app.use((req, res, next) => {
  if (PUBLIC_PATHS.has(req.path) || req.path.startsWith('/admin/')) return next();
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  const nick = resolveSession(token);
  if (!nick) return res.status(401).json({ ok: false, error: 'Не авторизовано' });
  req.nick = nick;
  next();
});

// ── Моніторинг ────────────────────────────────────────────────────────────
// Публічний liveness — БЕЗ чутливих даних (його бачить будь-хто): лише «живий».
app.get('/health', (req, res) => res.json({ ok: true }));

// Не дати заснути БАЗІ, а не лише веб-сервісу.
// Supabase на безкоштовному тарифі присипляє проєкт після ~7 днів без
// ЗАПИТІВ ДО БД. `/health` і `/ping` до Supabase не звертаються взагалі,
// тож пінг на них піднімає Render, а база далі спить — і виглядає це
// як «моніторинг працює». Тут навмисно робиться справжній запит.
// Будиться ззовні: .github/workflows/keepalive.yml, кожні 6 годин.
// 503 при збої — щоб зламана БД була ВИДНА (workflow впаде), а не тиха.
app.get('/keepalive', async (req, res) => {
  const t0 = Date.now();
  try {
    const { error } = await supabase.from('users').select('nick').limit(1);
    if (error) throw new Error(error.message);
    // node у відповіді — щоб бачити, на якій версії реально крутиться прод
    // (локально 18.19.1, а @supabase/supabase-js уже просить 20+). Без цього
    // фіксувати `engines` довелось би навмання.
    res.json({ ok: true, db: true, ms: Date.now() - t0, node: process.version });
  } catch (e) {
    console.log('[keepalive] db error:', e.message);
    res.status(503).json({ ok: false, db: false, error: e.message, ms: Date.now() - t0 });
  }
});
// Приватна статистика — лише за секретним токеном з env (STATS_KEY).
app.get('/stats', (req, res) => {
  const key = process.env.STATS_KEY;
  if (!key || req.query.key !== key) return res.status(403).json({ ok: false });
  const mem = process.memoryUsage();
  res.json({
    ok: true,
    online: onlineUsers.size,
    fcmTokens: fcmTokens.size,
    pendingCallOffers: pendingCallOffers.size,
    uptimeSec: Math.floor(process.uptime()),
    memoryMB: Math.round(mem.rss / 1024 / 1024),
    ts: Date.now(),
  });
});


const BCRYPT_ROUNDS = 10; // аудит #9: підняли з 8 (лише нові/змінені паролі)
const REQUIRE_EMAIL_VERIFICATION = false;

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
// ⚠️ Таймаути обовʼязкові. 28.08.2026 `/forgot` із реальною адресою висів
// понад 2 хвилини без відповіді: без них nodemailer чекає на SMTP нескінченно,
// і запит користувача просто вмирає (клієнт здається через 10 с і показує
// «перевір інтернет» — причина при цьому невидима).
const mailer = nodemailer.createTransport({
  host: 'smtp-relay.brevo.com', port: 587,
  auth: { user: process.env.BREVO_LOGIN, pass: process.env.BREVO_PASSWORD },
  connectionTimeout: 10000, // з'єднання з релеєм
  greetingTimeout: 10000,   // привітання SMTP
  socketTimeout: 20000,     // мовчання посеред сесії
});
const onlineUsers = new Map();
const resetCodes = new Map();
const pendingRegistrations = new Map();
const verifiedPhones = new Map(); // нормалізований номер -> expires (підтверджені, для реєстрації)
const fcmTokens = new Map();
// nick -> deviceId: щоб не дзвонити/не слати пуш на ТОЙ САМИЙ фізичний
// пристрій (кілька акаунтів на одному телефоні мають спільний FCM-токен,
// інакше дзвінок «сам собі»).
const nickDevices = new Map();
const pendingCallOffers = new Map();

// FCM-токени живуть у БД, а ці Map — лише кеш процесу. Тримати їх ЛИШЕ в
// пам'яті не можна: кожен деплой на Render обнуляв мапу, і пуші замовкали, бо
// відновити токен міг тільки сам клієнт при WS-логіні — а клієнт, якому
// потрібен пуш, за визначенням офлайн і залогінитись не може (27.08.2026).
async function saveFcmToken(nick, token, deviceId) {
  fcmTokens.set(nick, token);
  if (deviceId) nickDevices.set(nick, deviceId);
  try {
    const patch = { fcm_token: token };
    if (deviceId) patch.fcm_device_id = deviceId;
    await supabase.from('users').update(patch).eq('nick_lower', nick.toLowerCase());
  } catch (e) { console.error(`saveFcmToken(${nick}):`, e.message); }
}

async function getFcmToken(nick) {
  const cached = fcmTokens.get(nick);
  if (cached) return cached;
  try {
    const { data } = await supabase.from('users').select('fcm_token, fcm_device_id').eq('nick_lower', nick.toLowerCase()).single();
    if (data && data.fcm_token) {
      fcmTokens.set(nick, data.fcm_token);
      if (data.fcm_device_id) nickDevices.set(nick, data.fcm_device_id);
      return data.fcm_token;
    }
  } catch (e) { console.error(`getFcmToken(${nick}):`, e.message); }
  return null;
}

async function clearFcmToken(nick) {
  fcmTokens.delete(nick);
  nickDevices.delete(nick);
  try {
    await supabase.from('users').update({ fcm_token: null, fcm_device_id: null }).eq('nick_lower', nick.toLowerCase());
  } catch (e) { console.error(`clearFcmToken(${nick}):`, e.message); }
}
const linkPreviewCache = new Map();

// ── Сесійні токени (Фаза 1 аудиту): STATELESS HMAC ──────────────────────────
// Перша версія тримала токени в таблиці sessions, але сервер НЕ service_role —
// INSERT мовчки падав (таблиця лишалась порожньою), тож токени жили лише в
// пам'яті й гинули на кожному рестарті/спін-дауні Render → кік-цикл. Плюс anon
// (ключ у APK) міг ЧИТАТИ ту таблицю. Тому перейшли на підписані токени:
//   token = base64url(payload).base64url(HMAC-SHA256(payload, SECRET))
//   payload = {n: nick, t: issuedAt}
// Переваги: без БД (переживає рестарти), без anon-експозиції, миттєва перевірка.
// Секрет — з env (окремий SESSION_SECRET; як запасний — уже наявний
// EION_ADMIN_SECRET, щоб не вимагати нового env). Відкликання (logout/delete)
// не миттєве — прийнятно для пре-релізу; бан лишається дійсним, бо WS-login
// окремо перевіряє platform_bans.
const SESSION_SECRET = process.env.SESSION_SECRET || process.env.EION_ADMIN_SECRET || null;
function createSessionToken(nick) {
  const payload = Buffer.from(JSON.stringify({ n: nick, t: Date.now() })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET || 'insecure-dev').update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function resolveSession(token) {
  if (!token || typeof token !== 'string' || !SESSION_SECRET) return null;
  const i = token.lastIndexOf('.');
  if (i <= 0) return null;
  const payload = token.slice(0, i);
  const sig = token.slice(i + 1);
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { return JSON.parse(Buffer.from(payload, 'base64url').toString()).n || null; }
  catch (_) { return null; }
}
// Сумісність зі старими викликами (async). БД більше не потрібна.
async function createSession(nick, _deviceId = null) { return createSessionToken(nick); }
// Stateless → миттєвого відкликання немає (no-op). Бан діє через platform_bans
// у WS-login; зміна ніка видає новий токен; клієнт при виході стирає свій.
async function destroySession(_token) {}
async function destroySessionsForNick(_nick) {}

if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    console.log('Firebase Admin ініціалізовано');
  } catch (e) { console.error('Помилка ініціалізації Firebase Admin:', e.message); }
}

setInterval(() => {
  const now = Date.now();
  for (const [id, data] of pendingCallOffers) if (now > data.expires) pendingCallOffers.delete(id);
  for (const [url, data] of linkPreviewCache) if (now > data.expires) linkPreviewCache.delete(url);
  for (const [p, exp] of verifiedPhones) if (now > exp) verifiedPhones.delete(p);
}, 120000);

// ── Захист від SSRF (аудит #6) ────────────────
// Дозволяємо лише http(s) і публічні IP: блокуємо loopback/приватні/link-local
// (напр. 127.0.0.1, 169.254.169.254 метадані хмари, 10/8, 192.168/16).
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number);
    return p[0] === 0 || p[0] === 10 || p[0] === 127
      || (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31)
      || (p[0] === 192 && p[1] === 168) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127);
  }
  const lo = ip.toLowerCase().replace(/^\[|\]$/g, '');
  return lo === '::1' || lo === '::' || lo.startsWith('fc') || lo.startsWith('fd')
    || lo.startsWith('fe8') || lo.startsWith('fe9') || lo.startsWith('fea') || lo.startsWith('feb')
    || lo.startsWith('::ffff:');
}
async function assertPublicUrl(u) {
  let parsed;
  try { parsed = new URL(u); } catch { throw new Error('Невірний URL'); }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new Error('Схема заборонена');
  const host = parsed.hostname;
  const addrs = net.isIP(host) ? [host] : (await dnsp.lookup(host, { all: true })).map(a => a.address);
  if (addrs.length === 0) throw new Error('DNS');
  for (const ip of addrs) if (isPrivateIp(ip)) throw new Error('Приватна адреса заборонена');
}

// ── Link Preview ──────────────────────────────
app.get('/link-preview', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.json({ ok: false, error: 'url обов\'язковий' });
  const cached = linkPreviewCache.get(url);
  if (cached) return res.json({ ok: true, ...cached.data });
  try {
    await assertPublicUrl(url); // SSRF-захист
    const ytMatch = url.match(/(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/shorts\/)([a-zA-Z0-9_-]{11})/);
    if (ytMatch) {
      const videoId = ytMatch[1];
      let title = null;
      try { const oembed = await fetchJson(`https://www.youtube.com/oembed?url=${encodeURIComponent(url)}&format=json`); title = oembed.title || null; } catch (_) {}
      const preview = { title, description: null, image: `https://img.youtube.com/vi/${videoId}/hqdefault.jpg`, siteName: 'YouTube', domain: 'youtube.com', url };
      linkPreviewCache.set(url, { data: preview, expires: Date.now() + 3600000 });
      return res.json({ ok: true, ...preview });
    }
    const html = await fetchUrl(url);
    const preview = parseOpenGraph(html, url);
    linkPreviewCache.set(url, { data: preview, expires: Date.now() + 3600000 });
    res.json({ ok: true, ...preview });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : httpModule;
    const req = client.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 5000 }, (resp) => {
      let data = '';
      resp.on('data', chunk => data += chunk);
      resp.on('end', () => { try { resolve(JSON.parse(data)); } catch(e) { reject(e); } });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

function fetchUrl(url, depth = 0) {
  return new Promise((resolve, reject) => {
    if (depth > 4) return reject(new Error('Забагато редіректів'));
    const client = url.startsWith('https') ? https : httpModule;
    const req = client.get(url, { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; EIONBot/1.0)', 'Accept': 'text/html' }, timeout: 8000 }, (resp) => {
      if (resp.statusCode >= 300 && resp.statusCode < 400 && resp.headers.location) {
        // SSRF: редірект теж валідуємо (міг вести на приватну адресу).
        const loc = new URL(resp.headers.location, url).toString();
        resp.destroy();
        return assertPublicUrl(loc).then(() => fetchUrl(loc, depth + 1)).then(resolve).catch(reject);
      }
      let data = ''; resp.setEncoding('utf8');
      resp.on('data', chunk => { data += chunk; if (data.length > 100000) { resp.destroy(); resolve(data); } });
      resp.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

function parseOpenGraph(html, url) {
  const getMeta = (property) => {
    const match = html.match(new RegExp(`<meta[^>]+(?:property|name)=["']${property}["'][^>]+content=["']([^"']+)["']`, 'i'))
      || html.match(new RegExp(`<meta[^>]+content=["']([^"']+)["'][^>]+(?:property|name)=["']${property}["']`, 'i'));
    return match ? match[1].trim() : null;
  };
  const title = getMeta('og:title') || getMeta('twitter:title') || (html.match(/<title[^>]*>([^<]+)<\/title>/i) || [])[1]?.trim() || null;
  const description = getMeta('og:description') || getMeta('twitter:description') || getMeta('description') || null;
  let image = getMeta('og:image') || getMeta('twitter:image') || null;
  if (image && !image.startsWith('http')) { try { const base = new URL(url); image = new URL(image, base.origin).toString(); } catch (_) { image = null; } }
  const siteName = getMeta('og:site_name') || null;
  let domain = url; try { domain = new URL(url).hostname.replace('www.', ''); } catch (_) {}
  return { title, description, image, siteName, domain, url };
}

// ── AI-проксі (аудит #3) ────────────────────────────────────────────────────
// GROQ_API_KEY був у .env → пакувався в APK, будь-хто з розпакованого APK палив
// платну квоту. Тепер клієнт шле лише messages сюди (автентифіковано — endpoint
// не в PUBLIC_PATHS, тож req.nick є), ключ лишається на сервері. Модель і ліміти
// ФОРСУЮТЬСЯ тут (клієнт не обере дорожчу модель / більший max_tokens), а відповідь
// GROQ (SSE-стрім або JSON) пайпиться клієнту байт-у-байт — його парсер незмінний.
app.post('/ai/chat', (req, res) => {
  const key = process.env.GROQ_API_KEY;
  if (!key) return res.status(503).json({ error: { message: 'AI недоступний' } });
  const raw = Array.isArray(req.body && req.body.messages) ? req.body.messages : null;
  if (!raw || raw.length === 0) return res.status(400).json({ error: { message: 'messages обовʼязкові' } });
  // Санітизація + ліміти проти абʼюзу: лише валідні role/content-рядки, останні 40, обрізка довжини.
  const messages = raw
    .filter(m => m && typeof m.role === 'string' && typeof m.content === 'string')
    .slice(-40)
    .map(m => ({ role: m.role, content: m.content.slice(0, 8000) }));
  if (messages.length === 0) return res.status(400).json({ error: { message: 'messages невалідні' } });
  const stream = req.body.stream === true;
  const payload = JSON.stringify({
    model: 'llama-3.3-70b-versatile',   // форсуємо модель — клієнт не обирає
    messages,
    max_tokens: 1024,
    temperature: 0.7,
    stream,
  });
  const upstream = https.request({
    method: 'POST',
    hostname: 'api.groq.com',
    path: '/openai/v1/chat/completions',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${key}`,
      'Content-Length': Buffer.byteLength(payload),
    },
    timeout: 30000,
  }, (up) => {
    res.status(up.statusCode || 200);
    res.setHeader('Content-Type', up.headers['content-type'] || (stream ? 'text/event-stream' : 'application/json'));
    if (stream) { res.setHeader('Cache-Control', 'no-cache'); res.setHeader('X-Accel-Buffering', 'no'); }
    up.pipe(res);
  });
  upstream.on('timeout', () => { upstream.destroy(); if (!res.headersSent) res.status(504).json({ error: { message: 'AI таймаут' } }); else res.end(); });
  upstream.on('error', () => { if (!res.headersSent) res.status(502).json({ error: { message: 'AI помилка' } }); else res.end(); });
  // Клієнт закрив зʼєднання (скасував) — не тримаємо висячий запит до GROQ.
  res.on('close', () => upstream.destroy());
  upstream.write(payload);
  upstream.end();
});

async function sendCallPush(toNick, fromNick, hasVideo, offer) {
  const token = await getFcmToken(toNick); if (!token) return;
  const callId = `${fromNick}_${toNick}_${Date.now()}`;
  pendingCallOffers.set(callId, { fromNick, toNick, offer: typeof offer === 'string' ? offer : JSON.stringify(offer), hasVideo, expires: Date.now() + 60000 });
  try {
    await admin.messaging().send({ token, data: { type: 'call_offer', from_nick: fromNick, has_video: hasVideo ? 'true' : 'false', call_id: callId }, android: { priority: 'high', ttl: 30000 } });
    console.log(`FCM push відправлено до ${toNick}, callId=${callId}`);
  } catch (e) {
    console.error(`Помилка FCM push до ${toNick}:`, e.message);
    pendingCallOffers.delete(callId);
    if (e.code === 'messaging/registration-token-not-registered') await clearFcmToken(toNick);
  }
}

// ttlMs — скільки Google ТРИМАЄ пуш, поки пристрій недоступний (Doze/екран
// вимкнено/фон/поганий зв'язок). Було жорстко 10 с → фонові пуші гинули, і
// сповіщення «спливало» лише при відкритті застосунку (симптом «приходить
// після перезапуску»). Дефолт — 4 год для повідомлень; коротші значення
// передаються явно там, де протухлий пуш недоречний (напр. call_end).
async function sendFcmPush(toNick, data, ttlMs = 14400000) {
  const token = await getFcmToken(toNick); if (!token) return;
  // Не шлемо пуш на ВЛАСНИЙ пристрій: якщо адресат — інший акаунт на тому
  // самому телефоні (спільний FCM-токен), сповіщення набридали б власнику.
  // Саме повідомлення вже збережене й буде видиме при відкритті того акаунта.
  const fromNick = data && data.from_nick;
  if (fromNick) {
    const fromDev = nickDevices.get(fromNick);
    const toDev = nickDevices.get(toNick);
    if (fromDev && toDev && fromDev === toDev) {
      console.log(`push skipped: ${fromNick}->${toNick} same device ${fromDev}`);
      return;
    }
  }
  try { await admin.messaging().send({ token, data, android: { priority: 'high', ttl: ttlMs } }); }
  catch (e) { console.error(`FCM push error до ${toNick}:`, e.message); if (e.code === 'messaging/registration-token-not-registered') await clearFcmToken(toNick); }
}

// ── Єдина точка доставки повідомлення одному користувачу ──────────────────
// Уся адресна доставка йде через цю функцію. Коли знадобиться кілька
// інстансів — саме тут (і лише тут) вмикається Redis pub/sub: якщо сокет не на
// цьому інстансі, публікуємо в канал, а інстанс-власник доставить. Решта коду
// не зміниться. Повертає true, якщо доставлено локально.
// ── Storage 2.3: приватні бакети + підписані URL ────────────────────────────
// У БД/повідомленнях зберігається РЕФ `eion://<bucket>/<path>`, а не публічний
// URL. Сервер підписує реф при ВІДДАЧІ (тут — у sendToUser для живих WS; історія
// підписується окремо). Повні http-URL (легасі-публічні) і не-рефи ПРОПУСКАЮТЬСЯ
// без змін → поки дані ще публічні, це повний no-op (жодного зайвого запиту).
const STORAGE_BUCKETS_SET = new Set(['files', 'avatars']);
const SIGNED_URL_TTL = 7 * 24 * 3600;        // 7 діб життя підписаного URL
const SIGNED_URL_REFRESH_MS = 24 * 3600 * 1000; // перепідписуємо, якщо лишилось <1 доби
const _signedUrlCache = new Map();           // ref → { url, exp(ms) }

function _parseMediaRef(value) {
  if (typeof value !== 'string' || !value.startsWith('eion://')) return null;
  const rest = value.slice(7);
  const slash = rest.indexOf('/');
  if (slash <= 0) return null;
  const bucket = rest.slice(0, slash);
  const path = rest.slice(slash + 1);
  if (!STORAGE_BUCKETS_SET.has(bucket) || !path) return null;
  return { bucket, path };
}

// Підписує один реф. Не-реф (повний URL/порожнє/звичайний текст) → повертає як є.
// Помилка підпису → повертає вихідне значення (не валимо відповідь).
async function signMediaRef(value) {
  const ref = _parseMediaRef(value);
  if (!ref) return value;
  const now = Date.now();
  const cached = _signedUrlCache.get(value);
  if (cached && cached.exp - now > SIGNED_URL_REFRESH_MS) return cached.url;
  try {
    const { data, error } = await supabase.storage.from(ref.bucket)
      .createSignedUrl(ref.path, SIGNED_URL_TTL);
    if (error || !data || !data.signedUrl) return value;
    _signedUrlCache.set(value, { url: data.signedUrl, exp: now + SIGNED_URL_TTL * 1000 });
    return data.signedUrl;
  } catch (_) { return value; }
}

// Рекурсивно замінює всі медіа-рефи в структурі на підписані URL.
async function signDeep(node) {
  if (typeof node === 'string') return signMediaRef(node);
  if (Array.isArray(node)) return Promise.all(node.map(signDeep));
  if (node && typeof node === 'object') {
    const out = {};
    for (const k of Object.keys(node)) out[k] = await signDeep(node[k]);
    return out;
  }
  return node;
}

function sendToUser(nick, payload) {
  const u = onlineUsers.get(nick);
  if (!u || !u.ws || u.ws.readyState !== 1 /* OPEN */) return false;
  const raw = typeof payload === 'string' ? payload : JSON.stringify(payload);
  // Швидкий відсів: немає нашого префікса → шлемо синхронно (поточна поведінка).
  if (!raw.includes('eion://')) {
    try { u.ws.send(raw); return true; } catch (_) { return false; }
  }
  // Є медіа-рефи → підписуємо, тоді шлемо. Reachability (онлайн?) відома вже зараз,
  // тож boolean-контракт збережено; сам send асинхронний після підпису.
  (async () => {
    try {
      const obj = typeof payload === 'string' ? JSON.parse(raw) : payload;
      const signed = await signDeep(obj);
      const u2 = onlineUsers.get(nick);
      if (u2 && u2.ws && u2.ws.readyState === 1) u2.ws.send(JSON.stringify(signed));
    } catch (_) {}
  })();
  return true;
}

// Онлайн-запис адресата ЛИШЕ якщо сокет справді живий (readyState OPEN +
// heartbeat). Мертвий сокет (code=1006 на Render, ще не прибраний delete/
// heartbeat) прибираємо й вважаємо офлайн. Критично для доставки: інакше
// target «є», повідомлення позначається delivered=true і йде в нікуди —
// при повторному вході (delivered=false) його вже не виберуть → втрата.
function liveTarget(nick) {
  const t = onlineUsers.get(nick);
  if (!t) return null;
  const open = !!(t.ws && t.ws.readyState === 1 /* OPEN */);
  // Прибираємо з presence ЛИШЕ справді мертвий сокет (закритий). Раніше звідси
  // вилітав і живий адресат, якщо виклик влучив у вікно heartbeat: цикл щоцикла
  // (30с) ставить isAlive=false УСІМ сокетам і чекає pong. Такий адресат зникав
  // з onlineUsers до наступного login — і все, що адресує через onlineUsers.get
  // (реакції), більше його не бачило. Не відповів два цикли → heartbeat сам
  // обриває сокет, плюс cleanup за lastSeen>60с; presence чиститься там.
  if (!open) { onlineUsers.delete(nick); return null; }
  // Для ДОСТАВКИ лишаємось консервативними: у вікні isAlive=false вважаємо офлайн,
  // щоб повідомлення пішло надійним шляхом (збереглось недоставленим + FCM), а не
  // в мертвий сокет із позначкою delivered — це і була втрата повідомлень.
  return t.ws.isAlive !== false ? t : null;
}
function isLive(nick) { return liveTarget(nick) !== null; }

// ПОВНИЙ стан реакцій одного повідомлення: { emoji: [nick, ...] }.
// Клієнт присвоює його як є, замість того щоб «перемикати» реакцію в себе.
// Перемикання було крихким: одну подію нерідко застосовували двічі (панель +
// відкритий екран ділять ті самі об'єкти повідомлень), і друге застосування
// знімало щойно поставлену реакцію. Присвоєння ідемпотентне — повтор нешкідливий.
function groupReactionsState(groupId, msgId) {
  return supabase.from('group_message_reactions').select('emoji, nick').eq('group_id', groupId).eq('msg_id', msgId)
    .then(({ data }) => reactionsToMap(data, 'nick'));
}
function directReactionsState(pairKey, msgId) {
  return supabase.from('direct_message_reactions').select('emoji, from_nick').eq('pair_key', pairKey).eq('msg_id', msgId)
    .then(({ data }) => reactionsToMap(data, 'from_nick'));
}
function reactionsToMap(rows, nickField) {
  const out = {};
  for (const r of rows || []) (out[r.emoji] ??= []).push(r[nickField]);
  return out;
}

// Лічильники непрочитаного (chat_reads). Повертає мапу {chat_id: last_read_ts}
// для одного юзера й типу ('group'|'channel'). Відсутній вказівник → трактуємо як
// 0 (усе прочитане до першого відкриття), щоб на першому запуску після цієї фічі
// не показувати гігантський бейдж зі всієї історії. Пойнтер зсувається на
// mark-read при відкритті/закритті чату.
async function getChatReadMap(nick, type, ids) {
  if (!ids || ids.length === 0) return {};
  const { data } = await supabase.from('chat_reads')
    .select('chat_id, last_read_ts')
    .eq('nick', nick).eq('chat_type', type).in('chat_id', ids);
  const map = {};
  for (const r of data || []) map[r.chat_id] = Number(r.last_read_ts) || 0;
  return map;
}

// Журнал грошових операцій (append-only). Запис НЕ має ламати саму операцію:
// якщо лог не записався — гроші вже перемістились, тож просто ковтаємо помилку.
// Викликати ПІСЛЯ успішної зміни балансу, окремим рядком на кожну "половинку".
async function logTx({ fromNick = null, toNick = null, amount, kind, ref = null }) {
  try {
    await supabase.from('coin_transactions').insert({
      from_nick: fromNick, to_nick: toNick, amount, kind, ref,
    });
  } catch (e) {
    console.error('[logTx]', kind, e.message);
  }
}

// Нарахування доходу компанії (EION): атомарний add_coins + live-нотифікація,
// якщо EION зараз онлайн (раніше баланс оновлювався лише після перезаходу),
// + запис у журнал. amount<=0 або сам EION як платник — пропускаємо.
async function creditCompany(amount, kind, { fromNick = null, ref = null } = {}) {
  if (!amount || amount <= 0 || fromNick === COMPANY_NICK) return;
  const { data: newTotal } = await supabase.rpc('add_coins', { p_nick: COMPANY_NICK, p_amount: amount });
  if (newTotal != null) {
    sendToUser(COMPANY_NICK, { type: 'coins_received', fromNick: fromNick || 'system', amount, total: newTotal });
  }
  await logTx({ fromNick, toNick: COMPANY_NICK, amount, kind, ref });
}

async function notifyChannelSubscribers(channelId, payload, excludeNick = null) {
  const { data: members } = await supabase.from('channel_members').select('nick').eq('channel_id', channelId);
  const msg = JSON.stringify(payload);
  for (const m of members || []) {
    if (m.nick === excludeNick) continue;
    const t = onlineUsers.get(m.nick);
    // ws.send кидає на мертвому/напіввідкритому сокеті (Render flapping) —
    // не дати одному битому сокету зірвати решту розсилки й сам HTTP-запит.
    if (t) { try { t.ws.send(msg); } catch (_) {} }
  }
}

app.get('/call-offer', (req, res) => {
  const { callId } = req.query; if (!callId) return res.json({ ok: false, error: 'callId обов\'язковий' });
  const data = pendingCallOffers.get(callId); if (!data) return res.json({ ok: false, error: 'Offer не знайдено або застарів' });
  res.json({ ok: true, fromNick: data.fromNick, offer: data.offer, hasVideo: data.hasVideo });
});

app.post('/decline-call', async (req, res) => {
  const { toNick } = req.body; const fromNick = req.nick; if (!fromNick || !toNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const delivered = sendToUser(toNick, { type: 'call_reject', from: fromNick });
  // Нативне відхилення (Android у фоні) — теж свідоме, не пропущений: прибираємо
  // передчасний missed цієї пари (from=той-хто-дзвонив=toNick, to=я=fromNick).
  await clearPreemptiveMissed(toNick, fromNick);
  console.log(`[calldiag] /decline-call ${fromNick}->${toNick} reject delivered=${delivered} (socket ${delivered ? 'OPEN' : 'NOT-OPEN/absent'})`);
  res.json({ ok: true });
});

// ⚠️ Пошта йде через HTTP API Brevo, а НЕ через SMTP.
//
// Render блокує вихідні з'єднання на портах 25/465/587 (політика проти спаму),
// тож `smtp-relay.brevo.com:587` із прода недосяжний узагалі: сире TCP-
// з'єднання не встановлюється (перевірено 28.08.2026 — `/admin/mail-test`,
// probe timeout 8 с при живих кредах). Це означає, що відновлення пароля не
// працювало в проді й раніше, просто мовчки: без таймаутів запит вішався, а
// клієнт через 10 с показував «перевір інтернет».
//
// HTTP API йде на 443 і не блокується. SMTP лишається запасним шляхом — для
// запуску деінде, де порт відкритий (і щоб не втратити роботу без API-ключа).
const BREVO_API_KEY = process.env.BREVO_API_KEY || '';

// ⚠️ ДВІ РІЗНІ ПЕРЕШКОДИ, які легко сплутати — обидві перевірені 28.08.2026
// через /admin/mail-test, а не за здогадом:
//
// 1. Транзакційний модуль Brevo треба АКТИВУВАТИ вручну (пишеться в підтримку).
//    Доти будь-яка відправка через API дає 403 permission_denied
//    «Your SMTP account is not yet activated», хоч ключ дійсний і відправник
//    підтверджений. Це не про налаштування — обійти з нашого боку неможливо.
//
// 2. Відправник на @gmail.com сам по собі Brevo приймає (підтверджує кодом),
//    АЛЕ домен gmail.com неможливо автентифікувати — він чужий, DKIM для нього
//    не підпишеш. Gmail/Yahoo/Microsoft з 2024 вимагають автентифікації, тож
//    такі листи йдуть у спам або відкидаються приймачем. Тобто gmail — не
//    відмова API, а тиха втрата листів. Лікується власним доменом.
//
// У проєкту він є: eion.network (реєстратор Porkbun, DNS там же).
// Порядок: Brevo → Senders & domains → додати домен → покласти в Porkbun
// TXT-записи (brevo-code + DKIM) → підтвердити → сюди MAIL_FROM.
//
// Береться support@ (а не noreply@) з двох причин: пошта на нього вже
// доставляється — MX домену вказують на ImprovMX, форвард заведено й
// перевірено живим листом 28.08.2026, тож код підтвердження Brevo є куди
// прийняти; і Gmail/Yahoo прихильніші до відправника, який приймає
// відповіді, ніж до глухого noreply@.
const MAIL_FROM = { name: 'EION', email: process.env.MAIL_FROM || 'support@eion.network' };

async function sendEmail(to, subject, text) {
  if (BREVO_API_KEY) {
    const r = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'api-key': BREVO_API_KEY, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ sender: MAIL_FROM, to: [{ email: to }], subject, textContent: text }),
      signal: AbortSignal.timeout(15000),
    });
    const body = await r.text();
    if (!r.ok) throw new Error(`Brevo API ${r.status}: ${body.slice(0, 200)}`);
    return { response: body.slice(0, 200), via: 'api' };
  }
  const info = await mailer.sendMail({ from: `${MAIL_FROM.name} <${MAIL_FROM.email}>`, to, subject, text });
  return { ...info, via: 'smtp' };
}

// ── OTP: підключюваний відправник SMS ──────────
function httpPostJson(targetUrl, headers, bodyObj) {
  return new Promise((resolve) => {
    try {
      const u = new URL(targetUrl);
      const mod = u.protocol === 'http:' ? httpModule : https;
      const payload = JSON.stringify(bodyObj);
      const r = mod.request(u, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), ...headers },
      }, (resp) => {
        let data = '';
        resp.on('data', (c) => data += c);
        resp.on('end', () => resolve({ status: resp.statusCode, body: data }));
      });
      r.on('error', (e) => resolve({ status: 0, error: e.message }));
      r.write(payload);
      r.end();
    } catch (e) { resolve({ status: 0, error: e.message }); }
  });
}

// Відправляє OTP: спершу Telegram Gateway (дешево, масштабовано), далі SMS-шлюз (резерв).
// Без жодного каналу — dev-режим (лог у консоль).
async function sendOtp(phoneE164, code, text) {
  // 1. Telegram Gateway — основний канал (доставляє НАШ код у Telegram)
  if (process.env.TG_GATEWAY_TOKEN) {
    const tg = await httpPostJson(
      'https://gatewayapi.telegram.org/sendVerificationMessage',
      { 'Authorization': `Bearer ${process.env.TG_GATEWAY_TOKEN}` },
      { phone_number: phoneE164, code: code, ttl: 300 },
    );
    try {
      const body = JSON.parse(tg.body || '{}');
      if (tg.status >= 200 && tg.status < 300 && body.ok === true) return { ok: true, via: 'telegram' };
      console.error('[OTP] Telegram не доставив:', body.error || tg.status, '— пробую SMS-резерв');
    } catch (_) {
      console.error('[OTP] Telegram HTTP', tg.status, '— пробую SMS-резерв');
    }
    // не вдалось — падаємо у SMS-резерв нижче
  }

  // 2. SMS-шлюз (SMSGate) — резерв
  const url = process.env.SMS_GATEWAY_URL;
  if (!url) { console.log(`[OTP dev] -> ${phoneE164}: ${text}`); return { ok: true, dev: true }; }
  const headers = {};
  if (process.env.SMS_GATEWAY_TOKEN) headers['Authorization'] = `Bearer ${process.env.SMS_GATEWAY_TOKEN}`;
  else if (process.env.SMS_GATEWAY_BASIC) headers['Authorization'] = `Basic ${Buffer.from(process.env.SMS_GATEWAY_BASIC).toString('base64')}`;
  // Тіло під актуальний API SMSGate (sms-gate.app): { textMessage:{text}, phoneNumbers:[...] }
  const r = await httpPostJson(url, headers, { textMessage: { text: text }, phoneNumbers: [phoneE164] });
  if (r.status >= 200 && r.status < 300) return { ok: true, via: 'sms' };
  console.error('[OTP] SMS-шлюз помилка', r.status, r.error || r.body);
  return { ok: false };
}

async function isModOrCreator(groupId, nick) {
  const { data } = await supabase.from('group_members').select('role').eq('group_id', groupId).eq('nick', nick).single();
  return data && (data.role === 'creator' || data.role === 'moderator');
}

// Чи blockerNick заблокував otherNick (тобто otherNick не повинен мати
// можливості писати/дзвонити blockerNick).
async function isBlockedBy(blockerNick, otherNick) {
  if (!blockerNick || !otherNick) return false;
  const { data } = await supabase.from('blocked_contacts').select('id')
    .eq('blocker_nick', blockerNick).eq('blocked_nick', otherNick).maybeSingle();
  return !!data;
}

// Чи може recipient отримати особисте повідомлення від sender.
// Враховує глобальний блок вхідних (block_incoming) + allowlist (виняток для
// тих, кому власник блоку написав ПІСЛЯ ввімкнення). Точкове блокування
// (blocked_contacts) перевіряється окремо в наявному коді, тут не дублюємо.
async function canReceiveFrom(senderNick, recipientNick) {
  if (!senderNick || !recipientNick) return true;
  const { data: rcpt } = await supabase.from('users').select('block_incoming').eq('nick', recipientNick).maybeSingle();
  if (!rcpt || rcpt.block_incoming !== true) return true; // блок вимкнено — можна
  // Блок увімкнено — дозволено лише якщо sender у allowlist recipient
  // (тобто recipient сам написав sender за активного блоку).
  const { data: allowed } = await supabase.from('block_allowlist').select('owner_nick')
    .eq('owner_nick', recipientNick).eq('allowed_nick', senderNick).maybeSingle();
  return !!allowed;
}

// Коли власник блоку САМ пише комусь за активного блоку — додаємо адресата
// в його allowlist (той отримує право відповідати). Ідемпотентно.
async function grantAllowlistIfBlocking(ownerNick, allowedNick) {
  if (!ownerNick || !allowedNick || ownerNick === allowedNick) return;
  const { data: owner } = await supabase.from('users').select('block_incoming').eq('nick', ownerNick).maybeSingle();
  if (!owner || owner.block_incoming !== true) return; // блок вимкнено — allowlist не потрібен
  await supabase.from('block_allowlist').upsert(
    { owner_nick: ownerNick, allowed_nick: allowedNick },
    { onConflict: 'owner_nick,allowed_nick', ignoreDuplicates: true });
}

async function notifyMembers(groupId, payload, excludeNick = null) {
  const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', groupId);
  const msg = JSON.stringify(payload);
  for (const m of members || []) { if (m.nick === excludeNick) continue; const t = onlineUsers.get(m.nick); if (t) { try { t.ws.send(msg); } catch (_) {} } }
}

// Друга (сіра) галочка авторові групового повідомлення: хтось із учасників
// онлайн — отже, повідомлення вже доставлене. Синя ✓✓ ставиться окремо
// (group_read_receipt), коли прочитають ВСІ учасники.
function notifyGroupDelivered(ws, groupId, msgId, onlineMembers) {
  if (!msgId || !onlineMembers || onlineMembers.length === 0) return;
  if (ws.readyState !== WebSocket.OPEN) return;
  try { ws.send(JSON.stringify({ type: 'group_status_update', groupId, status: 'delivered', msgIds: [msgId] })); } catch (_) {}
}

async function sendGroupInvite(groupId, groupName, inviterNick, targetNick) {
  const target = onlineUsers.get(targetNick);
  const payload = { type: 'group_invite', groupId, groupName, inviterNick };
  if (target) target.ws.send(JSON.stringify(payload));
  else await supabase.from('pending_group_invites').upsert({ group_id: groupId, target_nick: targetNick, inviter_nick: inviterNick });
}

// ── Реєстрація / Авторизація ──────────────────
app.post('/register', async (req, res) => {
  const { nick, password, email, color, phone, phoneNormalized } = req.body;
  if (!nick || nick.trim().length < 2) return res.json({ ok: false, error: 'Нік занадто короткий (мін. 2 символи)' });
  if (!password || password.length < 8) return res.json({ ok: false, error: 'Пароль занадто короткий (мін. 8 символів)' });
  if (email && !email.includes('@')) return res.json({ ok: false, error: 'Невірний email' });
  const { data: existing } = await supabase.from('users').select('nick').eq('nick_lower', nick.toLowerCase()).single();
  if (existing) return res.json({ ok: false, error: 'Нік вже зайнятий' });
  if (email) {
    const { data: emailExists } = await supabase.from('users').select('nick').eq('email', email).single();
    if (emailExists) return res.json({ ok: false, error: 'Цей email вже використовується' });
  }
  // Перевіряємо унікальність телефону
  if (phoneNormalized) {
    const { data: phoneExists } = await supabase.from('users').select('nick').eq('phone_normalized', phoneNormalized).single();
    if (phoneExists) return res.json({ ok: false, error: 'Цей номер телефону вже зареєстрований в EION' });
  }
  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const userData = {
    nick, nick_lower: nick.toLowerCase(), password_hash: passwordHash,
    email, color: color || 4280391411, coins: 50,
    ...(phone ? { phone } : {}),
    ...(phoneNormalized ? { phone_normalized: phoneNormalized, phone_verified: verifiedPhones.has(phoneNormalized) } : {}),
  };
  if (REQUIRE_EMAIL_VERIFICATION) {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    pendingRegistrations.set(email, { ...userData, code, expires: Date.now() + 15 * 60 * 1000 });
    try { await sendEmail(email, 'EION — Підтвердження реєстрації', `Ваш код підтвердження: ${code}\n\nКод дійсний 15 хвилин.`); res.json({ ok: true, needVerification: true }); }
    catch (e) { res.json({ ok: false, error: 'Помилка відправки email: ' + e.message }); }
  } else {
    const { error } = await supabase.from('users').insert(userData);
    if (error) return res.json({ ok: false, error: 'Помилка створення акаунта' });
    // Одразу видаємо токен — після реєстрації користувач залогінений.
    const token = await createSession(nick, req.body.deviceId || null);
    res.json({ ok: true, needVerification: false, token, nick });
  }
});

app.post('/verify-email', async (req, res) => {
  const { email, code } = req.body;
  const pending = pendingRegistrations.get(email); if (!pending) return res.json({ ok: false, error: 'Реєстрацію не знайдено' });
  if (Date.now() > pending.expires) return res.json({ ok: false, error: 'Код застарів' });
  if (pending.code !== code) return res.json({ ok: false, error: 'Невірний код' });
  // Аудит #10: було pending.passwordHash (undefined) → акаунт без пароля.
  // Правильне поле — password_hash (з userData). Вставляємо повний набір полів.
  const { code: _c, expires: _e, ...userData } = pending;
  const { error } = await supabase.from('users').insert(userData);
  if (error) return res.json({ ok: false, error: 'Помилка створення акаунта' });
  pendingRegistrations.delete(email);
  const token = await createSession(pending.nick);
  res.json({ ok: true, token, nick: pending.nick });
});

app.post('/login', async (req, res) => {
  const { nick, password } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const { data: ban } = await supabase.from('platform_bans').select('reason').eq('nick', user.nick).single();
  if (ban) return res.json({ ok: false, error: `Акаунт заблоковано: ${ban.reason || 'порушення правил'}` });
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
  // Сесійний токен (Фаза 1): клієнт зберігає його й шле в Authorization/WS замість ніка.
  const token = await createSession(user.nick, req.body.deviceId || null);
  res.json({ ok: true, token, nick: user.nick, color: user.color, coins: user.coins || 0, avatar_url: user.avatar_url || null, premium_expires_at: user.premium_expires_at || null, premium_plan: user.premium_plan || null, nick_color: user.nick_color || null, block_incoming: user.block_incoming === true });
});

// Вихід: інвалідує токен (клієнт зве при виході з профілю).
app.post('/logout', async (req, res) => {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  await destroySession(token);
  res.json({ ok: true });
});

app.post('/forgot', async (req, res) => {
  const { email } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('email', email).single();
  if (!user) return res.json({ ok: false, error: 'Email не знайдено' });
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  resetCodes.set(email, { code, nick: user.nick, expires: Date.now() + 15 * 60 * 1000 });
  try { await sendEmail(email, 'EION — Відновлення пароля', `Ваш код відновлення: ${code}\n\nКод дійсний 15 хвилин.`); res.json({ ok: true }); }
  catch (e) { console.log('[forgot] sendEmail:', e.message); res.json({ ok: false, error: 'Помилка відправки email' }); }
});

app.post('/reset', async (req, res) => {
  const { email, code, newPassword } = req.body;
  const reset = resetCodes.get(email); if (!reset) return res.json({ ok: false, error: 'Код не знайдено' });
  if (Date.now() > reset.expires) return res.json({ ok: false, error: 'Код застарів' });
  if (reset.code !== code) return res.json({ ok: false, error: 'Невірний код' });
  if (!newPassword || newPassword.length < 8) return res.json({ ok: false, error: 'Пароль занадто короткий (мін. 8 символів)' });
  const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  await supabase.from('users').update({ password_hash: passwordHash }).eq('nick_lower', reset.nick.toLowerCase());
  resetCodes.delete(email); res.json({ ok: true });
});

app.post('/update-nick', async (req, res) => {
  const { password, newNick } = req.body; const nick = req.nick;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const valid = await bcrypt.compare(password, user.password_hash); if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
  if (!newNick || newNick.trim().length < 2) return res.json({ ok: false, error: 'Нік занадто короткий' });
  const { data: exists } = await supabase.from('users').select('nick').eq('nick_lower', newNick.toLowerCase()).single();
  if (exists) return res.json({ ok: false, error: 'Нік вже зайнятий' });
  const oldNick = user.nick;
  await supabase.from('users').update({ nick: newNick, nick_lower: newNick.toLowerCase() }).eq('nick_lower', nick.toLowerCase());
  await Promise.all([
    supabase.from('messages').update({ from_nick: newNick }).eq('from_nick', oldNick),
    supabase.from('messages').update({ to_nick: newNick }).eq('to_nick', oldNick),
    supabase.from('group_members').update({ nick: newNick }).eq('nick', oldNick),
    supabase.from('group_messages').update({ from_nick: newNick }).eq('from_nick', oldNick),
    supabase.from('groups').update({ creator_nick: newNick }).eq('creator_nick', oldNick),
    supabase.from('channel_members').update({ nick: newNick }).eq('nick', oldNick),
    supabase.from('channel_messages').update({ from_nick: newNick }).eq('from_nick', oldNick),
    supabase.from('channel_comments').update({ from_nick: newNick }).eq('from_nick', oldNick),
    supabase.from('channel_reactions').update({ nick: newNick }).eq('nick', oldNick),
    supabase.from('channel_comment_reactions').update({ nick: newNick }).eq('nick', oldNick),
    supabase.from('channels').update({ owner_nick: newNick }).eq('owner_nick', oldNick),
    supabase.from('deleted_messages').update({ from_nick: newNick }).eq('from_nick', oldNick),
    supabase.from('deleted_messages').update({ to_nick: newNick }).eq('to_nick', oldNick),
    supabase.from('pending_reactions').update({ from_nick: newNick }).eq('from_nick', oldNick),
    supabase.from('pending_reactions').update({ to_nick: newNick }).eq('to_nick', oldNick),
    supabase.from('call_logs').update({ from_nick: newNick }).eq('from_nick', oldNick),
    supabase.from('call_logs').update({ to_nick: newNick }).eq('to_nick', oldNick),
    supabase.from('pending_group_invites').update({ target_nick: newNick }).eq('target_nick', oldNick),
    supabase.from('pending_group_invites').update({ inviter_nick: newNick }).eq('inviter_nick', oldNick),
    supabase.from('pending_channel_invites').update({ target_nick: newNick }).eq('target_nick', oldNick),
    supabase.from('pending_channel_invites').update({ inviter_nick: newNick }).eq('inviter_nick', oldNick),
  ]);
  const userWs = onlineUsers.get(oldNick);
  if (userWs) { onlineUsers.delete(oldNick); onlineUsers.set(newNick, userWs); }
  for (const [n, u] of onlineUsers) if (n !== newNick) u.ws.send(JSON.stringify({ type: 'nick_changed', oldNick, newNick }));
  // Токен ніс старий нік — старі сесії гасимо, видаємо новий токен (клієнт зберігає).
  await destroySessionsForNick(oldNick);
  const newToken = await createSession(newNick, req.body.deviceId || null);
  res.json({ ok: true, newNick, token: newToken });
});

app.post('/update-password', async (req, res) => {
  const { password, newPassword } = req.body; const nick = req.nick;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const valid = await bcrypt.compare(password, user.password_hash); if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
  if (!newPassword || newPassword.length < 8) return res.json({ ok: false, error: 'Новий пароль занадто короткий (мін. 8 символів)' });
  const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  await supabase.from('users').update({ password_hash: passwordHash }).eq('nick_lower', nick.toLowerCase());
  res.json({ ok: true });
});

app.post('/update-phone', async (req, res) => {
  const { password, phone, phoneNormalized } = req.body; const nick = req.nick;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const valid = await bcrypt.compare(password, user.password_hash); if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
  if (!phoneNormalized) return res.json({ ok: false, error: 'Невірний номер' });
  // Унікальність номера (крім самого себе)
  const { data: phoneExists } = await supabase.from('users').select('nick').eq('phone_normalized', phoneNormalized).single();
  if (phoneExists && phoneExists.nick !== user.nick) return res.json({ ok: false, error: 'Цей номер телефону вже зареєстрований в EION' });
  const { error } = await supabase.from('users').update({ phone, phone_normalized: phoneNormalized, phone_verified: verifiedPhones.has(phoneNormalized) }).eq('nick_lower', nick.toLowerCase());
  if (error) return res.json({ ok: false, error: 'Помилка оновлення номера' });
  res.json({ ok: true });
});

// ── Підтвердження номера власним OTP (без Firebase) ──
app.post('/phone/request-code', async (req, res) => {
  const { phone, phoneNormalized } = req.body;
  if (!phoneNormalized || !phone) return res.json({ ok: false, error: 'Невірний номер' });
  // rate-limit: не частіше ніж раз на 60 с
  const { data: existing } = await supabase.from('phone_codes').select('last_sent_at').eq('phone', phoneNormalized).single();
  if (existing && existing.last_sent_at) {
    const elapsed = Date.now() - new Date(existing.last_sent_at).getTime();
    if (elapsed < 60000) return res.json({ ok: false, error: `Зачекайте ${Math.ceil((60000 - elapsed) / 1000)} с` });
  }
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const { error } = await supabase.from('phone_codes').upsert({
    phone: phoneNormalized, code,
    expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    attempts: 0, last_sent_at: new Date().toISOString(),
  });
  if (error) { console.error('[OTP] phone_codes upsert:', error); return res.json({ ok: false, error: 'Помилка збереження коду' }); }
  const sent = await sendOtp(phone, code, `EION код підтвердження: ${code}`);
  if (!sent.ok) return res.json({ ok: false, error: 'Не вдалося надіслати код' });
  // У dev-режимі (без шлюзу) можна повернути код для тесту, якщо явно дозволено env
  const devCode = (sent.dev && process.env.OTP_DEV_RETURN_CODE === 'true') ? code : undefined;
  res.json({ ok: true, ...(devCode ? { devCode } : {}) });
});

app.post('/phone/verify-code', async (req, res) => {
  const { phone, phoneNormalized, code, nick } = req.body;
  if (!phoneNormalized || !code) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: row } = await supabase.from('phone_codes').select('*').eq('phone', phoneNormalized).single();
  if (!row) return res.json({ ok: false, error: 'Код не знайдено. Запросіть новий' });
  if (new Date(row.expires_at).getTime() < Date.now()) {
    await supabase.from('phone_codes').delete().eq('phone', phoneNormalized);
    return res.json({ ok: false, error: 'Код протерміновано. Запросіть новий' });
  }
  if (row.attempts >= 5) {
    await supabase.from('phone_codes').delete().eq('phone', phoneNormalized);
    return res.json({ ok: false, error: 'Забагато спроб. Запросіть новий код' });
  }
  if (row.code !== String(code)) {
    await supabase.from('phone_codes').update({ attempts: row.attempts + 1 }).eq('phone', phoneNormalized);
    return res.json({ ok: false, error: 'Невірний код' });
  }
  await supabase.from('phone_codes').delete().eq('phone', phoneNormalized); // успіх — код видаляємо
  // Наявний користувач (зміна номера / discovery) — ставимо номер + phone_verified
  if (nick) {
    const { data: user } = await supabase.from('users').select('nick').eq('nick_lower', nick.toLowerCase()).single();
    if (user) {
      const { data: phoneExists } = await supabase.from('users').select('nick').eq('phone_normalized', phoneNormalized).single();
      if (phoneExists && phoneExists.nick !== user.nick) return res.json({ ok: false, error: 'Цей номер вже зареєстрований в EION' });
      await supabase.from('users').update({ ...(phone ? { phone } : {}), phone_normalized: phoneNormalized, phone_verified: true }).eq('nick_lower', nick.toLowerCase());
    }
  }
  // Для реєстрації (ще без ніка) — запам'ятовуємо підтверджений номер на 15 хв
  verifiedPhones.set(phoneNormalized, Date.now() + 15 * 60 * 1000);
  res.json({ ok: true, verified: true });
});

app.post('/update-email', async (req, res) => {
  const { password, newEmail } = req.body; const nick = req.nick;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const valid = await bcrypt.compare(password, user.password_hash); if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
  if (!newEmail || !newEmail.includes('@')) return res.json({ ok: false, error: 'Невірний email' });
  const { data: emailExists } = await supabase.from('users').select('nick').eq('email', newEmail).single();
  if (emailExists) return res.json({ ok: false, error: 'Email вже використовується' });
  await supabase.from('users').update({ email: newEmail }).eq('nick_lower', nick.toLowerCase());
  res.json({ ok: true });
});

// Видача ICE-серверів клієнту. Креди TURN живуть у env сервера, а не в APK —
// інакше їх витягують із застосунку й крадуть relay-трафік. STUN — публічний,
// віддаємо завжди; TURN — лише якщо налаштовані змінні оточення.
app.get('/turn-credentials', (req, res) => {
  const iceServers = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
  ];
  const user = process.env.TURN_USERNAME;
  const cred = process.env.TURN_CREDENTIAL;
  const host = process.env.TURN_HOST || 'global.relay.metered.ca';
  if (user && cred) {
    iceServers.push(
      { urls: `stun:${host}:80` },
      { urls: `turn:${host}:80`, username: user, credential: cred },
      { urls: `turn:${host}:80?transport=tcp`, username: user, credential: cred },
      { urls: `turn:${host}:443`, username: user, credential: cred },
      { urls: `turns:${host}:443?transport=tcp`, username: user, credential: cred },
    );
  }
  res.json({ ok: true, iceServers, ttl: 3600 });
});

app.post('/delete-account', async (req, res) => {
  const { password } = req.body; const nick = req.nick;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const valid = await bcrypt.compare(password, user.password_hash); if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
  await supabase.from('messages').delete().or(`from_nick.eq.${nick},to_nick.eq.${nick}`);
  await supabase.from('users').delete().eq('nick_lower', nick.toLowerCase());
  onlineUsers.delete(nick); await clearFcmToken(nick);
  await destroySessionsForNick(nick);
  res.json({ ok: true });
});

// In-memory набір невидимих ніків (invisible=true). Заповнюється при старті
// й оновлюється endpoint'ом перемикача. Дає синхронну перевірку без запиту в
// БД у гарячих шляхах (presence, доставка статусів).
const invisibleNicks = new Set();
async function loadInvisibleNicks() {
  try {
    const { data } = await supabase.from('users').select('nick').eq('invisible', true);
    invisibleNicks.clear();
    for (const u of (data || [])) invisibleNicks.add(u.nick);
  } catch (e) { console.error('[loadInvisibleNicks]', e.message); }
}
loadInvisibleNicks();

// Приватний presence: повертаємо лише тих із КОНТАКТІВ запитувача, хто онлайн.
// (Раніше GET віддавав список УСІХ онлайн будь-кому — витік ніків + не масштабно.)
// Невидимі (invisible) виключаються — для інших вони завжди офлайн.
app.post('/online-users', (req, res) => {
  const { contacts } = req.body || {};
  if (!Array.isArray(contacts)) return res.json({ ok: true, users: [] });
  const online = contacts.filter(n => typeof n === 'string' && onlineUsers.has(n) && !invisibleNicks.has(n)).slice(0, 5000);
  res.json({ ok: true, users: online });
});

app.get('/user-info', async (req, res) => {
  const { nick } = req.query; if (!nick) return res.json({ ok: false, error: 'Нік обов\'язковий' });
  const { data: user } = await supabase.from('users').select('nick, coins, avatar_url, premium_expires_at, premium_plan, nick_color, color, block_incoming, invisible').eq('nick', nick).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  res.json({ ok: true, nick: user.nick, coins: user.coins || 0, avatar_url: user.avatar_url || null, premium_expires_at: user.premium_expires_at || null, premium_plan: user.premium_plan || null, nick_color: user.nick_color || null, color: user.color || null, block_incoming: user.block_incoming === true, invisible: user.invisible === true });
});

app.get('/search-user', async (req, res) => {
  const { nick } = req.query; if (!nick || nick.trim().length < 2) return res.json({ ok: false, error: 'Введіть мін. 2 символи' });
  const { data } = await supabase.from('users').select('nick').ilike('nick_lower', `%${nick.toLowerCase()}%`).neq('invisible', true).limit(10);
  res.json({ ok: true, users: (data || []).map(u => u.nick) });
});

app.post('/users/by-phones', async (req, res) => {
  let { phones } = req.body;
  if (!phones || !Array.isArray(phones) || phones.length === 0) return res.json({ ok: false, error: 'Невірні параметри' });
  // Аудит #7: фільтруємо В ЗАПИТІ (не вивантажуємо всі номери в пам'ять) +
  // обмежуємо розмір списку, щоб не можна було перебирати всю базу за раз.
  phones = phones.filter(p => typeof p === 'string').slice(0, 2000);
  const { data } = await supabase.from('users')
    .select('nick, phone_normalized')
    .eq('phone_verified', true)
    .in('phone_normalized', phones);
  const result = {};
  for (const user of data || []) result[user.phone_normalized] = user.nick;
  res.json({ ok: true, users: result });
});

app.post('/unregister', (req, res) => { const nick = req.nick; if (nick) onlineUsers.delete(nick); res.json({ ok: true }); });
app.post('/register-fcm-token', (req, res) => {
  const { token, deviceId } = req.body; // token тут = FCM-токен (не сесійний)
  const nick = req.nick; // Фаза 1/#14: FCM-токен реєструється ЛИШЕ на свій нік.
  if (!nick || !token) return res.json({ ok: false, error: 'Невірні параметри' });
  saveFcmToken(nick, token, deviceId);
  res.json({ ok: true });
});

app.post('/update-nick-color', async (req, res) => {
  const { nickColor } = req.body; const nick = req.nick; if (!nick) return res.json({ ok: false, error: 'Нік обов\'язковий' });
  await supabase.from('users').update({ nick_color: nickColor || null }).eq('nick', nick);
  for (const [n, user] of onlineUsers) if (n !== nick) user.ws.send(JSON.stringify({ type: 'nick_color_changed', nick, nickColor: nickColor || null }));
  res.json({ ok: true });
});

app.post('/update-avatar', async (req, res) => {
  const { avatarUrl } = req.body; const nick = req.nick; if (!nick) return res.json({ ok: false, error: 'Нік обов\'язковий' });
  await supabase.from('users').update({ avatar_url: avatarUrl || null }).eq('nick', nick);
  for (const [n, user] of onlineUsers) if (n !== nick) user.ws.send(JSON.stringify({ type: 'avatar_changed', nick, avatarUrl: avatarUrl || null }));
  res.json({ ok: true });
});

app.post('/update-status', async (req, res) => {
  const { status } = req.body; const nick = req.nick; if (!nick) return res.json({ ok: false, error: 'Нік обов\'язковий' });
  const newStatus = status && status.trim().length > 0 ? status.trim().substring(0, 60) : null;
  await supabase.from('users').update({ status: newStatus }).eq('nick', nick);
  if (!invisibleNicks.has(nick)) {
    for (const [n, user] of onlineUsers) if (n !== nick) user.ws.send(JSON.stringify({ type: 'user_status', nick, status: newStatus }));
  }
  res.json({ ok: true, status: newStatus });
});

app.post('/transfer-coins', async (req, res) => {
  const { toNick, amount } = req.body;
  const fromNick = req.nick; // Фаза 1: платник — ЛИШЕ автентифікований юзер, не з тіла.
  if (!fromNick || !toNick || !amount || amount < 1) return res.json({ ok: false, error: 'Невірні параметри' });
  if (fromNick === toNick) return res.json({ ok: false, error: 'Не можна переказати собі' });
  const { data: receiver } = await supabase.from('users').select('nick').eq('nick', toNick).single();
  if (!receiver) return res.json({ ok: false, error: 'Отримувача не знайдено' });
  // Атомарне списання у відправника (повна сума).
  const { data: senderBalance, error: spendErr } = await supabase.rpc('spend_coins', { p_nick: fromNick, p_amount: amount });
  if (spendErr) return res.json({ ok: false, error: 'Помилка списання' });
  if (senderBalance === -1) return res.json({ ok: false, error: 'Недостатньо монет' });
  // Комісія відраховується ІЗ суми: отримувач отримує net, решта → компанії.
  const fee = Math.floor(amount * TRANSFER_FEE_PCT / 100);
  const netAmount = amount - fee;
  // Атомарне нарахування отримувачу (net). Якщо провалиться — повертаємо повну суму.
  const { data: newReceiverCoins, error: addErr } = await supabase.rpc('add_coins', { p_nick: toNick, p_amount: netAmount });
  if (addErr || newReceiverCoins === null) {
    await supabase.rpc('add_coins', { p_nick: fromNick, p_amount: amount }); // повертаємо кошти
    await logTx({ fromNick: null, toNick: fromNick, amount, kind: 'transfer_refund', ref: toNick });
    return res.json({ ok: false, error: 'Помилка переказу' });
  }
  // Комісія → компанії (EION) з live-нотифікацією + журнал. Не критично для
  // успіху переказу, тож без rollback.
  if (toNick !== COMPANY_NICK && fromNick !== COMPANY_NICK) {
    await creditCompany(fee, 'transfer_fee', { fromNick, ref: toNick });
  }
  await logTx({ fromNick, toNick, amount: netAmount, kind: 'transfer' });
  sendToUser(fromNick, { type: 'coins_update', amount: -amount, total: senderBalance });
  sendToUser(toNick, { type: 'coins_received', fromNick, amount: netAmount, total: newReceiverCoins });
  res.json({ ok: true, newBalance: senderBalance, fee, netAmount });
});

app.post('/call-log', async (req, res) => {
  const { fromNick, toNick, hasVideo, startedAt, durationSeconds, status } = req.body;
  if (!fromNick || !toNick || !startedAt || !status) return res.json({ ok: false, error: 'Невірні параметри' });
  // Актор має бути учасником дзвінка (вхідний/вихідний — обидві сторони логують).
  if (req.nick !== fromNick && req.nick !== toNick) return res.status(403).json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('call_logs').insert({ from_nick: fromNick, to_nick: toNick, has_video: hasVideo || false, started_at: startedAt, duration_seconds: durationSeconds || null, status });
  // Realtime: повідомляємо обидві онлайн-сторони перезавантажити логи (each reloads counterpart).
  // Кожен send у try/catch: мертвий сокет першого не має зривати пуш другому.
  const fromWs = onlineUsers.get(fromNick);
  const toWs = onlineUsers.get(toNick);
  console.log(`call-log: ${fromNick}->${toNick} ${status}; push from=${!!fromWs} to=${!!toWs}`);
  try { if (fromWs) fromWs.ws.send(JSON.stringify({ type: 'call_log_new', otherNick: toNick })); } catch (e) { console.log('call-log push from failed:', e.message); }
  try { if (toWs) toWs.ws.send(JSON.stringify({ type: 'call_log_new', otherNick: fromNick })); } catch (e) { console.log('call-log push to failed:', e.message); }
  res.json({ ok: true });
});

app.get('/call-logs', async (req, res) => {
  const { nick, otherNick } = req.query; if (!nick || !otherNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data } = await supabase.from('call_logs').select('*').or(`and(from_nick.eq.${nick},to_nick.eq.${otherNick}),and(from_nick.eq.${otherNick},to_nick.eq.${nick})`).order('started_at', { ascending: true });
  res.json({ ok: true, logs: data || [] });
});

app.delete('/call-logs', async (req, res) => {
  const { nick, otherNick } = req.query; if (!nick || !otherNick) return res.json({ ok: false, error: 'Невірні параметри' });
  await supabase.from('call_logs').delete().or(`and(from_nick.eq.${nick},to_nick.eq.${otherNick}),and(from_nick.eq.${otherNick},to_nick.eq.${nick})`);
  res.json({ ok: true });
});

// Storage 2.2 (аудит #2): підписаний upload-URL. Раніше клієнт заливав файли
// напряму anon-ключем (він у APK → будь-хто міг заливати/перезаписувати довільні
// файли). Тепер заливка можлива лише в автентифікованій сесії: сервер service-
// ключем видає одноразовий підписаний URL, клієнт заливає по ньому. Після переходу
// всіх клієнтів прибираємо anon INSERT-політики (migrations/storage_lockdown_2_2.sql).
app.post('/storage/signed-upload', async (req, res) => {
  const { bucket, path, upsert } = req.body;
  if (!bucket || !path || !STORAGE_BUCKETS_SET.has(bucket)) {
    return res.json({ ok: false, error: 'Невірні параметри' });
  }
  // Санітизація шляху: без обходу вгору й провідного слеша, розумна довжина.
  if (typeof path !== 'string' || path.includes('..') || path.startsWith('/') || path.length > 300) {
    return res.json({ ok: false, error: 'Невірний шлях' });
  }
  try {
    const { data, error } = await supabase.storage.from(bucket)
      .createSignedUploadUrl(path, { upsert: upsert !== false });
    if (error || !data) return res.json({ ok: false, error: error?.message || 'Не вдалось створити URL' });
    res.json({ ok: true, token: data.token, path: data.path, signedUrl: data.signedUrl });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

// Storage 2.3: пакетний підпис медіа-рефів для клієнта (ехо щойновідправленого,
// кеш аватарів тощо). Приймає масив рефів `eion://bucket/path`, повертає підписані
// URL у ТОМУ Ж порядку. Не-рефи повертаються без змін. Автентифіковано (req.nick).
app.post('/storage/resolve', async (req, res) => {
  const refs = Array.isArray(req.body && req.body.refs) ? req.body.refs : null;
  if (!refs) return res.json({ ok: false, error: 'refs обовʼязкові' });
  if (refs.length > 100) return res.json({ ok: false, error: 'Забагато рефів' });
  try {
    const urls = await Promise.all(refs.map(signMediaRef));
    res.json({ ok: true, urls });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

// Пропущені дзвінки для nick ПІСЛЯ since (мс). Клієнт викликає на login_ok, щоб
// сповістити про дзвінки, що надійшли, поки він був офлайн (сокет мертвий → лог
// missed створюється тут-таки при call_offer, але клієнт про це не дізнавався,
// бо логи підвантажуються лише при відкритті конкретного чату).
// status: 'missed' (не додзвонились / офлайн) і 'no_answer' (скасовано до відповіді) —
// обидва з погляду to_nick це пропущений. 'rejected'/'completed' не рахуємо.
app.get('/missed-calls', async (req, res) => {
  const { nick, since } = req.query;
  if (!nick) return res.json({ ok: false, error: 'Невірні параметри' });
  const sinceTs = parseInt(since, 10) || 0;
  const { data } = await supabase.from('call_logs')
    .select('from_nick, has_video, started_at, status')
    .eq('to_nick', nick)
    .in('status', ['missed', 'no_answer'])
    .gt('started_at', sinceTs)
    .order('started_at', { ascending: false });
  // Дедуп: один дзвінок може лишити і 'missed' (сервер, offer-time), і
  // 'no_answer' (той-хто-дзвонив, скасування) — близькі за часом від того ж
  // відправника. Згортаємо в один запис, щоб не рахувати двічі.
  const missed = [];
  for (const c of data || []) {
    if (missed.some(k => k.from_nick === c.from_nick && Math.abs(k.started_at - c.started_at) < 10000)) continue;
    missed.push(c);
  }
  res.json({ ok: true, missed });
});

// Прибирає передчасний 'missed'-лог пари (створюється при call_offer, коли
// адресат у фоні → FCM). Кличемо, коли дзвінок завершився НЕ пропущеним:
// прийняли (call_answer) АБО свідомо відхилили (call_reject / decline). Без
// цього відхилений дзвінок лишав по собі І 'missed', І 'rejected' → зайвий
// третій лог у адресата + хибне сповіщення «пропущений» при відкритті застосунку.
async function clearPreemptiveMissed(callerNick, calleeNick) {
  try {
    // Видаляємо ЛИШЕ НАЙНОВІШИЙ передчасний missed цієї пари — він відповідає
    // ПОТОЧНОМУ дзвінку (offer щойно був). Старіші missed чіпати НЕ можна: якщо
    // дзвінок A не підняли (законний «пропущений»), а наступний дзвінок B
    // відхилили — стирання всіх missed за вікном згубило б законний missed від A.
    const { data } = await supabase.from('call_logs')
      .select('id')
      .eq('from_nick', callerNick).eq('to_nick', calleeNick).eq('status', 'missed')
      .gt('started_at', Date.now() - 120000)
      .order('started_at', { ascending: false })
      .limit(1);
    if (data && data.length) {
      await supabase.from('call_logs').delete().eq('id', data[0].id);
    }
  } catch (_) {}
}

// ── Групи ──────────────────────────────────────
app.post('/group/create', async (req, res) => {
  const { name, members, type } = req.body; const creatorNick = req.nick;
  if (!name || name.trim().length < 1) return res.json({ ok: false, error: 'Назва групи порожня' });
  const groupType = type || 'closed';
  const { data: group, error } = await supabase.from('groups').insert({ name: name.trim(), creator_nick: creatorNick, type: groupType }).select().single();
  if (error) return res.json({ ok: false, error: 'Помилка створення групи' });
  await supabase.from('group_members').insert({ group_id: group.id, nick: creatorNick, role: 'creator' });
  for (const nick of (members || [])) { if (nick === creatorNick) continue; await sendGroupInvite(group.id, group.name, creatorNick, nick); }
  res.json({ ok: true, group: { id: group.id, name: group.name, creator_nick: group.creator_nick, type: group.type }, members: [creatorNick] });
});

app.post('/group/invite-response', async (req, res) => {
  const { groupId, accepted } = req.body; const nick = req.nick;
  if (accepted) {
    const { data: existing } = await supabase.from('group_members').select('nick').eq('group_id', groupId).eq('nick', nick).single();
    if (!existing) await supabase.from('group_members').insert({ group_id: groupId, nick, role: 'member' });
    const { data: group } = await supabase.from('groups').select('*').eq('id', groupId).single();
    const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', groupId);
    await notifyMembers(groupId, { type: 'group_member_added', groupId, nick }, nick);
    res.json({ ok: true, group: { id: group.id, name: group.name, creator_nick: group.creator_nick, type: group.type }, members: (members || []).map(m => m.nick) });
  } else res.json({ ok: true });
  await supabase.from('pending_group_invites').delete().eq('group_id', groupId).eq('target_nick', nick);
});

app.get('/group/list', async (req, res) => {
  const { nick } = req.query;
  const { data: memberships } = await supabase.from('group_members').select('group_id, role').eq('nick', nick);
  if (!memberships || memberships.length === 0) return res.json({ ok: true, groups: [] });
  const ids = memberships.map(m => m.group_id);
  const roleMap = Object.fromEntries(memberships.map(m => [m.group_id, m.role]));
  const { data: groups } = await supabase.from('groups').select('*').in('id', ids);
  const readMap = await getChatReadMap(nick, 'group', ids);
  const result = [];
  const toSeed = []; const nowTs = Date.now();
  for (const g of groups || []) {
    const { data: members } = await supabase.from('group_members').select('nick, role').eq('group_id', g.id);
    // Непрочитане = чужі повідомлення новіші за вказівник "останнє прочитане".
    // Немає вказівника (перший показ після фічі) → історія вважається прочитаною:
    // засіваємо вказівник = зараз і повертаємо 0, інакше в бейджі світилась би ВСЯ
    // історія. Далі рахуються лише повідомлення, новіші за цей момент.
    const ptr = readMap[g.id];
    let unread = 0;
    if (ptr === undefined) {
      toSeed.push({ nick, chat_type: 'group', chat_id: g.id, last_read_ts: nowTs });
    } else {
      const { count } = await supabase.from('group_messages')
        .select('*', { count: 'exact', head: true })
        .eq('group_id', g.id).neq('from_nick', nick)
        .gt('timestamp', ptr);
      unread = count || 0;
    }
    result.push({ ...g, members: (members || []).map(m => m.nick), memberRoles: Object.fromEntries((members || []).map(m => [m.nick, m.role])), myRole: roleMap[g.id], unread });
  }
  if (toSeed.length) { try { await supabase.from('chat_reads').upsert(toSeed, { onConflict: 'nick,chat_type,chat_id' }); } catch (_) {} }
  res.json({ ok: true, groups: result });
});

// Позначити групу/канал прочитаним — зсуває вказівник last_read_ts у Date.now(),
// щоб наступний /group/list чи /channel/list дав unread=0. Клієнт кличе при
// відкритті й закритті чату. actor-нік — із сесії (req.nick), не з тіла (аудит #1).
app.post('/chat/mark-read', async (req, res) => {
  const nick = req.nick;
  const { type, id } = req.body;
  if (!nick || (type !== 'group' && type !== 'channel') || id == null) {
    return res.json({ ok: false, error: 'Невірні параметри' });
  }
  await supabase.from('chat_reads').upsert(
    { nick, chat_type: type, chat_id: id, last_read_ts: Date.now() },
    { onConflict: 'nick,chat_type,chat_id' });
  res.json({ ok: true });
});

app.get('/group/search', async (req, res) => {
  const { query, nick } = req.query;
  if (!query || query.trim().length < 2) return res.json({ ok: false, error: 'Введіть мін. 2 символи' });
  const { data: groups } = await supabase.from('groups').select('*').ilike('name', `%${query}%`).in('type', ['open', 'approval']);
  const result = [];
  for (const g of groups || []) {
    const { data: membership } = await supabase.from('group_members').select('nick').eq('group_id', g.id).eq('nick', nick).single();
    if (!membership) { const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', g.id); result.push({ ...g, memberCount: (members || []).length }); }
  }
  res.json({ ok: true, groups: result });
});

app.post('/group/join', async (req, res) => {
  const { groupId } = req.body; const nick = req.nick;
  const { data: group } = await supabase.from('groups').select('*').eq('id', groupId).single();
  if (!group) return res.json({ ok: false, error: 'Групу не знайдено' });
  if (group.type === 'closed') return res.json({ ok: false, error: 'Група закрита' });
  const { data: existing } = await supabase.from('group_members').select('nick').eq('group_id', groupId).eq('nick', nick).single();
  if (existing) return res.json({ ok: false, error: 'Ви вже в групі' });
  if (group.type === 'open') {
    await supabase.from('group_members').insert({ group_id: groupId, nick, role: 'member' });
    const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', groupId);
    await notifyMembers(groupId, { type: 'group_member_added', groupId, nick }, nick);
    const t = onlineUsers.get(nick); if (t) t.ws.send(JSON.stringify({ type: 'group_added', group: { id: group.id, name: group.name, creator_nick: group.creator_nick, type: group.type }, members: (members || []).map(m => m.nick) }));
    return res.json({ ok: true, joined: true });
  }
  if (group.type === 'approval') {
    await supabase.from('group_join_requests').upsert({ group_id: groupId, nick, status: 'pending' });
    const { data: mods } = await supabase.from('group_members').select('nick').eq('group_id', groupId).in('role', ['creator', 'moderator']);
    for (const mod of mods || []) { const t = onlineUsers.get(mod.nick); if (t) t.ws.send(JSON.stringify({ type: 'group_join_request', groupId, groupName: group.name, nick })); }
    return res.json({ ok: true, joined: false, pending: true });
  }
});

app.post('/group/approve', async (req, res) => {
  const { groupId, targetNick, approve } = req.body; const requesterNick = req.nick;
  if (!(await isModOrCreator(groupId, requesterNick))) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('group_join_requests').update({ status: approve ? 'approved' : 'rejected' }).eq('group_id', groupId).eq('nick', targetNick);
  const t = onlineUsers.get(targetNick);
  if (approve) {
    const { data: group } = await supabase.from('groups').select('*').eq('id', groupId).single();
    await supabase.from('group_members').insert({ group_id: groupId, nick: targetNick, role: 'member' });
    const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', groupId);
    if (t) t.ws.send(JSON.stringify({ type: 'group_added', group: { id: group.id, name: group.name, creator_nick: group.creator_nick, type: group.type }, members: (members || []).map(m => m.nick) }));
    await notifyMembers(groupId, { type: 'group_member_added', groupId, nick: targetNick }, targetNick);
  } else { if (t) t.ws.send(JSON.stringify({ type: 'group_request_rejected', groupId })); }
  res.json({ ok: true });
});

app.post('/group/set-type', async (req, res) => {
  const { groupId, groupType } = req.body; const requesterNick = req.nick;
  const { data: member } = await supabase.from('group_members').select('role').eq('group_id', groupId).eq('nick', requesterNick).single();
  if (!member || member.role !== 'creator') return res.json({ ok: false, error: 'Тільки творець може змінювати тип групи' });
  await supabase.from('groups').update({ type: groupType }).eq('id', groupId);
  await notifyMembers(groupId, { type: 'group_type_changed', groupId, groupType });
  res.json({ ok: true });
});

app.post('/group/set-moderator', async (req, res) => {
  const { groupId, targetNick, isModerator } = req.body; const requesterNick = req.nick;
  const { data: member } = await supabase.from('group_members').select('role').eq('group_id', groupId).eq('nick', requesterNick).single();
  if (!member || member.role !== 'creator') return res.json({ ok: false, error: 'Тільки творець може призначати модераторів' });
  const newRole = isModerator ? 'moderator' : 'member';
  await supabase.from('group_members').update({ role: newRole }).eq('group_id', groupId).eq('nick', targetNick);
  await notifyMembers(groupId, { type: 'group_role_changed', groupId, nick: targetNick, role: newRole });
  res.json({ ok: true });
});

app.post('/group/add-member', async (req, res) => {
  const { groupId, newNick } = req.body; const requesterNick = req.nick;
  if (!(await isModOrCreator(groupId, requesterNick))) return res.json({ ok: false, error: 'Тільки модератор або творець може запрошувати учасників' });
  const { data: existing } = await supabase.from('group_members').select('nick').eq('group_id', groupId).eq('nick', newNick).single();
  if (existing) return res.json({ ok: false, error: 'Користувач вже в групі' });
  const { data: group } = await supabase.from('groups').select('name').eq('id', groupId).single();
  await sendGroupInvite(groupId, group.name, requesterNick, newNick);
  res.json({ ok: true, invited: true });
});

app.post('/group/remove-member', async (req, res) => {
  const { groupId, targetNick } = req.body; const requesterNick = req.nick;
  if (requesterNick !== targetNick && !(await isModOrCreator(groupId, requesterNick))) return res.json({ ok: false, error: 'Тільки модератор або творець може видаляти учасників' });
  await supabase.from('group_members').delete().eq('group_id', groupId).eq('nick', targetNick);
  sendToUser(targetNick, { type: 'group_removed', groupId });
  await notifyMembers(groupId, { type: 'group_member_removed', groupId, nick: targetNick });
  res.json({ ok: true });
});

app.get('/group/join-requests', async (req, res) => {
  const { groupId, nick } = req.query;
  if (!(await isModOrCreator(groupId, nick))) return res.json({ ok: false, error: 'Недостатньо прав' });
  const { data } = await supabase.from('group_join_requests').select('*').eq('group_id', groupId).eq('status', 'pending');
  res.json({ ok: true, requests: data || [] });
});

app.post('/group/delete', async (req, res) => {
  const { groupId } = req.body; const requesterNick = req.nick;
  const { data: member } = await supabase.from('group_members').select('role').eq('group_id', groupId).eq('nick', requesterNick).single();
  if (!member || member.role !== 'creator') return res.json({ ok: false, error: 'Тільки творець може видалити групу' });
  const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', groupId);
  await supabase.from('group_messages').delete().eq('group_id', groupId);
  await supabase.from('group_members').delete().eq('group_id', groupId);
  await supabase.from('group_join_requests').delete().eq('group_id', groupId);
  await supabase.from('pending_group_invites').delete().eq('group_id', groupId);
  await supabase.from('groups').delete().eq('id', groupId);
  for (const m of members || []) { const t = onlineUsers.get(m.nick); if (t) t.ws.send(JSON.stringify({ type: 'group_deleted', groupId })); }
  res.json({ ok: true });
});

// ═══ Блокування контактів (direct: повідомлення + дзвінки) ═══
app.post('/contact/block', async (req, res) => {
  const { targetNick } = req.body; const nick = req.nick;
  if (!nick || !targetNick) return res.json({ ok: false, error: 'Невірні параметри' });
  if (nick === targetNick) return res.json({ ok: false, error: 'Не можна заблокувати самого себе' });
  const { data, error } = await supabase.from('blocked_contacts').upsert(
    { blocker_nick: nick, blocked_nick: targetNick, blocked_at: Date.now() },
    { onConflict: 'blocker_nick,blocked_nick' }).select();
  if (error) { console.log('[contact/block] SUPABASE ERROR:', JSON.stringify(error)); return res.json({ ok: false, error: error.message }); }
  console.log('[contact/block] OK inserted:', JSON.stringify(data));
  res.json({ ok: true });
});

// Перемикач глобального блоку вхідних. При ВВІМКНЕННІ очищаємо allowlist
// (чистий аркуш: пишуть лише ті, кому власник напише вже за цього блоку).
// Перемикач режиму невидимості (лише для системного акаунта EION). Оновлює
// прапорець у БД + in-memory набір invisibleNicks (для presence без запиту в БД).
app.post('/settings/invisible', async (req, res) => {
  const { enabled } = req.body; const nick = req.nick;
  if (!nick || typeof enabled !== 'boolean') return res.json({ ok: false, error: 'Невірні параметри' });
  // Захист: невидимість доступна лише EION (системний акаунт).
  if (nick !== COMPANY_NICK) return res.json({ ok: false, error: 'Недоступно' });
  const { error } = await supabase.from('users').update({ invisible: enabled }).eq('nick', nick);
  if (error) return res.json({ ok: false, error: 'Помилка збереження' });
  if (enabled) invisibleNicks.add(nick); else invisibleNicks.delete(nick);
  res.json({ ok: true, invisible: enabled });
});

app.post('/settings/block-incoming', async (req, res) => {
  const { enabled } = req.body; const nick = req.nick;
  if (!nick || typeof enabled !== 'boolean') return res.json({ ok: false, error: 'Невірні параметри' });
  const { error } = await supabase.from('users').update({ block_incoming: enabled }).eq('nick', nick);
  if (error) return res.json({ ok: false, error: 'Помилка збереження' });
  if (enabled) {
    await supabase.from('block_allowlist').delete().eq('owner_nick', nick);
  }
  res.json({ ok: true, blockIncoming: enabled });
});

app.post('/contact/unblock', async (req, res) => {
  const { targetNick } = req.body; const nick = req.nick;
  if (!nick || !targetNick) return res.json({ ok: false, error: 'Невірні параметри' });
  await supabase.from('blocked_contacts').delete().eq('blocker_nick', nick).eq('blocked_nick', targetNick);
  res.json({ ok: true });
});

app.get('/contact/blocked-list', async (req, res) => {
  const { nick } = req.query;
  if (!nick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data } = await supabase.from('blocked_contacts').select('blocked_nick, blocked_at').eq('blocker_nick', nick);
  res.json({ ok: true, blocked: (data || []).map(r => r.blocked_nick) });
});

// Тимчасовий маркер версії — щоб однозначно підтвердити, яка збірка задеплоєна.
app.get('/contact/version-check', (req, res) => {
  res.json({ ok: true, marker: 'sticker-pending-v4-2026-07-11' });
});

app.get('/direct/reactions', async (req, res) => {
  const { me, other } = req.query;
  if (!me || !other) return res.json({ ok: false, error: 'Невірні параметри' });
  const pairKey = [me, other].sort().join('|');
  const { data } = await supabase.from('direct_message_reactions').select('msg_id, emoji, from_nick').eq('pair_key', pairKey);
  const byMsg = {};
  for (const r of data || []) {
    if (!byMsg[r.msg_id]) byMsg[r.msg_id] = {};
    if (!byMsg[r.msg_id][r.emoji]) byMsg[r.msg_id][r.emoji] = [];
    byMsg[r.msg_id][r.emoji].push(r.from_nick);
  }
  res.json({ ok: true, reactions: byMsg });
});

app.get('/group/messages', async (req, res) => {
  const { groupId, nick, before } = req.query;
  const limit = Math.min(parseInt(req.query.limit) || 100, 200);
  let clearedAt = 0;
  if (nick) {
    const { data: clRows } = await supabase.from('group_history_cleared').select('cleared_at').eq('nick', nick).eq('group_id', groupId).limit(1);
    if (clRows && clRows[0] && clRows[0].cleared_at) clearedAt = Number(clRows[0].cleared_at);
  }
  // Беремо ОСТАННІ limit повідомлень (descending + limit), потім розвертаємо в
  // ascending — порядок на виході той самий, що був, тож клієнт сумісний.
  // before (timestamp) — для підвантаження старіших (Б2, прокрутка вгору).
  let q = supabase.from('group_messages').select('*').eq('group_id', groupId);
  if (before) q = q.lt('timestamp', Number(before));
  if (clearedAt) q = q.gt('timestamp', clearedAt);
  q = q.order('timestamp', { ascending: false }).limit(limit + 1);
  const { data: rawDesc } = await q;
  const rows = rawDesc || [];
  const hasMore = rows.length > limit;        // є ще старіші
  const page = hasMore ? rows.slice(0, limit) : rows;
  const visible = page.slice().reverse();     // назад в ascending
  console.log(`[group/messages] groupId=${groupId} before=${before || '-'} limit=${limit} → returned=${visible.length} hasMore=${hasMore}`);
  const msgIds = visible.map(m => m.msg_id).filter(Boolean);
  const reactionsByMsg = {};
  if (msgIds.length) {
    const { data: reacts } = await supabase.from('group_message_reactions').select('msg_id, emoji, nick').eq('group_id', groupId).in('msg_id', msgIds);
    for (const r of reacts || []) {
      if (!reactionsByMsg[r.msg_id]) reactionsByMsg[r.msg_id] = {};
      if (!reactionsByMsg[r.msg_id][r.emoji]) reactionsByMsg[r.msg_id][r.emoji] = [];
      reactionsByMsg[r.msg_id][r.emoji].push(r.nick);
    }
  }
  res.json({ ok: true, hasMore, oldest: visible[0]?.timestamp ?? null, messages: visible.map(m => ({ ...m, type: m.type || 'text', file_name: m.file_name || null, file_data: m.file_data || null, waveform: m.waveform || null, duration_sec: m.duration_sec || null, replyToMsgId: m.reply_to_msg_id || null, replyToText: m.reply_to_text || null, replyToFrom: m.reply_to_from || null, replyToImage: m.reply_to_image || null, reactions: reactionsByMsg[m.msg_id] || {} })) });
});

// Очистити історію групи лише для себе (персистентний маркер часу)
app.post('/group/clear-history', async (req, res) => {
  const { groupId } = req.body; const nick = req.nick;
  if (!groupId || !nick) return res.json({ ok: false, error: 'Невірні параметри' });
  await supabase.from('group_history_cleared').upsert({ nick, group_id: groupId, cleared_at: Date.now() }, { onConflict: 'nick,group_id' });
  res.json({ ok: true });
});

app.get('/check-phone', async (req, res) => {
  const { phoneNormalized } = req.query;
  if (!phoneNormalized) return res.json({ exists: false });
  const { data } = await supabase.from('users').select('nick').eq('phone_normalized', phoneNormalized).single();
  res.json({ exists: !!data });
});

// ── Магазин Premium ──────────────────────────
app.post('/shop/buy-premium', async (req, res) => {
  const { plan } = req.body;
  const nick = req.nick; // Фаза 1: покупець — автентифікований юзер.
  if (!nick || !plan) return res.json({ ok: false, error: 'Невірні параметри' });
  const PRICES = { monthly: 500, yearly: 4200 };
  const price = PRICES[plan];
  if (!price) return res.json({ ok: false, error: 'Невідомий план' });
  const { data: user } = await supabase.from('users').select('premium_expires_at').eq('nick', nick).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  // Атомарне списання: spend_coins повертає новий баланс або -1 (недостатньо).
  const { data: newBalance, error: spendErr } = await supabase.rpc('spend_coins', { p_nick: nick, p_amount: price });
  if (spendErr) return res.json({ ok: false, error: 'Помилка списання' });
  if (newBalance === -1) return res.json({ ok: false, error: `Недостатньо EION (потрібно ${price})` });
  // Дохід від преміуму → компанії (EION) з live-нотифікацією + журнал.
  await creditCompany(price, 'premium', { fromNick: nick, ref: plan });
  const now = new Date();
  let expiresAt = (user.premium_expires_at && new Date(user.premium_expires_at) > now)
    ? new Date(user.premium_expires_at) : new Date(now);
  if (plan === 'monthly') expiresAt.setMonth(expiresAt.getMonth() + 1);
  else expiresAt.setFullYear(expiresAt.getFullYear() + 1);
  await supabase.from('users').update({ premium_expires_at: expiresAt.toISOString(), premium_plan: plan }).eq('nick', nick);
  sendToUser(nick, { type: 'coins_update', amount: -price, total: newBalance });
  res.json({ ok: true, newBalance, expiresAt: expiresAt.toISOString(), plan });
});

// ═══════════════════════════════════════════════
//  МАГАЗИН НАЛІПОК (Крок 2A — читання, без списання коінів)
// ═══════════════════════════════════════════════

// Видає користувачу всі БЕЗКОШТОВНІ паки (price=0), яких у нього ще немає.
// Викликається при завантаженні магазину — щоб tech01 та інші безкоштовні
// одразу були "у власності" без окремої купівлі. Ідемпотентно (on conflict).
async function grantFreePacks(nick) {
  try {
    const { data: freePacks } = await supabase.from('sticker_packs').select('id').eq('price', 0).eq('is_active', true);
    if (!freePacks || freePacks.length === 0) return;
    const rows = freePacks.map(p => ({ nick, pack_id: p.id }));
    await supabase.from('user_sticker_packs').upsert(rows, { onConflict: 'nick,pack_id', ignoreDuplicates: true });
  } catch (e) {
    console.error('[grantFreePacks]', e.message);
  }
}

// Каталог магазину + позначка, які паки в користувача вже є.
// Тільки читання — нічого не списує.
app.get('/shop/sticker-packs', async (req, res) => {
  const nick = req.query.nick;
  if (!nick) return res.json({ ok: false, error: 'Невірні параметри' });
  await grantFreePacks(nick); // безкоштовні одразу у власності
  const { data: packs, error } = await supabase.from('sticker_packs')
    .select('id, title, price, preview_sticker, sort_order')
    .eq('is_active', true).order('sort_order', { ascending: true });
  if (error) {
    console.error('[shop/sticker-packs] select error:', error);
    return res.json({ ok: false, error: 'Помилка каталогу' });
  }
  const { data: owned } = await supabase.from('user_sticker_packs').select('pack_id').eq('nick', nick);
  const ownedSet = new Set((owned || []).map(o => o.pack_id));
  const result = (packs || []).map(p => ({
    id: p.id, title: p.title, price: p.price,
    previewSticker: p.preview_sticker,
    owned: ownedSet.has(p.id) || p.price === 0,
  }));
  res.json({ ok: true, packs: result });
});

// Список ID паків, якими користувач володіє (для панелі наліпок).
app.get('/shop/my-packs', async (req, res) => {
  const nick = req.query.nick;
  if (!nick) return res.json({ ok: false, error: 'Невірні параметри' });
  await grantFreePacks(nick);
  const { data: owned } = await supabase.from('user_sticker_packs').select('pack_id').eq('nick', nick);
  res.json({ ok: true, packIds: (owned || []).map(o => o.pack_id) });
});

// Купівля пака за коіни (Крок 2B). Порядок критичний для безпеки:
// 1) перевірити, що пак існує й активний, взяти ціну З БД (не з клієнта);
// 2) якщо вже володіє — повернути ok без списання (ідемпотентно);
// 3) атомарно списати коіни (spend_coins);
// 4) записати власність; якщо запис провалився — повернути коіни.
app.post('/shop/buy-pack', async (req, res) => {
  const { packId } = req.body;
  const nick = req.nick; // Фаза 1: покупець — автентифікований юзер.
  if (!nick || !packId) return res.json({ ok: false, error: 'Невірні параметри' });
  // Ціна — виключно з БД (клієнт не може її підмінити).
  const { data: pack } = await supabase.from('sticker_packs').select('id, price, is_active').eq('id', packId).single();
  if (!pack || !pack.is_active) return res.json({ ok: false, error: 'Пак недоступний' });
  // Вже володіє? — не списувати повторно.
  const { data: existing } = await supabase.from('user_sticker_packs').select('pack_id').eq('nick', nick).eq('pack_id', packId).maybeSingle();
  if (existing) return res.json({ ok: true, alreadyOwned: true });
  const price = pack.price || 0;
  // Безкоштовний — просто видаємо, без списання.
  if (price === 0) {
    await supabase.from('user_sticker_packs').upsert([{ nick, pack_id: packId }], { onConflict: 'nick,pack_id', ignoreDuplicates: true });
    return res.json({ ok: true, granted: true });
  }
  // Платний — атомарне списання.
  const { data: newBalance, error: spendErr } = await supabase.rpc('spend_coins', { p_nick: nick, p_amount: price });
  if (spendErr) return res.json({ ok: false, error: 'Помилка списання' });
  if (newBalance === -1) return res.json({ ok: false, error: `Недостатньо EION (потрібно ${price})` });
  // Записуємо власність. Якщо провалилось — повертаємо коіни (щоб не списати даремно).
  const { error: ownErr } = await supabase.from('user_sticker_packs').insert({ nick, pack_id: packId });
  if (ownErr) {
    // Можливо, паралельний запит уже записав власність (гонка) — перевіряємо.
    const { data: recheck } = await supabase.from('user_sticker_packs').select('pack_id').eq('nick', nick).eq('pack_id', packId).maybeSingle();
    if (!recheck) {
      await supabase.rpc('add_coins', { p_nick: nick, p_amount: price }); // повертаємо кошти
      await logTx({ fromNick: null, toNick: nick, amount: price, kind: 'pack_refund', ref: packId });
      return res.json({ ok: false, error: 'Помилка купівлі' });
    }
  }
  // Дохід від паку → компанії (EION) з live-нотифікацією + журнал. Після
  // успішного запису власності, щоб при поверненні не нарахувати за скасовану купівлю.
  await creditCompany(price, 'pack', { fromNick: nick, ref: packId });
  sendToUser(nick, { type: 'coins_update', amount: -price, total: newBalance });
  res.json({ ok: true, newBalance, packId });
});

app.post('/group/update', async (req, res) => {
  const { groupId, name, avatarUrl } = req.body; const requesterNick = req.nick;
  if (!groupId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('group_members').select('role').eq('group_id', groupId).eq('nick', requesterNick).single();
  if (!member || !['creator', 'moderator'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  const updates = {};
  if (name !== undefined && name.trim().length > 0) updates.name = name.trim();
  if (avatarUrl !== undefined) updates.avatar_url = avatarUrl;
  if (Object.keys(updates).length === 0) return res.json({ ok: false, error: 'Нічого оновлювати' });
  await supabase.from('groups').update(updates).eq('id', groupId);
  await notifyMembers(groupId, { type: 'group_updated', groupId, ...updates });
  res.json({ ok: true });
});

app.get('/ping', (req, res) => res.json({ ok: true }));

// ── Закріплені повідомлення груп ──────────────────────────────
// Закріпити (creator/moderator). Клієнт шле прев'ю (text) + автора (from) + msgId.
app.post('/group/pin', async (req, res) => {
  const { groupId, msgId, text, from } = req.body; const requesterNick = req.nick;
  if (!groupId || !requesterNick || !msgId) return res.json({ ok: false, error: 'Невірні параметри' });
  if (!(await isModOrCreator(groupId, requesterNick))) return res.json({ ok: false, error: 'Недостатньо прав' });
  const pinnedAt = Date.now();
  await supabase.from('groups').update({ pinned_msg_id: msgId, pinned_text: text || null, pinned_from: from || null, pinned_at: pinnedAt }).eq('id', groupId);
  await notifyMembers(groupId, { type: 'group_pinned', groupId: Number(groupId), msgId, text: text || null, from: from || null, pinnedAt });
  res.json({ ok: true });
});

// Відкріпити (creator/moderator)
app.post('/group/unpin', async (req, res) => {
  const { groupId } = req.body; const requesterNick = req.nick;
  if (!groupId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри' });
  if (!(await isModOrCreator(groupId, requesterNick))) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('groups').update({ pinned_msg_id: null, pinned_text: null, pinned_from: null, pinned_at: null }).eq('id', groupId);
  await notifyMembers(groupId, { type: 'group_unpinned', groupId: Number(groupId) });
  res.json({ ok: true });
});


// ── Закріплені пости каналів (owner/admin) ──────────────────────────────
app.post('/channel/pin', async (req, res) => {
  const { channelId, postId, text, from } = req.body; const requesterNick = req.nick;
  if (!channelId || !requesterNick || !postId) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', requesterNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  const pinnedAt = Date.now();
  await supabase.from('channels').update({ pinned_post_id: String(postId), pinned_text: text || null, pinned_from: from || null, pinned_at: pinnedAt }).eq('id', channelId);
  await notifyChannelSubscribers(channelId, { type: 'channel_pinned', channelId: Number(channelId), postId: String(postId), text: text || null, from: from || null, pinnedAt }, null);
  res.json({ ok: true });
});

app.post('/channel/unpin', async (req, res) => {
  const { channelId } = req.body; const requesterNick = req.nick;
  if (!channelId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', requesterNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channels').update({ pinned_post_id: null, pinned_text: null, pinned_from: null, pinned_at: null }).eq('id', channelId);
  await notifyChannelSubscribers(channelId, { type: 'channel_unpinned', channelId: Number(channelId) }, null);
  res.json({ ok: true });
});


// ── Канали ──────────────────────────────────────
app.post('/channel/create', async (req, res) => {
  const { name, description, type, subscribers } = req.body; const ownerNick = req.nick;
  if (!ownerNick || !name || name.trim().length < 1) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: channel, error } = await supabase.from('channels').insert({
    name: name.trim(), description: description || null,
    owner_nick: ownerNick, type: type || 'public',
    created_at: Date.now(), last_post_at: null, last_post_text: null,
  }).select().single();
  if (error) return res.json({ ok: false, error: 'Помилка створення каналу' });
  await supabase.from('channel_members').insert({ channel_id: channel.id, nick: ownerNick, role: 'owner' });
  for (const nick of (subscribers || [])) {
    if (nick === ownerNick) continue;
    const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channel.id).eq('nick', nick).single();
    if (!blocked) await supabase.from('channel_members').insert({ channel_id: channel.id, nick, role: 'subscriber' }).catch(() => {});
  }
  res.json({ ok: true, channel: { ...channel, myRole: 'owner', subscriberCount: 1 + (subscribers || []).length, lastPostAt: null, lastPostText: null } });
});

app.get('/channel/list', async (req, res) => {
  const { nick } = req.query; if (!nick) return res.json({ ok: false, error: 'nick обов\'язковий' });
  const { data: memberships } = await supabase.from('channel_members').select('channel_id, role').eq('nick', nick);
  if (!memberships || memberships.length === 0) return res.json({ ok: true, channels: [] });
  const ids = memberships.map(m => m.channel_id);
  const roleMap = Object.fromEntries(memberships.map(m => [m.channel_id, m.role]));
  const { data: channels } = await supabase.from('channels').select('*').in('id', ids);
  const readMap = await getChatReadMap(nick, 'channel', ids);
  const result = [];
  const toSeed = []; const nowTs = Date.now();
  for (const c of channels || []) {
    const { count } = await supabase.from('channel_members').select('*', { count: 'exact', head: true }).eq('channel_id', c.id);
    // Непрочитане = чужі пости новіші за вказівник. Немає вказівника (перший показ)
    // → історія прочитана: засіваємо = зараз, повертаємо 0 (інакше світилась би вся історія).
    const ptr = readMap[c.id];
    let unread = 0;
    if (ptr === undefined) {
      toSeed.push({ nick, chat_type: 'channel', chat_id: c.id, last_read_ts: nowTs });
    } else {
      const { count: u } = await supabase.from('channel_messages')
        .select('*', { count: 'exact', head: true })
        .eq('channel_id', c.id).neq('from_nick', nick)
        .gt('timestamp', ptr);
      unread = u || 0;
    }
    const { data: lastPosts } = await supabase.from('channel_messages').select('content, image_url, file_name, timestamp').eq('channel_id', c.id).order('timestamp', { ascending: false }).limit(1);
    const lastPost = lastPosts && lastPosts.length > 0 ? lastPosts[0] : null;
    const lastPostAt = lastPost ? lastPost.timestamp : (c.last_post_at || c.created_at || null);
    // Пости-стріми й пости-наліпки зберігаються з маркером у content
    // ("[stream]videoId", "[sticker]packId:stickerId") — у прев'ю списку
    // каналів замість сирого маркера показуємо зрозумілий підпис.
    const previewText = (raw) => {
      if (raw.startsWith('[stream]')) return '📺 Трансляція';
      if (raw.startsWith('[sticker]')) return '🏷️ Наліпка';
      return raw.substring(0, 50);
    };
    const lastPostText = lastPost ? (lastPost.content ? previewText(lastPost.content) : (lastPost.image_url ? '🖼 Зображення' : (lastPost.file_name ? '📎 ' + lastPost.file_name.substring(0, 30) : ''))) : null;
    result.push({ ...c, myRole: roleMap[c.id], subscriberCount: count || 0, lastPostAt, lastPostText, unread });
  }
  if (toSeed.length) { try { await supabase.from('chat_reads').upsert(toSeed, { onConflict: 'nick,chat_type,chat_id' }); } catch (_) {} }
  result.sort((a, b) => (b.lastPostAt || 0) - (a.lastPostAt || 0));
  res.json({ ok: true, channels: result });
});

app.get('/channel/search', async (req, res) => {
  const { query, nick } = req.query;
  if (!query || query.trim().length < 2) return res.json({ ok: false, error: 'Введіть мін. 2 символи' });
  // Шукаємо публічні канали — nick може бути відсутній (незареєстрований пошук)
  const { data: channels } = await supabase.from('channels').select('*').ilike('name', `%${query}%`).eq('type', 'public');
  const result = [];
  for (const c of channels || []) {
    const { data: membership } = nick ? await supabase.from('channel_members').select('role').eq('channel_id', c.id).eq('nick', nick).single() : { data: null };
    const { count } = await supabase.from('channel_members').select('*', { count: 'exact', head: true }).eq('channel_id', c.id);
    result.push({ ...c, myRole: membership?.role || null, subscriberCount: count || 0 });
  }
  res.json({ ok: true, channels: result });
});

app.post('/channel/subscribe', async (req, res) => {
  const { channelId } = req.body; const nick = req.nick; if (!channelId || !nick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: channel } = await supabase.from('channels').select('type').eq('id', channelId).single();
  if (!channel) return res.json({ ok: false, error: 'Канал не знайдено' });
  if (channel.type === 'private') return res.json({ ok: false, error: 'Приватний канал — тільки за запрошенням' });
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', nick).single();
  if (blocked) return res.json({ ok: false, error: 'Ви заблоковані в цьому каналі' });
  const { data: existing } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  if (existing) return res.json({ ok: false, error: 'Ви вже підписані' });
  await supabase.from('channel_members').insert({ channel_id: channelId, nick, role: 'subscriber' });
  res.json({ ok: true });
});

app.post('/channel/unsubscribe', async (req, res) => {
  const { channelId } = req.body; const nick = req.nick; if (!channelId || !nick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  if (!member) return res.json({ ok: false, error: 'Ви не підписані' });
  if (member.role === 'owner') return res.json({ ok: false, error: 'Власник не може відписатись — видаліть канал' });
  await supabase.from('channel_members').delete().eq('channel_id', channelId).eq('nick', nick);
  res.json({ ok: true });
});

app.get('/channel/messages', async (req, res) => {
  const { channelId, nick } = req.query; if (!channelId) return res.json({ ok: false, error: 'channelId обов\'язковий' });
  // Гейт платного каналу: доступ мають власник/адмін або активна підписка
  const { data: paidCh } = await supabase.from('channels').select('is_paid, price, sub_days').eq('id', channelId).single();
  if (paidCh && paidCh.is_paid) {
    let hasAccess = false;
    if (nick) {
      const { data: mem } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
      if (mem && ['owner', 'admin'].includes(mem.role)) hasAccess = true;
      if (!hasAccess) {
        const { data: psubArr } = await supabase.from('channel_paid_subs').select('expires_at').eq('channel_id', channelId).eq('nick', nick).order('expires_at', { ascending: false }).limit(1);
        if (psubArr && psubArr[0] && Number(psubArr[0].expires_at) > Date.now()) hasAccess = true;
      }
    }
    if (!hasAccess) return res.json({ ok: true, locked: true, price: paidCh.price || 0, subDays: paidCh.sub_days || 30, messages: [] });
  }
  const { data: posts } = await supabase.from('channel_messages').select('*').eq('channel_id', channelId).order('timestamp', { ascending: true });
  if (!posts || posts.length === 0) return res.json({ ok: true, messages: [] });
  const postIds = posts.map(p => p.id);
  // Завантажуємо всі коментарі і реакції одним запитом
  const [commentsRes, reactionsRes] = await Promise.all([
    supabase.from('channel_comments').select('post_id, from_nick').in('post_id', postIds).order('timestamp', { ascending: false }),
    supabase.from('channel_reactions').select('post_id, emoji, nick').in('post_id', postIds),
  ]);
  const allComments = commentsRes.data || [];
  const allReactions = reactionsRes.data || [];
  const result = posts.map(p => {
    const postComments = allComments.filter(c => c.post_id === p.id);
    const postReactions = allReactions.filter(r => r.post_id === p.id);
    const topCommenters = [...new Set(postComments.map(c => c.from_nick))].slice(0, 3);
    return { ...p, commentCount: postComments.length, reactions: postReactions, topCommenters };
  });
  res.json({ ok: true, messages: result });
});

// POST /channel/message — підтримує text, imageUrl, fileData, fileName
app.post('/channel/message', async (req, res) => {
  const { channelId, text, imageUrl, fileData, fileName, waveform, durationSec, forwardedFrom } = req.body; const fromNick = req.nick;
  if (!channelId || !fromNick || (!text && !imageUrl && !fileData)) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', fromNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Тільки власник або адмін може писати' });
  const ts = Date.now(); const msgId = `ch_${channelId}_${ts}`;
  const isVideo = fileName && /\.(mp4|mov|avi|mkv|webm)$/i.test(fileName);
  const isVoice = fileName && fileName.startsWith('voice_');
  const { data: msg } = await supabase.from('channel_messages').insert({
    channel_id: channelId, from_nick: fromNick,
    content: text || null,
    image_url: imageUrl || null,
    file_data: fileData || null,
    file_name: fileName || null,
    timestamp: ts, msg_id: msgId,
    ...(forwardedFrom ? { forwarded_from: forwardedFrom } : {}),
    ...(waveform ? { waveform: JSON.stringify(waveform) } : {}),
    ...(durationSec != null ? { duration_sec: durationSec } : {}),
  }).select().single();
  const lastText = text ? text.substring(0, 50) : (imageUrl ? '🖼 Зображення' : (isVideo ? '🎬 Відео' : (isVoice ? '🎤 Голосове' : (fileName ? '📎 ' + fileName.substring(0, 30) : ''))));
  await supabase.from('channels').update({ last_post_at: ts, last_post_text: lastText }).eq('id', channelId);
  await notifyChannelSubscribers(channelId, { type: 'channel_message', channelId, postId: msg.id, from: fromNick, text: text || null, imageUrl: imageUrl || null, fileName: fileName || null, timestamp: ts, msgId, ...(forwardedFrom ? { forwardedFrom } : {}), message: { ...msg, commentCount: 0, reactions: [], topCommenters: [] } }, fromNick);
  res.json({ ok: true, message: { ...msg, commentCount: 0, reactions: [], topCommenters: [], waveform: waveform || null, duration_sec: durationSec || null } });
});

// Редагування поста (обидва шляхи для сумісності)
app.post('/channel/message/edit', async (req, res) => {
  const { channelId, postId, content } = req.body; const nick = req.nick;
  if (!channelId || !postId || !nick || !content) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  const { data: post } = await supabase.from('channel_messages').select('from_nick').eq('id', postId).single();
  if (!post) return res.json({ ok: false, error: 'Пост не знайдено' });
  const canEdit = post.from_nick === nick || (member && ['owner', 'admin'].includes(member.role));
  if (!canEdit) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channel_messages').update({ content, edited: true, edited_at: Date.now() }).eq('id', postId);
  await notifyChannelSubscribers(channelId, { type: 'channel_post_edited', channelId, postId, text: content }, null);
  res.json({ ok: true });
});

app.post('/channel/edit-message', async (req, res) => {
  const { channelId, postId, text } = req.body; const fromNick = req.nick;
  if (!channelId || !postId || !fromNick || !text) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', fromNick).single();
  const { data: post } = await supabase.from('channel_messages').select('from_nick').eq('id', postId).single();
  if (!post) return res.json({ ok: false, error: 'Пост не знайдено' });
  const canEdit = post.from_nick === fromNick || (member && ['owner', 'admin'].includes(member.role));
  if (!canEdit) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channel_messages').update({ content: text, edited: true, edited_at: Date.now() }).eq('id', postId);
  await notifyChannelSubscribers(channelId, { type: 'channel_post_edited', channelId, postId, text }, null);
  res.json({ ok: true });
});

// Видалення поста (обидва шляхи)
app.post('/channel/message/delete', async (req, res) => {
  const { channelId, postId } = req.body; const nick = req.nick;
  if (!postId || !channelId || !nick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  const { data: post } = await supabase.from('channel_messages').select('from_nick, image_url, file_data').eq('id', postId).single();
  if (!post) return res.json({ ok: false, error: 'Пост не знайдено' });
  const canDelete = post.from_nick === nick || (member && ['owner', 'admin'].includes(member.role));
  if (!canDelete) return res.json({ ok: false, error: 'Недостатньо прав' });
  const { data: postComments } = await supabase.from('channel_comments').select('file_data').eq('post_id', postId);
  await supabase.from('channel_comments').delete().eq('post_id', postId);
  await supabase.from('channel_reactions').delete().eq('post_id', postId);
  await supabase.from('channel_messages').delete().eq('id', postId);
  await removeChannelFile(post.image_url, post.file_data);
  for (const c of (postComments || [])) await removeChannelFile(c.file_data);
  await notifyChannelSubscribers(channelId, { type: 'channel_post_deleted', channelId, postId }, null);
  res.json({ ok: true });
});

app.delete('/channel/post', async (req, res) => {
  const { postId, channelId } = req.body; const requesterNick = req.nick;
  if (!postId || !channelId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', requesterNick).single();
  const { data: post } = await supabase.from('channel_messages').select('from_nick, image_url, file_data').eq('id', postId).single();
  if (!post) return res.json({ ok: false, error: 'Пост не знайдено' });
  const canDelete = post.from_nick === requesterNick || (member && ['owner', 'admin'].includes(member.role));
  if (!canDelete) return res.json({ ok: false, error: 'Недостатньо прав' });
  const { data: postComments } = await supabase.from('channel_comments').select('file_data').eq('post_id', postId);
  await supabase.from('channel_comments').delete().eq('post_id', postId);
  await supabase.from('channel_reactions').delete().eq('post_id', postId);
  await supabase.from('channel_messages').delete().eq('id', postId);
  await removeChannelFile(post.image_url, post.file_data);
  for (const c of (postComments || [])) await removeChannelFile(c.file_data);
  await notifyChannelSubscribers(channelId, { type: 'channel_post_deleted', channelId, postId }, null);
  res.json({ ok: true });
});

// Коментарі
app.get('/channel/comments', async (req, res) => {
  const { postId, before } = req.query; if (!postId) return res.json({ ok: false, error: 'postId обов\'язковий' });
  const limit = Math.min(parseInt(req.query.limit) || 100, 200);
  // Той самий двигун, що й /group/messages: беремо ОСТАННІ limit коментарів
  // (descending + limit), потім розвертаємо в ascending. before (timestamp) —
  // для довантаження старіших при скролі вгору.
  let q = supabase.from('channel_comments').select('*').eq('post_id', postId);
  if (before) q = q.lt('timestamp', Number(before));
  q = q.order('timestamp', { ascending: false }).limit(limit + 1);
  const { data: rawDesc } = await q;
  const rows = rawDesc || [];
  const hasMore = rows.length > limit;        // є ще старіші
  const page = hasMore ? rows.slice(0, limit) : rows;
  const comments = page.slice().reverse();    // назад в ascending
  console.log(`[channel/comments] postId=${postId} before=${before || '-'} limit=${limit} → returned=${comments.length} hasMore=${hasMore}`);
  const ids = comments.map(c => c.id);
  const reactionsByComment = {};
  if (ids.length > 0) {
    const { data: reacts } = await supabase.from('channel_comment_reactions').select('comment_id, emoji, nick').in('comment_id', ids);
    for (const r of reacts || []) {
      if (!reactionsByComment[r.comment_id]) reactionsByComment[r.comment_id] = [];
      reactionsByComment[r.comment_id].push({ emoji: r.emoji, nick: r.nick });
    }
  }
  const parseWf = (w) => { if (!w) return null; if (Array.isArray(w)) return w; try { return JSON.parse(w); } catch { return null; } };
  res.json({ ok: true, hasMore, oldest: comments[0]?.timestamp ?? null, comments: comments.map(c => ({ ...c, waveform: parseWf(c.waveform), reactions: reactionsByComment[c.id] || [] })) });
});

app.post('/channel/comment', async (req, res) => {
  const { channelId, postId, text, fileData, fileName, waveform, durationSec, replyToNick, replyToText, replyToImage, replyToId } = req.body; const fromNick = req.nick;
  if (!channelId || !postId || !fromNick || (!text && !fileData)) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', fromNick).single();
  if (blocked) return res.json({ ok: false, error: 'Ви заблоковані в цьому каналі' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', fromNick).single();
  if (!member) return res.json({ ok: false, error: 'Підпишіться на канал щоб коментувати' });
  const { data: postRow } = await supabase.from('channel_messages').select('comments_enabled').eq('id', postId).single();
  if (postRow && postRow.comments_enabled === false) return res.json({ ok: false, error: 'Коментарі вимкнені' });
  if (fileData) { const { data: chRow } = await supabase.from('channels').select('comments_allow_media').eq('id', channelId).single(); if (chRow && chRow.comments_allow_media === false) return res.json({ ok: false, error: 'Медіа в коментарях вимкнено' }); }
  const ts = Date.now();
  const { data: comment } = await supabase.from('channel_comments').insert({ channel_id: channelId, post_id: postId, from_nick: fromNick, content: text || fileName || '', file_data: fileData || null, file_name: fileName || null, timestamp: ts, reply_to_nick: replyToNick || null, reply_to_text: replyToText || null, reply_to_image: replyToImage || null, reply_to_id: replyToId || null, waveform: waveform ? JSON.stringify(waveform) : null, duration_sec: durationSec || null }).select().single();
  const { count: commentCount } = await supabase.from('channel_comments').select('*', { count: 'exact', head: true }).eq('post_id', postId);
  await notifyChannelSubscribers(channelId, { type: 'channel_comment', channelId, postId, from: fromNick, text: text || null, timestamp: ts, commentId: comment.id, commentCount: commentCount || 0, comment }, fromNick);
  res.json({ ok: true, comment: { ...comment, waveform: waveform || null } });
});

app.post('/channel/post/comments-toggle', async (req, res) => {
  const { channelId, postId, enabled } = req.body; const requesterNick = req.nick;
  if (!channelId || !postId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', requesterNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channel_messages').update({ comments_enabled: !!enabled }).eq('id', postId);
  res.json({ ok: true });
});

// Читач відкрив коментарі під постом → чужі коментарі позначаємо як побачені.
// Модель спрощена (на відміну від груп): другу галочку дає ПЕРШИЙ читач,
// синьої «прочитали всі» в каналах немає — множина підписників невизначена.
app.post('/channel/comments/read', async (req, res) => {
  const { postId } = req.body; const nick = req.nick;
  if (!postId || !nick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: rows } = await supabase.from('channel_comments')
    .select('id, from_nick, read_by')
    .eq('post_id', postId).neq('from_nick', nick)
    .not('read_by', 'cs', `{"${nick}"}`)
    .limit(500);
  const firstSeenByAuthor = {}; // автор → commentIds, що аж тепер стали побаченими
  for (const c of rows || []) {
    const readBy = c.read_by || [];
    if (readBy.includes(nick)) continue;
    await supabase.from('channel_comments').update({ read_by: [...readBy, nick] }).eq('id', c.id);
    if (readBy.length === 0) (firstSeenByAuthor[c.from_nick] ??= []).push(c.id);
  }
  for (const [author, commentIds] of Object.entries(firstSeenByAuthor)) {
    sendToUser(author, { type: 'channel_comment_status', postId: Number(postId), status: 'delivered', commentIds });
  }
  res.json({ ok: true });
});

app.delete('/channel/comment', async (req, res) => {
  const { commentId, channelId } = req.body; const requesterNick = req.nick;
  if (!commentId || !channelId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: comment } = await supabase.from('channel_comments').select('from_nick, file_data').eq('id', commentId).single();
  if (!comment) return res.json({ ok: false, error: 'Коментар не знайдено' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', requesterNick).single();
  const canDelete = comment.from_nick === requesterNick || (member && ['owner', 'admin'].includes(member.role));
  if (!canDelete) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channel_comment_reactions').delete().eq('comment_id', commentId);
  await supabase.from('channel_comments').delete().eq('id', commentId);
  await removeChannelFile(comment.file_data);
  res.json({ ok: true });
});

// Реакція на коментар (toggle) — дзеркало /channel/reaction
app.post('/channel/comment/reaction', async (req, res) => {
  const { commentId, channelId, emoji } = req.body; const nick = req.nick;
  if (!commentId || !channelId || !nick || !emoji) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', nick).single();
  if (blocked) return res.json({ ok: false, error: 'Ви заблоковані' });
  const { data: existing } = await supabase.from('channel_comment_reactions').select('id').eq('comment_id', commentId).eq('nick', nick).eq('emoji', emoji).single();
  if (existing) { await supabase.from('channel_comment_reactions').delete().eq('id', existing.id); }
  else {
    await supabase.from('channel_comment_reactions').delete().eq('comment_id', commentId).eq('nick', nick);
    await supabase.from('channel_comment_reactions').insert({ comment_id: commentId, nick, emoji });
  }
  const { data: reactions } = await supabase.from('channel_comment_reactions').select('emoji, nick').eq('comment_id', commentId);
  const { data: c } = await supabase.from('channel_comments').select('post_id').eq('id', commentId).single();
  await notifyChannelSubscribers(channelId, { type: 'channel_comment_reaction', channelId, postId: c ? c.post_id : null, commentId, reactions }, null);
  res.json({ ok: true, reactions: reactions || [] });
});

// Редагування коментаря (свій або owner/admin) — дзеркало /channel/message/edit
app.post('/channel/comment/edit', async (req, res) => {
  const { channelId, commentId, content } = req.body; const nick = req.nick;
  if (!channelId || !commentId || !nick || !content) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: comment } = await supabase.from('channel_comments').select('from_nick, post_id').eq('id', commentId).single();
  if (!comment) return res.json({ ok: false, error: 'Коментар не знайдено' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  const canEdit = comment.from_nick === nick || (member && ['owner', 'admin'].includes(member.role));
  if (!canEdit) return res.json({ ok: false, error: 'Недостатньо прав' });
  const editedAt = Date.now();
  await supabase.from('channel_comments').update({ content, edited: true, edited_at: editedAt }).eq('id', commentId);
  await notifyChannelSubscribers(channelId, { type: 'channel_comment_edited', channelId, postId: comment.post_id, commentId, text: content, editedAt }, null);
  res.json({ ok: true });
});

// Інкремент переглядів поста
app.post('/channel/view', async (req, res) => {
  const { postId } = req.body; const nick = req.nick;
  if (!postId) return res.json({ ok: false });
  const { data: post } = await supabase.from('channel_messages').select('view_count, channel_id').eq('id', postId).single();
  if (!post) return res.json({ ok: false });
  // Рахуємо лише унікальних глядачів: 1 людина = 1 перегляд.
  if (nick) {
    const { data: seen } = await supabase.from('channel_post_views').select('id').eq('post_id', postId).eq('nick', nick).maybeSingle();
    if (seen) return res.json({ ok: true, viewCount: post.view_count || 0, counted: false });
    await supabase.from('channel_post_views').insert({ post_id: postId, nick });
  }
  const newCount = (post.view_count || 0) + 1;
  await supabase.from('channel_messages').update({ view_count: newCount }).eq('id', postId);
  // Розсилаємо новий лічильник переглядів усім підписникам (real-time)
  await notifyChannelSubscribers(post.channel_id, { type: 'channel_view', channelId: post.channel_id, postId, viewCount: newCount }, null);
  res.json({ ok: true, viewCount: newCount, counted: true });
});

// Реакції
app.post('/channel/reaction', async (req, res) => {
  const { postId, channelId, emoji } = req.body; const nick = req.nick;
  if (!postId || !channelId || !nick || !emoji) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', nick).single();
  if (blocked) return res.json({ ok: false, error: 'Ви заблоковані' });
  const { data: existing } = await supabase.from('channel_reactions').select('id').eq('post_id', postId).eq('nick', nick).eq('emoji', emoji).single();
  if (existing) { await supabase.from('channel_reactions').delete().eq('id', existing.id); }
  else {
    await supabase.from('channel_reactions').delete().eq('post_id', postId).eq('nick', nick);
    await supabase.from('channel_reactions').insert({ post_id: postId, nick, emoji });
  }
  const { data: reactions } = await supabase.from('channel_reactions').select('emoji, nick').eq('post_id', postId);
  await notifyChannelSubscribers(channelId, { type: 'channel_reaction', channelId, postId, reactions }, null);
  res.json({ ok: true, reactions: reactions || [] });
});

// Модерація каналу
app.post('/channel/block-subscriber', async (req, res) => {
  const { channelId, targetNick } = req.body; const ownerNick = req.nick;
  if (!channelId || !ownerNick || !targetNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channel_blocked').upsert({ channel_id: channelId, nick: targetNick, blocked_at: Date.now() });
  res.json({ ok: true });
});

app.get('/channel/blocked-list', async (req, res) => {
  const { channelId, ownerNick } = req.query;
  if (!channelId || !ownerNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  const { data: blocked } = await supabase.from('channel_blocked').select('nick, blocked_at').eq('channel_id', channelId).order('blocked_at', { ascending: false });
  res.json({ ok: true, blocked: blocked || [] });
});

app.post('/channel/unblock-subscriber', async (req, res) => {
  const { channelId, targetNick } = req.body; const ownerNick = req.nick;
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channel_blocked').delete().eq('channel_id', channelId).eq('nick', targetNick);
  res.json({ ok: true });
});

app.post('/channel/remove-subscriber', async (req, res) => {
  const { channelId, targetNick } = req.body; const ownerNick = req.nick;
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channel_members').delete().eq('channel_id', channelId).eq('nick', targetNick);
  sendToUser(targetNick, { type: 'channel_removed', channelId });
  res.json({ ok: true });
});

app.post('/channel/set-admin', async (req, res) => {
  const { channelId, targetNick, isAdmin } = req.body; const ownerNick = req.nick;
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || member.role !== 'owner') return res.json({ ok: false, error: 'Тільки власник може призначати адмінів' });
  await supabase.from('channel_members').update({ role: isAdmin ? 'admin' : 'subscriber' }).eq('channel_id', channelId).eq('nick', targetNick);
  res.json({ ok: true });
});

app.get('/channel/subscribers', async (req, res) => {
  const { channelId, ownerNick } = req.query;
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  const { data: members } = await supabase.from('channel_members').select('nick, role, joined_at').eq('channel_id', channelId).order('joined_at', { ascending: true });
  const { data: blocked } = await supabase.from('channel_blocked').select('nick').eq('channel_id', channelId);
  const blockedSet = new Set((blocked || []).map(b => b.nick));
  res.json({ ok: true, subscribers: (members || []).map(m => ({ ...m, isBlocked: blockedSet.has(m.nick) })) });
});

app.post('/channel/invite', async (req, res) => {
  const { channelId, targetNick } = req.body; const ownerNick = req.nick;
  if (!channelId || !ownerNick || !targetNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  const { data: existing } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', targetNick).single();
  if (existing) return res.json({ ok: false, error: 'Користувач вже є підписником' });
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', targetNick).single();
  if (blocked) return res.json({ ok: false, error: 'Цей користувач заблокований у каналі' });
  const { data: targetUser } = await supabase.from('users').select('nick').eq('nick', targetNick).single();
  if (!targetUser) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const { data: channel } = await supabase.from('channels').select('name').eq('id', channelId).single();
  // Надсилаємо ЗАПРОШЕННЯ — користувач має підтвердити
  const targetWs = onlineUsers.get(targetNick);
  if (targetWs) {
    targetWs.ws.send(JSON.stringify({ type: 'channel_invite_request', channelId, channelName: channel?.name, byNick: ownerNick }));
  } else {
    await supabase.from('pending_channel_invites').upsert({ channel_id: channelId, target_nick: targetNick, inviter_nick: ownerNick });
  }
  res.json({ ok: true, pending: true });
});

app.post('/channel/invite-response', async (req, res) => {
  const { channelId, accepted } = req.body; const nick = req.nick;
  if (!channelId || !nick) return res.json({ ok: false, error: 'Невірні параметри' });
  await supabase.from('pending_channel_invites').delete().eq('channel_id', channelId).eq('target_nick', nick);
  if (!accepted) return res.json({ ok: true });
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', nick).single();
  if (blocked) return res.json({ ok: false, error: 'Ви заблоковані в цьому каналі' });
  const { data: existing } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  if (!existing) await supabase.from('channel_members').insert({ channel_id: channelId, nick, role: 'subscriber' });
  const { data: channel } = await supabase.from('channels').select('*').eq('id', channelId).single();
  const { count } = await supabase.from('channel_members').select('*', { count: 'exact', head: true }).eq('channel_id', channelId);
  res.json({ ok: true, channel: { ...channel, myRole: 'subscriber', subscriberCount: count || 0 } });
});



app.post('/channel/contact-owner', async (req, res) => {
  const { channelId } = req.body;
  const fromNick = req.nick; // Фаза 1: платник — автентифікований юзер.
  if (!channelId || !fromNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const CONTACT_PRICE = 100; const OWNER_SHARE = 70; const COMPANY_SHARE = 30;
  const { data: channel } = await supabase.from('channels').select('owner_nick').eq('id', channelId).single();
  if (!channel) return res.json({ ok: false, error: 'Канал не знайдено' });
  if (channel.owner_nick === fromNick) return res.json({ ok: false, error: 'Ви є власником каналу' });
  const { data: owner } = await supabase.from('users').select('nick').eq('nick', channel.owner_nick).single();
  if (!owner) return res.json({ ok: false, error: 'Власника каналу не знайдено' });
  // Атомарне списання у покупця.
  const { data: senderBalance, error: spendErr } = await supabase.rpc('spend_coins', { p_nick: fromNick, p_amount: CONTACT_PRICE });
  if (spendErr) return res.json({ ok: false, error: 'Помилка списання' });
  if (senderBalance === -1) return res.json({ ok: false, error: 'Недостатньо EION монет (потрібно 100)' });
  // Розподіл: власнику (атомарно) + компанії (creditCompany з live+журнал).
  const { data: ownerBalance } = await supabase.rpc('add_coins', { p_nick: channel.owner_nick, p_amount: OWNER_SHARE });
  await logTx({ fromNick, toNick: channel.owner_nick, amount: OWNER_SHARE, kind: 'contact_owner', ref: String(channelId) });
  await creditCompany(COMPANY_SHARE, 'contact_fee', { fromNick, ref: String(channelId) });
  sendToUser(fromNick, { type: 'coins_update', amount: -CONTACT_PRICE, total: senderBalance });
  if (ownerBalance != null) sendToUser(channel.owner_nick, { type: 'coins_received', fromNick, amount: OWNER_SHARE, total: ownerBalance });
  res.json({ ok: true, ownerNick: channel.owner_nick });
});

// ── Платна підписка на канал (монети, комісія 30% платформі) ──────────────
app.post('/channel/subscribe-paid', async (req, res) => {
  const { channelId } = req.body;
  const nick = req.nick; // Фаза 1: платник — автентифікований юзер.
  if (!channelId || !nick) return res.json({ ok: false, error: 'Невірні параметри' });
  const FEE_PCT = 30;
  const { data: ch } = await supabase.from('channels').select('owner_nick, is_paid, price, sub_days').eq('id', channelId).single();
  if (!ch) return res.json({ ok: false, error: 'Канал не знайдено' });
  if (!ch.is_paid) return res.json({ ok: false, error: 'Канал безкоштовний' });
  // Вже є активна підписка — не списувати повторно
  const { data: curArr } = await supabase.from('channel_paid_subs').select('expires_at').eq('channel_id', channelId).eq('nick', nick).order('expires_at', { ascending: false }).limit(1);
  if (curArr && curArr[0] && Number(curArr[0].expires_at) > Date.now()) return res.json({ ok: true, alreadySubscribed: true, expiresAt: Number(curArr[0].expires_at) });
  const price = ch.price || 0;
  const companyShare = Math.floor(price * FEE_PCT / 100);
  const ownerShare = price - companyShare;
  // Атомарне списання.
  const { data: newBalance, error: spendErr } = await supabase.rpc('spend_coins', { p_nick: nick, p_amount: price });
  if (spendErr) return res.json({ ok: false, error: 'Помилка списання' });
  if (newBalance === -1) return res.json({ ok: false, error: `Недостатньо EION (потрібно ${price})` });
  if (ch.owner_nick && ch.owner_nick !== nick) {
    const { data: ownerNew } = await supabase.rpc('add_coins', { p_nick: ch.owner_nick, p_amount: ownerShare });
    await logTx({ fromNick: nick, toNick: ch.owner_nick, amount: ownerShare, kind: 'paid_sub', ref: String(channelId) });
    if (ownerNew != null) sendToUser(ch.owner_nick, { type: 'coins_received', fromNick: nick, amount: ownerShare, total: ownerNew });
  }
  await creditCompany(companyShare, 'paid_sub_fee', { fromNick: nick, ref: String(channelId) });
  const subDays = ch.sub_days || 30;
  const expiresAt = Date.now() + subDays * 86400000;
  // Запис підписки БЕЗ залежності від unique-констрейнта (upsert+onConflict міг тихо падати)
  const { data: existArr, error: existErr } = await supabase.from('channel_paid_subs').select('nick').eq('channel_id', channelId).eq('nick', nick).limit(1);
  if (existErr) console.error('[paid-sub] existArr ERROR:', JSON.stringify(existErr));
  const subBranch = (existArr && existArr.length > 0) ? 'update' : 'insert';
  let subWriteErr = null;
  if (subBranch === 'update') {
    const { error } = await supabase.from('channel_paid_subs').update({ expires_at: expiresAt }).eq('channel_id', channelId).eq('nick', nick);
    subWriteErr = error;
  } else {
    const { error } = await supabase.from('channel_paid_subs').insert({ channel_id: Number(channelId), nick, expires_at: expiresAt });
    subWriteErr = error;
  }
  if (subWriteErr) console.error('[paid-sub] WRITE ERROR:', JSON.stringify(subWriteErr));
  const { data: existing } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  if (!existing) await supabase.from('channel_members').insert({ channel_id: channelId, nick, role: 'subscriber' });
  sendToUser(nick, { type: 'coins_update', amount: -price, total: newBalance });
  res.json({ ok: true, newBalance, expiresAt });
});

// Власник вмикає/вимикає платність і ставить ціну/період
app.post('/channel/set-paid', async (req, res) => {
  const { channelId, isPaid, price, subDays } = req.body; const requesterNick = req.nick;
  if (!channelId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', requesterNick).single();
  if (!member || member.role !== 'owner') return res.json({ ok: false, error: 'Лише власник' });
  await supabase.from('channels').update({ is_paid: !!isPaid, price: Math.max(0, parseInt(price) || 0), sub_days: Math.max(1, parseInt(subDays) || 30) }).eq('id', channelId);
  res.json({ ok: true });
});

app.post('/channel/update', async (req, res) => {
  const { channelId, name, description, type, avatar_url, comments_allow_media } = req.body; const ownerNick = req.nick;
  if (!channelId || !ownerNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  const updates = {};
  if (name !== undefined) updates.name = name;
  if (description !== undefined) updates.description = description;
  if (type !== undefined) updates.type = type;
  if (avatar_url !== undefined) updates.avatar_url = avatar_url;
  if (comments_allow_media !== undefined) updates.comments_allow_media = comments_allow_media;
  if (Object.keys(updates).length === 0) return res.json({ ok: false, error: 'Нічого оновлювати' });
  await supabase.from('channels').update(updates).eq('id', channelId);
  res.json({ ok: true });
});

// ── Стрім у каналі (вбудований YouTube) ──────────────
// Валідатор YouTube-посилання: приймає watch?v=, youtu.be/, live/, embed/.
function extractYouTubeId(url) {
  if (typeof url !== 'string') return null;
  const patterns = [
    /(?:youtube\.com\/watch\?v=)([\w-]{11})/,
    /(?:youtu\.be\/)([\w-]{11})/,
    /(?:youtube\.com\/live\/)([\w-]{11})/,
    /(?:youtube\.com\/embed\/)([\w-]{11})/,
  ];
  for (const p of patterns) { const m = url.match(p); if (m) return m[1]; }
  return null;
}

// Почати трансляцію: власник вставляє YouTube-посилання.
app.post('/channel/stream/start', async (req, res) => {
  const { channelId, url } = req.body; const ownerNick = req.nick;
  if (!channelId || !ownerNick || !url) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  const videoId = extractYouTubeId(url);
  if (!videoId) return res.json({ ok: false, error: 'Це не схоже на посилання YouTube' });
  const startedAt = Date.now();
  const liveUrl = `https://www.youtube.com/watch?v=${videoId}`;
  // Створюємо ПОСТ зі стрімом — коментарі йтимуть до нього, і після завершення
  // він природно лишається у стрічці як запис. Маркер [stream] у content, щоб
  // клієнт розпізнав пост-стрім і показав плеєр замість звичайного тексту.
  const ts = startedAt; const msgId = `ch_${channelId}_${ts}`;
  const { data: post } = await supabase.from('channel_messages').insert({
    channel_id: channelId, from_nick: ownerNick,
    content: `[stream]${videoId}`,
    timestamp: ts, msg_id: msgId,
  }).select().single();
  await supabase.from('channels').update({
    live_url: liveUrl,
    live_active: true,
    live_started_at: startedAt,
    live_post_id: post.id,
    last_post_at: ts,
    last_post_text: '🔴 Трансляція',
  }).eq('id', channelId);
  // Сповіщаємо онлайн-підписників: і про новий пост, і про live-стан.
  notifyChannelSubscribers(channelId, { type: 'channel_message', channelId, postId: post.id, from: ownerNick, text: `[stream]${videoId}`, timestamp: ts, msgId, message: { ...post, commentCount: 0, reactions: [], topCommenters: [] } }, ownerNick).catch(() => {});
  notifyChannelSubscribers(channelId, { type: 'channel_live', channelId, videoId, active: true, postId: post.id }).catch(() => {});
  res.json({ ok: true, videoId, startedAt, postId: post.id });
});

// Завершити трансляцію: live_active=false, live_url лишається як запис.
app.post('/channel/stream/stop', async (req, res) => {
  const { channelId } = req.body; const ownerNick = req.nick;
  if (!channelId || !ownerNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channels').update({ live_active: false }).eq('id', channelId);
  notifyChannelSubscribers(channelId, { type: 'channel_live', channelId, active: false }).catch(() => {});
  res.json({ ok: true });
});

app.post('/channel/delete', async (req, res) => {
  const { channelId } = req.body; const ownerNick = req.nick;
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || member.role !== 'owner') return res.json({ ok: false, error: 'Тільки власник може видалити канал' });
  // Збираємо файли постів і коментарів перед видаленням — щоб прибрати зі Storage.
  const { data: chPosts } = await supabase.from('channel_messages').select('id, image_url, file_data').eq('channel_id', channelId);
  const { data: chComments } = await supabase.from('channel_comments').select('file_data').eq('channel_id', channelId);
  await supabase.from('channel_comments').delete().eq('channel_id', channelId);
  await supabase.from('channel_reactions').delete().in('post_id', (chPosts || []).map(m => m.id));
  await supabase.from('channel_messages').delete().eq('channel_id', channelId);
  await supabase.from('channel_members').delete().eq('channel_id', channelId);
  await supabase.from('channel_blocked').delete().eq('channel_id', channelId);
  await supabase.from('channels').delete().eq('id', channelId);
  for (const p of (chPosts || [])) await removeChannelFile(p.image_url, p.file_data);
  for (const c of (chComments || [])) await removeChannelFile(c.file_data);
  res.json({ ok: true });
});

// ── Модерація платформи ────────────────────────
app.post('/report', async (req, res) => {
  const { targetNick, reason, context } = req.body; const reporterNick = req.nick;
  if (!reporterNick || !targetNick) return res.json({ ok: false, error: 'Невірні параметри' });
  await supabase.from('reports').insert({ reporter_nick: reporterNick, target_nick: targetNick, reason: reason || null, context: context || null, created_at: Date.now() });
  res.json({ ok: true });
});

// ── Аудит осиротілих файлів (тільки читання) ─────────────────────────────────
//
// Чому endpoint, а не скрипт. Скрипт (`~/EION-нотатки/orphan/orphan_audit.js`)
// вимагає service-ключ, який живе ЛИШЕ в env Render — тягти його на машину
// розробника чи в чат заради разової довідки не варто. Тут ключ уже є, а
// назовні виходить сама лише зведена цифра.
//
// ⚠️ Видалення тут НЕМАЄ і не буде: endpoint лише рахує. Реальна чистка — це
// окремий, свідомий крок з переглянутим списком.
const ORPHAN_MARKERS = ['/object/public/files/', '/object/sign/files/'];
const ORPHAN_REF = 'eion://files/';
const ORPHAN_PREFIXES = ['direct/', 'group/', 'channel/', 'channels/'];

function orphanPathFromValue(val) {
  if (!val || typeof val !== 'string') return null;
  for (const marker of ORPHAN_MARKERS) {
    const i = val.indexOf(marker);
    if (i !== -1) {
      const tail = val.slice(i + marker.length).split('?')[0];
      try { return decodeURIComponent(tail); } catch (_) { return tail; }
    }
  }
  const r = val.indexOf(ORPHAN_REF);
  if (r !== -1) {
    const tail = val.slice(r + ORPHAN_REF.length).split('?')[0];
    try { return decodeURIComponent(tail); } catch (_) { return tail; }
  }
  const trimmed = val.trim();
  if (ORPHAN_PREFIXES.some(p => trimmed.startsWith(p))) {
    try { return decodeURIComponent(trimmed.split('?')[0]); } catch (_) { return trimmed.split('?')[0]; }
  }
  return null;
}

async function orphanWalk(prefix, out, depth = 0) {
  if (depth > 6) return; // захист від нескінченного обходу
  let offset = 0; const limit = 100;
  while (true) {
    const { data, error } = await supabase.storage.from('files')
      .list(prefix, { limit, offset, sortBy: { column: 'name', order: 'asc' } });
    if (error || !data || !data.length) break;
    for (const item of data) {
      const full = prefix ? `${prefix}/${item.name}` : item.name;
      const isFolder = item.id === null && !item.metadata;
      if (isFolder) await orphanWalk(full, out, depth + 1);
      else out.push({ path: full, size: (item.metadata && item.metadata.size) || 0 });
    }
    if (data.length < limit) break;
    offset += limit;
  }
}

app.get('/admin/orphan-audit', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Доступ заборонено' });
  const tables = ['messages', 'group_messages', 'channel_messages', 'channel_comments'];
  const refs = new Set();
  let hadError = false;
  for (const table of tables) {
    let from = 0; const page = 1000;
    while (true) {
      const { data, error } = await supabase.from(table).select('*').range(from, from + page - 1);
      if (error) { hadError = true; break; }
      if (!data || !data.length) break;
      for (const row of data) for (const v of Object.values(row)) {
        const p = orphanPathFromValue(v); if (p) refs.add(p);
      }
      if (data.length < page) break;
      from += page;
    }
  }
  const files = [];
  await orphanWalk('', files);
  const orphans = files.filter(f => !refs.has(f.path));
  const bytes = orphans.reduce((n, f) => n + (f.size || 0), 0);
  res.json({
    ok: true,
    // hadError означає, що набір посилань НЕПОВНИЙ → числу вірити не можна.
    complete: !hadError,
    files: files.length,
    referenced: refs.size,
    orphans: orphans.length,
    orphanBytes: bytes,
    orphanMB: +(bytes / 1048576).toFixed(1),
    sample: orphans.slice(0, 20).map(o => o.path),
  });
});

// Перевірка поштового тракту: віддає СПРАВЖНЮ помилку SMTP, а не загальне
// «Помилка відправки email». Публічним такий текст робити не можна (він
// розкриває конфігурацію релею), тому — під адмін-секретом.
app.get('/admin/mail-test', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Доступ заборонено' });
  // Крок 1 — сирий TCP-пробник. Відрізняє «порт/мережа закриті» (сокет не
  // відкривається) від «бібліотека або облікові дані» (сокет відкрився, релей
  // привітався). Без цього обидва випадки виглядають однаково.
  const probe = await new Promise((resolve) => {
    const t0 = Date.now();
    const sock = net.connect({ host: 'smtp-relay.brevo.com', port: 587 });
    let greeting = '';
    const done = (r) => { try { sock.destroy(); } catch (_) {} resolve({ ...r, ms: Date.now() - t0 }); };
    sock.setTimeout(8000);
    sock.on('data', (d) => { greeting += d.toString(); if (greeting.includes('\n')) done({ connected: true, greeting: greeting.trim().slice(0, 120) }); });
    sock.on('connect', () => { /* чекаємо привітання 220 */ });
    sock.on('timeout', () => done({ connected: false, error: 'timeout' }));
    sock.on('error', (e) => done({ connected: false, error: e.message, code: e.code || null }));
  });

  const creds = { apiKey: !!BREVO_API_KEY, login: !!process.env.BREVO_LOGIN, password: !!process.env.BREVO_PASSWORD };

  // Крок 2 — стан акаунта Brevo. Без нього «швидка відмова» виглядає однаково
  // для невірного ключа, для непідтвердженого відправника і для домену, який
  // Brevo не приймає. Питаємо саме сервіс, а не вгадуємо за текстом помилки.
  let brevo = null;
  if (BREVO_API_KEY) {
    const ask = async (path) => {
      try {
        const r = await fetch(`https://api.brevo.com/v3${path}`, {
          headers: { 'api-key': BREVO_API_KEY, accept: 'application/json' },
          signal: AbortSignal.timeout(10000),
        });
        return { status: r.status, body: await r.json().catch(() => null) };
      } catch (e) { return { status: 0, error: e.message }; }
    };
    const acc = await ask('/account');
    const snd = await ask('/senders');
    const list = snd.body && Array.isArray(snd.body.senders) ? snd.body.senders : null;
    brevo = {
      keyValid: acc.status === 200,
      account: acc.status === 200 ? ((acc.body && acc.body.email) || null) : `HTTP ${acc.status} ${JSON.stringify(acc.body || acc.error || '').slice(0, 120)}`,
      from: MAIL_FROM.email,
      senders: list ? list.map((x) => `${x.email}${x.active ? '' : ' — НЕ підтверджений'}`) : `HTTP ${snd.status}`,
      fromActive: list ? list.some((x) => String(x.email).toLowerCase() === MAIL_FROM.email.toLowerCase() && x.active) : null,
    };
  }

  const to = req.query.to;
  if (!to || !String(to).includes('@')) return res.json({ ok: false, probe, creds, brevo, hint: 'Додай ?to=адреса, щоб спробувати справжню відправку' });
  const t0 = Date.now();
  try {
    const info = await sendEmail(String(to), 'EION — перевірка пошти', 'Тестовий лист. Якщо він прийшов — тракт відправки працює.');
    res.json({ ok: true, probe, creds, brevo, via: info && info.via, ms: Date.now() - t0, info: info && info.response ? String(info.response) : null });
  } catch (e) {
    res.json({ ok: false, probe, creds, brevo, ms: Date.now() - t0, error: e.message, code: e.code || null });
  }
});

// Тестовий endpoint для перевірки механізму адмін-авторизації (нешкідливий).
app.get('/admin/ping', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Доступ заборонено' });
  res.json({ ok: true, admin: true, message: 'Секрет вірний' });
});

app.get('/admin/reports', async (req, res) => {
  if (!isAdmin(req)) return res.json({ ok: false, error: 'Доступ заборонено' });
  const { data } = await supabase.from('reports').select('*').eq('status', 'pending').order('created_at', { ascending: false });
  res.json({ ok: true, reports: data || [] });
});

app.post('/admin/ban', async (req, res) => {
  if (!isAdmin(req)) return res.json({ ok: false, error: 'Доступ заборонено' });
  const { targetNick, reason } = req.body;
  await supabase.from('platform_bans').upsert({ nick: targetNick, reason: reason || null, banned_at: Date.now(), banned_by: COMPANY_NICK });
  const t = onlineUsers.get(targetNick); if (t) { t.ws.send(JSON.stringify({ type: 'kicked', reason: 'Акаунт заблоковано' })); t.ws.close(); }
  await destroySessionsForNick(targetNick); // забанений не має лишатись автентифікованим
  res.json({ ok: true });
});

app.post('/admin/unban', async (req, res) => {
  if (!isAdmin(req)) return res.json({ ok: false, error: 'Доступ заборонено' });
  const { targetNick } = req.body;
  await supabase.from('platform_bans').delete().eq('nick', targetNick);
  res.json({ ok: true });
});

app.post('/admin/resolve-report', async (req, res) => {
  if (!isAdmin(req)) return res.json({ ok: false, error: 'Доступ заборонено' });
  const { reportId } = req.body;
  await supabase.from('reports').update({ status: 'resolved' }).eq('id', reportId);
  res.json({ ok: true });
});

// ── WebSocket ────────────────────────────────
wss.on('connection', (ws) => {
  let userNick = null;
  // Storage 2.3: WS-чокпойнт. Усі релеї file/group/channel шлють напряму
  // target.ws.send (повз sendToUser), тож підписуємо медіа-рефи тут — у будь-якому
  // ws.send цього з'єднання. No-op, поки в тілі немає eion:// (швидкий відсів).
  const _rawSend = ws.send.bind(ws);
  ws.send = (data, ...rest) => {
    if (typeof data === 'string' && data.includes('eion://')) {
      try {
        const obj = JSON.parse(data);
        signDeep(obj).then((s) => _rawSend(JSON.stringify(s))).catch(() => _rawSend(data));
        return;
      } catch (_) { return _rawSend(data, ...rest); }
    }
    return _rawSend(data, ...rest);
  };
  // Серверний heartbeat (проти code=1006: мертвий транспорт виявляємо швидко).
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; if (userNick && onlineUsers.has(userNick)) onlineUsers.get(userNick).lastSeen = Date.now(); });
  ws.on('message', async (raw) => {
    try {
      const msg = JSON.parse(raw);

      if (msg.type === 'login') {
        // Автентифікація WS (Фаза 1): нік беремо з ТОКЕНА, не з msg.nick.
        // Невалідний токен → close (жорсткий режим).
        userNick = resolveSession(msg.token);
        if (!userNick) { ws.send(JSON.stringify({ type: 'kicked', reason: 'Сесія недійсна, увійдіть знову' })); ws.close(); return; }
        const { data: ban } = await supabase.from('platform_bans').select('reason').eq('nick', userNick).single();
        if (ban) { ws.send(JSON.stringify({ type: 'kicked', reason: `Акаунт заблоковано: ${ban.reason || 'порушення правил'}` })); ws.close(); return; }
        if (onlineUsers.has(userNick)) { const old = onlineUsers.get(userNick); old.ws.send(JSON.stringify({ type: 'kicked', reason: 'Новий пристрій підключився' })); old.ws.close(); }
        onlineUsers.set(userNick, { ws, lastSeen: Date.now() });
        // nickDevices має відображати, де нік ЗАРАЗ, а не де колись був.
        // Мапа живе в памʼяті й накопичувалась: якщо акаунт колись заходив із
        // телефона, запис лишався назавжди. Коли ТОЙ САМИЙ нік потім заходив із
        // десктопа (десктоп deviceId не реєструє), стара привʼязка вціліла — і
        // перевірка «дзвінок на той самий пристрій» хибно спрацьовувала для двох
        // різних машин: блокувались і call_offer, і пуші (лог 09.08:
        // `call_offer blocked: void->Rumpel same device dev_…`). Чистимо на вході;
        // якщо ця сесія справді з телефона, register_fcm_token одразу поставить
        // актуальний deviceId назад.
        //
        // Те саме стосується fcmTokens: нік, що колись заходив із телефона,
        // назавжди лишав там токен ТОГО телефона. Перейшовши на десктоп (де
        // FCM немає), він зберігав «привида» — сервер бачив `hasToken=true`,
        // кидав call_offer у FCM-гілку замість живого WS і слав пуш на чужий
        // тепер пристрій (лог 09.08: `push from=true to=true` для ніка на
        // Linux). Чистимо разом; клієнт на Android одразу після login_ok шле
        // register_fcm_token і повертає актуальний токен.
        await clearFcmToken(userNick);
        ws.send(JSON.stringify({ type: 'login_ok' }));
        // Невидимі (invisible) не сповіщають інших про свій онлайн.
        if (!invisibleNicks.has(userNick)) {
          for (const [nick, user] of onlineUsers) { if (nick !== userNick) user.ws.send(JSON.stringify({ type: 'user_online', nick: userNick })); }
        }

        const { data: pendingDeletes } = await supabase.from('deleted_messages').select('msg_id, from_nick').eq('to_nick', userNick);
        if (pendingDeletes && pendingDeletes.length > 0) {
          const delIds = pendingDeletes.map(d => d.msg_id).filter(Boolean);
          if (delIds.length > 0) await supabase.from('messages').delete().eq('to_nick', userNick).in('msg_id', delIds);
          for (const d of pendingDeletes) ws.send(JSON.stringify({ type: 'delete_message', from: d.from_nick, msgId: d.msg_id }));
          await supabase.from('deleted_messages').delete().eq('to_nick', userNick);
        }

        const { data: toDeliver } = await supabase.from('messages').select('id, from_nick, msg_id').eq('to_nick', userNick).eq('status', 'sent');
        if (toDeliver && toDeliver.length > 0) {
          await supabase.from('messages').update({ status: 'delivered' }).eq('to_nick', userNick).eq('status', 'sent');
          const senders = [...new Set(toDeliver.map(m => m.from_nick))];
          for (const sender of senders) { const senderWs = onlineUsers.get(sender); if (senderWs) { const msgIds = toDeliver.filter(m => m.from_nick === sender).map(m => m.msg_id).filter(Boolean); if (msgIds.length > 0) senderWs.ws.send(JSON.stringify({ type: 'status_update', status: 'delivered', msgIds })); } }
        }

        const { data: myStatuses } = await supabase.from('messages').select('msg_id, status').eq('from_nick', userNick).neq('status', 'sent').not('msg_id', 'is', null);
        if (myStatuses && myStatuses.length > 0) ws.send(JSON.stringify({ type: 'status_sync', statuses: myStatuses }));

        const { data: pending } = await supabase.from('messages').select('*').eq('to_nick', userNick).eq('delivered', false).order('timestamp', { ascending: true });
        if (pending && pending.length > 0) {
          for (const m of pending) {
            // Storage 2.3: реф (eion://) теж іде як fileUrl (не base64 data), а весь
            // payload підписується — цей шлях повз sendToUser і res.json чокпойнти.
            const payload = m.type === 'sticker' ? { type: 'sticker', from: m.from_nick, ...decodeStickerContent(m.content), timestamp: m.timestamp, msgId: m.msg_id } : m.type === 'file' ? { type: 'file_message', from: m.from_nick, fileName: m.file_name, ...(m.content && m.content !== m.file_name ? { caption: m.content } : {}), ...(m.file_data && /^(https?:\/\/|eion:\/\/)/.test(m.file_data) ? { fileUrl: m.file_data } : { data: m.file_data }), timestamp: m.timestamp, msgId: m.msg_id, ...(m.waveform ? { waveform: JSON.parse(m.waveform) } : {}), ...(m.duration_sec != null ? { durationSec: m.duration_sec } : {}) } : { type: 'chat_message', from: m.from_nick, text: m.content, msgId: m.msg_id, timestamp: m.timestamp, ...(m.reply_to_msg_id ? { replyToMsgId: m.reply_to_msg_id } : {}), ...(m.reply_to_text ? { replyToText: m.reply_to_text } : {}), ...(m.reply_to_from ? { replyToFrom: m.reply_to_from } : {}), ...(m.reply_to_image ? { replyToImage: m.reply_to_image } : {}) };
            ws.send(JSON.stringify(await signDeep(payload)));
          }
          await supabase.from('messages').update({ delivered: true }).eq('to_nick', userNick).eq('delivered', false);
        }

        const { data: myGroups } = await supabase.from('group_members').select('group_id').eq('nick', userNick);
        if (myGroups && myGroups.length > 0) {
          for (const gm of myGroups) {
            const { data: pendingGroup } = await supabase.from('group_messages').select('*').eq('group_id', gm.group_id).not('delivered_to', 'cs', `{"${userNick}"}`).order('timestamp', { ascending: true });
            const deliveredBySender = {}; // автор → msgIds, що аж тепер дійшли цьому юзеру
            if (pendingGroup && pendingGroup.length > 0) { for (const m of pendingGroup) {
              if (m.type === 'file') ws.send(JSON.stringify({ type: 'file_message', groupId: m.group_id, from: m.from_nick, fileName: m.file_name, ...(m.content && m.content !== m.file_name ? { caption: m.content } : {}), ...(m.file_data && /^(https?|eion):\/\//.test(m.file_data) ? { fileUrl: m.file_data } : { data: m.file_data }), timestamp: m.timestamp, msgId: m.msg_id, catchup: true, ...(m.waveform ? { waveform: m.waveform } : {}), ...(m.duration_sec != null ? { durationSec: m.duration_sec } : {}) }));
              else ws.send(JSON.stringify({ type: 'group_message', groupId: m.group_id, from: m.from_nick, text: m.content, timestamp: m.timestamp, msgId: m.msg_id, catchup: true }));
              await supabase.from('group_messages').update({ delivered_to: [...(m.delivered_to || []), userNick] }).eq('id', m.id);
              if (m.msg_id && m.from_nick !== userNick) (deliveredBySender[m.from_nick] ??= []).push(m.msg_id);
            } }
            // Авторам — друга (сіра) галочка: їхні повідомлення щойно дійшли.
            for (const [sender, msgIds] of Object.entries(deliveredBySender)) {
              const target = onlineUsers.get(sender);
              if (target && target.ws.readyState === WebSocket.OPEN) target.ws.send(JSON.stringify({ type: 'group_status_update', groupId: gm.group_id, status: 'delivered', msgIds }));
            }
          }
        }

        const { data: pendingReactions, error: prErr } = await supabase.from('pending_reactions').select('*').eq('to_nick', userNick);
        if (prErr) console.log(`[reaction] pending SELECT FAILED for=${userNick}: ${prErr.message}`);
        if (pendingReactions && pendingReactions.length > 0) {
          // Дедуп: на одне повідомлення могло накопичитись кілька відкладених
          // подій — актуальний стан у них однаковий, тож шлемо його раз.
          const seen = new Set();
          for (const r of pendingReactions) {
            const gid = r.group_id != null ? Number(r.group_id) : null;
            const key = `${gid ?? r.chat_nick}|${r.msg_id}`;
            if (seen.has(key)) continue;
            seen.add(key);
            const reactions = gid != null
              ? await groupReactionsState(gid, r.msg_id)
              : await directReactionsState([userNick, r.chat_nick].sort().join('|'), r.msg_id);
            ws.send(JSON.stringify({ type: 'reaction', msgId: r.msg_id, emoji: r.emoji, from: r.from_nick, chatNick: r.chat_nick, groupId: gid, reactions }));
          }
          await supabase.from('pending_reactions').delete().eq('to_nick', userNick);
        }

        const { data: modGroups } = await supabase.from('group_members').select('group_id').eq('nick', userNick).in('role', ['creator', 'moderator']);
        if (modGroups && modGroups.length > 0) { for (const gm of modGroups) { const { data: reqs } = await supabase.from('group_join_requests').select('nick').eq('group_id', gm.group_id).eq('status', 'pending'); if (reqs && reqs.length > 0) { const { data: g } = await supabase.from('groups').select('name').eq('id', gm.group_id).single(); for (const r of reqs) ws.send(JSON.stringify({ type: 'group_join_request', groupId: gm.group_id, groupName: g?.name, nick: r.nick })); } } }

        const { data: groupInvites } = await supabase.from('pending_group_invites').select('*').eq('target_nick', userNick);
        if (groupInvites && groupInvites.length > 0) {
          for (const inv of groupInvites) { const { data: g } = await supabase.from('groups').select('name').eq('id', inv.group_id).single(); if (g) ws.send(JSON.stringify({ type: 'group_invite', groupId: inv.group_id, groupName: g.name, inviterNick: inv.inviter_nick })); }
        }

        // Pending channel invites
        const { data: channelInvites } = await supabase.from('pending_channel_invites').select('*').eq('target_nick', userNick);
        if (channelInvites && channelInvites.length > 0) {
          for (const inv of channelInvites) {
            const { data: ch } = await supabase.from('channels').select('name').eq('id', inv.channel_id).single();
            if (ch) ws.send(JSON.stringify({ type: 'channel_invite_request', channelId: inv.channel_id, channelName: ch.name, byNick: inv.inviter_nick }));
          }
        }
      }

      if (msg.type === 'register_fcm_token') { if (userNick && msg.token) { if (msg.deviceId) ws.deviceId = msg.deviceId; await saveFcmToken(userNick, msg.token, msg.deviceId); } }
      if (msg.type === 'check_online') ws.send(JSON.stringify({ type: 'online_status', nick: msg.nick, online: onlineUsers.has(msg.nick) }));
      if (msg.type === 'connect_request') { if (!sendToUser(msg.to, { type: 'connect_request', from: userNick })) ws.send(JSON.stringify({ type: 'error', error: `${msg.to} не в мережі` })); }
      if (msg.type === 'connect_response') { sendToUser(msg.to, { type: 'connect_response', from: userNick, accepted: msg.accepted }); }

      if (msg.type === 'chat_message') {
        // Якщо адресат заблокував відправника — повідомлення не зберігається
        // і не доставляється (мовчки, без сигналу відправнику).
        if (await isBlockedBy(msg.to, userNick)) return;
        // Глобальний блок вхідних адресата (крім тих, кому він сам написав за блоку).
        if (!(await canReceiveFrom(userNick, msg.to))) {
          if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'send_blocked', to: msg.to, reason: 'block_incoming', ...(msg.msgId ? { msgId: msg.msgId } : {}) }));
          return;
        }
        // Відправник сам пише — якщо в НЬОГО ввімкнено блок, адресат потрапляє
        // в його allowlist (зможе відповісти).
        await grantAllowlistIfBlocking(userNick, msg.to);
        const ts = (typeof msg.timestamp === 'number' && msg.timestamp > 0 && msg.timestamp <= Date.now() + 60000) ? msg.timestamp : Date.now(); const target = liveTarget(msg.to); const msgId = msg.msgId || null;
        const status = target ? 'delivered' : 'sent';
        const hasFile = msg.isFile && (msg.fileData || msg.fileUrl);
        await supabase.from('messages').insert({ from_nick: userNick, to_nick: msg.to, type: hasFile ? 'file' : 'text', content: msg.text, timestamp: ts, delivered: !!target, msg_id: msgId, status, ...(hasFile ? { file_name: msg.fileName, file_data: msg.fileData || msg.fileUrl } : {}), ...(msg.replyToMsgId ? { reply_to_msg_id: msg.replyToMsgId } : {}), ...(msg.replyToText ? { reply_to_text: msg.replyToText } : {}), ...(msg.replyToFrom ? { reply_to_from: msg.replyToFrom } : {}), ...(msg.replyToImage ? { reply_to_image: msg.replyToImage } : {}) });
        if (target) { target.ws.send(JSON.stringify({ type: 'chat_message', from: userNick, text: msg.text, timestamp: ts, msgId, ...(msg.isFile ? { isFile: true } : {}), ...(msg.isVoice ? { isVoice: true } : {}), ...(msg.fileName ? { fileName: msg.fileName } : {}), ...(msg.fileData ? { fileData: msg.fileData } : {}), ...(msg.fileUrl ? { fileUrl: msg.fileUrl } : {}), ...(msg.replyToMsgId ? { replyToMsgId: msg.replyToMsgId } : {}), ...(msg.replyToText ? { replyToText: msg.replyToText } : {}), ...(msg.replyToFrom ? { replyToFrom: msg.replyToFrom } : {}), ...(msg.replyToImage ? { replyToImage: msg.replyToImage } : {}), ...(msg.forwardedFrom ? { forwardedFrom: msg.forwardedFrom } : {}) })); if (msgId && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'status_update', status: 'delivered', msgIds: [msgId] })); }
        else {
          // Безтілесний push (приватність): лише сигнал + нік, без тексту.
          sendFcmPush(msg.to, { type: 'message', from_nick: userNick });
        }
      }

      if (msg.type === 'sticker') {
        const ts = (typeof msg.timestamp === 'number' && msg.timestamp > 0 && msg.timestamp <= Date.now() + 60000) ? msg.timestamp : Date.now();
        const msgId = msg.msgId || null;
        // UGC-наліпка (packId 'user') несе stickerUrl+crop. Щоб дані пережили
        // offline-доставку й перезавантаження історії без нових колонок у БД,
        // кодуємо їх у content тим самим форматом, що й клієнт (роздільник ~|~):
        //   'packId:stickerId'                             — офіційний пак
        //   'user:id~|~url~|~scale~|~dx~|~dy'  — UGC
        const SEP = '~|~';
        const hasUgc = typeof msg.stickerUrl === 'string' && msg.stickerUrl.length > 0;
        const content = hasUgc
          ? [`${msg.packId || 'user'}:${msg.stickerId || ''}`, msg.stickerUrl,
             String(msg.cropScale != null ? msg.cropScale : 1),
             String(msg.cropDx != null ? msg.cropDx : 0),
             String(msg.cropDy != null ? msg.cropDy : 0)].join(SEP)
          : `${msg.packId || 'tech01'}:${msg.stickerId || ''}`;
        // Додаткові поля, які додаємо у ретрансльований JSON (щоб отримувач
        // одразу мав URL/crop, а не тільки packId/stickerId).
        const ugcOut = hasUgc ? {
          stickerUrl: msg.stickerUrl,
          cropScale: msg.cropScale != null ? msg.cropScale : 1,
          cropDx: msg.cropDx != null ? msg.cropDx : 0,
          cropDy: msg.cropDy != null ? msg.cropDy : 0,
        } : {};
        if (msg.groupId) {
          // Стікер у групу
          const { data: membership } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId).eq('nick', userNick).single();
          if (!membership) return;
          const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId);
          const onlineMembers = (members || []).map(m => m.nick).filter(n => n !== userNick && isLive(n));
          await supabase.from('group_messages').insert({ group_id: msg.groupId, from_nick: userNick, content, timestamp: ts, msg_id: msgId, delivered_to: [userNick, ...onlineMembers], type: 'sticker' });
          for (const nick of onlineMembers) onlineUsers.get(nick).ws.send(JSON.stringify({ type: 'sticker', groupId: msg.groupId, from: userNick, packId: msg.packId, stickerId: msg.stickerId, ...ugcOut, timestamp: ts, msgId }));
          notifyGroupDelivered(ws, msg.groupId, msgId, onlineMembers);
        } else {
          // Стікер у direct
          if (await isBlockedBy(msg.to, userNick)) return;
          if (!(await canReceiveFrom(userNick, msg.to))) {
            if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'send_blocked', to: msg.to, reason: 'block_incoming', ...(msgId ? { msgId } : {}) }));
            return;
          }
          await grantAllowlistIfBlocking(userNick, msg.to);
          const target = liveTarget(msg.to);
          const status = target ? 'delivered' : 'sent';
          await supabase.from('messages').insert({ from_nick: userNick, to_nick: msg.to, type: 'sticker', content, timestamp: ts, delivered: !!target, msg_id: msgId, status });
          if (target) { target.ws.send(JSON.stringify({ type: 'sticker', from: userNick, packId: msg.packId, stickerId: msg.stickerId, ...ugcOut, timestamp: ts, msgId })); if (msgId && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'status_update', status: 'delivered', msgIds: [msgId] })); }
          else { sendFcmPush(msg.to, { type: 'message', from_nick: userNick }); }
        }
      }

      if (msg.type === 'file_message') {
        const ts = (typeof msg.timestamp === 'number' && msg.timestamp > 0 && msg.timestamp <= Date.now() + 60000) ? msg.timestamp : Date.now(); const msgId = msg.msgId || null;
        const fileData = msg.fileUrl || msg.data || null;
        if (msg.groupId) {
          const { data: membership } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId).eq('nick', userNick).single();
          if (!membership) return;
          const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId);
          const onlineMembers = (members || []).map(m => m.nick).filter(n => n !== userNick && isLive(n));
          await supabase.from('group_messages').insert({ group_id: msg.groupId, from_nick: userNick, content: mediaCaption(msg), timestamp: ts, msg_id: msgId, delivered_to: [userNick, ...onlineMembers], type: 'file', file_name: msg.fileName, file_data: fileData, ...(msg.waveform ? { waveform: msg.waveform } : {}), ...(msg.durationSec != null ? { duration_sec: msg.durationSec } : {}) });
          await trackFileObject(fileData, (members || []).map(m => m.nick).filter(n => n !== userNick)); // 2C
          for (const nick of onlineMembers) onlineUsers.get(nick).ws.send(JSON.stringify({ type: 'file_message', groupId: msg.groupId, from: userNick, fileName: msg.fileName, fileSize: msg.fileSize, ...(msg.caption ? { caption: String(msg.caption).slice(0, 4000) } : {}), ...(msg.fileUrl ? { fileUrl: msg.fileUrl } : { data: msg.data }), timestamp: ts, msgId, ...(msg.waveform ? { waveform: msg.waveform } : {}), ...(msg.durationSec != null ? { durationSec: msg.durationSec } : {}), ...(msg.forwardedFrom ? { forwardedFrom: msg.forwardedFrom } : {}) }));
          notifyGroupDelivered(ws, msg.groupId, msgId, onlineMembers);
        } else {
          if (await isBlockedBy(msg.to, userNick)) return;
          if (!(await canReceiveFrom(userNick, msg.to))) {
            if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'send_blocked', to: msg.to, reason: 'block_incoming', ...(msgId ? { msgId } : {}) }));
            return;
          }
          await grantAllowlistIfBlocking(userNick, msg.to);
          const target = liveTarget(msg.to); const status = target ? 'delivered' : 'sent';
          await supabase.from('messages').insert({ from_nick: userNick, to_nick: msg.to, type: 'file', content: mediaCaption(msg), file_name: msg.fileName, file_data: fileData, timestamp: ts, delivered: !!target, msg_id: msgId, status, ...(msg.waveform ? { waveform: JSON.stringify(msg.waveform) } : {}), ...(msg.durationSec != null ? { duration_sec: msg.durationSec } : {}) });
          await trackFileObject(fileData, [msg.to]); // 2C
          if (target) { target.ws.send(JSON.stringify({ type: 'file_message', from: userNick, fileName: msg.fileName, fileSize: msg.fileSize, ...(msg.caption ? { caption: String(msg.caption).slice(0, 4000) } : {}), ...(msg.fileUrl ? { fileUrl: msg.fileUrl } : { data: msg.data }), timestamp: ts, msgId, ...(msg.waveform ? { waveform: msg.waveform } : {}), ...(msg.durationSec != null ? { durationSec: msg.durationSec } : {}), ...(msg.forwardedFrom ? { forwardedFrom: msg.forwardedFrom } : {}) })); if (msgId && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'status_update', status: 'delivered', msgIds: [msgId] })); }
          else { sendFcmPush(msg.to, { type: 'message', from_nick: userNick }); }
        }
      }

      if (msg.type === 'file_downloaded') {
        const path = storagePathFromUrl(msg.fileUrl || msg.path || msg.fileData || '');
        if (path && userNick) {
          try {
            const { data: rows } = await supabase.from('file_objects').select('downloaded_by').eq('storage_path', path).limit(1);
            if (rows && rows.length) {
              const set = new Set(rows[0].downloaded_by || []);
              if (!set.has(userNick)) { set.add(userNick); await supabase.from('file_objects').update({ downloaded_by: [...set] }).eq('storage_path', path); }
            }
          } catch (e) { console.log('[2C] file_downloaded error:', e.message); }
        }
      }

      if (msg.type === 'group_message') {
        const ts = (typeof msg.timestamp === 'number' && msg.timestamp > 0 && msg.timestamp <= Date.now() + 60000) ? msg.timestamp : Date.now(); const msgId = msg.msgId || `${userNick}_g${msg.groupId}_${ts}`;
        const { data: membership } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId).eq('nick', userNick).single();
        if (!membership) return;
        const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId);
        const onlineMembers = (members || []).map(m => m.nick).filter(n => n !== userNick && isLive(n));
        await supabase.from('group_messages').insert({ group_id: msg.groupId, from_nick: userNick, content: msg.text, timestamp: ts, msg_id: msgId, delivered_to: [userNick, ...onlineMembers], ...(msg.isFile ? { type: 'file', file_name: msg.fileName, file_data: msg.fileData || msg.fileUrl } : {}), ...(msg.replyToMsgId ? { reply_to_msg_id: msg.replyToMsgId } : {}), ...(msg.replyToText ? { reply_to_text: msg.replyToText } : {}), ...(msg.replyToFrom ? { reply_to_from: msg.replyToFrom } : {}), ...(msg.replyToImage ? { reply_to_image: msg.replyToImage } : {}) });
        for (const nick of onlineMembers) onlineUsers.get(nick).ws.send(JSON.stringify({ type: 'group_message', groupId: msg.groupId, from: userNick, text: msg.text, timestamp: ts, msgId, ...(msg.isFile ? { isFile: true } : {}), ...(msg.isVoice ? { isVoice: true } : {}), ...(msg.fileName ? { fileName: msg.fileName } : {}), ...(msg.fileData ? { fileData: msg.fileData } : {}), ...(msg.fileUrl ? { fileUrl: msg.fileUrl } : {}), ...(msg.replyToMsgId ? { replyToMsgId: msg.replyToMsgId } : {}), ...(msg.replyToText ? { replyToText: msg.replyToText } : {}), ...(msg.replyToFrom ? { replyToFrom: msg.replyToFrom } : {}), ...(msg.replyToImage ? { replyToImage: msg.replyToImage } : {}), ...(msg.forwardedFrom ? { forwardedFrom: msg.forwardedFrom } : {}) }));
        notifyGroupDelivered(ws, msg.groupId, msgId, onlineMembers);
      }

      if (msg.type === 'ei_message') { /* нарахування прибрано */ }
      if (msg.type === 'group_typing') { const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId); for (const m of members || []) { if (m.nick !== userNick) { const t = onlineUsers.get(m.nick); if (t) t.ws.send(JSON.stringify({ type: 'group_typing', groupId: msg.groupId, from: userNick })); } } }
      // Групова read-квитанція: користувач відкрив групу → позначаємо всі
      // повідомлення інших як прочитані ним. Статус «переглянуто» (fully_read)
      // виставляється лише коли ВСІ учасники, крім автора, прочитали.
      // Тоді автору (якщо онлайн) шлемо group_status_update.
      if (msg.type === 'group_read_receipt') {
        const groupId = msg.groupId;
        const { data: membership } = await supabase.from('group_members').select('nick').eq('group_id', groupId).eq('nick', userNick).single();
        if (membership) {
          const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', groupId);
          const memberNicks = (members || []).map(m => m.nick);
          const { data: msgs } = await supabase.from('group_messages')
            .select('id, from_nick, msg_id, read_by, fully_read')
            .eq('group_id', groupId).neq('from_nick', userNick).eq('fully_read', false);
          const nowReadBySender = {};  // автор → [msgId, що стали fully_read] → сині ✓✓
          const nowSeenBySender = {};  // автор → [msgId, що прочитав хтось один] → сірі ✓✓
          for (const m of msgs || []) {
            const readBy = m.read_by || [];
            if (readBy.includes(userNick)) continue;
            const newReadBy = [...readBy, userNick];
            const others = memberNicks.filter(n => n !== m.from_nick);
            const allRead = others.length > 0 && others.every(n => newReadBy.includes(n));
            await supabase.from('group_messages').update({ read_by: newReadBy, ...(allRead ? { fully_read: true } : {}) }).eq('id', m.id);
            if (m.msg_id) (allRead ? (nowReadBySender[m.from_nick] ??= []) : (nowSeenBySender[m.from_nick] ??= [])).push(m.msg_id);
          }
          for (const [status, bySender] of [['read', nowReadBySender], ['delivered', nowSeenBySender]]) {
            for (const [sender, msgIds] of Object.entries(bySender)) {
              const t = onlineUsers.get(sender);
              if (t && t.ws.readyState === WebSocket.OPEN) t.ws.send(JSON.stringify({ type: 'group_status_update', groupId, status, msgIds }));
            }
          }
        }
      }
      if (msg.type === 'reaction') {
        const { msgId, emoji, chatNick, groupId } = msg;
        if (groupId) {
          const { data: ex } = await supabase.from('group_message_reactions').select('id').eq('msg_id', msgId).eq('group_id', groupId).eq('nick', userNick).eq('emoji', emoji).maybeSingle();
          if (ex) { await supabase.from('group_message_reactions').delete().eq('id', ex.id); }
          else {
            await supabase.from('group_message_reactions').delete().eq('msg_id', msgId).eq('group_id', groupId).eq('nick', userNick);
            await supabase.from('group_message_reactions').insert({ msg_id: msgId, group_id: groupId, nick: userNick, emoji });
          }
          const payload = { type: 'reaction', msgId, emoji, from: userNick, groupId, reactions: await groupReactionsState(groupId, msgId) };
          const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', groupId);
          for (const m of (members || [])) {
            if (m.nick === userNick) continue;
            if (sendToUser(m.nick, payload)) continue;
            const { error: pErr } = await supabase.from('pending_reactions').insert({ msg_id: msgId, emoji, from_nick: userNick, to_nick: m.nick, group_id: groupId, chat_nick: null });
            if (pErr) console.log(`[reaction] pending INSERT FAILED to=${m.nick}: ${pErr.message}`);
          }
        } else if (chatNick) {
          const pairKey = [userNick, chatNick].sort().join('|');
          const { data: dex } = await supabase.from('direct_message_reactions').select('id').eq('msg_id', msgId).eq('from_nick', userNick).eq('emoji', emoji).maybeSingle();
          if (dex) { await supabase.from('direct_message_reactions').delete().eq('id', dex.id); }
          else {
            await supabase.from('direct_message_reactions').delete().eq('msg_id', msgId).eq('from_nick', userNick).eq('pair_key', pairKey);
            await supabase.from('direct_message_reactions').insert({ msg_id: msgId, from_nick: userNick, emoji, pair_key: pairKey });
          }
          const payload = { type: 'reaction', msgId, emoji, from: userNick, chatNick, reactions: await directReactionsState(pairKey, msgId) };
          if (!sendToUser(chatNick, payload)) {
            const { error: pErr } = await supabase.from('pending_reactions').insert({ msg_id: msgId, emoji, from_nick: userNick, to_nick: chatNick, chat_nick: chatNick, group_id: null });
            if (pErr) console.log(`[reaction] pending INSERT FAILED to=${chatNick}: ${pErr.message}`);
          }
        }
      }
      if (msg.type === 'edit_message') { await supabase.from('messages').update({ content: msg.text }).eq('msg_id', msg.msgId).eq('from_nick', userNick); sendToUser(msg.to, { type: 'edit_message', from: userNick, msgId: msg.msgId, text: msg.text }); }
      if (msg.type === 'edit_group_message') { const { data: membership } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId).eq('nick', userNick).single(); if (!membership) return; await supabase.from('group_messages').update({ content: msg.text }).eq('msg_id', msg.msgId).eq('group_id', msg.groupId).eq('from_nick', userNick); await notifyMembers(msg.groupId, { type: 'edit_group_message', groupId: msg.groupId, msgId: msg.msgId, text: msg.text }, userNick); }
      if (msg.type === 'delete_group_message') { const { data: gMsg } = await supabase.from('group_messages').select('from_nick').eq('msg_id', msg.msgId).single(); if (!gMsg || (gMsg.from_nick !== userNick && !(await isModOrCreator(msg.groupId, userNick)))) return; await supabase.from('group_messages').delete().eq('msg_id', msg.msgId); await notifyMembers(msg.groupId, { type: 'delete_group_message', groupId: msg.groupId, msgId: msg.msgId }, userNick); }
      if (msg.type === 'delete_comment') {
        const { data: c } = await supabase.from('channel_comments').select('from_nick, channel_id, post_id, file_data').eq('id', msg.commentId).single();
        if (!c) return;
        const { data: cm } = await supabase.from('channel_members').select('role').eq('channel_id', c.channel_id).eq('nick', userNick).single();
        const canDel = c.from_nick === userNick || (cm && ['owner', 'admin'].includes(cm.role));
        if (!canDel) return;
        await supabase.from('channel_comment_reactions').delete().eq('comment_id', msg.commentId);
        await supabase.from('channel_comments').delete().eq('id', msg.commentId);
        await removeChannelFile(c.file_data);
        await notifyChannelSubscribers(c.channel_id, { type: 'channel_comment_deleted', channelId: c.channel_id, postId: c.post_id, commentId: msg.commentId }, userNick);
      }
      if (msg.type === 'read_receipt') { await supabase.from('messages').update({ status: 'read' }).eq('to_nick', userNick).eq('from_nick', msg.to); const target = onlineUsers.get(msg.to); if (target) { const { data: readMsgs } = await supabase.from('messages').select('msg_id').eq('to_nick', userNick).eq('from_nick', msg.to).not('msg_id', 'is', null); target.ws.send(JSON.stringify({ type: 'read_receipt', from: userNick, msgIds: (readMsgs || []).map(m => m.msg_id).filter(Boolean) })); } }
      if (msg.type === 'delete_message') { if (!sendToUser(msg.to, { type: 'delete_message', from: userNick, msgId: msg.msgId })) await supabase.from('deleted_messages').insert({ msg_id: msg.msgId, from_nick: userNick, to_nick: msg.to }); }
      if (msg.type === 'typing') { const target = onlineUsers.get(msg.to); if (target) target.ws.send(JSON.stringify({ type: 'typing', from: userNick })); }
      // Застосунковий ping тримає сокет живим для heartbeat (isAlive), а не лише
      // оновлює lastSeen: якщо Render не пропускає ПРОТОКОЛЬНІ ping/pong, сервер
      // інакше вбивав би живий сокет кожні 30с (флапінг presence/дзвінків).
      if (msg.type === 'ping') { ws.isAlive = true; if (userNick && onlineUsers.has(userNick)) onlineUsers.get(userNick).lastSeen = Date.now(); ws.send(JSON.stringify({ type: 'pong' })); }

      if (msg.type === 'call_offer') {
        // Якщо адресат заблокував того, хто дзвонить — не з'єднуємо. Той самий
        // сигнал call_error, що й для інших "недоступний" сценаріїв.
        if (await isBlockedBy(msg.to, userNick)) {
          ws.send(JSON.stringify({ type: 'call_error', error: 'Абонент недоступний' }));
          return;
        }
        // Глобальний блок вхідних адресата (крім тих, кому він сам написав за блоку).
        if (!(await canReceiveFrom(userNick, msg.to))) {
          ws.send(JSON.stringify({ type: 'call_error', error: 'Абонент не приймає дзвінки' }));
          return;
        }
        // Захист від «дзвінка самому собі»: якщо адресат — інший акаунт на
        // ТОМУ САМОМУ пристрої (спільний FCM-токен), не доставляємо ні WS, ні пуш.
        const target = onlineUsers.get(msg.to);
        // Порівнюємо deviceId ФАКТИЧНИХ сокетів обох сторін, а не мапу за
        // ніками: мапа памʼятає історію («нік колись заходив із цього
        // телефона») і хибно блокувала дзвінки між РІЗНИМИ пристроями. Сокет
        // же завжди належить одній конкретній машині. Десктоп deviceId не
        // реєструє → undefined → перевірка не спрацьовує, і це правильно.
        const fromDev = ws.deviceId;
        const toDev = target && target.ws && target.ws.deviceId;
        if (fromDev && toDev && fromDev === toDev) {
          console.log(`call_offer blocked: ${userNick}->${msg.to} same device ${fromDev}`);
          ws.send(JSON.stringify({ type: 'call_error', error: 'Неможливо дзвонити на цей самий пристрій' }));
          return;
        }
        const openSocket = !!(target && target.ws && target.ws.readyState === 1 /* WebSocket.OPEN */);
        const hasToken = !!(await getFcmToken(msg.to));
        // ВАЖЛИВО: сокет міг «померти» (клієнт пішов у фон, code=1006), але ще
        // не бути прибраним із onlineUsers (delete/heartbeat не встигли). Тоді
        // наївний target.ws.send піде в нікуди, а FCM не спрацює — дзвінок
        // зникає безслідно. Тому для клієнта З FCM-токеном доставляємо через WS
        // лише якщо сокет виглядає ЖИВИМ, інакше — пуш.
        //
        // НЕ покладаємось на смикливий isAlive: heartbeat щоцикла (30с) ставить
        // isAlive=false до наступного pong/app-ping. call_offer — одномоментна
        // подія: влучивши в це вікно, він помилково йшов у FCM.
        const wsAlive = openSocket
          && (target.ws.isAlive !== false || Date.now() - (target.lastSeen || 0) < 35000);
        // Доставляємо offer через WS, якщо: (а) сокет живий за евристикою, АБО
        // (б) сокет ВІДКРИТИЙ, але FCM-фолбеку однаково немає (десктоп без токена).
        // Випадок (б) — це і був баг: для десктопа евристика isAlive/lastSeen лише
        // шкодила. Хибно спрацювавши (Render глушить протокольні pong; app-ping
        // десктопа міг відставати → lastSeen «протухав»), вона кидала offer ЖИВОГО
        // десктопа у FCM-гілку, а там для десктопа глухий кут — call_error «не в
        // мережі». Симптом (підтверджено логом 03.08): call_ice долітали ДЕСЯТКАМИ
        // (вони без гейту), а call_offer — жодного разу, вхідний не дзвенів. Для
        // Android із токеном поведінка НЕ змінюється (зомбі-сокет → FCM, як і було).
        if (wsAlive || (openSocket && !hasToken)) {
          target.ws.send(JSON.stringify({ type: 'call_offer', from: userNick, offer: msg.offer, hasVideo: msg.hasVideo || false }));
        } else {
          if (target) { onlineUsers.delete(msg.to); console.log(`call_offer: ${msg.to} stale socket → FCM`); }
          // Missed-лог створюємо ЗАВЖДИ, коли доставити наживо не вдалось —
          // і для FCM (адресат у фоні/офлайн, пуш міг не розбудити), і без токена.
          // Це єдиний запис, який БАЧИТЬ адресат: no_answer від того-хто-дзвонив
          // для нього фільтрується. Якщо пуш розбудить і дзвінок приймуть —
          // цей запис приберемо в call_answer (див. нижче).
          await supabase.from('call_logs').insert({ from_nick: userNick, to_nick: msg.to, has_video: msg.hasVideo || false, started_at: Date.now(), status: 'missed' });
          if (hasToken) {
            await sendCallPush(msg.to, userNick, msg.hasVideo || false, msg.offer);
          } else {
            ws.send(JSON.stringify({ type: 'call_error', error: `${msg.to} не в мережі` }));
          }
        }
      }
      if (msg.type === 'call_answer') {
        const target = onlineUsers.get(msg.to);
        if (target) target.ws.send(JSON.stringify({ type: 'call_answer', from: userNick, answer: msg.answer }));
        // Дзвінок таки прийняли (FCM розбудив) → прибираємо передчасний missed-лог
        // цієї пари (from=той-хто-дзвонив=msg.to, to=я=userNick).
        await clearPreemptiveMissed(msg.to, userNick);
      }
      if (msg.type === 'call_ice') { const target = onlineUsers.get(msg.to); if (target) target.ws.send(JSON.stringify({ type: 'call_ice', from: userNick, candidate: msg.candidate })); }
      // Перемикання аудіо↔відео посеред дзвінка (renegotiation)
      if (msg.type === 'call_renegotiate') { const target = onlineUsers.get(msg.to); if (target) target.ws.send(JSON.stringify({ type: 'call_renegotiate', from: userNick, offer: msg.offer })); }
      if (msg.type === 'call_renegotiate_answer') { const target = onlineUsers.get(msg.to); if (target) target.ws.send(JSON.stringify({ type: 'call_renegotiate_answer', from: userNick, answer: msg.answer })); }
      if (msg.type === 'call_video_state') { const target = onlineUsers.get(msg.to); if (target) target.ws.send(JSON.stringify({ type: 'call_video_state', from: userNick, on: !!msg.on })); }
      if (msg.type === 'call_reject') {
        const target = onlineUsers.get(msg.to);
        let delivered = false;
        if (target && target.ws && target.ws.readyState === 1) {
          try { target.ws.send(JSON.stringify({ type: 'call_reject', from: userNick })); delivered = true; } catch (_) {}
        }
        if (!delivered) { await sendFcmPush(msg.to, { type: 'call_end', from_nick: userNick }, 60000); }
        // Свідоме відхилення ≠ пропущений: прибираємо передчасний missed цієї пари
        // (from=той-хто-дзвонив=msg.to, to=я=userNick), інакше в адресата лишиться
        // зайвий 'missed' поряд із 'rejected'.
        await clearPreemptiveMissed(msg.to, userNick);
        console.log(`[calldiag] WS call_reject ${userNick}->${msg.to} delivered=${delivered}${delivered ? '' : ' (fallback FCM push)'}`);
      }
      if (msg.type === 'call_end') {
        const target = onlineUsers.get(msg.to);
        if (target) { try { target.ws.send(JSON.stringify({ type: 'call_end', from: userNick })); } catch (_) {} }
        // ЗАВЖДИ шлемо й FCM (не лише коли офлайн): якщо вхідний показує НАТИВНИЙ
        // CallActivity (offer прийшов через FCM, поки Android був у фоні), а тепер
        // Android онлайн — сам WS-call_end нативний дзвінок не спинить. FCM-пуш
        // прибирає CallActivity нативно; для foreground-Flutter це безпечний no-op
        // (activeConnection == null, рингтон не грає, нотифікації 1 нема).
        await sendFcmPush(msg.to, { type: 'call_end', from_nick: userNick }, 60000);
      }
    } catch (e) { console.error('Помилка:', e); }
  });
  ws.on('close', (code, reason) => {
    console.log(`[ws] close nick=${userNick || '?'} code=${code} reason=${reason ? reason.toString() : ''}`);
    // ВАЖЛИВО: видаляємо presence ЛИШЕ якщо цей сокет — досі поточний. Інакше
    // гонка реконекту: закриття СТАРОГО сокета (після того, як login уже
    // зареєстрував НОВИЙ) стирало б запис нового → юзер «постійно офлайн».
    if (userNick && onlineUsers.get(userNick)?.ws === ws) onlineUsers.delete(userNick);
  });
  ws.on('error', (e) => { console.log(`[ws] error nick=${userNick || '?'}: ${e && e.message}`); });
});

setInterval(() => { const now = Date.now(); for (const [nick, user] of onlineUsers) if (now - user.lastSeen > 60000) onlineUsers.delete(nick); }, 60000);

// Серверний WS-heartbeat: кожні 30с пінгуємо всі сокети; хто не відповів pong
// з минулого циклу — транспорт мертвий (code=1006) → термінуємо й чистимо presence.
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) {
      try { ws.terminate(); } catch (_) {}
      return;
    }
    ws.isAlive = false;
    try { ws.ping(); } catch (_) {}
  });
}, 30000);

// ── Прибирання транзитного сховища (БЕЗПЕЧНО) ──────────────────────────────
// Принцип «сервер = транзит, не архів»: доставлені повідомлення прибираються за TTL,
// і ПАРНО з рядком видаляються байти у Storage (фікс «осиротілих» файлів).
// ЗАПОБІЖНИК: за замовчуванням DRY-RUN — лише ЛОГУЄ, що видалив би, нічого не чіпає.
// Перевіривши логи на реальних даних — постав env CLEANUP_DRY_RUN=false, щоб увімкнути реальне видалення.
const CLEANUP_DRY_RUN = (process.env.CLEANUP_DRY_RUN || 'true') !== 'false';
const DIRECT_TTL_MS = 7 * 24 * 60 * 60 * 1000;   // direct: 7 днів після доставки
const GROUP_TTL_MS = 30 * 24 * 60 * 60 * 1000;   // групи: 30 днів І лише якщо доставлено ВСІМ поточним учасникам

// Видалення файлу каналу (пост/коментар) зі Storage при видаленні запису.
// Безпечний: пропускає base64/порожнє, ковтає помилки, не блокує відповідь.
async function removeChannelFile(...urls) {
  for (const u of urls) {
    const path = storagePathFromUrl(u);
    if (!path) continue; // base64 або не-Storage URL — нічого видаляти
    try { await supabase.storage.from('files').remove([path]); console.log('[channel-cleanup] removed:', path); }
    catch (e) { console.log('[channel-cleanup] remove error:', path, e.message); }
  }
}

// Шлях у бакеті `files` з будь-якого представлення файлу.
// Після Storage 2b їх три, і функція знала лише найстаріше:
//   • eion://files/<path>              — реф (те, що клієнт шле тепер);
//   • …/object/sign/files/<path>?token — підписаний URL (приватний бакет);
//   • …/object/public/files/<path>     — публічний URL (до міграції).
// Поки розпізнавався лише public, `file_downloaded` не знаходив шляху й
// downloaded_by не оновлювався — тобто чистка файлів (2C) мовчки не
// працювала з моменту переходу на приватний Storage.
function storagePathFromUrl(url) {
  if (!url || typeof url !== 'string') return null;
  let tail = null;
  if (url.startsWith('eion://files/')) {
    tail = url.slice('eion://files/'.length);
  } else {
    for (const marker of ['/object/sign/files/', '/object/public/files/']) {
      const i = url.indexOf(marker);
      if (i !== -1) { tail = url.slice(i + marker.length); break; }
    }
  }
  if (tail === null) return null;
  const q = tail.indexOf('?');            // підписаний URL несе ?token=…
  if (q !== -1) tail = tail.slice(0, q);
  try { return decodeURIComponent(tail); } catch (_) { return tail; }
}

// Чи посилається на цей файл ще якийсь рядок (окрім тих, що ЗАРАЗ видаляємо)?
// Це захищає переслані копії: файл прибираємо лише коли на нього більше нема посилань.
async function fileStillReferenced(fileData, delDirectIds, delGroupIds) {
  const { data: m } = await supabase.from('messages').select('id').eq('file_data', fileData);
  if ((m || []).some(r => !delDirectIds.has(r.id))) return true;
  const { data: g } = await supabase.from('group_messages').select('id').eq('file_data', fileData);
  if ((g || []).some(r => !delGroupIds.has(r.id))) return true;
  return false;
}

async function removeOrphanFile(fileData, delDirectIds, delGroupIds) {
  const path = storagePathFromUrl(fileData);
  if (!path) return;
  if (await fileStillReferenced(fileData, delDirectIds, delGroupIds)) return; // ще використовується — не чіпаємо
  if (await fileObjectActive(path)) return; // 2C: ще не всі забрали і TTL не вийшов — лишаємо 2C
  if (CLEANUP_DRY_RUN) { console.log('[cleanup][dry] would remove storage:', path); return; }
  try { await supabase.storage.from('files').remove([path]); console.log('[cleanup] removed storage:', path); }
  catch (e) { console.log('[cleanup] storage remove error:', path, e.message); }
}

async function cleanupDirect() {
  const cutoff = Date.now() - DIRECT_TTL_MS;
  const { data: old } = await supabase.from('messages').select('id, file_data').eq('delivered', true).lt('timestamp', cutoff);
  const rows = old || [];
  if (!rows.length) return;
  const delIds = new Set(rows.map(r => r.id));
  const seen = new Set();
  for (const r of rows) {
    if (!r.file_data || seen.has(r.file_data)) continue;
    seen.add(r.file_data);
    await removeOrphanFile(r.file_data, delIds, new Set());
  }
  if (CLEANUP_DRY_RUN) { console.log(`[cleanup][dry] direct: would delete ${rows.length} rows (${seen.size} unique files)`); return; }
  await supabase.from('messages').delete().eq('delivered', true).lt('timestamp', cutoff);
  console.log(`[cleanup] direct: deleted ${rows.length} rows`);
}

async function cleanupGroups() {
  const cutoff = Date.now() - GROUP_TTL_MS;
  const { data: old } = await supabase.from('group_messages').select('id, group_id, file_data, delivered_to').lt('timestamp', cutoff);
  const rows = old || [];
  if (!rows.length) return;
  const byGroup = new Map();
  for (const r of rows) { if (!byGroup.has(r.group_id)) byGroup.set(r.group_id, []); byGroup.get(r.group_id).push(r); }
  const delRows = [];
  for (const [gid, grows] of byGroup) {
    const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', gid);
    const memberNicks = (members || []).map(m => m.nick);
    if (!memberNicks.length) continue; // підстрахування: групу без учасників не чіпаємо
    for (const r of grows) {
      const dt = new Set(r.delivered_to || []);
      if (memberNicks.every(n => dt.has(n))) delRows.push(r); // доставлено ВСІМ поточним учасникам
    }
  }
  if (!delRows.length) return;
  const delIds = new Set(delRows.map(r => r.id));
  const seen = new Set();
  for (const r of delRows) {
    if (!r.file_data || seen.has(r.file_data)) continue;
    seen.add(r.file_data);
    await removeOrphanFile(r.file_data, new Set(), delIds);
  }
  if (CLEANUP_DRY_RUN) { console.log(`[cleanup][dry] groups: would delete ${delRows.length} delivered-to-all rows (${seen.size} unique files)`); return; }
  const ids = [...delIds];
  for (let i = 0; i < ids.length; i += 100) {
    await supabase.from('group_messages').delete().in('id', ids.slice(i, i + 100));
  }
  console.log(`[cleanup] groups: deleted ${delRows.length} rows`);
}

// ── 2C: облік завантажень файлів (видаляємо зі Storage лише коли ВСІ забрали АБО вийшов TTL) ──
const FILE_OBJECT_TTL_MS = 30 * 24 * 60 * 60 * 1000; // жорсткий TTL: 30 днів

// Заводимо облік для надісланого файлу: хто має забрати (recipients).
// Підпис до медіа їде в колонці `content`: для файлових повідомлень вона й так
// дублювала `file_name` (саме ім'я лежить в окремій колонці), тож нової колонки
// не треба. Клієнт відрізняє підпис від службового імені саме за цією
// нерівністю — так само, як це давно зроблено в коментарях каналів.
function mediaCaption(msg) {
  const c = typeof msg.caption === 'string' ? msg.caption.trim() : '';
  return c ? c.slice(0, 4000) : msg.fileName;
}

async function trackFileObject(fileData, recipients) {
  const path = storagePathFromUrl(fileData);
  if (!path || !recipients || !recipients.length) return;
  const now = Date.now();
  try {
    await supabase.from('file_objects').upsert({
      storage_path: path, recipients, downloaded_by: [],
      created_at: now, expires_at: now + FILE_OBJECT_TTL_MS,
    }, { onConflict: 'storage_path' });
  } catch (e) { console.log('[2C] trackFileObject error:', e.message); }
}

// true, якщо для шляху є активний облік (ще не всі забрали І TTL не вийшов) → 2A не чіпає.
async function fileObjectActive(path) {
  try {
    const { data } = await supabase.from('file_objects').select('recipients, downloaded_by, expires_at').eq('storage_path', path).limit(1);
    if (!data || !data.length) return false;
    const r = data[0];
    const recips = r.recipients || [];
    const dl = new Set(r.downloaded_by || []);
    const allDownloaded = recips.length > 0 && recips.every(x => dl.has(x));
    const expired = Date.now() > (r.expires_at || 0);
    return !(allDownloaded || expired);
  } catch (_) { return false; }
}

async function cleanupFileObjects() {
  const now = Date.now();
  const { data: rows } = await supabase.from('file_objects').select('storage_path, recipients, downloaded_by, expires_at');
  const list = rows || [];
  if (!list.length) return;
  let removed = 0;
  for (const r of list) {
    const recips = r.recipients || [];
    const dl = new Set(r.downloaded_by || []);
    const allDownloaded = recips.length > 0 && recips.every(x => dl.has(x));
    const expired = now > (r.expires_at || 0);
    if (!allDownloaded && !expired) continue;
    if (CLEANUP_DRY_RUN) {
      console.log(`[cleanup][dry] 2C would remove ${r.storage_path} (allDownloaded=${allDownloaded}, expired=${expired})`);
      continue;
    }
    try { await supabase.storage.from('files').remove([r.storage_path]); } catch (e) { console.log('[2C] remove err:', e.message); }
    await supabase.from('file_objects').delete().eq('storage_path', r.storage_path);
    removed++;
  }
  if (!CLEANUP_DRY_RUN && removed) console.log(`[cleanup] 2C removed ${removed} files`);
}

setInterval(async () => {
  try { await cleanupDirect(); } catch (e) { console.log('[cleanup] direct error:', e.message); }
  try { await cleanupGroups(); } catch (e) { console.log('[cleanup] groups error:', e.message); }
  try { await cleanupFileObjects(); } catch (e) { console.log('[cleanup] fileObjects error:', e.message); }
}, 60 * 60 * 1000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`EION сервер запущено на порті ${PORT}`));
