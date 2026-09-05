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
const fs = require('fs');
const path = require('path');

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
// Ціни преміуму — на рівні модуля: їх читає і покупка, і довідка, яку сервер
// підкладає AI-асистенту. Дві копії розійшлись би тихо, і асистент упевнено
// називав би стару ціну.
const PREMIUM_PRICES = { monthly: 1000, yearly: 8400 };
// Стартовий баланс нового акаунта. Задається ТУТ (у /register), колонка в БД
// має свій DEFAULT лише як запобіжник.
const NEW_USER_COINS = 200;
// Гаманець створюється НЕ автоматично, а кнопкою — і його відкриття коштує
// монет: наша реальна витрата тут одна, рента токен-рахунку (~0,002 SOL ≈
// $0,37 на mainnet), і платить її наш гаманець. Преміум звільняється.
const WALLET_OPEN_FEE = Number(process.env.WALLET_OPEN_FEE || 50);
const WALLET_BIND_DAILY = Number(process.env.WALLET_BIND_DAILY || 3);
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
      return res.status(429).json({ ok: false, error: 'Забагато запитів, спробуйте пізніше', code: 'err_rate_limited' });
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

// 🔴 Нік потрапляє у фільтри PostgREST, де кома й дужки — РОЗДІЛЬНИКИ. Нік
// `x,id.gt.0` перетворював `or=(from_nick.eq.x,to_nick.eq.x)` на умову, що
// збігається з УСІЄЮ таблицею: «видалити свій акаунт» стирало переписку всіх.
// Значення ми більше не вставляємо у фільтр рядком (див. /delete-account і
// /call-logs), але забороняємо їх і на вході — другий рубіж, бо нік їде ще й
// у шляхи сховища та в підписи.
const NICK_FORBIDDEN = /[,()"'\\]|[\u0000-\u001f\u007f]/;
function nickLooksSafe(nick) {
  return typeof nick === 'string' && !NICK_FORBIDDEN.test(nick);
}

// ── Класи монет при переказі між людьми ─────────────────────────────────────
// Виводиться в токен лише «зароблене» — те, за що заплатила ІНША людина.
// Але сам переказ мусить клас ПЕРЕНОСИТИ, а не створювати: інакше бонус
// новачка ставав виведеним через один зайвий крок (зареєструвався → переказав
// собі на основний акаунт → вивів), і два класи не давали б нічого.
//
/// Списати монети й дізнатись, скільки з витраченого було «зароблене».
/// Внутрішнє витрачається першим — виведене лишається за власником.
async function spendCoinsSplit(nick, amount) {
  const { data, error } = await supabase.rpc('spend_coins_split', { p_nick: nick, p_amount: amount });
  if (error) {
    // Міграції ще немає. Тоді списуємо старою функцією, але «зароблене» з
    // повітря НЕ вигадуємо: краще недодати виведеного, ніж відкрити кран.
    console.error('[coins] spend_coins_split недоступна:', error.message);
    const { data: bal, error: e2 } = await supabase.rpc('spend_coins', { p_nick: nick, p_amount: amount });
    if (e2) return { ok: false, code: 'err_charge_failed', error: 'Помилка списання' };
    if (bal === -1) return { ok: false, code: 'err_not_enough_coins', error: 'Недостатньо монет' };
    return { ok: true, balance: bal, earnedSpent: 0 };
  }
  const row = Array.isArray(data) ? data[0] : data;
  const balance = Number(row && row.balance);
  if (!Number.isFinite(balance) || balance < 0) {
    return { ok: false, code: 'err_not_enough_coins', error: 'Недостатньо монет' };
  }
  return { ok: true, balance, earnedSpent: Math.max(0, Number(row.earned_spent) || 0) };
}

/// Нарахувати отримувачу: «зароблених» рівно стільки, скільки заплатив
/// відправник зі свого заробленого (але не більше самої суми), решта —
/// внутрішніми. Повертає новий баланс або null, якщо нарахувати не вдалось.
async function creditSplit(nick, amount, earnedPart) {
  const earned = Math.max(0, Math.min(Math.floor(earnedPart || 0), amount));
  const internal = amount - earned;
  let balance = null;
  if (earned > 0) {
    const { data } = await supabase.rpc('add_coins_earned', { p_nick: nick, p_amount: earned });
    if (data != null) balance = data;
  }
  if (internal > 0) {
    const { data } = await supabase.rpc('add_coins', { p_nick: nick, p_amount: internal });
    if (data != null) balance = data;
  }
  return balance;
}

/// Повернути відправнику рівно те, що з нього зняли — з тих самих класів.
async function refundSplit(nick, amount, earnedPart) {
  const earned = Math.max(0, Math.min(Math.floor(earnedPart || 0), amount));
  const internal = amount - earned;
  if (earned > 0) await supabase.rpc('add_coins_earned', { p_nick: nick, p_amount: earned });
  if (internal > 0) await supabase.rpc('add_coins', { p_nick: nick, p_amount: internal });
}

// ── Пароль акаунта на грошових шляхах ───────────────────────────────────────
// Сесійний токен ≠ дозвіл рухати гроші. Пароль на клієнті НЕ зберігається
// (аудит #16), тож із вкраденого пристрою його не дістати — саме це й робить
// його другим рубежем: токен дає читати переписку, але не спорожнити баланс.
// Прикрито рівно три шляхи, якими гроші виходять з-під контролю власника:
//   /transfer-coins          — монети на інший акаунт;
//   /token/payout            — монети → токен на привʼязану адресу;
//   /profile/solana-address  — підміна САМОЇ адреси виплати (наступна виплата
//                              власника пішла б злодію, і пароль тут не спитали б).
// Токенні перекази й поповнення сюди НЕ входять: там транзакцію підписує ключ
// із пристрою, а він лежить під паролем гаманця (Argon2id) — окремий рубіж.
// Стеля ціни платної підписки на канал (монет за період).
const CHANNEL_PRICE_MAX = 10000;
const PW_FAIL_MAX = 5;              // невдалих спроб поспіль
const PW_LOCK_MS = 15 * 60 * 1000;  // пауза після вичерпання
const pwFails = new Map(); // nick -> { count, lockedUntil, at }
setInterval(() => {
  const now = Date.now();
  for (const [n, r] of pwFails) if (now - r.at > PW_LOCK_MS) pwFails.delete(n);
}, PW_LOCK_MS).unref?.();

/// Звірити пароль акаунта перед грошовою дією.
/// Повертає null, якщо все гаразд; інакше — готове тіло відповіді для res.json.
///
/// ⚠️ Лічильник невдач тримаємо в памʼяті СВІДОМО (на відміну від кодів
/// відновлення, які довелось переносити в БД). Втрата стану тут грає на користь
/// власника, а не атакувальника: рестарт знімає лише блокування, а не сам
/// захист, і активний перебір не дає Render заснути, тож само собою воно не
/// обнулиться. При ввімкненому кластері це місце переїде в спільний шар разом
/// із rate-limit.
/// Ті самі лічильник і пауза, але для шляхів, які звіряють пароль самі
/// (вхід і зміна даних акаунта). Раніше блокування було лише на грошових
/// діях — тобто підбирати пароль можна було на `/login` без обмежень на нік,
/// а звідти він відмикає й гроші.
///
/// ⚠️ Компроміс, свідомий: чужими невдалими спробами можна на 15 хв
/// заблокувати вхід власнику. Тому для входу поріг вищий (10 проти 5) — там
/// помиляється жива людина, а не той, хто вже знає половину пароля.
function pwLocked(nick) {
  const rec = pwFails.get(nick);
  return !!(rec && rec.lockedUntil > Date.now());
}

function notePwFail(nick, max = PW_FAIL_MAX) {
  const now = Date.now();
  const rec = pwFails.get(nick);
  let cur = (rec && rec.lockedUntil && rec.lockedUntil <= now) ? null : rec;
  cur = cur || { count: 0, lockedUntil: 0, at: now };
  cur.count++; cur.at = now;
  if (cur.count >= max) cur.lockedUntil = now + PW_LOCK_MS;
  pwFails.set(nick, cur);
}

const PW_LOCKED_BODY = { ok: false, error: 'Забагато спроб, спробуйте за 15 хвилин', code: 'err_password_locked' };

async function requireAccountPassword(req) {
  const nick = req.nick;
  if (!nick) return { ok: false, error: 'Не авторизовано', code: 'err_unauthorized' };
  const now = Date.now();
  const rec = pwFails.get(nick);
  if (rec && rec.lockedUntil > now) {
    return { ok: false, error: 'Забагато спроб, спробуйте за 15 хвилин', code: 'err_password_locked' };
  }
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  if (!password) return { ok: false, error: 'Потрібен пароль', code: 'err_password_required' };
  const { data: user } = await supabase.from('users').select('password_hash').eq('nick', nick).single();
  if (!user || !user.password_hash) return { ok: false, error: 'Користувача не знайдено', code: 'err_user_not_found' };
  if (!(await bcrypt.compare(password, user.password_hash))) {
    // Блокування минуло — рахуємо з чистого аркуша, інакше давня серія помилок
    // складалась би з новою й замикала акаунт з другої спроби.
    let cur = (rec && rec.lockedUntil && rec.lockedUntil <= now) ? null : rec;
    cur = cur || { count: 0, lockedUntil: 0, at: now };
    cur.count++; cur.at = now;
    if (cur.count >= PW_FAIL_MAX) cur.lockedUntil = now + PW_LOCK_MS;
    pwFails.set(nick, cur);
    return { ok: false, error: 'Невірний пароль', code: 'err_wrong_password' };
  }
  pwFails.delete(nick); // успіх скидає лічильник
  return null;
}

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
  '/download-ping', '/app/version',
]);
app.use((req, res, next) => {
  if (PUBLIC_PATHS.has(req.path) || req.path.startsWith('/admin/') || req.path.startsWith('/locales/') || req.path === '/coin/supply') return next();
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  const nick = resolveSession(token);
  if (!nick) return res.status(401).json({ ok: false, error: 'Не авторизовано', code: 'err_unauthorized' });
  req.nick = nick;
  next();
});

// Денні норми користувача для екрана гаманця. Актор — ЗАВЖДИ з сесії:
// чужі витрати не показуємо, ніка в запиті немає взагалі.
//
// Навіщо endpoint, а не число в локалі: тексти з зашитими нормами вже двічі
// розходились із кодом (ціни 30.08, «+50» у гаманці). Те, що прийшло з
// сервера, розійтись не може — і заразом видно, скільки норми лишилось.
app.get('/usage/today', async (req, res) => {
  try {
    res.json({ ok: true, ...(await quotaSnapshot(req.nick)) });
  } catch (e) {
    console.error('[usage/today]', e.message);
    res.status(500).json({ ok: false, error: 'Не вдалося отримати норми', code: 'err_quota_unavailable' });
  }
});

// Яка збірка застосунку зараз актуальна. Публічний шлях навмисно: перевірка
// має працювати й до входу (застаріла збірка може не вміти залогінитись).
//
// Навіщо взагалі: APK роздається з сайту, магазину немає, автооновлення теж —
// тобто без цієї перевірки кожна встановлена збірка лишається назавжди тією,
// якою була. Виправлення, зроблені після неї, до людини не доїжджають ніколи,
// і вона про це не дізнається.
//
// ⚠️ ОНОВЛЮВАТИ РАЗОМ ІЗ ЗАЛИВКОЮ РЕЛІЗУ. `code` — це `+N` з pubspec.yaml
// клієнта; він і порівнюється (назва версії лише для показу людині).
// `minCode` підвищувати лише тоді, коли старий клієнт СПРАВДІ несумісний
// із сервером: він робить оновлення обовʼязковим, без кнопки «Пізніше».
const APP_RELEASE = {
  version: '0.9.51',
  code: 52,
  minCode: 0,
  android: 'https://github.com/eichat/eion-network/releases/latest/download/EION.apk',
  linux: 'https://github.com/eichat/eion-network/releases/latest/download/EION-x86_64.AppImage',
};
app.get('/app/version', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.json({ ok: true, ...APP_RELEASE });
});

// Лічильник завантажень. Кнопки на сайті ведуть ПРЯМО на GitHub, а сюди летить
// `navigator.sendBeacon` — тобто завантаження починається одразу, не чекаючи
// нашого сервера (він на безкоштовному тарифі спить і будиться 30–60 с; редирект
// через нього перетворив би головну дію сайту на півхвилини очікування).
//
// Навіщо взагалі свій лічильник: GitHub рахує завантаження НА ФАЙЛ, а ми при
// кожній збірці замінюємо asset у релізі — старий видаляється разом зі своїм
// лічильником, і число там завжди «з моменту останньої заміни».
//
// Точність свідомо неповна: beacon може не дійти (вимкнений JS, блокувальник,
// закрита вкладка). Це показник динаміки, а не бухгалтерія.
app.post('/download-ping', async (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.json({ ok: true });   // відповідаємо одразу, рахуємо після
  const kind = req.query.kind === 'appimage' ? 'appimage' : 'apk';
  // Джерело — лише «наш сайт чи ні». Referer далі не розбираємо: повний шлях
  // разом із часом уже наближається до сліду конкретної людини.
  const ref = String(req.headers['referer'] || '');
  const source = /(^|\/\/)([a-z0-9-]+\.)?eion\.network/i.test(ref) ? 'site' : 'other';
  try {
    const { error } = await supabase.rpc('bump_download', { p_kind: kind, p_source: source });
    if (error) console.error('[download-ping]', error.message);
  } catch (e) { console.error('[download-ping]', e.message); }
});

// Публічний стан монети: скільки видано з фондів і скільки спалено назавжди.
// Токеноміка вимагає прозорого burn-дашборда; це його джерело даних.
app.get('/coin/supply', async (req, res) => {
  // Єдиний endpoint, який читає браузер із сайту (burn-дашборд на eion.network),
  // тому заголовок ставимо точково тут, а не глобальним cors() — решта API
  // працює з токеном і в браузері їй робити нічого.
  res.set('Access-Control-Allow-Origin', '*');
  try {
    // Заразом показуємо, чи живий облік використання: без нього сінки мовчки
    // роздають усе безкоштовно, і це не видно ні з чого іншого.
    const { error: ucErr } = await supabase.from('usage_counters').select('nick').limit(1);
    // Толерантно до ще не виконаної міграції `coin_backing`: без нових колонок
    // запит відхилився б цілком, і сайт показав би нулі замість справжніх чисел.
    let { data } = await supabase.from('coin_supply')
      .select('minted, burned, deposited, released, float_in, updated_at').eq('id', 1).single();
    if (!data) {
      const r = await supabase.from('coin_supply').select('minted, burned, updated_at').eq('id', 1).single();
      data = r.data;
    }
    const { data: company } = await supabase.from('users').select('coins').eq('nick', COMPANY_NICK).single();
    const { data: circ } = await supabase.rpc('coins_circulating');
    res.json({
      ok: true,
      minted: Number(data?.minted || 0),
      burned: Number(data?.burned || 0),
      treasury: Number(company?.coins || 0),
      // Монета входить в обіг лише за замкнений у мості токен: `deposited` —
      // вніс користувач, `float_in` — влили з фондів проєкту.
      circulating: circ == null ? null : Number(circ),
      deposited: Number(data?.deposited || 0),
      released: Number(data?.released || 0),
      floatIn: Number(data?.float_in || 0),
      quotasWorking: !ucErr,
      updatedAt: data?.updated_at || null,
    });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

// ── Локалі ─────────────────────────────────────────────────────────────────
// Роздаємо переклади самі, а не з GitHub raw: той не є CDN (без гарантій
// доступності, з лімітами, і в частині країн заблокований), а клієнт ходить
// сюди й так. ETag дозволяє не пересилати незмінений файл — 45 КБ на кожен
// старт застосунку перетворюються на 304 без тіла.
const LOCALES_DIR = path.join(__dirname, 'locales');
const _localeCache = new Map(); // lang → { body, etag }

app.get('/locales/:lang.json', (req, res) => {
  const lang = String(req.params.lang || '').toLowerCase();
  if (!/^[a-z]{2}$/.test(lang)) return res.status(400).json({ ok: false, error: 'bad lang' });
  try {
    let entry = _localeCache.get(lang);
    if (!entry) {
      const body = fs.readFileSync(path.join(LOCALES_DIR, `${lang}.json`), 'utf8');
      const etag = '"' + crypto.createHash('sha1').update(body).digest('hex').slice(0, 16) + '"';
      entry = { body, etag };
      _localeCache.set(lang, entry);
    }
    res.set('ETag', entry.etag);
    res.set('Cache-Control', 'public, max-age=300');
    if (req.headers['if-none-match'] === entry.etag) return res.status(304).end();
    res.type('application/json').send(entry.body);
  } catch (e) {
    res.status(404).json({ ok: false, error: 'locale not found' });
  }
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
// Коди відновлення пароля живуть у таблиці email_codes (migrations/email_reset_codes.sql):
// в пам'яті вони гинули при кожному рестарті/засинанні Render — див. коментар у міграції.
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
  if (deviceId) { nickDevices.set(nick, deviceId); busPublish({ t: 'dev', nick, deviceId }); }
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
  try {
    const { n, t } = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (!n) return null;
    // Відкликання: токени, випущені до межі, недійсні (зміна пароля, бан, …).
    const cut = sessionValidFrom.get(String(n).toLowerCase());
    if (cut && !(Number(t) >= cut)) return null;
    return n;
  } catch (_) { return null; }
}
// Сумісність зі старими викликами (async). БД більше не потрібна.
async function createSession(nick, _deviceId = null) { return createSessionToken(nick); }

// ── Відкликання сесій ────────────────────────────────────────────────────────
// Раніше це були заглушки, тобто НІЩО не гасило токен: зміна пароля лишала
// викрадену сесію робочою. Тепер зберігається межа на користувача — момент,
// раніше за який усі його токени недійсні (у токені вже є час випуску).
// Кеш у пам'яті тримає resolveSession синхронною (вона в кожному HTTP-запиті),
// джерело істини — users.tokens_valid_from, тож межа переживає рестарт.
const sessionValidFrom = new Map(); // nick_lower -> ms
async function loadSessionValidFrom() {
  try {
    const { data } = await supabase.from('users').select('nick_lower, tokens_valid_from').not('tokens_valid_from', 'is', null);
    sessionValidFrom.clear();
    for (const u of (data || [])) sessionValidFrom.set(u.nick_lower, Number(u.tokens_valid_from));
    console.log('[sessions] меж відкликання завантажено:', sessionValidFrom.size);
  } catch (e) { console.error('[loadSessionValidFrom]', e.message); }
}
loadSessionValidFrom();

// Одиничний токен stateless-схема відкликати не вміє (немає реєстру виданих),
// тож logout лишається клієнтським — він стирає свій токен у себе.
async function destroySession(_token) {}

async function destroySessionsForNick(nick) {
  if (!nick) return;
  const key = String(nick).toLowerCase();
  const now = Date.now();
  sessionValidFrom.set(key, now);
  // Для ВИДАЛЕНОГО акаунта рядка вже немає й update нічого не зачепить — межа
  // лишиться тільки в пам'яті. Це не діра: нік звільнено, а якщо його займе
  // інший, новий акаунт отримає власний tokens_valid_from при реєстрації.
  const { error } = await supabase.from('users').update({ tokens_valid_from: now }).eq('nick_lower', key);
  if (error) console.error('[sessions] revoke', key, error.message);
}

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
  if (!url) return res.json({ ok: false, error: 'url обов\'язковий', code: 'err_param_url' });
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
// ── Провайдери AI ─────────────────────────────────────────────────────────
// Асистент не привʼязаний до одного постачальника. Причин дві, і обидві вже
// боліли:
//  1. НАДІЙНІСТЬ. 29.08.2026 Groq зняв зашиту llama-3.3 — кожен запит почав
//     давати 404, і асистент був мертвий, доки ми цього не помітили. Другий
//     провайдер перетворює таку подію на «стало трохи повільніше».
//  2. ЕКОНОМІЯ. У більшості постачальників є безкоштовна денна норма. Коли
//     їх кілька, запити йдуть по черзі й безкоштовні норми складаються.
//
// Усі перелічені сумісні з форматом OpenAI (`/chat/completions`), тож код
// один — різняться лише хост, шлях і назви моделей. Провайдер вважається
// доступним, ЯКЩО задано його ключ у env: жодних правок коду, щоб додати ще
// одного, не потрібно.
//
// ⚠️ Назви моделей у `prefs` — це переваги, а не жорсткий вибір. При старті
// ми питаємо в провайдера список і беремо першу наявну; якщо не збіглась
// жодна — провайдер позначається несправним і в чергу не потрапляє (а не
// мовчки шле запити з неіснуючою моделлю). Перекрити вручну: env
// `AI_MODEL_<ID>` і `AI_MODEL_<ID>_PRO`, напр. `AI_MODEL_GROQ`.
const AI_PROVIDERS = [
  {
    id: 'groq', env: 'GROQ_API_KEY',
    host: 'api.groq.com', path: '/openai/v1/chat/completions', modelsPath: '/openai/v1/models',
    prefs: {
      base: ['openai/gpt-oss-20b', 'qwen/qwen3.8-27b', 'groq/compound-mini'],
      pro: ['openai/gpt-oss-120b', 'qwen/qwen3.8-27b', 'openai/gpt-oss-20b'],
    },
  },
  {
    id: 'cerebras', env: 'CEREBRAS_API_KEY',
    host: 'api.cerebras.ai', path: '/v1/chat/completions', modelsPath: '/v1/models',
    prefs: {
      base: ['llama3.1-8b', 'llama-3.3-70b', 'qwen-3-32b'],
      pro: ['llama-3.3-70b', 'qwen-3-32b', 'llama3.1-8b'],
    },
  },
  {
    id: 'mistral', env: 'MISTRAL_API_KEY',
    host: 'api.mistral.ai', path: '/v1/chat/completions', modelsPath: '/v1/models',
    prefs: {
      base: ['mistral-small-latest', 'open-mistral-nemo'],
      pro: ['mistral-large-latest', 'mistral-small-latest'],
    },
  },
  {
    id: 'gemini', env: 'GEMINI_API_KEY',
    host: 'generativelanguage.googleapis.com',
    path: '/v1beta/openai/chat/completions', modelsPath: '/v1beta/openai/models',
    // Аліаси `-latest` навмисно перші: Google перейменовує моделі частіше,
    // ніж ми деплоїмо, а аліас переживає перейменування.
    prefs: {
      base: ['gemini-flash-lite-latest', 'gemini-flash-latest', 'gemini-2.5-flash-lite', 'gemini-2.5-flash'],
      pro: ['gemini-pro-latest', 'gemini-2.5-pro', 'gemini-flash-latest'],
    },
  },
  {
    id: 'openrouter', env: 'OPENROUTER_API_KEY',
    host: 'openrouter.ai', path: '/api/v1/chat/completions', modelsPath: '/api/v1/models',
    // Тут перелік безкоштовних моделей змінюється надто часто, щоб його
    // зашивати: беремо будь-яку з міткою `:free`.
    prefs: { base: [], pro: [] }, preferFree: true,
  },
];

/// Обрані моделі по провайдерах: id → { base, pro, ok, error, checkedAt }.
const aiModels = {};

const aiKey = (p) => process.env[p.env];
const aiEnvModel = (p, tier) =>
  process.env[`AI_MODEL_${p.id.toUpperCase()}${tier === 'pro' ? '_PRO' : ''}`]
  || (p.id === 'groq' ? process.env[tier === 'pro' ? 'AI_MODEL_PRO' : 'AI_MODEL'] : null);

/// Порядок опитування. `AI_PROVIDER_ORDER` (через кому) дозволяє поставити
/// поперед дешевшого — без деплою.
function aiProviderOrder() {
  const raw = (process.env.AI_PROVIDER_ORDER || '').split(',').map(s => s.trim()).filter(Boolean);
  const known = AI_PROVIDERS.filter(p => aiKey(p) && aiModels[p.id] && aiModels[p.id].ok);
  if (!raw.length) return known;
  const byId = new Map(known.map(p => [p.id, p]));
  const first = raw.map(id => byId.get(id)).filter(Boolean);
  return [...first, ...known.filter(p => !raw.includes(p.id))];
}

function httpJson({ method = 'GET', host, path, headers = {}, body = null, timeout = 20000 }) {
  return new Promise((resolve) => {
    const r = https.request({ method, hostname: host, path, headers, timeout }, (up) => {
      let b = '';
      up.on('data', (c) => { b += c; });
      up.on('end', () => {
        let json = null;
        try { json = JSON.parse(b); } catch (_) {}
        resolve({ status: up.statusCode || 500, body: b, json });
      });
    });
    r.on('timeout', () => { r.destroy(); resolve({ status: 504, body: 'timeout' }); });
    r.on('error', (e) => resolve({ status: 502, body: e.message }));
    if (body) r.write(body);
    r.end();
  });
}

async function refreshProviderModels(p) {
  if (!aiKey(p)) { delete aiModels[p.id]; return; }
  const envBase = aiEnvModel(p, 'base');
  const envPro = aiEnvModel(p, 'pro');
  if (envBase && envPro) {
    aiModels[p.id] = { base: envBase, pro: envPro, ok: true, source: 'env', checkedAt: Date.now() };
    return;
  }
  const r = await httpJson({ host: p.host, path: p.modelsPath, headers: { Authorization: `Bearer ${aiKey(p)}` } });
  if (r.status !== 200 || !r.json) {
    aiModels[p.id] = { ok: false, error: `список моделей: ${r.status} ${String(r.body).slice(0, 120)}`, checkedAt: Date.now() };
    console.error(`[ai] ${p.id}: не вдалось отримати список моделей —`, r.status);
    return;
  }
  // ⚠️ Google віддає id з префіксом `models/…` — без зрізання жодна перевага
  // не збігалась, і провайдер мовчки не потрапляв у чергу.
  const ids = (r.json.data || r.json.models || [])
    .map(m => m.id || m.name).filter(Boolean)
    .map(id => String(id).replace(/^models\//, ''));
  const idSet = new Set(ids);
  const pick = (tier) => {
    const env = aiEnvModel(p, tier);
    if (env) return env;
    const fromPrefs = (p.prefs[tier] || []).find(m => idSet.has(m));
    if (fromPrefs) return fromPrefs;
    if (p.preferFree) return ids.find(id => String(id).endsWith(':free')) || null;
    return null;
  };
  const base = pick('base');
  const pro = pick('pro') || base;
  if (!base) {
    aiModels[p.id] = { ok: false, error: 'жодна з бажаних моделей недоступна', checkedAt: Date.now(), available: ids.slice(0, 40) };
    console.error(`[ai] ${p.id}: жодна з бажаних моделей недоступна — задай AI_MODEL_${p.id.toUpperCase()}`);
    return;
  }
  const prev = aiModels[p.id];
  aiModels[p.id] = { base, pro, ok: true, source: 'discovered', checkedAt: Date.now() };
  if (!prev || prev.base !== base || prev.pro !== pro) console.log(`[ai] ${p.id}: base=${base} pro=${pro}`);
}

async function refreshAiModels() {
  await Promise.all(AI_PROVIDERS.map(p => refreshProviderModels(p).catch(() => {})));
  const live = aiProviderOrder().map(p => p.id);
  console.log('[ai] провайдери в черзі:', live.join(', ') || 'ЖОДНОГО');
}
refreshAiModels();
setInterval(refreshAiModels, 12 * 60 * 60 * 1000);

/// Денна стеля запитів на провайдера — щоб безкоштовні норми не вигорали за
/// годину і черга справді розкладалась між постачальниками. Задається env
/// `AI_CAP_<ID>` (напр. `AI_CAP_GROQ=800`); без неї стелі немає.
/// Лічильник живе в тій самій `usage_counters` під службовим ніком, тобто
/// переживає рестарти Render (в памʼяті він обнулявся б на кожному деплої —
/// саме так ми вже втрачали FCM-токени).
const AI_PROVIDER_NICK = '#ai-provider';
async function providerCapLeft(p) {
  const cap = parseInt(process.env[`AI_CAP_${p.id.toUpperCase()}`] || '', 10);
  if (!Number.isFinite(cap) || cap <= 0) return Infinity;
  const used = await usageToday(AI_PROVIDER_NICK, p.id);
  if (used === null) return Infinity;   // лічильник недоступний — не блокуємо
  return Math.max(0, cap - used);
}

/// Черга провайдерів на цей запит: спершу ті, у кого лишилась денна норма.
///
/// Вичерпані НЕ викидаємо — вони йдуть у хвіст. Стеля потрібна, щоб рознести
/// навантаження по безкоштовних нормах, а не щоб лишити користувача без
/// асистента, коли всі норми вибрано.
async function aiQueue() {
  let order = aiProviderOrder();
  // Холодний старт: `refreshAiModels` асинхронний, а Render будиться саме на
  // першому запиті. Без цього перший після сну виклик AI бачив би порожню
  // чергу й повертав «AI недоступний» на рівному місці.
  if (!order.length && AI_PROVIDERS.some(p => aiKey(p))) {
    await refreshAiModels();
    order = aiProviderOrder();
  }
  const fresh = [], spent = [];
  for (const p of order) ((await providerCapLeft(p)) > 0 ? fresh : spent).push(p);
  return [...fresh, ...spent];
}

// Стан усіх провайдерів AI: який ключ заданий, яка модель обрана, чи жива.
// Потрібно, бо постачальники знімають моделі без попередження: 29.08.2026
// Groq зняв зашиту llama-3.3, і кожен запит мовчки давав 404.
// Стан кластера. Поки `REDIS_URL` не задано — enabled:false, і сервер
// працює рівно як раніше, одним інстансом.
app.get('/admin/cluster', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Доступ заборонено', code: 'err_forbidden' });
  let local = 0; const byInstance = {};
  for (const [, u] of onlineUsers) {
    if (u.remote) byInstance[u.inst] = (byInstance[u.inst] || 0) + 1;
    else local++;
  }
  res.json({
    ok: true,
    enabled: busReady(),
    redisConfigured: !!REDIS_URL,
    instance: INSTANCE_ID,
    onlineLocal: local,
    onlineRemote: Object.values(byInstance).reduce((a, b) => a + b, 0),
    byInstance,
    hint: REDIS_URL ? undefined : 'Щоб увімкнути: задати REDIS_URL у Render. Без нього — один інстанс.',
  });
});

app.get('/admin/ai-models', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Доступ заборонено', code: 'err_forbidden' });
  if (req.query.refresh === '1') await refreshAiModels();
  const queue = (await aiQueue()).map(p => p.id);
  const providers = [];
  for (const p of AI_PROVIDERS) {
    const m = aiModels[p.id];
    const cap = parseInt(process.env[`AI_CAP_${p.id.toUpperCase()}`] || '', 10);
    providers.push({
      id: p.id,
      keySet: !!aiKey(p),
      ok: !!(m && m.ok),
      base: m && m.base || null,
      pro: m && m.pro || null,
      source: m && m.source || null,
      error: m && m.error || null,
      available: m && m.available || undefined,
      usedToday: aiKey(p) ? await usageToday(AI_PROVIDER_NICK, p.id) : null,
      dailyCap: Number.isFinite(cap) && cap > 0 ? cap : null,
    });
  }
  const ep = embedProvider();
  res.json({ ok: true, queue, providers, lastAiError, embeddings: ep ? { provider: ep.id, model: process.env.EMBED_MODEL || ep.model, dims: EMBED_DIMS } : null });
});

/// Коротка довідка про EION, яку сервер підкладає асистенту.
///
/// Без неї на «скільки коштує преміум?» чи «чому в мене списались монети?»
/// модель відповідала загальними здогадами — вона про наш застосунок нічого
/// не знає. Текст СКЛАДАЄТЬСЯ З КОНСТАНТ вище, тому не може розійтися з тим,
/// що робить код: змінилась ціна — змінилась і відповідь асистента.
/// Англійською навмисно: модель однаково відповідає мовою користувача (це
/// задає системний промпт клієнта), а англійський опис коштує менше токенів.
function eionFactsPrompt() {
  return [
    'Facts about EION, the messenger this assistant lives in. Use them when asked; do not invent features.',
    '- Platforms: Android and Linux (beta). iOS and Windows are planned.',
    '- Chats, groups, channels with comments and streams, HD calls, sticker packs.',
    '- Calls are end-to-end encrypted (WebRTC). In direct one-to-one chats BOTH the text AND the attachments (photos, video, voice, documents, with their captions) are end-to-end encrypted: the key is created on the device and never leaves it, so the server and the file storage hold only ciphertext and we cannot read or restore them. Groups and channels are NOT encrypted yet — that is the next step. What the server still sees even in encrypted chats: file name, file size, voice length and waveform (delivery and cleanup rely on them), plus who talks to whom and when. Two honest limits: our server distributes the public keys, so without verification codes it does not formally protect against us; and the key is static, so there is no forward secrecy. The key is not backed up: reinstalling the app makes undelivered messages encrypted for the old key unreadable.',
    `- Coins are the in-app unit, not money and not cryptocurrency. New accounts get ${NEW_USER_COINS}.`,
    '- The EION token is a separate thing from coins: coins live inside the app, the token on a blockchain. The wallet can convert one into the other. Do not name the blockchain network.',
    `- The wallet is NOT created automatically. In profile settings there are two buttons: create a wallet, or restore one from its 12-word recovery phrase. On a second device the user must RESTORE, otherwise they get a second, separate wallet. Opening a wallet costs ${WALLET_OPEN_FEE} coins once (free for premium) and covers the on-chain account rent we pay.`,
    '- The wallet key never leaves the device and is encrypted with a wallet password, which is separate from the account password. We cannot recover either the password or the phrase; losing both means losing the tokens.',
    '- Only coins someone else paid you can be converted into tokens: a transfer from another user, an author share from a paid channel or from a paid contact, or a deposit of tokens. Coins we granted (the signup bonus, refunds) can be spent inside EION but not withdrawn. A transfer carries the class over rather than creating it: if the sender paid out of their own granted coins, the recipient also receives granted (non-withdrawable) coins. Inside an account the granted part is always spent first, so the withdrawable part stays.',
    `- Premium costs ${PREMIUM_PRICES.monthly} coins per month or ${PREMIUM_PRICES.yearly} per year.`,
    `- Free daily allowance: ${FREE_QUOTA.ai} AI requests, ${FREE_QUOTA.storage} MB of uploads, ${FREE_QUOTA.turn} relayed calls, ${FREE_QUOTA.translate} translations.`,
    `- Premium allowance: ${FREE_QUOTA.ai_premium} AI requests, ${FREE_QUOTA.storage_premium} MB, ${FREE_QUOTA.turn_premium} relayed calls, ${FREE_QUOTA.translate_premium} translations; files up to 20 MB instead of 5, and a stronger AI model.`,
    `- Beyond the allowance the user pays coins: ${SINK_PRICE.ai} per AI request, ${SINK_PRICE.storage} per MB, ${SINK_PRICE.turn} per relayed call.`,
    `- Transfers between users carry a ${TRANSFER_FEE_PCT}% fee. Paid channels give 70% to the author.`,
    '- Any action that moves coins out of the account asks for the ACCOUNT password (not the wallet password): transferring coins, converting coins into tokens, changing the wallet address, subscribing to a paid channel, paying to contact a channel owner. The password is never stored on the device, so a stolen phone cannot spend the balance. Buying stickers or premium does not ask, because those coins stay inside EION.',
    '- You have tools for the current user: balance, today\'s usage against the daily allowance, sticker packs, coin supply. Call them instead of guessing or asking the user to check.',
    '- If you do not know something about EION, say so instead of guessing.',
  ].join('\n');
}

// ── Переклад повідомлень ──────────────────────────────────────────────────
// ОКРЕМИЙ шлях, а не `/ai/chat` із перекладацьким промптом від клієнта. Три
// причини, і кожна вже боліла б у проді:
//  1. Квота. Переклад витрачається на КОЖНЕ вхідне повідомлення, тобто не за
//     рішенням користувача. На нормі асистента (15/добу) автопереклад помирав
//     би за 15 чужих реплік і далі брав по 3 монети за те, що тобі написали.
//  2. Зловживання. Коли промпт складає клієнт, «переклад» — це просто дешевший
//     тариф на довільні запити до моделі. Тут промпт складає сервер, а від
//     клієнта приходять лише текст і мова.
//  3. Ціна. Перекладу не потрібні ні 2048 токенів, ні температура 0.7.
const TRANSLATE_LANGS = {
  en: 'English', uk: 'Ukrainian', ru: 'Russian', de: 'German', es: 'Spanish',
  fr: 'French', it: 'Italian', pt: 'Portuguese', nl: 'Dutch', pl: 'Polish',
  tr: 'Turkish', id: 'Indonesian', vi: 'Vietnamese', tl: 'Tagalog', th: 'Thai',
  ja: 'Japanese', ko: 'Korean', zh: 'Chinese', hi: 'Hindi', bn: 'Bengali',
  ar: 'Arabic',
};
const TRANSLATE_MAX_CHARS = 2000;

/// Непотоковий виклик із перемиканням провайдерів: відповідає перший, хто зміг.
async function aiComplete(messages, { maxTokens = 512, temperature = 0, tier = 'base' } = {}) {
  const queue = await aiQueue();
  if (!queue.length) throw new Error('немає доступних провайдерів');
  let last = '';
  for (const p of queue) {
    const r = await aiJsonOnce(p, JSON.stringify({
      model: aiModels[p.id][tier], messages, max_tokens: maxTokens, temperature,
    }));
    if (r.status === 200 && r.json && !r.json.error) {
      await bumpUsage(AI_PROVIDER_NICK, p.id, 1);
      const m = r.json.choices && r.json.choices[0] && r.json.choices[0].message;
      return String((m && m.content) || '');
    }
    // Тіло читаємо ЗАВЖДИ: саме мовчазний 404 у тілі приховував зняту Groq
    // модель, поки кожен запит «просто не працював» (29.08.2026).
    last = `${p.id} ${r.status} ${String(r.body || '').slice(0, 150)}`;
    console.error('[ai/complete] провайдер відмовив:', last);
  }
  throw new Error(last || 'усі провайдери відмовили');
}

app.post('/ai/translate', async (req, res) => {
  const text = typeof req.body?.text === 'string' ? req.body.text.trim() : '';
  const target = typeof req.body?.target === 'string' ? req.body.target.toLowerCase() : '';
  const lang = TRANSLATE_LANGS[target];
  if (!text || !lang) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  if (text.length > TRANSLATE_MAX_CHARS) return res.json({ ok: false, error: 'Текст задовгий', code: 'err_text_too_long' });
  if (!aiProviderOrder().length) return res.json({ ok: false, error: 'AI недоступний', code: 'err_ai_unavailable' });

  const charge = await chargeSink(req.nick, 'translate');
  if (!charge.ok) return res.status(402).json({ ok: false, error: charge.error, code: charge.code });

  try {
    const content = (await aiComplete([
      { role: 'system', content: 'You are a translation engine. Output only the translation, with no quotes, notes or explanations.' },
      { role: 'user', content: `Translate the message below into ${lang}. If it is already in ${lang}, reply with exactly: OK\n\n${text}` },
    ], { maxTokens: 700, temperature: 0 })).trim();
    // Модель відповідає «OK» на текст, що вже цільовою мовою. Порівнюємо без
    // розділових знаків: трапляються «OK.» і «ok».
    const same = content.replace(/[^a-z]/gi, '').toLowerCase() === 'ok';
    res.json({ ok: true, same, text: same ? null : content, freeLeft: charge.free ?? 0, paid: charge.paid ?? 0 });
  } catch (e) {
    console.error('[ai/translate]', e.message);
    res.json({ ok: false, error: 'AI помилка', code: 'err_ai_failed' });
  }
});

// ── Памʼять відповідей ────────────────────────────────────────────────────
// Питання повторюються: «як створити канал», «скільки коштує преміум», «що
// таке монети». Платити моделі за ту саму відповідь щоразу — марно, тож
// відповідь запамʼятовується і наступному віддається одразу, без виклику
// моделі й без списання норми.
//
// 🔴 Кеш СПІЛЬНИЙ для всіх, тому головне тут — не пустити в нього приватне.
// Чотири умови разом (`cacheEligible` + перевірка після відповіді):
//   1. це ПЕРШЕ питання розмови — інакше відповідь залежить від контексту,
//      якого в іншого користувача немає;
//   2. у питанні немає цифр, пошти й посилань — найдешевший спосіб відсіяти
//      номери, суми й адреси;
//   3. відповідь дана БЕЗ жодного інструмента — саме інструменти приносять
//      у розмову особисті дані (баланс, витрату норми);
//   4. у відповіді немає ніка того, хто питав — інакше «як мене звати»
//      осіло б у кеші з чужим імʼям.
const AI_CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000;   // факти змінюються; місяць — розумна межа

function normalizeQuestion(text) {
  return String(text || '')
    .toLowerCase()
    .replace(/[\s\u00a0]+/g, ' ')
    .replace(/[!?.,;:()\[\]"'«»„“”…-]+/g, '')
    .trim();
}

/// Чи можна взагалі кешувати це питання (до того, як пішли до моделі).
/// `messages` — уже із санітизацією, але ДО додавання довідки.
function cacheEligible(messages) {
  const users = messages.filter(m => m.role === 'user');
  if (users.length !== 1) return null;                  // не перше питання розмови
  const q = users[0].content.trim();
  if (q.length < 8 || q.length > 200) return null;      // надто коротке або надто своєрідне
  if (/\d/.test(q) || q.includes('@') || /https?:\/\//i.test(q)) return null;
  const norm = normalizeQuestion(q);
  if (!norm) return null;
  // Мову задає системний промпт клієнта; нік у ньому в кожного свій, тож
  // прибираємо його — лишається саме мовний шаблон. Його відбиток і розрізняє
  // «як створити канал» українською та англійською.
  const sys = messages.filter(m => m.role === 'system').map(m => m.content).join(' ');
  return { question: q, norm, sysTemplate: sys };
}

function cacheKeyFor(elig, nick) {
  const template = elig.sysTemplate.split(nick).join('');
  const fp = crypto.createHash('sha1').update(template).digest('hex').slice(0, 8);
  return { fp, key: `${fp}:${crypto.createHash('sha1').update(elig.norm).digest('hex')}` };
}

// ── Ембединги: смисловий пошук по базі знань ──────────────────────────────
// Триграми порівнюють літери, тож «стерти профіль» і «видалити акаунт» вони
// не зіставлять. Ембединг перетворює речення на вектор змісту — і такі пари
// стають близькими. Але для цього потрібен постачальник ембедингів: Groq їх
// не віддає, безкоштовна норма є в Gemini.
//
// Без ключа нічого не ламається: `embedText` віддає null, пошук лишається
// триграмним. Тому увімкнення — це просто ключ у env, без деплою.
const EMBED_DIMS = 768;   // має збігатися з vector(768) у міграції
const EMBED_PROVIDERS = [
  {
    id: 'gemini', env: 'GEMINI_API_KEY',
    host: 'generativelanguage.googleapis.com', path: '/v1beta/openai/embeddings',
    // ⚠️ `text-embedding-004` у списку ключа НЕМАЄ — перша спроба дала 8 із 8
    // помилок саме через це. Питати список моделей, а не покладатись на памʼять.
    // gemini-embedding-001 рідно віддає 3072 виміри, тож просимо 768 явно;
    // для косинусної відстані нормалізація не потрібна — `<=>` робить її сам.
    model: 'gemini-embedding-001', dimensions: EMBED_DIMS,
  },
  {
    id: 'openai', env: 'OPENAI_API_KEY',
    host: 'api.openai.com', path: '/v1/embeddings',
    model: 'text-embedding-3-small', dimensions: EMBED_DIMS,   // 1536 → урізаємо до 768
  },
];

function embedProvider() {
  const forced = process.env.EMBED_PROVIDER;
  const list = forced ? EMBED_PROVIDERS.filter(p => p.id === forced) : EMBED_PROVIDERS;
  return list.find(p => process.env[p.env]) || null;
}

let lastEmbedError = null;   // для /admin/ai-embed-test: причина має бути видима
// Остання відмова чат-провайдера. 502 без сліду — саме те, через що ми вже
// двічі шукали причину наосліп; тут вона лишається видимою в /admin/ai-models.
let lastAiError = null;

/// Вектор змісту речення або null (немає ключа / збій — не привід ламати чат).
async function embedText(text) {
  const p = embedProvider();
  if (!p) return null;
  const body = JSON.stringify({
    model: process.env.EMBED_MODEL || p.model,
    input: String(text || '').slice(0, 2000),
    ...(p.dimensions ? { dimensions: p.dimensions } : {}),
  });
  const r = await httpJson({
    method: 'POST', host: p.host, path: p.path,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${process.env[p.env]}`,
      'Content-Length': Buffer.byteLength(body),
    },
    body, timeout: 20000,
  });
  if (r.status !== 200 || !r.json) {
    lastEmbedError = `${p.id} ${r.status} ${String(r.body || '').slice(0, 300)}`;
    console.error('[embed]', lastEmbedError);
    return null;
  }
  const vec = r.json.data && r.json.data[0] && r.json.data[0].embedding;
  if (!Array.isArray(vec)) {
    lastEmbedError = `${p.id}: несподівана відповідь ${String(r.body || '').slice(0, 200)}`;
    console.error('[embed]', lastEmbedError); return null;
  }
  if (vec.length !== EMBED_DIMS) {
    // Мовчазна невідповідність розмірності зіпсувала б таблицю: половина
    // записів була б непорівнянна з іншою половиною.
    lastEmbedError = `${p.id}: ${vec.length} вимірів замість ${EMBED_DIMS}`;
    console.error('[embed]', lastEmbedError);
    return null;
  }
  lastEmbedError = null;
  return vec;
}

const vecToSql = (v) => `[${v.join(',')}]`;

// ── База знань: наш шар відповідей перед провайдером ──────────────────────
// Поріг ПРЯМОЇ видачі високий: віддати збережену відповідь на схоже, але інше
// питання — гірше, ніж спитати модель. Середні збіги йдуть лише в контекст.
const KB_SERVE_SIM = 0.72;     // дослівно, без виклику моделі
const KB_CONTEXT_SIM = 0.35;   // підмішати як довідку
// Косинусна близькість живе в іншій шкалі, ніж схожість триграм: у неї навіть
// геть різні речення однієї мови дають 0.5–0.6. Тому пороги окремі й вищі.
const KB_VEC_SERVE_SIM = 0.88;
// 🔴 Поріг НЕ здатен відділити доречне від недоречного, і це виміряно:
// хибний збіг «створити групу» → «створити канал» дав 0.738, а правильний
// «якими мовами працює застосунок» → «якими мовами працює EION» — 0.745.
// Вони перетинаються. Тому поріг тут лише щоб відсікти зовсім далеке, а
// розбирається промпт: моделі прямо дозволено відкинути недоречний запис.
// Ціна помилок різна: зайвий запис у контексті модель проігнорує, а
// пропущений означає «не знаю» про те, що ми задокументували.
const KB_VEC_CONTEXT_SIM = 0.70;

/// Пошук по базі знань. Два шляхи, і вони доповнюють один одного:
/// вектор ловить зміст іншими словами, триграми — точні збіги й терміни,
/// яких у навчанні ембедингів могло не бути (назви, коди, «libmpv»).
/// Кожен рядок несе `via` і свій поріг: шкали в них різні.
async function kbSearch(fp, question) {
  const rows = [];
  const vec = await embedText(question);
  if (vec) {
    const { data, error } = await supabase.rpc('ai_kb_search_vec',
      { p_fp: fp, p_vec: vecToSql(vec), p_limit: 4 });
    if (error) console.error('[ai-kb] векторний пошук:', error.message);
    for (const r of data || []) rows.push({ ...r, via: 'vec' });
  }
  const { data, error } = await supabase.rpc('ai_kb_search', { p_fp: fp, p_query: question, p_limit: 4 });
  if (error) {
    // Не ковтати: без бази знань асистент просто дорожчає, і це має бути видно.
    console.error('[ai-kb] пошук:', error.message);
  }
  for (const r of data || []) {
    if (!rows.some(x => x.key === r.key)) rows.push({ ...r, via: 'trgm' });
  }
  return rows;
}

const kbServeOk = (r) => Number(r.sim) >= (r.via === 'vec' ? KB_VEC_SERVE_SIM : KB_SERVE_SIM);
const kbContextOk = (r) => Number(r.sim) >= (r.via === 'vec' ? KB_VEC_CONTEXT_SIM : KB_CONTEXT_SIM);

/// Знайдене підмішується як ДОВІДКА, а не як готова відповідь: модель має
/// відповісти нашими фактами, але мовою користувача й на його питання.
function kbContextPrompt(rows) {
  // «Не додавай кроків, яких тут немає» — не зайва обережність: на першому ж
  // тесті модель дописала до нашої інструкції крок, якого в застосунку немає.
  // Довідка має звужувати відповідь, а не бути приводом дофантазувати навколо.
  let out = 'Entries from the EION knowledge base, retrieved by similarity. '
    + 'They may cover a DIFFERENT feature than the one asked about (channels vs groups, for example) — '
    + 'use only the entries that actually answer the question and ignore the rest. '
    + 'What you do use is authoritative: follow it exactly, answer in the user language, and do NOT invent '
    + 'extra steps, buttons or settings that are not mentioned. If nothing here covers the question, '
    + 'just say you do not know that about EION — never mention this knowledge base, retrieval or context.';
  for (const r of rows) {
    const block = `\n\nQ: ${r.question}\nA: ${r.answer}`;
    if (out.length + block.length > 4000) break;
    out += block;
  }
  return out;
}

async function cacheLookup(key) {
  const { data, error } = await supabase.from('ai_cache').select('answer, created_at, hits').eq('key', key).limit(1);
  if (error) { console.error('[ai-cache] читання:', error.message); return null; }
  const row = data && data[0];
  if (!row) return null;
  if (Date.now() - Number(row.created_at || 0) > AI_CACHE_TTL_MS) {
    await supabase.from('ai_cache').delete().eq('key', key);
    return null;
  }
  // hits — щоб було видно, які питання справді повторюються (і що варто
  // винести в довідку самого застосунку). Гонка тут нікому не шкодить.
  await supabase.from('ai_cache')
    .update({ hits: Number(row.hits || 0) + 1, last_used: Date.now() }).eq('key', key);
  return row.answer;
}

async function cacheStore(key, fp, question, answer, model, nick) {
  const a = String(answer || '').trim();
  if (a.length < 4 || a.length > 4000) return;
  if (nick && a.toLowerCase().includes(String(nick).toLowerCase())) return;   // умова 4
  const now = Date.now();
  // Вектор рахуємо для ПИТАННЯ: шукати ми будемо саме по ньому.
  const vec = await embedText(question);
  const { error } = await supabase.from('ai_cache').upsert({
    key, question, answer: a, model, hits: 0, created_at: now, last_used: now,
    lang_fp: fp, source: 'model', enabled: true,
    // ⚠️ Вектор передається ТЕКСТОМ: масив чисел PostgREST до `vector` не приводить.
    ...(vec ? { embedding: vecToSql(vec) } : {}),
  }, { onConflict: 'key' });
  if (error) console.error('[ai-cache] запис:', error.message);
}

// ── Інструменти асистента ─────────────────────────────────────────────────
// Асистент знає ФАКТИ про EION (eionFactsPrompt), але не бачив ДАНИХ
// користувача: на «скільки в мене монет» чи «чому списались монети» він міг
// лише переказати правила. Інструменти дають йому дивитись у базу.
//
// Цикл виконується НА СЕРВЕРІ, а не в клієнті. Три причини:
//  1. Актор — `req.nick` із сесії. Клієнт не може попросити чужий баланс:
//     нік у інструменти взагалі не передається, він береться з токена.
//  2. Новий інструмент не потребує збірки застосунку.
//  3. Дані й так серверні — гнати їх у клієнт, щоб той відправив назад
//     моделі, означало б зайвий круг і зайве світло приватних даних.
//
// ⚠️ Усі інструменти — ТІЛЬКИ ЧИТАННЯ. Дію, що змінює світ (надіслати
// повідомлення, переказати монети), інструментом робити не можна без
// підтвердження в інтерфейсі: помилкове спрацювання моделі написало б живій
// людині або витратило гроші, і скасувати це вже не можна.
const AI_TOOLS = [
  {
    type: 'function',
    function: {
      name: 'get_balance',
      description: 'Баланс монет і стан преміуму того, хто зараз питає.',
      parameters: { type: 'object', properties: {}, required: [] },
    },
  },
  {
    type: 'function',
    function: {
      name: 'get_usage_today',
      description: 'Скільки денної норми витрачено сьогодні (AI, вивантаження, дзвінки через релей, переклади) і скільки коштує одиниця понад норму.',
      parameters: { type: 'object', properties: {}, required: [] },
    },
  },
  {
    type: 'function',
    function: {
      name: 'find_user',
      description: 'Знайти користувача EION за ніком або його частиною.',
      parameters: {
        type: 'object',
        properties: { nick: { type: 'string', description: 'Нік або його частина, мінімум 2 символи' } },
        required: ['nick'],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'list_sticker_packs',
      description: 'Набори наліпок у магазині: назва, ціна в монетах і чи вже куплений.',
      parameters: { type: 'object', properties: {}, required: [] },
    },
  },
  {
    type: 'function',
    function: {
      name: 'get_coin_supply',
      description: 'Публічний стан монети EION: видано з фондів, спалено назавжди, у скарбниці.',
      parameters: { type: 'object', properties: {}, required: [] },
    },
  },
];

/// Виконати інструмент. `nick` завжди з сесії — аргументом він не приходить.
async function runAiTool(name, rawArgs, nick) {
  let args = {};
  try { if (rawArgs) args = JSON.parse(rawArgs); } catch (_) { /* модель дала не-JSON — працюємо без аргументів */ }
  try {
    if (name === 'get_balance') {
      const { data: u } = await supabase.from('users').select('coins, premium_expires_at, premium_plan').eq('nick', nick).single();
      if (!u) return { error: 'user not found' };
      const premium = !!(u.premium_expires_at && new Date(u.premium_expires_at) > new Date());
      return { coins: u.coins || 0, premium, premium_until: premium ? u.premium_expires_at : null, premium_plan: premium ? u.premium_plan : null };
    }
    if (name === 'get_usage_today') {
      const snap = await quotaSnapshot(nick);
      const out = { premium: snap.premium, kinds: {} };
      for (const [kind, k] of Object.entries(snap.kinds)) {
        out.kinds[kind] = {
          used: k.used === null ? 'unknown' : k.used,
          free_per_day: k.limit,
          left: k.left === null ? 'unknown' : k.left,
          coins_per_unit_over: k.price,
        };
      }
      out.units = { ai: 'requests', storage: 'megabytes uploaded', turn: 'relayed calls', translate: 'translated messages' };
      return out;
    }
    if (name === 'find_user') {
      const q = typeof args.nick === 'string' ? args.nick.trim() : '';
      if (q.length < 2) return { error: 'need at least 2 characters' };
      // Невидимі не показуються — той самий фільтр, що і в /search-user.
      const { data } = await supabase.from('users').select('nick')
        .ilike('nick_lower', `%${q.toLowerCase()}%`).neq('invisible', true).limit(10);
      return { found: (data || []).length, users: (data || []).map(u => ({ nick: u.nick, online: isLive(u.nick) })) };
    }
    if (name === 'list_sticker_packs') {
      const { data: packs } = await supabase.from('sticker_packs')
        .select('id, title, price').eq('is_active', true).order('sort_order', { ascending: true });
      const { data: owned } = await supabase.from('user_sticker_packs').select('pack_id').eq('nick', nick);
      const ownedSet = new Set((owned || []).map(o => o.pack_id));
      return { packs: (packs || []).map(p => ({ id: p.id, title: p.title, price: p.price, owned: ownedSet.has(p.id) })) };
    }
    if (name === 'get_coin_supply') {
      const { data } = await supabase.from('coin_supply').select('minted, burned').eq('id', 1).single();
      const { data: company } = await supabase.from('users').select('coins').eq('nick', COMPANY_NICK).single();
      return { minted: Number(data?.minted || 0), burned: Number(data?.burned || 0), treasury: Number(company?.coins || 0) };
    }
  } catch (e) {
    console.error('[ai-tool]', name, e.message);
    return { error: 'tool failed' };
  }
  return { error: 'unknown tool' };
}

/// Один потоковий виклик Groq.
///
/// Рядки з текстом віддаємо назовні одразу (`onData`), а tool_calls
/// накопичуємо: вони приходять шматками, як і текст, тому ім'я і аргументи
/// доводиться склеювати по індексу.
/// Розбір ОДНОГО рядка SSE від Groq.
///
/// Винесено окремо навмисно: це найкрихкіше місце всього циклу — і текст, і
/// виклики інструментів приходять шматками, тож ім'я функції та її аргументи
/// доводиться склеювати по `index`. Окрема функція дає перевірити це тестом,
/// не ганяючи прод.
/// `calls` мутується; рядки з текстом ідуть у `onData` як є.
function parseGroqSseLine(line, calls, onData, sink) {
  const s = line.trim();
  if (!s.startsWith('data:')) return;
  const body = s.slice(5).trim();
  if (body === '[DONE]') return;   // своє [DONE] надішлемо в кінці, одне на всю відповідь
  try {
    const d = JSON.parse(body);
    const delta = (d.choices && d.choices[0] && d.choices[0].delta) || {};
    if (Array.isArray(delta.tool_calls)) {
      for (const tc of delta.tool_calls) {
        const i = tc.index || 0;
        if (!calls[i]) calls[i] = { id: '', name: '', args: '' };
        if (tc.id) calls[i].id = tc.id;
        if (tc.function && tc.function.name) calls[i].name += tc.function.name;
        if (tc.function && tc.function.arguments) calls[i].args += tc.function.arguments;
      }
    }
    if (typeof delta.content === 'string' && delta.content.length) {
      if (sink) sink.push(delta.content);
      onData(`${line}\n\n`);
    }
  } catch (_) { /* не-JSON у потоці (коментар SSE) — пропускаємо */ }
}

function aiStreamOnce(p, payload, onData, holder) {
  return new Promise((resolve) => {
    const calls = [];
    const textParts = [];
    let buf = '';
    const handleLine = (line) => parseGroqSseLine(line, calls, onData, textParts);
    const up = https.request({
      method: 'POST', hostname: p.host, path: p.path,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${aiKey(p)}`,
        'Content-Length': Buffer.byteLength(payload),
      },
      timeout: 60000,
    }, (r) => {
      const status = r.statusCode || 500;
      if (status !== 200) {
        let b = '';
        r.on('data', (c) => { b += c; });
        r.on('end', () => resolve({ status, errorBody: b }));
        return;
      }
      r.on('data', (chunk) => {
        buf += chunk.toString('utf8');
        let i;
        while ((i = buf.indexOf('\n')) >= 0) { handleLine(buf.slice(0, i)); buf = buf.slice(i + 1); }
      });
      r.on('end', () => { if (buf) handleLine(buf); resolve({ status: 200, toolCalls: calls.filter(Boolean), text: textParts.join('') }); });
    });
    if (holder) holder.req = up;
    up.on('timeout', () => { up.destroy(); resolve({ status: 504 }); });
    up.on('error', (e) => resolve({ status: 502, errorBody: e.message }));
    up.write(payload); up.end();
  });
}

/// Один непотоковий виклик. Повертає сире тіло — клієнт розбирає його сам.
function aiJsonOnce(p, payload, holder) {
  return new Promise((resolve) => {
    const up = https.request({
      method: 'POST', hostname: p.host, path: p.path,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${aiKey(p)}`,
        'Content-Length': Buffer.byteLength(payload),
      },
      timeout: 60000,
    }, (r) => {
      let b = '';
      r.on('data', (c) => { b += c; });
      r.on('end', () => {
        let json = null;
        try { json = JSON.parse(b); } catch (_) {}
        resolve({ status: r.statusCode || 500, body: b, json });
      });
    });
    if (holder) holder.req = up;
    up.on('timeout', () => { up.destroy(); resolve({ status: 504, body: '' }); });
    up.on('error', (e) => resolve({ status: 502, body: e.message }));
    up.write(payload); up.end();
  });
}

// Чи вміє обрана модель викликати інструменти. Без цього «асистент не покликав
// інструмент» не відрізнити від «провайдер їх не прийняв»: відкат на роботу
// без інструментів навмисно тихий для користувача.
app.get('/admin/ai-tools-check', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Доступ заборонено', code: 'err_forbidden' });
  const out = [];
  for (const p of AI_PROVIDERS) {
    const m = aiModels[p.id];
    if (!m || !m.ok) continue;
    for (const tier of ['base', 'pro']) {
      if (tier === 'pro' && m.pro === m.base) continue;
      const r = await aiJsonOnce(p, JSON.stringify({
        model: m[tier],
        messages: [
          { role: 'system', content: 'Use the tools when asked about the user data.' },
          { role: 'user', content: 'How many coins do I have?' },
        ],
        tools: AI_TOOLS, tool_choice: 'auto', max_tokens: 256, temperature: 0,
      }));
      const msg = r.json && r.json.choices && r.json.choices[0] && r.json.choices[0].message;
      out.push({
        provider: p.id, tier, model: m[tier], status: r.status,
        toolCalls: ((msg && msg.tool_calls) || []).map(c => c.function && c.function.name),
        content: msg && typeof msg.content === 'string' ? msg.content.slice(0, 160) : null,
        error: r.status === 200 ? null : String(r.body || '').slice(0, 300),
      });
    }
  }
  res.json({ ok: true, checks: out });
});

// Що асистент уже запамʼятав. Заразом єдиний спосіб почистити памʼять, коли
// змінились факти (ціна, норми) — інакше стара відповідь жила б до кінця TTL.
app.get('/admin/ai-cache', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Доступ заборонено', code: 'err_forbidden' });
  if (req.query.clear === '1') {
    const { error } = await supabase.from('ai_cache').delete().neq('key', '');
    return res.json({ ok: !error, cleared: !error, error: error ? error.message : null });
  }
  const { data, error } = await supabase.from('ai_cache')
    .select('question, hits, created_at, model, source').order('hits', { ascending: false }).limit(50);
  if (error) return res.json({ ok: false, error: error.message });
  // Раніше `count` рахував довжину видачі, обмеженої 50 — і при 200 записах
  // діагностика показувала б 50. Числа, що тихо брешуть, і є те, через що
  // сьогодні тричі шукали причину не там.
  const total = await supabase.from('ai_cache').select('key', { count: 'exact', head: true });
  const model = await supabase.from('ai_cache').select('key', { count: 'exact', head: true }).eq('source', 'model');
  res.json({
    ok: true, total: total.count ?? null, modelAnswers: model.count ?? null,
    shown: (data || []).length, ttlDays: Math.round(AI_CACHE_TTL_MS / 86400000), top: data || [],
  });
});

// ── База знань: наші власні відповіді ─────────────────────────────────────
// Пишуться руками й ніколи не віддаються дослівно — підмішуються в контекст,
// щоб модель відповіла нашими фактами, але мовою користувача. Саме це робить
// асистента «своїм»: він знає те, чого немає в жодній моделі.
/// Забути відповіді, які модель дала ДО зміни бази знань.
///
/// 🔴 Інакше погана відповідь консервується: на «скільки мов підтримує
/// застосунок» асистент один раз сказав «не знаю», це осіло в памʼяті — і
/// віддавалось далі навіть після того, як відповідь у базу додали.
/// Наші власні записи не чіпаємо, а модельні відновляться самі за копійки.
async function forgetModelAnswers(reason) {
  const { error, count } = await supabase.from('ai_cache')
    .delete({ count: 'exact' }).eq('source', 'model');
  if (error) console.error('[ai-cache] чистка:', error.message);
  else console.log(`[ai-cache] забуто ${count ?? '?'} модельних відповідей — ${reason}`);
}

app.get('/admin/ai-kb', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Доступ заборонено', code: 'err_forbidden' });
  const { data, error } = await supabase.from('ai_cache')
    .select('key, question, answer, hits, enabled, created_at')
    .eq('source', 'curated').order('created_at', { ascending: false }).limit(200);
  if (error) return res.json({ ok: false, error: error.message });
  res.json({ ok: true, count: (data || []).length, entries: data || [] });
});

// Приймає `question` АБО `questions: [...]` — кілька формулювань однієї
// відповіді. Це не зручність, а спосіб обійти межу триграм: вони порівнюють
// літери, тож «не працює відео на лінуксі» не зіставиться з «Чому відео не
// відкривається на Linux». Доки немає смислового пошуку (ембединги), запис
// просто описують кількома способами — і кожен знаходить ту саму відповідь.
app.post('/admin/ai-kb', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Доступ заборонено', code: 'err_forbidden' });
  const list = Array.isArray(req.body?.questions) ? req.body.questions
    : (typeof req.body?.question === 'string' ? [req.body.question] : []);
  const questions = list.filter(q => typeof q === 'string').map(q => q.trim()).filter(q => q.length >= 4 && q.length <= 300);
  const answer = typeof req.body?.answer === 'string' ? req.body.answer.trim() : '';
  if (!questions.length || answer.length < 2) return res.json({ ok: false, error: 'Потрібні question(s) і answer' });
  if (answer.length > 4000) return res.json({ ok: false, error: 'Відповідь задовга' });
  const now = Date.now();
  const rows = [];
  for (const question of questions) {
    const vec = await embedText(question);
    rows.push({
      key: `curated:${crypto.createHash('sha1').update(normalizeQuestion(question)).digest('hex')}`,
      question, answer, model: null, hits: 0, created_at: now, last_used: now,
      // lang_fp порожній: наш запис не привʼязаний до мови інтерфейсу, бо
      // дослівно він не віддається — лише як довідка для моделі.
      lang_fp: '', source: 'curated', enabled: req.body.enabled !== false,
      ...(vec ? { embedding: vecToSql(vec) } : {}),
    });
  }
  const { error } = await supabase.from('ai_cache').upsert(rows, { onConflict: 'key' });
  if (error) return res.json({ ok: false, error: error.message });
  await forgetModelAnswers('додано запис до бази знань');
  res.json({ ok: true, added: rows.length, keys: rows.map(r => r.key) });
});

app.post('/admin/ai-kb/delete', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Доступ заборонено', code: 'err_forbidden' });
  const key = typeof req.body?.key === 'string' ? req.body.key : '';
  if (!key) return res.json({ ok: false, error: 'Потрібен key' });
  const { error } = await supabase.from('ai_cache').delete().eq('key', key);
  if (!error) await forgetModelAnswers('запис бази знань видалено');
  res.json({ ok: !error, error: error ? error.message : null });
});

// Перевірити ембединги одним запитом: що саме відповів постачальник.
// Без цього «done:0, failed:8» не відрізнити від «немає ключа», «немає такої
// моделі» й «не та розмірність» — а це три різні дії.
app.get('/admin/ai-embed-test', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Доступ заборонено', code: 'err_forbidden' });
  const p = embedProvider();
  if (!p) return res.json({ ok: false, error: 'Немає ключа ембедингів' });
  const vec = await embedText(typeof req.query.q === 'string' && req.query.q ? req.query.q : 'тестове речення');
  res.json({
    ok: !!vec, provider: p.id, model: process.env.EMBED_MODEL || p.model,
    dims: vec ? vec.length : null, expected: EMBED_DIMS, error: vec ? null : lastEmbedError,
  });
});

// Дозаповнити вектори для записів, доданих до появи ключа ембедингів.
// Порціями: кожен запис — це мережевий виклик, а Render рубає довгі запити.
app.post('/admin/ai-kb/embed', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Доступ заборонено', code: 'err_forbidden' });
  if (!embedProvider()) return res.json({ ok: false, error: 'Немає ключа ембедингів (GEMINI_API_KEY)' });
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit || '25', 10) || 25));
  const { data, error } = await supabase.from('ai_cache')
    .select('key, question').is('embedding', null).limit(limit);
  if (error) return res.json({ ok: false, error: error.message });
  let done = 0, failed = 0;
  for (const row of data || []) {
    const vec = await embedText(row.question);
    if (!vec) { failed++; continue; }
    const { error: e2 } = await supabase.from('ai_cache')
      .update({ embedding: vecToSql(vec) }).eq('key', row.key);
    if (e2) { console.error('[ai-kb] запис вектора:', e2.message); failed++; } else done++;
  }
  const { count } = await supabase.from('ai_cache')
    .select('key', { count: 'exact', head: true }).is('embedding', null);
  res.json({ ok: true, done, failed, left: count ?? null });
});

// Перевірити, що знайде база знань на конкретне питання — без виклику моделі.
app.get('/admin/ai-kb/search', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Доступ заборонено', code: 'err_forbidden' });
  const q = typeof req.query.q === 'string' ? req.query.q.trim() : '';
  if (!q) return res.json({ ok: false, error: 'Потрібен ?q=' });
  const rows = await kbSearch(typeof req.query.fp === 'string' ? req.query.fp : '', q);
  res.json({
    ok: true, serveThreshold: KB_SERVE_SIM, contextThreshold: KB_CONTEXT_SIM,
    vecServeThreshold: KB_VEC_SERVE_SIM, vecContextThreshold: KB_VEC_CONTEXT_SIM,
    embedProvider: embedProvider() ? embedProvider().id : null,
    rows: rows.map(r => ({
      question: r.question, source: r.source, via: r.via, sameLang: r.same_lang,
      sim: Number(r.sim).toFixed(3), wouldServe: kbServeOk(r), wouldContext: kbContextOk(r),
    })),
  });
});

app.post('/ai/chat', async (req, res) => {
  const raw = Array.isArray(req.body && req.body.messages) ? req.body.messages : null;
  if (!raw || raw.length === 0) return res.status(400).json({ error: { message: 'messages обовʼязкові' } });
  // Санітизація + ліміти проти абʼюзу: лише валідні role/content-рядки, останні 40, обрізка довжини.
  const messages = raw
    .filter(m => m && typeof m.role === 'string' && typeof m.content === 'string')
    .slice(-40)
    .map(m => ({ role: m.role, content: m.content.slice(0, 8000) }));
  if (messages.length === 0) return res.status(400).json({ error: { message: 'messages невалідні' } });

  // Памʼять відповідей — ДО списання норми: якщо відповідь уже знаємо, вона
  // не коштує нам виклику моделі, а отже не має коштувати нічого й користувачу.
  const elig = cacheEligible(messages);
  const ck = elig ? cacheKeyFor(elig, req.nick) : null;
  const cacheKey = ck && ck.key;

  /// Віддати готову відповідь без звернення до моделі.
  const serveKnown = (text, how) => {
    res.set('X-AI-Cache', how);
    if (req.body.stream === true) {
      res.status(200);
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('X-Accel-Buffering', 'no');
      res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: text } }] })}\n\n`);
      res.write('data: [DONE]\n\n');
      return res.end();
    }
    return res.json({ choices: [{ message: { role: 'assistant', content: text }, finish_reason: 'stop' }], cached: true });
  };

  // Рівень 1: те саме питання слово в слово.
  if (cacheKey) {
    const cached = await cacheLookup(cacheKey);
    if (cached) return serveKnown(cached, 'hit');
  }

  // Рівні 2–3: схоже питання і наша база знань.
  let kbContext = null;
  if (elig) {
    const rows = await kbSearch(ck.fp, elig.question);
    const strong = rows.find(r => r.source === 'model' && r.same_lang && kbServeOk(r));
    if (strong) return serveKnown(strong.answer, `similar:${strong.via}`);
    const ctx = rows.filter(kbContextOk).slice(0, 3);
    if (ctx.length) kbContext = kbContextPrompt(ctx);
  }

  // Кожен запит коштує нам грошей у постачальника, тож понад денну норму — за
  // монети. Це сінк, що покриває реальні витрати (токеноміка §4-A): саме такі
  // створюють справжній попит на монету, на відміну від суто косметичних.
  const charge = await chargeSink(req.nick, 'ai');
  if (!charge.ok) {
    return res.status(402).json({ error: { message: charge.error }, code: charge.code });
  }
  res.set('X-AI-Free-Left', String(charge.free ?? 0));
  res.set('X-AI-Paid', String(charge.paid ?? 0));
  // Довідку кладемо ПІСЛЯ системного промпту клієнта (він задає мову відповіді
  // й ім'я співрозмовника), але перед розмовою.
  const firstUser = messages.findIndex(m => m.role !== 'system');
  const at = firstUser === -1 ? messages.length : firstUser;
  messages.splice(at, 0, { role: 'system', content: eionFactsPrompt() });
  if (kbContext) messages.splice(at + 1, 0, { role: 'system', content: kbContext });
  const stream = req.body.stream === true;
  const tier = charge.isPremium ? 'pro' : 'base';   // преміуму — сильніша модель
  // 1024 різало довші відповіді на півслові (модель впиралась у стелю й
  // зупинялась). 2048 при ціні дешевої моделі нічого помітного не коштує.
  const build = (p, withTools) => JSON.stringify({
    model: aiModels[p.id][tier], messages, max_tokens: 2048, temperature: 0.7, stream,
    ...(withTools ? { tools: AI_TOOLS, tool_choice: 'auto' } : {}),
  });

  // Клієнт закрив зʼєднання (скасував) — не тримаємо висячий запит до моделі.
  const holder = { req: null };
  let aborted = false;
  res.on('close', () => { aborted = true; if (holder.req) holder.req.destroy(); });

  const queue = await aiQueue();
  if (!queue.length) return res.status(503).json({ error: { message: 'AI недоступний' }, code: 'err_ai_unavailable' });

  // Модель може не підтримувати інструменти. Тоді провайдер відповідає 400, і
  // без цього відкату асистент був би зламаний повністю, а не гірший.
  let withTools = true;
  const MAX_STEPS = 4;   // стеля циклу: інакше модель могла б ганяти інструменти без кінця

  /// Дописати в розмову виклики інструментів і їх результати.
  async function applyToolCalls(calls) {
    messages.push({
      role: 'assistant',
      content: '',
      tool_calls: calls.map(c => ({ id: c.id, type: 'function', function: { name: c.name, arguments: c.args || '{}' } })),
    });
    for (const c of calls) {
      const result = await runAiTool(c.name, c.args, req.nick);
      messages.push({ role: 'tool', tool_call_id: c.id, name: c.name, content: JSON.stringify(result) });
    }
  }

  /// Провайдер, який відповів першим успіхом. Далі тримаємось його: у межах
  /// однієї відповіді змішувати постачальників не можна — tool_call_id із
  /// чужої розмови для наступного нічого не означає.
  let pi = 0;
  let usedTools = false;      // чи торкалась відповідь особистих даних
  let answerText = '';        // для памʼяті відповідей
  const nextProvider = () => (pi < queue.length ? queue[pi++] : null);
  let provider = nextProvider();
  let lastError = null;

  if (stream) {
    let started = false;
    const send = (chunk) => {
      if (aborted || res.writableEnded) return;
      if (!started) {
        started = true;
        res.status(200);
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('X-Accel-Buffering', 'no');
      }
      res.write(chunk);
    };
    for (let step = 0; step < MAX_STEPS && !aborted && provider; step++) {
      const r = await aiStreamOnce(provider, build(provider, withTools), send, holder);
      if (r.status === 200) {
        await bumpUsage(AI_PROVIDER_NICK, provider.id, 1);
        answerText += r.text || '';
        if (!r.toolCalls || r.toolCalls.length === 0) break;
        usedTools = true;
        await applyToolCalls(r.toolCalls);
        continue;
      }
      lastError = lastAiError = `${new Date().toISOString()} ${provider.id} ${r.status} ${String(r.errorBody || '').slice(0, 200)}`;
      if (withTools && r.status === 400) {
        console.error('[ai] модель відхилила інструменти, повторюю без них:', lastError);
        withTools = false; step--; continue;
      }
      // Провайдер відмовив (ліміт, збій, знята модель) — пробуємо наступного.
      // Якщо частину відповіді вже віддали, переграти її не можна: продовжимо
      // з тим, що є, інакше користувач побачив би дві різні відповіді підряд.
      console.error('[ai] провайдер відмовив:', lastError);
      if (started) break;
      provider = nextProvider();
      if (!provider) {
        return res.status(502).json({ error: { message: 'AI помилка' }, code: r.status === 504 ? 'err_ai_timeout' : 'err_ai_failed' });
      }
      withTools = true; step--;
    }
    send('data: [DONE]\n\n');
    if (!res.writableEnded) res.end();
    // Запамʼятовуємо лише відповідь, дану БЕЗ інструментів: саме вони
    // приносять у розмову особисті дані.
    if (cacheKey && !usedTools && !aborted && answerText.trim()) {
      await cacheStore(cacheKey, ck.fp, elig.question, answerText, provider && aiModels[provider.id][tier], req.nick);
    }
    return;
  }

  for (let step = 0; step < MAX_STEPS && provider; step++) {
    const r = await aiJsonOnce(provider, build(provider, withTools), holder);
    if (r.status === 200) {
      await bumpUsage(AI_PROVIDER_NICK, provider.id, 1);
      const msg = r.json && r.json.choices && r.json.choices[0] && r.json.choices[0].message;
      const calls = (msg && msg.tool_calls) || [];
      if (calls.length === 0) {
        if (cacheKey && !usedTools && msg && typeof msg.content === 'string' && msg.content.trim()) {
          await cacheStore(cacheKey, ck.fp, elig.question, msg.content, aiModels[provider.id][tier], req.nick);
        }
        return res.type('application/json').send(r.body);
      }
      usedTools = true;
      await applyToolCalls(calls.map(c => ({ id: c.id, name: c.function && c.function.name, args: c.function && c.function.arguments })));
      continue;
    }
    lastError = lastAiError = `${new Date().toISOString()} ${provider.id} ${r.status} ${String(r.body || '').slice(0, 200)}`;
    if (withTools && r.status === 400) {
      console.error('[ai] модель відхилила інструменти, повторюю без них:', lastError);
      withTools = false; step--; continue;
    }
    console.error('[ai] провайдер відмовив:', lastError);
    provider = nextProvider();
    if (!provider) {
      return res.status(502).json({ error: { message: 'AI помилка' }, code: r.status === 504 ? 'err_ai_timeout' : 'err_ai_failed' });
    }
    withTools = true; step--;
  }
  res.status(502).json({ error: { message: 'AI помилка' }, code: 'err_ai_failed' });
});

async function sendCallPush(toNick, fromNick, hasVideo, offer) {
  const token = await getFcmToken(toNick); if (!token) return;
  const callId = `${fromNick}_${toNick}_${Date.now()}`;
  const offerRow = { fromNick, toNick, offer: typeof offer === 'string' ? offer : JSON.stringify(offer), hasVideo, expires: Date.now() + 60000 };
  pendingCallOffers.set(callId, offerRow);
  if (busReady()) { try { await busPub.set(`eion:offer:${callId}`, JSON.stringify(offerRow), 'EX', 90); } catch (e) { console.error('[cluster] offer:', e.message); } }
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

// Шлях зі СТАРОГО представлення: до рефів у БД лягали підписані та публічні
// URL. Підпис живе SIGNED_URL_TTL (7 діб) — тобто таке медіа мовчки протухало
// назавжди (Storage віддає 400), і його не можна було ні показати, ні зберегти.
// Дістаємо з нього bucket+path, щоб підписати заново.
function _parseStorageUrl(value) {
  if (typeof value !== 'string') return null;
  for (const marker of ['/object/sign/', '/object/public/']) {
    const i = value.indexOf(marker);
    if (i === -1) continue;
    let tail = value.slice(i + marker.length);
    const q = tail.indexOf('?');
    if (q !== -1) tail = tail.slice(0, q);
    const slash = tail.indexOf('/');
    if (slash <= 0) return null;
    const bucket = tail.slice(0, slash);
    let path = tail.slice(slash + 1);
    if (!STORAGE_BUCKETS_SET.has(bucket) || !path) return null;
    try { path = decodeURIComponent(path); } catch (_) { /* лишаємо як є */ }
    return { bucket, path };
  }
  return null;
}

// Підписує реф АБО перепідписує старий Storage-URL. Не наше (порожнє, чужий
// хост, звичайний текст) → повертає як є. Помилка підпису → теж як є.
async function signMediaRef(value) {
  const ref = _parseMediaRef(value) || _parseStorageUrl(value);
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

// ── Кластер: спільний стан між інстансами ─────────────────────────────────
// 🔴 Причина існування. `onlineUsers`, `nickDevices`, `pendingCallOffers`,
// `invisibleNicks` — це Map у памʼяті ОДНОГО процесу. Другий інстанс на Render
// не побачить сокетів першого: користувач A на інстансі 1 напише B на
// інстансі 2, і повідомлення ТИХО не дійде. Тобто масштабуватись горизонтально
// зараз неможливо в принципі, і виявилось би це вже в проді.
//
// ⚠️ ВИМКНЕНО, доки не задано `REDIS_URL`. Без нього кожна функція нижче —
// no-op, а поведінка бітово така сама, як була. Увімкнення = змінна в env.
//
// Ключове рішення: не переписувати 41 місце, що шле в сокет напряму, а
// зробити кластерним САМ `onlineUsers`. Для користувача з іншого інстансу
// кладемо запис-заглушку, чий `ws.send` публікує в шину замість сокета — і
// весь наявний код (`t.ws.send`, `readyState`, `close`) працює без змін.
// Дублювання при розсилках не виникає: запис на нік лише один, тож інстанс,
// де сокет живий, доставляє локально, а решта — через шину.
const REDIS_URL = process.env.REDIS_URL || '';
const INSTANCE_ID = crypto.randomBytes(6).toString('hex');
const CLUSTER_CH = 'eion:cluster';
const REMOTE_TTL_MS = 70000;      // запис-заглушка живий, поки надходить sync
let busPub = null, busSub = null;

const busReady = () => !!(busPub && busSub);

function busPublish(obj) {
  if (!busReady()) return false;
  try { busPub.publish(CLUSTER_CH, JSON.stringify({ ...obj, inst: INSTANCE_ID })); return true; }
  catch (e) { console.error('[cluster] publish:', e.message); return false; }
}

/// Запис про користувача, чий сокет тримає ІНШИЙ інстанс.
/// Реалізує рівно ту поверхню сокета, яку використовує код: send, close,
/// readyState, isAlive, deviceId (звірено grep-ом, а не на око).
function remoteEntry(nick, inst) {
  const relay = (extra) => busPublish({ t: 'relay', to: nick, dest: inst, ...extra });
  return {
    remote: true, inst, lastSeen: Date.now(),
    ws: {
      readyState: 1, isAlive: true, deviceId: null,
      send: (raw) => relay({ raw: typeof raw === 'string' ? raw : JSON.stringify(raw) }),
      close: () => relay({ close: true }),
      terminate: () => relay({ close: true }),
    },
  };
}

function onClusterMessage(msg) {
  if (!msg || msg.inst === INSTANCE_ID) return;   // власні повідомлення не обробляємо
  if (msg.t === 'up' || msg.t === 'sync') {
    for (const nick of (msg.t === 'up' ? [msg.nick] : (msg.nicks || []))) {
      const cur = onlineUsers.get(nick);
      // Живий ЛОКАЛЬНИЙ сокет завжди пріоритетніший за чужий запис.
      if (cur && !cur.remote) continue;
      if (cur && cur.remote) { cur.lastSeen = Date.now(); cur.inst = msg.inst; }
      else onlineUsers.set(nick, remoteEntry(nick, msg.inst));
    }
    return;
  }
  if (msg.t === 'down') {
    const cur = onlineUsers.get(msg.nick);
    if (cur && cur.remote && cur.inst === msg.inst) onlineUsers.delete(msg.nick);
    return;
  }
  if (msg.t === 'relay') {
    if (msg.dest !== INSTANCE_ID) return;
    const u = onlineUsers.get(msg.to);
    if (!u || u.remote || !u.ws || u.ws.readyState !== 1) return;
    try { if (msg.close) u.ws.close(); else u.ws.send(msg.raw); } catch (_) {}
    return;
  }
  if (msg.t === 'invis') {
    if (msg.on) invisibleNicks.add(msg.nick); else invisibleNicks.delete(msg.nick);
    return;
  }
  if (msg.t === 'dev') { nickDevices.set(msg.nick, msg.deviceId); }
}

function initCluster() {
  if (!REDIS_URL) { console.log('[cluster] вимкнено (немає REDIS_URL) — працюємо одним інстансом'); return; }
  let IORedis;
  try { IORedis = require('ioredis'); }
  catch (e) { console.error('[cluster] ioredis не встановлено:', e.message); return; }
  busPub = new IORedis(REDIS_URL, { maxRetriesPerRequest: null, lazyConnect: false });
  busSub = new IORedis(REDIS_URL, { maxRetriesPerRequest: null, lazyConnect: false });
  busPub.on('error', (e) => console.error('[cluster] pub:', e.message));
  busSub.on('error', (e) => console.error('[cluster] sub:', e.message));
  busSub.subscribe(CLUSTER_CH, (err) => {
    if (err) return console.error('[cluster] subscribe:', err.message);
    console.log(`[cluster] увімкнено, інстанс ${INSTANCE_ID}`);
  });
  busSub.on('message', (_ch, raw) => {
    try { onClusterMessage(JSON.parse(raw)); } catch (e) { console.error('[cluster] розбір:', e.message); }
  });
  // Періодична синхронізація: новий інстанс дізнається, хто вже онлайн, а
  // застарілі заглушки вимирають за REMOTE_TTL_MS без оновлення.
  setInterval(() => {
    const local = [];
    for (const [nick, u] of onlineUsers) if (!u.remote) local.push(nick);
    busPublish({ t: 'sync', nicks: local });
    const now = Date.now();
    for (const [nick, u] of onlineUsers) if (u.remote && now - u.lastSeen > REMOTE_TTL_MS) onlineUsers.delete(nick);
  }, 25000);
}
initCluster();

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
// Частка кожного платежу, що СПАЛЮЄТЬСЯ (токеноміка §5). Решта — у скарбницю.
// Платежі без контрагента палимо сильніше: там немає кому віддавати, і саме
// вони мали б інакше накопичуватись на службовому рахунку без межі.
// P2P (канали, контакт власника) майже не палимо — 90% і так іде автору.
const BURN_PCT = {
  premium: 50,
  pack: 40,
  ai: 40,             // покриває реальні витрати на Groq
  translate: 40,      // те саме джерело витрат, що й ai
  storage: 30,        // покриває Supabase Storage
  turn: 30,           // покриває релей дзвінків
  transfer_fee: 50,
  contact_fee: 50,
  paid_sub_fee: 50,
};

/// Облік потоку монет. Монета входить в обіг лише за замкнений у мості токен
/// (`deposited` — вніс користувач, `float_in` — влили з фондів проєкту) і
/// виходить виплатою (`released`) чи спалюванням (`burned`). Тримаємо це в БД,
/// а не в памʼяті: числа переживають рестарти й показуються публічно.
async function noteFlow(kind, amount) {
  if (!amount || amount <= 0) return;
  try {
    await supabase.rpc('note_coin_flow', { p_kind: kind, p_amount: amount });
  } catch (e) { console.error('[supply] noteFlow:', e.message); }
}

/// Видати монети зі СКАРБНИЦІ, а не створити нові.
///
/// 🔴 Це і є те, що робить скарбницю справжньою: роздачі (бонус новачка,
/// майбутні нагороди, компенсації) обмежені тим, що люди вже заплатили
/// комісіями плюс тим, що ми самі влили з фондів. Порожня скарбниця = роздавати
/// нічого, а не «намалювати ще». Повертає видану суму (0, якщо не вистачило).
async function grantFromTreasury(toNick, amount, kind, { earned = false, ref = null } = {}) {
  if (!amount || amount <= 0) return 0;
  const { data: left, error } = await supabase.rpc('spend_coins', { p_nick: COMPANY_NICK, p_amount: amount });
  if (error || left === -1 || left === null) {
    console.log(`[treasury] порожньо: ${kind} ${amount} для ${toNick} не видано`);
    return 0;
  }
  const rpc = earned ? 'add_coins_earned' : 'add_coins';
  const { error: addErr } = await supabase.rpc(rpc, { p_nick: toNick, p_amount: amount });
  if (addErr) {
    // Не дійшло до отримувача — повертаємо в скарбницю, інакше монети зникли б
    // з обігу без сліду в лічильнику спалювання.
    await supabase.rpc('add_coins', { p_nick: COMPANY_NICK, p_amount: amount });
    return 0;
  }
  await logTx({ fromNick: COMPANY_NICK, toNick, amount, kind, ref });
  return amount;
}

/// Дохід платформи: частина спалюється, решта йде на службовий рахунок.
///
/// Спалене НЕ потрапляє на жоден рахунок — воно просто зникає з обігу, а
/// лічильник у coin_supply дозволяє це показати публічно. Дохід від цього не
/// зникає: більша частина утиліті-платежів лишається в скарбниці.
async function creditCompany(amount, kind, { fromNick = null, ref = null } = {}) {
  if (!amount || amount <= 0 || fromNick === COMPANY_NICK) return;
  const burnPct = BURN_PCT[kind] || 0;
  const burn = Math.floor(amount * burnPct / 100);
  const keep = amount - burn;
  if (burn > 0) {
    try {
      await supabase.rpc('burn_coins', { p_amount: burn });
      await logTx({ fromNick, toNick: null, amount: burn, kind: `${kind}_burn`, ref });
    } catch (e) { console.log('[burn] error:', e.message); }
  }
  if (keep <= 0) return;
  // 🔴 «Зароблене», а не внутрішнє. Раніше тут був `add_coins`, і скарбниця
  // показувала «до виведення: 0» — тобто виглядала як гроші, які нікуди не
  // ведуть. З 03.09 кожна монета забезпечена замкненим у мості токеном, і ці
  // монети люди СПРАВДІ заплатили комісіями — отже вони виводяться, як і будь-яке
  // інше зароблене. Клас тут уже не про емісію (вона неможлива), а лише про
  // анти-Sybil: роздачі й далі йдуть внутрішніми.
  const { data: newTotal } = await supabase.rpc('add_coins_earned', { p_nick: COMPANY_NICK, p_amount: keep });
  if (newTotal != null) {
    sendToUser(COMPANY_NICK, { type: 'coins_received', fromNick: fromNick || 'system', amount: keep, total: newTotal });
  }
  await logTx({ fromNick, toNick: COMPANY_NICK, amount: keep, kind, ref });
}

// ── Денні квоти на дорогі операції ────────────────────────────────────────
// Безкоштовна норма, далі — за монети. Саме такі сінки створюють справжній
// попит: вони покривають витрати, які ми й так несемо.
// Одиниці різні: для AI — запит, для сховища — мегабайт, для дзвінків — виклик
// через релей. Норма щодня оновлюється; преміум має ширшу.
const FREE_QUOTA = {
  ai: 15,          ai_premium: 100,      // запитів на добу
  storage: 200,    storage_premium: 1000, // МБ вивантажень на добу
  turn: 10,        turn_premium: 50,      // дзвінків через релей на добу
  // Переклад — ОКРЕМА норма, і навмисно щедра. Він витрачається не рішенням
  // користувача, а самим фактом, що йому написали: одиниця на КОЖНЕ вхідне
  // повідомлення. На нормі AI (15) автопереклад помирав би за 15 повідомлень,
  // далі беручи по 3 монети за чужий текст. Витрати на нього мізерні (короткий
  // запит до найдешевшої моделі), тож обмеження тут — проти зловживання, а не
  // заради грошей.
  translate: 200,  translate_premium: 1000,
};
const SINK_PRICE = { ai: 3, storage: 1, turn: 2, translate: 1 }; // монет за одиницю понад норму

/// Скільки одиниць `kind` користувач витратив сьогодні.
// ⚠️ Помилки тут НЕ ковтати. Якщо лічильник не читається (немає таблиці, збій
// БД), `used` дорівнює нулю — і квота не вичерпується НІКОЛИ, тобто сінк тихо
// вимкнений. Саме так воно й поводилось при першому прогоні.
async function usageToday(nick, kind) {
  const day = new Date().toISOString().slice(0, 10);
  const { data, error } = await supabase.from('usage_counters')
    .select('used').eq('nick', nick).eq('kind', kind).eq('day', day).limit(1);
  if (error) { console.error('[sink] usageToday:', kind, error.message); return null; }
  return (data && data[0] ? data[0].used : 0);
}

/// Стан денних норм користувача: скільки витрачено, скільки лишилось і почому
/// одиниця понад норму. ОДНЕ джерело для екрана гаманця (`GET /usage/today`) і
/// для інструмента асистента `get_usage_today` — інакше вони розійшлись би,
/// і застосунок показував би одні числа, а асистент називав інші.
///
/// `used: null` означає «лічильник недоступний», а не нуль: при збої запиту
/// сінк пропускає операцію безкоштовно, і мовчазний нуль приховав би це.
const QUOTA_KINDS = ['ai', 'storage', 'turn', 'translate'];
async function quotaSnapshot(nick) {
  const { data: u } = await supabase.from('users').select('premium_expires_at').eq('nick', nick).single();
  const premium = !!(u && u.premium_expires_at && new Date(u.premium_expires_at) > new Date());
  const kinds = {};
  for (const kind of QUOTA_KINDS) {
    const limit = premium ? (FREE_QUOTA[`${kind}_premium`] || FREE_QUOTA[kind]) : FREE_QUOTA[kind];
    const used = await usageToday(nick, kind);
    // freeLimit/premiumLimit — щоб екран преміуму показував «зараз → стане» з
    // ЖИВИХ чисел. Інакше клієнт зашивав би ті самі норми вдруге, і при зміні
    // константи сторінка продажу почала б обіцяти не те, що видає сервер: цей
    // клас розбіжностей уже коштував нам сайту з ціною 50 замість 200.
    kinds[kind] = { used, limit, left: used === null ? null : Math.max(0, limit - used),
      price: SINK_PRICE[kind] || 0,
      freeLimit: FREE_QUOTA[kind],
      premiumLimit: FREE_QUOTA[`${kind}_premium`] || FREE_QUOTA[kind] };
  }
  return { premium, kinds, prices: PREMIUM_PRICES, walletFee: WALLET_OPEN_FEE };
}

/// Позначка «нік був онлайн». Пишемо не частіше разу на годину на нік: логін
/// трапляється при кожному реконекті (а на Render їх багато через code=1006),
/// і без цього фільтра метрика коштувала б запису в БД на кожен обрив звʼязку.
const lastSeenWrites = new Map();
const LAST_SEEN_MIN_INTERVAL = 60 * 60 * 1000;
function touchLastSeen(nick) {
  if (!nick) return;
  const prev = lastSeenWrites.get(nick) || 0;
  if (Date.now() - prev < LAST_SEEN_MIN_INTERVAL) return;
  lastSeenWrites.set(nick, Date.now());
  supabase.from('users').update({ last_seen: new Date().toISOString() }).eq('nick', nick)
    .then(({ error }) => { if (error) console.error('[metrics] last_seen:', error.message); });
}

async function bumpUsage(nick, kind, by = 1) {
  const day = new Date().toISOString().slice(0, 10);
  const used = (await usageToday(nick, kind)) || 0;
  const { error } = await supabase.from('usage_counters')
    .upsert({ nick, kind, day, used: used + by }, { onConflict: 'nick,kind,day' });
  if (error) console.error('[sink] bumpUsage:', kind, error.message);
  return used + by;
}

/// Дозволити дорогу операцію: у межах норми — безкоштовно, понад — за монети.
/// Повертає { ok, paid, error, code }.
async function chargeSink(nick, kind, units = 1) {
  if (!nick) return { ok: false, error: 'Не авторизовано', code: 'err_unauthorized' };
  units = Math.max(1, Math.ceil(units));
  const { data: user } = await supabase.from('users')
    .select('premium_expires_at').eq('nick', nick).single();
  const isPremium = user && user.premium_expires_at && new Date(user.premium_expires_at) > new Date();
  const free = isPremium ? (FREE_QUOTA[`${kind}_premium`] || FREE_QUOTA[kind]) : FREE_QUOTA[kind];
  const usedRaw = await usageToday(nick, kind);
  if (usedRaw === null) {
    // Лічильник недоступний: пропускаємо операцію (краще безкоштовно, ніж
    // зламаний застосунок), але гучно — інакше сінк мовчки не працює.
    console.error('[sink] лічильник недоступний, пропускаю без оплати:', kind, nick);
    return { ok: true, paid: 0, free: 0, degraded: true };
  }
  const used = usedRaw;

  // Частина одиниць може ще влізти в безкоштовну норму — платимо лише за решту.
  const freeUnits = Math.max(0, Math.min(units, free - used));
  const paidUnits = units - freeUnits;
  const price = (SINK_PRICE[kind] || 0) * paidUnits;

  if (price > 0) {
    const { data: balance } = await supabase.rpc('spend_coins', { p_nick: nick, p_amount: price });
    if (balance === -1) {
      return { ok: false, error: 'Денна норма вичерпана, монет не вистачає', code: 'err_quota_no_coins' };
    }
    await creditCompany(price, kind, { fromNick: nick, ref: kind });
    sendToUser(nick, { type: 'coins_update', amount: -price, total: balance });
  }
  await bumpUsage(nick, kind, units);
  return { ok: true, paid: price, free: Math.max(0, free - used - units), isPremium };
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

app.get('/call-offer', async (req, res) => {
  const { callId } = req.query; if (!callId) return res.json({ ok: false, error: 'callId обов\'язковий', code: 'err_param_call_id' });
  let data = pendingCallOffers.get(callId);
  // Дзвінок міг прийти на інший інстанс — беремо offer зі спільного сховища.
  if (!data && busReady()) {
    try { const raw = await busPub.get(`eion:offer:${callId}`); if (raw) data = JSON.parse(raw); }
    catch (e) { console.error('[cluster] offer get:', e.message); }
  }
  if (!data) return res.json({ ok: false, error: 'Offer не знайдено або застарів', code: 'err_offer_expired' });
  res.json({ ok: true, fromNick: data.fromNick, offer: data.offer, hasVideo: data.hasVideo });
});

app.post('/decline-call', async (req, res) => {
  const { toNick } = req.body; const fromNick = req.nick; if (!fromNick || !toNick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
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
  // 🔴 Немає жодного каналу доставки — це ПОМИЛКА, а не «ok, dev».
  // Доти ця гілка вдавала успіх, і разом із OTP_DEV_RETURN_CODE=true код
  // повертався прямо у відповіді. Обидва endpoint публічні, тож будь-хто міг
  // попросити код на ЧУЖИЙ номер, тут же його прочитати й підтвердити цей
  // номер на СВОЄМУ акаунті: у телефонній книзі друзі власника номера бачили б
  // чужий акаунт як його, а справжній власник більше не міг би прив'язати свій
  // номер («вже зареєстрований»). Тобто верифікація не просто не працювала —
  // вона працювала на користь того, хто цим скористається.
  if (!url) { console.error('[OTP] немає каналу доставки (TG_GATEWAY_TOKEN / SMS_GATEWAY_URL) — код не надіслано'); return { ok: false, unavailable: true }; }
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
  if (!nick || nick.trim().length < 2) return res.json({ ok: false, error: 'Нік занадто короткий (мін. 2 символи)', code: 'err_nick_too_short' });
  if (!nickLooksSafe(nick)) return res.json({ ok: false, error: 'Нік містить недопустимі символи', code: 'err_nick_bad_chars' });
  if (!password || password.length < 8) return res.json({ ok: false, error: 'Пароль занадто короткий (мін. 8 символів)', code: 'err_password_too_short' });
  if (email && !email.includes('@')) return res.json({ ok: false, error: 'Невірний email', code: 'err_invalid_email' });
  const { data: existing } = await supabase.from('users').select('nick').eq('nick_lower', nick.toLowerCase()).single();
  if (existing) return res.json({ ok: false, error: 'Нік вже зайнятий', code: 'err_nick_taken' });
  if (email) {
    const { data: emailExists } = await supabase.from('users').select('nick').eq('email', email).single();
    if (emailExists) return res.json({ ok: false, error: 'Цей email вже використовується', code: 'err_email_taken' });
  }
  // Перевіряємо унікальність телефону
  if (phoneNormalized) {
    const { data: phoneExists } = await supabase.from('users').select('nick').eq('phone_normalized', phoneNormalized).single();
    if (phoneExists) return res.json({ ok: false, error: 'Цей номер телефону вже зареєстрований в EION', code: 'err_phone_taken' });
  }
  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const userData = {
    nick, nick_lower: nick.toLowerCase(), password_hash: passwordHash,
    email, color: color || 4280391411, coins: 0,
    // Нік міг належати комусь раніше — відсікаємо його токени (див. destroySessionsForNick).
    tokens_valid_from: Date.now(),
    ...(phone ? { phone } : {}),
    ...(phoneNormalized ? { phone_normalized: phoneNormalized, phone_verified: verifiedPhones.has(phoneNormalized) } : {}),
  };
  if (REQUIRE_EMAIL_VERIFICATION) {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    pendingRegistrations.set(email, { ...userData, code, expires: Date.now() + 15 * 60 * 1000 });
    try { await sendEmail(email, 'EION — Підтвердження реєстрації', `Ваш код підтвердження: ${code}\n\nКод дійсний 15 хвилин.`); res.json({ ok: true, needVerification: true }); }
    catch (e) { res.json({ ok: false, error: 'Помилка відправки email: ' + e.message, code: 'err_email_send' }); }
  } else {
    const { error } = await supabase.from('users').insert(userData);
    if (error) return res.json({ ok: false, error: 'Помилка створення акаунта', code: 'err_account_create' });
    // Бонус — ЗІ СКАРБНИЦІ, а не з повітря. Внутрішніми (не «заробленими»):
    // інакше реєстрація ставала б краном токена, і фальшиві акаунти виводили б
    // по 200 за штуку. Порожня скарбниця → акаунт просто без бонусу.
    await grantFromTreasury(nick, NEW_USER_COINS, 'signup_bonus');
    // Одразу видаємо токен — після реєстрації користувач залогінений.
    const token = await createSession(nick, req.body.deviceId || null);
    res.json({ ok: true, needVerification: false, token, nick });
  }
});

app.post('/verify-email', async (req, res) => {
  const { email, code } = req.body;
  const pending = pendingRegistrations.get(email); if (!pending) return res.json({ ok: false, error: 'Реєстрацію не знайдено', code: 'err_registration_not_found' });
  if (Date.now() > pending.expires) return res.json({ ok: false, error: 'Код застарів', code: 'err_code_expired' });
  if (pending.code !== code) return res.json({ ok: false, error: 'Невірний код', code: 'err_code_invalid' });
  // Аудит #10: було pending.passwordHash (undefined) → акаунт без пароля.
  // Правильне поле — password_hash (з userData). Вставляємо повний набір полів.
  const { code: _c, expires: _e, ...userData } = pending;
  const { error } = await supabase.from('users').insert(userData);
  if (error) return res.json({ ok: false, error: 'Помилка створення акаунта', code: 'err_account_create' });
  await grantFromTreasury(pending.nick, NEW_USER_COINS, 'signup_bonus');
  pendingRegistrations.delete(email);
  const token = await createSession(pending.nick);
  res.json({ ok: true, token, nick: pending.nick });
});

app.post('/login', async (req, res) => {
  const { nick, password } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено', code: 'err_user_not_found' });
  if (pwLocked(user.nick)) return res.json(PW_LOCKED_BODY);
  const { data: ban } = await supabase.from('platform_bans').select('reason').eq('nick', user.nick).single();
  if (ban) return res.json({ ok: false, error: `Акаунт заблоковано: ${ban.reason || 'порушення правил'}` });
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    notePwFail(user.nick, 10);
    return res.json({ ok: false, error: 'Невірний пароль', code: 'err_wrong_password' });
  }
  pwFails.delete(user.nick);
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

// Код відновлення лежить у БД (email_codes), а не в пам'яті: Render присипляє
// інстанс після ~15 хв бездіяльності, тобто рівно в межах життя коду.
app.post('/forgot', async (req, res) => {
  const { email } = req.body;
  const { data: user } = await supabase.from('users').select('nick').eq('email', email).single();
  if (!user) return res.json({ ok: false, error: 'Email не знайдено', code: 'err_email_not_found' });
  // Cooldown 60 с на адресу (як у /phone/request-code): ліміт по IP обходиться
  // зміною IP, а за спам у чужу скриньку платить її власник — і наша квота Brevo.
  const { data: existing } = await supabase.from('email_codes').select('last_sent_at').eq('email', email).single();
  if (existing && existing.last_sent_at) {
    const elapsed = Date.now() - new Date(existing.last_sent_at).getTime();
    if (elapsed < 60000) return res.json({ ok: false, error: `Зачекайте ${Math.ceil((60000 - elapsed) / 1000)} с`, code: 'err_wait_before_retry' });
  }
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const { error } = await supabase.from('email_codes').upsert({
    email, code, nick: user.nick,
    expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
    attempts: 0, last_sent_at: new Date().toISOString(),
  });
  if (error) { console.error('[forgot] email_codes upsert:', error); return res.json({ ok: false, error: 'Помилка збереження коду', code: 'err_code_save' }); }
  try { await sendEmail(email, 'EION — Відновлення пароля', `Ваш код відновлення: ${code}\n\nКод дійсний 15 хвилин.`); res.json({ ok: true }); }
  catch (e) { console.log('[forgot] sendEmail:', e.message); res.json({ ok: false, error: 'Помилка відправки email', code: 'err_email_send' }); }
});

app.post('/reset', async (req, res) => {
  const { email, code, newPassword } = req.body;
  const { data: reset } = await supabase.from('email_codes').select('*').eq('email', email).single();
  if (!reset) return res.json({ ok: false, error: 'Код не знайдено', code: 'err_code_not_found' });
  if (new Date(reset.expires_at).getTime() < Date.now()) {
    await supabase.from('email_codes').delete().eq('email', email);
    return res.json({ ok: false, error: 'Код застарів', code: 'err_code_expired' });
  }
  // 5 спроб на код: захист від перебору, не зав'язаний на IP.
  if (reset.attempts >= 5) {
    await supabase.from('email_codes').delete().eq('email', email);
    return res.json({ ok: false, error: 'Забагато спроб. Запросіть новий код', code: 'err_code_attempts' });
  }
  if (reset.code !== String(code)) {
    await supabase.from('email_codes').update({ attempts: reset.attempts + 1 }).eq('email', email);
    return res.json({ ok: false, error: 'Невірний код', code: 'err_code_invalid' });
  }
  // Довжину перевіряємо ПІСЛЯ коду й ДО видалення — щоб закороткий пароль
  // не спалював уже підтверджений код (користувач просто вводить довший).
  if (!newPassword || newPassword.length < 8) return res.json({ ok: false, error: 'Пароль занадто короткий (мін. 8 символів)', code: 'err_password_too_short' });
  const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  await supabase.from('users').update({ password_hash: passwordHash }).eq('nick_lower', reset.nick.toLowerCase());
  // Сенс відновлення пароля — вигнати того, хто захопив акаунт: старі токени
  // мають померти. Тут це нікого не турбує — власник ще на екрані входу.
  await destroySessionsForNick(reset.nick);
  // Токен помер, але вже відкритий сокет живе далі — його треба розірвати окремо
  // (той самий патерн, що в /admin/ban). onlineUsers тримає один сокет на нік, а
  // власник зараз на екрані входу, тож тут ми виганяємо саме чужий пристрій.
  const kickWs = onlineUsers.get(reset.nick);
  if (kickWs) {
    try { kickWs.ws.send(JSON.stringify({ type: 'kicked', reason: 'Пароль змінено, увійдіть знову', code: 'err_kick_password_changed' })); kickWs.ws.close(); }
    catch (e) { console.log('[reset] kick:', e.message); }
  }
  await supabase.from('email_codes').delete().eq('email', email);
  res.json({ ok: true });
});

app.post('/update-nick', async (req, res) => {
  const { password, newNick } = req.body; const nick = req.nick;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено', code: 'err_user_not_found' });
  if (pwLocked(user.nick)) return res.json(PW_LOCKED_BODY);
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) { notePwFail(user.nick); return res.json({ ok: false, error: 'Невірний пароль', code: 'err_wrong_password' }); }
  pwFails.delete(user.nick);
  if (!newNick || newNick.trim().length < 2) return res.json({ ok: false, error: 'Нік занадто короткий', code: 'err_nick_too_short' });
  if (!nickLooksSafe(newNick)) return res.json({ ok: false, error: 'Нік містить недопустимі символи', code: 'err_nick_bad_chars' });
  const { data: exists } = await supabase.from('users').select('nick').eq('nick_lower', newNick.toLowerCase()).single();
  if (exists) return res.json({ ok: false, error: 'Нік вже зайнятий', code: 'err_nick_taken' });
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
  if (userWs) {
    onlineUsers.delete(oldNick); onlineUsers.set(newNick, userWs);
    busPublish({ t: 'down', nick: oldNick });
    if (!userWs.remote) busPublish({ t: 'up', nick: newNick });
  }
  for (const [n, u] of onlineUsers) if (n !== newNick) u.ws.send(JSON.stringify({ type: 'nick_changed', oldNick, newNick }));
  // Токен ніс старий нік — старі сесії гасимо, видаємо новий токен (клієнт зберігає).
  await destroySessionsForNick(oldNick);
  const newToken = await createSession(newNick, req.body.deviceId || null);
  res.json({ ok: true, newNick, token: newToken });
});

app.post('/update-password', async (req, res) => {
  const { password, newPassword } = req.body; const nick = req.nick;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено', code: 'err_user_not_found' });
  if (pwLocked(user.nick)) return res.json(PW_LOCKED_BODY);
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) { notePwFail(user.nick); return res.json({ ok: false, error: 'Невірний пароль', code: 'err_wrong_password' }); }
  pwFails.delete(user.nick);
  if (!newPassword || newPassword.length < 8) return res.json({ ok: false, error: 'Новий пароль занадто короткий (мін. 8 символів)', code: 'err_password_too_short' });
  const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  await supabase.from('users').update({ password_hash: passwordHash }).eq('nick_lower', nick.toLowerCase());
  // Гасимо всі сесії й одразу видаємо новий токен ЦЬОМУ пристрою: інші виходять,
  // той, з якого міняли пароль, лишається залогіненим (клієнт зберігає token).
  await destroySessionsForNick(nick);
  const token = await createSession(nick, req.body.deviceId || null);
  res.json({ ok: true, token });
});

app.post('/update-phone', async (req, res) => {
  const { password, phone, phoneNormalized } = req.body; const nick = req.nick;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено', code: 'err_user_not_found' });
  if (pwLocked(user.nick)) return res.json(PW_LOCKED_BODY);
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) { notePwFail(user.nick); return res.json({ ok: false, error: 'Невірний пароль', code: 'err_wrong_password' }); }
  pwFails.delete(user.nick);
  if (!phoneNormalized) return res.json({ ok: false, error: 'Невірний номер', code: 'err_invalid_phone' });
  // Унікальність номера (крім самого себе)
  const { data: phoneExists } = await supabase.from('users').select('nick').eq('phone_normalized', phoneNormalized).single();
  if (phoneExists && phoneExists.nick !== user.nick) return res.json({ ok: false, error: 'Цей номер телефону вже зареєстрований в EION', code: 'err_phone_taken' });
  const { error } = await supabase.from('users').update({ phone, phone_normalized: phoneNormalized, phone_verified: verifiedPhones.has(phoneNormalized) }).eq('nick_lower', nick.toLowerCase());
  if (error) return res.json({ ok: false, error: 'Помилка оновлення номера', code: 'err_phone_update_failed' });
  res.json({ ok: true });
});

// ── Підтвердження номера власним OTP (без Firebase) ──
app.post('/phone/request-code', async (req, res) => {
  const { phone, phoneNormalized } = req.body;
  if (!phoneNormalized || !phone) return res.json({ ok: false, error: 'Невірний номер', code: 'err_invalid_phone' });
  // rate-limit: не частіше ніж раз на 60 с
  const { data: existing } = await supabase.from('phone_codes').select('last_sent_at').eq('phone', phoneNormalized).single();
  if (existing && existing.last_sent_at) {
    const elapsed = Date.now() - new Date(existing.last_sent_at).getTime();
    if (elapsed < 60000) return res.json({ ok: false, error: `Зачекайте ${Math.ceil((60000 - elapsed) / 1000)} с`, code: 'err_wait_before_retry' });
  }
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const { error } = await supabase.from('phone_codes').upsert({
    phone: phoneNormalized, code,
    expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    attempts: 0, last_sent_at: new Date().toISOString(),
  });
  if (error) { console.error('[OTP] phone_codes upsert:', error); return res.json({ ok: false, error: 'Помилка збереження коду', code: 'err_code_save' }); }
  const sent = await sendOtp(phone, code, `EION код підтвердження: ${code}`);
  if (!sent.ok) {
    // Код у відповідь НЕ повертаємо за жодних умов і жодним прапорцем env:
    // endpoint публічний, тож це дорівнювало б «підтвердь будь-який номер».
    // Для локальної перевірки код видно в таблиці phone_codes.
    await supabase.from('phone_codes').delete().eq('phone', phoneNormalized);
    return sent.unavailable
      ? res.json({ ok: false, error: 'Підтвердження номера тимчасово недоступне', code: 'err_otp_unavailable' })
      : res.json({ ok: false, error: 'Не вдалося надіслати код', code: 'err_code_send' });
  }
  res.json({ ok: true });
});

app.post('/phone/verify-code', async (req, res) => {
  // `nick` із тіла свідомо НЕ читаємо: прив'язка йде лише за сесією (див. нижче).
  const { phone, phoneNormalized, code } = req.body;
  if (!phoneNormalized || !code) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: row } = await supabase.from('phone_codes').select('*').eq('phone', phoneNormalized).single();
  if (!row) return res.json({ ok: false, error: 'Код не знайдено. Запросіть новий', code: 'err_code_not_found' });
  if (new Date(row.expires_at).getTime() < Date.now()) {
    await supabase.from('phone_codes').delete().eq('phone', phoneNormalized);
    return res.json({ ok: false, error: 'Код протерміновано. Запросіть новий', code: 'err_code_expired' });
  }
  if (row.attempts >= 5) {
    await supabase.from('phone_codes').delete().eq('phone', phoneNormalized);
    return res.json({ ok: false, error: 'Забагато спроб. Запросіть новий код', code: 'err_code_attempts' });
  }
  if (row.code !== String(code)) {
    await supabase.from('phone_codes').update({ attempts: row.attempts + 1 }).eq('phone', phoneNormalized);
    return res.json({ ok: false, error: 'Невірний код', code: 'err_code_invalid' });
  }
  await supabase.from('phone_codes').delete().eq('phone', phoneNormalized); // успіх — код видаляємо
  // Нік беремо з СЕСІЇ, коли запит автентифікований: інакше номер, підтверджений
  // однією людиною, можна було б прив'язати до чужого акаунта. Без сесії
  // лишається тільки реєстраційний шлях (verifiedPhones нижче) — саме заради
  // нього endpoint і публічний.
  const auth = req.headers['authorization'] || '';
  const bindNick = auth.startsWith('Bearer ') ? resolveSession(auth.slice(7)) : null;
  if (bindNick) {
    const nick = bindNick;
    const { data: user } = await supabase.from('users').select('nick').eq('nick_lower', nick.toLowerCase()).single();
    if (user) {
      const { data: phoneExists } = await supabase.from('users').select('nick').eq('phone_normalized', phoneNormalized).single();
      if (phoneExists && phoneExists.nick !== user.nick) return res.json({ ok: false, error: 'Цей номер вже зареєстрований в EION', code: 'err_phone_taken' });
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
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено', code: 'err_user_not_found' });
  if (pwLocked(user.nick)) return res.json(PW_LOCKED_BODY);
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) { notePwFail(user.nick); return res.json({ ok: false, error: 'Невірний пароль', code: 'err_wrong_password' }); }
  pwFails.delete(user.nick);
  if (!newEmail || !newEmail.includes('@')) return res.json({ ok: false, error: 'Невірний email', code: 'err_invalid_email' });
  const { data: emailExists } = await supabase.from('users').select('nick').eq('email', newEmail).single();
  if (emailExists) return res.json({ ok: false, error: 'Email вже використовується', code: 'err_email_taken' });
  await supabase.from('users').update({ email: newEmail }).eq('nick_lower', nick.toLowerCase());
  res.json({ ok: true });
});

// Видача ICE-серверів клієнту. Креди TURN живуть у env сервера, а не в APK —
// інакше їх витягують із застосунку й крадуть relay-трафік. STUN — публічний,
// віддаємо завжди; TURN — лише якщо налаштовані змінні оточення.
app.get('/turn-credentials', async (req, res) => {
  // Релей — платний трафік, тож понад норму дзвінків на добу беремо монети.
  // STUN лишається безкоштовним завжди: він майже нічого не коштує і без нього
  // не працюватиме навіть прямий звʼязок.
  const charge = await chargeSink(req.nick, 'turn');
  const relayAllowed = charge.ok;
  const iceServers = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
  ];
  const user = process.env.TURN_USERNAME;
  const cred = process.env.TURN_CREDENTIAL;
  const host = process.env.TURN_HOST || 'global.relay.metered.ca';
  if (user && cred && relayAllowed) {
    iceServers.push(
      { urls: `stun:${host}:80` },
      { urls: `turn:${host}:80`, username: user, credential: cred },
      { urls: `turn:${host}:80?transport=tcp`, username: user, credential: cred },
      { urls: `turn:${host}:443`, username: user, credential: cred },
      { urls: `turns:${host}:443?transport=tcp`, username: user, credential: cred },
    );
  }
  res.json({
    ok: true, iceServers, ttl: 3600,
    relay: relayAllowed,
    ...(relayAllowed ? {} : { relayError: charge.error, relayCode: charge.code }),
  });
});


// ── Повне видалення акаунта (GDPR ст. 17) ───────────────────────────────────
// Раніше `/delete-account` прибирав рівно дві речі — `messages` і рядок
// `users` — тоді як політика обіцяла видалення профілю, повідомлень, файлів і
// сесій. Усе інше, привʼязане до ніка (підписки, членства, реакції, лічильники
// норм, коди, заявки на виплату), лишалось у базі назавжди.
//
// Три класи даних, і поводимось з ними по-різному:
//
//  • ВИДАЛЯЄМО — те, що бачить лише сам користувач або що без нього не має
//    сенсу: членства, підписки, реакції, позначки прочитання, лічильники,
//    коди, запрошення, чернетки блокувань.
//  • ЗНЕОСОБЛЮЄМО (нік → null) — те, що потрібне НЕ як дані людини, а як
//    облік: журнал монет (інакше «попливе» баланс емісії) і `token_deposits`
//    (його первинний ключ — підпис транзакції, і саме він не дає зарахувати
//    той самий депозит удруге; видалення рядка відкрило б повторне зарахування).
//    Плюс `reports.reporter_nick`: сама скарга лишається робочою для модерації.
//  • ЛИШАЄМО — повідомлення в групах, пости й коментарі каналів: їх бачать
//    інші учасники, і саме це написано в політиці. І `platform_bans` — інакше
//    видалення акаунта стало б способом зняти блокування.
//
// ⚠️ Канал чи група, які створив видалений акаунт, лишаються без власника.
// Це свідомо: сам вміст належить учасникам, а вигадувати спадкоємця гірше, ніж
// лишити його як є.
//
// Колонки з ніком, які лишаються НАВМИСНО (звірено зі схемою — інших немає):
//   channel_comments.from_nick, .reply_to_nick · channel_messages.from_nick ·
//   group_messages.from_nick   — вміст, який бачать інші;
//   channels.owner_nick · groups.creator_nick — те саме, див. вище;
//   platform_bans.nick         — інакше видалення знімало б бан;
//   reports.target_nick        — скарга описує вміст, який лишився.

/// Шлях у бакеті `avatars` з публічного або підписаного URL.
function avatarPathFromUrl(url) {
  if (!url || typeof url !== 'string') return null;
  let tail = null;
  if (url.startsWith('eion://avatars/')) tail = url.slice('eion://avatars/'.length);
  else for (const marker of ['/object/sign/avatars/', '/object/public/avatars/']) {
    const i = url.indexOf(marker);
    if (i !== -1) { tail = url.slice(i + marker.length); break; }
  }
  if (tail === null) return null;
  const q = tail.indexOf('?');
  if (q !== -1) tail = tail.slice(0, q);
  try { return decodeURIComponent(tail); } catch (_) { return tail; }
}

/// Прибрати все, що привʼязане до ніка. Повертає звіт для логу.
/// Помилка в одній таблиці не зупиняє решту: недоприбране краще за
/// напівживий акаунт, у якого зник профіль, але лишились членства.
async function purgeAccountData(nick, user) {
  const report = { deleted: {}, anonymized: {}, files: 0, errors: [] };

  // 🔴 Залишок балансу — У СКАРБНИЦЮ, а не в нікуди. З 03.09 кожна монета
  // забезпечена замкненим у мості токеном: якщо видалити рядок користувача
  // разом із монетами, токени лишились би в мості без жодного власника, а
  // обіг і скарбниця розійшлися б із дійсністю. Тому баланс повертається
  // туди, звідки колись вийшов.
  const leftover = Math.max(0, Number(user?.coins) || 0);
  if (leftover > 0 && nick !== COMPANY_NICK) {
    const { error } = await supabase.rpc('add_coins_earned', { p_nick: COMPANY_NICK, p_amount: leftover });
    if (error) report.errors.push(`treasury_return: ${error.message}`);
    else {
      await logTx({ fromNick: nick, toNick: COMPANY_NICK, amount: leftover, kind: 'account_closed' });
      report.returnedToTreasury = leftover;
    }
  }

  const del = async (table, col, value) => {
    const { error, count } = await supabase.from(table).delete({ count: 'exact' }).eq(col, value);
    if (error) { report.errors.push(`${table}.${col}: ${error.message}`); return; }
    report.deleted[table] = (report.deleted[table] || 0) + (count || 0);
  };
  const anon = async (table, col) => {
    const { error, count } = await supabase.from(table).update({ [col]: null }, { count: 'exact' }).eq(col, nick);
    if (error) { report.errors.push(`${table}.${col}(anon): ${error.message}`); return; }
    report.anonymized[`${table}.${col}`] = count || 0;
  };

  // 1. Файли з особистих переписок — ЗБИРАЄМО ДО видалення рядків, інакше
  //    посилання зникне разом із повідомленням і об'єкт лишиться сиротою
  //    назавжди: періодична чистка ходить по повідомленнях, яких уже не буде.
  const fileData = new Set();
  const msgIds = new Set();
  for (const col of ['from_nick', 'to_nick']) {
    const { data } = await supabase.from('messages').select('id, file_data').eq(col, nick);
    for (const r of (data || [])) { msgIds.add(r.id); if (r.file_data) fileData.add(r.file_data); }
  }

  // 2. Особисті переписки. Два окремі .eq замість рядкового or= — див.
  //    NICK_FORBIDDEN: нік із комою робив із цього «видалити все».
  await del('messages', 'from_nick', nick);
  await del('messages', 'to_nick', nick);

  // 3. Решта рядків, привʼязаних до ніка.
  const byNick = [
    'channel_blocked', 'channel_comment_reactions', 'channel_members', 'channel_paid_subs',
    'channel_post_views', 'channel_reactions', 'chat_reads', 'email_codes', 'group_bans',
    'group_history_cleared', 'group_join_requests', 'group_members', 'group_message_reactions',
    'token_payouts', 'usage_counters', 'user_sticker_packs',
  ];
  for (const t of byNick) await del(t, 'nick', nick);

  for (const [t, cols] of [
    ['block_allowlist', ['owner_nick', 'allowed_nick']],
    ['blocked_contacts', ['blocker_nick', 'blocked_nick']],
    ['call_logs', ['from_nick', 'to_nick']],
    ['deleted_messages', ['from_nick', 'to_nick']],
    ['direct_message_reactions', ['from_nick']],
    ['pending_channel_invites', ['inviter_nick', 'target_nick']],
    ['pending_group_invites', ['inviter_nick', 'target_nick']],
    ['pending_reactions', ['from_nick', 'to_nick', 'chat_nick']],
  ]) for (const c of cols) await del(t, c, nick);

  // Коди телефону лежать під самим номером; у користувача він у двох формах.
  for (const ph of [user && user.phone_normalized, user && user.phone]) {
    if (ph) await del('phone_codes', 'phone', ph);
  }

  // 4. Знеособлення — там, де рядок потрібен без людини.
  await anon('coin_transactions', 'from_nick');
  await anon('coin_transactions', 'to_nick');
  await anon('token_deposits', 'nick');
  await anon('reports', 'reporter_nick');

  // 5. Файли. Прибираємо лише те, на що більше ніхто не посилається: та сама
  //    перевірка, що захищає переслані копії від чистки за TTL. 2C тут НЕ
  //    чекаємо — людина попросила стерти свої дані, а не «коли всі заберуть».
  for (const fd of fileData) {
    const path = storagePathFromUrl(fd);
    if (!path) continue;
    if (await fileStillReferenced(fd, msgIds, new Set())) continue;
    try {
      await supabase.storage.from('files').remove([path]);
      await supabase.from('file_objects').delete().eq('storage_path', path);
      report.files++;
    } catch (e) { report.errors.push(`storage ${path}: ${e.message}`); }
  }
  const avatarPath = avatarPathFromUrl(user && user.avatar_url);
  if (avatarPath) {
    try { await supabase.storage.from('avatars').remove([avatarPath]); report.files++; }
    catch (e) { report.errors.push(`avatar ${avatarPath}: ${e.message}`); }
  }
  return report;
}

app.post('/delete-account', async (req, res) => {
  const { password } = req.body; const nick = req.nick;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено', code: 'err_user_not_found' });
  if (pwLocked(user.nick)) return res.json(PW_LOCKED_BODY);
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) { notePwFail(user.nick); return res.json({ ok: false, error: 'Невірний пароль', code: 'err_wrong_password' }); }
  pwFails.delete(user.nick);
  // Спершу все привʼязане до ніка, і лише потім сам рядок users: якщо на
  // півдорозі щось упаде, акаунт іще існує і видалення можна повторити.
  const purge = await purgeAccountData(user.nick, user);
  console.log('[delete-account]', user.nick, JSON.stringify(purge));
  await supabase.from('users').delete().eq('nick_lower', nick.toLowerCase());
  onlineUsers.delete(nick); busPublish({ t: 'down', nick }); await clearFcmToken(nick);
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

// Виведена частина балансу окремим запитом: доки міграція `coin_classes_wallet`
// не виконана, колонок ще немає — і тоді профіль має працювати як раніше, а не
// падати цілком через одне додаткове поле.
async function earnedInfo(nick, coins) {
  const { data, error } = await supabase.from('users')
    .select('coins_earned, wallet_opened').eq('nick', nick).single();
  if (error || !data) return {};
  return {
    coins_earned: Math.min(data.coins_earned || 0, coins),
    wallet_opened: data.wallet_opened === true,
  };
}

app.get('/user-info', async (req, res) => {
  const { nick } = req.query; if (!nick) return res.json({ ok: false, error: 'Нік обов\'язковий', code: 'err_param_nick' });
  const { data: user } = await supabase.from('users').select('nick, coins, avatar_url, premium_expires_at, premium_plan, nick_color, color, block_incoming, invisible, solana_address').eq('nick', nick).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено', code: 'err_user_not_found' });
  const ei = await earnedInfo(nick, user.coins || 0);
  // Ціна відкриття — 0, якщо гаманець уже відкривали або є преміум: клієнт
  // показує цю примітку ДО створення, і обіцяти плату, якої не буде, не можна.
  const premiumNow = !!(user.premium_expires_at && new Date(user.premium_expires_at).getTime() > Date.now());
  res.json({ ok: true, nick: user.nick, coins: user.coins || 0, avatar_url: user.avatar_url || null, premium_expires_at: user.premium_expires_at || null, premium_plan: user.premium_plan || null, nick_color: user.nick_color || null, color: user.color || null, block_incoming: user.block_incoming === true, invisible: user.invisible === true, solana_address: user.solana_address || null,
    // Скільки з балансу дозволено виводити в токен і чи вже сплачено відкриття
    // гаманця — клієнт має показувати це чесно, а не обіцяти вивід усього.
    ...ei, wallet_open_fee: (ei.wallet_opened || premiumNow) ? 0 : WALLET_OPEN_FEE });
});

// ── Гаманець Solana: тільки АДРЕСА, без ключів ───────────────────────────
// Ми не зберігаємо приватних ключів і не підписуємо транзакцій: людина каже,
// КУДИ надсилати токени, підписує її власний гаманець. Зберігання чужих активів
// зробило б сервіс постачальником послуг з віртуальними активами (Україна —
// закон про віртуальні активи, ЄС — MiCA) і поклало б на нас відповідальність
// за кожен злам.
const SOLANA_RPC = process.env.SOLANA_RPC || 'https://api.devnet.solana.com';
const SOLANA_TOKEN_MINT = process.env.SOLANA_TOKEN_MINT || '';
const SOLANA_CLUSTER = process.env.SOLANA_CLUSTER || 'devnet';

// Base58 без залежностей: перевіряємо, що адреса декодується рівно в 32 байти.
// Самої регулярки мало — під неї підходять і рядки, які не є ключем.
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Len(str) {
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(str)) return -1;
  // Масив починається ПОРОЖНІМ: із початковим [0] адреса з самих одиниць
  // (наприклад system program) давала б на байт більше і не проходила перевірку.
  const bytes = [];
  for (const ch of str) {
    let carry = B58.indexOf(ch);
    if (carry < 0) return -1;
    for (let i = 0; i < bytes.length; i++) { carry += bytes[i] * 58; bytes[i] = carry & 0xff; carry >>= 8; }
    while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  // Провідні '1' у base58 — це нульові байти, у циклі вище вони не зʼявляються.
  for (const ch of str) { if (ch !== '1') break; bytes.push(0); }
  return bytes.length;
}

app.post('/profile/solana-address', async (req, res) => {
  const address = typeof req.body.address === 'string' ? req.body.address.trim() : '';
  // Порожній рядок = відвʼязати гаманець. Це має бути можливо завжди.
  if (address && base58Len(address) !== 32) {
    return res.json({ ok: false, error: 'Невірна адреса Solana', code: 'err_invalid_solana_address' });
  }
  // Службову адресу прив'язати не можна: інакше наші ж перекази між фондами
  // виглядали б як поповнення цього акаунта (так уже сталося з EION).
  const payoutAddr = payoutReady() ? getPayoutKeypair().publicKey.toBase58() : null;
  if (address && (SOLANA_INTERNAL.has(address) || address === payoutAddr)) {
    return res.json({ ok: false, error: 'Ця адреса службова', code: 'err_solana_internal_address' });
  }
  // Пароль акаунта потрібен лише коли адреса ЗМІНЮЄТЬСЯ на іншу — саме підміна
  // вже привʼязаної адреси небезпечна: власник робить виплату своїм паролем, а
  // токени йдуть злодію. ПЕРША привʼязка (поле порожнє) пароля не вимагає:
  // вивести монети вкрадена сесія однаково не зможе — /token/payout просить
  // пароль сама, — а змушувати вводити другий пароль поспіль одразу після
  // пароля гаманця лише плутає.
  const { data: cur } = await supabase.from('users')
    .select('solana_address').eq('nick', req.nick).single();
  const prevAddr = (cur && cur.solana_address ? String(cur.solana_address).trim() : '');
  if (address && prevAddr && prevAddr !== address) {
    const pwErr = await requireAccountPassword(req);
    if (pwErr) return res.json(pwErr);
  }
  // Стеля прив'язок на добу: створення й відновлення гаманця — рідкісні дії,
  // а скрипт міг би ганяти їх нескінченно, щоразу списуючи ренту з нашого
  // гаманця через нові токен-рахунки.
  const bindsToday = await usageToday(req.nick, 'wallet_bind');
  if (bindsToday !== null && bindsToday >= WALLET_BIND_DAILY) {
    return res.json({ ok: false, error: 'Забагато спроб за добу', code: 'err_wallet_bind_limit' });
  }

  // Одна адреса — один акаунт. Інакше надходження з неї не зарахувалось би
  // НІКОМУ: запит `.eq('solana_address', …).single()` на двох рядках падає, і
  // депозит тихо ставав би «нерозпізнаним». Плюс це відкривало б плутанину,
  // коли двоє вказують чужий гаманець.
  if (address) {
    const { data: taken } = await supabase.from('users')
      .select('nick').eq('solana_address', address).neq('nick', req.nick).limit(1);
    if (taken && taken.length) {
      return res.json({ ok: false, error: 'Ця адреса вже прив\'язана до іншого акаунта', code: 'err_solana_address_taken' });
    }
  }
  // Плата за ВІДКРИТТЯ гаманця. Береться саме тут, бо реальна витрата в нас
  // одна: рента токен-рахунку (~0,002 SOL) — її платить наш гаманець, коли на
  // адресу вперше щось приходить. Створення ключа не коштує нічого, тож
  // порожній гаманець лишається безкоштовним, а плата бере рівно те, що
  // коштує грошей. Преміум звільняється: це перевага, а не бар'єр.
  let charged = 0;
  if (address) {
    const { data: me, error: meErr } = await supabase.from('users')
      .select('wallet_opened, coins, premium_expires_at').eq('nick', req.nick).single();
    // Помилка тут = колонки ще немає (міграція не виконана). Тоді просто не
    // беремо плату: краще недоотримати монети, ніж не дати прив'язати гаманець.
    if (!meErr && me && !me.wallet_opened) {
      const premium = me.premium_expires_at && new Date(me.premium_expires_at) > new Date();
      if (!premium && WALLET_OPEN_FEE > 0) {
        const { data: left } = await supabase.rpc('spend_coins', { p_nick: req.nick, p_amount: WALLET_OPEN_FEE });
        if (left === -1 || left === null) {
          return res.json({ ok: false, error: 'Недостатньо монет', code: 'err_not_enough_coins' });
        }
        charged = WALLET_OPEN_FEE;
        creditCompany(WALLET_OPEN_FEE, 'wallet_open', { fromNick: req.nick });
      }
      await supabase.from('users').update({ wallet_opened: true }).eq('nick', req.nick);
    }
  }

  const { error } = await supabase.from('users')
    .update({ solana_address: address || null }).eq('nick', req.nick);
  if (error) return res.json({ ok: false, error: 'Не вдалося зберегти', code: 'err_save_failed' });
  await bumpUsage(req.nick, 'wallet_bind');
  res.json({ ok: true, address: address || null, charged });
});

// Баланс токена читаємо НА СЕРВЕРІ: так адресу RPC (і платний ключ, якщо він
// зʼявиться) можна змінити без нової збірки застосунку, а мережа й mint не
// зашиті в клієнті — при переході devnet → mainnet міняється лише env.
app.get('/token/balance', async (req, res) => {
  if (!SOLANA_TOKEN_MINT) return res.json({ ok: false, error: 'Токен ще не випущено', code: 'err_token_disabled' });
  const { data: user } = await supabase.from('users').select('solana_address').eq('nick', req.nick).single();
  const owner = user && user.solana_address;
  if (!owner) return res.json({ ok: true, address: null, amount: null, cluster: SOLANA_CLUSTER });
  const r = await httpPostJson(SOLANA_RPC, {}, {
    jsonrpc: '2.0', id: 1, method: 'getTokenAccountsByOwner',
    params: [owner, { mint: SOLANA_TOKEN_MINT }, { encoding: 'jsonParsed' }],
  });
  try {
    const body = JSON.parse(r.body || '{}');
    if (body.error) throw new Error(body.error.message || 'RPC error');
    // Токен-акаунтів на один mint може бути кілька — сумуємо, інакше показали б
    // менше, ніж людина насправді має.
    let total = 0;
    for (const acc of body.result?.value || []) {
      const ui = acc.account?.data?.parsed?.info?.tokenAmount?.uiAmount;
      if (typeof ui === 'number') total += ui;
    }
    res.json({ ok: true, address: owner, amount: total, mint: SOLANA_TOKEN_MINT, cluster: SOLANA_CLUSTER });
  } catch (e) {
    console.error('[solana] balance:', e.message);
    res.json({ ok: false, error: 'Не вдалося прочитати баланс', code: 'err_token_balance' });
  }
});

// ── Виплата токена за внутрішні бали ─────────────────────────────────────
// Найтонше місце всієї теми: між списанням балів і підтвердженням транзакції
// є проміжок, у якому процес може впасти. Тому порядок саме такий:
//   1) атомарно списуємо бали (spend_coins) — інакше два паралельні запити
//      витратили б один баланс двічі;
//   2) створюємо заявку pending ДО відправки — щоб слід лишився навіть якщо
//      далі все обірветься;
//   3) відправляємо, зберігаємо підпис, підтверджуємо;
//   4) не вдалося — повертаємо бали й пишемо чому.
// Незавершені заявки доперевіряються в мережі за підписом (`resumePendingPayouts`),
// а не переграються наосліп: підтверджену транзакцію повторити означало б
// надіслати вдруге.
const TOKEN_PAYOUT_RATE = Number(process.env.TOKEN_PAYOUT_RATE || 1);   // токенів за 1 бал
const TOKEN_PAYOUT_MIN = Number(process.env.TOKEN_PAYOUT_MIN || 100);   // мінімум балів за раз
const TOKEN_PAYOUT_DAILY = Number(process.env.TOKEN_PAYOUT_DAILY || 1000); // стеля балів на добу
const SOLANA_PAYOUT_SECRET = process.env.SOLANA_PAYOUT_SECRET || '';
// 🔴 Наші власні гаманці (фонди, payer) НІКОЛИ не зараховуються як депозит.
// Причина з практики: адреса фонду винагород опинилась прив'язаною до акаунта
// EION (її вставили, щоб подивитись баланс), і службовий переказ 5 млн токенів
// на гаманець обміну перетворився на 5 млн нарахованих балів. Службовий рух
// коштів між нашими ж гаманцями не є чиїмось поповненням за визначенням.
const SOLANA_INTERNAL = new Set(
  (process.env.SOLANA_INTERNAL_ADDRESSES || '').split(',').map(x => x.trim()).filter(Boolean)
);
// Стеля на одне надходження: захист від абсурдних сум, які означають помилку
// (службовий переказ, тест, чужий скрипт), а не справжнє поповнення.
const TOKEN_DEPOSIT_MAX = Number(process.env.TOKEN_DEPOSIT_MAX || 100000);

let payoutKeypair = null;
function getPayoutKeypair() {
  if (payoutKeypair || !SOLANA_PAYOUT_SECRET) return payoutKeypair;
  try {
    const { Keypair } = require('@solana/web3.js');
    const bs58 = require('bs58');
    const dec = (bs58.default || bs58).decode(SOLANA_PAYOUT_SECRET.trim());
    payoutKeypair = Keypair.fromSecretKey(Uint8Array.from(dec));
  } catch (e) {
    console.error('[payout] SOLANA_PAYOUT_SECRET не розібрано:', e.message);
  }
  return payoutKeypair;
}
const payoutReady = () => !!(SOLANA_TOKEN_MINT && getPayoutKeypair());

// Скільки балів людина вже вивела за добу. Рахуємо ВСІ заявки, крім повернених:
// невдала спроба теж витратила ліміт, інакше нею можна було б довбати мережу.
async function payoutUsedToday(nick) {
  const since = new Date(Date.now() - 86400000).toISOString();
  const { data, error } = await supabase.from('token_payouts')
    .select('coins, status').eq('nick', nick).gte('created_at', since);
  if (error) { console.error('[payout] usedToday:', error.message); return null; }
  return (data || []).filter(r => r.status !== 'refunded').reduce((a, r) => a + (r.coins || 0), 0);
}

// Транзакція будується вручну (а не через готовий `transfer`) заради ОДНОГО:
// підпис має бути відомий ДО відправки. `transfer` повертає його вже після
// підтвердження, тож обрив посеред очікування лишив би нас без підпису при
// можливо надісланих токенах — і повторна спроба надіслала б удруге.
//
// `createAssociatedTokenAccountIdempotent` замість звичайного створення: у
// отримувача акаунт може вже бути (або зʼявитись між нашою перевіркою та
// відправкою), і звичайна інструкція в такому разі валить усю транзакцію.
async function buildPayoutTx(toAddress, tokensAmount) {
  const { Connection, PublicKey, Transaction } = require('@solana/web3.js');
  const {
    getMint, getAssociatedTokenAddress, createTransferInstruction,
    createAssociatedTokenAccountIdempotentInstruction,
  } = require('@solana/spl-token');
  const bs58 = require('bs58');
  const c = new Connection(SOLANA_RPC, 'confirmed');
  const kp = getPayoutKeypair();
  const mint = new PublicKey(SOLANA_TOKEN_MINT);
  const owner = new PublicKey(toAddress);
  const info = await getMint(c, mint);
  const raw = BigInt(Math.round(tokensAmount)) * (10n ** BigInt(info.decimals));

  const from = await getAssociatedTokenAddress(mint, kp.publicKey);
  const to = await getAssociatedTokenAddress(mint, owner);
  const { blockhash, lastValidBlockHeight } = await c.getLatestBlockhash('confirmed');
  const tx = new Transaction({ feePayer: kp.publicKey, blockhash, lastValidBlockHeight })
    // Ренту за новий акаунт отримувача (~0.002 SOL) платить гаманець виплат.
    .add(createAssociatedTokenAccountIdempotentInstruction(kp.publicKey, to, owner, mint))
    .add(createTransferInstruction(from, to, kp.publicKey, raw));
  tx.sign(kp);
  const signature = (bs58.default || bs58).encode(tx.signature);
  return { c, tx, signature, lastValidBlockHeight };
}

// Стан транзакції в мережі: єдине джерело правди про те, чи пішли токени.
async function payoutTxStatus(signature) {
  const { Connection } = require('@solana/web3.js');
  const c = new Connection(SOLANA_RPC, 'confirmed');
  const st = await c.getSignatureStatus(signature, { searchTransactionHistory: true });
  const v = st && st.value;
  if (!v) return 'unknown';                       // не знайдено: або ще летить, або не існувала
  if (v.err) return 'failed';
  return 'sent';
}

// Дорозбір заявок, що лишились у pending після падіння процесу. Ключове: ми
// НЕ переграємо їх наосліп — питаємо мережу за підписом. Підтверджену
// транзакцію повторити означало б надіслати вдруге.
async function resumePendingPayouts() {
  if (!payoutReady()) return;
  const cutoff = new Date(Date.now() - 2 * 60 * 1000).toISOString();
  const { data, error } = await supabase.from('token_payouts')
    .select('id, nick, coins, signature').eq('status', 'pending').lt('created_at', cutoff).limit(50);
  if (error) { console.error('[payout] resume:', error.message); return; }
  for (const p of data || []) {
    try {
      if (!p.signature) {
        // Підпису немає — транзакція не будувалась, тож і токенів не було.
        await supabase.from('token_payouts').update({ status: 'refunded', error: 'обірвано до відправки' }).eq('id', p.id);
        await supabase.rpc('add_coins_earned', { p_nick: p.nick, p_amount: p.coins });
        console.log('[payout] повернуто бали за заявкою', p.id);
        continue;
      }
      const st = await payoutTxStatus(p.signature);
      if (st === 'sent') {
        await supabase.from('token_payouts').update({ status: 'sent', sent_at: new Date().toISOString() }).eq('id', p.id);
        await noteFlow('released', p.coins);
        console.log('[payout] заявка', p.id, 'насправді пройшла');
      } else if (st === 'failed') {
        await supabase.from('token_payouts').update({ status: 'refunded', error: 'транзакція відхилена мережею' }).eq('id', p.id);
        await supabase.rpc('add_coins_earned', { p_nick: p.nick, p_amount: p.coins });
        console.log('[payout] заявка', p.id, 'відхилена, бали повернуто');
      }
      // 'unknown' лишаємо як є: транзакція може ще підтвердитись. Повторна
      // перевірка буде наступного разу — краще затримка, ніж подвійна виплата.
    } catch (e) { console.error('[payout] resume', p.id, e.message); }
  }
}

app.post('/token/payout', async (req, res) => {
  if (!payoutReady()) return res.json({ ok: false, error: 'Виплати недоступні', code: 'err_payout_disabled' });
  const coins = Math.floor(Number(req.body.coins));
  if (!Number.isFinite(coins) || coins < TOKEN_PAYOUT_MIN) {
    return res.json({ ok: false, error: `Мінімум ${TOKEN_PAYOUT_MIN} монет`, code: 'err_payout_min' });
  }
  const { data: user } = await supabase.from('users').select('solana_address').eq('nick', req.nick).single();
  const address = user && user.solana_address;
  if (!address) return res.json({ ok: false, error: 'Спершу вкажіть адресу Solana', code: 'err_payout_no_address' });

  const used = await payoutUsedToday(req.nick);
  if (used === null) return res.json({ ok: false, error: 'Не вдалося перевірити ліміт', code: 'err_payout_limit_check' });
  if (used + coins > TOKEN_PAYOUT_DAILY) {
    return res.json({ ok: false, error: 'Денний ліміт виплат вичерпано', code: 'err_payout_daily_limit' });
  }

  // Пароль акаунта: виплата — єдиний шлях, яким монети виходять за межі EION,
  // і адреса призначення вже задана, тож підпису з пристрою тут не потрібно.
  const pwErr = await requireAccountPassword(req);
  if (pwErr) return res.json(pwErr);

  // Списання ПЕРШИМ і атомарно: два паралельні запити не витратять один баланс двічі.
  // 🔴 Саме з «заробленої» частини: міст працює 1:1, тож усе, що ми роздали
  // самі (бонус новачка, компенсації), інакше було б прямою емісією токена.
  // Виводиться лише те, за що вже заплатила інша людина.
  const { data: left, error: spendErr } = await supabase.rpc('spend_coins_earned', { p_nick: req.nick, p_amount: coins });
  if (spendErr || left === -1 || left === null) {
    return res.json({ ok: false, error: 'Недостатньо монет до виведення', code: 'err_not_enough_earned' });
  }

  const tokens = coins * TOKEN_PAYOUT_RATE;
  const { data: row, error: insErr } = await supabase.from('token_payouts')
    .insert({ nick: req.nick, address, coins, tokens, status: 'pending' }).select('id').single();
  if (insErr) {
    // Заявку не записали — тоді й бали не мають зникнути (повертаємо в ту саму частину).
    await supabase.rpc('add_coins_earned', { p_nick: req.nick, p_amount: coins });
    return res.json({ ok: false, error: 'Не вдалося створити заявку', code: 'err_payout_create' });
  }

  try {
    const { c, tx, signature, lastValidBlockHeight } = await buildPayoutTx(address, tokens);
    // Підпис у базу ДО відправки — щоб обрив не лишив нас без сліду.
    await supabase.from('token_payouts').update({ signature }).eq('id', row.id);
    const raw = tx.serialize();
    await c.sendRawTransaction(raw, { skipPreflight: false });
    await c.confirmTransaction({ signature, blockhash: tx.recentBlockhash, lastValidBlockHeight }, 'confirmed');
    await supabase.from('token_payouts')
      .update({ status: 'sent', sent_at: new Date().toISOString() }).eq('id', row.id);
    await noteFlow('released', coins);   // монети вийшли з обігу, токени — з мосту
    logTx({ fromNick: req.nick, toNick: null, amount: coins, kind: 'token_payout', ref: signature });
    res.json({ ok: true, id: row.id, tokens, signature, balance: left, cluster: SOLANA_CLUSTER });
  } catch (e) {
    console.error('[payout] send:', e.message);
    // 🔴 Бали НЕ повертаємо наосліп: помилка могла статись уже після того, як
    // транзакція пішла в мережу (найчастіше — таймаут підтвердження). Заявка
    // лишається pending із підписом, і resumePendingPayouts спитає мережу.
    // Повертати тут означало б віддати бали за реально надіслані токени.
    await supabase.from('token_payouts')
      .update({ error: String(e.message).slice(0, 300) }).eq('id', row.id);
    setTimeout(() => resumePendingPayouts().catch(() => {}), 30000).unref?.();
    res.json({ ok: false, error: 'Виплату не підтверджено, перевіряємо', code: 'err_payout_unconfirmed' });
  }
});

// ── Надходження: токен → бали ────────────────────────────────────────────
// Зворотний бік мосту. Людина надсилає токени на гаманець обміну (той самий,
// що платить виплати — так ліквідність не розсипається на два пули), а ми
// зараховуємо бали.
//
// Хто надіслав, визначаємо ЗА АДРЕСОЮ ВІДПРАВНИКА, без memo: адреса вже є в
// профілі. Memo вимагало б від людини вставити код у поле, яке більшість
// гаманців ховає, і кожна помилка означала б загублені токени.
//
// Баланси читаємо з `preTokenBalances`/`postTokenBalances` транзакції, а не
// розбираємо інструкції: різниця балансів однаково точна і не залежить від
// того, якою саме інструкцією зроблено переказ.
async function scanTokenDeposits() {
  if (!payoutReady()) return { ok: false, reason: 'disabled' };
  const { Connection, PublicKey } = require('@solana/web3.js');
  const { getAssociatedTokenAddress } = require('@solana/spl-token');
  const c = new Connection(SOLANA_RPC, 'confirmed');
  const kp = getPayoutKeypair();
  const mint = new PublicKey(SOLANA_TOKEN_MINT);
  const ata = await getAssociatedTokenAddress(mint, kp.publicKey);

  const sigs = await c.getSignaturesForAddress(ata, { limit: 25 }, 'confirmed');
  if (!sigs.length) return { ok: true, checked: 0, credited: 0 };

  // Уже оброблені відсіюємо ОДНИМ запитом: інакше на кожен скан ішло б 25.
  const { data: known } = await supabase.from('token_deposits')
    .select('signature').in('signature', sigs.map(x => x.signature));
  const seen = new Set((known || []).map(r => r.signature));

  let credited = 0;
  for (const s of sigs) {
    if (seen.has(s.signature) || s.err) continue;
    try {
      const tx = await c.getParsedTransaction(s.signature, { maxSupportedTransactionVersion: 0 });
      if (!tx || !tx.meta) continue;
      const pre = tx.meta.preTokenBalances || [];
      const post = tx.meta.postTokenBalances || [];
      const amountOf = (arr, owner) => {
        const r = arr.find(b => b.owner === owner && b.mint === SOLANA_TOKEN_MINT);
        return r ? Number(r.uiTokenAmount.uiAmount || 0) : 0;
      };
      const gained = amountOf(post, kp.publicKey.toBase58()) - amountOf(pre, kp.publicKey.toBase58());
      if (gained <= 0) continue;   // це не надходження (виплата або чужа операція)

      // Відправник — той, чий баланс цього ж mint зменшився найбільше.
      let sender = null, drop = 0;
      for (const b of post) {
        if (b.mint !== SOLANA_TOKEN_MINT || b.owner === kp.publicKey.toBase58()) continue;
        const d = amountOf(pre, b.owner) - Number(b.uiTokenAmount.uiAmount || 0);
        if (d > drop) { drop = d; sender = b.owner; }
      }
      if (!sender) continue;

      // Внутрішній гаманець або сума понад стелю — записуємо, але не зараховуємо.
      // Запис потрібен, щоб наступний скан не розбирав цю транзакцію знову.
      const internal = SOLANA_INTERNAL.has(sender) || sender === kp.publicKey.toBase58();
      const tooBig = gained > TOKEN_DEPOSIT_MAX;
      // limit(1) замість single(): якщо в старих даних адреса все ж дублюється,
      // single() кинув би помилку і надходження не зарахувалось би нікому.
      const { data: found } = internal || tooBig ? { data: null } : await supabase.from('users')
        .select('nick').eq('solana_address', sender).limit(1);
      const user = found && found.length ? found[0] : null;
      const coins = user ? Math.floor(gained / TOKEN_PAYOUT_RATE) : 0;
      if (internal || tooBig) {
        console.log('[deposit] пропущено:', s.signature, internal ? 'внутрішня адреса' : `сума ${gained} > ${TOKEN_DEPOSIT_MAX}`);
      }

      // Спершу запис (ключ — signature), потім нарахування: якщо процес упаде
      // між ними, повторний скан побачить запис і не зарахує вдруге. Втратити
      // нарахування гірше не буде — його видно в історії й можна долити руками.
      const { error: insErr } = await supabase.from('token_deposits').insert({
        signature: s.signature, nick: user ? user.nick : null, address: sender,
        tokens: gained, coins, slot: s.slot,
        status: user ? 'credited' : 'unmatched',
      });
      if (insErr) continue;   // найімовірніше гонка — інший інстанс уже записав
      if (user && coins > 0) {
        // Токени прийшли ззовні — отже це «зароблене»: інакше поповнення
        // стало б пасткою (внести можна, вивести назад — ні).
        await supabase.rpc('add_coins_earned', { p_nick: user.nick, p_amount: coins });
        await noteFlow('deposited', coins);   // монети зʼявились за замкнені токени
        logTx({ fromNick: null, toNick: user.nick, amount: coins, kind: 'token_deposit', ref: s.signature });
        credited++;
      }
    } catch (e) { console.error('[deposit]', s.signature, e.message); }
  }
  return { ok: true, checked: sigs.length, credited };
}

// ── Поповнення вбудованим гаманцем: сервер платить комісію ───────────────
// У нового користувача немає SOL, тож самостійно надіслати токени він не може.
// Тому транзакцію збирає й оплачує сервер (feePayer — гаманець обміну), а
// користувач лише ПІДПИСУЄ: без його підпису токени не зрушать, тобто
// розпоряджається ними тільки він.
//
// Сервер будує транзакцію сам навмисно: так він точно знає, що підписує, і не
// може бути використаний як безкоштовний оплатник чужих переказів — інструкції
// тут фіксовані, з клієнта приходить лише сума.
const pendingRelay = new Map();   // nick → { message, amount, blockhash, ts }

app.post('/token/deposit-prepare', async (req, res) => {
  if (!payoutReady()) return res.json({ ok: false, error: 'Виплати недоступні', code: 'err_payout_disabled' });
  const amount = Number(req.body.amount);
  if (!Number.isFinite(amount) || amount <= 0 || amount > TOKEN_DEPOSIT_MAX) {
    return res.json({ ok: false, error: 'Невірна сума', code: 'err_invalid_params' });
  }
  const { data: user } = await supabase.from('users').select('solana_address').eq('nick', req.nick).single();
  const owner = user && user.solana_address;
  if (!owner) return res.json({ ok: false, error: 'Спершу вкажіть адресу Solana', code: 'err_payout_no_address' });

  try {
    const { Connection, PublicKey, Transaction } = require('@solana/web3.js');
    const { getMint, getAssociatedTokenAddress, createTransferInstruction,
            createAssociatedTokenAccountIdempotentInstruction } = require('@solana/spl-token');
    const c = new Connection(SOLANA_RPC, 'confirmed');
    const kp = getPayoutKeypair();
    const mint = new PublicKey(SOLANA_TOKEN_MINT);
    const ownerPk = new PublicKey(owner);
    const info = await getMint(c, mint);
    const raw = BigInt(Math.round(amount)) * (10n ** BigInt(info.decimals));
    const from = await getAssociatedTokenAddress(mint, ownerPk);
    const to = await getAssociatedTokenAddress(mint, kp.publicKey);
    const { blockhash, lastValidBlockHeight } = await c.getLatestBlockhash('confirmed');
    const tx = new Transaction({ feePayer: kp.publicKey, blockhash, lastValidBlockHeight })
      .add(createAssociatedTokenAccountIdempotentInstruction(kp.publicKey, to, kp.publicKey, mint))
      .add(createTransferInstruction(from, to, ownerPk, raw));
    // Клієнт підписує саме message, а не всю транзакцію: так підпис не залежить
    // від того, у якому порядку ми потім складемо підписи.
    const message = tx.serializeMessage();
    pendingRelay.set(req.nick, {
      message: message.toString('base64'), amount, owner,
      blockhash, lastValidBlockHeight, ts: Date.now(),
    });
    res.json({ ok: true, message: message.toString('base64'), amount });
  } catch (e) {
    console.error('[relay] prepare:', e.message);
    res.json({ ok: false, error: 'Не вдалося підготувати переказ', code: 'err_relay_prepare' });
  }
});

app.post('/token/deposit-submit', async (req, res) => {
  const pending = pendingRelay.get(req.nick);
  if (!pending) return res.json({ ok: false, error: 'Переказ не підготовано', code: 'err_relay_expired' });
  // Blockhash живе ~60–90 с; протермінований підпис усе одно не пройде, тож
  // краще сказати про це одразу, ніж ловити помилку мережі.
  if (Date.now() - pending.ts > 90000) {
    pendingRelay.delete(req.nick);
    return res.json({ ok: false, error: 'Переказ протерміновано, спробуйте ще', code: 'err_relay_expired' });
  }
  try {
    const { Connection, PublicKey, Transaction } = require('@solana/web3.js');
    const c = new Connection(SOLANA_RPC, 'confirmed');
    const kp = getPayoutKeypair();
    const tx = Transaction.populate(
      require('@solana/web3.js').Message.from(Buffer.from(pending.message, 'base64')), []);
    tx.addSignature(new PublicKey(pending.owner), Buffer.from(req.body.signature, 'base64'));
    tx.partialSign(kp);
    if (!tx.verifySignatures()) {
      return res.json({ ok: false, error: 'Підпис недійсний', code: 'err_relay_signature' });
    }
    const signature = await c.sendRawTransaction(tx.serialize());
    await c.confirmTransaction({ signature, blockhash: pending.blockhash, lastValidBlockHeight: pending.lastValidBlockHeight }, 'confirmed');
    pendingRelay.delete(req.nick);

    // Зараховуємо одразу: ми знаємо і суму, і хто підписав. Запис у
    // token_deposits із тим самим ключем-підписом — щоб періодичний сканер
    // побачив його своїм і не нарахував удруге.
    const coins = Math.floor(pending.amount / TOKEN_PAYOUT_RATE);
    const { error: insErr } = await supabase.from('token_deposits').insert({
      signature, nick: req.nick, address: pending.owner,
      tokens: pending.amount, coins, status: 'credited',
    });
    if (insErr) return res.json({ ok: true, signature, credited: 0 });
    await supabase.rpc('add_coins_earned', { p_nick: req.nick, p_amount: coins });
    await noteFlow('deposited', coins);
    logTx({ fromNick: null, toNick: req.nick, amount: coins, kind: 'token_deposit', ref: signature });
    const { data: u } = await supabase.from('users').select('coins').eq('nick', req.nick).single();
    res.json({ ok: true, signature, credited: coins, balance: u ? u.coins : null });
  } catch (e) {
    console.error('[relay] submit:', e.message);
    res.json({ ok: false, error: 'Переказ не пройшов', code: 'err_relay_failed' });
  }
});

// ── Переказ токена між гаманцями ────────────────────────────────────────
// Той самий relayer, що й у поповненні: комісію платить сервер, бо в
// користувача SOL немає взагалі. Отримувач задається НІКОМ або адресою —
// нік зручніший у месенджері, адреса потрібна, щоб надіслати назовні.
//
// Денна стеля тут не про токени, а про НАШ SOL: кожен переказ коштує комісії,
// а перший переказ на нову адресу — ще й ренти за її токен-акаунт (~0.002 SOL).
// Без стелі один користувач міг би ганяти переказ туди-сюди й спорожнити
// гаманець обміну.
const TOKEN_TRANSFER_DAILY = Number(process.env.TOKEN_TRANSFER_DAILY || 20);
const pendingTokenTransfer = new Map();   // nick → { message, ... }

/// Кому надсилаємо: нік нашого користувача або зовнішня адреса.
/// Повертає { address, nick } або { error, code }.
async function resolveTokenRecipient(to) {
  const raw = typeof to === 'string' ? to.trim() : '';
  if (!raw) return { error: 'Вкажіть отримувача', code: 'err_invalid_params' };
  if (base58Len(raw) === 32) return { address: raw, nick: null };
  let { data: u } = await supabase.from('users')
    .select('nick, solana_address').eq('nick', raw).single();
  if (!u) {
    const { data: alt } = await supabase.from('users')
      .select('nick, solana_address').eq('nick_lower', raw.toLowerCase()).limit(1);
    u = alt && alt[0];
  }
  if (!u) return { error: 'Отримувача не знайдено', code: 'err_recipient_not_found' };
  if (!u.solana_address) {
    return { error: 'У отримувача немає гаманця', code: 'err_recipient_no_wallet' };
  }
  return { address: u.solana_address, nick: u.nick };
}

app.post('/token/transfer-prepare', async (req, res) => {
  if (!payoutReady()) return res.json({ ok: false, error: 'Виплати недоступні', code: 'err_payout_disabled' });
  const amount = Number(req.body.amount);
  if (!Number.isFinite(amount) || amount <= 0 || amount > TOKEN_DEPOSIT_MAX) {
    return res.json({ ok: false, error: 'Невірна сума', code: 'err_invalid_params' });
  }
  const { data: user } = await supabase.from('users').select('solana_address').eq('nick', req.nick).single();
  const owner = user && user.solana_address;
  if (!owner) return res.json({ ok: false, error: 'Спершу вкажіть адресу Solana', code: 'err_payout_no_address' });

  const dest = await resolveTokenRecipient(req.body.to);
  if (dest.error) return res.json({ ok: false, error: dest.error, code: dest.code });
  if (dest.address === owner) {
    return res.json({ ok: false, error: 'Не можна переказати собі', code: 'err_cannot_transfer_self' });
  }
  // Службові гаманці не приймають переказів: надходження на них ми трактуємо
  // як внутрішній рух фондів, і такий переказ просто зник би для відправника.
  const payoutAddr = getPayoutKeypair().publicKey.toBase58();
  if (SOLANA_INTERNAL.has(dest.address) || dest.address === payoutAddr) {
    return res.json({ ok: false, error: 'Ця адреса службова', code: 'err_solana_internal_address' });
  }
  const used = await usageToday(req.nick, 'token_transfer');
  if (used !== null && used >= TOKEN_TRANSFER_DAILY) {
    return res.json({ ok: false, error: 'Ліміт переказів на сьогодні вичерпано', code: 'err_transfer_daily_limit' });
  }

  try {
    const { Connection, PublicKey, Transaction } = require('@solana/web3.js');
    const { getMint, getAssociatedTokenAddress, createTransferInstruction,
            createAssociatedTokenAccountIdempotentInstruction } = require('@solana/spl-token');
    const c = new Connection(SOLANA_RPC, 'confirmed');
    const kp = getPayoutKeypair();
    const mint = new PublicKey(SOLANA_TOKEN_MINT);
    const ownerPk = new PublicKey(owner);
    const destPk = new PublicKey(dest.address);
    const info = await getMint(c, mint);
    const raw = BigInt(Math.round(amount)) * (10n ** BigInt(info.decimals));
    const from = await getAssociatedTokenAddress(mint, ownerPk);
    const toAta = await getAssociatedTokenAddress(mint, destPk);
    const { blockhash, lastValidBlockHeight } = await c.getLatestBlockhash('confirmed');
    // Рахунок отримувача може не існувати або зʼявитись між перевіркою й
    // відправкою — idempotent-варіант не валить транзакцію в обох випадках.
    const tx = new Transaction({ feePayer: kp.publicKey, blockhash, lastValidBlockHeight })
      .add(createAssociatedTokenAccountIdempotentInstruction(kp.publicKey, toAta, destPk, mint))
      .add(createTransferInstruction(from, toAta, ownerPk, raw));
    const message = tx.serializeMessage();
    pendingTokenTransfer.set(req.nick, {
      message: message.toString('base64'), amount, owner,
      toAddress: dest.address, toNick: dest.nick,
      blockhash, lastValidBlockHeight, ts: Date.now(),
    });
    res.json({ ok: true, message: message.toString('base64'), amount,
               to: dest.address, toNick: dest.nick });
  } catch (e) {
    console.error('[transfer] prepare:', e.message);
    res.json({ ok: false, error: 'Не вдалося підготувати переказ', code: 'err_relay_prepare' });
  }
});

app.post('/token/transfer-submit', async (req, res) => {
  const pending = pendingTokenTransfer.get(req.nick);
  if (!pending) return res.json({ ok: false, error: 'Переказ не підготовано', code: 'err_relay_expired' });
  if (Date.now() - pending.ts > 90000) {
    pendingTokenTransfer.delete(req.nick);
    return res.json({ ok: false, error: 'Переказ протерміновано, спробуйте ще', code: 'err_relay_expired' });
  }
  try {
    const { Connection, PublicKey, Transaction, Message } = require('@solana/web3.js');
    const c = new Connection(SOLANA_RPC, 'confirmed');
    const kp = getPayoutKeypair();
    const tx = Transaction.populate(Message.from(Buffer.from(pending.message, 'base64')), []);
    tx.addSignature(new PublicKey(pending.owner), Buffer.from(req.body.signature, 'base64'));
    tx.partialSign(kp);
    if (!tx.verifySignatures()) {
      return res.json({ ok: false, error: 'Підпис недійсний', code: 'err_relay_signature' });
    }
    const signature = await c.sendRawTransaction(tx.serialize());
    await c.confirmTransaction({ signature, blockhash: pending.blockhash, lastValidBlockHeight: pending.lastValidBlockHeight }, 'confirmed');
    pendingTokenTransfer.delete(req.nick);
    await bumpUsage(req.nick, 'token_transfer');
    // Отримувач-користувач дізнається одразу, не відкриваючи гаманець.
    if (pending.toNick) {
      sendToUser(pending.toNick, { type: 'token_received', amount: pending.amount, from: req.nick, signature });
    }
    res.json({ ok: true, signature, amount: pending.amount, to: pending.toAddress, toNick: pending.toNick });
  } catch (e) {
    console.error('[transfer] submit:', e.message);
    res.json({ ok: false, error: 'Переказ не пройшов', code: 'err_relay_failed' });
  }
});

// Куди надсилати + ручна перевірка. Автоматичний скан теж є (раз на 5 хв), але
// чекати п'ять хвилин, дивлячись на порожній екран, — погана перша вражіння.
app.get('/token/deposit-address', async (req, res) => {
  if (!payoutReady()) return res.json({ ok: false, error: 'Виплати недоступні', code: 'err_payout_disabled' });
  const { data: user } = await supabase.from('users').select('solana_address').eq('nick', req.nick).single();
  res.json({
    ok: true,
    address: getPayoutKeypair().publicKey.toBase58(),
    mint: SOLANA_TOKEN_MINT,
    cluster: SOLANA_CLUSTER,
    rate: TOKEN_PAYOUT_RATE,
    // Без прив'язаної адреси надходження не буде кому зарахувати.
    from: (user && user.solana_address) || null,
  });
});

app.post('/token/deposit-check', async (req, res) => {
  try {
    const r = await scanTokenDeposits();
    if (!r.ok) return res.json({ ok: false, error: 'Виплати недоступні', code: 'err_payout_disabled' });
    const { data: u } = await supabase.from('users').select('coins').eq('nick', req.nick).single();
    res.json({ ok: true, checked: r.checked, credited: r.credited, balance: u ? u.coins : null });
  } catch (e) {
    console.error('[deposit] check:', e.message);
    res.json({ ok: false, error: 'Не вдалося перевірити надходження', code: 'err_deposit_check' });
  }
});

app.get('/token/payouts', async (req, res) => {
  const { data, error } = await supabase.from('token_payouts')
    .select('id, coins, tokens, status, signature, created_at')
    .eq('nick', req.nick).order('id', { ascending: false }).limit(20);
  if (error) return res.json({ ok: false, error: 'Не вдалося прочитати історію', code: 'err_payout_history' });
  res.json({ ok: true, cluster: SOLANA_CLUSTER, payouts: data || [] });
});

app.get('/search-user', async (req, res) => {
  const { nick } = req.query; if (!nick || nick.trim().length < 2) return res.json({ ok: false, error: 'Введіть мін. 2 символи', code: 'err_query_too_short' });
  const { data } = await supabase.from('users').select('nick').ilike('nick_lower', `%${nick.toLowerCase()}%`).neq('invisible', true).limit(10);
  res.json({ ok: true, users: (data || []).map(u => u.nick) });
});

app.post('/users/by-phones', async (req, res) => {
  let { phones } = req.body;
  if (!phones || !Array.isArray(phones) || phones.length === 0) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
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

app.post('/unregister', (req, res) => { const nick = req.nick; if (nick) { onlineUsers.delete(nick); busPublish({ t: 'down', nick }); } res.json({ ok: true }); });
app.post('/register-fcm-token', (req, res) => {
  const { token, deviceId } = req.body; // token тут = FCM-токен (не сесійний)
  const nick = req.nick; // Фаза 1/#14: FCM-токен реєструється ЛИШЕ на свій нік.
  if (!nick || !token) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  saveFcmToken(nick, token, deviceId);
  res.json({ ok: true });
});

app.post('/update-nick-color', async (req, res) => {
  const { nickColor } = req.body; const nick = req.nick; if (!nick) return res.json({ ok: false, error: 'Нік обов\'язковий', code: 'err_param_nick' });
  await supabase.from('users').update({ nick_color: nickColor || null }).eq('nick', nick);
  for (const [n, user] of onlineUsers) if (n !== nick) user.ws.send(JSON.stringify({ type: 'nick_color_changed', nick, nickColor: nickColor || null }));
  res.json({ ok: true });
});


// ── Наскрізне шифрування особистих чатів: обмін публічними ключами ─────────
// Сервер бачить лише ПУБЛІЧНІ ключі й шифротекст. Приватний ключ живе у
// сховищі ОС на пристрої й сюди не потрапляє — тому «відновити переписку» ми
// не можемо навіть на запит власника, і це навмисно.
//
// Опортуністично: у кого ключа немає (стара збірка), тому пишуть відкритим
// текстом. Тобто перехід не потребує дня переходу — щойно обидві сторони
// оновились, їхні повідомлення починають шифруватись самі.
//
// ⚠️ Чесна межа: публічні ключі роздаємо МИ. Проти крадіжки бази, інсайдера й
// запиту органів це працює; проти нас самих — ні, доки немає кодів звірки.
const E2EE_PUBKEY_RE = /^[A-Za-z0-9_-]{43}$/;   // 32 байти в base64url без padding

app.post('/keys/publish', async (req, res) => {
  const pubkey = typeof req.body.pubkey === 'string' ? req.body.pubkey.trim() : '';
  if (!E2EE_PUBKEY_RE.test(pubkey)) {
    return res.json({ ok: false, error: 'Невірний ключ', code: 'err_invalid_params' });
  }
  const { error } = await supabase.from('users').update({ e2ee_pubkey: pubkey }).eq('nick', req.nick);
  if (error) {
    // Колонки ще немає (міграція не виконана) — не падаємо: клієнт просто
    // лишиться на відкритому тексті, як до шифрування.
    console.error('[e2ee] publish:', error.message);
    return res.json({ ok: false, error: 'Не вдалося зберегти', code: 'err_save_failed' });
  }
  res.json({ ok: true });
});

app.get('/keys', async (req, res) => {
  const nick = typeof req.query.nick === 'string' ? req.query.nick : '';
  if (!nick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data, error } = await supabase.from('users').select('e2ee_pubkey').eq('nick', nick).maybeSingle();
  if (error) { console.error('[e2ee] fetch:', error.message); return res.json({ ok: true, pubkey: null }); }
  res.json({ ok: true, pubkey: (data && data.e2ee_pubkey) || null });
});

app.post('/update-avatar', async (req, res) => {
  const { avatarUrl } = req.body; const nick = req.nick; if (!nick) return res.json({ ok: false, error: 'Нік обов\'язковий', code: 'err_param_nick' });
  await supabase.from('users').update({ avatar_url: avatarUrl || null }).eq('nick', nick);
  for (const [n, user] of onlineUsers) if (n !== nick) user.ws.send(JSON.stringify({ type: 'avatar_changed', nick, avatarUrl: avatarUrl || null }));
  res.json({ ok: true });
});

app.post('/update-status', async (req, res) => {
  const { status } = req.body; const nick = req.nick; if (!nick) return res.json({ ok: false, error: 'Нік обов\'язковий', code: 'err_param_nick' });
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
  if (!fromNick || !toNick || !amount || amount < 1) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  if (fromNick === toNick) return res.json({ ok: false, error: 'Не можна переказати собі', code: 'err_cannot_transfer_self' });
  const { data: receiver } = await supabase.from('users').select('nick').eq('nick', toNick).single();
  if (!receiver) return res.json({ ok: false, error: 'Отримувача не знайдено', code: 'err_recipient_not_found' });
  // Пароль акаунта: вкрадена сесія не має спорожнювати баланс. Стоїть після
  // дешевих перевірок (щоб через одруківку в ніку не питати пароль двічі), але
  // ДО першого руху монет.
  const pwErr = await requireAccountPassword(req);
  if (pwErr) return res.json(pwErr);
  // Атомарне списання у відправника (повна сума) з поділом на класи.
  const spend = await spendCoinsSplit(fromNick, amount);
  if (!spend.ok) return res.json({ ok: false, error: spend.error, code: spend.code });
  const senderBalance = spend.balance;
  // Комісія відраховується ІЗ суми: отримувач отримує net, решта → компанії.
  const fee = Math.floor(amount * TRANSFER_FEE_PCT / 100);
  const netAmount = amount - fee;
  // Нарахування отримувачу (net) з ПЕРЕНЕСЕННЯМ класу: виведеним стає лише те,
  // що відправник заплатив зі свого заробленого. Інакше переказ сам по собі
  // перетворював би внутрішні монети на виведені (див. spendCoinsSplit).
  const newReceiverCoins = await creditSplit(toNick, netAmount, spend.earnedSpent);
  if (newReceiverCoins === null) {
    // Відкат повертає рівно ті класи, які зняли: тепер це безпечно, бо
    // «зароблене» з нічого не виникає — відмити бонус через збій не вийде.
    await refundSplit(fromNick, amount, spend.earnedSpent);
    await logTx({ fromNick: null, toNick: fromNick, amount, kind: 'transfer_refund', ref: toNick });
    return res.json({ ok: false, error: 'Помилка переказу', code: 'err_transfer_failed' });
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
  if (!fromNick || !toNick || !startedAt || !status) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  // Актор має бути учасником дзвінка (вхідний/вихідний — обидві сторони логують).
  if (req.nick !== fromNick && req.nick !== toNick) return res.status(403).json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
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
  const { nick, otherNick } = req.query; if (!nick || !otherNick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  // Пара ніків через .in(): значення екрануються клієнтом, тоді як рядковий
  // `or=(...)` дозволяв дописати умову — обидва ніки приходять із запиту.
  // from і to з одного набору = рівно розмова цієї пари.
  const { data } = await supabase.from('call_logs').select('*')
    .in('from_nick', [nick, otherNick]).in('to_nick', [nick, otherNick])
    .order('started_at', { ascending: true });
  res.json({ ok: true, logs: data || [] });
});

app.delete('/call-logs', async (req, res) => {
  const { nick, otherNick } = req.query; if (!nick || !otherNick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  await supabase.from('call_logs').delete()
    .in('from_nick', [nick, otherNick]).in('to_nick', [nick, otherNick]);
  res.json({ ok: true });
});

// Storage 2.2 (аудит #2): підписаний upload-URL. Раніше клієнт заливав файли
// напряму anon-ключем (він у APK → будь-хто міг заливати/перезаписувати довільні
// файли). Тепер заливка можлива лише в автентифікованій сесії: сервер service-
// ключем видає одноразовий підписаний URL, клієнт заливає по ньому. Після переходу
// всіх клієнтів прибираємо anon INSERT-політики (migrations/storage_lockdown_2_2.sql).
app.post('/storage/signed-upload', async (req, res) => {
  const { bucket, path, upsert, size } = req.body;
  if (!bucket || !path || !STORAGE_BUCKETS_SET.has(bucket)) {
    return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  }
  // Санітизація шляху: без обходу вгору й провідного слеша, розумна довжина.
  if (typeof path !== 'string' || path.includes('..') || path.startsWith('/') || path.length > 300) {
    return res.json({ ok: false, error: 'Невірний шлях', code: 'err_invalid_path' });
  }
  // Сховище коштує грошей щомісяця, тож понад денну норму вивантажень платимо
  // монетами. Аватари не рахуємо — вони дрібні й міняються рідко.
  if (bucket === 'files' && Number(size) > 0) {
    const mb = Math.max(1, Math.ceil(Number(size) / (1024 * 1024)));
    const charge = await chargeSink(req.nick, 'storage', mb);
    if (!charge.ok) return res.json({ ok: false, error: charge.error, code: charge.code });
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
  if (!refs) return res.json({ ok: false, error: 'refs обовʼязкові', code: 'err_param_refs' });
  if (refs.length > 100) return res.json({ ok: false, error: 'Забагато рефів', code: 'err_too_many_refs' });
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
// Позначка часу правки — окремим запитом ПІСЛЯ оновлення тексту.
//
// ⚠️ Навмисно не одним `update({ content, edited_at })`: доки міграція
// `message_edits_catchup.sql` не виконана, колонки немає, і спільний запит
// відхилився б цілком — тобто правка не застосувалась би взагалі. Так текст
// оновлюється завжди, а догін просто не працює до міграції.
async function markEdited(table, match) {
  try {
    const { error } = await supabase.from(table).update({ edited_at: Date.now() }).match(match);
    if (error) console.error('markEdited', table, error.message);
  } catch (e) { console.error('markEdited', table, e.message); }
}

// Правки, які людина пропустила, поки була офлайн.
//
// Сервер сповіщає про правку лише наживо, тож без цього офлайн-адресат лишався
// зі старим текстом назавжди. Вікно природно обмежене TTL самих повідомлень
// (7 діб direct / 30 груп) — старіші правки стосуються того, чого вже немає.
app.get('/edits', async (req, res) => {
  const since = parseInt(req.query.since, 10) || 0;
  const out = { ok: true, direct: [], groups: [] };
  try {
    const { data, error } = await supabase.from('messages')
      .select('msg_id, from_nick, content, edited_at')
      .eq('to_nick', req.nick)
      .gt('edited_at', since)
      .order('edited_at', { ascending: true })
      .limit(500);
    // Колонки ще немає (міграцію не виконано) — віддаємо порожньо, а не 500:
    // клієнт має працювати й до міграції.
    if (error) return res.json(out);
    out.direct = (data || []).map(m => ({ msgId: m.msg_id, from: m.from_nick, text: m.content, editedAt: m.edited_at }));

    const { data: gm } = await supabase.from('group_members').select('group_id').eq('nick', req.nick);
    const gids = (gm || []).map(g => g.group_id);
    if (gids.length) {
      const { data: ge } = await supabase.from('group_messages')
        .select('msg_id, group_id, from_nick, content, edited_at')
        .in('group_id', gids)
        .gt('edited_at', since)
        .neq('from_nick', req.nick)      // свої правки клієнт уже застосував локально
        .order('edited_at', { ascending: true })
        .limit(500);
      out.groups = (ge || []).map(m => ({ msgId: m.msg_id, groupId: m.group_id, from: m.from_nick, text: m.content, editedAt: m.edited_at }));
    }
  } catch (e) {
    console.error('/edits', e.message);
  }
  res.json(out);
});

app.get('/missed-calls', async (req, res) => {
  const { nick, since } = req.query;
  if (!nick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
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
  if (!name || name.trim().length < 1) return res.json({ ok: false, error: 'Назва групи порожня', code: 'err_group_name_empty' });
  const groupType = type || 'closed';
  const { data: group, error } = await supabase.from('groups').insert({ name: name.trim(), creator_nick: creatorNick, type: groupType }).select().single();
  if (error) return res.json({ ok: false, error: 'Помилка створення групи', code: 'err_group_create_failed' });
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
    return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  }
  await supabase.from('chat_reads').upsert(
    { nick, chat_type: type, chat_id: id, last_read_ts: Date.now() },
    { onConflict: 'nick,chat_type,chat_id' });
  res.json({ ok: true });
});

app.get('/group/search', async (req, res) => {
  const { query, nick } = req.query;
  if (!query || query.trim().length < 2) return res.json({ ok: false, error: 'Введіть мін. 2 символи', code: 'err_query_too_short' });
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
  if (!group) return res.json({ ok: false, error: 'Групу не знайдено', code: 'err_group_not_found' });
  if (group.type === 'closed') return res.json({ ok: false, error: 'Група закрита', code: 'err_group_closed' });
  const { data: existing } = await supabase.from('group_members').select('nick').eq('group_id', groupId).eq('nick', nick).single();
  if (existing) return res.json({ ok: false, error: 'Ви вже в групі', code: 'err_already_in_group' });
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
  if (!(await isModOrCreator(groupId, requesterNick))) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
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
  if (!member || member.role !== 'creator') return res.json({ ok: false, error: 'Тільки творець може змінювати тип групи', code: 'err_only_creator_group_type' });
  await supabase.from('groups').update({ type: groupType }).eq('id', groupId);
  await notifyMembers(groupId, { type: 'group_type_changed', groupId, groupType });
  res.json({ ok: true });
});

app.post('/group/set-moderator', async (req, res) => {
  const { groupId, targetNick, isModerator } = req.body; const requesterNick = req.nick;
  const { data: member } = await supabase.from('group_members').select('role').eq('group_id', groupId).eq('nick', requesterNick).single();
  if (!member || member.role !== 'creator') return res.json({ ok: false, error: 'Тільки творець може призначати модераторів', code: 'err_only_creator_set_mod' });
  const newRole = isModerator ? 'moderator' : 'member';
  await supabase.from('group_members').update({ role: newRole }).eq('group_id', groupId).eq('nick', targetNick);
  await notifyMembers(groupId, { type: 'group_role_changed', groupId, nick: targetNick, role: newRole });
  res.json({ ok: true });
});

app.post('/group/add-member', async (req, res) => {
  const { groupId, newNick } = req.body; const requesterNick = req.nick;
  if (!(await isModOrCreator(groupId, requesterNick))) return res.json({ ok: false, error: 'Тільки модератор або творець може запрошувати учасників', code: 'err_only_mod_invite' });
  const { data: existing } = await supabase.from('group_members').select('nick').eq('group_id', groupId).eq('nick', newNick).single();
  if (existing) return res.json({ ok: false, error: 'Користувач вже в групі', code: 'err_user_already_in_group' });
  const { data: group } = await supabase.from('groups').select('name').eq('id', groupId).single();
  await sendGroupInvite(groupId, group.name, requesterNick, newNick);
  res.json({ ok: true, invited: true });
});

app.post('/group/remove-member', async (req, res) => {
  const { groupId, targetNick } = req.body; const requesterNick = req.nick;
  if (requesterNick !== targetNick && !(await isModOrCreator(groupId, requesterNick))) return res.json({ ok: false, error: 'Тільки модератор або творець може видаляти учасників', code: 'err_only_mod_remove_member' });
  await supabase.from('group_members').delete().eq('group_id', groupId).eq('nick', targetNick);
  sendToUser(targetNick, { type: 'group_removed', groupId });
  await notifyMembers(groupId, { type: 'group_member_removed', groupId, nick: targetNick });
  res.json({ ok: true });
});

app.get('/group/join-requests', async (req, res) => {
  const { groupId, nick } = req.query;
  if (!(await isModOrCreator(groupId, nick))) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  const { data } = await supabase.from('group_join_requests').select('*').eq('group_id', groupId).eq('status', 'pending');
  res.json({ ok: true, requests: data || [] });
});

app.post('/group/delete', async (req, res) => {
  const { groupId } = req.body; const requesterNick = req.nick;
  const { data: member } = await supabase.from('group_members').select('role').eq('group_id', groupId).eq('nick', requesterNick).single();
  if (!member || member.role !== 'creator') return res.json({ ok: false, error: 'Тільки творець може видалити групу', code: 'err_only_creator_delete_group' });
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
  if (!nick || !targetNick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  if (nick === targetNick) return res.json({ ok: false, error: 'Не можна заблокувати самого себе', code: 'err_cannot_block_self' });
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
  if (!nick || typeof enabled !== 'boolean') return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  // Захист: невидимість доступна лише EION (системний акаунт).
  if (nick !== COMPANY_NICK) return res.json({ ok: false, error: 'Недоступно', code: 'err_unavailable' });
  const { error } = await supabase.from('users').update({ invisible: enabled }).eq('nick', nick);
  if (error) return res.json({ ok: false, error: 'Помилка збереження', code: 'err_save_failed' });
  if (enabled) invisibleNicks.add(nick); else invisibleNicks.delete(nick);
  busPublish({ t: 'invis', nick, on: enabled });
  res.json({ ok: true, invisible: enabled });
});

app.post('/settings/block-incoming', async (req, res) => {
  const { enabled } = req.body; const nick = req.nick;
  if (!nick || typeof enabled !== 'boolean') return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { error } = await supabase.from('users').update({ block_incoming: enabled }).eq('nick', nick);
  if (error) return res.json({ ok: false, error: 'Помилка збереження', code: 'err_save_failed' });
  if (enabled) {
    await supabase.from('block_allowlist').delete().eq('owner_nick', nick);
  }
  res.json({ ok: true, blockIncoming: enabled });
});

app.post('/contact/unblock', async (req, res) => {
  const { targetNick } = req.body; const nick = req.nick;
  if (!nick || !targetNick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  await supabase.from('blocked_contacts').delete().eq('blocker_nick', nick).eq('blocked_nick', targetNick);
  res.json({ ok: true });
});

app.get('/contact/blocked-list', async (req, res) => {
  const { nick } = req.query;
  if (!nick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data } = await supabase.from('blocked_contacts').select('blocked_nick, blocked_at').eq('blocker_nick', nick);
  res.json({ ok: true, blocked: (data || []).map(r => r.blocked_nick) });
});

// Тимчасовий маркер версії — щоб однозначно підтвердити, яка збірка задеплоєна.
app.get('/contact/version-check', (req, res) => {
  res.json({ ok: true, marker: 'sticker-pending-v4-2026-07-11' });
});

app.get('/direct/reactions', async (req, res) => {
  const { me, other } = req.query;
  if (!me || !other) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
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
  if (!groupId || !nick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
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
  if (!nick || !plan) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const PRICES = PREMIUM_PRICES;
  const price = PRICES[plan];
  if (!price) return res.json({ ok: false, error: 'Невідомий план', code: 'err_unknown_plan' });
  const { data: user } = await supabase.from('users').select('premium_expires_at').eq('nick', nick).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено', code: 'err_user_not_found' });
  // Атомарне списання: spend_coins повертає новий баланс або -1 (недостатньо).
  const { data: newBalance, error: spendErr } = await supabase.rpc('spend_coins', { p_nick: nick, p_amount: price });
  if (spendErr) return res.json({ ok: false, error: 'Помилка списання', code: 'err_charge_failed' });
  if (newBalance === -1) return res.json({ ok: false, error: `Недостатньо EION (потрібно ${price})`, code: 'err_not_enough_coins' });
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
// Публічний URL наліпки. Бакет `stickers` навмисно публічний (на відміну від
// files/avatars): це статичний контент магазину, однаковий для всіх, тож
// підписувати кожен файл нема сенсу — лише зайві запити й зіпсований кеш.
function stickerPublicUrl(storagePath) {
  const { data } = supabase.storage.from('stickers').getPublicUrl(storagePath);
  return data?.publicUrl || null;
}

// Додати або оновити пак цілком: метадані + файли. Дозволяє поповнювати
// магазин БЕЗ нової збірки застосунку — саме заради цього все й затівалось.
// Файли йдуть у base64; пак із 12 Lottie важить ~600 КБ і влазить у ліміт тіла.
app.post('/admin/sticker-pack', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Доступ заборонено', code: 'err_forbidden' });
  const { id, title, price = 0, sortOrder = 0, previewSticker, items } = req.body || {};
  if (!id || !title || !Array.isArray(items) || !items.length) {
    return res.json({ ok: false, error: 'Потрібні id, title і items', code: 'err_invalid_params' });
  }
  if (!/^[a-z0-9_-]{2,32}$/.test(id)) return res.json({ ok: false, error: 'Невірний id пака', code: 'err_invalid_params' });
  try {
    const uploaded = [];
    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      if (!it || !it.stickerId || !it.dataBase64) {
        return res.json({ ok: false, error: `items[${i}]: потрібні stickerId і dataBase64`, code: 'err_invalid_params' });
      }
      const kind = it.kind === 'image' ? 'image' : 'lottie';
      const ext = kind === 'image' ? (it.ext || 'webp') : 'json';
      const path = `${id}/${it.stickerId}.${ext}`;
      const buf = Buffer.from(it.dataBase64, 'base64');
      const { error: upErr } = await supabase.storage.from('stickers')
        .upload(path, buf, {
          contentType: kind === 'image' ? `image/${ext}` : 'application/json',
          upsert: true,
        });
      if (upErr) return res.json({ ok: false, error: `upload ${path}: ${upErr.message}` });
      uploaded.push({ pack_id: id, sticker_id: it.stickerId, storage_path: path, kind, sort_order: i });
    }
    await supabase.from('sticker_packs').upsert({
      id, title, price: Number(price) || 0, sort_order: Number(sortOrder) || 0,
      preview_sticker: previewSticker || uploaded[0].sticker_id, is_active: true,
    }, { onConflict: 'id' });
    await supabase.from('sticker_pack_items').upsert(uploaded, { onConflict: 'pack_id,sticker_id' });
    res.json({ ok: true, packId: id, items: uploaded.length });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

app.get('/shop/sticker-packs', async (req, res) => {
  const nick = req.query.nick;
  if (!nick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  await grantFreePacks(nick); // безкоштовні одразу у власності
  const { data: packs, error } = await supabase.from('sticker_packs')
    .select('id, title, price, preview_sticker, sort_order')
    .eq('is_active', true).order('sort_order', { ascending: true });
  if (error) {
    console.error('[shop/sticker-packs] select error:', error);
    return res.json({ ok: false, error: 'Помилка каталогу', code: 'err_catalog_failed' });
  }
  const { data: owned } = await supabase.from('user_sticker_packs').select('pack_id').eq('nick', nick);
  const ownedSet = new Set((owned || []).map(o => o.pack_id));
  // Склад паків — щоб клієнт міг показати наліпки, яких немає в його збірці.
  // Раніше картинки жили лише в assets застосунку: новий пак вимагав релізу, а
  // до того куплений пак виглядав як «зображення недоступне».
  const { data: items } = await supabase.from('sticker_pack_items')
    .select('pack_id, sticker_id, storage_path, kind, sort_order')
    .order('sort_order', { ascending: true });
  const byPack = new Map();
  for (const it of items || []) {
    if (!byPack.has(it.pack_id)) byPack.set(it.pack_id, []);
    byPack.get(it.pack_id).push({
      id: it.sticker_id,
      url: stickerPublicUrl(it.storage_path),
      kind: it.kind || 'lottie',
    });
  }
  const result = (packs || []).map(p => ({
    id: p.id, title: p.title, price: p.price,
    previewSticker: p.preview_sticker,
    owned: ownedSet.has(p.id) || p.price === 0,
    items: byPack.get(p.id) || [],   // порожньо → пак вбудований у застосунок
  }));
  res.json({ ok: true, packs: result });
});

// Список ID паків, якими користувач володіє (для панелі наліпок).
app.get('/shop/my-packs', async (req, res) => {
  const nick = req.query.nick;
  if (!nick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
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
  if (!nick || !packId) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  // Ціна — виключно з БД (клієнт не може її підмінити).
  const { data: pack } = await supabase.from('sticker_packs').select('id, price, is_active').eq('id', packId).single();
  if (!pack || !pack.is_active) return res.json({ ok: false, error: 'Пак недоступний', code: 'err_pack_unavailable' });
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
  if (spendErr) return res.json({ ok: false, error: 'Помилка списання', code: 'err_charge_failed' });
  if (newBalance === -1) return res.json({ ok: false, error: `Недостатньо EION (потрібно ${price})`, code: 'err_not_enough_coins' });
  // Записуємо власність. Якщо провалилось — повертаємо коіни (щоб не списати даремно).
  const { error: ownErr } = await supabase.from('user_sticker_packs').insert({ nick, pack_id: packId });
  if (ownErr) {
    // Можливо, паралельний запит уже записав власність (гонка) — перевіряємо.
    const { data: recheck } = await supabase.from('user_sticker_packs').select('pack_id').eq('nick', nick).eq('pack_id', packId).maybeSingle();
    if (!recheck) {
      await supabase.rpc('add_coins', { p_nick: nick, p_amount: price }); // повертаємо кошти
      await logTx({ fromNick: null, toNick: nick, amount: price, kind: 'pack_refund', ref: packId });
      return res.json({ ok: false, error: 'Помилка купівлі', code: 'err_purchase_failed' });
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
  if (!groupId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: member } = await supabase.from('group_members').select('role').eq('group_id', groupId).eq('nick', requesterNick).single();
  if (!member || !['creator', 'moderator'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  const updates = {};
  if (name !== undefined && name.trim().length > 0) updates.name = name.trim();
  if (avatarUrl !== undefined) updates.avatar_url = avatarUrl;
  if (Object.keys(updates).length === 0) return res.json({ ok: false, error: 'Нічого оновлювати', code: 'err_nothing_to_update' });
  await supabase.from('groups').update(updates).eq('id', groupId);
  await notifyMembers(groupId, { type: 'group_updated', groupId, ...updates });
  res.json({ ok: true });
});

app.get('/ping', (req, res) => res.json({ ok: true }));

// ── Закріплені повідомлення груп ──────────────────────────────
// Закріпити (creator/moderator). Клієнт шле прев'ю (text) + автора (from) + msgId.
app.post('/group/pin', async (req, res) => {
  const { groupId, msgId, text, from } = req.body; const requesterNick = req.nick;
  if (!groupId || !requesterNick || !msgId) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  if (!(await isModOrCreator(groupId, requesterNick))) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  const pinnedAt = Date.now();
  await supabase.from('groups').update({ pinned_msg_id: msgId, pinned_text: text || null, pinned_from: from || null, pinned_at: pinnedAt }).eq('id', groupId);
  await notifyMembers(groupId, { type: 'group_pinned', groupId: Number(groupId), msgId, text: text || null, from: from || null, pinnedAt });
  res.json({ ok: true });
});

// Відкріпити (creator/moderator)
app.post('/group/unpin', async (req, res) => {
  const { groupId } = req.body; const requesterNick = req.nick;
  if (!groupId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  if (!(await isModOrCreator(groupId, requesterNick))) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  await supabase.from('groups').update({ pinned_msg_id: null, pinned_text: null, pinned_from: null, pinned_at: null }).eq('id', groupId);
  await notifyMembers(groupId, { type: 'group_unpinned', groupId: Number(groupId) });
  res.json({ ok: true });
});


// ── Закріплені пости каналів (owner/admin) ──────────────────────────────
app.post('/channel/pin', async (req, res) => {
  const { channelId, postId, text, from } = req.body; const requesterNick = req.nick;
  if (!channelId || !requesterNick || !postId) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', requesterNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  const pinnedAt = Date.now();
  await supabase.from('channels').update({ pinned_post_id: String(postId), pinned_text: text || null, pinned_from: from || null, pinned_at: pinnedAt }).eq('id', channelId);
  await notifyChannelSubscribers(channelId, { type: 'channel_pinned', channelId: Number(channelId), postId: String(postId), text: text || null, from: from || null, pinnedAt }, null);
  res.json({ ok: true });
});

app.post('/channel/unpin', async (req, res) => {
  const { channelId } = req.body; const requesterNick = req.nick;
  if (!channelId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', requesterNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  await supabase.from('channels').update({ pinned_post_id: null, pinned_text: null, pinned_from: null, pinned_at: null }).eq('id', channelId);
  await notifyChannelSubscribers(channelId, { type: 'channel_unpinned', channelId: Number(channelId) }, null);
  res.json({ ok: true });
});


// ── Канали ──────────────────────────────────────
app.post('/channel/create', async (req, res) => {
  const { name, description, type, subscribers } = req.body; const ownerNick = req.nick;
  if (!ownerNick || !name || name.trim().length < 1) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: channel, error } = await supabase.from('channels').insert({
    name: name.trim(), description: description || null,
    owner_nick: ownerNick, type: type || 'public',
    created_at: Date.now(), last_post_at: null, last_post_text: null,
  }).select().single();
  if (error) return res.json({ ok: false, error: 'Помилка створення каналу', code: 'err_channel_create_failed' });
  await supabase.from('channel_members').insert({ channel_id: channel.id, nick: ownerNick, role: 'owner' });
  for (const nick of (subscribers || [])) {
    if (nick === ownerNick) continue;
    const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channel.id).eq('nick', nick).single();
    if (!blocked) await supabase.from('channel_members').insert({ channel_id: channel.id, nick, role: 'subscriber' }).catch(() => {});
  }
  res.json({ ok: true, channel: { ...channel, myRole: 'owner', subscriberCount: 1 + (subscribers || []).length, lastPostAt: null, lastPostText: null } });
});

app.get('/channel/list', async (req, res) => {
  const { nick } = req.query; if (!nick) return res.json({ ok: false, error: 'nick обов\'язковий', code: 'err_param_nick' });
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
  if (!query || query.trim().length < 2) return res.json({ ok: false, error: 'Введіть мін. 2 символи', code: 'err_query_too_short' });
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
  const { channelId } = req.body; const nick = req.nick; if (!channelId || !nick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: channel } = await supabase.from('channels').select('type').eq('id', channelId).single();
  if (!channel) return res.json({ ok: false, error: 'Канал не знайдено', code: 'err_channel_not_found' });
  if (channel.type === 'private') return res.json({ ok: false, error: 'Приватний канал — тільки за запрошенням', code: 'err_channel_private' });
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', nick).single();
  if (blocked) return res.json({ ok: false, error: 'Ви заблоковані в цьому каналі', code: 'err_blocked_in_channel' });
  const { data: existing } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  if (existing) return res.json({ ok: false, error: 'Ви вже підписані', code: 'err_already_subscribed' });
  await supabase.from('channel_members').insert({ channel_id: channelId, nick, role: 'subscriber' });
  res.json({ ok: true });
});

app.post('/channel/unsubscribe', async (req, res) => {
  const { channelId } = req.body; const nick = req.nick; if (!channelId || !nick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  if (!member) return res.json({ ok: false, error: 'Ви не підписані', code: 'err_not_subscribed' });
  if (member.role === 'owner') return res.json({ ok: false, error: 'Власник не може відписатись — видаліть канал', code: 'err_owner_cannot_unsub' });
  await supabase.from('channel_members').delete().eq('channel_id', channelId).eq('nick', nick);
  res.json({ ok: true });
});

app.get('/channel/messages', async (req, res) => {
  const { channelId, nick } = req.query; if (!channelId) return res.json({ ok: false, error: 'channelId обов\'язковий', code: 'err_param_channel_id' });
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
  if (!channelId || !fromNick || (!text && !imageUrl && !fileData)) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', fromNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Тільки власник або адмін може писати', code: 'err_only_owner_admin_post' });
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
  if (!channelId || !postId || !nick || !content) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  const { data: post } = await supabase.from('channel_messages').select('from_nick').eq('id', postId).single();
  if (!post) return res.json({ ok: false, error: 'Пост не знайдено', code: 'err_post_not_found' });
  const canEdit = post.from_nick === nick || (member && ['owner', 'admin'].includes(member.role));
  if (!canEdit) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  await supabase.from('channel_messages').update({ content, edited: true, edited_at: Date.now() }).eq('id', postId);
  await notifyChannelSubscribers(channelId, { type: 'channel_post_edited', channelId, postId, text: content }, null);
  res.json({ ok: true });
});

app.post('/channel/edit-message', async (req, res) => {
  const { channelId, postId, text } = req.body; const fromNick = req.nick;
  if (!channelId || !postId || !fromNick || !text) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', fromNick).single();
  const { data: post } = await supabase.from('channel_messages').select('from_nick').eq('id', postId).single();
  if (!post) return res.json({ ok: false, error: 'Пост не знайдено', code: 'err_post_not_found' });
  const canEdit = post.from_nick === fromNick || (member && ['owner', 'admin'].includes(member.role));
  if (!canEdit) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  await supabase.from('channel_messages').update({ content: text, edited: true, edited_at: Date.now() }).eq('id', postId);
  await notifyChannelSubscribers(channelId, { type: 'channel_post_edited', channelId, postId, text }, null);
  res.json({ ok: true });
});

// Видалення поста (обидва шляхи)
app.post('/channel/message/delete', async (req, res) => {
  const { channelId, postId } = req.body; const nick = req.nick;
  if (!postId || !channelId || !nick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  const { data: post } = await supabase.from('channel_messages').select('from_nick, image_url, file_data').eq('id', postId).single();
  if (!post) return res.json({ ok: false, error: 'Пост не знайдено', code: 'err_post_not_found' });
  const canDelete = post.from_nick === nick || (member && ['owner', 'admin'].includes(member.role));
  if (!canDelete) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
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
  if (!postId || !channelId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', requesterNick).single();
  const { data: post } = await supabase.from('channel_messages').select('from_nick, image_url, file_data').eq('id', postId).single();
  if (!post) return res.json({ ok: false, error: 'Пост не знайдено', code: 'err_post_not_found' });
  const canDelete = post.from_nick === requesterNick || (member && ['owner', 'admin'].includes(member.role));
  if (!canDelete) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
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
  const { postId, before } = req.query; if (!postId) return res.json({ ok: false, error: 'postId обов\'язковий', code: 'err_param_post_id' });
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
  if (!channelId || !postId || !fromNick || (!text && !fileData)) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', fromNick).single();
  if (blocked) return res.json({ ok: false, error: 'Ви заблоковані в цьому каналі', code: 'err_blocked_in_channel' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', fromNick).single();
  if (!member) return res.json({ ok: false, error: 'Підпишіться на канал щоб коментувати', code: 'err_subscribe_to_comment' });
  const { data: postRow } = await supabase.from('channel_messages').select('comments_enabled').eq('id', postId).single();
  if (postRow && postRow.comments_enabled === false) return res.json({ ok: false, error: 'Коментарі вимкнені', code: 'err_comments_disabled' });
  if (fileData) { const { data: chRow } = await supabase.from('channels').select('comments_allow_media').eq('id', channelId).single(); if (chRow && chRow.comments_allow_media === false) return res.json({ ok: false, error: 'Медіа в коментарях вимкнено', code: 'err_comment_media_disabled' }); }
  const ts = Date.now();
  const { data: comment } = await supabase.from('channel_comments').insert({ channel_id: channelId, post_id: postId, from_nick: fromNick, content: text || fileName || '', file_data: fileData || null, file_name: fileName || null, timestamp: ts, reply_to_nick: replyToNick || null, reply_to_text: replyToText || null, reply_to_image: replyToImage || null, reply_to_id: replyToId || null, waveform: waveform ? JSON.stringify(waveform) : null, duration_sec: durationSec || null }).select().single();
  const { count: commentCount } = await supabase.from('channel_comments').select('*', { count: 'exact', head: true }).eq('post_id', postId);
  await notifyChannelSubscribers(channelId, { type: 'channel_comment', channelId, postId, from: fromNick, text: text || null, timestamp: ts, commentId: comment.id, commentCount: commentCount || 0, comment }, fromNick);
  res.json({ ok: true, comment: { ...comment, waveform: waveform || null } });
});

app.post('/channel/post/comments-toggle', async (req, res) => {
  const { channelId, postId, enabled } = req.body; const requesterNick = req.nick;
  if (!channelId || !postId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', requesterNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  await supabase.from('channel_messages').update({ comments_enabled: !!enabled }).eq('id', postId);
  res.json({ ok: true });
});

// Читач відкрив коментарі під постом → чужі коментарі позначаємо як побачені.
// Модель спрощена (на відміну від груп): другу галочку дає ПЕРШИЙ читач,
// синьої «прочитали всі» в каналах немає — множина підписників невизначена.
app.post('/channel/comments/read', async (req, res) => {
  const { postId } = req.body; const nick = req.nick;
  if (!postId || !nick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
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
  if (!commentId || !channelId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: comment } = await supabase.from('channel_comments').select('from_nick, file_data').eq('id', commentId).single();
  if (!comment) return res.json({ ok: false, error: 'Коментар не знайдено', code: 'err_comment_not_found' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', requesterNick).single();
  const canDelete = comment.from_nick === requesterNick || (member && ['owner', 'admin'].includes(member.role));
  if (!canDelete) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  await supabase.from('channel_comment_reactions').delete().eq('comment_id', commentId);
  await supabase.from('channel_comments').delete().eq('id', commentId);
  await removeChannelFile(comment.file_data);
  res.json({ ok: true });
});

// Реакція на коментар (toggle) — дзеркало /channel/reaction
app.post('/channel/comment/reaction', async (req, res) => {
  const { commentId, channelId, emoji } = req.body; const nick = req.nick;
  if (!commentId || !channelId || !nick || !emoji) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', nick).single();
  if (blocked) return res.json({ ok: false, error: 'Ви заблоковані', code: 'err_you_blocked' });
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
  if (!channelId || !commentId || !nick || !content) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: comment } = await supabase.from('channel_comments').select('from_nick, post_id').eq('id', commentId).single();
  if (!comment) return res.json({ ok: false, error: 'Коментар не знайдено', code: 'err_comment_not_found' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  const canEdit = comment.from_nick === nick || (member && ['owner', 'admin'].includes(member.role));
  if (!canEdit) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
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
  if (!postId || !channelId || !nick || !emoji) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', nick).single();
  if (blocked) return res.json({ ok: false, error: 'Ви заблоковані', code: 'err_you_blocked' });
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
  if (!channelId || !ownerNick || !targetNick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  await supabase.from('channel_blocked').upsert({ channel_id: channelId, nick: targetNick, blocked_at: Date.now() });
  res.json({ ok: true });
});

app.get('/channel/blocked-list', async (req, res) => {
  const { channelId, ownerNick } = req.query;
  if (!channelId || !ownerNick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  const { data: blocked } = await supabase.from('channel_blocked').select('nick, blocked_at').eq('channel_id', channelId).order('blocked_at', { ascending: false });
  res.json({ ok: true, blocked: blocked || [] });
});

app.post('/channel/unblock-subscriber', async (req, res) => {
  const { channelId, targetNick } = req.body; const ownerNick = req.nick;
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  await supabase.from('channel_blocked').delete().eq('channel_id', channelId).eq('nick', targetNick);
  res.json({ ok: true });
});

app.post('/channel/remove-subscriber', async (req, res) => {
  const { channelId, targetNick } = req.body; const ownerNick = req.nick;
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  await supabase.from('channel_members').delete().eq('channel_id', channelId).eq('nick', targetNick);
  sendToUser(targetNick, { type: 'channel_removed', channelId });
  res.json({ ok: true });
});

app.post('/channel/set-admin', async (req, res) => {
  const { channelId, targetNick, isAdmin } = req.body; const ownerNick = req.nick;
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || member.role !== 'owner') return res.json({ ok: false, error: 'Тільки власник може призначати адмінів', code: 'err_only_owner_set_admin' });
  await supabase.from('channel_members').update({ role: isAdmin ? 'admin' : 'subscriber' }).eq('channel_id', channelId).eq('nick', targetNick);
  res.json({ ok: true });
});

app.get('/channel/subscribers', async (req, res) => {
  const { channelId, ownerNick } = req.query;
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  const { data: members } = await supabase.from('channel_members').select('nick, role, joined_at').eq('channel_id', channelId).order('joined_at', { ascending: true });
  const { data: blocked } = await supabase.from('channel_blocked').select('nick').eq('channel_id', channelId);
  const blockedSet = new Set((blocked || []).map(b => b.nick));
  res.json({ ok: true, subscribers: (members || []).map(m => ({ ...m, isBlocked: blockedSet.has(m.nick) })) });
});

app.post('/channel/invite', async (req, res) => {
  const { channelId, targetNick } = req.body; const ownerNick = req.nick;
  if (!channelId || !ownerNick || !targetNick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  const { data: existing } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', targetNick).single();
  if (existing) return res.json({ ok: false, error: 'Користувач вже є підписником', code: 'err_user_already_subscriber' });
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', targetNick).single();
  if (blocked) return res.json({ ok: false, error: 'Цей користувач заблокований у каналі', code: 'err_user_blocked_in_channel' });
  const { data: targetUser } = await supabase.from('users').select('nick').eq('nick', targetNick).single();
  if (!targetUser) return res.json({ ok: false, error: 'Користувача не знайдено', code: 'err_user_not_found' });
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
  if (!channelId || !nick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  await supabase.from('pending_channel_invites').delete().eq('channel_id', channelId).eq('target_nick', nick);
  if (!accepted) return res.json({ ok: true });
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', nick).single();
  if (blocked) return res.json({ ok: false, error: 'Ви заблоковані в цьому каналі', code: 'err_blocked_in_channel' });
  const { data: existing } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  if (!existing) await supabase.from('channel_members').insert({ channel_id: channelId, nick, role: 'subscriber' });
  const { data: channel } = await supabase.from('channels').select('*').eq('id', channelId).single();
  const { count } = await supabase.from('channel_members').select('*', { count: 'exact', head: true }).eq('channel_id', channelId);
  res.json({ ok: true, channel: { ...channel, myRole: 'subscriber', subscriberCount: count || 0 } });
});



app.post('/channel/contact-owner', async (req, res) => {
  const { channelId } = req.body;
  const fromNick = req.nick; // Фаза 1: платник — автентифікований юзер.
  if (!channelId || !fromNick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const CONTACT_PRICE = 100; const OWNER_SHARE = 70; const COMPANY_SHARE = 30;
  const { data: channel } = await supabase.from('channels').select('owner_nick').eq('id', channelId).single();
  if (!channel) return res.json({ ok: false, error: 'Канал не знайдено', code: 'err_channel_not_found' });
  if (channel.owner_nick === fromNick) return res.json({ ok: false, error: 'Ви є власником каналу', code: 'err_you_are_owner' });
  const { data: owner } = await supabase.from('users').select('nick').eq('nick', channel.owner_nick).single();
  if (!owner) return res.json({ ok: false, error: 'Власника каналу не знайдено', code: 'err_owner_not_found' });
  // Пароль: 70 монет ідуть власнику каналу в «зароблене», тобто виводяться в
  // токен. Без пароля вкрадена сесія платила б власному каналу зловмисника —
  // обхід захисту переказу тим самим результатом.
  const pwErr = await requireAccountPassword(req);
  if (pwErr) return res.json(pwErr);
  // Атомарне списання у покупця.
  const spend = await spendCoinsSplit(fromNick, CONTACT_PRICE);
  if (!spend.ok) return res.json({ ok: false, error: spend.error, code: spend.code });
  const senderBalance = spend.balance;
  // Розподіл: власнику (з перенесенням класу — інакше внутрішні монети
  // покупця ставали б у власника виведеними) + компанії.
  const ownerBalance = await creditSplit(channel.owner_nick, OWNER_SHARE, spend.earnedSpent);
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
  if (!channelId || !nick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const FEE_PCT = 30;
  const { data: ch } = await supabase.from('channels').select('owner_nick, is_paid, price, sub_days').eq('id', channelId).single();
  if (!ch) return res.json({ ok: false, error: 'Канал не знайдено', code: 'err_channel_not_found' });
  if (!ch.is_paid) return res.json({ ok: false, error: 'Канал безкоштовний', code: 'err_channel_free' });
  // Вже є активна підписка — не списувати повторно
  const { data: curArr } = await supabase.from('channel_paid_subs').select('expires_at').eq('channel_id', channelId).eq('nick', nick).order('expires_at', { ascending: false }).limit(1);
  if (curArr && curArr[0] && Number(curArr[0].expires_at) > Date.now()) return res.json({ ok: true, alreadySubscribed: true, expiresAt: Number(curArr[0].expires_at) });
  const price = ch.price || 0;
  // Пароль: ownerShare теж іде в «зароблене». Тут ще гірше, ніж зі зверненням
  // до власника, — ціну задає САМ власник, тож одна підписка могла винести
  // весь баланс жертви (стеля ціни нижче, у /channel/set-paid).
  const pwErr = await requireAccountPassword(req);
  if (pwErr) return res.json(pwErr);
  const companyShare = Math.floor(price * FEE_PCT / 100);
  const ownerShare = price - companyShare;
  // Атомарне списання з поділом на класи.
  const spend = await spendCoinsSplit(nick, price);
  if (!spend.ok) return res.json({ ok: false, error: spend.error, code: spend.code });
  const newBalance = spend.balance;
  if (ch.owner_nick && ch.owner_nick !== nick) {
    const ownerNew = await creditSplit(ch.owner_nick, ownerShare, spend.earnedSpent);
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
  if (!channelId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', requesterNick).single();
  if (!member || member.role !== 'owner') return res.json({ ok: false, error: 'Лише власник', code: 'err_owner_only' });
  // Стеля ціни. Була відсутня: власник міг поставити будь-яке число, і одна
  // підписка виносила весь баланс підписника. Заразом ловить одруківку в нулях.
  const priceCapped = Math.min(CHANNEL_PRICE_MAX, Math.max(0, parseInt(price) || 0));
  await supabase.from('channels').update({ is_paid: !!isPaid, price: priceCapped, sub_days: Math.max(1, parseInt(subDays) || 30) }).eq('id', channelId);
  res.json({ ok: true });
});

app.post('/channel/update', async (req, res) => {
  const { channelId, name, description, type, avatar_url, comments_allow_media } = req.body; const ownerNick = req.nick;
  if (!channelId || !ownerNick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  const updates = {};
  if (name !== undefined) updates.name = name;
  if (description !== undefined) updates.description = description;
  if (type !== undefined) updates.type = type;
  if (avatar_url !== undefined) updates.avatar_url = avatar_url;
  if (comments_allow_media !== undefined) updates.comments_allow_media = comments_allow_media;
  if (Object.keys(updates).length === 0) return res.json({ ok: false, error: 'Нічого оновлювати', code: 'err_nothing_to_update' });
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
  if (!channelId || !ownerNick || !url) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  const videoId = extractYouTubeId(url);
  if (!videoId) return res.json({ ok: false, error: 'Це не схоже на посилання YouTube', code: 'err_not_youtube_url' });
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
  if (!channelId || !ownerNick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  await supabase.from('channels').update({ live_active: false }).eq('id', channelId);
  notifyChannelSubscribers(channelId, { type: 'channel_live', channelId, active: false }).catch(() => {});
  res.json({ ok: true });
});

/// Видалити канал разом з усім, що на нього посилається.
/// Винесено з endpoint'а, бо тепер має ДВА входи: власник і адміністратор.
async function deleteChannelById(channelId) {
  // Збираємо файли постів і коментарів перед видаленням — щоб прибрати зі Storage.
  const { data: chPosts } = await supabase.from('channel_messages').select('id, image_url, file_data').eq('channel_id', channelId);
  const { data: chComments } = await supabase.from('channel_comments').select('id, file_data').eq('channel_id', channelId);
  await supabase.from('channel_comment_reactions').delete().in('comment_id', (chComments || []).map(c => c.id));
  await supabase.from('channel_comments').delete().eq('channel_id', channelId);
  await supabase.from('channel_reactions').delete().in('post_id', (chPosts || []).map(m => m.id));
  await supabase.from('channel_post_views').delete().in('post_id', (chPosts || []).map(m => m.id));
  await supabase.from('channel_messages').delete().eq('channel_id', channelId);
  await supabase.from('channel_members').delete().eq('channel_id', channelId);
  await supabase.from('channel_blocked').delete().eq('channel_id', channelId);
  await supabase.from('channel_paid_subs').delete().eq('channel_id', channelId);
  await supabase.from('pending_channel_invites').delete().eq('channel_id', channelId);
  await supabase.from('channels').delete().eq('id', channelId);
  for (const p of (chPosts || [])) await removeChannelFile(p.image_url, p.file_data);
  for (const c of (chComments || [])) await removeChannelFile(c.file_data);
}

app.post('/channel/delete', async (req, res) => {
  const { channelId } = req.body; const ownerNick = req.nick;
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || member.role !== 'owner') return res.json({ ok: false, error: 'Тільки власник може видалити канал', code: 'err_only_owner_delete_channel' });
  await deleteChannelById(channelId);
  res.json({ ok: true });
});

// Канал, власник якого видалив акаунт, лишається без жодного власника — і тоді
// на скаргу про нього не може відреагувати НІХТО. Це єдиний шлях прибрати такий
// канал; звичайне видалення так і лишається доступним тільки власнику.
app.post('/admin/channel/delete', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  const channelId = Number(req.body.channelId);
  if (!Number.isFinite(channelId)) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
  const { data: ch } = await supabase.from('channels').select('id, name, owner_nick').eq('id', channelId).single();
  if (!ch) return res.json({ ok: false, error: 'Канал не знайдено', code: 'err_channel_not_found' });
  await deleteChannelById(channelId);
  console.log('[admin] channel deleted:', channelId, ch.name, 'owner:', ch.owner_nick);
  res.json({ ok: true, deleted: { id: ch.id, name: ch.name, ownerNick: ch.owner_nick } });
});

// Канали без живого власника — щоб їх було видно, а не шукати наосліп.
app.get('/admin/orphan-channels', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Недостатньо прав', code: 'err_not_enough_rights' });
  const { data: chans } = await supabase.from('channels').select('id, name, owner_nick, created_at');
  const out = [];
  for (const ch of (chans || [])) {
    const { data: owner } = await supabase.from('users').select('nick').eq('nick', ch.owner_nick).maybeSingle();
    if (!owner) out.push({ id: ch.id, name: ch.name, ownerNick: ch.owner_nick });
  }
  res.json({ ok: true, total: (chans || []).length, orphans: out });
});

// ── Модерація платформи ────────────────────────
app.post('/report', async (req, res) => {
  const { targetNick, reason, context } = req.body; const reporterNick = req.nick;
  if (!reporterNick || !targetNick) return res.json({ ok: false, error: 'Невірні параметри', code: 'err_invalid_params' });
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

// 🔴 Шлях треба обрізати не лише по `?`, а й по роздільнику codec-рядка.
// UGC-наліпка лежить у повідомленні як `user:id~|~<url>~|~scale~|~dx~|~dy`,
// тож без цього «шлях» виходив `stickers/nick/1.png~|~1.0~|~0~|~0` — у набір
// посилань справжній шлях не потрапляв, і жива наліпка виглядала сміттям.
// Саме через це перевірка перед видаленням і робилась.
function orphanCutTail(tail) {
  let out = tail.split('?')[0];
  const sep = out.indexOf('~|~');
  if (sep !== -1) out = out.slice(0, sep);
  const stop = out.search(/[\s"'<>)\]]/);
  if (stop !== -1) out = out.slice(0, stop);
  return out;
}

function orphanPathFromValue(val) {
  if (!val || typeof val !== 'string') return null;
  for (const marker of ORPHAN_MARKERS) {
    const i = val.indexOf(marker);
    if (i !== -1) {
      const tail = orphanCutTail(val.slice(i + marker.length));
      try { return decodeURIComponent(tail); } catch (_) { return tail; }
    }
  }
  const r = val.indexOf(ORPHAN_REF);
  if (r !== -1) {
    const tail = orphanCutTail(val.slice(r + ORPHAN_REF.length));
    try { return decodeURIComponent(tail); } catch (_) { return tail; }
  }
  const trimmed = val.trim();
  if (ORPHAN_PREFIXES.some(p => trimmed.startsWith(p))) {
    const tail = orphanCutTail(trimmed);
    try { return decodeURIComponent(tail); } catch (_) { return tail; }
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
      else out.push({
        path: full,
        size: (item.metadata && item.metadata.size) || 0,
        createdAt: Date.parse(item.created_at || item.updated_at || '') || 0,
      });
    }
    if (data.length < limit) break;
    offset += limit;
  }
}

// Захищені префікси: файли, на які в БАЗІ посилань може не бути взагалі.
// UGC-наліпка існує у Storage одразу після створення, а в повідомлення
// потрапляє лише коли її НАДІШЛЮТЬ — і може не потрапити ніколи. Прибрати її
// як «сміття» означало б зламати людині її ж набір наліпок.
const ORPHAN_PROTECTED = ['stickers/'];
// Скільки файл має відлежати, перш ніж вважати його покинутим. Захищає від
// гонки «файл залито, рядок повідомлення ще не створено».
const ORPHAN_MIN_AGE_MS = 7 * 24 * 60 * 60 * 1000;

app.get('/admin/orphan-audit', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Доступ заборонено', code: 'err_forbidden' });
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
  const now = Date.now();
  const orphans = files.filter(f => !refs.has(f.path));
  const bytes = orphans.reduce((n, f) => n + (f.size || 0), 0);

  // Кандидати на видалення — лише ті, що пройшли ВСІ запобіжники.
  const protectedOnes = orphans.filter(f => ORPHAN_PROTECTED.some(p => f.path.startsWith(p)));
  const tooFresh = orphans.filter(f => !ORPHAN_PROTECTED.some(p => f.path.startsWith(p))
    && (!f.createdAt || now - f.createdAt < ORPHAN_MIN_AGE_MS));
  let candidates = orphans.filter(f => !protectedOnes.includes(f) && !tooFresh.includes(f));

  // 2C: файл ще може чекати, поки його заберуть.
  const stillActive = [];
  for (const f of candidates) if (await fileObjectActive(f.path)) stillActive.push(f);
  candidates = candidates.filter(f => !stillActive.includes(f));

  const doDelete = req.query.delete === '1';
  let deleted = 0, deleteError = null;
  if (doDelete) {
    // 🔴 Видаляємо ЛИШЕ якщо набір посилань повний. Неповний означає, що
    // якийсь запит до БД упав — і тоді «сміттям» виглядають живі файли.
    if (hadError) deleteError = 'набір посилань неповний — видалення скасовано';
    else {
      for (let i = 0; i < candidates.length; i += 50) {
        const batch = candidates.slice(i, i + 50).map(f => f.path);
        const { error } = await supabase.storage.from('files').remove(batch);
        if (error) { deleteError = error.message; break; }
        deleted += batch.length;
        for (const p of batch) await supabase.from('file_objects').delete().eq('storage_path', p);
      }
      console.log(`[orphan] видалено ${deleted} покинутих файлів`);
    }
  }

  res.json({
    ok: true,
    // hadError означає, що набір посилань НЕПОВНИЙ → числу вірити не можна.
    complete: !hadError,
    files: files.length,
    referenced: refs.size,
    orphans: orphans.length,
    orphanMB: +(bytes / 1048576).toFixed(1),
    candidates: candidates.length,
    candidateMB: +(candidates.reduce((n, f) => n + (f.size || 0), 0) / 1048576).toFixed(1),
    skipped: { protected: protectedOnes.length, tooFresh: tooFresh.length, waitingPickup: stillActive.length },
    minAgeDays: Math.round(ORPHAN_MIN_AGE_MS / 86400000),
    // Періодична чистка за замовчуванням лише ЛОГУЄ. Якщо тут true — старі
    // повідомлення й файли не видаляються взагалі, і сховище лише росте.
    periodicCleanupDryRun: CLEANUP_DRY_RUN,
    deleted, deleteError,
    sample: candidates.slice(0, 20).map(o => o.path),
  });
});

// Перевірка поштового тракту: віддає СПРАВЖНЮ помилку SMTP, а не загальне
// «Помилка відправки email». Публічним такий текст робити не можна (він
// розкриває конфігурацію релею), тому — під адмін-секретом.
app.get('/admin/mail-test', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Доступ заборонено', code: 'err_forbidden' });
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
    const dom = await ask('/senders/domains');
    const list = snd.body && Array.isArray(snd.body.senders) ? snd.body.senders : null;
    const dlist = dom.body && Array.isArray(dom.body.domains) ? dom.body.domains : null;
    const fromDomain = MAIL_FROM.email.split('@')[1] || '';
    const domName = (x) => String(x.domain_name || x.domain || x.name || '');
    brevo = {
      keyValid: acc.status === 200,
      account: acc.status === 200 ? ((acc.body && acc.body.email) || null) : `HTTP ${acc.status} ${JSON.stringify(acc.body || acc.error || '').slice(0, 120)}`,
      plan: acc.status === 200 && acc.body && Array.isArray(acc.body.plan) ? acc.body.plan.map((x) => `${x.type}${x.credits != null ? ` (${x.credits})` : ''}`) : null,
      from: MAIL_FROM.email,
      senders: list ? list.map((x) => `${x.email}${x.active ? '' : ' — НЕ підтверджений'}`) : `HTTP ${snd.status}`,
      fromActive: list ? list.some((x) => String(x.email).toLowerCase() === MAIL_FROM.email.toLowerCase() && x.active) : null,
      // Домен важливіший за відправника: без DKIM лист піде, але в спам.
      // Ім'я домену Brevo віддає під різними назвами залежно від версії API
      // (domain_name / domain / name) — читали лише `domain`, і звіт показував
      // `undefined: автентифікований`, а fromDomainOk хибно казав «ні».
      domains: dlist ? dlist.map((x) => `${domName(x)}: ${x.authenticated ? 'автентифікований' : 'НЕ автентифікований'}${x.verified === false ? ', не підтверджений' : ''}`) : `HTTP ${dom.status}`,
      fromDomainOk: dlist ? dlist.some((x) => domName(x).toLowerCase() === fromDomain.toLowerCase() && x.authenticated) : null,
      // Ключі сирого елемента — щоб наступного разу не гадати, як зветься поле.
      domainFields: dlist && dlist[0] ? Object.keys(dlist[0]) : null,
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
// ── Огляд: одна картина «що відбувається» ────────────────────────────────
// Доти дивитись доводилось руками по таблицях Supabase, логах Render, Sentry і
// GitHub — тобто в чотирьох місцях, і жодне не давало відповіді «скільки людей
// користується». Тут усе разом; `?format=html` — щоб відкрити з телефона.
// Скільки ще операцій витримає гаманець релея. Рента токен-рахунку (~0,00204
// SOL) — найдорожча з них, тож рахуємо в «перших надходженнях»: саме вони
// закінчаться першими.
const ATA_RENT_SOL = 0.00204;
async function relayerStatus() {
  if (!payoutReady()) return { enabled: false };
  try {
    const kp = getPayoutKeypair();
    const r = await httpPostJson(SOLANA_RPC, {}, {
      jsonrpc: '2.0', id: 1, method: 'getBalance', params: [kp.publicKey.toBase58()],
    });
    const body = JSON.parse(r.body || '{}');
    if (body.error) throw new Error(body.error.message || 'RPC error');
    const sol = (body.result && body.result.value ? body.result.value : 0) / 1e9;
    const newWallets = Math.floor(sol / ATA_RENT_SOL);
    return {
      enabled: true, address: kp.publicKey.toBase58(), sol: Number(sol.toFixed(6)),
      newWalletsLeft: newWallets, low: newWallets < 50, cluster: SOLANA_CLUSTER,
    };
  } catch (e) {
    return { enabled: true, error: e.message };
  }
}

async function collectOverview() {
  const iso = (ms) => new Date(Date.now() - ms).toISOString();
  const DAY = 86400000;
  const dayAgo = iso(DAY), weekAgo = iso(7 * DAY);
  const errors = [];

  // head:true — рахунок без вигрібання рядків.
  const cnt = async (table, apply) => {
    let q = supabase.from(table).select('*', { count: 'exact', head: true });
    if (apply) q = apply(q);
    const { count, error } = await q;
    // message інколи порожній (напр. коли колонки ще немає) — тоді код або hint,
    // інакше в списку помилок висів би безмовний рядок «users: ».
    if (error) { errors.push(`${table}: ${error.message || error.code || error.hint || 'запит не вдався'}`); return null; }
    return count;
  };

  const [
    usersTotal, usersNewDay, usersNewWeek, usersSeenDay, usersSeenWeek,
    usersNoCreated, usersPremium, usersPhone, banned,
    msgs, msgsDay, groupMsgs, channelMsgs, comments,
    groups, channels, files, packsOwned,
  ] = await Promise.all([
    cnt('users'),
    cnt('users', q => q.gte('created_at', dayAgo)),
    cnt('users', q => q.gte('created_at', weekAgo)),
    cnt('users', q => q.gte('last_seen', dayAgo)),
    cnt('users', q => q.gte('last_seen', weekAgo)),
    cnt('users', q => q.is('created_at', null)),
    cnt('users', q => q.gt('premium_expires_at', new Date().toISOString())),
    cnt('users', q => q.eq('phone_verified', true)),
    cnt('platform_bans'),
    cnt('messages'),
    cnt('messages', q => q.gte('timestamp', Date.now() - DAY)),
    cnt('group_messages'),
    cnt('channel_messages'),
    cnt('channel_comments'),
    cnt('groups'),
    cnt('channels'),
    cnt('file_objects'),
    cnt('user_sticker_packs'),
  ]);

  // Норми за сьогодні: рядків мало (по одному на нік×вид), тож агрегуємо в JS.
  const today = new Date().toISOString().slice(0, 10);
  const quotas = {};
  let quotaUsers = null;
  {
    const { data, error } = await supabase.from('usage_counters')
      .select('nick, kind, used').eq('day', today);
    if (error) errors.push(`usage_counters: ${error.message}`);
    else {
      const nicks = new Set();
      for (const r of data) {
        // Службові лічильники (#ai-provider — денна стеля на провайдера) живуть
        // у тій самій таблиці. Без фільтра вони і додавали чужі види ('groq'),
        // і роздували «скільки людей витрачали норму».
        if (String(r.nick).startsWith('#')) continue;
        quotas[r.kind] = (quotas[r.kind] || 0) + (r.used || 0);
        nicks.add(r.nick);
      }
      quotaUsers = nicks.size;
    }
  }

  // Монета
  let coins = null;
  {
    const { data: supply } = await supabase.from('coin_supply').select('minted, burned').eq('id', 1).single();
    const { data: company } = await supabase.from('users').select('coins').eq('nick', COMPANY_NICK).single();
    const txWeek = await cnt('coin_transactions', q => q.gte('created_at', weekAgo));
    coins = {
      minted: supply ? supply.minted : null,
      burned: supply ? supply.burned : null,
      treasury: company ? company.coins : null,
      transactionsWeek: txWeek,
    };
  }

  // Завантаження: за 7 днів у розрізі файлу й джерела + сума за весь час.
  const downloads = { week: {}, total: {} };
  {
    const { data, error } = await supabase.from('download_counts')
      .select('day, kind, source, count').gte('day', weekAgo.slice(0, 10));
    if (error) errors.push(`download_counts: ${error.message}`);
    else for (const r of data) {
      downloads.week[r.kind] = (downloads.week[r.kind] || 0) + r.count;
      downloads.week[`${r.kind}:${r.source}`] = (downloads.week[`${r.kind}:${r.source}`] || 0) + r.count;
    }
    const { data: all, error: e2 } = await supabase.from('download_counts').select('kind, count');
    if (e2) errors.push(`download_counts(all): ${e2.message}`);
    else for (const r of all) downloads.total[r.kind] = (downloads.total[r.kind] || 0) + r.count;
  }

  // Останні рухи монет: без них числа «спалено / у скарбниці» доводиться
  // реконструювати в голові («200 за пак → 40% спалено → 80»), а журнал
  // append-only і так є — просто ніде не показувався.
  let recentTx = [];
  {
    const { data, error } = await supabase.from('coin_transactions')
      .select('created_at, kind, amount, from_nick, to_nick')
      .order('id', { ascending: false }).limit(15);
    if (error) errors.push(`coin_transactions: ${error.message || 'запит не вдався'}`);
    else recentTx = data.map(r => ({
      at: r.created_at, kind: r.kind, amount: r.amount,
      from: r.from_nick, to: r.to_nick,
    }));
  }

  const mem = process.memoryUsage();
  return {
    ok: true,
    generatedAt: new Date().toISOString(),
    users: {
      total: usersTotal, newDay: usersNewDay, newWeek: usersNewWeek,
      activeDay: usersSeenDay, activeWeek: usersSeenWeek,
      premium: usersPremium, phoneVerified: usersPhone, banned,
      // Акаунти, створені до появи колонки: у «нових» вони не рахуються ніколи.
      withoutCreatedAt: usersNoCreated,
    },
    content: {
      directMessages: msgs, directMessagesDay: msgsDay,
      groupMessages: groupMsgs, channelPosts: channelMsgs, channelComments: comments,
      groups, channels, files, stickerPacksOwned: packsOwned,
    },
    quotasToday: { ...quotas, users: quotaUsers },
    coins,
    // SOL гаманця, з якого ми платимо комісії й ренту токен-рахунків. Коли він
    // вичерпається, перекази почнуть падати з err_relay_failed — і дізнаємось
    // ми про це від користувачів. Тому число має бути перед очима.
    relayer: await relayerStatus(),
    recentTransactions: recentTx,
    downloads,
    runtime: {
      onlineNow: onlineUsers.size,
      uptimeHours: +(process.uptime() / 3600).toFixed(1),
      memoryMB: Math.round(mem.rss / 1024 / 1024),
      cluster: busReady() ? 'on' : 'off',
      node: process.version,
    },
    // Порожній масив = усі запити пройшли. Непорожній означає, що числа
    // НЕПОВНІ — мовчазний нуль тут гірший за видиму помилку.
    errors,
  };
}

function overviewHtml(o) {
  const n = (v) => v === null || v === undefined ? '—' : String(v).replace(/\B(?=(\d{3})+(?!\d))/g, ' ');
  const card = (title, rows) => `<section><h2>${title}</h2><table>${
    rows.map(([k, v]) => `<tr><td>${k}</td><td class="v">${n(v)}</td></tr>`).join('')}</table></section>`;
  const d = o.downloads;
  return `<!doctype html><html lang="uk"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EION — огляд</title><style>
:root{color-scheme:dark}body{margin:0;padding:16px;background:#0b1015;color:#dbe6ee;
font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
h1{font-size:18px;margin:0 0 4px}.sub{color:#7d8f9d;font-size:12px;margin-bottom:16px}
section{background:#121a22;border:1px solid #1e2a35;border-radius:12px;padding:12px 14px;margin-bottom:12px}
h2{font-size:13px;margin:0 0 8px;color:#4fd1c5;text-transform:uppercase;letter-spacing:.04em}
table{width:100%;border-collapse:collapse}td{padding:3px 0;border-bottom:1px solid #18232d}
tr:last-child td{border:0}td.v{text-align:right;font-variant-numeric:tabular-nums;font-weight:600}
.err{background:#2b1416;border-color:#5c2126;color:#ffb4ad}</style></head><body>
<h1>EION — огляд</h1><div class="sub">${o.generatedAt.replace('T', ' ').slice(0, 16)} UTC</div>
${o.errors.length ? `<section class="err"><h2>Числа неповні</h2><table>${
    o.errors.map(e => `<tr><td>${e}</td></tr>`).join('')}</table></section>` : ''}
${card('Люди', [
    ['Усього акаунтів', o.users.total],
    ['Нових за добу', o.users.newDay],
    ['Нових за тиждень', o.users.newWeek],
    ['Заходили за добу', o.users.activeDay],
    ['Заходили за тиждень', o.users.activeWeek],
    ['З преміумом', o.users.premium],
    ['Підтверджений телефон', o.users.phoneVerified],
    ['Заблоковані', o.users.banned],
    ['Без дати реєстрації (старі)', o.users.withoutCreatedAt],
  ])}
${o.relayer && o.relayer.enabled ? card('Гаманець комісій' + (o.relayer.low ? ' ⚠️ МАЛО' : ''), [
    ['SOL', o.relayer.sol ?? o.relayer.error ?? '—'],
    ['Вистачить нових гаманців', o.relayer.newWalletsLeft ?? '—'],
    ['Мережа', o.relayer.cluster || '—'],
  ]) : ''}
${card('Завантаження', [
    ['APK за тиждень', d.week.apk || 0],
    ['— із сайту', d.week['apk:site'] || 0],
    ['AppImage за тиждень', d.week.appimage || 0],
    ['— із сайту', d.week['appimage:site'] || 0],
    ['APK усього', d.total.apk || 0],
    ['AppImage усього', d.total.appimage || 0],
  ])}
${card('Вміст', [
    ['Особисті повідомлення', o.content.directMessages],
    ['— за добу', o.content.directMessagesDay],
    ['Групові повідомлення', o.content.groupMessages],
    ['Пости в каналах', o.content.channelPosts],
    ['Коментарі', o.content.channelComments],
    ['Групи', o.content.groups],
    ['Канали', o.content.channels],
    ['Файли у сховищі', o.content.files],
    ['Куплених наборів наліпок', o.content.stickerPacksOwned],
  ])}
${card('Норми сьогодні', [
    ['Людей витрачали', o.quotasToday.users],
    ['AI-запитів', o.quotasToday.ai || 0],
    ['Вивантажено, МБ', o.quotasToday.storage || 0],
    ['Дзвінків через релей', o.quotasToday.turn || 0],
    ['Перекладів', o.quotasToday.translate || 0],
  ])}
${card('Монета', [
    ['Видано з фондів', o.coins.minted],
    ['Спалено назавжди', o.coins.burned],
    ['У скарбниці', o.coins.treasury],
    ['Транзакцій за тиждень', o.coins.transactionsWeek],
  ])}
${o.recentTransactions.length ? `<section><h2>Останні рухи монет</h2><table>${
    o.recentTransactions.map(t => `<tr><td>${t.at.slice(5, 16).replace('T', ' ')} · ${t.kind}<br><span style="color:#7d8f9d;font-size:12px">${t.from || '—'} → ${t.to || '—'}</span></td><td class="v">${n(t.amount)}</td></tr>`).join('')}</table></section>` : ''}
${card('Сервер', [
    ['Онлайн зараз', o.runtime.onlineNow],
    ['Аптайм, год', o.runtime.uptimeHours],
    ['Памʼять, МБ', o.runtime.memoryMB],
    ['Кластер', o.runtime.cluster],
    ['Node', o.runtime.node],
  ])}
</body></html>`;
}

// Окремий ключ ЛИШЕ для читання огляду: у браузері з телефона заголовок
// X-Admin-Secret не задаси, а тягти туди адмінський секрет через ?key= не можна —
// він відмикає бан і розбан, а URL осідає в історії браузера й логах Render.
// OVERVIEW_KEY не відмикає нічого, крім цієї сторінки; немає змінної — лишається
// тільки заголовок.
const OVERVIEW_KEY = process.env.OVERVIEW_KEY || '';
app.get('/admin/overview', async (req, res) => {
  const byKey = OVERVIEW_KEY && req.query.key === OVERVIEW_KEY;
  if (!byKey && !isAdmin(req)) return res.status(403).json({ ok: false });
  try {
    const o = await collectOverview();
    if (req.query.format === 'html') return res.type('html').send(overviewHtml(o));
    res.json(o);
  } catch (e) {
    console.error('[admin/overview]', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ── Резерв: чи забезпечені монети токенами ───────────────────────────────
//
// Це головне число нової моделі: скільки монет існує проти того, скільки
// токенів замкнено в мості. Якщо забезпечення менше за обіг — виводити зможуть
// не всі, і це має бути видно ДО того, як хтось упреться в порожній гаманець.
async function bridgeTokenBalance() {
  if (!payoutReady()) return null;
  const owner = getPayoutKeypair().publicKey.toBase58();
  const r = await httpPostJson(SOLANA_RPC, {}, {
    jsonrpc: '2.0', id: 1, method: 'getTokenAccountsByOwner',
    params: [owner, { mint: SOLANA_TOKEN_MINT }, { encoding: 'jsonParsed' }],
  });
  const body = JSON.parse(r.body || '{}');
  if (body.error) throw new Error(body.error.message || 'RPC error');
  let total = 0;
  for (const acc of body.result?.value || []) {
    const ui = acc.account?.data?.parsed?.info?.tokenAmount?.uiAmount;
    if (typeof ui === 'number') total += ui;
  }
  return total;
}

app.get('/admin/reserve', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Доступ заборонено' });
  try {
    const { data: circ } = await supabase.rpc('coins_circulating');
    const { data: sup } = await supabase.from('coin_supply')
      .select('burned, deposited, released, float_in').eq('id', 1).single();
    const { data: company } = await supabase.from('users').select('coins').eq('nick', COMPANY_NICK).single();
    // null, а не 0: без міграції функції ще немає, і «0 монет в обігу» було б
    // не фактом, а виглядало б як ідеальне забезпечення.
    const circulating = circ == null ? null : Number(circ);
    const backing = await bridgeTokenBalance();
    const known = circulating != null && backing != null;
    res.json({
      ok: true,
      circulating,                                   // скільки монет існує
      backing,                                       // скільки токенів у мості
      surplus: known ? backing - circulating : null,
      solvent: known ? backing >= circulating : null,
      treasury: Number(company?.coins || 0),
      flows: {
        deposited: Number(sup?.deposited || 0),
        floatIn: Number(sup?.float_in || 0),
        released: Number(sup?.released || 0),
        burned: Number(sup?.burned || 0),
      },
      wallet: payoutReady() ? getPayoutKeypair().publicKey.toBase58() : null,
      cluster: SOLANA_CLUSTER,
    });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

// Влити монети в скарбницю під токени, які вже надіслані в міст.
//
// ⚠️ Приймаємо не суму, а ПІДПИС транзакції: сервер сам питає мережу, скільки
// саме токенів прийшло на гаманець мосту. Інакше це був би той самий кран,
// лише під адмінським ключем. Запис у token_deposits робить дію ідемпотентною:
// той самий підпис не зарахується двічі, і періодичний сканер його не підбере.
app.post('/admin/treasury-credit', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Доступ заборонено' });
  const signature = typeof req.body?.signature === 'string' ? req.body.signature.trim() : '';
  if (!signature) return res.json({ ok: false, error: 'Потрібен підпис транзакції' });
  if (!payoutReady()) return res.json({ ok: false, error: 'Гаманець мосту не налаштований' });
  try {
    const owner = getPayoutKeypair().publicKey.toBase58();
    const r = await httpPostJson(SOLANA_RPC, {}, {
      jsonrpc: '2.0', id: 1, method: 'getTransaction',
      // commitment обовʼязковий: за замовчуванням getTransaction відповідає
      // лише про 'finalized', а щойно підтверджену транзакцію показує як
      // «не знайдено» — і поповнення виглядало б як невдале при вдалому переказі.
      params: [signature, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0, commitment: 'confirmed' }],
    });
    const body = JSON.parse(r.body || '{}');
    const tx = body.result;
    if (!tx) return res.json({ ok: false, error: 'Транзакцію не знайдено' });
    if (tx.meta?.err) return res.json({ ok: false, error: 'Транзакція відхилена мережею' });
    // Приріст саме нашого токена саме на гаманці мосту — рахуємо з балансів
    // до/після, як і для звичайних поповнень.
    const pre = (tx.meta?.preTokenBalances || []).filter(b => b.owner === owner && b.mint === SOLANA_TOKEN_MINT);
    const post = (tx.meta?.postTokenBalances || []).filter(b => b.owner === owner && b.mint === SOLANA_TOKEN_MINT);
    const sum = arr => arr.reduce((a, b) => a + (b.uiTokenAmount?.uiAmount || 0), 0);
    const gained = sum(post) - sum(pre);
    if (!(gained > 0)) return res.json({ ok: false, error: 'Ця транзакція не поповнила гаманець мосту' });
    const coins = Math.floor(gained / TOKEN_PAYOUT_RATE);
    // ⚠️ Рядок за цим підписом уже може існувати: періодичний сканер поповнень
    // бачить будь-який вхідний переказ і записує його — з `status: unmatched`,
    // якщо відправник не є користувачем (а гаманці фондів ним і не є). Тому не
    // «вставити або відмовити», а: зарахувати лише те, що ще не зараховано.
    const { data: prev } = await supabase.from('token_deposits')
      .select('status, nick').eq('signature', signature).maybeSingle();
    if (prev && prev.status === 'credited') {
      return res.json({ ok: false, error: 'Цей підпис уже зараховано' });
    }
    if (prev) {
      // `neq('status','credited')` робить оновлення гонко-безпечним: якщо інший
      // інстанс устиг першим, ми не отримаємо жодного рядка й не нарахуємо вдруге.
      const { data: upd } = await supabase.from('token_deposits')
        .update({ nick: COMPANY_NICK, address: owner, tokens: gained, coins, status: 'credited' })
        .eq('signature', signature).neq('status', 'credited').select('signature');
      if (!upd || upd.length === 0) return res.json({ ok: false, error: 'Цей підпис уже зараховано' });
    } else {
      const { error: insErr } = await supabase.from('token_deposits').insert({
        signature, nick: COMPANY_NICK, address: owner, tokens: gained, coins,
        slot: tx.slot || null, status: 'credited',
      });
      if (insErr) return res.json({ ok: false, error: 'Цей підпис уже зараховано' });
    }
    // Влите з фондів теж забезпечене — його можна забрати назад тим самим мостом.
    await supabase.rpc('add_coins_earned', { p_nick: COMPANY_NICK, p_amount: coins });
    await noteFlow('float_in', coins);
    await logTx({ fromNick: null, toNick: COMPANY_NICK, amount: coins, kind: 'treasury_float', ref: signature });
    const { data: company } = await supabase.from('users').select('coins').eq('nick', COMPANY_NICK).single();
    res.json({ ok: true, credited: coins, tokens: gained, treasury: Number(company?.coins || 0) });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

// Вивести зі скарбниці в токен — щоб платити реальні рахунки.
//
// Це НЕ емісія: монети скарбниці забезпечені токенами, які лежать у мості ще
// відтоді, як їх туди внесли. Вивід звільняє рівно стільки, скільки знищує
// монет, тож обіг і забезпечення зменшуються разом.
app.post('/admin/treasury-payout', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Доступ заборонено' });
  const coins = Math.floor(Number(req.body?.coins));
  const address = typeof req.body?.address === 'string' ? req.body.address.trim() : '';
  if (!Number.isFinite(coins) || coins <= 0) return res.json({ ok: false, error: 'Потрібна сума' });
  if (base58Len(address) !== 32) return res.json({ ok: false, error: 'Адреса недійсна' });
  if (!payoutReady()) return res.json({ ok: false, error: 'Гаманець мосту не налаштований' });
  // Не спорожнити міст: після виводу забезпечення має лишитись не меншим за
  // те, що люди можуть зажадати назад.
  try {
    const { data: circ } = await supabase.rpc('coins_circulating');
    const backing = await bridgeTokenBalance();
    if (backing != null && backing - coins * TOKEN_PAYOUT_RATE < Number(circ || 0) - coins) {
      return res.json({ ok: false, error: 'Після виводу забезпечення стало б меншим за обіг' });
    }
  } catch (e) { return res.json({ ok: false, error: 'Не вдалося перевірити резерв: ' + e.message }); }

  const { data: left, error } = await supabase.rpc('spend_coins', { p_nick: COMPANY_NICK, p_amount: coins });
  if (error || left === -1 || left === null) return res.json({ ok: false, error: 'У скарбниці недостатньо монет' });
  const tokens = coins * TOKEN_PAYOUT_RATE;
  const { data: row } = await supabase.from('token_payouts')
    .insert({ nick: COMPANY_NICK, address, coins, tokens, status: 'pending' }).select('id').single();
  try {
    const { c, tx, signature, lastValidBlockHeight } = await buildPayoutTx(address, tokens);
    if (row) await supabase.from('token_payouts').update({ signature }).eq('id', row.id);
    await c.sendRawTransaction(tx.serialize(), { skipPreflight: false });
    await c.confirmTransaction({ signature, blockhash: tx.recentBlockhash, lastValidBlockHeight }, 'confirmed');
    if (row) await supabase.from('token_payouts')
      .update({ status: 'sent', sent_at: new Date().toISOString() }).eq('id', row.id);
    await noteFlow('released', coins);
    await logTx({ fromNick: COMPANY_NICK, toNick: null, amount: coins, kind: 'treasury_payout', ref: signature });
    res.json({ ok: true, tokens, signature, treasury: left, cluster: SOLANA_CLUSTER });
  } catch (e) {
    // Як і в користувацькій виплаті: не повертаємо наосліп — транзакція могла
    // піти. Заявка лишається pending, resumePendingPayouts спитає мережу.
    console.error('[treasury] payout:', e.message);
    res.json({ ok: false, error: 'Виплата не підтвердилась, заявка лишилась у роботі' });
  }
});

app.get('/admin/ping', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false, error: 'Доступ заборонено', code: 'err_forbidden' });
  res.json({ ok: true, admin: true, message: 'Секрет вірний' });
});

app.get('/admin/reports', async (req, res) => {
  if (!isAdmin(req)) return res.json({ ok: false, error: 'Доступ заборонено', code: 'err_forbidden' });
  const { data } = await supabase.from('reports').select('*').eq('status', 'pending').order('created_at', { ascending: false });
  res.json({ ok: true, reports: data || [] });
});

app.post('/admin/ban', async (req, res) => {
  if (!isAdmin(req)) return res.json({ ok: false, error: 'Доступ заборонено', code: 'err_forbidden' });
  const { targetNick, reason } = req.body;
  await supabase.from('platform_bans').upsert({ nick: targetNick, reason: reason || null, banned_at: Date.now(), banned_by: COMPANY_NICK });
  const t = onlineUsers.get(targetNick); if (t) { t.ws.send(JSON.stringify({ type: 'kicked', reason: 'Акаунт заблоковано', code: 'err_kick_banned' })); t.ws.close(); }
  await destroySessionsForNick(targetNick); // забанений не має лишатись автентифікованим
  res.json({ ok: true });
});

app.post('/admin/unban', async (req, res) => {
  if (!isAdmin(req)) return res.json({ ok: false, error: 'Доступ заборонено', code: 'err_forbidden' });
  const { targetNick } = req.body;
  await supabase.from('platform_bans').delete().eq('nick', targetNick);
  res.json({ ok: true });
});

app.post('/admin/resolve-report', async (req, res) => {
  if (!isAdmin(req)) return res.json({ ok: false, error: 'Доступ заборонено', code: 'err_forbidden' });
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
        if (!userNick) { ws.send(JSON.stringify({ type: 'kicked', reason: 'Сесія недійсна, увійдіть знову', code: 'err_kick_session_invalid' })); ws.close(); return; }
        const { data: ban } = await supabase.from('platform_bans').select('reason').eq('nick', userNick).single();
        if (ban) { ws.send(JSON.stringify({ type: 'kicked', reason: `Акаунт заблоковано: ${ban.reason || 'порушення правил'}`, ...(ban.reason ? { code: 'err_kick_banned_reason', banReason: ban.reason } : { code: 'err_kick_banned' }) })); ws.close(); return; }
        if (onlineUsers.has(userNick)) { const old = onlineUsers.get(userNick); old.ws.send(JSON.stringify({ type: 'kicked', reason: 'Новий пристрій підключився', code: 'err_kick_new_device' })); old.ws.close(); }
        onlineUsers.set(userNick, { ws, lastSeen: Date.now() });
        touchLastSeen(userNick);
        busPublish({ t: 'up', nick: userNick });
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
      if (msg.type === 'connect_request') { if (!sendToUser(msg.to, { type: 'connect_request', from: userNick })) ws.send(JSON.stringify({ type: 'error', error: `${msg.to} не в мережі`, code: 'err_user_offline', nick: msg.to })); }
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
      if (msg.type === 'edit_message') { await supabase.from('messages').update({ content: msg.text }).eq('msg_id', msg.msgId).eq('from_nick', userNick); await markEdited('messages', { msg_id: msg.msgId, from_nick: userNick }); sendToUser(msg.to, { type: 'edit_message', from: userNick, msgId: msg.msgId, text: msg.text }); }
      if (msg.type === 'edit_group_message') { const { data: membership } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId).eq('nick', userNick).single(); if (!membership) return; await supabase.from('group_messages').update({ content: msg.text }).eq('msg_id', msg.msgId).eq('group_id', msg.groupId).eq('from_nick', userNick); await markEdited('group_messages', { msg_id: msg.msgId, group_id: msg.groupId, from_nick: userNick }); await notifyMembers(msg.groupId, { type: 'edit_group_message', groupId: msg.groupId, msgId: msg.msgId, text: msg.text }, userNick); }
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
          ws.send(JSON.stringify({ type: 'call_error', error: 'Абонент недоступний', code: 'err_callee_offline' }));
          return;
        }
        // Глобальний блок вхідних адресата (крім тих, кому він сам написав за блоку).
        if (!(await canReceiveFrom(userNick, msg.to))) {
          ws.send(JSON.stringify({ type: 'call_error', error: 'Абонент не приймає дзвінки', code: 'err_callee_blocks' }));
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
          ws.send(JSON.stringify({ type: 'call_error', error: 'Неможливо дзвонити на цей самий пристрій', code: 'err_call_same_device' }));
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
            ws.send(JSON.stringify({ type: 'call_error', error: `${msg.to} не в мережі`, code: 'err_callee_offline' }));
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
    if (userNick && onlineUsers.get(userNick)?.ws === ws) {
      onlineUsers.delete(userNick);
      busPublish({ t: 'down', nick: userNick });
    }
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

/// Чи посилається на це саме значення ще якийсь запис у базі?
///
/// Потрібно, бо переслана копія несе ТЕ САМЕ значення `file_data`: без
/// перевірки видалення одного поста забирало б файл в усіх, хто його
/// переслав. Рядок самого поста на момент виклику вже видалений, тож
/// перевірка чесна.
async function valueStillReferenced(value) {
  const probes = [
    ['channel_messages', 'file_data'], ['channel_messages', 'image_url'],
    ['channel_comments', 'file_data'],
    ['messages', 'file_data'], ['group_messages', 'file_data'],
  ];
  for (const [table, col] of probes) {
    const { data, error } = await supabase.from(table).select('id').eq(col, value).limit(1);
    // Помилка запиту — вважаємо, що посилання Є: краще лишити зайвий файл,
    // ніж видалити потрібний через збій БД.
    if (error) return true;
    if (data && data.length) return true;
  }
  return false;
}

// Видалення файлу каналу (пост/коментар) зі Storage при видаленні запису.
// Безпечний: пропускає base64/порожнє, ковтає помилки, не блокує відповідь.
async function removeChannelFile(...urls) {
  for (const u of urls) {
    const path = storagePathFromUrl(u);
    if (!path) continue; // base64 або не-Storage URL — нічого видаляти
    if (await valueStillReferenced(u)) { console.log('[channel-cleanup] ще використовується:', path); continue; }
    try {
      await supabase.storage.from('files').remove([path]);
      // Разом із байтами прибираємо й обліковий рядок 2C — інакше він
      // лишався б назавжди вказувати на неіснуючий обʼєкт.
      await supabase.from('file_objects').delete().eq('storage_path', path);
      console.log('[channel-cleanup] removed:', path);
    } catch (e) { console.log('[channel-cleanup] remove error:', path, e.message); }
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

// Мінімальне утримання: файл живе щонайменше стільки, НАВІТЬ коли всі забрали.
// Без цього фото зникало зі Storage за хвилини: «забрав» рахується на НІК, а
// автокеш вхідного (лише фото й голосові) шле file_downloaded одразу після
// отримання. Тобто другий пристрій того ж користувача, перевстановлення чи
// чистка кешу лишали медіа недоступним назавжди — при живому повідомленні в
// історії. Документи цього не мали: їх ніхто не качає автоматично.
const FILE_MIN_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;

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
    // Свіжий файл тримаємо незалежно від того, чи всі забрали (див. константу).
    if (Date.now() < (r.created_at || 0) + FILE_MIN_RETENTION_MS) return true;
    return !(allDownloaded || expired);
  } catch (_) { return false; }
}

async function cleanupFileObjects() {
  const now = Date.now();
  const { data: rows } = await supabase.from('file_objects').select('storage_path, recipients, downloaded_by, created_at, expires_at');
  const list = rows || [];
  if (!list.length) return;
  let removed = 0;
  for (const r of list) {
    const recips = r.recipients || [];
    const dl = new Set(r.downloaded_by || []);
    const allDownloaded = recips.length > 0 && recips.every(x => dl.has(x));
    const expired = now > (r.expires_at || 0);
    if (!allDownloaded && !expired) continue;
    if (now < (r.created_at || 0) + FILE_MIN_RETENTION_MS) continue; // ще свіже
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
server.listen(PORT, () => {
  console.log(`EION сервер запущено на порті ${PORT}`);
  // Заявки, що зависли в pending після падіння чи перезапуску (Render робить це
  // при кожному деплої й після сну). Питаємо мережу, а не переграємо наосліп.
  resumePendingPayouts().catch((e) => console.error('[payout] resume on boot:', e.message));
  setInterval(() => resumePendingPayouts().catch(() => {}), 10 * 60 * 1000).unref();
  // Надходження токена: людина могла надіслати їх, не відкриваючи застосунок.
  setInterval(() => scanTokenDeposits().catch((e) => console.error('[deposit] scan:', e.message)), 5 * 60 * 1000).unref();
});
