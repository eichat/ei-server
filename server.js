const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');
const admin = require('firebase-admin');
const https = require('https');
const httpModule = require('http');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
app.use(express.json({ limit: '20mb' }));

const BCRYPT_ROUNDS = 8;
const REQUIRE_EMAIL_VERIFICATION = false;

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const mailer = nodemailer.createTransport({
  host: 'smtp-relay.brevo.com', port: 587,
  auth: { user: process.env.BREVO_LOGIN, pass: process.env.BREVO_PASSWORD },
});
const onlineUsers = new Map();
const resetCodes = new Map();
const pendingRegistrations = new Map();
const fcmTokens = new Map();
const pendingCallOffers = new Map();
const linkPreviewCache = new Map();

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
}, 120000);

// ── Link Preview ──────────────────────────────
app.get('/link-preview', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.json({ ok: false, error: 'url обов\'язковий' });
  const cached = linkPreviewCache.get(url);
  if (cached) return res.json({ ok: true, ...cached.data });
  try {
    const ytMatch = url.match(/(?:youtube\.com\/watch\?v=|youtu\.be\/)([a-zA-Z0-9_-]{11})/);
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

function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : httpModule;
    const req = client.get(url, { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; EIONBot/1.0)', 'Accept': 'text/html' }, timeout: 8000 }, (resp) => {
      if (resp.statusCode >= 300 && resp.statusCode < 400 && resp.headers.location) return fetchUrl(resp.headers.location).then(resolve).catch(reject);
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

async function sendCallPush(toNick, fromNick, hasVideo, offer) {
  const token = fcmTokens.get(toNick); if (!token) return;
  const callId = `${fromNick}_${toNick}_${Date.now()}`;
  pendingCallOffers.set(callId, { fromNick, toNick, offer: typeof offer === 'string' ? offer : JSON.stringify(offer), hasVideo, expires: Date.now() + 60000 });
  try {
    await admin.messaging().send({ token, data: { type: 'call_offer', from_nick: fromNick, has_video: hasVideo ? 'true' : 'false', call_id: callId }, android: { priority: 'high', ttl: 30000 } });
    console.log(`FCM push відправлено до ${toNick}, callId=${callId}`);
  } catch (e) {
    console.error(`Помилка FCM push до ${toNick}:`, e.message);
    pendingCallOffers.delete(callId);
    if (e.code === 'messaging/registration-token-not-registered') fcmTokens.delete(toNick);
  }
}

async function sendFcmPush(toNick, data) {
  const token = fcmTokens.get(toNick); if (!token) return;
  try { await admin.messaging().send({ token, data, android: { priority: 'high', ttl: 10000 } }); }
  catch (e) { console.error(`FCM push error до ${toNick}:`, e.message); if (e.code === 'messaging/registration-token-not-registered') fcmTokens.delete(toNick); }
}

async function notifyChannelSubscribers(channelId, payload, excludeNick = null) {
  const { data: members } = await supabase.from('channel_members').select('nick').eq('channel_id', channelId);
  for (const m of members || []) {
    if (m.nick === excludeNick) continue;
    const t = onlineUsers.get(m.nick);
    if (t) t.ws.send(JSON.stringify(payload));
  }
}

app.get('/call-offer', (req, res) => {
  const { callId } = req.query; if (!callId) return res.json({ ok: false, error: 'callId обов\'язковий' });
  const data = pendingCallOffers.get(callId); if (!data) return res.json({ ok: false, error: 'Offer не знайдено або застарів' });
  res.json({ ok: true, fromNick: data.fromNick, offer: data.offer, hasVideo: data.hasVideo });
});

app.post('/decline-call', (req, res) => {
  const { fromNick, toNick } = req.body; if (!fromNick || !toNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const target = onlineUsers.get(toNick); if (target) target.ws.send(JSON.stringify({ type: 'call_reject', from: fromNick }));
  res.json({ ok: true });
});

async function sendEmail(to, subject, text) { await mailer.sendMail({ from: 'EI° <eichatserver@gmail.com>', to, subject, text }); }

async function isModOrCreator(groupId, nick) {
  const { data } = await supabase.from('group_members').select('role').eq('group_id', groupId).eq('nick', nick).single();
  return data && (data.role === 'creator' || data.role === 'moderator');
}

async function notifyMembers(groupId, payload, excludeNick = null) {
  const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', groupId);
  for (const m of members || []) { if (m.nick === excludeNick) continue; const t = onlineUsers.get(m.nick); if (t) t.ws.send(JSON.stringify(payload)); }
}

async function sendGroupInvite(groupId, groupName, inviterNick, targetNick) {
  const target = onlineUsers.get(targetNick);
  const payload = { type: 'group_invite', groupId, groupName, inviterNick };
  if (target) target.ws.send(JSON.stringify(payload));
  else await supabase.from('pending_group_invites').upsert({ group_id: groupId, target_nick: targetNick, inviter_nick: inviterNick });
}

// ── Реєстрація / Авторизація ──────────────────
app.post('/register', async (req, res) => {
  const { nick, password, email, color } = req.body;
  if (!nick || nick.trim().length < 2) return res.json({ ok: false, error: 'Нік занадто короткий (мін. 2 символи)' });
  if (!password || password.length < 4) return res.json({ ok: false, error: 'Пароль занадто короткий (мін. 4 символи)' });
  if (!email || !email.includes('@')) return res.json({ ok: false, error: 'Невірний email' });
  const { data: existing } = await supabase.from('users').select('nick').eq('nick_lower', nick.toLowerCase()).single();
  if (existing) return res.json({ ok: false, error: 'Нік вже зайнятий' });
  const { data: emailExists } = await supabase.from('users').select('nick').eq('email', email).single();
  if (emailExists) return res.json({ ok: false, error: 'Цей email вже використовується' });
  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  if (REQUIRE_EMAIL_VERIFICATION) {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    pendingRegistrations.set(email, { nick, passwordHash, color: color || 4280391411, code, expires: Date.now() + 15 * 60 * 1000 });
    try { await sendEmail(email, 'EION — Підтвердження реєстрації', `Ваш код підтвердження: ${code}\n\nКод дійсний 15 хвилин.`); res.json({ ok: true, needVerification: true }); }
    catch (e) { res.json({ ok: false, error: 'Помилка відправки email: ' + e.message }); }
  } else {
    const { error } = await supabase.from('users').insert({ nick, nick_lower: nick.toLowerCase(), password_hash: passwordHash, email, color: color || 4280391411, coins: 50 });
    if (error) return res.json({ ok: false, error: 'Помилка створення акаунта' });
    res.json({ ok: true, needVerification: false });
  }
});

app.post('/verify-email', async (req, res) => {
  const { email, code } = req.body;
  const pending = pendingRegistrations.get(email); if (!pending) return res.json({ ok: false, error: 'Реєстрацію не знайдено' });
  if (Date.now() > pending.expires) return res.json({ ok: false, error: 'Код застарів' });
  if (pending.code !== code) return res.json({ ok: false, error: 'Невірний код' });
  const { error } = await supabase.from('users').insert({ nick: pending.nick, nick_lower: pending.nick.toLowerCase(), password_hash: pending.passwordHash, email, color: pending.color, coins: 50 });
  if (error) return res.json({ ok: false, error: 'Помилка створення акаунта' });
  pendingRegistrations.delete(email); res.json({ ok: true });
});

app.post('/login', async (req, res) => {
  const { nick, password } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  // Перевіряємо бан
  const { data: ban } = await supabase.from('platform_bans').select('reason').eq('nick', user.nick).single();
  if (ban) return res.json({ ok: false, error: `Акаунт заблоковано: ${ban.reason || 'порушення правил'}` });
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
  res.json({ ok: true, nick: user.nick, color: user.color, coins: user.coins || 0, avatar_url: user.avatar_url || null, premium_expires_at: user.premium_expires_at || null, premium_plan: user.premium_plan || null, nick_color: user.nick_color || null });
});

app.post('/forgot', async (req, res) => {
  const { email } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('email', email).single();
  if (!user) return res.json({ ok: false, error: 'Email не знайдено' });
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  resetCodes.set(email, { code, nick: user.nick, expires: Date.now() + 15 * 60 * 1000 });
  try { await sendEmail(email, 'EION — Відновлення пароля', `Ваш код відновлення: ${code}\n\nКод дійсний 15 хвилин.`); res.json({ ok: true }); }
  catch (e) { res.json({ ok: false, error: 'Помилка відправки email' }); }
});

app.post('/reset', async (req, res) => {
  const { email, code, newPassword } = req.body;
  const reset = resetCodes.get(email); if (!reset) return res.json({ ok: false, error: 'Код не знайдено' });
  if (Date.now() > reset.expires) return res.json({ ok: false, error: 'Код застарів' });
  if (reset.code !== code) return res.json({ ok: false, error: 'Невірний код' });
  if (!newPassword || newPassword.length < 4) return res.json({ ok: false, error: 'Пароль занадто короткий' });
  const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  await supabase.from('users').update({ password_hash: passwordHash }).eq('nick_lower', reset.nick.toLowerCase());
  resetCodes.delete(email); res.json({ ok: true });
});

app.post('/update-nick', async (req, res) => {
  const { nick, password, newNick } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const valid = await bcrypt.compare(password, user.password_hash); if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
  if (!newNick || newNick.trim().length < 2) return res.json({ ok: false, error: 'Нік занадто короткий' });
  const { data: exists } = await supabase.from('users').select('nick').eq('nick_lower', newNick.toLowerCase()).single();
  if (exists) return res.json({ ok: false, error: 'Нік вже зайнятий' });
  await supabase.from('users').update({ nick: newNick, nick_lower: newNick.toLowerCase() }).eq('nick_lower', nick.toLowerCase());
  res.json({ ok: true });
});

app.post('/update-password', async (req, res) => {
  const { nick, password, newPassword } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const valid = await bcrypt.compare(password, user.password_hash); if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
  if (!newPassword || newPassword.length < 4) return res.json({ ok: false, error: 'Новий пароль занадто короткий' });
  const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  await supabase.from('users').update({ password_hash: passwordHash }).eq('nick_lower', nick.toLowerCase());
  res.json({ ok: true });
});

app.post('/update-email', async (req, res) => {
  const { nick, password, newEmail } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const valid = await bcrypt.compare(password, user.password_hash); if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
  if (!newEmail || !newEmail.includes('@')) return res.json({ ok: false, error: 'Невірний email' });
  const { data: emailExists } = await supabase.from('users').select('nick').eq('email', newEmail).single();
  if (emailExists) return res.json({ ok: false, error: 'Email вже використовується' });
  await supabase.from('users').update({ email: newEmail }).eq('nick_lower', nick.toLowerCase());
  res.json({ ok: true });
});

app.post('/delete-account', async (req, res) => {
  const { nick, password } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const valid = await bcrypt.compare(password, user.password_hash); if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
  await supabase.from('messages').delete().or(`from_nick.eq.${nick},to_nick.eq.${nick}`);
  await supabase.from('users').delete().eq('nick_lower', nick.toLowerCase());
  onlineUsers.delete(nick); fcmTokens.delete(nick);
  res.json({ ok: true });
});

app.get('/online-users', (req, res) => res.json({ ok: true, users: [...onlineUsers.keys()] }));

app.get('/user-info', async (req, res) => {
  const { nick } = req.query; if (!nick) return res.json({ ok: false, error: 'Нік обов\'язковий' });
  const { data: user } = await supabase.from('users').select('nick, coins, avatar_url, premium_expires_at, premium_plan, nick_color').eq('nick', nick).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  res.json({ ok: true, nick: user.nick, coins: user.coins || 0, avatar_url: user.avatar_url || null, premium_expires_at: user.premium_expires_at || null, premium_plan: user.premium_plan || null, nick_color: user.nick_color || null });
});

app.get('/search-user', async (req, res) => {
  const { nick } = req.query; if (!nick || nick.trim().length < 2) return res.json({ ok: false, error: 'Введіть мін. 2 символи' });
  const { data } = await supabase.from('users').select('nick').ilike('nick_lower', `%${nick.toLowerCase()}%`).limit(10);
  res.json({ ok: true, users: (data || []).map(u => u.nick) });
});

app.post('/unregister', (req, res) => { const { nick } = req.body; if (nick) onlineUsers.delete(nick); res.json({ ok: true }); });
app.post('/register-fcm-token', (req, res) => {
  const { nick, token } = req.body; if (!nick || !token) return res.json({ ok: false, error: 'Невірні параметри' });
  fcmTokens.set(nick, token); res.json({ ok: true });
});

app.post('/update-nick-color', async (req, res) => {
  const { nick, nickColor } = req.body; if (!nick) return res.json({ ok: false, error: 'Нік обов\'язковий' });
  await supabase.from('users').update({ nick_color: nickColor || null }).eq('nick', nick);
  for (const [n, user] of onlineUsers) if (n !== nick) user.ws.send(JSON.stringify({ type: 'nick_color_changed', nick, nickColor: nickColor || null }));
  res.json({ ok: true });
});

app.post('/update-status', async (req, res) => {
  const { nick, status } = req.body; if (!nick) return res.json({ ok: false, error: 'Нік обов\'язковий' });
  const newStatus = status && status.trim().length > 0 ? status.trim().substring(0, 60) : null;
  await supabase.from('users').update({ status: newStatus }).eq('nick', nick);
  for (const [n, user] of onlineUsers) if (n !== nick) user.ws.send(JSON.stringify({ type: 'user_status', nick, status: newStatus }));
  res.json({ ok: true, status: newStatus });
});

app.post('/transfer-coins', async (req, res) => {
  const { fromNick, toNick, amount } = req.body;
  if (!fromNick || !toNick || !amount || amount < 1) return res.json({ ok: false, error: 'Невірні параметри' });
  if (fromNick === toNick) return res.json({ ok: false, error: 'Не можна переказати собі' });
  const { data: sender } = await supabase.from('users').select('coins').eq('nick', fromNick).single();
  if (!sender) return res.json({ ok: false, error: 'Відправника не знайдено' });
  if ((sender.coins || 0) < amount) return res.json({ ok: false, error: 'Недостатньо монет' });
  const { data: receiver } = await supabase.from('users').select('coins').eq('nick', toNick).single();
  if (!receiver) return res.json({ ok: false, error: 'Отримувача не знайдено' });
  await supabase.from('users').update({ coins: (sender.coins || 0) - amount }).eq('nick', fromNick);
  const newReceiverCoins = (receiver.coins || 0) + amount;
  await supabase.from('users').update({ coins: newReceiverCoins }).eq('nick', toNick);
  const senderWs = onlineUsers.get(fromNick); if (senderWs) senderWs.ws.send(JSON.stringify({ type: 'coins_update', amount: -amount, total: (sender.coins || 0) - amount }));
  const receiverWs = onlineUsers.get(toNick); if (receiverWs) receiverWs.ws.send(JSON.stringify({ type: 'coins_received', fromNick, amount, total: newReceiverCoins }));
  res.json({ ok: true, newBalance: (sender.coins || 0) - amount });
});

app.post('/call-log', async (req, res) => {
  const { fromNick, toNick, hasVideo, startedAt, durationSeconds, status } = req.body;
  if (!fromNick || !toNick || !startedAt || !status) return res.json({ ok: false, error: 'Невірні параметри' });
  await supabase.from('call_logs').insert({ from_nick: fromNick, to_nick: toNick, has_video: hasVideo || false, started_at: startedAt, duration_seconds: durationSeconds || null, status });
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

// ── Групи ──────────────────────────────────────
app.post('/group/create', async (req, res) => {
  const { name, creatorNick, members, type } = req.body;
  if (!name || name.trim().length < 1) return res.json({ ok: false, error: 'Назва групи порожня' });
  const groupType = type || 'closed';
  const { data: group, error } = await supabase.from('groups').insert({ name: name.trim(), creator_nick: creatorNick, type: groupType }).select().single();
  if (error) return res.json({ ok: false, error: 'Помилка створення групи' });
  await supabase.from('group_members').insert({ group_id: group.id, nick: creatorNick, role: 'creator' });
  for (const nick of (members || [])) { if (nick === creatorNick) continue; await sendGroupInvite(group.id, group.name, creatorNick, nick); }
  res.json({ ok: true, group: { id: group.id, name: group.name, creator_nick: group.creator_nick, type: group.type }, members: [creatorNick] });
});

app.post('/group/invite-response', async (req, res) => {
  const { groupId, nick, accepted } = req.body;
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
  const result = [];
  for (const g of groups || []) {
    const { data: members } = await supabase.from('group_members').select('nick, role').eq('group_id', g.id);
    result.push({ ...g, members: (members || []).map(m => m.nick), memberRoles: Object.fromEntries((members || []).map(m => [m.nick, m.role])), myRole: roleMap[g.id] });
  }
  res.json({ ok: true, groups: result });
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
  const { groupId, nick } = req.body;
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
  const { groupId, requesterNick, targetNick, approve } = req.body;
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
  const { groupId, requesterNick, groupType } = req.body;
  const { data: member } = await supabase.from('group_members').select('role').eq('group_id', groupId).eq('nick', requesterNick).single();
  if (!member || member.role !== 'creator') return res.json({ ok: false, error: 'Тільки творець може змінювати тип групи' });
  await supabase.from('groups').update({ type: groupType }).eq('id', groupId);
  await notifyMembers(groupId, { type: 'group_type_changed', groupId, groupType });
  res.json({ ok: true });
});

app.post('/group/set-moderator', async (req, res) => {
  const { groupId, requesterNick, targetNick, isModerator } = req.body;
  const { data: member } = await supabase.from('group_members').select('role').eq('group_id', groupId).eq('nick', requesterNick).single();
  if (!member || member.role !== 'creator') return res.json({ ok: false, error: 'Тільки творець може призначати модераторів' });
  const newRole = isModerator ? 'moderator' : 'member';
  await supabase.from('group_members').update({ role: newRole }).eq('group_id', groupId).eq('nick', targetNick);
  await notifyMembers(groupId, { type: 'group_role_changed', groupId, nick: targetNick, role: newRole });
  res.json({ ok: true });
});

app.post('/group/add-member', async (req, res) => {
  const { groupId, requesterNick, newNick } = req.body;
  if (!(await isModOrCreator(groupId, requesterNick))) return res.json({ ok: false, error: 'Тільки модератор або творець може запрошувати учасників' });
  const { data: existing } = await supabase.from('group_members').select('nick').eq('group_id', groupId).eq('nick', newNick).single();
  if (existing) return res.json({ ok: false, error: 'Користувач вже в групі' });
  const { data: group } = await supabase.from('groups').select('name').eq('id', groupId).single();
  await sendGroupInvite(groupId, group.name, requesterNick, newNick);
  res.json({ ok: true, invited: true });
});

app.post('/group/remove-member', async (req, res) => {
  const { groupId, requesterNick, targetNick } = req.body;
  if (requesterNick !== targetNick && !(await isModOrCreator(groupId, requesterNick))) return res.json({ ok: false, error: 'Тільки модератор або творець може видаляти учасників' });
  await supabase.from('group_members').delete().eq('group_id', groupId).eq('nick', targetNick);
  const target = onlineUsers.get(targetNick); if (target) target.ws.send(JSON.stringify({ type: 'group_removed', groupId }));
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
  const { groupId, requesterNick } = req.body;
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

app.get('/group/messages', async (req, res) => {
  const { groupId } = req.query;
  const { data } = await supabase.from('group_messages').select('*').eq('group_id', groupId).order('timestamp', { ascending: true });
  res.json({ ok: true, messages: (data || []).map(m => ({ ...m, type: m.type || 'text', file_name: m.file_name || null, file_data: m.file_data || null, waveform: m.waveform || null })) });
});

app.get('/ping', (req, res) => res.json({ ok: true }));

// ── Канали ──────────────────────────────────────
app.post('/channel/create', async (req, res) => {
  const { ownerNick, name, description, type } = req.body;
  if (!ownerNick || !name || name.trim().length < 1) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: channel, error } = await supabase.from('channels').insert({ name: name.trim(), description: description || null, owner_nick: ownerNick, type: type || 'public', created_at: Date.now() }).select().single();
  if (error) return res.json({ ok: false, error: 'Помилка створення каналу' });
  await supabase.from('channel_members').insert({ channel_id: channel.id, nick: ownerNick, role: 'owner' });
  res.json({ ok: true, channel });
});

app.get('/channel/list', async (req, res) => {
  const { nick } = req.query; if (!nick) return res.json({ ok: false, error: 'nick обов\'язковий' });
  const { data: memberships } = await supabase.from('channel_members').select('channel_id, role').eq('nick', nick);
  if (!memberships || memberships.length === 0) return res.json({ ok: true, channels: [] });
  const ids = memberships.map(m => m.channel_id);
  const roleMap = Object.fromEntries(memberships.map(m => [m.channel_id, m.role]));
  const { data: channels } = await supabase.from('channels').select('*').in('id', ids);
  const result = [];
  for (const c of channels || []) {
    const { count } = await supabase.from('channel_members').select('*', { count: 'exact', head: true }).eq('channel_id', c.id);
    result.push({ ...c, myRole: roleMap[c.id], subscriberCount: count || 0 });
  }
  res.json({ ok: true, channels: result });
});

app.get('/channel/search', async (req, res) => {
  const { query, nick } = req.query;
  if (!query || query.trim().length < 2) return res.json({ ok: false, error: 'Введіть мін. 2 символи' });
  const { data: channels } = await supabase.from('channels').select('*').ilike('name', `%${query}%`).eq('type', 'public');
  const result = [];
  for (const c of channels || []) {
    const { data: membership } = await supabase.from('channel_members').select('role').eq('channel_id', c.id).eq('nick', nick).single();
    const { count } = await supabase.from('channel_members').select('*', { count: 'exact', head: true }).eq('channel_id', c.id);
    result.push({ ...c, myRole: membership?.role || null, subscriberCount: count || 0 });
  }
  res.json({ ok: true, channels: result });
});

app.post('/channel/subscribe', async (req, res) => {
  const { channelId, nick } = req.body; if (!channelId || !nick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', nick).single();
  if (blocked) return res.json({ ok: false, error: 'Ви заблоковані в цьому каналі' });
  const { data: existing } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  if (existing) return res.json({ ok: false, error: 'Ви вже підписані' });
  await supabase.from('channel_members').insert({ channel_id: channelId, nick, role: 'subscriber' });
  res.json({ ok: true });
});

app.post('/channel/unsubscribe', async (req, res) => {
  const { channelId, nick } = req.body; if (!channelId || !nick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', nick).single();
  if (!member) return res.json({ ok: false, error: 'Ви не підписані' });
  if (member.role === 'owner') return res.json({ ok: false, error: 'Власник не може відписатись — видаліть канал' });
  await supabase.from('channel_members').delete().eq('channel_id', channelId).eq('nick', nick);
  res.json({ ok: true });
});

app.get('/channel/messages', async (req, res) => {
  const { channelId } = req.query; if (!channelId) return res.json({ ok: false, error: 'channelId обов\'язковий' });
  const { data: posts } = await supabase.from('channel_messages').select('*').eq('channel_id', channelId).order('timestamp', { ascending: true });
  // Додаємо кількість коментарів і реакції до кожного поста
  const result = [];
  for (const p of posts || []) {
    const { count: commentCount } = await supabase.from('channel_comments').select('*', { count: 'exact', head: true }).eq('post_id', p.id);
    const { data: reactions } = await supabase.from('channel_reactions').select('emoji, nick').eq('post_id', p.id);
    const { data: topCommenters } = await supabase.from('channel_comments').select('from_nick').eq('post_id', p.id).order('timestamp', { ascending: false }).limit(3);
    result.push({ ...p, commentCount: commentCount || 0, reactions: reactions || [], topCommenters: [...new Set((topCommenters || []).map(c => c.from_nick))].slice(0, 3) });
  }
  res.json({ ok: true, messages: result });
});

app.post('/channel/message', async (req, res) => {
  const { channelId, fromNick, text, imageUrl } = req.body;
  if (!channelId || !fromNick || (!text && !imageUrl)) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', fromNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Тільки власник або адмін може писати' });
  const ts = Date.now(); const msgId = `ch_${channelId}_${ts}`;
  const { data: msg } = await supabase.from('channel_messages').insert({ channel_id: channelId, from_nick: fromNick, content: text || null, image_url: imageUrl || null, timestamp: ts, msg_id: msgId }).select().single();
  await notifyChannelSubscribers(channelId, { type: 'channel_message', channelId, postId: msg.id, from: fromNick, text: text || null, imageUrl: imageUrl || null, timestamp: ts, msgId }, fromNick);
  res.json({ ok: true, message: { ...msg, commentCount: 0, reactions: [], topCommenters: [] } });
});

// Коментарі
app.get('/channel/comments', async (req, res) => {
  const { postId } = req.query; if (!postId) return res.json({ ok: false, error: 'postId обов\'язковий' });
  const { data } = await supabase.from('channel_comments').select('*').eq('post_id', postId).order('timestamp', { ascending: true });
  res.json({ ok: true, comments: data || [] });
});

app.post('/channel/comment', async (req, res) => {
  const { channelId, postId, fromNick, text } = req.body;
  if (!channelId || !postId || !fromNick || !text) return res.json({ ok: false, error: 'Невірні параметри' });
  // Перевіряємо чи не заблокований
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', fromNick).single();
  if (blocked) return res.json({ ok: false, error: 'Ви заблоковані в цьому каналі' });
  // Перевіряємо чи підписаний
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', fromNick).single();
  if (!member) return res.json({ ok: false, error: 'Підпишіться на канал щоб коментувати' });
  const ts = Date.now();
  const { data: comment } = await supabase.from('channel_comments').insert({ channel_id: channelId, post_id: postId, from_nick: fromNick, content: text, timestamp: ts }).select().single();
  // Сповіщаємо підписників
  await notifyChannelSubscribers(channelId, { type: 'channel_comment', channelId, postId, from: fromNick, text, timestamp: ts, commentId: comment.id }, fromNick);
  res.json({ ok: true, comment });
});

app.delete('/channel/comment', async (req, res) => {
  const { commentId, channelId, requesterNick } = req.body;
  if (!commentId || !channelId || !requesterNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: comment } = await supabase.from('channel_comments').select('from_nick').eq('id', commentId).single();
  if (!comment) return res.json({ ok: false, error: 'Коментар не знайдено' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', requesterNick).single();
  const canDelete = comment.from_nick === requesterNick || (member && ['owner', 'admin'].includes(member.role));
  if (!canDelete) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channel_comments').delete().eq('id', commentId);
  res.json({ ok: true });
});

// Реакції на пости
app.post('/channel/reaction', async (req, res) => {
  const { postId, channelId, nick, emoji } = req.body;
  if (!postId || !channelId || !nick || !emoji) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: blocked } = await supabase.from('channel_blocked').select('id').eq('channel_id', channelId).eq('nick', nick).single();
  if (blocked) return res.json({ ok: false, error: 'Ви заблоковані' });
  // Toggle реакцію
  const { data: existing } = await supabase.from('channel_reactions').select('id').eq('post_id', postId).eq('nick', nick).eq('emoji', emoji).single();
  if (existing) {
    await supabase.from('channel_reactions').delete().eq('id', existing.id);
  } else {
    await supabase.from('channel_reactions').insert({ post_id: postId, nick, emoji });
  }
  const { data: reactions } = await supabase.from('channel_reactions').select('emoji, nick').eq('post_id', postId);
  await notifyChannelSubscribers(channelId, { type: 'channel_reaction', channelId, postId, reactions }, null);
  res.json({ ok: true, reactions: reactions || [] });
});

// Модерація каналу
app.post('/channel/block-subscriber', async (req, res) => {
  const { channelId, ownerNick, targetNick } = req.body;
  if (!channelId || !ownerNick || !targetNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channel_blocked').upsert({ channel_id: channelId, nick: targetNick, blocked_at: Date.now() });
  // Якщо підписаний — не видаляємо, просто блокуємо коментарі
  res.json({ ok: true });
});

app.post('/channel/unblock-subscriber', async (req, res) => {
  const { channelId, ownerNick, targetNick } = req.body;
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channel_blocked').delete().eq('channel_id', channelId).eq('nick', targetNick);
  res.json({ ok: true });
});

app.post('/channel/remove-subscriber', async (req, res) => {
  const { channelId, ownerNick, targetNick } = req.body;
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || !['owner', 'admin'].includes(member.role)) return res.json({ ok: false, error: 'Недостатньо прав' });
  await supabase.from('channel_members').delete().eq('channel_id', channelId).eq('nick', targetNick);
  const t = onlineUsers.get(targetNick); if (t) t.ws.send(JSON.stringify({ type: 'channel_removed', channelId }));
  res.json({ ok: true });
});

app.post('/channel/set-admin', async (req, res) => {
  const { channelId, ownerNick, targetNick, isAdmin } = req.body;
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

// Написати автору (100 EION: 70 → автору, 30 → eion_company)
app.post('/channel/contact-owner', async (req, res) => {
  const { channelId, fromNick } = req.body;
  if (!channelId || !fromNick) return res.json({ ok: false, error: 'Невірні параметри' });
  const CONTACT_PRICE = 100; const OWNER_SHARE = 70; const COMPANY_SHARE = 30; const COMPANY_NICK = 'eion_company';
  const { data: channel } = await supabase.from('channels').select('owner_nick').eq('id', channelId).single();
  if (!channel) return res.json({ ok: false, error: 'Канал не знайдено' });
  if (channel.owner_nick === fromNick) return res.json({ ok: false, error: 'Ви є власником каналу' });
  const { data: sender } = await supabase.from('users').select('coins').eq('nick', fromNick).single();
  if (!sender || (sender.coins || 0) < CONTACT_PRICE) return res.json({ ok: false, error: 'Недостатньо EION монет (потрібно 100)' });
  const { data: owner } = await supabase.from('users').select('coins').eq('nick', channel.owner_nick).single();
  if (!owner) return res.json({ ok: false, error: 'Власника каналу не знайдено' });
  await supabase.from('users').update({ coins: (sender.coins || 0) - CONTACT_PRICE }).eq('nick', fromNick);
  await supabase.from('users').update({ coins: (owner.coins || 0) + OWNER_SHARE }).eq('nick', channel.owner_nick);
  const { data: company } = await supabase.from('users').select('coins').eq('nick', COMPANY_NICK).single();
  if (company) await supabase.from('users').update({ coins: (company.coins || 0) + COMPANY_SHARE }).eq('nick', COMPANY_NICK);
  const senderWs = onlineUsers.get(fromNick); if (senderWs) senderWs.ws.send(JSON.stringify({ type: 'coins_update', amount: -CONTACT_PRICE, total: (sender.coins || 0) - CONTACT_PRICE }));
  const ownerWs = onlineUsers.get(channel.owner_nick); if (ownerWs) ownerWs.ws.send(JSON.stringify({ type: 'coins_received', fromNick, amount: OWNER_SHARE, total: (owner.coins || 0) + OWNER_SHARE }));
  res.json({ ok: true, ownerNick: channel.owner_nick });
});

app.post('/channel/delete', async (req, res) => {
  const { channelId, ownerNick } = req.body;
  const { data: member } = await supabase.from('channel_members').select('role').eq('channel_id', channelId).eq('nick', ownerNick).single();
  if (!member || member.role !== 'owner') return res.json({ ok: false, error: 'Тільки власник може видалити канал' });
  await supabase.from('channel_comments').delete().eq('channel_id', channelId);
  await supabase.from('channel_reactions').delete().in('post_id', (await supabase.from('channel_messages').select('id').eq('channel_id', channelId)).data?.map(m => m.id) || []);
  await supabase.from('channel_messages').delete().eq('channel_id', channelId);
  await supabase.from('channel_members').delete().eq('channel_id', channelId);
  await supabase.from('channel_blocked').delete().eq('channel_id', channelId);
  await supabase.from('channels').delete().eq('id', channelId);
  res.json({ ok: true });
});

// ── Модерація платформи ────────────────────────
app.post('/report', async (req, res) => {
  const { reporterNick, targetNick, reason, context } = req.body;
  if (!reporterNick || !targetNick) return res.json({ ok: false, error: 'Невірні параметри' });
  await supabase.from('reports').insert({ reporter_nick: reporterNick, target_nick: targetNick, reason: reason || null, context: context || null, created_at: Date.now() });
  res.json({ ok: true });
});

app.get('/admin/reports', async (req, res) => {
  const { adminNick } = req.query;
  if (adminNick !== 'eion_company') return res.json({ ok: false, error: 'Доступ заборонено' });
  const { data } = await supabase.from('reports').select('*').eq('status', 'pending').order('created_at', { ascending: false });
  res.json({ ok: true, reports: data || [] });
});

app.post('/admin/ban', async (req, res) => {
  const { adminNick, targetNick, reason } = req.body;
  if (adminNick !== 'eion_company') return res.json({ ok: false, error: 'Доступ заборонено' });
  await supabase.from('platform_bans').upsert({ nick: targetNick, reason: reason || null, banned_at: Date.now(), banned_by: adminNick });
  // Закриваємо активну сесію
  const t = onlineUsers.get(targetNick); if (t) { t.ws.send(JSON.stringify({ type: 'kicked', reason: 'Акаунт заблоковано' })); t.ws.close(); }
  res.json({ ok: true });
});

app.post('/admin/unban', async (req, res) => {
  const { adminNick, targetNick } = req.body;
  if (adminNick !== 'eion_company') return res.json({ ok: false, error: 'Доступ заборонено' });
  await supabase.from('platform_bans').delete().eq('nick', targetNick);
  res.json({ ok: true });
});

app.post('/admin/resolve-report', async (req, res) => {
  const { adminNick, reportId } = req.body;
  if (adminNick !== 'eion_company') return res.json({ ok: false, error: 'Доступ заборонено' });
  await supabase.from('reports').update({ status: 'resolved' }).eq('id', reportId);
  res.json({ ok: true });
});

// ── WebSocket ────────────────────────────────
wss.on('connection', (ws) => {
  let userNick = null;
  ws.on('message', async (raw) => {
    try {
      const msg = JSON.parse(raw);

      if (msg.type === 'login') {
        userNick = msg.nick;
        // Перевіряємо бан
        const { data: ban } = await supabase.from('platform_bans').select('reason').eq('nick', userNick).single();
        if (ban) { ws.send(JSON.stringify({ type: 'kicked', reason: `Акаунт заблоковано: ${ban.reason || 'порушення правил'}` })); ws.close(); return; }
        if (onlineUsers.has(userNick)) { const old = onlineUsers.get(userNick); old.ws.send(JSON.stringify({ type: 'kicked', reason: 'Новий пристрій підключився' })); old.ws.close(); }
        onlineUsers.set(userNick, { ws, lastSeen: Date.now() });
        ws.send(JSON.stringify({ type: 'login_ok' }));
        for (const [nick, user] of onlineUsers) { if (nick !== userNick) user.ws.send(JSON.stringify({ type: 'user_online', nick: userNick })); }

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
          for (const m of pending) ws.send(JSON.stringify(m.type === 'file' ? { type: 'file_message', from: m.from_nick, fileName: m.file_name, data: m.file_data, timestamp: m.timestamp, msgId: m.msg_id, ...(m.waveform ? { waveform: JSON.parse(m.waveform) } : {}) } : { type: 'chat_message', from: m.from_nick, text: m.content, msgId: m.msg_id, timestamp: m.timestamp }));
          await supabase.from('messages').update({ delivered: true }).eq('to_nick', userNick).eq('delivered', false);
        }

        const { data: myGroups } = await supabase.from('group_members').select('group_id').eq('nick', userNick);
        if (myGroups && myGroups.length > 0) {
          for (const gm of myGroups) {
            const { data: pendingGroup } = await supabase.from('group_messages').select('*').eq('group_id', gm.group_id).not('delivered_to', 'cs', `{"${userNick}"}`).order('timestamp', { ascending: true });
            if (pendingGroup && pendingGroup.length > 0) { for (const m of pendingGroup) {
              if (m.type === 'file') ws.send(JSON.stringify({ type: 'file_message', groupId: m.group_id, from: m.from_nick, fileName: m.file_name, data: m.file_data, timestamp: m.timestamp, msgId: m.msg_id, ...(m.waveform ? { waveform: m.waveform } : {}) }));
              else ws.send(JSON.stringify({ type: 'group_message', groupId: m.group_id, from: m.from_nick, text: m.content, timestamp: m.timestamp, msgId: m.msg_id }));
              await supabase.from('group_messages').update({ delivered_to: [...(m.delivered_to || []), userNick] }).eq('id', m.id);
            } }
          }
        }

        const { data: pendingReactions } = await supabase.from('pending_reactions').select('*').eq('to_nick', userNick);
        if (pendingReactions && pendingReactions.length > 0) { for (const r of pendingReactions) ws.send(JSON.stringify({ type: 'reaction', msgId: r.msg_id, emoji: r.emoji, from: r.from_nick, chatNick: r.chat_nick, groupId: r.group_id })); await supabase.from('pending_reactions').delete().eq('to_nick', userNick); }

        const { data: modGroups } = await supabase.from('group_members').select('group_id').eq('nick', userNick).in('role', ['creator', 'moderator']);
        if (modGroups && modGroups.length > 0) { for (const gm of modGroups) { const { data: reqs } = await supabase.from('group_join_requests').select('nick').eq('group_id', gm.group_id).eq('status', 'pending'); if (reqs && reqs.length > 0) { const { data: g } = await supabase.from('groups').select('name').eq('id', gm.group_id).single(); for (const r of reqs) ws.send(JSON.stringify({ type: 'group_join_request', groupId: gm.group_id, groupName: g?.name, nick: r.nick })); } } }

        const { data: groupInvites } = await supabase.from('pending_group_invites').select('*').eq('target_nick', userNick);
        if (groupInvites && groupInvites.length > 0) {
          for (const inv of groupInvites) { const { data: g } = await supabase.from('groups').select('name').eq('id', inv.group_id).single(); if (g) ws.send(JSON.stringify({ type: 'group_invite', groupId: inv.group_id, groupName: g.name, inviterNick: inv.inviter_nick })); }
        }
      }

      if (msg.type === 'register_fcm_token') { if (userNick && msg.token) fcmTokens.set(userNick, msg.token); }
      if (msg.type === 'check_online') ws.send(JSON.stringify({ type: 'online_status', nick: msg.nick, online: onlineUsers.has(msg.nick) }));
      if (msg.type === 'connect_request') { const target = onlineUsers.get(msg.to); if (target) target.ws.send(JSON.stringify({ type: 'connect_request', from: userNick })); else ws.send(JSON.stringify({ type: 'error', error: `${msg.to} не в мережі` })); }
      if (msg.type === 'connect_response') { const target = onlineUsers.get(msg.to); if (target) target.ws.send(JSON.stringify({ type: 'connect_response', from: userNick, accepted: msg.accepted })); }

      if (msg.type === 'chat_message') {
        const ts = Date.now(); const target = onlineUsers.get(msg.to); const msgId = msg.msgId || null;
        const status = target ? 'delivered' : 'sent';
        await supabase.from('messages').insert({ from_nick: userNick, to_nick: msg.to, type: 'text', content: msg.text, timestamp: ts, delivered: !!target, msg_id: msgId, status });
        if (target) { target.ws.send(JSON.stringify({ type: 'chat_message', from: userNick, text: msg.text, timestamp: ts, msgId })); if (msgId && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'status_update', status: 'delivered', msgIds: [msgId] })); }
      }

      if (msg.type === 'file_message') {
        const ts = Date.now(); const msgId = msg.msgId || null;
        if (msg.groupId) {
          const { data: membership } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId).eq('nick', userNick).single();
          if (!membership) return;
          const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId);
          const onlineMembers = (members || []).map(m => m.nick).filter(n => n !== userNick && onlineUsers.has(n));
          await supabase.from('group_messages').insert({ group_id: msg.groupId, from_nick: userNick, content: msg.fileName, timestamp: ts, msg_id: msgId, delivered_to: [userNick, ...onlineMembers], type: 'file', file_name: msg.fileName, file_data: msg.data, ...(msg.waveform ? { waveform: msg.waveform } : {}) });
          for (const nick of onlineMembers) onlineUsers.get(nick).ws.send(JSON.stringify({ type: 'file_message', groupId: msg.groupId, from: userNick, fileName: msg.fileName, fileSize: msg.fileSize, data: msg.data, timestamp: ts, msgId, ...(msg.waveform ? { waveform: msg.waveform } : {}) }));
        } else {
          const target = onlineUsers.get(msg.to); const status = target ? 'delivered' : 'sent';
          await supabase.from('messages').insert({ from_nick: userNick, to_nick: msg.to, type: 'file', content: msg.fileName, file_name: msg.fileName, file_data: msg.data, timestamp: ts, delivered: !!target, msg_id: msgId, status, ...(msg.waveform ? { waveform: JSON.stringify(msg.waveform) } : {}) });
          if (target) { target.ws.send(JSON.stringify({ type: 'file_message', from: userNick, fileName: msg.fileName, fileSize: msg.fileSize, data: msg.data, timestamp: ts, msgId, ...(msg.waveform ? { waveform: msg.waveform } : {}) })); if (msgId && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'status_update', status: 'delivered', msgIds: [msgId] })); }
        }
      }

      if (msg.type === 'group_message') {
        const ts = Date.now(); const msgId = msg.msgId || `${userNick}_g${msg.groupId}_${ts}`;
        const { data: membership } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId).eq('nick', userNick).single();
        if (!membership) return;
        const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId);
        const onlineMembers = (members || []).map(m => m.nick).filter(n => n !== userNick && onlineUsers.has(n));
        await supabase.from('group_messages').insert({ group_id: msg.groupId, from_nick: userNick, content: msg.text, timestamp: ts, msg_id: msgId, delivered_to: [userNick, ...onlineMembers] });
        for (const nick of onlineMembers) onlineUsers.get(nick).ws.send(JSON.stringify({ type: 'group_message', groupId: msg.groupId, from: userNick, text: msg.text, timestamp: ts, msgId }));
      }

      if (msg.type === 'ei_message') { /* нарахування прибрано */ }
      if (msg.type === 'group_typing') { const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId); for (const m of members || []) { if (m.nick !== userNick) { const t = onlineUsers.get(m.nick); if (t) t.ws.send(JSON.stringify({ type: 'group_typing', groupId: msg.groupId, from: userNick })); } } }
      if (msg.type === 'reaction') { const { msgId, emoji, chatNick, groupId } = msg; const payload = { type: 'reaction', msgId, emoji, from: userNick, chatNick, groupId }; if (groupId) { const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', groupId); for (const m of members || []) { if (m.nick === userNick) continue; const t = onlineUsers.get(m.nick); if (t) t.ws.send(JSON.stringify(payload)); else await supabase.from('pending_reactions').insert({ msg_id: msgId, emoji, from_nick: userNick, to_nick: m.nick, group_id: groupId, chat_nick: null }); } } else if (chatNick) { const target = onlineUsers.get(chatNick); if (target) target.ws.send(JSON.stringify(payload)); else await supabase.from('pending_reactions').insert({ msg_id: msgId, emoji, from_nick: userNick, to_nick: chatNick, chat_nick: chatNick, group_id: null }); } }
      if (msg.type === 'edit_message') { const target = onlineUsers.get(msg.to); if (target) target.ws.send(JSON.stringify({ type: 'edit_message', from: userNick, msgId: msg.msgId, text: msg.text })); }
      if (msg.type === 'edit_group_message') { const { data: membership } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId).eq('nick', userNick).single(); if (!membership) return; await supabase.from('group_messages').update({ content: msg.text }).eq('msg_id', msg.msgId).eq('group_id', msg.groupId).eq('from_nick', userNick); await notifyMembers(msg.groupId, { type: 'edit_group_message', groupId: msg.groupId, msgId: msg.msgId, text: msg.text }, userNick); }
      if (msg.type === 'delete_group_message') { const { data: gMsg } = await supabase.from('group_messages').select('from_nick').eq('msg_id', msg.msgId).single(); if (!gMsg || (gMsg.from_nick !== userNick && !(await isModOrCreator(msg.groupId, userNick)))) return; await supabase.from('group_messages').delete().eq('msg_id', msg.ms
