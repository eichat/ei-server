const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json({ limit: '10mb' }));

// ── Supabase ────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// ── Онлайн користувачі (в пам'яті) ─────────
const onlineUsers = new Map();
const resetCodes = new Map();
const pendingRegistrations = new Map();

// ── Email ───────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// ── REST API ────────────────────────────────

app.post('/register', async (req, res) => {
  const { nick, password, email, color } = req.body;
  if (!nick || nick.trim().length < 2)
    return res.json({ ok: false, error: 'Нік занадто короткий (мін. 2 символи)' });
  if (!password || password.length < 4)
    return res.json({ ok: false, error: 'Пароль занадто короткий (мін. 4 символи)' });
  if (!email || !email.includes('@'))
    return res.json({ ok: false, error: 'Невірний email' });

  const { data: existing } = await supabase
    .from('users').select('nick').eq('nick_lower', nick.toLowerCase()).single();
  if (existing) return res.json({ ok: false, error: 'Нік вже зайнятий' });

  const { data: emailExists } = await supabase
    .from('users').select('nick').eq('email', email).single();
  if (emailExists) return res.json({ ok: false, error: 'Цей email вже використовується' });

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  pendingRegistrations.set(email, {
    nick, passwordHash: hashPassword(password),
    color: color || 4280391411, code,
    expires: Date.now() + 15 * 60 * 1000,
  });

  try {
    await transporter.sendMail({
      from: process.env.GMAIL_USER, to: email,
      subject: 'EI° — Підтвердження реєстрації',
      text: `Ваш код підтвердження: ${code}\n\nКод дійсний 15 хвилин.`,
    });
    res.json({ ok: true, needVerification: true });
  } catch (e) {
    res.json({ ok: false, error: 'Помилка відправки email' });
  }
});

app.post('/verify-email', async (req, res) => {
  const { email, code } = req.body;
  const pending = pendingRegistrations.get(email);
  if (!pending) return res.json({ ok: false, error: 'Реєстрацію не знайдено' });
  if (Date.now() > pending.expires) return res.json({ ok: false, error: 'Код застарів' });
  if (pending.code !== code) return res.json({ ok: false, error: 'Невірний код' });

  const { error } = await supabase.from('users').insert({
    nick: pending.nick, nick_lower: pending.nick.toLowerCase(),
    password_hash: pending.passwordHash, email, color: pending.color,
  });
  if (error) return res.json({ ok: false, error: 'Помилка створення акаунта' });
  pendingRegistrations.delete(email);
  res.json({ ok: true });
});

app.post('/login', async (req, res) => {
  const { nick, password } = req.body;
  const { data: user } = await supabase
    .from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  if (user.password_hash !== hashPassword(password))
    return res.json({ ok: false, error: 'Невірний пароль' });
  res.json({ ok: true, nick: user.nick, color: user.color });
});

app.post('/forgot', async (req, res) => {
  const { email } = req.body;
  const { data: user } = await supabase
    .from('users').select('*').eq('email', email).single();
  if (!user) return res.json({ ok: false, error: 'Email не знайдено' });

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  resetCodes.set(email, { code, nick: user.nick, expires: Date.now() + 15 * 60 * 1000 });

  try {
    await transporter.sendMail({
      from: process.env.GMAIL_USER, to: email,
      subject: 'EI° — Відновлення пароля',
      text: `Ваш код відновлення: ${code}\n\nКод дійсний 15 хвилин.`,
    });
    res.json({ ok: true });
  } catch (e) {
    res.json({ ok: false, error: 'Помилка відправки email' });
  }
});

app.post('/reset', async (req, res) => {
  const { email, code, newPassword } = req.body;
  const reset = resetCodes.get(email);
  if (!reset) return res.json({ ok: false, error: 'Код не знайдено' });
  if (Date.now() > reset.expires) return res.json({ ok: false, error: 'Код застарів' });
  if (reset.code !== code) return res.json({ ok: false, error: 'Невірний код' });
  if (!newPassword || newPassword.length < 4)
    return res.json({ ok: false, error: 'Пароль занадто короткий' });

  await supabase.from('users')
    .update({ password_hash: hashPassword(newPassword) })
    .eq('nick_lower', reset.nick.toLowerCase());
  resetCodes.delete(email);
  res.json({ ok: true });
});

app.post('/update-nick', async (req, res) => {
  const { nick, password, newNick } = req.body;
  const { data: user } = await supabase
    .from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  if (user.password_hash !== hashPassword(password))
    return res.json({ ok: false, error: 'Невірний пароль' });
  if (!newNick || newNick.trim().length < 2)
    return res.json({ ok: false, error: 'Нік занадто короткий' });

  const { data: exists } = await supabase
    .from('users').select('nick').eq('nick_lower', newNick.toLowerCase()).single();
  if (exists) return res.json({ ok: false, error: 'Нік вже зайнятий' });

  await supabase.from('users')
    .update({ nick: newNick, nick_lower: newNick.toLowerCase() })
    .eq('nick_lower', nick.toLowerCase());
  res.json({ ok: true });
});

app.post('/update-password', async (req, res) => {
  const { nick, password, newPassword } = req.body;
  const { data: user } = await supabase
    .from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  if (user.password_hash !== hashPassword(password))
    return res.json({ ok: false, error: 'Невірний пароль' });
  if (!newPassword || newPassword.length < 4)
    return res.json({ ok: false, error: 'Новий пароль занадто короткий' });

  await supabase.from('users')
    .update({ password_hash: hashPassword(newPassword) })
    .eq('nick_lower', nick.toLowerCase());
  res.json({ ok: true });
});

app.post('/update-email', async (req, res) => {
  const { nick, password, newEmail } = req.body;
  const { data: user } = await supabase
    .from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  if (user.password_hash !== hashPassword(password))
    return res.json({ ok: false, error: 'Невірний пароль' });
  if (!newEmail || !newEmail.includes('@'))
    return res.json({ ok: false, error: 'Невірний email' });

  const { data: emailExists } = await supabase
    .from('users').select('nick').eq('email', newEmail).single();
  if (emailExists) return res.json({ ok: false, error: 'Email вже використовується' });

  await supabase.from('users').update({ email: newEmail }).eq('nick_lower', nick.toLowerCase());
  res.json({ ok: true });
});

app.post('/delete-account', async (req, res) => {
  const { nick, password } = req.body;
  const { data: user } = await supabase
    .from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  if (user.password_hash !== hashPassword(password))
    return res.json({ ok: false, error: 'Невірний пароль' });

  await supabase.from('messages').delete().or(`from_nick.eq.${nick},to_nick.eq.${nick}`);
  await supabase.from('users').delete().eq('nick_lower', nick.toLowerCase());
  onlineUsers.delete(nick);
  res.json({ ok: true });
});

app.get('/online-users', (req, res) => {
  res.json({ ok: true, users: [...onlineUsers.keys()] });
});

app.get('/search-user', async (req, res) => {
  const { nick } = req.query;
  if (!nick || nick.trim().length < 2)
    return res.json({ ok: false, error: 'Введіть мін. 2 символи' });
  const { data } = await supabase
    .from('users').select('nick')
    .ilike('nick_lower', `%${nick.toLowerCase()}%`)
    .limit(10);
  res.json({ ok: true, users: (data || []).map(u => u.nick) });
});

app.post('/unregister', (req, res) => {
  const { nick } = req.body;
  if (nick) onlineUsers.delete(nick);
  res.json({ ok: true });
});

// ── WebSocket ───────────────────────────────
wss.on('connection', (ws) => {
  let userNick = null;

  ws.on('message', async (raw) => {
    try {
      const msg = JSON.parse(raw);

      if (msg.type === 'login') {
        userNick = msg.nick;
        if (onlineUsers.has(userNick)) {
          const old = onlineUsers.get(userNick);
          old.ws.send(JSON.stringify({ type: 'kicked', reason: 'Новий пристрій підключився' }));
          old.ws.close();
        }
        onlineUsers.set(userNick, { ws, lastSeen: Date.now() });
        ws.send(JSON.stringify({ type: 'login_ok' }));

        // Доставляємо пропущені повідомлення
        const { data: pending } = await supabase
          .from('messages').select('*')
          .eq('to_nick', userNick).eq('delivered', false)
          .order('timestamp', { ascending: true });

        if (pending && pending.length > 0) {
          for (const m of pending) {
            ws.send(JSON.stringify(
              m.type === 'file'
                ? { type: 'file_message', from: m.from_nick, fileName: m.file_name, data: m.file_data, timestamp: m.timestamp }
                : { type: 'chat_message', from: m.from_nick, text: m.content, timestamp: m.timestamp }
            ));
          }
          await supabase.from('messages')
            .update({ delivered: true })
            .eq('to_nick', userNick).eq('delivered', false);
        }
      }

      if (msg.type === 'check_online') {
        ws.send(JSON.stringify({ type: 'online_status', nick: msg.nick, online: onlineUsers.has(msg.nick) }));
      }

      if (msg.type === 'connect_request') {
        const target = onlineUsers.get(msg.to);
        if (target) target.ws.send(JSON.stringify({ type: 'connect_request', from: userNick }));
        else ws.send(JSON.stringify({ type: 'error', error: `${msg.to} не в мережі` }));
      }

      if (msg.type === 'connect_response') {
        const target = onlineUsers.get(msg.to);
        if (target) target.ws.send(JSON.stringify({ type: 'connect_response', from: userNick, accepted: msg.accepted }));
      }

      if (msg.type === 'chat_message') {
        const ts = Date.now();
        const target = onlineUsers.get(msg.to);
        await supabase.from('messages').insert({
          from_nick: userNick, to_nick: msg.to,
          type: 'text', content: msg.text,
          timestamp: ts, delivered: !!target,
        });
        if (target) target.ws.send(JSON.stringify({ type: 'chat_message', from: userNick, text: msg.text, timestamp: ts }));
      }

      if (msg.type === 'file_message') {
        const ts = Date.now();
        const target = onlineUsers.get(msg.to);
        await supabase.from('messages').insert({
          from_nick: userNick, to_nick: msg.to,
          type: 'file', content: msg.fileName,
          file_name: msg.fileName, file_data: msg.data,
          timestamp: ts, delivered: !!target,
        });
        if (target) target.ws.send(JSON.stringify({ type: 'file_message', from: userNick, fileName: msg.fileName, fileSize: msg.fileSize, data: msg.data, timestamp: ts }));
      }

      if (msg.type === 'read_receipt') {
  const target = onlineUsers.get(msg.to);
  if (target) {
    target.ws.send(JSON.stringify({
      type: 'read_receipt',
      from: userNick,
    }));
  }
}
      
      if (msg.type === 'ping') {
        if (userNick && onlineUsers.has(userNick)) onlineUsers.get(userNick).lastSeen = Date.now();
        ws.send(JSON.stringify({ type: 'pong' }));
      }

    } catch (e) {
      console.error('Помилка:', e);
    }
  });

  ws.on('close', () => { if (userNick) onlineUsers.delete(userNick); });
});

setInterval(() => {
  const now = Date.now();
  for (const [nick, user] of onlineUsers) {
    if (now - user.lastSeen > 60000) onlineUsers.delete(nick);
  }
}, 60000);

setInterval(async () => {
  const week = Date.now() - 7 * 24 * 60 * 60 * 1000;
  await supabase.from('messages').delete().eq('delivered', true).lt('timestamp', week);
}, 60 * 60 * 1000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`EI° сервер запущено на порті ${PORT}`));
