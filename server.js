const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json());

// ── База даних (в пам'яті) ──────────────────
const users = new Map();      // nick -> {passwordHash, email, color}
const onlineUsers = new Map(); // nick -> {ws, lastSeen}
const resetCodes = new Map();  // email -> {code, nick, expires}

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

// Тимчасове сховище для очікуючих реєстрацій
const pendingRegistrations = new Map(); // email -> {nick, passwordHash, color, code, expires}

// Крок 1 — надіслати код підтвердження
app.post('/register', async (req, res) => {
  const { nick, password, email, color } = req.body;
  if (!nick || nick.trim().length < 2)
    return res.json({ ok: false, error: 'Нік занадто короткий (мін. 2 символи)' });
  if (!password || password.length < 4)
    return res.json({ ok: false, error: 'Пароль занадто короткий (мін. 4 символи)' });
  if (!email || !email.includes('@'))
    return res.json({ ok: false, error: 'Невірний email' });
  if (users.has(nick.toLowerCase()))
    return res.json({ ok: false, error: 'Нік вже зайнятий' });
  const emailExists = [...users.values()].find(u => u.email === email);
  if (emailExists)
    return res.json({ ok: false, error: 'Цей email вже використовується' });

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  pendingRegistrations.set(email, {
    nick,
    passwordHash: hashPassword(password),
    color: color || 4280391411,
    code,
    expires: Date.now() + 15 * 60 * 1000,
  });

  try {
    await transporter.sendMail({
      from: process.env.GMAIL_USER,
      to: email,
      subject: 'EI° — Підтвердження реєстрації',
      text: `Ваш код підтвердження: ${code}\n\nКод дійсний 15 хвилин.`,
    });
    res.json({ ok: true, needVerification: true });
  } catch (e) {
    res.json({ ok: false, error: 'Помилка відправки email' });
  }
});

// Крок 2 — підтвердити email і створити акаунт
app.post('/verify-email', (req, res) => {
  const { email, code } = req.body;
  const pending = pendingRegistrations.get(email);
  if (!pending)
    return res.json({ ok: false, error: 'Реєстрацію не знайдено' });
  if (Date.now() > pending.expires)
    return res.json({ ok: false, error: 'Код застарів' });
  if (pending.code !== code)
    return res.json({ ok: false, error: 'Невірний код' });

  users.set(pending.nick.toLowerCase(), {
    nick: pending.nick,
    passwordHash: pending.passwordHash,
    email,
    color: pending.color,
  });
  pendingRegistrations.delete(email);
  res.json({ ok: true });
});

// Вхід
app.post('/login', (req, res) => {
  const { nick, password } = req.body;
  const user = users.get(nick?.toLowerCase());
  if (!user)
    return res.json({ ok: false, error: 'Користувача не знайдено' });
  if (user.passwordHash !== hashPassword(password))
    return res.json({ ok: false, error: 'Невірний пароль' });
  res.json({ ok: true, nick: user.nick, color: user.color });
});

// Запит на відновлення пароля
app.post('/forgot', async (req, res) => {
  const { email } = req.body;

  // Шукаємо користувача за email
  const user = [...users.values()].find(u => u.email === email);
  if (!user)
    return res.json({ ok: false, error: 'Email не знайдено' });

  // Генеруємо 6-значний код
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  resetCodes.set(email, {
    code,
    nick: user.nick,
    expires: Date.now() + 15 * 60 * 1000, // 15 хвилин
  });

  try {
    await transporter.sendMail({
      from: process.env.GMAIL_USER,
      to: email,
      subject: 'EI° — Відновлення пароля',
      text: `Ваш код відновлення: ${code}\n\nКод дійсний 15 хвилин.\n\nЯкщо ви не запитували відновлення — проігноруйте цей лист.`,
    });
    res.json({ ok: true });
  } catch (e) {
    res.json({ ok: false, error: 'Помилка відправки email' });
  }
});

// Скидання пароля
app.post('/reset', (req, res) => {
  const { email, code, newPassword } = req.body;
  const reset = resetCodes.get(email);

  if (!reset)
    return res.json({ ok: false, error: 'Код не знайдено' });
  if (Date.now() > reset.expires)
    return res.json({ ok: false, error: 'Код застарів' });
  if (reset.code !== code)
    return res.json({ ok: false, error: 'Невірний код' });
  if (!newPassword || newPassword.length < 4)
    return res.json({ ok: false, error: 'Пароль занадто короткий' });

  const user = users.get(reset.nick.toLowerCase());
  if (!user)
    return res.json({ ok: false, error: 'Користувача не знайдено' });

  user.passwordHash = hashPassword(newPassword);
  resetCodes.delete(email);
  res.json({ ok: true });
});

// Зміна ніку
app.post('/update-nick', (req, res) => {
  const { nick, password, newNick } = req.body;
  const user = users.get(nick?.toLowerCase());
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  if (user.passwordHash !== hashPassword(password))
    return res.json({ ok: false, error: 'Невірний пароль' });
  if (!newNick || newNick.trim().length < 2)
    return res.json({ ok: false, error: 'Нік занадто короткий' });
  if (users.has(newNick.toLowerCase()))
    return res.json({ ok: false, error: 'Нік вже зайнятий' });
  users.delete(nick.toLowerCase());
  user.nick = newNick;
  users.set(newNick.toLowerCase(), user);
  res.json({ ok: true });
});

// Зміна пароля
app.post('/update-password', (req, res) => {
  const { nick, password, newPassword } = req.body;
  const user = users.get(nick?.toLowerCase());
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  if (user.passwordHash !== hashPassword(password))
    return res.json({ ok: false, error: 'Невірний пароль' });
  if (!newPassword || newPassword.length < 4)
    return res.json({ ok: false, error: 'Новий пароль занадто короткий' });
  user.passwordHash = hashPassword(newPassword);
  res.json({ ok: true });
});

// Зміна email
app.post('/update-email', async (req, res) => {
  const { nick, password, newEmail } = req.body;
  const user = users.get(nick?.toLowerCase());
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  if (user.passwordHash !== hashPassword(password))
    return res.json({ ok: false, error: 'Невірний пароль' });
  if (!newEmail || !newEmail.includes('@'))
    return res.json({ ok: false, error: 'Невірний email' });
  const emailExists = [...users.values()].find(u => u.email === newEmail);
  if (emailExists) return res.json({ ok: false, error: 'Email вже використовується' });
  user.email = newEmail;
  res.json({ ok: true });
});

// Видалення акаунта
app.post('/delete-account', (req, res) => {
  const { nick, password } = req.body;
  const user = users.get(nick?.toLowerCase());
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  if (user.passwordHash !== hashPassword(password))
    return res.json({ ok: false, error: 'Невірний пароль' });
  users.delete(nick.toLowerCase());
  onlineUsers.delete(nick);
  res.json({ ok: true });
});

// Список онлайн користувачів
app.get('/online-users', (req, res) => {
  const online = [...onlineUsers.keys()];
  res.json({ ok: true, users: online });
});

// Звільнення ніку
app.post('/unregister', (req, res) => {
  const { nick } = req.body;
  if (nick) onlineUsers.delete(nick);
  res.json({ ok: true });
});

// ── WebSocket ───────────────────────────────
wss.on('connection', (ws) => {
  let userNick = null;

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw);

      if (msg.type === 'login') {
        userNick = msg.nick;
        // Виганяємо стару сесію якщо є
        if (onlineUsers.has(userNick)) {
          const old = onlineUsers.get(userNick);
          old.ws.send(JSON.stringify({ type: 'kicked', reason: 'Новий пристрій підключився' }));
          old.ws.close();
        }
        onlineUsers.set(userNick, { ws, lastSeen: Date.now() });
        ws.send(JSON.stringify({ type: 'login_ok' }));
      }

      if (msg.type === 'check_online') {
        ws.send(JSON.stringify({
          type: 'online_status',
          nick: msg.nick,
          online: onlineUsers.has(msg.nick),
        }));
      }

      if (msg.type === 'connect_request') {
        const target = onlineUsers.get(msg.to);
        if (target) {
          target.ws.send(JSON.stringify({ type: 'connect_request', from: userNick }));
        } else {
          ws.send(JSON.stringify({ type: 'error', error: `${msg.to} не в мережі` }));
        }
      }

      if (msg.type === 'connect_response') {
        const target = onlineUsers.get(msg.to);
        if (target) {
          target.ws.send(JSON.stringify({
            type: 'connect_response',
            from: userNick,
            accepted: msg.accepted,
          }));
        }
      }

      if (msg.type === 'chat_message') {
        const target = onlineUsers.get(msg.to);
        if (target) {
          target.ws.send(JSON.stringify({
            type: 'chat_message',
            from: userNick,
            text: msg.text,
            timestamp: Date.now(),
          }));
        }
      }

      if (msg.type === 'file_message') {
        const target = onlineUsers.get(msg.to);
        if (target) {
          target.ws.send(JSON.stringify({
            type: 'file_message',
            from: userNick,
            fileName: msg.fileName,
            fileSize: msg.fileSize,
            data: msg.data,
          }));
        }
      }
      
      if (msg.type === 'ping') {
        if (userNick && onlineUsers.has(userNick)) {
          onlineUsers.get(userNick).lastSeen = Date.now();
        }
        ws.send(JSON.stringify({ type: 'pong' }));
      }

    } catch (e) {
      console.error('Помилка:', e);
    }
  });

  ws.on('close', () => {
    if (userNick) onlineUsers.delete(userNick);
  });
});

// Очищення неактивних
setInterval(() => {
  const now = Date.now();
  for (const [nick, user] of onlineUsers) {
    if (now - user.lastSeen > 60000) onlineUsers.delete(nick);
  }
}, 60000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`EI° сервер запущено на порті ${PORT}`));
