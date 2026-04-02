const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json({ limit: '10mb' }));

// ── База даних ──────────────────────────────
const db = new Database(path.join('/tmp', 'ei.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    nick TEXT PRIMARY KEY,
    nick_lower TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    color INTEGER NOT NULL DEFAULT 4280391411,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_nick TEXT NOT NULL,
    to_nick TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'text',
    content TEXT NOT NULL,
    file_name TEXT,
    file_data TEXT,
    timestamp INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
    delivered INTEGER NOT NULL DEFAULT 0
  );

  CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_nick, delivered);
  CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(from_nick, to_nick, timestamp);
`);

// ── Онлайн користувачі (в пам'яті) ─────────
const onlineUsers = new Map(); // nick -> {ws, lastSeen}
const resetCodes = new Map();  // email -> {code, nick, expires}
const pendingRegistrations = new Map(); // email -> {nick, passwordHash, color, code, expires}

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

// Реєстрація — крок 1
app.post('/register', async (req, res) => {
  const { nick, password, email, color } = req.body;
  if (!nick || nick.trim().length < 2)
    return res.json({ ok: false, error: 'Нік занадто короткий (мін. 2 символи)' });
  if (!password || password.length < 4)
    return res.json({ ok: false, error: 'Пароль занадто короткий (мін. 4 символи)' });
  if (!email || !email.includes('@'))
    return res.json({ ok: false, error: 'Невірний email' });

  const existing = db.prepare('SELECT nick FROM users WHERE nick_lower = ?').get(nick.toLowerCase());
  if (existing) return res.json({ ok: false, error: 'Нік вже зайнятий' });

  const emailExists = db.prepare('SELECT nick FROM users WHERE email = ?').get(email);
  if (emailExists) return res.json({ ok: false, error: 'Цей email вже використовується' });

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

// Реєстрація — крок 2
app.post('/verify-email', (req, res) => {
  const { email, code } = req.body;
  const pending = pendingRegistrations.get(email);
  if (!pending) return res.json({ ok: false, error: 'Реєстрацію не знайдено' });
  if (Date.now() > pending.expires) return res.json({ ok: false, error: 'Код застарів' });
  if (pending.code !== code) return res.json({ ok: false, error: 'Невірний код' });

  db.prepare('INSERT INTO users (nick, nick_lower, password_hash, email, color) VALUES (?, ?, ?, ?, ?)').run(
    pending.nick, pending.nick.toLowerCase(), pending.passwordHash, email, pending.color
  );
  pendingRegistrations.delete(email);
  res.json({ ok: true });
});

// Вхід
app.post('/login', (req, res) => {
  const { nick, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE nick_lower = ?').get(nick?.toLowerCase());
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  if (user.password_hash !== hashPassword(password)) return res.json({ ok: false, error: 'Невірний пароль' });
  res.json({ ok: true, nick: user.nick, color: user.color });
});

// Відновлення пароля
app.post('/forgot', async (req, res) => {
  const { email } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.json({ ok: false, error: 'Email не знайдено' });

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  resetCodes.set(email, { code, nick: user.nick, expires: Date.now() + 15 * 60 * 1000 });

  try {
    await transporter.sendMail({
      from: process.env.GMAIL_USER,
      to: email,
      subject: 'EI° — Відновлення пароля',
      text: `Ваш код відновлення: ${code}\n\nКод дійсний 15 хвилин.`,
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
  if (!reset) return res.json({ ok: false, error: 'Код не знайдено' });
  if (Date.now() > reset.expires) return res.json({ ok: false, error: 'Код застарів' });
  if (reset.code !== code) return res.json({ ok: false, error: 'Невірний код' });
  if (!newPassword || newPassword.length < 4) return res.json({ ok: false, error: 'Пароль занадто короткий' });

  db.prepare('UPDATE users SET password_hash = ? WHERE nick_lower = ?').run(
    hashPassword(newPassword), reset.nick.toLowerCase()
  );
  resetCodes.delete(email);
  res.json({ ok: true });
});

// Зміна ніку
app.post('/update-nick', (req, res) => {
  const { nick, password, newNick } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE nick_lower = ?').get(nick?.toLowerCase());
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  if (user.password_hash !== hashPassword(password)) return res.json({ ok: false, error: 'Невірний пароль' });
  if (!newNick || newNick.trim().length < 2) return res.json({ ok: false, error: 'Нік занадто короткий' });

  const exists = db.prepare('SELECT nick FROM users WHERE nick_lower = ?').get(newNick.toLowerCase());
  if (exists) return res.json({ ok: false, error: 'Нік вже зайнятий' });

  db.prepare('UPDATE users SET nick = ?, nick_lower = ? WHERE nick_lower = ?').run(
    newNick, newNick.toLowerCase(), nick.toLowerCase()
  );
  res.json({ ok: true });
});

// Зміна пароля
app.post('/update-password', (req, res) => {
  const { nick, password, newPassword } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE nick_lower = ?').get(nick?.toLowerCase());
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  if (user.password_hash !== hashPassword(password)) return res.json({ ok: false, error: 'Невірний пароль' });
  if (!newPassword || newPassword.length < 4) return res.json({ ok: false, error: 'Новий пароль занадто короткий' });

  db.prepare('UPDATE users SET password_hash = ? WHERE nick_lower = ?').run(
    hashPassword(newPassword), nick.toLowerCase()
  );
  res.json({ ok: true });
});

// Зміна email
app.post('/update-email', (req, res) => {
  const { nick, password, newEmail } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE nick_lower = ?').get(nick?.toLowerCase());
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  if (user.password_hash !== hashPassword(password)) return res.json({ ok: false, error: 'Невірний пароль' });
  if (!newEmail || !newEmail.includes('@')) return res.json({ ok: false, error: 'Невірний email' });

  const emailExists = db.prepare('SELECT nick FROM users WHERE email = ?').get(newEmail);
  if (emailExists) return res.json({ ok: false, error: 'Email вже використовується' });

  db.prepare('UPDATE users SET email = ? WHERE nick_lower = ?').run(newEmail, nick.toLowerCase());
  res.json({ ok: true });
});

// Видалення акаунта
app.post('/delete-account', (req, res) => {
  const { nick, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE nick_lower = ?').get(nick?.toLowerCase());
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  if (user.password_hash !== hashPassword(password)) return res.json({ ok: false, error: 'Невірний пароль' });

  db.prepare('DELETE FROM messages WHERE from_nick = ? OR to_nick = ?').run(nick, nick);
  db.prepare('DELETE FROM users WHERE nick_lower = ?').run(nick.toLowerCase());
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
        if (onlineUsers.has(userNick)) {
          const old = onlineUsers.get(userNick);
          old.ws.send(JSON.stringify({ type: 'kicked', reason: 'Новий пристрій підключився' }));
          old.ws.close();
        }
        onlineUsers.set(userNick, { ws, lastSeen: Date.now() });
        ws.send(JSON.stringify({ type: 'login_ok' }));

        // Доставляємо пропущені повідомлення
        const pending = db.prepare(
          'SELECT * FROM messages WHERE to_nick = ? AND delivered = 0 ORDER BY timestamp ASC'
        ).all(userNick);

        for (const m of pending) {
          if (m.type === 'file') {
            ws.send(JSON.stringify({
              type: 'file_message',
              from: m.from_nick,
              fileName: m.file_name,
              data: m.file_data,
              timestamp: m.timestamp,
            }));
          } else {
            ws.send(JSON.stringify({
              type: 'chat_message',
              from: m.from_nick,
              text: m.content,
              timestamp: m.timestamp,
            }));
          }
          db.prepare('UPDATE messages SET delivered = 1 WHERE id = ?').run(m.id);
        }
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
        const ts = Date.now();
        // Зберігаємо в БД
        db.prepare(
          'INSERT INTO messages (from_nick, to_nick, type, content, timestamp) VALUES (?, ?, ?, ?, ?)'
        ).run(userNick, msg.to, 'text', msg.text, ts);

        const target = onlineUsers.get(msg.to);
        if (target) {
          target.ws.send(JSON.stringify({
            type: 'chat_message',
            from: userNick,
            text: msg.text,
            timestamp: ts,
          }));
          // Позначаємо як доставлене
          db.prepare(
            'UPDATE messages SET delivered = 1 WHERE from_nick = ? AND to_nick = ? AND timestamp = ?'
          ).run(userNick, msg.to, ts);
        }
      }

      if (msg.type === 'file_message') {
        const ts = Date.now();
        // Зберігаємо файл в БД
        db.prepare(
          'INSERT INTO messages (from_nick, to_nick, type, content, file_name, file_data, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)'
        ).run(userNick, msg.to, 'file', msg.fileName, msg.fileName, msg.data, ts);

        const target = onlineUsers.get(msg.to);
        if (target) {
          target.ws.send(JSON.stringify({
            type: 'file_message',
            from: userNick,
            fileName: msg.fileName,
            fileSize: msg.fileSize,
            data: msg.data,
            timestamp: ts,
          }));
          db.prepare(
            'UPDATE messages SET delivered = 1 WHERE from_nick = ? AND to_nick = ? AND timestamp = ?'
          ).run(userNick, msg.to, ts);
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

// Очищення старих доставлених повідомлень (старші 7 днів)
setInterval(() => {
  const week = Date.now() - 7 * 24 * 60 * 60 * 1000;
  db.prepare('DELETE FROM messages WHERE delivered = 1 AND timestamp < ?').run(week);
}, 60 * 60 * 1000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`EI° сервер запущено на порті ${PORT}`));
