const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json());

// Зберігаємо онлайн користувачів
const onlineUsers = new Map(); // nick -> {ws, lastSeen}

// Реєстр нікнеймів
const registeredNicks = new Set();

// Перевірка унікальності ніку
app.post('/register', (req, res) => {
  const { nick } = req.body;
  if (!nick || nick.trim().length < 2) {
    return res.json({ ok: false, error: 'Нік занадто короткий' });
  }
  if (registeredNicks.has(nick.toLowerCase())) {
    return res.json({ ok: false, error: 'Нік вже зайнятий' });
  }
  registeredNicks.add(nick.toLowerCase());
  res.json({ ok: true });
});

// WebSocket підключення
wss.on('connection', (ws) => {
  let userNick = null;

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw);

      // Вхід
      if (msg.type === 'login') {
        userNick = msg.nick;
        onlineUsers.set(userNick, { ws, lastSeen: Date.now() });
        ws.send(JSON.stringify({ type: 'login_ok' }));
        console.log(`${userNick} онлайн`);
      }

      // Запит чи онлайн співрозмовник
      if (msg.type === 'check_online') {
        const target = onlineUsers.get(msg.nick);
        ws.send(JSON.stringify({
          type: 'online_status',
          nick: msg.nick,
          online: !!target,
        }));
      }

      // Запит на підключення
      if (msg.type === 'connect_request') {
        const target = onlineUsers.get(msg.to);
        if (target) {
          target.ws.send(JSON.stringify({
            type: 'connect_request',
            from: userNick,
          }));
        } else {
          ws.send(JSON.stringify({
            type: 'error',
            error: `${msg.to} не в мережі`,
          }));
        }
      }

      // Відповідь на запит підключення
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

      // Повідомлення в чаті
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

      // Heartbeat
      if (msg.type === 'ping') {
        if (userNick) {
          const user = onlineUsers.get(userNick);
          if (user) user.lastSeen = Date.now();
        }
        ws.send(JSON.stringify({ type: 'pong' }));
      }

    } catch (e) {
      console.error('Помилка:', e);
    }
  });

  ws.on('close', () => {
    if (userNick) {
      onlineUsers.delete(userNick);
      console.log(`${userNick} офлайн`);
    }
  });
});

// Очищення неактивних користувачів кожну хвилину
setInterval(() => {
  const now = Date.now();
  for (const [nick, user] of onlineUsers) {
    if (now - user.lastSeen > 60000) {
      onlineUsers.delete(nick);
      console.log(`${nick} відключено (таймаут)`);
    }
  }
}, 60000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`EI° сервер запущено на порті ${PORT}`));
