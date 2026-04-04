const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json({ limit: '10mb' }));

const BCRYPT_ROUNDS = 10;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

const onlineUsers = new Map();
const resetCodes = new Map();
const pendingRegistrations = new Map();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS },
});

app.post('/register', async (req, res) => {
  const { nick, password, email, color } = req.body;
  if (!nick || nick.trim().length < 2)
    return res.json({ ok: false, error: 'Нік занадто короткий (мін. 2 символи)' });
  if (!password || password.length < 4)
    return res.json({ ok: false, error: 'Пароль занадто короткий (мін. 4 символи)' });
  if (!email || !email.includes('@'))
    return res.json({ ok: false, error: 'Невірний email' });
  const { data: existing } = await supabase.from('users').select('nick').eq('nick_lower', nick.toLowerCase()).single();
  if (existing) return res.json({ ok: false, error: 'Нік вже зайнятий' });
  const { data: emailExists } = await supabase.from('users').select('nick').eq('email', email).single();
  if (emailExists) return res.json({ ok: false, error: 'Цей email вже використовується' });
  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  pendingRegistrations.set(email, { nick, passwordHash, color: color || 4280391411, code, expires: Date.now() + 15 * 60 * 1000 });
  try {
    await transporter.sendMail({ from: process.env.GMAIL_USER, to: email, subject: 'EI° — Підтвердження реєстрації', text: `Ваш код підтвердження: ${code}\n\nКод дійсний 15 хвилин.` });
    res.json({ ok: true, needVerification: true });
  } catch (e) { res.json({ ok: false, error: 'Помилка відправки email' }); }
});

app.post('/verify-email', async (req, res) => {
  const { email, code } = req.body;
  const pending = pendingRegistrations.get(email);
  if (!pending) return res.json({ ok: false, error: 'Реєстрацію не знайдено' });
  if (Date.now() > pending.expires) return res.json({ ok: false, error: 'Код застарів' });
  if (pending.code !== code) return res.json({ ok: false, error: 'Невірний код' });
  const { error } = await supabase.from('users').insert({ nick: pending.nick, nick_lower: pending.nick.toLowerCase(), password_hash: pending.passwordHash, email, color: pending.color });
  if (error) return res.json({ ok: false, error: 'Помилка створення акаунта' });
  pendingRegistrations.delete(email);
  res.json({ ok: true });
});

app.post('/login', async (req, res) => {
  const { nick, password } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
  res.json({ ok: true, nick: user.nick, color: user.color });
});

app.post('/forgot', async (req, res) => {
  const { email } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('email', email).single();
  if (!user) return res.json({ ok: false, error: 'Email не знайдено' });
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  resetCodes.set(email, { code, nick: user.nick, expires: Date.now() + 15 * 60 * 1000 });
  try {
    await transporter.sendMail({ from: process.env.GMAIL_USER, to: email, subject: 'EI° — Відновлення пароля', text: `Ваш код відновлення: ${code}\n\nКод дійсний 15 хвилин.` });
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: 'Помилка відправки email' }); }
});

app.post('/reset', async (req, res) => {
  const { email, code, newPassword } = req.body;
  const reset = resetCodes.get(email);
  if (!reset) return res.json({ ok: false, error: 'Код не знайдено' });
  if (Date.now() > reset.expires) return res.json({ ok: false, error: 'Код застарів' });
  if (reset.code !== code) return res.json({ ok: false, error: 'Невірний код' });
  if (!newPassword || newPassword.length < 4) return res.json({ ok: false, error: 'Пароль занадто короткий' });
  const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  await supabase.from('users').update({ password_hash: passwordHash }).eq('nick_lower', reset.nick.toLowerCase());
  resetCodes.delete(email);
  res.json({ ok: true });
});

app.post('/update-nick', async (req, res) => {
  const { nick, password, newNick } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
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
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
  if (!newPassword || newPassword.length < 4) return res.json({ ok: false, error: 'Новий пароль занадто короткий' });
  const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  await supabase.from('users').update({ password_hash: passwordHash }).eq('nick_lower', nick.toLowerCase());
  res.json({ ok: true });
});

app.post('/update-email', async (req, res) => {
  const { nick, password, newEmail } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('nick_lower', nick?.toLowerCase()).single();
  if (!user) return res.json({ ok: false, error: 'Користувача не знайдено' });
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
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
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.json({ ok: false, error: 'Невірний пароль' });
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
  if (!nick || nick.trim().length < 2) return res.json({ ok: false, error: 'Введіть мін. 2 символи' });
  const { data } = await supabase.from('users').select('nick').ilike('nick_lower', `%${nick.toLowerCase()}%`).limit(10);
  res.json({ ok: true, users: (data || []).map(u => u.nick) });
});

app.post('/unregister', (req, res) => {
  const { nick } = req.body;
  if (nick) onlineUsers.delete(nick);
  res.json({ ok: true });
});

// ── Групові чати REST ────────────────────────
app.post('/group/create', async (req, res) => {
  const { name, creatorNick, members } = req.body;
  if (!name || name.trim().length < 1) return res.json({ ok: false, error: 'Назва групи порожня' });
  const { data: group, error } = await supabase.from('groups').insert({ name: name.trim(), creator_nick: creatorNick }).select().single();
  if (error) return res.json({ ok: false, error: 'Помилка створення групи' });
  const allMembers = [...new Set([creatorNick, ...(members || [])])];
  await supabase.from('group_members').insert(allMembers.map(nick => ({ group_id: group.id, nick })));
  // Сповіщаємо онлайн учасників
  for (const nick of allMembers) {
    if (nick !== creatorNick) {
      const target = onlineUsers.get(nick);
      if (target) target.ws.send(JSON.stringify({ type: 'group_added', group: { id: group.id, name: group.name, creator_nick: group.creator_nick }, members: allMembers }));
    }
  }
  res.json({ ok: true, group: { id: group.id, name: group.name, creator_nick: group.creator_nick }, members: allMembers });
});

app.get('/group/list', async (req, res) => {
  const { nick } = req.query;
  const { data: memberships } = await supabase.from('group_members').select('group_id').eq('nick', nick);
  if (!memberships || memberships.length === 0) return res.json({ ok: true, groups: [] });
  const ids = memberships.map(m => m.group_id);
  const { data: groups } = await supabase.from('groups').select('*').in('id', ids);
  const result = [];
  for (const g of groups || []) {
    const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', g.id);
    result.push({ ...g, members: (members || []).map(m => m.nick) });
  }
  res.json({ ok: true, groups: result });
});

app.post('/group/add-member', async (req, res) => {
  const { groupId, requesterNick, newNick } = req.body;
  const { data: group } = await supabase.from('groups').select('*').eq('id', groupId).single();
  if (!group) return res.json({ ok: false, error: 'Групу не знайдено' });
  if (group.creator_nick !== requesterNick) return res.json({ ok: false, error: 'Тільки творець може додавати учасників' });
  await supabase.from('group_members').insert({ group_id: groupId, nick: newNick });
  const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', groupId);
  const memberList = (members || []).map(m => m.nick);
  // Сповіщаємо нового учасника
  const target = onlineUsers.get(newNick);
  if (target) target.ws.send(JSON.stringify({ type: 'group_added', group: { id: group.id, name: group.name, creator_nick: group.creator_nick }, members: memberList }));
  // Сповіщаємо існуючих учасників
  for (const nick of memberList) {
    if (nick !== newNick) {
      const t = onlineUsers.get(nick);
      if (t) t.ws.send(JSON.stringify({ type: 'group_member_added', groupId, nick: newNick }));
    }
  }
  res.json({ ok: true });
});

app.post('/group/remove-member', async (req, res) => {
  const { groupId, requesterNick, targetNick } = req.body;
  const { data: group } = await supabase.from('groups').select('*').eq('id', groupId).single();
  if (!group) return res.json({ ok: false, error: 'Групу не знайдено' });
  if (group.creator_nick !== requesterNick) return res.json({ ok: false, error: 'Тільки творець може видаляти учасників' });
  await supabase.from('group_members').delete().eq('group_id', groupId).eq('nick', targetNick);
  const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', groupId);
  const memberList = (members || []).map(m => m.nick);
  // Сповіщаємо видаленого
  const target = onlineUsers.get(targetNick);
  if (target) target.ws.send(JSON.stringify({ type: 'group_removed', groupId }));
  // Сповіщаємо решту
  for (const nick of memberList) {
    const t = onlineUsers.get(nick);
    if (t) t.ws.send(JSON.stringify({ type: 'group_member_removed', groupId, nick: targetNick }));
  }
  res.json({ ok: true });
});

app.post('/group/delete', async (req, res) => {
  const { groupId, requesterNick } = req.body;
  const { data: group } = await supabase.from('groups').select('*').eq('id', groupId).single();
  if (!group) return res.json({ ok: false, error: 'Групу не знайдено' });
  if (group.creator_nick !== requesterNick) return res.json({ ok: false, error: 'Тільки творець може видалити групу' });
  const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', groupId);
  await supabase.from('group_messages').delete().eq('group_id', groupId);
  await supabase.from('group_members').delete().eq('group_id', groupId);
  await supabase.from('groups').delete().eq('id', groupId);
  for (const m of members || []) {
    const t = onlineUsers.get(m.nick);
    if (t) t.ws.send(JSON.stringify({ type: 'group_deleted', groupId }));
  }
  res.json({ ok: true });
});

app.get('/group/messages', async (req, res) => {
  const { groupId } = req.query;
  const { data } = await supabase.from('group_messages').select('*').eq('group_id', groupId).order('timestamp', { ascending: true });
  res.json({ ok: true, messages: data || [] });
});

// ── WebSocket ────────────────────────────────
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

        for (const [nick, user] of onlineUsers) {
          if (nick !== userNick) user.ws.send(JSON.stringify({ type: 'user_online', nick: userNick }));
        }

        // Доставляємо пропущені видалення
        const { data: pendingDeletes } = await supabase.from('deleted_messages').select('msg_id, from_nick').eq('to_nick', userNick);
        if (pendingDeletes && pendingDeletes.length > 0) {
          for (const d of pendingDeletes) ws.send(JSON.stringify({ type: 'delete_message', from: d.from_nick, msgId: d.msg_id }));
          await supabase.from('deleted_messages').delete().eq('to_nick', userNick);
        }

        // Статуси повідомлень
        const { data: toDeliver } = await supabase.from('messages').select('id, from_nick, msg_id').eq('to_nick', userNick).eq('status', 'sent');
        if (toDeliver && toDeliver.length > 0) {
          await supabase.from('messages').update({ status: 'delivered' }).eq('to_nick', userNick).eq('status', 'sent');
          const senders = [...new Set(toDeliver.map(m => m.from_nick))];
          for (const sender of senders) {
            const senderWs = onlineUsers.get(sender);
            if (senderWs) {
              const msgIds = toDeliver.filter(m => m.from_nick === sender).map(m => m.msg_id).filter(Boolean);
              if (msgIds.length > 0) senderWs.ws.send(JSON.stringify({ type: 'status_update', status: 'delivered', msgIds }));
            }
          }
        }

        const { data: myStatuses } = await supabase.from('messages').select('msg_id, status').eq('from_nick', userNick).neq('status', 'sent').not('msg_id', 'is', null);
        if (myStatuses && myStatuses.length > 0) ws.send(JSON.stringify({ type: 'status_sync', statuses: myStatuses }));

        // Пропущені особисті повідомлення
        const { data: pending } = await supabase.from('messages').select('*').eq('to_nick', userNick).eq('delivered', false).order('timestamp', { ascending: true });
        if (pending && pending.length > 0) {
          for (const m of pending) {
            ws.send(JSON.stringify(
              m.type === 'file'
                ? { type: 'file_message', from: m.from_nick, fileName: m.file_name, data: m.file_data, timestamp: m.timestamp }
                : { type: 'chat_message', from: m.from_nick, text: m.content, msgId: m.msg_id, timestamp: m.timestamp }
            ));
          }
          await supabase.from('messages').update({ delivered: true }).eq('to_nick', userNick).eq('delivered', false);
        }

        // Пропущені групові повідомлення
        const { data: myGroups } = await supabase.from('group_members').select('group_id').eq('nick', userNick);
        if (myGroups && myGroups.length > 0) {
          for (const gm of myGroups) {
            const { data: pendingGroup } = await supabase.from('group_messages').select('*')
              .eq('group_id', gm.group_id)
              .not('delivered_to', 'cs', `{"${userNick}"}`)
              .order('timestamp', { ascending: true });
            if (pendingGroup && pendingGroup.length > 0) {
              for (const m of pendingGroup) {
                ws.send(JSON.stringify({ type: 'group_message', groupId: m.group_id, from: m.from_nick, text: m.content, timestamp: m.timestamp, msgId: m.msg_id }));
                await supabase.from('group_messages').update({ delivered_to: [...(m.delivered_to || []), userNick] }).eq('id', m.id);
              }
            }
          }
        }
      }

      if (msg.type === 'check_online') ws.send(JSON.stringify({ type: 'online_status', nick: msg.nick, online: onlineUsers.has(msg.nick) }));

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
        const msgId = msg.msgId || null;
        await supabase.from('messages').insert({ from_nick: userNick, to_nick: msg.to, type: 'text', content: msg.text, timestamp: ts, delivered: !!target, msg_id: msgId });
        if (target) target.ws.send(JSON.stringify({ type: 'chat_message', from: userNick, text: msg.text, timestamp: ts, msgId }));
      }

      if (msg.type === 'file_message') {
        const ts = Date.now();
        const target = onlineUsers.get(msg.to);
        await supabase.from('messages').insert({ from_nick: userNick, to_nick: msg.to, type: 'file', content: msg.fileName, file_name: msg.fileName, file_data: msg.data, timestamp: ts, delivered: !!target });
        if (target) target.ws.send(JSON.stringify({ type: 'file_message', from: userNick, fileName: msg.fileName, fileSize: msg.fileSize, data: msg.data, timestamp: ts }));
      }

      if (msg.type === 'group_message') {
        const ts = Date.now();
        const msgId = msg.msgId || `${userNick}_g${msg.groupId}_${ts}`;
        // Перевіряємо членство
        const { data: membership } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId).eq('nick', userNick).single();
        if (!membership) return;
        // Отримуємо всіх учасників
        const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId);
        const memberNicks = (members || []).map(m => m.nick);
        const onlineMembers = memberNicks.filter(n => n !== userNick && onlineUsers.has(n));
        // Зберігаємо повідомлення
        await supabase.from('group_messages').insert({
          group_id: msg.groupId, from_nick: userNick, content: msg.text,
          timestamp: ts, msg_id: msgId,
          delivered_to: [userNick, ...onlineMembers],
        });
        // Розсилаємо онлайн учасникам
        for (const nick of onlineMembers) {
          onlineUsers.get(nick).ws.send(JSON.stringify({ type: 'group_message', groupId: msg.groupId, from: userNick, text: msg.text, timestamp: ts, msgId }));
        }
      }

      if (msg.type === 'group_typing') {
        const { data: members } = await supabase.from('group_members').select('nick').eq('group_id', msg.groupId);
        for (const m of members || []) {
          if (m.nick !== userNick) {
            const t = onlineUsers.get(m.nick);
            if (t) t.ws.send(JSON.stringify({ type: 'group_typing', groupId: msg.groupId, from: userNick }));
          }
        }
      }

      if (msg.type === 'read_receipt') {
        await supabase.from('messages').update({ status: 'read' }).eq('to_nick', userNick).eq('from_nick', msg.to);
        const target = onlineUsers.get(msg.to);
        if (target) {
          const { data: readMsgs } = await supabase.from('messages').select('msg_id').eq('to_nick', userNick).eq('from_nick', msg.to).not('msg_id', 'is', null);
          const msgIds = (readMsgs || []).map(m => m.msg_id).filter(Boolean);
          target.ws.send(JSON.stringify({ type: 'read_receipt', from: userNick, msgIds }));
        }
      }

      if (msg.type === 'delete_message') {
        const target = onlineUsers.get(msg.to);
        if (target) {
          target.ws.send(JSON.stringify({ type: 'delete_message', from: userNick, msgId: msg.msgId }));
        } else {
          await supabase.from('deleted_messages').insert({ msg_id: msg.msgId, from_nick: userNick, to_nick: msg.to });
        }
      }

      if (msg.type === 'typing') {
        const target = onlineUsers.get(msg.to);
        if (target) target.ws.send(JSON.stringify({ type: 'typing', from: userNick }));
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
