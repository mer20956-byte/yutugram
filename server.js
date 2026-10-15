const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function writeJson(file, value) {
  const temp = file + '.tmp';
  fs.writeFileSync(temp, JSON.stringify(value, null, 2), 'utf8');
  fs.renameSync(temp, file);
}
let users = readJson(USERS_FILE, []);
let messages = readJson(MESSAGES_FILE, []);
const socketsByLogin = new Map();

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(UPLOAD_DIR));
app.use(express.static(path.join(__dirname, 'public')));

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).slice(0, 12).replace(/[^a-zA-Z0-9.]/g, '');
    cb(null, `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 15 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    // Keep common documents, images, audio, and video; block executable/script types.
    const ext = path.extname(file.originalname).toLowerCase();
    const blocked = new Set(['.exe','.msi','.bat','.cmd','.com','.scr','.ps1','.sh','.js','.html','.htm','.jar','.vbs']);
    if (blocked.has(ext)) return cb(new Error('Этот тип файла запрещён'));
    cb(null, true);
  }
});


// Аватарки принимают только изображения размером до 5 МБ.
const avatarUpload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    if (!/^image\/(png|jpeg|gif|webp|avif|bmp|svg\+xml)$/i.test(file.mimetype)) {
      return cb(new Error('Для аватарки разрешены только изображения'));
    }
    cb(null, true);
  }
});

function cleanLogin(value) {
  return String(value || '').trim().toLowerCase();
}
function publicUser(user) {
  return { login: user.login, name: user.name, ...(user.avatar ? { avatar: user.avatar } : {}) };
}
function validLogin(login) {
  return /^[a-z0-9_.-]{3,24}$/.test(login);
}
function getConversation(a, b) {
  return messages.filter(m => (m.from === a && m.to === b) || (m.from === b && m.to === a))
    .sort((x, y) => x.time - y.time);
}
function saveMessages() { writeJson(MESSAGES_FILE, messages); }
function emitToLogin(login, event, payload) {
  const ids = socketsByLogin.get(login);
  if (!ids) return;
  for (const id of ids) io.to(id).emit(event, payload);
}
function onlineList() { return [...socketsByLogin.keys()]; }

app.post('/api/register', async (req, res) => {
  try {
    const login = cleanLogin(req.body.login);
    const name = String(req.body.name || login).trim().slice(0, 40) || login;
    const password = String(req.body.password || '');
    if (!validLogin(login)) return res.status(400).json({ error: 'Логин: 3–24 символа, латиница, цифры, точка, _ или -' });
    if (password.length < 6 || password.length > 128) return res.status(400).json({ error: 'Пароль должен содержать от 6 до 128 символов' });
    if (users.some(u => u.login === login)) return res.status(409).json({ error: 'Этот логин уже занят' });
    const user = { login, name, passwordHash: await bcrypt.hash(password, 12), createdAt: Date.now() };
    users.push(user);
    writeJson(USERS_FILE, users);
    res.json({ user: publicUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Не удалось создать аккаунт' });
  }
});

app.post('/api/login', async (req, res) => {
  const login = cleanLogin(req.body.login);
  const password = String(req.body.password || '');
  const user = users.find(u => u.login === login);
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }
  res.json({ user: publicUser(user) });
});

app.get('/api/users', (_req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json(users.map(publicUser));
});

app.get('/api/messages/:a/:b', (req, res) => {
  const a = cleanLogin(req.params.a);
  const b = cleanLogin(req.params.b);
  if (!users.some(u => u.login === a) || !users.some(u => u.login === b)) {
    return res.status(404).json({ error: 'Пользователь не найден' });
  }
  res.json(getConversation(a, b).map(({ id, from, to, text, time, file, edited, read, replyTo, pinned }) =>
    ({ id, from, to, text, time, file: file || null, edited: !!edited, read: !!read, replyTo: replyTo || null, pinned: !!pinned })));
});


app.get('/api/profile/:login', (req, res) => {
  const login = cleanLogin(req.params.login);
  const user = users.find(u => u.login === login);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  res.set('Cache-Control', 'no-store');
  res.json({ user: publicUser(user) });
});

app.patch('/api/profile', (req, res) => {
  try {
    const login = cleanLogin(req.body.login);
    const user = users.find(u => u.login === login);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    if (typeof req.body.name === 'string') {
      const name = req.body.name.trim().slice(0, 40);
      if (!name) return res.status(400).json({ error: 'Имя не может быть пустым' });
      user.name = name;
    }
    if (typeof req.body.avatar === 'string') {
      if (!req.body.avatar.startsWith('/uploads/') || req.body.avatar.length > 300) {
        return res.status(400).json({ error: 'Некорректный путь аватарки' });
      }
      user.avatar = req.body.avatar;
    }
    writeJson(USERS_FILE, users);
    res.json({ user: publicUser(user) });
    io.emit('profile-updated', publicUser(user));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Не удалось обновить профиль' });
  }
});

app.post('/api/upload-avatar', avatarUpload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Файл не выбран' });
  res.json({ file: { name: req.file.originalname, url: `/uploads/${req.file.filename}`, size: req.file.size, mime: req.file.mimetype } });
});

app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Файл не выбран' });
  res.json({
    file: {
      name: req.file.originalname,
      url: `/uploads/${req.file.filename}`,
      size: req.file.size,
      mime: req.file.mimetype
    }
  });
});
app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    const msg = err.code === 'LIMIT_FILE_SIZE' ? 'Превышен максимальный размер файла (5 МБ для аватарки, 15 МБ для вложений)' : 'Не удалось загрузить файл';
    return res.status(400).json({ error: msg });
  }
  if (err) return res.status(400).json({ error: err.message || 'Ошибка запроса' });
});

io.on('connection', socket => {
  let loginForSocket = null;

  socket.on('auth', loginValue => {
    const login = cleanLogin(loginValue);
    if (!users.some(u => u.login === login)) return;
    if (loginForSocket && socketsByLogin.has(loginForSocket)) {
      socketsByLogin.get(loginForSocket).delete(socket.id);
      if (!socketsByLogin.get(loginForSocket).size) socketsByLogin.delete(loginForSocket);
    }
    loginForSocket = login;
    if (!socketsByLogin.has(login)) socketsByLogin.set(login, new Set());
    socketsByLogin.get(login).add(socket.id);
    io.emit('online', onlineList());
  });

  // Сигналинг WebRTC: SDP и ICE передаются только между двумя авторизованными сокетами.
  function validPeer(to) { return typeof to === 'string' && users.some(u => u.login === cleanLogin(to)) && cleanLogin(to) !== loginForSocket; }
  socket.on('call-offer', payload => {
    if (!loginForSocket || !payload || !validPeer(payload.to) || !payload.offer || typeof payload.offer.sdp !== 'string') return;
    emitToLogin(cleanLogin(payload.to), 'call-offer', { from: loginForSocket, offer: payload.offer });
  });
  socket.on('call-answer', payload => {
    if (!loginForSocket || !payload || !validPeer(payload.to) || !payload.answer || typeof payload.answer.sdp !== 'string') return;
    emitToLogin(cleanLogin(payload.to), 'call-answer', { from: loginForSocket, answer: payload.answer });
  });
  socket.on('call-ice', payload => {
    if (!loginForSocket || !payload || !validPeer(payload.to) || !payload.candidate || typeof payload.candidate.candidate !== 'string') return;
    emitToLogin(cleanLogin(payload.to), 'call-ice', { from: loginForSocket, candidate: payload.candidate });
  });
  socket.on('call-end', payload => {
    if (!loginForSocket || !payload || !validPeer(payload.to)) return;
    emitToLogin(cleanLogin(payload.to), 'call-end', { from: loginForSocket, reason: String(payload.reason || '').slice(0, 30) });
  });

  socket.on('message', payload => {
    if (!loginForSocket || !payload || typeof payload !== 'object') return;
    const to = cleanLogin(payload.to);
    if (!users.some(u => u.login === to) || to === loginForSocket) return;
    const text = String(payload.text || '').trim().slice(0, 5000);
    const file = payload.file && typeof payload.file === 'object' ? {
      name: String(payload.file.name || 'Файл').slice(0, 180),
      url: String(payload.file.url || '').startsWith('/uploads/') ? String(payload.file.url) : '',
      size: Number(payload.file.size) || 0,
      mime: String(payload.file.mime || '').slice(0, 100)
    } : null;
    if (!text && !(file && file.url)) return;
    const msg = {
      id: crypto.randomUUID(), from: loginForSocket, to, text,
      time: Date.now(), file, edited: false, read: false,
      replyTo: payload.replyTo && typeof payload.replyTo === 'object' ? {
        id: String(payload.replyTo.id || '').slice(0, 80),
        from: cleanLogin(payload.replyTo.from),
        text: String(payload.replyTo.text || '').slice(0, 240)
      } : null,
      pinned: false
    };
    messages.push(msg);
    saveMessages();
    emitToLogin(loginForSocket, 'message', msg);
    emitToLogin(to, 'message', msg);
  });

  socket.on('edit-message', payload => {
    if (!loginForSocket || !payload) return;
    const msg = messages.find(m => m.id === payload.id && m.from === loginForSocket);
    if (!msg || msg.file) return;
    const text = String(payload.text || '').trim().slice(0, 5000);
    if (!text) return;
    msg.text = text;
    msg.edited = true;
    saveMessages();
    emitToLogin(msg.from, 'message-edited', msg);
    emitToLogin(msg.to, 'message-edited', msg);
  });

  socket.on('delete-message', payload => {
    if (!loginForSocket || !payload) return;
    const index = messages.findIndex(m => m.id === payload.id && m.from === loginForSocket);
    if (index < 0) return;
    const [msg] = messages.splice(index, 1);
    saveMessages();
    emitToLogin(msg.from, 'message-deleted', { id: msg.id });
    emitToLogin(msg.to, 'message-deleted', { id: msg.id });
  });

  // Закреплено может быть только одно сообщение в личном диалоге.
  socket.on('pin-message', payload => {
    if (!loginForSocket || !payload || typeof payload.id !== 'string') return;
    const target = messages.find(m => m.id === payload.id &&
      ((m.from === loginForSocket && m.to === cleanLogin(payload.peer)) ||
       (m.to === loginForSocket && m.from === cleanLogin(payload.peer))));
    if (!target) return;
    const peer = cleanLogin(payload.peer);
    for (const m of messages) {
      if ((m.from === loginForSocket && m.to === peer) || (m.from === peer && m.to === loginForSocket)) {
        m.pinned = m.id === target.id;
      }
    }
    saveMessages();
    const conversation = getConversation(loginForSocket, peer).map(m => ({ ...m }));
    emitToLogin(loginForSocket, 'pin-updated', { peer, messages: conversation });
    emitToLogin(peer, 'pin-updated', { peer: loginForSocket, messages: conversation });
  });

  socket.on('typing', payload => {
    if (!loginForSocket || !payload) return;
    const to = cleanLogin(payload.to);
    if (users.some(u => u.login === to)) emitToLogin(to, 'typing', { from: loginForSocket, active: !!payload.active });
  });

  socket.on('read', payload => {
    if (!loginForSocket || !payload) return;
    const from = cleanLogin(payload.from);
    let changed = false;
    for (const msg of messages) {
      if (msg.from === from && msg.to === loginForSocket && !msg.read) {
        msg.read = true; changed = true;
        emitToLogin(msg.from, 'message-read', { id: msg.id });
      }
    }
    if (changed) saveMessages();
  });

  socket.on('disconnect', () => {
    if (!loginForSocket) return;
    const set = socketsByLogin.get(loginForSocket);
    if (set) {
      set.delete(socket.id);
      if (!set.size) socketsByLogin.delete(loginForSocket);
    }
    io.emit('online', onlineList());
  });
});

server.listen(PORT, () => {
  console.log(`YutuGram запущен: http://localhost:${PORT}`);
});
