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
const VIDEOS_FILE = path.join(DATA_DIR, 'videos.json');

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
let videos = readJson(VIDEOS_FILE, []);
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

function cleanLogin(value) {
  return String(value || '').trim().toLowerCase();
}
function publicUser(user) {
  return { login: user.login, name: user.name };
}
function validLogin(login) {
  return /^[a-z0-9_.-]{3,24}$/.test(login);
}
function getConversation(a, b) {
  return messages.filter(m => (m.from === a && m.to === b) || (m.from === b && m.to === a))
    .sort((x, y) => x.time - y.time);
}
function saveMessages() { writeJson(MESSAGES_FILE, messages); }
function saveVideos() { writeJson(VIDEOS_FILE, videos); }
function parseVideoUrl(input) {
  let url;
  try { url = new URL(String(input || '').trim()); } catch { return null; }
  if (!['http:', 'https:'].includes(url.protocol)) return null;
  const host = url.hostname.toLowerCase().replace(/^www\./, '').replace(/^m\./, '');
  let platform = '', id = '', embedUrl = '', ratio = '16:9';
  if (host === 'youtube.com' || host === 'youtu.be' || host === 'youtube-nocookie.com') {
    platform = 'YouTube';
    if (host === 'youtu.be') id = url.pathname.split('/').filter(Boolean)[0] || '';
    else id = url.searchParams.get('v') || (url.pathname.match(/\/(?:embed|shorts|live)\/([^/?]+)/) || [])[1] || '';
    if (!/^[\w-]{6,20}$/.test(id)) return null;
    embedUrl = `https://www.youtube.com/embed/${id}`;
  } else if (host === 'tiktok.com' || host.endsWith('.tiktok.com')) {
    platform = 'TikTok'; ratio = '9:16';
    id = (url.pathname.match(/\/video\/(\d+)/) || [])[1] || '';
    if (!id) return null;
    embedUrl = `https://www.tiktok.com/embed/v2/${id}`;
  } else if (host === 'instagram.com' || host.endsWith('.instagram.com')) {
    platform = 'Instagram'; ratio = '9:16';
    id = (url.pathname.match(/\/(?:p|reel|tv)\/([\w-]+)/) || [])[1] || '';
    if (!id) return null;
    embedUrl = `https://www.instagram.com/p/${id}/embed`;
  } else if (host === 'vk.com' || host === 'vk.ru' || host === 'm.vk.com') {
    platform = 'VK';
    const oid = url.searchParams.get('oid') || (url.pathname.match(/video(-?\d+)_/) || [])[1];
    id = url.searchParams.get('id') || (url.pathname.match(/video-?\d+_(\d+)/) || [])[1] || '';
    if (oid && id) embedUrl = `https://vk.com/video_ext.php?oid=${encodeURIComponent(oid)}&id=${encodeURIComponent(id)}`;
    else {
      const match = url.pathname.match(/video(-?\d+)_(\d+)/);
      if (!match) return null;
      embedUrl = `https://vk.com/video_ext.php?oid=${match[1]}&id=${match[2]}`; id = match[2];
    }
    ratio = '16:9';
  } else if (host === 'rutube.ru' || host.endsWith('.rutube.ru')) {
    platform = 'Rutube'; id = (url.pathname.match(/\/video\/([\w-]+)/) || [])[1] || '';
    if (!id) return null; embedUrl = `https://rutube.ru/play/embed/${id}`;
  } else if (host === 'twitter.com' || host === 'x.com' || host.endsWith('.twitter.com')) {
    platform = 'Twitter'; id = (url.pathname.match(/\/status\/(\d+)/) || [])[1] || '';
    if (!id) return null; embedUrl = `https://platform.twitter.com/embed/Tweet.html?id=${id}`;
  } else return null;
  return { platform, id, originalUrl: url.href, embedUrl, ratio };
}
function publicVideo(video, viewer) {
  return { ...video, liked: video.likes.includes(viewer), saved: video.savedBy.includes(viewer), likes: video.likes.length };
}
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
  res.json(getConversation(a, b).map(({ id, from, to, text, time, file, edited, read }) =>
    ({ id, from, to, text, time, file: file || null, edited: !!edited, read: !!read })));
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
    const msg = err.code === 'LIMIT_FILE_SIZE' ? 'Максимальный размер файла — 15 МБ' : 'Не удалось загрузить файл';
    return res.status(400).json({ error: msg });
  }
  if (err) return res.status(400).json({ error: err.message || 'Ошибка запроса' });
});

app.get('/api/videos', (req, res) => {
  const viewer = cleanLogin(req.query.login);
  const platform = String(req.query.platform || 'all');
  const allowed = ['all', 'TikTok', 'YouTube', 'VK'];
  if (!allowed.includes(platform)) return res.status(400).json({ error: 'Неизвестный фильтр' });
  res.set('Cache-Control', 'no-store');
  res.json(videos.filter(v => platform === 'all' || v.platform === platform).sort((a,b) => b.time-a.time).map(v => publicVideo(v, viewer)));
});
app.post('/api/videos', (req, res) => {
  const author = cleanLogin(req.body.login);
  if (!users.some(u => u.login === author)) return res.status(401).json({ error: 'Сначала войдите в аккаунт' });
  const parsed = parseVideoUrl(req.body.url);
  if (!parsed) return res.status(400).json({ error: 'Не удалось распознать ссылку. Поддерживаются TikTok, YouTube, Instagram, VK, Rutube и X/Twitter.' });
  const video = { id: crypto.randomUUID(), ...parsed, author, time: Date.now(), likes: [], comments: [], savedBy: [] };
  videos.push(video); saveVideos();
  const payload = publicVideo(video, author);
  io.emit('video-added', payload);
  res.status(201).json(payload);
});
app.post('/api/videos/:id/like', (req, res) => {
  const login = cleanLogin(req.body.login);
  if (!users.some(u => u.login === login)) return res.status(401).json({ error: 'Сначала войдите в аккаунт' });
  const video = videos.find(v => v.id === req.params.id);
  if (!video) return res.status(404).json({ error: 'Видео не найдено' });
  const idx = video.likes.indexOf(login); if (idx >= 0) video.likes.splice(idx, 1); else video.likes.push(login);
  saveVideos(); const payload = { id: video.id, likes: video.likes.length, login, liked: video.likes.includes(login) };
  io.emit('video-liked', payload); res.json(payload);
});
app.post('/api/videos/:id/comment', (req, res) => {
  const login = cleanLogin(req.body.login), text = String(req.body.text || '').trim().slice(0, 1000);
  if (!users.some(u => u.login === login)) return res.status(401).json({ error: 'Сначала войдите в аккаунт' });
  if (!text) return res.status(400).json({ error: 'Напиши комментарий' });
  const video = videos.find(v => v.id === req.params.id); if (!video) return res.status(404).json({ error: 'Видео не найдено' });
  const comment = { id: crypto.randomUUID(), login, text, time: Date.now() };
  video.comments.push(comment); saveVideos(); const payload = { id: video.id, comment };
  io.emit('video-commented', payload); res.status(201).json(payload);
});
app.delete('/api/videos/:id', (req, res) => {
  const login = cleanLogin(req.query.login || req.body.login);
  const idx = videos.findIndex(v => v.id === req.params.id);
  if (idx < 0) return res.status(404).json({ error: 'Видео не найдено' });
  if (videos[idx].author !== login) return res.status(403).json({ error: 'Удалить может только автор' });
  videos.splice(idx, 1); saveVideos(); io.emit('video-deleted', { id: req.params.id }); res.json({ ok: true });
});
app.get('/api/videos/saved/:login', (req, res) => {
  const login = cleanLogin(req.params.login);
  if (!users.some(u => u.login === login)) return res.status(401).json({ error: 'Пользователь не найден' });
  res.json(videos.filter(v => v.savedBy.includes(login)).sort((a,b)=>b.time-a.time).map(v=>publicVideo(v, login)));
});
app.post('/api/videos/:id/save', (req, res) => {
  const login = cleanLogin(req.body.login); if (!users.some(u=>u.login===login)) return res.status(401).json({error:'Сначала войдите в аккаунт'});
  const video = videos.find(v=>v.id===req.params.id); if (!video) return res.status(404).json({error:'Видео не найдено'});
  const idx=video.savedBy.indexOf(login); if(idx>=0)video.savedBy.splice(idx,1);else video.savedBy.push(login); saveVideos(); res.json({saved:video.savedBy.includes(login)});
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
      time: Date.now(), file, edited: false, read: false
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
