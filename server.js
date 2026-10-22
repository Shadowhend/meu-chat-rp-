'use strict';
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { maxHttpBufferSize: 4 * 1024 * 1024 });
app.use(express.json({ limit: '4mb' }));

// On Render, attach a persistent disk mounted at /var/data to retain accounts across deploys.
const dataDir = process.env.LOBBYZERO_DATA_DIR || (fs.existsSync('/var/data') ? '/var/data' : path.join(__dirname, 'data'));
fs.mkdirSync(dataDir, { recursive: true });
const usersFile = path.join(dataDir, 'users.json');
let users = {};
try { users = JSON.parse(fs.readFileSync(usersFile, 'utf8')); } catch (_) { users = {}; }
function saveUsers() { fs.writeFileSync(usersFile, JSON.stringify(users, null, 2), { mode: 0o600 }); }
const secretFile = path.join(dataDir, 'session-secret.txt');
let storedSecret = '';
try { storedSecret = fs.readFileSync(secretFile, 'utf8').trim(); } catch (_) {}
if (!process.env.SESSION_SECRET && !storedSecret) { storedSecret = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(secretFile, storedSecret, { mode: 0o600 }); }
const sessionsSecret = process.env.SESSION_SECRET || storedSecret;
const SESSION_COOKIE = 'lobbyzero_session';
const SESSION_MS = 30 * 24 * 60 * 60 * 1000;
const history = [];
const online = new Map();
const imageLastSent = new Map();

function safeName(value) { return typeof value === 'string' ? value.trim().slice(0, 32) : ''; }
function cookieValue(req, name) {
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i >= 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return '';
}
function sign(value) { return crypto.createHmac('sha256', sessionsSecret).update(value).digest('base64url'); }
function createToken(user) {
  const payload = Buffer.from(JSON.stringify({ username: user.username, exp: Date.now() + SESSION_MS })).toString('base64url');
  return payload + '.' + sign(payload);
}
function readToken(token) {
  if (!token || !token.includes('.')) return null;
  const [payload, signature] = token.split('.');
  const expected = sign(payload);
  const a = Buffer.from(signature || ''); const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data.username || data.exp < Date.now() || !users[data.username.toLowerCase()]) return null;
    return users[data.username.toLowerCase()];
  } catch (_) { return null; }
}
function currentUser(req) { return readToken(cookieValue(req, SESSION_COOKIE)); }
function setSession(res, user) {
  const token = createToken(user);
  res.cookie(SESSION_COOKIE, token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: SESSION_MS, path: '/' });
}
function clearSession(res) { res.clearCookie(SESSION_COOKIE, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/' }); }
function hashPassword(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, key) => {
      if (err) reject(err); else resolve(key.toString('hex'));
    });
  });
}

app.get('/api/me', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'Not signed in' });
  res.json({ username: user.username });
});
app.post('/api/register', async (req, res) => {
  const username = safeName(req.body && req.body.username);
  const password = req.body && req.body.password;
  if (!/^[A-Za-z0-9_-]{3,32}$/.test(username)) return res.status(400).json({ error: 'Username must be 3–32 characters (letters, numbers, _ or -).' });
  if (typeof password !== 'string' || password.length < 8 || password.length > 200) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const key = username.toLowerCase();
  if (users[key]) return res.status(409).json({ error: 'That username is already taken.' });
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = await hashPassword(password, salt);
  users[key] = { username, salt, passwordHash };
  saveUsers(); setSession(res, users[key]);
  res.json({ username });
});
app.post('/api/login', async (req, res) => {
  const username = safeName(req.body && req.body.username);
  const password = req.body && req.body.password;
  const user = users[username.toLowerCase()];
  if (!user || typeof password !== 'string') return res.status(401).json({ error: 'Incorrect username or password.' });
  const candidate = await hashPassword(password, user.salt);
  const a = Buffer.from(candidate, 'hex'); const b = Buffer.from(user.passwordHash, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: 'Incorrect username or password.' });
  setSession(res, user); res.json({ username: user.username });
});
app.post('/api/logout', (req, res) => { clearSession(res); res.json({ ok: true }); });
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

io.use((socket, next) => {
  const header = socket.handshake.headers.cookie || '';
  const part = header.split(';').map(x => x.trim()).find(x => x.startsWith(SESSION_COOKIE + '='));
  const token = part ? decodeURIComponent(part.slice(SESSION_COOKIE.length + 1)) : '';
  const user = readToken(token);
  if (!user) return next(new Error('Please sign in to use Lobby Zero.'));
  socket.user = user;
  next();
});
function emitOnline() {
  io.emit('lista_participantes', Array.from(online.entries()).map(([id, person]) => ({ id, personagem: person.personagem, foto: person.foto })));
}
function safePhoto(value) {
  if (typeof value !== 'string' || value.length > 2000) return '';
  try { const u = new URL(value); return ['https:', 'http:'].includes(u.protocol) ? u.href : ''; } catch (_) { return ''; }
}
function isAllowedImage(data) {
  return typeof data === 'string' && data.length <= 2_800_000 && /^data:image\/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/=]+$/.test(data);
}
io.on('connection', socket => {
  const accountName = socket.user.username;
  socket.emit('carregar_historico', history);
  socket.on('registrar_participante', data => {
    data = data || {};
    online.set(socket.id, { personagem: safeName(data.personagem) || accountName, foto: safePhoto(data.foto), accountName });
    emitOnline();
  });
  socket.on('msg_rp', (data, ack) => {
    data = data || {};
    const text = typeof data.texto === 'string' ? data.texto.slice(0, 4000) : '';
    const image = data.imagem || '';
    if (!text.trim() && !image) { if (typeof ack === 'function') ack({ error: 'Message is empty.' }); return; }
    if (image) {
      if (!isAllowedImage(image)) { if (typeof ack === 'function') ack({ error: 'Image must be PNG, JPEG, GIF or WebP and smaller than 2 MB.' }); return; }
      const now = Date.now(); const previous = imageLastSent.get(socket.id) || 0;
      if (now - previous < 5000) { if (typeof ack === 'function') ack({ error: `Wait ${Math.ceil((5000 - (now - previous)) / 1000)} seconds before sending another image.` }); return; }
      imageLastSent.set(socket.id, now);
    }
    const current = online.get(socket.id) || { personnage: accountName, foto: '' };
    const message = { id: socket.id, personagem: safeName(data.personagem) || current.personagem || accountName, texto: text, foto: safePhoto(data.foto) || current.foto || '', imagem, timestamp: Date.now() };
    if (image && !text) message.texto = '';
    history.push(message); if (history.length > 100) history.shift();
    socket.broadcast.emit('enviar_msg_rp', message);
    socket.emit('enviar_msg_rp', message);
    if (typeof ack === 'function') ack({ ok: true });
  });
  socket.on('disconnect', () => { online.delete(socket.id); imageLastSent.delete(socket.id); emitOnline(); });
});
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`LobbyZero running on port ${PORT}`));
