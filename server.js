'use strict';
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is required. Add the PostgreSQL Internal Database URL in Render Environment.');
  process.exit(1);
}
if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
  console.error('SESSION_SECRET is required in production. Add a long random secret in Render Environment.');
  process.exit(1);
}
const sessionsSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Render's internal database connection normally does not require SSL.
  // Set PGSSL=true only if your database provider requires TLS.
  ...(process.env.PGSSL === 'true' ? { ssl: { rejectUnauthorized: false } } : {})
});
const app = express();
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 4 * 1024 * 1024 });
app.use(express.json({ limit: '4mb' }));
app.use(express.static(__dirname, { index: false }));

const SESSION_COOKIE = 'lobbyzero_session';
const SESSION_MS = 30 * 24 * 60 * 60 * 1000;
const history = [];
const online = new Map();
const imageLastSent = new Map();

async function initDatabase() {
  await pool.query(`CREATE TABLE IF NOT EXISTS lobbyzero_users (
    username_key VARCHAR(32) PRIMARY KEY,
    username VARCHAR(32) NOT NULL,
    salt VARCHAR(64) NOT NULL,
    password_hash VARCHAR(128) NOT NULL,
    avatar_url VARCHAR(2000) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`ALTER TABLE lobbyzero_users ADD COLUMN IF NOT EXISTS avatar_url VARCHAR(2000) NOT NULL DEFAULT ''`);
  await pool.query(`CREATE TABLE IF NOT EXISTS lobbyzero_character_sheets (username_key VARCHAR(32) PRIMARY KEY REFERENCES lobbyzero_users(username_key) ON DELETE CASCADE, sheet JSONB NOT NULL DEFAULT '{}'::jsonb, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  console.log('PostgreSQL ready.');
}
function safeName(value) { return typeof value === 'string' ? value.trim().slice(0, 32) : ''; }
function cookieValue(req, name) {
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i >= 0 && part.slice(0, i).trim() === name) {
      try { return decodeURIComponent(part.slice(i + 1).trim()); } catch (_) { return ''; }
    }
  }
  return '';
}
function sign(value) { return crypto.createHmac('sha256', sessionsSecret).update(value).digest('base64url'); }
function createToken(user) {
  const payload = Buffer.from(JSON.stringify({ username: user.username, exp: Date.now() + SESSION_MS })).toString('base64url');
  return payload + '.' + sign(payload);
}
async function readToken(token) {
  if (!token || !token.includes('.')) return null;
  const dot = token.lastIndexOf('.');
  const payload = token.slice(0, dot), signature = token.slice(dot + 1);
  const expected = sign(payload);
  const a = Buffer.from(signature), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data.username || !Number.isFinite(data.exp) || data.exp < Date.now()) return null;
    const result = await pool.query('SELECT username, avatar_url FROM lobbyzero_users WHERE username_key = $1', [data.username.toLowerCase()]);
    return result.rowCount ? { username: result.rows[0].username, avatarUrl: result.rows[0].avatar_url || '' } : null;
  } catch (_) { return null; }
}
async function currentUser(req) { return readToken(cookieValue(req, SESSION_COOKIE)); }
function setSession(res, user) {
  res.cookie(SESSION_COOKIE, createToken(user), {
    httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: SESSION_MS, path: '/'
  });
}
function clearSession(res) { res.clearCookie(SESSION_COOKIE, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/' }); }
function hashPassword(password, salt) {
  return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, (err, key) => err ? reject(err) : resolve(key.toString('hex'))));
}
app.get('/api/me', async (req, res) => {
  try {
    const user = await currentUser(req);
    if (!user) return res.status(401).json({ error: 'Not signed in' });
    res.json({ username: user.username, avatarUrl: user.avatarUrl || '' });
  } catch (error) { console.error('Session lookup failed:', error.message); res.status(500).json({ error: 'Account service temporarily unavailable.' }); }
});
app.post('/api/register', async (req, res) => {
  try {
    const username = safeName(req.body && req.body.username);
    const password = req.body && req.body.password;
    const avatarUrl = '';
    if (!/^[A-Za-z0-9_-]{3,32}$/.test(username)) return res.status(400).json({ error: 'Username must be 3–32 characters (letters, numbers, _ or -).' });
    if (typeof password !== 'string' || password.length < 8 || password.length > 200) return res.status(400).json({ error: 'Password must be 8–200 characters.' });
    const key = username.toLowerCase();
    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = await hashPassword(password, salt);
    try {
      await pool.query('INSERT INTO lobbyzero_users (username_key, username, salt, password_hash, avatar_url) VALUES ($1, $2, $3, $4, $5)', [key, username, salt, passwordHash, avatarUrl]);
    } catch (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'That username is already taken.' });
      throw error;
    }
    setSession(res, { username });
    res.json({ username, avatarUrl });
  } catch (error) { console.error('Registration failed:', error.message); res.status(500).json({ error: 'Could not create account. Please try again.' }); }
});
app.post('/api/login', async (req, res) => {
  try {
    const username = safeName(req.body && req.body.username);
    const password = req.body && req.body.password;
    if (typeof password !== 'string') return res.status(401).json({ error: 'Incorrect username or password.' });
    const result = await pool.query('SELECT username, salt, password_hash, avatar_url FROM lobbyzero_users WHERE username_key = $1', [username.toLowerCase()]);
    if (!result.rowCount) return res.status(401).json({ error: 'Incorrect username or password.' });
    const user = result.rows[0];
    const candidate = Buffer.from(await hashPassword(password, user.salt), 'hex');
    const stored = Buffer.from(user.password_hash, 'hex');
    if (candidate.length !== stored.length || !crypto.timingSafeEqual(candidate, stored)) return res.status(401).json({ error: 'Incorrect username or password.' });
    const avatarUrl = user.avatar_url || '';
    setSession(res, { username: user.username });
    res.json({ username: user.username, avatarUrl });
  } catch (error) { console.error('Login failed:', error.message); res.status(500).json({ error: 'Account service temporarily unavailable.' }); }
});
app.post('/api/avatar', async (req, res) => {
  try {
    const user = await currentUser(req);
    if (!user) return res.status(401).json({ error: 'Log in to save your avatar URL.' });
    const raw = req.body && typeof req.body.avatarUrl === 'string' ? req.body.avatarUrl.trim() : '';
    const avatarUrl = raw ? safePhoto(raw) : '';
    if (raw && !avatarUrl) return res.status(400).json({ error: 'Avatar must be a valid HTTP or HTTPS URL.' });
    await pool.query('UPDATE lobbyzero_users SET avatar_url = $1 WHERE username_key = $2', [avatarUrl, user.username.toLowerCase()]);
    res.json({ ok: true, avatarUrl });
  } catch (error) { console.error('Avatar update failed:', error.message); res.status(500).json({ error: 'Could not save avatar URL.' }); }
});
app.post('/api/logout', (req, res) => { clearSession(res); res.json({ ok: true }); });
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// Authentication is optional: visitors may connect without an account.
io.use(async (socket, next) => {
  try {
    const header = socket.handshake.headers.cookie || '';
    const part = header.split(';').map(x => x.trim()).find(x => x.startsWith(SESSION_COOKIE + '='));
    let token = '';
    if (part) { try { token = decodeURIComponent(part.slice(SESSION_COOKIE.length + 1)); } catch (_) {} }
    socket.user = token ? await readToken(token) : null;
    socket.guestId = crypto.randomUUID();
    next();
  } catch (error) { console.error('Socket auth check failed:', error.message); next(new Error('Unable to connect right now.')); }
});
function emitOnline() {
  io.emit('lista_participantes', Array.from(online.entries()).map(([id, person]) => ({ id, personagem: person.personagem, foto: person.foto, accountName: person.accountName || '' })));
}
function safePhoto(value) {
  if (typeof value !== 'string' || value.length > 2000) return '';
  try { const u = new URL(value); return ['https:', 'http:'].includes(u.protocol) ? u.href : ''; } catch (_) { return ''; }
}
function isAllowedImage(data) {
  return typeof data === 'string' && data.length <= 2_800_000 && /^data:image\/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/=]+$/.test(data);
}
io.on('connection', socket => {
  const accountName = socket.user ? socket.user.username : 'Guest';
  socket.emit('carregar_historico', history);
  socket.on('registrar_participante', data => {
    data = data || {};
    const existing = online.get(socket.id) || {};
    online.set(socket.id, { personagem: safeName(data.personagem) || accountName, foto: safePhoto(data.foto) || (socket.user && socket.user.avatarUrl) || '', accountName, sheet: existing.sheet || {} });
    emitOnline();
  });
  socket.on('get_character_sheet', async (data, ack) => {
    if (typeof ack !== 'function') return;
    try {
      const targetId = data && typeof data.targetId === 'string' ? data.targetId : socket.id;
      const target = online.get(targetId);
      if (!target) return ack({ error: 'That participant is no longer online.' });
      if (target.accountName) {
        const result = await pool.query('SELECT sheet FROM lobbyzero_character_sheets WHERE username_key = $1', [target.accountName.toLowerCase()]);
        const sheet = result.rowCount && result.rows[0].sheet ? result.rows[0].sheet : {};
        if (targetId === socket.id) target.sheet = sheet;
        return ack({ sheet, owner: target.accountName });
      }
      return ack({ sheet: target.sheet || {}, owner: '' });
    } catch (error) {
      console.error('Could not load character sheet:', error.message);
      ack({ error: 'Could not load this character sheet.' });
    }
  });
  socket.on('save_character_sheet', async (data, ack) => {
    if (typeof ack !== 'function') return;
    try {
      const person = online.get(socket.id);
      if (!person) return ack({ error: 'Register your presence before saving a sheet.' });
      const input = data && data.sheet && typeof data.sheet === 'object' ? data.sheet : {};
      const allowed = ['characterName','age','species','role','appearance','personality','backstory','abilities','extra'];
      const sheet = {};
      for (const key of allowed) sheet[key] = typeof input[key] === 'string' ? input[key].slice(0, key === 'backstory' ? 5000 : key === 'abilities' || key === 'extra' ? 3000 : key === 'appearance' || key === 'personality' ? 2000 : 120) : '';
      if (socket.user) {
        await pool.query(`INSERT INTO lobbyzero_character_sheets (username_key, sheet, updated_at) VALUES ($1, $2::jsonb, NOW()) ON CONFLICT (username_key) DO UPDATE SET sheet = EXCLUDED.sheet, updated_at = NOW()`, [socket.user.username.toLowerCase(), JSON.stringify(sheet)]);
      }
      person.sheet = sheet;
      online.set(socket.id, person);
      emitOnline();
      ack({ ok: true, persisted: !!socket.user });
    } catch (error) {
      console.error('Could not save character sheet:', error.message);
      ack({ error: 'Could not save this character sheet.' });
    }
  });
  socket.on('msg_rp', (data, ack) => {
    data = data || {};
    const text = typeof data.texto === 'string' ? data.texto.slice(0, 4000) : '';
    const image = typeof data.imagem === 'string' ? data.imagem : '';
    if (!text.trim() && !image) { if (typeof ack === 'function') ack({ error: 'Message is empty.' }); return; }
    if (image) {
      if (!isAllowedImage(image)) { if (typeof ack === 'function') ack({ error: 'Image must be PNG, JPEG, GIF or WebP and smaller than 2 MB.' }); return; }
      const now = Date.now(), previous = imageLastSent.get(socket.id) || 0;
      if (now - previous < 5000) { if (typeof ack === 'function') ack({ error: `Wait ${Math.ceil((5000 - (now - previous)) / 1000)} seconds before sending another image.` }); return; }
      imageLastSent.set(socket.id, now);
    }
    const current = online.get(socket.id) || { personagem: accountName, foto: '' };
    const message = {
      id: socket.id,
      personagem: safeName(data.personagem) || current.personagem || accountName,
      texto: text,
      foto: safePhoto(data.foto) || current.foto || (socket.user && socket.user.avatarUrl) || '',
      imagem: image,
      timestamp: Date.now()
    };
    history.push(message);
    if (history.length > 100) history.shift();
    socket.broadcast.emit('enviar_msg_rp', message);
    socket.emit('enviar_msg_rp', message);
    if (typeof ack === 'function') ack({ ok: true });
  });
  socket.on('disconnect', () => { online.delete(socket.id); imageLastSent.delete(socket.id); emitOnline(); });
});
const PORT = process.env.PORT || 3000;
initDatabase().then(() => server.listen(PORT, () => console.log(`LobbyZero running on port ${PORT}`))).catch(error => {
  console.error('Could not initialize PostgreSQL:', error.message);
  process.exit(1);
});
