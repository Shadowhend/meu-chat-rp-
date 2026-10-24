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
const histories = new Map();
const online = new Map();
const COMMUNITIES = ['comunidade-1', 'comunidade-2', 'comunidade-3'];
function safeCommunity(value) { return COMMUNITIES.includes(value) ? value : COMMUNITIES[0]; }
function roomHistory(community) { if (!histories.has(community)) histories.set(community, []); return histories.get(community); }
const imageLastSent = new Map();
// Mutes apply to a guest connection for as long as that connection stays online.
const mutedGuests = new Set();

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
  await pool.query(`CREATE TABLE IF NOT EXISTS lobbyzero_community_admins (username_key VARCHAR(32) NOT NULL REFERENCES lobbyzero_users(username_key) ON DELETE CASCADE, community VARCHAR(32) NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY (username_key, community))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS lobbyzero_suspensions (username_key VARCHAR(32) NOT NULL REFERENCES lobbyzero_users(username_key) ON DELETE CASCADE, community VARCHAR(32) NOT NULL, reason VARCHAR(500) NOT NULL DEFAULT '', suspended_until TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY (username_key, community))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS lobbyzero_community_admins (username_key VARCHAR(32) NOT NULL REFERENCES lobbyzero_users(username_key) ON DELETE CASCADE, community VARCHAR(32) NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY (username_key, community))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS lobbyzero_suspensions (username_key VARCHAR(32) NOT NULL REFERENCES lobbyzero_users(username_key) ON DELETE CASCADE, community VARCHAR(32) NOT NULL, reason VARCHAR(500) NOT NULL DEFAULT '', suspended_until TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY (username_key, community))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS lobbyzero_community_settings (community VARCHAR(32) PRIMARY KEY, background_url TEXT NOT NULL DEFAULT '', music_url TEXT NOT NULL DEFAULT '', updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS lobbyzero_character_sheets (username_key VARCHAR(32) PRIMARY KEY REFERENCES lobbyzero_users(username_key) ON DELETE CASCADE, sheet JSONB NOT NULL DEFAULT '{}'::jsonb, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  const bootstrap = safeName(process.env.ADMIN_BOOTSTRAP_USERNAME || '');
  if (bootstrap) {
    const exists = await pool.query('SELECT username_key FROM lobbyzero_users WHERE username_key = $1', [bootstrap.toLowerCase()]);
    if (exists.rowCount) for (const community of COMMUNITIES) await pool.query('INSERT INTO lobbyzero_community_admins (username_key, community) VALUES ($1, $2) ON CONFLICT DO NOTHING', [bootstrap.toLowerCase(), community]);
    else console.warn('ADMIN_BOOTSTRAP_USERNAME is set but that account does not exist yet. Register the account, then restart the service to grant initial admin access.');
  }
  console.log('PostgreSQL ready. Communities:', COMMUNITIES.join(', '));
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
const bootstrapAdminKey = () => safeName(process.env.ADMIN_BOOTSTRAP_USERNAME || '').toLowerCase();
function isSuperAdmin(user) { return !!user && !!bootstrapAdminKey() && user.username.toLowerCase() === bootstrapAdminKey(); }
async function adminUser(req, res, community) {
  const user = await currentUser(req);
  if (!user) { res.status(401).json({ error: 'Faça login para acessar a administração.' }); return null; }
  if (isSuperAdmin(user)) return user;
  const allowed = await pool.query('SELECT 1 FROM lobbyzero_community_admins WHERE username_key = $1 AND community = $2', [user.username.toLowerCase(), safeCommunity(community)]);
  if (!allowed.rowCount) { res.status(403).json({ error: 'Você não é administrador desta comunidade.' }); return null; }
  return user;
}
app.get('/api/admin/communities', async (req, res) => {
  try {
    const user = await currentUser(req);
    if (!user) return res.status(401).json({ error: 'Faça login para acessar a administração.' });
    const result = await pool.query('SELECT community FROM lobbyzero_community_admins WHERE username_key = $1 ORDER BY community', [user.username.toLowerCase()]);
    const superAdmin = isSuperAdmin(user);
    res.json({ communities: superAdmin ? COMMUNITIES : result.rows.map(row => row.community), allCommunities: COMMUNITIES, superAdmin });
  } catch (error) { console.error('Admin communities failed:', error.message); res.status(500).json({ error: 'Não foi possível carregar as permissões.' }); }
});
app.get('/api/admin/overview', async (req, res) => {
  try {
    const community = safeCommunity(req.query.community);
    const user = await adminUser(req, res, community); if (!user) return;
    const users = await pool.query(`SELECT u.username, u.created_at, EXISTS(SELECT 1 FROM lobbyzero_suspensions s WHERE s.username_key=u.username_key AND s.community=$1 AND (s.suspended_until IS NULL OR s.suspended_until > NOW())) AS suspended FROM lobbyzero_users u ORDER BY u.created_at DESC LIMIT 300`, [community]);
    const totalUsers = await pool.query('SELECT COUNT(*)::int AS count FROM lobbyzero_users');
    const admins = await pool.query('SELECT u.username, a.created_at FROM lobbyzero_community_admins a JOIN lobbyzero_users u ON u.username_key=a.username_key WHERE a.community=$1 ORDER BY u.username', [community]);
    const onlineUsers = Array.from(online.entries()).filter(([, person]) => person.community === community).map(([id, person]) => ({ id, username: person.accountName || 'Guest', character: person.personagem || '', isAccount: !!person.isAccount, muted: mutedGuests.has(id) }));
    res.json({ community, users: users.rows, admins: admins.rows, superAdmin: isSuperAdmin(user), online: onlineUsers, onlineCount: onlineUsers.length, registeredCount: totalUsers.rows[0].count, messagesInMemory: roomHistory(community).length });
  } catch (error) { console.error('Admin overview failed:', error.message); res.status(500).json({ error: 'Não foi possível carregar o painel.' }); }
});
app.post('/api/admin/roles', async (req, res) => {
  try {
    const community = safeCommunity(req.body && req.body.community);
    const actor = await adminUser(req, res, community); if (!actor) return;
    const username = safeName(req.body && req.body.username), grant = !!(req.body && req.body.grant);
    const target = await pool.query('SELECT username_key FROM lobbyzero_users WHERE username_key=$1', [username.toLowerCase()]);
    if (!target.rowCount) return res.status(404).json({ error: 'Cadastre a conta antes de torná-la administradora.' });
    if (grant) await pool.query('INSERT INTO lobbyzero_community_admins (username_key, community) VALUES ($1,$2) ON CONFLICT DO NOTHING', [username.toLowerCase(), community]);
    else {
      if (username.toLowerCase() === bootstrapAdminKey()) return res.status(400).json({ error: 'A conta ADM supremo é definida por ADMIN_BOOTSTRAP_USERNAME no Render. Para retirar esse privilégio, altere ou remova essa variável no Render.' });
      if (username.toLowerCase() === actor.username.toLowerCase() && !isSuperAdmin(actor)) return res.status(400).json({ error: 'Um ADM de comunidade não pode remover a própria permissão. Peça a outro ADM ou ao ADM supremo.' });
      await pool.query('DELETE FROM lobbyzero_community_admins WHERE username_key=$1 AND community=$2', [username.toLowerCase(), community]);
    }
    res.json({ ok: true, admin: grant, community });
  } catch (error) { console.error('Admin role update failed:', error.message); res.status(500).json({ error: 'Não foi possível alterar a permissão administrativa.' }); }
});
app.post('/api/admin/suspensions', async (req, res) => {
  try {
    const community = safeCommunity(req.body && req.body.community);
    const actor = await adminUser(req, res, community); if (!actor) return;
    const username = safeName(req.body && req.body.username), suspend = !!(req.body && req.body.suspend);
    const target = await pool.query('SELECT username_key FROM lobbyzero_users WHERE username_key=$1', [username.toLowerCase()]);
    if (!target.rowCount) return res.status(404).json({ error: 'Usuário não encontrado.' });
    if (target.rows[0].username_key === actor.username.toLowerCase()) return res.status(400).json({ error: 'Você não pode suspender sua própria conta.' });
    if (suspend) {
      const reason = typeof req.body.reason === 'string' ? req.body.reason.slice(0,500) : '';
      await pool.query('INSERT INTO lobbyzero_suspensions (username_key, community, reason, suspended_until) VALUES ($1,$2,$3,NULL) ON CONFLICT (username_key, community) DO UPDATE SET reason=EXCLUDED.reason, suspended_until=NULL, created_at=NOW()', [username.toLowerCase(), community, reason]);
      for (const [id, person] of online) if (person.community === community && person.isAccount && String(person.accountName).toLowerCase() === username.toLowerCase()) io.sockets.sockets.get(id)?.disconnect(true);
    } else await pool.query('DELETE FROM lobbyzero_suspensions WHERE username_key=$1 AND community=$2', [username.toLowerCase(), community]);
    res.json({ ok: true, suspended: suspend });
  } catch (error) { console.error('Admin suspension failed:', error.message); res.status(500).json({ error: 'Não foi possível alterar a suspensão.' }); }
});
app.post('/api/admin/mute-guest', async (req, res) => {
  try {
    const community = safeCommunity(req.body && req.body.community);
    const actor = await adminUser(req, res, community); if (!actor) return;
    const targetId = req.body && req.body.socketId;
    const target = online.get(targetId);
    if (!target || target.community !== community) return res.status(404).json({ error: 'Participante não encontrado nesta comunidade.' });
    if (target.isAccount) return res.status(400).json({ error: 'Esta ação é somente para guests.' });
    const mute = !!(req.body && req.body.mute);
    if (mute) mutedGuests.add(targetId); else mutedGuests.delete(targetId);
    io.to(targetId).emit('guest_mute_changed', { muted: mute, message: mute ? 'Você foi silenciado por um administrador.' : 'Seu silêncio foi removido.' });
    res.json({ ok: true, muted: mute });
  } catch (error) { console.error('Guest mute failed:', error.message); res.status(500).json({ error: 'Não foi possível alterar o silêncio do guest.' }); }
});
app.post('/api/admin/history/clear', async (req, res) => {
  try {
    const community = safeCommunity(req.body && req.body.community);
    const user = await adminUser(req, res, community); if (!user) return;
    const allCommunities = !!(req.body && req.body.allCommunities);
    if (allCommunities && !isSuperAdmin(user)) return res.status(403).json({ error: 'Somente o ADM supremo pode limpar todas as comunidades.' });
    const targets = allCommunities ? COMMUNITIES : [community];
    const counts = {};
    for (const target of targets) {
      counts[target] = roomHistory(target).length;
      histories.set(target, []);
      io.to(target).emit('admin_history_cleared', { community: target });
    }
    res.json({ ok: true, cleared: counts, allCommunities });
  } catch (error) { console.error('Admin history clear failed:', error.message); res.status(500).json({ error: 'Não foi possível limpar o histórico.' }); }
});
app.post('/api/admin/messages/delete', async (req, res) => {
  try {
    const community = safeCommunity(req.body && req.body.community);
    const user = await adminUser(req, res, community); if (!user) return;
    const id = req.body && req.body.id;
    if (typeof id !== 'string' || !id.trim()) return res.status(400).json({ error: 'ID da mensagem inválido.' });
    const messages = roomHistory(community);
    const index = messages.findIndex(message => String(message.messageId) === id);
    // Always broadcast the removal to this community. A message can still be visible
    // in a connected client even if its in-memory history was reset by a server restart.
    if (index >= 0) messages.splice(index, 1);
    io.to(community).emit('admin_message_deleted', { messageId: id });
    res.json({ ok: true, removedFromHistory: index >= 0 });
  } catch (error) { console.error('Admin message deletion failed:', error.message); res.status(500).json({ error: 'Não foi possível apagar a mensagem.' }); }
});
app.post('/api/admin/disconnect', async (req, res) => {
  try {
    const community = safeCommunity(req.body && req.body.community);
    const user = await adminUser(req, res, community); if (!user) return;
    const targetId = req.body && req.body.socketId, target = online.get(targetId);
    if (!target || target.community !== community) return res.status(404).json({ error: 'Participante não encontrado nesta comunidade.' });
    const targetSocket = io.sockets.sockets.get(targetId); if (targetSocket) { targetSocket.emit('admin_disconnected', { message: 'Você foi desconectado por um administrador desta comunidade.' }); targetSocket.disconnect(true); }
    res.json({ ok: true });
  } catch (error) { console.error('Admin disconnect failed:', error.message); res.status(500).json({ error: 'Não foi possível desconectar o participante.' }); }
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
    socket.community = safeCommunity(socket.handshake.query && socket.handshake.query.community);
    if (socket.user) { const suspended = await pool.query('SELECT 1 FROM lobbyzero_suspensions WHERE username_key=$1 AND community=$2 AND (suspended_until IS NULL OR suspended_until > NOW())', [socket.user.username.toLowerCase(), socket.community]); if (suspended.rowCount) return next(new Error('Sua conta está suspensa nesta comunidade.')); }
    socket.join(socket.community);
    socket.guestId = crypto.randomUUID();
    next();
  } catch (error) { console.error('Socket auth check failed:', error.message); next(new Error('Unable to connect right now.')); }
});
function emitOnline() {
  // Each registered account appears only once in each viewer's roster, even
  // when several tabs/devices are connected. For the account owner, prefer
  // that viewer's own socket so their profile remains editable in that tab.
  // Guests remain separate participants per connection.
  const entries = Array.from(online.entries());
  for (const viewer of io.sockets.sockets.values()) {
    const chosen = new Map();
    for (const [id, person] of entries) {
      if (person.community !== (viewer.community || COMMUNITIES[0])) continue;
      const key = person.isAccount
        ? `account:${person.community}:${String(person.accountName || '').toLowerCase()}`
        : `guest:${id}`;
      const existing = chosen.get(key);
      const viewerOwnAccount = person.isAccount && viewer.user &&
        String(viewer.user.username).toLowerCase() === String(person.accountName || '').toLowerCase();
      if (!existing || viewerOwnAccount) chosen.set(key, { id, person });
    }
    const viewerCommunity = viewer.community || COMMUNITIES[0];
    const roster = Array.from(chosen.values()).filter(({ person }) => person.community === viewerCommunity).map(({ id, person }) => ({
      id, personagem: person.personagem, foto: person.foto,
      accountName: person.accountName || 'Guest',
      sheet: person.isAccount ? undefined : (person.sheet || {})
    }));
    viewer.emit('lista_participantes', roster);
  }
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
  socket.emit('carregar_historico', roomHistory(socket.community));
  pool.query('SELECT background_url,music_url FROM lobbyzero_community_settings WHERE community=$1',[socket.community]).then(r=>{const row=r.rows[0]||{}; socket.emit('server_background_changed',{url:row.background_url||''}); if(row.music_url) socket.emit('server_music_changed',{url:row.music_url});}).catch(e=>console.error('Community settings load failed:',e.message));
  async function canManageCommunity(){ if(!socket.user) return false; if(isSuperAdmin(socket.user)) return true; const r=await pool.query('SELECT 1 FROM lobbyzero_community_admins WHERE username_key=$1 AND community=$2',[socket.user.username.toLowerCase(),socket.community]); return !!r.rowCount; }
  canManageCommunity().then(isAdmin => socket.emit('community_tool_permissions',{isAdmin})).catch(()=>socket.emit('community_tool_permissions',{isAdmin:false}));
  socket.on('admin_server_background', async (data,ack)=>{ const reply=typeof ack==='function'?ack:()=>{}; try { if(!await canManageCommunity()) return reply({error:'Somente administradores desta comunidade podem alterar o fundo.'}); const url=typeof(data&&data.url)==='string'?data.url.trim():''; let parsed; try{parsed=new URL(url)}catch(_){return reply({error:'URL inválida.'})} if(parsed.protocol!=='https:' || url.length>2000) return reply({error:'Use uma URL HTTPS válida de até 2000 caracteres.'}); await pool.query(`INSERT INTO lobbyzero_community_settings(community,background_url) VALUES($1,$2) ON CONFLICT(community) DO UPDATE SET background_url=EXCLUDED.background_url,updated_at=NOW()`,[socket.community,url]); io.to(socket.community).emit('server_background_changed',{url}); reply({ok:true}); } catch(e){console.error('Community background update failed:',e.message);reply({error:'Não foi possível atualizar o fundo.'})} });
  socket.on('admin_server_music_stop', async (data,ack)=>{ const reply=typeof ack==='function'?ack:()=>{}; try { if(!await canManageCommunity()) return reply({error:'Somente administradores desta comunidade podem parar a música para todos.'}); await pool.query(`INSERT INTO lobbyzero_community_settings(community,music_url) VALUES($1,'') ON CONFLICT(community) DO UPDATE SET music_url='',updated_at=NOW()`,[socket.community]); io.to(socket.community).emit('server_music_changed',{url:''}); reply({ok:true}); } catch(e) { console.error('Community music stop failed:',e.message); reply({error:'Não foi possível parar a música da comunidade.'}); } });
  socket.on('admin_server_music', async (data,ack)=>{ const reply=typeof ack==='function'?ack:()=>{}; try { if(!await canManageCommunity()) return reply({error:'Somente administradores desta comunidade podem controlar a música.'}); const url=typeof(data&&data.url)==='string'?data.url.trim():''; const validDataAudio=/^data:audio\/(mpeg|mp3|ogg|wav|mp4|webm);base64,[A-Za-z0-9+/=]+$/.test(url) && url.length<=2_850_000; let parsed; try{parsed=new URL(url)}catch(_){} if(!validDataAudio && (!parsed || parsed.protocol!=='https:' || url.length>2000)) return reply({error:'Envie um arquivo de áudio de até 2 MB.'}); await pool.query(`INSERT INTO lobbyzero_community_settings(community,music_url) VALUES($1,$2) ON CONFLICT(community) DO UPDATE SET music_url=EXCLUDED.music_url,updated_at=NOW()`,[socket.community,url]); io.to(socket.community).emit('server_music_changed',{url}); reply({ok:true}); } catch(e){console.error('Community music update failed:',e.message);reply({error:'Não foi possível iniciar a música.'})} });
  socket.on('registrar_participante', data => {
    data = data || {};
    const existing = online.get(socket.id) || {};
    online.set(socket.id, {
      personagem: safeName(data.personagem) || accountName,
      foto: safePhoto(data.foto) || (socket.user && socket.user.avatarUrl) || '',
      accountName, isAccount: !!socket.user, community: socket.community, sheet: existing.sheet || {}
    });
    emitOnline();
  });
  socket.on('get_character_sheet', async (data, ack) => {
    if (typeof ack !== 'function') return;
    try {
      const targetId = data && typeof data.targetId === 'string' ? data.targetId : socket.id;
      const target = online.get(targetId);
      if (!target || target.community !== socket.community) return ack({ error: 'That participant is no longer online in this community.' });
      if (target.isAccount && target.accountName) {
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
      const allowed = ['content'];
      const sheet = {};
      for (const key of allowed) sheet[key] = typeof input[key] === 'string' ? input[key].slice(0, 12000) : '';
      if (socket.user) {
        await pool.query(`INSERT INTO lobbyzero_character_sheets (username_key, sheet, updated_at) VALUES ($1, $2::jsonb, NOW()) ON CONFLICT (username_key) DO UPDATE SET sheet = EXCLUDED.sheet, updated_at = NOW()`, [socket.user.username.toLowerCase(), JSON.stringify(sheet)]);
      }
      person.sheet = sheet;
      online.set(socket.id, person);
      emitOnline();
      io.to(socket.community).emit('character_sheet_updated', { ownerId: socket.id, sheet, persisted: !!socket.user });
      ack({ ok: true, persisted: !!socket.user });
    } catch (error) {
      console.error('Could not save character sheet:', error.message);
      ack({ error: 'Could not save this character sheet.' });
    }
  });
  socket.on('msg_rp', async (data, ack) => {
    data = data || {};
    if (!socket.user && mutedGuests.has(socket.id)) { if (typeof ack === 'function') ack({ error: 'Você está silenciado nesta comunidade.' }); return; }
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
    let isAdmin = false;
    if (socket.user) { try { isAdmin = isSuperAdmin(socket.user) || !!(await pool.query('SELECT 1 FROM lobbyzero_community_admins WHERE username_key=$1 AND community=$2',[socket.user.username.toLowerCase(),socket.community])).rowCount; } catch (_) {} }
    const message = {
      id: socket.id,
      isHost: isSuperAdmin(socket.user),
      isAdmin,
      accountName,
      personagem: safeName(data.personagem) || current.personagem || accountName,
      texto: text,
      foto: safePhoto(data.foto) || current.foto || (socket.user && socket.user.avatarUrl) || '',
      imagem: image,
      timestamp: Date.now()
    };
    message.messageId = crypto.randomUUID();
    message.community = socket.community;
    const history = roomHistory(socket.community);
    history.push(message);
    if (history.length > 100) history.shift();
    socket.to(socket.community).emit('enviar_msg_rp', message);
    socket.emit('enviar_msg_rp', message);
    if (typeof ack === 'function') ack({ ok: true });
  });
  socket.on('disconnect', () => { online.delete(socket.id); imageLastSent.delete(socket.id); mutedGuests.delete(socket.id); emitOnline(); });
});
const PORT = process.env.PORT || 3000;
initDatabase().then(() => server.listen(PORT, () => console.log(`LobbyZero running on port ${PORT}`))).catch(error => {
  console.error('Could not initialize PostgreSQL:', error.message);
  process.exit(1);
});
