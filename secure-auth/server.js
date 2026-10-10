'use strict';
const express = require('express');
const fs = require('fs');
const path = require('path');
const QRCode = require('qrcode');
const C = require('./crypto-utils');
const store = require('./store');

const PORT = process.env.PORT || 3000;
const BACKUP_MINUTES = Number(process.env.BACKUP_MINUTES || 60);
const KEEP_BACKUPS = 10;
const MAX_AUDIT = 1000;
const SESSION_MS = 30 * 60 * 1000, PENDING_MS = 5 * 60 * 1000;
const SERVERLESS = !!(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME);

// ================= Encrypted database =================
// The whole database is one AES-256-GCM blob (see crypto-utils.js) kept in store.js.
// Users, sessions and pending logins all live inside it, so ANY copy of the app can serve ANY
// request. On Vercel the app is reloaded from storage before each request and written back
// before the reply is sent. A normal server keeps it in memory and writes after each change.
let db = null;
let needsWrite = false, dirtySinceBackup = false;
const emptyDb = () => ({ users: [], audit: [], sessions: {}, pending: {} });

async function loadDb() {
  if (db && store.mode !== 'redis') return; // one long-running process: memory is the source of truth
  const blob = await store.readDb();
  if (blob == null) db = emptyDb();
  else {
    try { db = JSON.parse(C.decrypt(blob)); }
    catch { db = null; throw new Error('INTEGRITY FAILURE: database cannot be decrypted (wrong key or the data was modified). Run "npm run restore".'); }
  }
  db.users ||= []; db.audit ||= []; db.sessions ||= {}; db.pending ||= {};
  needsWrite = false;
  const now = Date.now(); // drop expired sessions and pending logins
  for (const m of [db.sessions, db.pending]) for (const k of Object.keys(m)) if (m[k].exp < now) delete m[k];
}
function save() { needsWrite = true; dirtySinceBackup = true; }
async function persist() {
  if (!needsWrite) return null;
  const blob = C.encrypt(JSON.stringify(db));
  await store.writeDb(blob);
  needsWrite = false;
  return blob;
}

// ================= Auto-backup =================
// Signed copies (HMAC) of the encrypted database. Made when data changes and the last backup is
// older than BACKUP_MINUTES, on start-up, on shutdown (normal servers) and on demand (admin button).
async function backup(blob) {
  blob = blob || await store.readDb();
  if (!blob) return;
  const name = `db-${new Date().toISOString().replace(/[:.]/g, '-')}.enc`;
  await store.writeBackup(name, blob, C.mac(Buffer.from(blob, 'utf8'))); // integrity signature
  await store.pruneBackups(KEEP_BACKUPS);
  dirtySinceBackup = false;
  console.log('[backup] saved', name);
}
async function flushDb() { // runs just before every reply
  const blob = await persist();
  if (blob && (Date.now() - (await store.lastBackupTime())) >= BACKUP_MINUTES * 60 * 1000) {
    try { await backup(blob); } catch (e) { console.error('[backup] failed:', e.message); } // never block a login because of a backup
  }
}
if (!SERVERLESS) {
  setInterval(async () => { try { if (dirtySinceBackup) { await persist(); await backup(); } } catch (e) { console.error('[backup] failed:', e.message); } }, BACKUP_MINUTES * 60 * 1000).unref();
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, async () => { try { await persist(); if (dirtySinceBackup) await backup(); } catch {} process.exit(0); });
}

// ================= Tamper-evident audit log (hash chain) =================
function audit(event, user = '-') {
  const prev = db.audit.length ? db.audit[db.audit.length - 1].hash : 'GENESIS';
  const entry = { ts: new Date().toISOString(), event, user, prev };
  entry.hash = C.sha256(prev + entry.ts + event + user);
  db.audit.push(entry);
  if (db.audit.length > MAX_AUDIT) db.audit.splice(0, db.audit.length - MAX_AUDIT); // keep the newest entries
}
function auditIntact() {
  let prev = db.audit.length ? db.audit[0].prev : 'GENESIS';
  return db.audit.every(e => { const ok = e.prev === prev && e.hash === C.sha256(prev + e.ts + e.event + e.user); prev = e.hash; return ok; });
}

// ================= Sessions (stored in the database; only a hash of each token is kept) =================
const sk = id => C.sha256(String(id));
const getSession = sid => typeof sid === 'string' ? db.sessions[sk(sid)] : undefined;
const getPending = id => typeof id === 'string' ? db.pending[sk(id)] : undefined;
const purge = (userId, exceptSid) => {
  const keep = exceptSid ? sk(exceptSid) : null;
  for (const [k, v] of Object.entries(db.sessions)) if (v.userId === userId && k !== keep) delete db.sessions[k];
  save();
};
const newPending = (userId, purpose) => { const id = C.token(); db.pending[sk(id)] = { userId, purpose, exp: Date.now() + PENDING_MS, tries: 0 }; save(); return id; };
function cookies(req) { return Object.fromEntries((req.headers.cookie || '').split(';').map(s => s.trim().split('=')).filter(p => p[0])); }
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ================= App + middleware =================
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));
app.use((req, res, next) => {
  res.set({
    'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'",
    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store'
  });
  next();
});
// The page is read with a plain readFileSync so Vercel includes it in the function bundle.
const INDEX_HTML = (() => { try { return fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8'); } catch { return null; } })();
app.get('/', (req, res, next) => INDEX_HTML ? res.type('html').send(INDEX_HTML) : next());
app.use(express.static(path.join(__dirname, 'public')));

// --- API gate: one API request at a time per app copy; load the database first and
//     write it back before the reply leaves (a serverless function can freeze right after replying).
let chain = Promise.resolve();
app.use('/api', (req, res, next) => {
  const turn = chain;
  let release; chain = new Promise(r => { release = r; });
  turn.then(async () => {
    let guard; let done = false;
    const finish = () => { if (!done) { done = true; clearTimeout(guard); release(); } };
    guard = setTimeout(finish, 20000); // never let one stuck request block the rest
    res.on('finish', finish); res.on('close', finish);
    const send = res.json.bind(res);
    res.json = body => {
      flushDb().then(() => send(body), err => {
        console.error('[storage] write failed:', err.message);
        res.status(500); send({ error: 'Could not save your data. Please try again.' });
      });
      return res;
    };
    try { await loadDb(); }
    catch (e) { console.error(e.message); res.status(500); return send({ error: 'Database unavailable or failed its integrity check. See the server logs.' }); }
    next();
  });
});

// --- Authentication guard
function requireAuth(req, res, next) {
  const sid = cookies(req).sid;
  const s = getSession(sid);
  if (!s || s.exp < Date.now()) return res.status(401).json({ error: 'Not logged in' });
  const user = db.users.find(u => u.id === s.userId);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  if (s.exp - Date.now() < SESSION_MS - 5 * 60 * 1000) { s.exp = Date.now() + SESSION_MS; save(); } // slide the expiry, saving at most every 5 min
  req.user = user; req.sid = sid; next();
}
// --- Authorization guard (role-based)
const requireRole = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : (audit(`DENIED ${req.method} ${req.path}`, req.user.username), save(), res.status(403).json({ error: 'Forbidden: insufficient role' }));

const validPassword = p => typeof p === 'string' && p.length >= 10 && p.length <= 128 && /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p);
// Phone keyboards often add a trailing space or invisible character; strip them before checking.
const cleanName = u => typeof u === 'string' ? u.normalize('NFKC').replace(/[​-‍⁠﻿]/g, '').trim() : u;
const validUsername = u => typeof u === 'string' && /^[A-Za-z0-9_]{3,20}$/.test(u);
const GENERIC = { error: 'Invalid username or password' };
const dummy = C.hashPassword('dummy-password'); // equalises timing for unknown users

async function enrollPayload(user) {
  const uri = `otpauth://totp/SecureAuth:${encodeURIComponent(user.username)}?secret=${user.totpSecret}&issuer=SecureAuth&digits=6&period=30`;
  return { step: 'enroll', pendingId: newPending(user.id, 'enroll'), secret: user.totpSecret, qr: await QRCode.toDataURL(uri) };
}

app.get('/api/health', (req, res) => res.json({ ok: true, storage: store.mode, persistent: store.mode !== 'tmp' }));

// ================= 1. Identification: register =================
app.post('/api/register', wrap(async (req, res) => {
  const { password } = req.body || {};
  const username = cleanName(req.body?.username);
  if (!validUsername(username)) return res.status(400).json({ error: 'Username must be 3-20 characters: letters, numbers or underscore (no spaces)' });
  if (!validPassword(password)) return res.status(400).json({ error: 'Password: 10+ characters with upper, lower, number and symbol' });
  if (db.users.some(u => u.username.toLowerCase() === username.toLowerCase())) return res.status(409).json({ error: 'Username already taken' });
  const { salt, hash } = C.hashPassword(password);              // salt + pepper
  const user = {
    id: C.token(8), username, salt, hash,
    role: db.users.length === 0 ? 'admin' : 'user',              // first account becomes admin
    totpSecret: C.newTotpSecret(), totpEnabled: false, lastStep: 0, fails: 0, lockUntil: 0, created: new Date().toISOString()
  };
  db.users.push(user); audit('REGISTER', username); save();
  res.json(await enrollPayload(user));
}));

// ================= 2. Two-factor: activate (enrol) =================
app.post('/api/2fa/activate', (req, res) => {
  const p = getPending(req.body?.pendingId);
  if (!p || p.purpose !== 'enroll' || p.exp < Date.now()) return res.status(400).json({ error: 'Session expired, log in again' });
  const user = db.users.find(u => u.id === p.userId);
  if (!user) return res.status(400).json({ error: 'Session expired, log in again' });
  const step = C.checkTotp(user.totpSecret, req.body.code, user.lastStep);
  if (!step) return res.status(401).json({ error: 'Wrong code' });
  user.totpEnabled = true; user.lastStep = step; delete db.pending[sk(req.body.pendingId)];
  audit('2FA_ENABLED', user.username); save();
  res.json({ ok: true });
});

// ================= Login step 1: password =================
app.post('/api/login', wrap(async (req, res) => {
  const { password } = req.body || {};
  const username = cleanName(req.body?.username);
  const user = db.users.find(u => u.username.toLowerCase() === String(username).toLowerCase());
  if (user && user.lockUntil > Date.now()) return res.status(429).json({ error: 'Account locked for a few minutes after too many attempts' });
  const ok = user ? C.verifyPassword(String(password), user.salt, user.hash) : (C.verifyPassword(String(password), dummy.salt, dummy.hash), false);
  if (!ok) {
    if (user && ++user.fails >= 5) { user.lockUntil = Date.now() + 5 * 60 * 1000; user.fails = 0; audit('LOCKOUT', user.username); }
    audit('LOGIN_FAIL', user ? user.username : String(username).slice(0, 20)); save();
    return res.status(401).json(GENERIC);
  }
  user.fails = 0;
  if (!user.totpEnabled) return res.json(await enrollPayload(user)); // finish 2FA setup first
  res.json({ step: '2fa', pendingId: newPending(user.id, 'login') });
}));

// ================= Login step 2: TOTP =================
app.post('/api/login/2fa', (req, res) => {
  const p = getPending(req.body?.pendingId);
  if (!p || p.purpose !== 'login' || p.exp < Date.now()) return res.status(400).json({ error: 'Session expired, log in again' });
  const user = db.users.find(u => u.id === p.userId);
  if (!user) return res.status(400).json({ error: 'Session expired, log in again' });
  const step = C.checkTotp(user.totpSecret, req.body.code, user.lastStep);
  if (!step) {
    if (++p.tries >= 5) delete db.pending[sk(req.body.pendingId)];
    audit('2FA_FAIL', user.username); save();
    return res.status(401).json({ error: 'Wrong code' });
  }
  user.lastStep = step; delete db.pending[sk(req.body.pendingId)];
  const sid = C.token(); db.sessions[sk(sid)] = { userId: user.id, exp: Date.now() + SESSION_MS };
  res.cookie('sid', sid, { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production' || SERVERLESS, maxAge: SESSION_MS });
  user.lastLogin = new Date().toISOString();
  audit('LOGIN_OK', user.username); save();
  res.json({ ok: true });
});

app.post('/api/logout', requireAuth, (req, res) => { delete db.sessions[sk(req.sid)]; res.clearCookie('sid'); audit('LOGOUT', req.user.username); save(); res.json({ ok: true }); });

// ================= 3. Authorization by role =================
app.get('/api/me', requireAuth, (req, res) => res.json({ username: req.user.username, role: req.user.role, created: req.user.created, lastLogin: req.user.lastLogin || null, twoFactor: req.user.totpEnabled }));
app.get('/api/user/area', requireAuth, requireRole('user', 'admin'), (req, res) => res.json({ message: `Welcome ${req.user.username}. This area is open to the roles: user and admin.` }));

app.get('/api/admin/users', requireAuth, requireRole('admin'), (req, res) =>
  res.json(db.users.map(u => ({ id: u.id, username: u.username, role: u.role, twoFactor: u.totpEnabled, created: u.created, lastLogin: u.lastLogin || null, locked: u.lockUntil > Date.now() }))));
app.post('/api/admin/users/:id/role', requireAuth, requireRole('admin'), (req, res) => {
  const t = db.users.find(u => u.id === req.params.id);
  if (!t) return res.status(404).json({ error: 'User not found' });
  if (!['user', 'admin'].includes(req.body?.role)) return res.status(400).json({ error: 'Role must be user or admin' });
  if (t.id === req.user.id) return res.status(400).json({ error: 'You cannot change your own role' });
  t.role = req.body.role; audit(`ROLE ${t.username}=${t.role}`, req.user.username); save(); res.json({ ok: true });
});
app.delete('/api/admin/users/:id', requireAuth, requireRole('admin'), (req, res) => {
  const i = db.users.findIndex(u => u.id === req.params.id);
  if (i < 0 || db.users[i].id === req.user.id) return res.status(400).json({ error: 'Bad request' });
  audit(`DELETE_USER ${db.users[i].username}`, req.user.username); purge(db.users[i].id); db.users.splice(i, 1); save(); res.json({ ok: true });
});
app.get('/api/admin/audit', requireAuth, requireRole('admin'), (req, res) => res.json({ chainIntact: auditIntact(), entries: db.audit.slice(-50).reverse() }));
app.post('/api/admin/backup', requireAuth, requireRole('admin'), wrap(async (req, res) => {
  await persist(); await backup();
  audit('MANUAL_BACKUP', req.user.username); save(); res.json({ ok: true });
}));

// ---- Extra admin tools
app.post('/api/admin/users/:id/unlock', requireAuth, requireRole('admin'), (req, res) => {
  const t = db.users.find(u => u.id === req.params.id);
  if (!t) return res.status(404).json({ error: 'User not found' });
  t.lockUntil = 0; t.fails = 0; audit(`UNLOCK ${t.username}`, req.user.username); save(); res.json({ ok: true });
});
app.post('/api/admin/users/:id/reset-2fa', requireAuth, requireRole('admin'), (req, res) => {
  const t = db.users.find(u => u.id === req.params.id);
  if (!t) return res.status(404).json({ error: 'User not found' });
  if (t.id === req.user.id) return res.status(400).json({ error: 'You cannot reset your own 2FA' });
  t.totpSecret = C.newTotpSecret(); t.totpEnabled = false; t.lastStep = 0; purge(t.id); // forces fresh enrolment at next login
  audit(`RESET_2FA ${t.username}`, req.user.username); save(); res.json({ ok: true });
});

// ---- Any logged-in user: change own password
app.post('/api/account/password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  const u = req.user;
  if (!C.verifyPassword(String(currentPassword), u.salt, u.hash)) {
    if (++u.fails >= 5) { u.lockUntil = Date.now() + 5 * 60 * 1000; u.fails = 0; purge(u.id); audit('LOCKOUT', u.username); }
    audit('PASSWORD_CHANGE_FAIL', u.username); save();
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  if (!validPassword(newPassword)) return res.status(400).json({ error: 'New password: 10+ characters with upper, lower, number and symbol' });
  if (newPassword === currentPassword) return res.status(400).json({ error: 'New password must be different' });
  const { salt, hash } = C.hashPassword(newPassword);
  u.salt = salt; u.hash = hash; u.fails = 0;
  purge(u.id, req.sid); // sign out every other device
  audit('PASSWORD_CHANGED', u.username); save(); res.json({ ok: true });
});

// ---- Errors: always answer, never hang
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const status = err.status >= 400 && err.status < 500 ? err.status : 500;
  if (status === 500) console.error(err);
  res.status(status).json({ error: status === 500 ? 'Server error' : 'Bad request' });
});

// ================= Start =================
// Vercel imports this file and calls the exported app itself; a normal server starts listening here.
module.exports = app;
if (!SERVERLESS && require.main === module) {
  (async () => {
    try { await loadDb(); } catch (e) { console.error(e.message); process.exit(1); }
    try { await backup(); } catch (e) { console.error('[backup] failed:', e.message); }
    app.listen(PORT, () => console.log(`Secure auth running at http://localhost:${PORT}`));
  })();
}
