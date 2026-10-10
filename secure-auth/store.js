'use strict';
// Storage adapter. Everything stored here is ALREADY encrypted (AES-256-GCM) by crypto-utils.js,
// so the storage service only ever sees ciphertext.
//
//   redis : Upstash/Vercel KV over its REST API. Use this on Vercel (serverless: read-only disk,
//           many short-lived copies of the app, nothing kept in memory between requests).
//   file  : ./data (or DATA_DIR). Use this on your own computer or a server with a normal disk.
//   tmp   : last-resort fallback when the disk is read-only (e.g. Vercel without Redis).
//           Data lives in the OS temp folder and WILL be lost. Fine for a quick demo only.
const fs = require('fs');
const fsp = fs.promises;
const os = require('os');
const path = require('path');

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
const P = 'secure-auth:';

// ---------------- Redis (REST) ----------------
async function cmd(...args) {
  const r = await fetch(REDIS_URL, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + REDIS_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(args.map(String))
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.error) throw new Error('Redis: ' + (j.error || 'HTTP ' + r.status));
  return j.result;
}
const redisStore = {
  mode: 'redis',
  readDb: () => cmd('GET', P + 'db'),
  writeDb: blob => cmd('SET', P + 'db', blob),
  async writeBackup(name, blob, mac) {
    await cmd('SET', P + 'backup:' + name, JSON.stringify({ blob, mac }));
    await cmd('LPUSH', P + 'backups', name);
    await cmd('SET', P + 'lastbackup', Date.now());
  },
  async pruneBackups(keep) {
    for (const n of await cmd('LRANGE', P + 'backups', keep, -1)) await cmd('DEL', P + 'backup:' + n);
    await cmd('LTRIM', P + 'backups', 0, keep - 1);
  },
  async listBackups() { return (await cmd('LRANGE', P + 'backups', 0, -1)).sort(); },
  async readBackup(name) { const v = await cmd('GET', P + 'backup:' + name); return v ? JSON.parse(v) : null; },
  async lastBackupTime() { return Number(await cmd('GET', P + 'lastbackup')) || 0; }
};

// ---------------- Files ----------------
function fileStore(dir, mode) {
  const DB = path.join(dir, 'db.enc'), BK = path.join(dir, 'backups');
  let last = null;
  return {
    mode,
    async readDb() {
      try { return await fsp.readFile(DB, 'utf8'); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
    },
    async writeDb(blob) {
      const tmp = DB + '.tmp';
      await fsp.writeFile(tmp, blob, { mode: 0o600 });
      await fsp.rename(tmp, DB); // atomic replace: no half-written file
    },
    async writeBackup(name, blob, mac) {
      await fsp.writeFile(path.join(BK, name), blob, { mode: 0o600 });
      await fsp.writeFile(path.join(BK, name + '.mac'), mac);
      last = Date.now();
    },
    async pruneBackups(keep) {
      const names = await this.listBackups();
      for (const n of names.slice(0, Math.max(0, names.length - keep))) {
        await fsp.rm(path.join(BK, n), { force: true });
        await fsp.rm(path.join(BK, n + '.mac'), { force: true });
      }
    },
    async listBackups() { return (await fsp.readdir(BK)).filter(f => f.endsWith('.enc')).sort(); },
    async readBackup(name) {
      try {
        return { blob: await fsp.readFile(path.join(BK, name), 'utf8'), mac: (await fsp.readFile(path.join(BK, name + '.mac'), 'utf8')).trim() };
      } catch { return null; }
    },
    async lastBackupTime() {
      if (last === null) {
        last = 0;
        for (const n of await this.listBackups()) last = Math.max(last, (await fsp.stat(path.join(BK, n))).mtimeMs);
      }
      return last;
    }
  };
}

function pickFileStore() {
  const wanted = process.env.DATA_DIR || path.join(__dirname, 'data');
  try {
    fs.mkdirSync(path.join(wanted, 'backups'), { recursive: true });
    fs.accessSync(wanted, fs.constants.W_OK);
    return fileStore(wanted, 'file');
  } catch (e) {
    // Read-only disk (this is what crashed on Vercel): fall back to the temp folder instead of dying.
    const tmp = path.join(os.tmpdir(), 'secure-auth-data');
    fs.mkdirSync(path.join(tmp, 'backups'), { recursive: true });
    console.warn(`[storage] Cannot write to ${wanted} (${e.code}). Using ${tmp}: data is TEMPORARY and will be lost. Connect a Redis database for permanent storage.`);
    return fileStore(tmp, 'tmp');
  }
}

if (!!REDIS_URL !== !!REDIS_TOKEN) console.warn('[storage] Only one of the Redis URL / token variables is set, so Redis is NOT being used.');
const store = REDIS_URL && REDIS_TOKEN ? redisStore : pickFileStore();
console.log('[storage] mode:', store.mode);
module.exports = store;
