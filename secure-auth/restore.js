'use strict';
// node restore.js              -> verify every backup (signature + decryption)
// node restore.js <backup>     -> verify that backup, then restore it as the live database
// Works with both storage modes (files or Redis). For Redis, set the same environment
// variables the app uses (PEPPER, DB_KEY and the Redis URL/token) before running it.
const C = require('./crypto-utils');
const store = require('./store');

function verify(b) {
  if (!b) return 'MISSING';
  try {
    if (!C.safeEq(C.mac(Buffer.from(b.blob, 'utf8')), b.mac)) return 'BAD SIGNATURE (data was modified)';
    JSON.parse(C.decrypt(b.blob));
    return 'OK';
  } catch { return 'CORRUPT (cannot decrypt)'; }
}

(async () => {
  const arg = process.argv[2];
  if (!arg) {
    const names = await store.listBackups();
    if (!names.length) console.log('No backups found.');
    for (const n of names) console.log(n.padEnd(40), verify(await store.readBackup(n)));
    return;
  }
  const name = arg.split(/[\\/]/).pop();
  const b = await store.readBackup(name);
  const r = verify(b);
  if (r !== 'OK') { console.error('Refusing to restore:', r); process.exit(1); }
  await store.writeDb(b.blob);
  console.log('Restored', name, '- restart the server (or just reload the site on Vercel).');
})().catch(e => { console.error(e.message); process.exit(1); });
