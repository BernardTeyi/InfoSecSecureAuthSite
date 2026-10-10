# Secure Auth

Simple login system: identification, TOTP two-factor, role-based access, salted + peppered passwords, encrypted database, automatic signed backups. Runs on your own computer or on Vercel.

## Run on your computer
    npm install
    npm start          # http://localhost:3000
On first start a `.env` file is created with a random PEPPER and DB_KEY. Keep a copy somewhere safe, away from the backups. If DB_KEY is lost, the data cannot be recovered. Data is stored in `./data` (set `DATA_DIR` to change it).

## Deploy on Vercel
Vercel runs the app as short-lived functions on a read-only disk, and several copies can run at once. So the data must live in a Redis database, and the secrets must be environment variables.

1. **Create a free Redis database.** Vercel dashboard, your project, Storage, create a database, choose Upstash (Redis) and connect it to the project. This adds the REST URL and token as environment variables (`KV_REST_API_URL` / `KV_REST_API_TOKEN`, or `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN`). The app accepts either pair. If you create the database at upstash.com instead, add its REST URL and token yourself as `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN`.
2. **Create your two secrets.** Run `npm run gen-secrets` on your computer. Add the two lines it prints as environment variables named `PEPPER` and `DB_KEY` (Project, Settings, Environment Variables). Keep a private copy and never commit them. If you change them later, existing accounts and backups can no longer be read.
3. **Redeploy.** Environment variables only apply to new deployments.
4. **Check it.** Open `https://your-site/api/health`. You should see `{"ok":true,"storage":"redis","persistent":true}`. If it says `"storage":"tmp"`, the Redis variables were not picked up and data will be lost.
5. Register the first account yourself. It becomes the admin.

Everything saved in Redis is already encrypted with AES-256-GCM, so Redis only ever holds ciphertext. Sessions are stored inside that encrypted database (as hashes), so a login works no matter which copy of the app answers.

Limits: if two people change data at exactly the same moment on different Vercel copies, the last write wins. That is fine for a class project or small team; use a real database for heavy use.

## How each requirement is met
| Requirement | Where | How |
|---|---|---|
| 1. Identification | server.js `/api/register`, `/api/login` | Unique username, strong-password rules, generic error messages, lockout after 5 failed attempts |
| 2. Two-factor | crypto-utils.js `checkTotp` | TOTP (RFC 6238) with an authenticator app. Mandatory: login is incomplete without the code. Used codes cannot be replayed |
| 3. Authorization | server.js `requireRole` | Two roles, `user` and `admin`. The first account registered becomes admin. Admin can change roles, delete users, view the audit log and trigger a backup |
| 4. Salt + pepper | crypto-utils.js `hashPassword` | Password -> HMAC-SHA256 with secret pepper (an environment variable or `.env`, never in the DB) -> scrypt with a unique 16-byte salt per user |
| Confidentiality | crypto-utils.js `encrypt` | Whole database encrypted with AES-256-GCM |
| Integrity | `decrypt`, `mac`, audit chain | GCM auth tag detects any change to the DB. Backups carry an HMAC signature. The audit log is a SHA-256 hash chain, so edits or deletions are detectable |
| Auto-backup | server.js `backup`, store.js | A signed backup is made when data changes and the last one is older than `BACKUP_MINUTES` (default 60), on start-up and shutdown of a normal server, and on demand from the admin page. Last 10 kept (in files, or in Redis) |

## Interface
A colourful single-page UI with a navigation bar, step indicators for sign-up and login, and short "what's happening / next step" hints on every screen. Pages:
- **Login, Register, 2FA setup, 2FA code**: guided flow with a live password-strength checklist and a 30-second code countdown
- **Dashboard**: role badge, shortcut tiles, and live user stats for admins
- **My account**: profile, 2FA status, change password (signs out other devices)
- **Users** (admin): change roles, unlock locked accounts, reset 2FA, delete users, search, and a role-permission table
- **Audit and backups** (admin): hash-chain verification banner, recent events, one-click backup

## Role rules
- Two roles: `user` and `admin`. The first account created becomes admin.
- Role changes apply immediately, with no re-login needed. Deleting a user or resetting their 2FA ends their sessions.
- An admin cannot change, delete or reset the 2FA of their own account, so at least one admin always remains.
- Every action is enforced on the server. Hiding buttons in the UI is only for convenience.

## Backups
    npm run restore                    # verify all backups (signature + decryption)
    node restore.js <backup-name>      # verify, then restore one
Works for both files and Redis. For Redis, run it with the same `PEPPER`, `DB_KEY` and Redis URL/token variables the app uses.

## Files
- `server.js` the app (routes, sessions, roles, audit log, backups)
- `store.js` where data is kept (Redis, files, or a temporary fallback)
- `crypto-utils.js` password hashing, encryption, signing, TOTP, secrets loading
- `restore.js` backup check and restore tool
- `public/index.html` the interface

## Before wider use
Run behind HTTPS (Vercel does this for you) and add IP-based rate limiting.
