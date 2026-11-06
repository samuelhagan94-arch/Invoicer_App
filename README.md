# Invoicer

Stack: **Node.js + Express** (API) · **SQLite** via better-sqlite3 (database, one file, no install)
· **bcrypt + JWT in an httpOnly cookie** (email/password accounts) · **Google Identity Services**
(Sign in with Google, token verified on the server) · plain **HTML/JS** frontend in `public/index.html`.

## Run it in VS Code
1. Install Node.js 18 or newer (https://nodejs.org) and VS Code.
2. Open this folder in VS Code (File > Open Folder), then open the terminal (Ctrl+`).
3. `npm install`
4. Copy `.env.example` to `.env` and set `JWT_SECRET` to a long random string
   (`node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`).
5. `npm start` (or `npm run dev` to auto-restart on changes), then open http://localhost:3000.
   You can also press F5 to run and debug with the included launch config.

## Turn on Google sign-in
1. Go to https://console.cloud.google.com > APIs & Services > Credentials > Create credentials > OAuth client ID > Web application.
2. Under Authorized JavaScript origins add `http://localhost:3000` (and your real domain when you deploy).
3. Paste the client ID into `.env` as `GOOGLE_CLIENT_ID=...` and restart the server.

## What lives where
- `server.js`: database tables (users, invoices, invoice_items), auth routes, profile, invoices API.
  The server recomputes every row total (quantity x unit price) and the totals, so numbers can't be tampered with.
- `public/index.html`: the whole UI. Invoice columns: SN, Item, Description, Quantity, Unit price, Total, with a totals row (total quantity and grand total).
- `invoicer.db`: created automatically on first run. Delete it to reset all data.

## Going live
Set `NODE_ENV=production` (cookies become HTTPS-only), set a strong `JWT_SECRET`, serve over HTTPS,
and host on Render, Railway, Fly.io or a VPS (keep the `invoicer.db` file on a persistent disk,
or switch to PostgreSQL when you outgrow SQLite).
