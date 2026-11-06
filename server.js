require('dotenv').config();
const path = require('path');
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { OAuth2Client } = require('google-auth-library');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const gClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;
const isProd = process.env.NODE_ENV === 'production';

// ---------- Database ----------
const db = new Database(path.join(__dirname, 'invoicer.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT DEFAULT '',
  password_hash TEXT, google_id TEXT,
  business_name TEXT DEFAULT '', logo TEXT DEFAULT '', next_no INTEGER DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS invoices(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  number TEXT, client TEXT, date TEXT, currency TEXT,
  business_name TEXT, logo TEXT, total_qty REAL, total REAL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS invoice_items(
  id INTEGER PRIMARY KEY, invoice_id INTEGER NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
  sn INTEGER, item TEXT, description TEXT, quantity REAL, unit_price REAL, total REAL);
CREATE INDEX IF NOT EXISTS idx_inv_user ON invoices(user_id);
`);

// ---------- App ----------
const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 40, standardHeaders: true, legacyHeaders: false });

const publicUser = u => ({ email: u.email, name: u.name, businessName: u.business_name, logo: u.logo, nextNo: u.next_no });
const setSession = (res, user) => {
  const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: isProd, maxAge: 7 * 24 * 3600 * 1000 });
};
const requireAuth = (req, res, next) => {
  try {
    const { id } = jwt.verify(req.cookies.token, SECRET);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    if (!user) throw new Error('no user');
    req.user = user; next();
  } catch { res.status(401).json({ error: 'Not signed in' }); }
};
const emailOk = e => typeof e === 'string' && /^\S+@\S+\.\S+$/.test(e);

app.get('/api/config', (_req, res) => res.json({ googleClientId: GOOGLE_CLIENT_ID }));

// ---------- Auth ----------
app.post('/api/auth/register', authLimiter, (req, res) => {
  const { name = '', password } = req.body;
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!emailOk(email)) return res.status(400).json({ error: 'Enter a valid email.' });
  if (typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) return res.status(409).json({ error: 'An account with this email already exists.' });
  const info = db.prepare('INSERT INTO users(email,name,password_hash) VALUES(?,?,?)')
    .run(email, String(name).slice(0, 100), bcrypt.hashSync(password, 10));
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
  setSession(res, user); res.json(publicUser(user));
});

app.post('/api/auth/login', authLimiter, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !user.password_hash || !bcrypt.compareSync(String(req.body.password || ''), user.password_hash))
    return res.status(401).json({ error: 'Incorrect email or password.' });
  setSession(res, user); res.json(publicUser(user));
});

app.post('/api/auth/google', authLimiter, async (req, res) => {
  if (!gClient) return res.status(501).json({ error: 'Google sign-in is not configured on the server.' });
  try {
    const ticket = await gClient.verifyIdToken({ idToken: req.body.credential, audience: GOOGLE_CLIENT_ID });
    const p = ticket.getPayload();
    if (!p.email_verified) return res.status(401).json({ error: 'Google email is not verified.' });
    const email = p.email.toLowerCase();
    let user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      const info = db.prepare('INSERT INTO users(email,name,google_id) VALUES(?,?,?)').run(email, p.name || '', p.sub);
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    } else if (!user.google_id) {
      db.prepare('UPDATE users SET google_id = ? WHERE id = ?').run(p.sub, user.id);
    }
    setSession(res, user); res.json(publicUser(user));
  } catch { res.status(401).json({ error: 'Google sign-in failed.' }); }
});

app.post('/api/auth/logout', (_req, res) => { res.clearCookie('token'); res.json({ ok: true }); });
app.get('/api/me', requireAuth, (req, res) => res.json(publicUser(req.user)));

// ---------- Business profile ----------
app.put('/api/profile', requireAuth, (req, res) => {
  const businessName = String(req.body.businessName ?? req.user.business_name).slice(0, 150);
  let logo = req.user.logo;
  if (typeof req.body.logo === 'string') {
    if (req.body.logo && !/^data:image\/(png|jpeg|webp|gif);base64,/.test(req.body.logo)) return res.status(400).json({ error: 'Logo must be a PNG, JPEG, WebP or GIF image.' });
    if (req.body.logo.length > 900000) return res.status(400).json({ error: 'Logo is too large.' });
    logo = req.body.logo;
  }
  db.prepare('UPDATE users SET business_name = ?, logo = ? WHERE id = ?').run(businessName, logo, req.user.id);
  res.json(publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id)));
});

// ---------- Invoices ----------
const loadInvoice = (id, userId) => {
  const inv = db.prepare('SELECT * FROM invoices WHERE id = ? AND user_id = ?').get(id, userId);
  if (!inv) return null;
  inv.items = db.prepare('SELECT sn,item,description,quantity,unit_price,total FROM invoice_items WHERE invoice_id = ? ORDER BY sn').all(id);
  return inv;
};

app.get('/api/invoices', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT id,number,client,date,currency,total_qty,total,created_at FROM invoices WHERE user_id = ? ORDER BY id DESC').all(req.user.id));
});

app.get('/api/invoices/:id', requireAuth, (req, res) => {
  const inv = loadInvoice(req.params.id, req.user.id);
  inv ? res.json(inv) : res.status(404).json({ error: 'Invoice not found' });
});

app.post('/api/invoices', requireAuth, (req, res) => {
  const { client = '', date, currency = '$', items } = req.body;
  if (!Array.isArray(items) || !items.length || items.length > 200) return res.status(400).json({ error: 'Add between 1 and 200 rows.' });
  // Totals are always recomputed on the server: total = quantity * unit price.
  const rows = items.map((r, i) => {
    const q = Number(r.quantity) || 0, p = Number(r.unit_price) || 0;
    return { sn: i + 1, item: String(r.item || '').slice(0, 200), description: String(r.description || '').slice(0, 500), quantity: q, unit_price: p, total: Math.round(q * p * 100) / 100 };
  });
  const totalQty = rows.reduce((a, r) => a + r.quantity, 0);
  const total = Math.round(rows.reduce((a, r) => a + r.total, 0) * 100) / 100;

  const create = db.transaction(() => {
    const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    const number = String(req.body.number || '').trim().slice(0, 40) || 'INV-' + String(u.next_no).padStart(4, '0');
    db.prepare('UPDATE users SET next_no = next_no + 1 WHERE id = ?').run(u.id);
    const info = db.prepare(`INSERT INTO invoices(user_id,number,client,date,currency,business_name,logo,total_qty,total)
      VALUES(?,?,?,?,?,?,?,?,?)`).run(u.id, number, String(client).slice(0, 150), date || new Date().toISOString().slice(0, 10),
      String(currency).slice(0, 5), u.business_name, u.logo, totalQty, total);
    const ins = db.prepare('INSERT INTO invoice_items(invoice_id,sn,item,description,quantity,unit_price,total) VALUES(?,?,?,?,?,?,?)');
    rows.forEach(r => ins.run(info.lastInsertRowid, r.sn, r.item, r.description, r.quantity, r.unit_price, r.total));
    return info.lastInsertRowid;
  });
  res.status(201).json(loadInvoice(create(), req.user.id));
});

app.delete('/api/invoices/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM invoices WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Invoicer running at http://localhost:${PORT}`));
