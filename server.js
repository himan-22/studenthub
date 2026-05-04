/**
 * StudentHub — Backend API Server
 * Connects to NeonDB (PostgreSQL) via pg.
 *
 * Setup:
 *   1.  npm install
 *   2.  cp .env.example .env   ← fill in DATABASE_URL from your Neon project
 *   3.  node server.js
 *
 * All API routes are under /api/*.
 * In production, place index.html in the /public folder and this serves it too.
 */

require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const { Pool } = require('pg');
const path     = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'studenthub_dev_secret_change_in_prod';

// ── DATABASE ─────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }   // required for NeonDB
});

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*', credentials: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── DB INIT ───────────────────────────────────────────────────────────────────
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id            SERIAL PRIMARY KEY,
        name          TEXT        NOT NULL,
        phone         TEXT        NOT NULL UNIQUE,
        college       TEXT,
        password_hash TEXT        NOT NULL,
        role          TEXT        NOT NULL DEFAULT 'learner',
        role_label    TEXT        NOT NULL DEFAULT 'Learner account',
        summary       TEXT,
        created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS listings (
        id         SERIAL PRIMARY KEY,
        user_id    INTEGER      REFERENCES users(id) ON DELETE CASCADE,
        cat        TEXT         NOT NULL CHECK (cat IN ('tutoring','fitness','merch')),
        name       TEXT         NOT NULL,
        by_name    TEXT         NOT NULL,
        meta       TEXT,
        rating     TEXT         DEFAULT 'New',
        phone      TEXT         NOT NULL,
        approved   BOOLEAN      NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS contact_logs (
        id           SERIAL PRIMARY KEY,
        listing_id   INTEGER  REFERENCES listings(id) ON DELETE CASCADE,
        requester_id INTEGER  REFERENCES users(id),
        created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS sell_enquiries (
        id         SERIAL PRIMARY KEY,
        name       TEXT NOT NULL,
        college    TEXT,
        phone      TEXT NOT NULL,
        product    TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    console.log('[DB] Tables ready.');
  } finally {
    client.release();
  }
}

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer '))
    return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── HELPERS ───────────────────────────────────────────────────────────────────
const cleanPhone = (p) => String(p || '').replace(/\D/g, '');

// ── ROUTES ────────────────────────────────────────────────────────────────────

app.get('/api/health', (_req, res) => res.json({ ok: true, ts: new Date() }));

// ── AUTH ──────────────────────────────────────────────────────────────────────

/**
 * POST /api/auth/signup
 * { name, phone, college?, password, role, roleLabel, summary? }
 */
app.post('/api/auth/signup', async (req, res) => {
  const { name, phone, college, password, role, roleLabel, summary } = req.body;
  if (!name || !phone || !password)
    return res.status(400).json({ error: 'name, phone and password are required.' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO users (name, phone, college, password_hash, role, role_label, summary)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING id, name, phone, college, role, role_label AS "roleLabel", summary`,
      [name.trim(), cleanPhone(phone), college || null, hash,
       role || 'learner', roleLabel || 'Learner account', summary || null]
    );
    const token = jwt.sign({ id: rows[0].id, role: rows[0].role }, JWT_SECRET, { expiresIn: '30d' });
    res.status(201).json({ user: rows[0], token });
  } catch (err) {
    if (err.code === '23505')
      return res.status(409).json({ error: 'A user with this phone number already exists.' });
    console.error('[signup]', err.message);
    res.status(500).json({ error: 'Server error during signup.' });
  }
});

/**
 * POST /api/auth/login
 * { phone?, name?, password }
 */
app.post('/api/auth/login', async (req, res) => {
  const { name, phone, password } = req.body;
  if ((!name && !phone) || !password)
    return res.status(400).json({ error: 'Phone/name and password are required.' });

  try {
    const { rows } = phone
      ? await pool.query('SELECT * FROM users WHERE phone=$1', [cleanPhone(phone)])
      : await pool.query('SELECT * FROM users WHERE LOWER(name)=LOWER($1)', [name.trim()]);

    if (!rows.length)
      return res.status(401).json({ error: 'Account not found. Please sign up first.' });

    const ok = await bcrypt.compare(password, rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Incorrect password.' });

    const u = rows[0];
    const token = jwt.sign({ id: u.id, role: u.role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({
      user: { id: u.id, name: u.name, phone: u.phone, college: u.college,
              role: u.role, roleLabel: u.role_label, summary: u.summary },
      token
    });
  } catch (err) {
    console.error('[login]', err.message);
    res.status(500).json({ error: 'Server error during login.' });
  }
});

/** GET /api/auth/me */
app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, name, phone, college, role, role_label AS "roleLabel", summary FROM users WHERE id=$1`,
      [req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error(err); res.status(500).json({ error: 'Server error.' });
  }
});

/** PATCH /api/auth/me */
app.patch('/api/auth/me', auth, async (req, res) => {
  const { name, college, phone } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required.' });
  try {
    const { rows } = await pool.query(
      `UPDATE users SET name=$1, college=$2, phone=COALESCE(NULLIF($3,''), phone)
       WHERE id=$4
       RETURNING id, name, phone, college, role, role_label AS "roleLabel", summary`,
      [name.trim(), college || null, phone ? cleanPhone(phone) : '', req.user.id]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error(err); res.status(500).json({ error: 'Server error.' });
  }
});

// ── LISTINGS ──────────────────────────────────────────────────────────────────

/** GET /api/listings?cat=&q= */
app.get('/api/listings', async (req, res) => {
  const { cat, q } = req.query;
  const conds = ['l.approved = TRUE'];
  const params = [];

  if (cat && ['tutoring','fitness','merch'].includes(cat)) {
    params.push(cat); conds.push(`l.cat=$${params.length}`);
  }
  if (q) {
    params.push(`%${q.toLowerCase()}%`);
    const n = params.length;
    conds.push(`(LOWER(l.name) LIKE $${n} OR LOWER(l.by_name) LIKE $${n} OR LOWER(l.meta) LIKE $${n})`);
  }

  try {
    const { rows } = await pool.query(
      `SELECT l.id, l.cat, l.name, l.by_name AS "by", l.meta, l.rating, l.phone
       FROM listings l WHERE ${conds.join(' AND ')} ORDER BY l.created_at DESC`,
      params
    );
    res.json(rows);
  } catch (err) {
    console.error(err); res.status(500).json({ error: 'Failed to fetch listings.' });
  }
});

/** POST /api/listings  (auth required) */
app.post('/api/listings', auth, async (req, res) => {
  const { cat, name, by: byName, meta, phone, rating } = req.body;
  if (!cat || !name || !byName || !phone)
    return res.status(400).json({ error: 'cat, name, by and phone are required.' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO listings (user_id, cat, name, by_name, meta, rating, phone, approved)
       VALUES ($1,$2,$3,$4,$5,$6,$7,FALSE)
       RETURNING id, cat, name, by_name AS "by", meta, rating, phone, approved`,
      [req.user.id, cat, name.trim(), byName.trim(), meta || '', rating || 'New', cleanPhone(phone)]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error(err); res.status(500).json({ error: 'Failed to create listing.' });
  }
});

/** GET /api/listings/mine */
app.get('/api/listings/mine', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, cat, name, by_name AS "by", meta, rating, phone, approved
       FROM listings WHERE user_id=$1 ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error(err); res.status(500).json({ error: 'Failed to fetch your listings.' });
  }
});

/** DELETE /api/listings/:id */
app.delete('/api/listings/:id', auth, async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      'DELETE FROM listings WHERE id=$1 AND user_id=$2',
      [req.params.id, req.user.id]
    );
    if (!rowCount) return res.status(404).json({ error: 'Listing not found or not yours.' });
    res.json({ ok: true });
  } catch (err) {
    console.error(err); res.status(500).json({ error: 'Failed to delete listing.' });
  }
});

/** POST /api/listings/:id/contact */
app.post('/api/listings/:id/contact', auth, async (req, res) => {
  try {
    await pool.query(
      'INSERT INTO contact_logs (listing_id, requester_id) VALUES ($1,$2)',
      [req.params.id, req.user.id]
    );
    const { rows } = await pool.query(
      'SELECT phone, name FROM listings WHERE id=$1', [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Listing not found.' });
    res.json({ phone: rows[0].phone, name: rows[0].name });
  } catch (err) {
    console.error(err); res.status(500).json({ error: 'Failed to log contact.' });
  }
});

// ── SELL ENQUIRY ──────────────────────────────────────────────────────────────

/** POST /api/sell-enquiry */
app.post('/api/sell-enquiry', async (req, res) => {
  const { name, college, phone, product } = req.body;
  if (!name || !phone || !product)
    return res.status(400).json({ error: 'name, phone and product are required.' });
  try {
    await pool.query(
      `INSERT INTO sell_enquiries (name, college, phone, product) VALUES ($1,$2,$3,$4)`,
      [name.trim(), college || null, cleanPhone(phone), product.trim()]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error(err); res.status(500).json({ error: 'Failed to save enquiry.' });
  }
});

// ── SPA FALLBACK ──────────────────────────────────────────────────────────────
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── BOOT ──────────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`🚀  StudentHub running on http://localhost:${PORT}`));
}).catch((err) => {
  console.error('[FATAL] DB init failed:', err.message);
  process.exit(1);
});
