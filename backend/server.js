require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { DatabaseSync } = require('node:sqlite');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

// ─── Database setup ───────────────────────────────────────────────────────────

const db = new DatabaseSync('travelpals.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    name          TEXT    NOT NULL,
    age           INTEGER,
    gender        TEXT,
    hobbies       TEXT    DEFAULT '[]',
    bio           TEXT    DEFAULT '',
    created_at    TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS trips (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    creator_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title       TEXT    NOT NULL,
    destination TEXT    NOT NULL,
    country     TEXT    NOT NULL,
    description TEXT    DEFAULT '',
    start_date  TEXT    NOT NULL,
    end_date    TEXT    NOT NULL,
    max_members INTEGER DEFAULT 5,
    created_at  TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS trip_members (
    trip_id   INTEGER NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined_at TEXT    DEFAULT (datetime('now')),
    PRIMARY KEY (trip_id, user_id)
  );
`);

// ─── Middleware ────────────────────────────────────────────────────────────────

app.use(cors({
  origin: [
    'http://localhost:5500',
    'http://127.0.0.1:5500',
    'http://localhost:8080',
    'http://127.0.0.1:8080',
  ]
}));
app.use(express.json());

function requireAuth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ─── Auth routes ──────────────────────────────────────────────────────────────

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name) {
    return res.status(400).json({ error: 'email, password and name are required' });
  }
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return res.status(409).json({ error: 'Email already in use' });

  const password_hash = await bcrypt.hash(password, 10);
  const result = db.prepare(
    'INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)'
  ).run(email, password_hash, name);

  const user = db.prepare('SELECT id, email, name, age, gender, hobbies, bio FROM users WHERE id = ?').get(result.lastInsertRowid);
  user.hobbies = JSON.parse(user.hobbies || '[]');
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.status(201).json({ token, user });
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!row) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, row.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  const user = { id: row.id, email: row.email, name: row.name, age: row.age, gender: row.gender, hobbies: JSON.parse(row.hobbies || '[]'), bio: row.bio };
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user });
});

// ─── User routes ──────────────────────────────────────────────────────────────

// GET /api/users?hobbies=hiking
app.get('/api/users', (req, res) => {
  let rows = db.prepare('SELECT id, email, name, age, gender, hobbies, bio FROM users').all();
  rows = rows.map(u => ({ ...u, hobbies: JSON.parse(u.hobbies || '[]') }));

  if (req.query.hobbies) {
    const filter = req.query.hobbies.toLowerCase();
    rows = rows.filter(u => u.hobbies.some(h => h.toLowerCase().includes(filter)));
  }
  res.json(rows);
});

// GET /api/users/:id
app.get('/api/users/:id', (req, res) => {
  const user = db.prepare('SELECT id, email, name, age, gender, hobbies, bio, created_at FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.hobbies = JSON.parse(user.hobbies || '[]');
  res.json(user);
});

// PUT /api/users/:id
app.put('/api/users/:id', requireAuth, (req, res) => {
  if (req.user.id !== parseInt(req.params.id)) {
    return res.status(403).json({ error: "Cannot edit another user's profile" });
  }
  const { name, age, gender, hobbies, bio } = req.body;
  db.prepare(`
    UPDATE users SET name = ?, age = ?, gender = ?, hobbies = ?, bio = ?
    WHERE id = ?
  `).run(name, age, gender, JSON.stringify(hobbies || []), bio, req.params.id);

  const user = db.prepare('SELECT id, email, name, age, gender, hobbies, bio FROM users WHERE id = ?').get(req.params.id);
  user.hobbies = JSON.parse(user.hobbies || '[]');
  res.json(user);
});

// DELETE /api/users/:id
app.delete('/api/users/:id', requireAuth, (req, res) => {
  if (req.user.id !== parseInt(req.params.id)) {
    return res.status(403).json({ error: "Cannot delete another user's account" });
  }
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ message: 'Account deleted' });
});

// ─── Trip routes ──────────────────────────────────────────────────────────────

// GET /api/trips?country=France&destination=paris
app.get('/api/trips', (req, res) => {
  let trips = db.prepare(`
    SELECT t.*, u.name as creator_name,
           (SELECT COUNT(*) FROM trip_members WHERE trip_id = t.id) as member_count
    FROM trips t
    JOIN users u ON t.creator_id = u.id
    ORDER BY t.created_at DESC
  `).all();

  if (req.query.country) {
    trips = trips.filter(t => t.country.toLowerCase().includes(req.query.country.toLowerCase()));
  }
  if (req.query.destination) {
    trips = trips.filter(t => t.destination.toLowerCase().includes(req.query.destination.toLowerCase()));
  }
  res.json(trips);
});

// POST /api/trips
app.post('/api/trips', requireAuth, (req, res) => {
  const { title, destination, country, description, start_date, end_date, max_members } = req.body;
  if (!title || !destination || !country || !start_date || !end_date) {
    return res.status(400).json({ error: 'title, destination, country, start_date and end_date are required' });
  }
  const result = db.prepare(`
    INSERT INTO trips (creator_id, title, destination, country, description, start_date, end_date, max_members)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(req.user.id, title, destination, country, description || '', start_date, end_date, max_members || 5);

  // Creator automatically joins their own trip
  db.prepare('INSERT OR IGNORE INTO trip_members (trip_id, user_id) VALUES (?, ?)').run(result.lastInsertRowid, req.user.id);

  const trip = db.prepare('SELECT * FROM trips WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json(trip);
});

// GET /api/trips/:id
app.get('/api/trips/:id', (req, res) => {
  const trip = db.prepare(`
    SELECT t.*, u.name as creator_name
    FROM trips t JOIN users u ON t.creator_id = u.id
    WHERE t.id = ?
  `).get(req.params.id);
  if (!trip) return res.status(404).json({ error: 'Trip not found' });

  const members = db.prepare(`
    SELECT u.id, u.name, u.age, u.gender, u.hobbies, tm.joined_at
    FROM trip_members tm JOIN users u ON tm.user_id = u.id
    WHERE tm.trip_id = ?
  `).all(req.params.id);
  members.forEach(m => { m.hobbies = JSON.parse(m.hobbies || '[]'); });

  res.json({ ...trip, members });
});

// PUT /api/trips/:id
app.put('/api/trips/:id', requireAuth, (req, res) => {
  const trip = db.prepare('SELECT * FROM trips WHERE id = ?').get(req.params.id);
  if (!trip) return res.status(404).json({ error: 'Trip not found' });
  if (trip.creator_id !== req.user.id) return res.status(403).json({ error: 'Only the trip creator can edit this trip' });

  const { title, destination, country, description, start_date, end_date, max_members } = req.body;
  db.prepare(`
    UPDATE trips SET title = ?, destination = ?, country = ?, description = ?,
                     start_date = ?, end_date = ?, max_members = ?
    WHERE id = ?
  `).run(title, destination, country, description, start_date, end_date, max_members, req.params.id);

  res.json(db.prepare('SELECT * FROM trips WHERE id = ?').get(req.params.id));
});

// DELETE /api/trips/:id
app.delete('/api/trips/:id', requireAuth, (req, res) => {
  const trip = db.prepare('SELECT * FROM trips WHERE id = ?').get(req.params.id);
  if (!trip) return res.status(404).json({ error: 'Trip not found' });
  if (trip.creator_id !== req.user.id) return res.status(403).json({ error: 'Only the trip creator can delete this trip' });

  db.prepare('DELETE FROM trips WHERE id = ?').run(req.params.id);
  res.json({ message: 'Trip deleted' });
});

// POST /api/trips/:id/join
app.post('/api/trips/:id/join', requireAuth, (req, res) => {
  const trip = db.prepare('SELECT * FROM trips WHERE id = ?').get(req.params.id);
  if (!trip) return res.status(404).json({ error: 'Trip not found' });

  const memberCount = db.prepare('SELECT COUNT(*) as count FROM trip_members WHERE trip_id = ?').get(req.params.id).count;
  if (memberCount >= trip.max_members) return res.status(400).json({ error: 'Trip is full' });

  const already = db.prepare('SELECT 1 FROM trip_members WHERE trip_id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (already) return res.status(400).json({ error: 'Already a member of this trip' });

  db.prepare('INSERT INTO trip_members (trip_id, user_id) VALUES (?, ?)').run(req.params.id, req.user.id);
  res.json({ message: 'Joined trip' });
});

// DELETE /api/trips/:id/leave
app.delete('/api/trips/:id/leave', requireAuth, (req, res) => {
  const trip = db.prepare('SELECT * FROM trips WHERE id = ?').get(req.params.id);
  if (!trip) return res.status(404).json({ error: 'Trip not found' });
  if (trip.creator_id === req.user.id) return res.status(400).json({ error: 'Trip creator cannot leave. Delete the trip instead.' });

  db.prepare('DELETE FROM trip_members WHERE trip_id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ message: 'Left trip' });
});

// ─── Hotels route (Booking.com proxy) ────────────────────────────────────────

// GET /api/hotels/search?destination=Paris
app.get('/api/hotels/search', requireAuth, async (req, res) => {
  const { destination } = req.query;
  if (!destination) return res.status(400).json({ error: 'destination query param required' });

  const RAPIDAPI_KEY = process.env.RAPIDAPI_KEY;
  if (!RAPIDAPI_KEY) {
    return res.status(503).json({ error: 'Hotel search not configured. Add your RAPIDAPI_KEY to .env' });
  }

  const RAPIDAPI_HOST = 'booking-com15.p.rapidapi.com';
  const apiHeaders = { 'X-RapidAPI-Key': RAPIDAPI_KEY, 'X-RapidAPI-Host': RAPIDAPI_HOST };

  try {
    // Step 1: resolve destination to dest_id + search_type
    const destRes = await fetch(
      `https://${RAPIDAPI_HOST}/api/v1/hotels/searchDestination?query=${encodeURIComponent(destination)}`,
      { headers: apiHeaders }
    );
    const destData = await destRes.json();
    if (!destData.status || !destData.data?.length) return res.json([]);

    const { dest_id, search_type } = destData.data[0];

    // Step 2: search hotels — use trip dates if provided, else today + 2 days
    const today = new Date();
    const todayStr = today.toISOString().split('T')[0];
    let arrival   = req.query.arrival_date   || todayStr;
    let departure = req.query.departure_date || new Date(today.getTime() + 2 * 86400000).toISOString().split('T')[0];
    if (arrival < todayStr) arrival = todayStr;
    if (departure <= arrival) departure = new Date(new Date(arrival).getTime() + 2 * 86400000).toISOString().split('T')[0];

    const hotelsRes = await fetch(
      `https://${RAPIDAPI_HOST}/api/v1/hotels/searchHotels?dest_id=${encodeURIComponent(dest_id)}&search_type=${encodeURIComponent(search_type)}&arrival_date=${arrival}&departure_date=${departure}&adults=2&room_qty=1&languagecode=en-us&currency_code=EUR`,
      { headers: apiHeaders }
    );
    const hotelsData = await hotelsRes.json();
    const hotels = (hotelsData.data?.hotels || []).slice(0, 10).map(h => ({
      id: h.hotel_id,
      name: h.property.name,
      stars: h.property.accuratePropertyClass || h.property.propertyClass,
      score: h.property.reviewScore,
      scoreWord: h.property.reviewScoreWord,
      price: h.property.priceBreakdown?.grossPrice?.value,
      currency: h.property.priceBreakdown?.grossPrice?.currency,
      photo: h.property.photoUrls?.[0]
    }));
    res.json(hotels);
  } catch (err) {
    res.status(500).json({ error: 'Hotel search failed', details: err.message });
  }
});

// ─── Start server ─────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`TravelPals backend running on http://localhost:${PORT}`);
});
