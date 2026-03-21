require('dotenv').config();
const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const cors       = require('cors');
const { Pool }   = require('pg');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

// ─────────────────────────────────────────────
//  CONFIG
// ─────────────────────────────────────────────
const PORT       = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'shadowtalk-secret-change-in-prod';
const CLIENT_URL = process.env.CLIENT_URL || '*';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// ─────────────────────────────────────────────
//  EXPRESS + SOCKET.IO
// ─────────────────────────────────────────────
const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin: CLIENT_URL, methods: ['GET', 'POST'] },
  pingTimeout: 60000,
});

app.use(cors({ origin: CLIENT_URL }));
app.use(express.json());

// ─────────────────────────────────────────────
//  DB INIT
// ─────────────────────────────────────────────
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        username    TEXT UNIQUE NOT NULL,
        display_name TEXT NOT NULL DEFAULT '',
        password_hash TEXT NOT NULL,
        avatar_color TEXT NOT NULL DEFAULT '#7c3aed',
        bio         TEXT NOT NULL DEFAULT '',
        is_online   BOOLEAN NOT NULL DEFAULT false,
        last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS conversations (
        id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        type       TEXT NOT NULL CHECK(type IN ('direct','group')),
        name       TEXT,
        avatar_color TEXT DEFAULT '#7c3aed',
        created_by UUID REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS conversation_members (
        conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
        user_id         UUID REFERENCES users(id) ON DELETE CASCADE,
        role            TEXT NOT NULL DEFAULT 'member',
        joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (conversation_id, user_id)
      );

      CREATE TABLE IF NOT EXISTS messages (
        id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
        sender_id       UUID REFERENCES users(id) ON DELETE SET NULL,
        content         TEXT NOT NULL,
        type            TEXT NOT NULL DEFAULT 'text',
        is_read         BOOLEAN NOT NULL DEFAULT false,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_msg_conv ON messages(conversation_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_members_user ON conversation_members(user_id);
      CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    `);
    console.log('✅ Database initialized');
  } finally {
    client.release();
  }
}

// ─────────────────────────────────────────────
//  AUTH MIDDLEWARE
// ─────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function makeToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
}

// ─────────────────────────────────────────────
//  REST API — AUTH
// ─────────────────────────────────────────────

// Register
app.post('/api/auth/register', async (req, res) => {
  const { username, display_name, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  if (!/^[a-z0-9_]{3,32}$/.test(username)) return res.status(400).json({ error: 'Invalid username' });
  if (password.length < 8) return res.status(400).json({ error: 'Password too short' });

  try {
    const exists = await pool.query('SELECT id FROM users WHERE username=$1', [username]);
    if (exists.rows.length) return res.status(409).json({ error: 'Username taken' });

    const hash  = await bcrypt.hash(password, 10);
    const colors = ['#7c3aed','#0f766e','#1d4ed8','#be185d','#b45309','#15803d','#9333ea','#0369a1'];
    const color  = colors[Math.floor(Math.random() * colors.length)];

    const { rows } = await pool.query(
      `INSERT INTO users(username, display_name, password_hash, avatar_color)
       VALUES($1,$2,$3,$4) RETURNING id, username, display_name, avatar_color, bio, created_at`,
      [username, display_name || username, hash, color]
    );
    const user = rows[0];
    res.json({ user, token: makeToken(user) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });

  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });

    const user = rows[0];
    const ok   = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Wrong password' });

    delete user.password_hash;
    res.json({ user, token: makeToken(user) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Me
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id,username,display_name,avatar_color,bio,is_online,last_seen,created_at FROM users WHERE id=$1',
      [req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─────────────────────────────────────────────
//  REST API — USERS
// ─────────────────────────────────────────────

// Search users by username
app.get('/api/users/search', authMiddleware, async (req, res) => {
  const q = (req.query.q || '').toLowerCase().trim();
  if (!q) return res.json([]);
  try {
    const { rows } = await pool.query(
      `SELECT id, username, display_name, avatar_color, is_online, last_seen
       FROM users
       WHERE (username ILIKE $1 OR display_name ILIKE $1) AND id != $2
       ORDER BY is_online DESC, username ASC
       LIMIT 20`,
      [`%${q}%`, req.user.id]
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Check username availability
app.get('/api/users/check/:username', async (req, res) => {
  const { rows } = await pool.query('SELECT id FROM users WHERE username=$1', [req.params.username]);
  res.json({ available: rows.length === 0 });
});

// ─────────────────────────────────────────────
//  REST API — CONVERSATIONS
// ─────────────────────────────────────────────

// Get my conversations
app.get('/api/conversations', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        c.id, c.type, c.name, c.avatar_color, c.created_at,
        -- last message
        lm.content  AS last_content,
        lm.created_at AS last_at,
        lm.sender_id  AS last_sender,
        -- unread count
        (SELECT COUNT(*) FROM messages m
          WHERE m.conversation_id = c.id
          AND m.sender_id != $1
          AND m.is_read = false) AS unread,
        -- for direct: other user info
        ou.id           AS other_id,
        ou.username     AS other_username,
        ou.display_name AS other_display_name,
        ou.avatar_color AS other_avatar_color,
        ou.is_online    AS other_online,
        ou.last_seen    AS other_last_seen
      FROM conversations c
      JOIN conversation_members cm ON cm.conversation_id = c.id AND cm.user_id = $1
      LEFT JOIN LATERAL (
        SELECT content, created_at, sender_id FROM messages
        WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1
      ) lm ON true
      LEFT JOIN conversation_members cm2
        ON cm2.conversation_id = c.id AND cm2.user_id != $1 AND c.type = 'direct'
      LEFT JOIN users ou ON ou.id = cm2.user_id
      ORDER BY COALESCE(lm.created_at, c.created_at) DESC
    `, [req.user.id]);
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get or create direct conversation
app.post('/api/conversations/direct', authMiddleware, async (req, res) => {
  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: 'user_id required' });
  const me = req.user.id;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Find existing
    const existing = await client.query(`
      SELECT c.id FROM conversations c
      JOIN conversation_members cm1 ON cm1.conversation_id = c.id AND cm1.user_id = $1
      JOIN conversation_members cm2 ON cm2.conversation_id = c.id AND cm2.user_id = $2
      WHERE c.type = 'direct' LIMIT 1
    `, [me, user_id]);

    if (existing.rows.length) {
      await client.query('COMMIT');
      return res.json({ id: existing.rows[0].id });
    }

    const conv = await client.query(
      `INSERT INTO conversations(type, created_by) VALUES('direct',$1) RETURNING id`, [me]
    );
    const cid = conv.rows[0].id;
    await client.query(
      `INSERT INTO conversation_members(conversation_id, user_id) VALUES($1,$2),($1,$3)`,
      [cid, me, user_id]
    );
    await client.query('COMMIT');
    res.json({ id: cid });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  } finally {
    client.release();
  }
});

// ─────────────────────────────────────────────
//  REST API — MESSAGES
// ─────────────────────────────────────────────

// Get messages for a conversation
app.get('/api/messages/:convId', authMiddleware, async (req, res) => {
  const { convId } = req.params;
  try {
    // Verify membership
    const mem = await pool.query(
      'SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2',
      [convId, req.user.id]
    );
    if (!mem.rows.length) return res.status(403).json({ error: 'Not a member' });

    const { rows } = await pool.query(`
      SELECT m.id, m.content, m.type, m.is_read, m.created_at, m.sender_id,
             u.username, u.display_name, u.avatar_color
      FROM messages m
      LEFT JOIN users u ON u.id = m.sender_id
      WHERE m.conversation_id = $1
      ORDER BY m.created_at ASC
      LIMIT 200
    `, [convId]);

    // Mark as read
    await pool.query(
      `UPDATE messages SET is_read=true
       WHERE conversation_id=$1 AND sender_id!=$2 AND is_read=false`,
      [convId, req.user.id]
    );

    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─────────────────────────────────────────────
//  SOCKET.IO
// ─────────────────────────────────────────────
const onlineUsers = new Map(); // userId -> socketId

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  try {
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    next(new Error('Invalid token'));
  }
});

io.on('connection', async (socket) => {
  const userId = socket.user.id;
  console.log(`🔌 Connected: ${socket.user.username} (${socket.id})`);

  // Mark online
  onlineUsers.set(userId, socket.id);
  await pool.query('UPDATE users SET is_online=true WHERE id=$1', [userId]);
  io.emit('user:online', { userId, online: true });

  // Join all conversation rooms
  const { rows: convs } = await pool.query(
    'SELECT conversation_id FROM conversation_members WHERE user_id=$1', [userId]
  );
  convs.forEach(c => socket.join(c.conversation_id));

  // ── SEND MESSAGE ──
  socket.on('message:send', async (data, ack) => {
    const { conversation_id, content } = data;
    if (!conversation_id || !content?.trim()) return;

    try {
      // Verify membership
      const mem = await pool.query(
        'SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2',
        [conversation_id, userId]
      );
      if (!mem.rows.length) return;

      const { rows } = await pool.query(
        `INSERT INTO messages(conversation_id, sender_id, content)
         VALUES($1,$2,$3)
         RETURNING id, conversation_id, sender_id, content, type, is_read, created_at`,
        [conversation_id, userId, content.trim()]
      );
      const msg = rows[0];

      // Attach sender info
      const { rows: senderRows } = await pool.query(
        'SELECT username, display_name, avatar_color FROM users WHERE id=$1', [userId]
      );
      const full = { ...msg, ...senderRows[0] };

      // Broadcast to conversation room
      io.to(conversation_id).emit('message:new', full);

      if (ack) ack({ ok: true, message: full });
    } catch (e) {
      console.error('message:send error', e);
      if (ack) ack({ ok: false });
    }
  });

  // ── TYPING ──
  socket.on('typing:start', ({ conversation_id }) => {
    socket.to(conversation_id).emit('typing:start', {
      conversation_id,
      userId,
      username: socket.user.username,
    });
  });

  socket.on('typing:stop', ({ conversation_id }) => {
    socket.to(conversation_id).emit('typing:stop', { conversation_id, userId });
  });

  // ── READ RECEIPT ──
  socket.on('messages:read', async ({ conversation_id }) => {
    await pool.query(
      'UPDATE messages SET is_read=true WHERE conversation_id=$1 AND sender_id!=$2 AND is_read=false',
      [conversation_id, userId]
    );
    socket.to(conversation_id).emit('messages:read', { conversation_id, userId });
  });

  // ── JOIN NEW CONVERSATION ──
  socket.on('conversation:join', ({ conversation_id }) => {
    socket.join(conversation_id);
  });

  // ── DISCONNECT ──
  socket.on('disconnect', async () => {
    console.log(`❌ Disconnected: ${socket.user.username}`);
    onlineUsers.delete(userId);
    await pool.query(
      'UPDATE users SET is_online=false, last_seen=NOW() WHERE id=$1', [userId]
    );
    io.emit('user:online', { userId, online: false, last_seen: new Date() });
  });
});

// ─────────────────────────────────────────────
//  HEALTH CHECK
// ─────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));

// ─────────────────────────────────────────────
//  START
// ─────────────────────────────────────────────
initDB().then(() => {
  server.listen(PORT, () => console.log(`🚀 ShadowTalk backend on port ${PORT}`));
}).catch(e => {
  console.error('DB init failed:', e);
  process.exit(1);
});