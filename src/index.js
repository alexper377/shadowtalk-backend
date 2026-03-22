require('dotenv').config();
const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const cors       = require('cors');
const { Pool }   = require('pg');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path       = require('path');

const PORT       = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'shadowtalk-secret';
const CLIENT_URL = process.env.CLIENT_URL || '*';
const MAX_FILE_MB = 20;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin: CLIENT_URL, methods: ['GET','POST'] },
  pingTimeout: 60000,
  maxHttpBufferSize: MAX_FILE_MB * 1024 * 1024,
});

app.use(cors({ origin: CLIENT_URL }));
app.set('io', io);
app.use(express.json({ limit: `${MAX_FILE_MB}mb` }));

// ─── DB INIT ───
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        username     TEXT UNIQUE NOT NULL,
        display_name TEXT NOT NULL DEFAULT '',
        password_hash TEXT NOT NULL,
        avatar_color TEXT NOT NULL DEFAULT '#7c3aed',
        bio          TEXT NOT NULL DEFAULT '',
        is_online    BOOLEAN NOT NULL DEFAULT false,
        last_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS friendships (
        id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
        friend_id  UUID REFERENCES users(id) ON DELETE CASCADE,
        status     TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','blocked')),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(user_id, friend_id)
      );
      CREATE TABLE IF NOT EXISTS conversations (
        id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        type         TEXT NOT NULL CHECK(type IN ('direct','group')),
        name         TEXT,
        description  TEXT DEFAULT '',
        avatar_color TEXT DEFAULT '#7c3aed',
        created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
        created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
        content         TEXT NOT NULL DEFAULT '',
        type            TEXT NOT NULL DEFAULT 'text' CHECK(type IN ('text','image','file','audio','system','call','deleted')),
        file_name       TEXT,
        file_size       INTEGER,
        file_data       TEXT,
        reply_to_id     UUID,
        reply_to_content TEXT,
        reply_to_user   TEXT,
        is_read         BOOLEAN NOT NULL DEFAULT false,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      -- Add reply columns if they don't exist (for existing tables)
      ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to_id UUID;
      ALTER TABLE conversations ADD COLUMN IF NOT EXISTS description TEXT DEFAULT '';
      ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_data TEXT;
      ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_name TEXT;
      ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_size INTEGER;
      ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to_content TEXT;
      ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to_user TEXT;
      CREATE INDEX IF NOT EXISTS idx_msg_conv ON messages(conversation_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_members_user ON conversation_members(user_id);
      CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
      CREATE INDEX IF NOT EXISTS idx_friends ON friendships(user_id, status);
    `);
    console.log('✅ Database initialized');
  } finally { client.release(); }
}

// ─── AUTH MIDDLEWARE ───
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}
function makeToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
}

// ─── AUTH ───
app.post('/api/auth/register', async (req, res) => {
  const { username, display_name, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  if (!/^[a-z0-9_]{3,32}$/.test(username)) return res.status(400).json({ error: 'Invalid username' });
  if (password.length < 8) return res.status(400).json({ error: 'Password too short' });
  try {
    const exists = await pool.query('SELECT id FROM users WHERE username=$1', [username]);
    if (exists.rows.length) return res.status(409).json({ error: 'Username taken' });
    const hash = await bcrypt.hash(password, 10);
    const colors = ['#7c3aed','#0f766e','#1d4ed8','#be185d','#b45309','#15803d','#9333ea','#0369a1'];
    const color = colors[Math.floor(Math.random()*colors.length)];
    const { rows } = await pool.query(
      `INSERT INTO users(username,display_name,password_hash,avatar_color)
       VALUES($1,$2,$3,$4) RETURNING id,username,display_name,avatar_color,bio,created_at`,
      [username, display_name||username, hash, color]
    );
    res.json({ user: rows[0], token: makeToken(rows[0]) });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    const ok = await bcrypt.compare(password, rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Wrong password' });
    delete rows[0].password_hash;
    res.json({ user: rows[0], token: makeToken(rows[0]) });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/auth/me', auth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id,username,display_name,avatar_color,bio,is_online,last_seen,created_at FROM users WHERE id=$1',
    [req.user.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Not found' });
  res.json(rows[0]);
});

// ─── USERS ───
app.get('/api/users/search', auth, async (req, res) => {
  const q = (req.query.q||'').trim();
  if (!q) return res.json([]);
  const { rows } = await pool.query(
    `SELECT id,username,display_name,avatar_color,is_online,last_seen
     FROM users WHERE (username ILIKE $1 OR display_name ILIKE $1) AND id!=$2
     ORDER BY is_online DESC, username ASC LIMIT 20`,
    [`%${q}%`, req.user.id]
  );
  res.json(rows);
});

app.get('/api/users/check/:username', async (req, res) => {
  const { rows } = await pool.query('SELECT id FROM users WHERE username=$1', [req.params.username]);
  res.json({ available: rows.length === 0 });
});

// ─── FRIENDS ───
app.get('/api/friends', auth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT u.id,u.username,u.display_name,u.avatar_color,u.is_online,u.last_seen,
           f.status, f.id as friendship_id,
           CASE WHEN f.user_id=$1 THEN 'sent' ELSE 'received' END as direction
    FROM friendships f
    JOIN users u ON u.id = CASE WHEN f.user_id=$1 THEN f.friend_id ELSE f.user_id END
    WHERE (f.user_id=$1 OR f.friend_id=$1) AND f.status != 'blocked'
    ORDER BY f.status, u.display_name
  `, [req.user.id]);
  res.json(rows);
});

app.post('/api/friends/request', auth, async (req, res) => {
  const { user_id } = req.body;
  if (!user_id || user_id === req.user.id) return res.status(400).json({ error: 'Invalid' });
  try {
    const existing = await pool.query(
      'SELECT id,status FROM friendships WHERE (user_id=$1 AND friend_id=$2) OR (user_id=$2 AND friend_id=$1)',
      [req.user.id, user_id]
    );
    if (existing.rows.length) return res.json({ friendship: existing.rows[0] });
    const { rows } = await pool.query(
      'INSERT INTO friendships(user_id,friend_id,status) VALUES($1,$2,$3) RETURNING *',
      [req.user.id, user_id, 'pending']
    );
    res.json({ friendship: rows[0] });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/friends/accept', auth, async (req, res) => {
  const { friendship_id } = req.body;
  const { rows } = await pool.query(
    `UPDATE friendships SET status='accepted' WHERE id=$1 AND friend_id=$2 RETURNING *`,
    [friendship_id, req.user.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Not found' });
  res.json({ friendship: rows[0] });
});

app.delete('/api/friends/:id', auth, async (req, res) => {
  await pool.query(
    'DELETE FROM friendships WHERE id=$1 AND (user_id=$2 OR friend_id=$2)',
    [req.params.id, req.user.id]
  );
  res.json({ ok: true });
});

// ─── CONVERSATIONS ───
app.get('/api/conversations', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.id, c.type, c.name, c.description, c.avatar_color, c.created_at,
        lm.content AS last_content, lm.type AS last_type, lm.created_at AS last_at,
        (SELECT COUNT(*) FROM messages m WHERE m.conversation_id=c.id AND m.sender_id!=$1 AND m.is_read=false) AS unread,
        ou.id AS other_id, ou.username AS other_username,
        ou.display_name AS other_display_name, ou.avatar_color AS other_avatar_color,
        ou.is_online AS other_online, ou.last_seen AS other_last_seen
      FROM conversations c
      JOIN conversation_members cm ON cm.conversation_id=c.id AND cm.user_id=$1
      LEFT JOIN LATERAL (
        SELECT content,type,created_at,sender_id FROM messages
        WHERE conversation_id=c.id ORDER BY created_at DESC LIMIT 1
      ) lm ON true
      LEFT JOIN conversation_members cm2 ON cm2.conversation_id=c.id AND cm2.user_id!=$1 AND c.type='direct'
      LEFT JOIN users ou ON ou.id=cm2.user_id
      ORDER BY COALESCE(lm.created_at, c.created_at) DESC
    `, [req.user.id]);
    res.json(rows);
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/conversations/direct', auth, async (req, res) => {
  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: 'user_id required' });
  const me = req.user.id;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const existing = await client.query(`
      SELECT c.id FROM conversations c
      JOIN conversation_members cm1 ON cm1.conversation_id=c.id AND cm1.user_id=$1
      JOIN conversation_members cm2 ON cm2.conversation_id=c.id AND cm2.user_id=$2
      WHERE c.type='direct' LIMIT 1
    `, [me, user_id]);
    if (existing.rows.length) { await client.query('COMMIT'); return res.json({ id: existing.rows[0].id }); }
    const conv = await client.query(`INSERT INTO conversations(type,created_by) VALUES('direct',$1) RETURNING id`, [me]);
    const cid = conv.rows[0].id;
    await client.query(`INSERT INTO conversation_members(conversation_id,user_id) VALUES($1,$2),($1,$3)`, [cid,me,user_id]);
    await client.query('COMMIT');
    res.json({ id: cid });
  } catch(e) { await client.query('ROLLBACK'); console.error(e); res.status(500).json({ error: 'Server error' }); }
  finally { client.release(); }
});

app.post('/api/conversations/group', auth, async (req, res) => {
  const { name, description, member_ids } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  const colors = ['#7c3aed','#0f766e','#1d4ed8','#be185d','#b45309','#15803d'];
  const color = colors[Math.floor(Math.random()*colors.length)];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const conv = await client.query(
      `INSERT INTO conversations(type,name,description,avatar_color,created_by) VALUES('group',$1,$2,$3,$4) RETURNING id`,
      [name, description||'', color, req.user.id]
    );
    const cid = conv.rows[0].id;
    const allMembers = [req.user.id, ...(member_ids||[])].filter((v,i,a)=>a.indexOf(v)===i);
    for (const uid of allMembers) {
      const role = uid === req.user.id ? 'admin' : 'member';
      await client.query(`INSERT INTO conversation_members(conversation_id,user_id,role) VALUES($1,$2,$3)`, [cid,uid,role]);
    }
    await client.query(`INSERT INTO messages(conversation_id,sender_id,content,type) VALUES($1,$2,$3,'system')`,
      [cid, req.user.id, `Group "${name}" created`]);
    await client.query('COMMIT');
    res.json({ id: cid, name, color });
  } catch(e) { await client.query('ROLLBACK'); console.error(e); res.status(500).json({ error: 'Server error' }); }
  finally { client.release(); }
});

// ─── MESSAGES ───
app.get('/api/messages/:convId', auth, async (req, res) => {
  const { convId } = req.params;
  const before = req.query.before;
  try {
    const mem = await pool.query('SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2', [convId, req.user.id]);
    if (!mem.rows.length) return res.status(403).json({ error: 'Not a member' });
    let q = `SELECT m.id,m.content,m.type,m.file_name,m.file_size,m.file_data,m.reply_to_id,m.reply_to_content,m.reply_to_user,m.is_read,m.created_at,m.sender_id,
             u.username,u.display_name,u.avatar_color
             FROM messages m LEFT JOIN users u ON u.id=m.sender_id
             WHERE m.conversation_id=$1`;
    const params = [convId];
    if (before) { params.push(before); q += ` AND m.created_at < $${params.length}`; }
    q += ` ORDER BY m.created_at ASC LIMIT 100`;
    const { rows } = await pool.query(q, params);
    await pool.query(`UPDATE messages SET is_read=true WHERE conversation_id=$1 AND sender_id!=$2 AND is_read=false`, [convId, req.user.id]);
    res.json(rows);
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// ─── FILE UPLOAD ───
app.post('/api/messages/upload', auth, async (req, res) => {
  const { conversation_id, type, file_name, file_size, file_data, content } = req.body;
  if (!conversation_id || !file_data) return res.status(400).json({ error: 'Missing fields' });
  try {
    const mem = await pool.query('SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2', [conversation_id, req.user.id]);
    if (!mem.rows.length) return res.status(403).json({ error: 'Not a member' });
    const { rows } = await pool.query(
      `INSERT INTO messages(conversation_id,sender_id,content,type,file_name,file_size,file_data)
       VALUES($1,$2,$3,$4,$5,$6,$7)
       RETURNING id,conversation_id,sender_id,content,type,file_name,file_size,file_data,reply_to_id,reply_to_content,reply_to_user,is_read,created_at`,
      [conversation_id, req.user.id, content||'', type||'file', file_name||null, file_size||null, file_data]
    );
    const msg = rows[0];
    const { rows: sr } = await pool.query('SELECT username,display_name,avatar_color FROM users WHERE id=$1', [req.user.id]);
    const full = { ...msg, ...sr[0] };
    const io_instance = req.app.get('io');
    if (io_instance) io_instance.to(conversation_id).emit('message:new', full);
    res.json({ ok: true, message: full });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// ─── SOCKET.IO ───
const onlineUsers = new Map();

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  try { socket.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { next(new Error('Invalid token')); }
});

io.on('connection', async (socket) => {
  const userId = socket.user.id;
  console.log(`🔌 Connected: ${socket.user.username}`);
  onlineUsers.set(userId, socket.id);
  await pool.query('UPDATE users SET is_online=true WHERE id=$1', [userId]);
  io.emit('user:online', { userId, online: true });

  // Join rooms
  const { rows: convs } = await pool.query('SELECT conversation_id FROM conversation_members WHERE user_id=$1', [userId]);
  convs.forEach(c => socket.join(c.conversation_id));

  // ── SEND MESSAGE ──
  socket.on('message:send', async (data, ack) => {
    if (!data?.conversation_id) return;
    const { conversation_id, content, type='text', file_name, file_size, file_data } = data;
    if (!content && !file_data) return;
    try {
      const mem = await pool.query('SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2', [conversation_id, userId]);
      if (!mem.rows.length) return;
      const { reply_to_id, reply_to_content, reply_to_user } = data;
      const { rows } = await pool.query(
        `INSERT INTO messages(conversation_id,sender_id,content,type,file_name,file_size,file_data,reply_to_id,reply_to_content,reply_to_user)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         RETURNING id,conversation_id,sender_id,content,type,file_name,file_size,file_data,reply_to_id,reply_to_content,reply_to_user,is_read,created_at`,
        [conversation_id, userId, content||'', type, file_name||null, file_size||null, file_data||null, reply_to_id||null, reply_to_content||null, reply_to_user||null]
      );
      const msg = rows[0];
      const { rows: sr } = await pool.query('SELECT username,display_name,avatar_color FROM users WHERE id=$1', [userId]);
      const full = { ...msg, ...sr[0] };
      io.to(conversation_id).emit('message:new', full);
      if (ack) ack({ ok: true, message: full });
    } catch(e) { console.error('message:send error', e); if(ack) ack({ok:false}); }
  });

  // ── TYPING ──
  socket.on('typing:start', (data) => {
    if (!data?.conversation_id) return;
    socket.to(data.conversation_id).emit('typing:start', {
      conversation_id: data.conversation_id, userId, username: socket.user.username
    });
  });
  socket.on('typing:stop', (data) => {
    if (!data?.conversation_id) return;
    socket.to(data.conversation_id).emit('typing:stop', { conversation_id: data.conversation_id, userId });
  });

  // ── READ ──
  socket.on('messages:read', async (data) => {
    if (!data?.conversation_id) return;
    await pool.query('UPDATE messages SET is_read=true WHERE conversation_id=$1 AND sender_id!=$2 AND is_read=false', [data.conversation_id, userId]);
    socket.to(data.conversation_id).emit('messages:read', { conversation_id: data.conversation_id, userId });
  });

  // ── JOIN ROOM ──
  socket.on('conversation:join', (data) => {
    if (!data?.conversation_id) return;
    socket.join(data.conversation_id);
  });

  // ── WEBRTC CALL SIGNALING ──
  socket.on('call:offer', (data) => {
    if (!data?.conversation_id) return;
    socket.to(data.conversation_id).emit('call:offer', { ...data, from: userId, username: socket.user.username });
  });
  socket.on('call:answer', (data) => {
    if (!data?.conversation_id) return;
    socket.to(data.conversation_id).emit('call:answer', { ...data, from: userId });
  });
  socket.on('call:ice', (data) => {
    if (!data?.conversation_id) return;
    socket.to(data.conversation_id).emit('call:ice', { ...data, from: userId });
  });
  socket.on('call:end', (data) => {
    if (!data?.conversation_id) return;
    socket.to(data.conversation_id).emit('call:end', { from: userId });
  });
  socket.on('call:reject', (data) => {
    if (!data?.conversation_id) return;
    socket.to(data.conversation_id).emit('call:reject', { from: userId });
  });

  // ── DISCONNECT ──
  socket.on('disconnect', async () => {
    console.log(`❌ Disconnected: ${socket.user.username}`);
    onlineUsers.delete(userId);
    await pool.query('UPDATE users SET is_online=false,last_seen=NOW() WHERE id=$1', [userId]);
    io.emit('user:online', { userId, online: false, last_seen: new Date() });
  });
});

app.get('/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));

initDB().then(() => {
  server.listen(PORT, () => console.log(`🚀 ShadowTalk backend on port ${PORT}`));
}).catch(e => { console.error('DB init failed:', e); process.exit(1); });

// ─── DELETE MESSAGE ───
app.delete('/api/messages/:msgId', auth, async (req, res) => {
  const { msgId } = req.params;
  const { for_everyone } = req.body || {};
  try {
    const { rows } = await pool.query('SELECT * FROM messages WHERE id=$1', [msgId]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    const msg = rows[0];
    if (for_everyone && msg.sender_id !== req.user.id) {
      return res.status(403).json({ error: 'Can only delete your own messages for everyone' });
    }
    if (for_everyone) {
      await pool.query('DELETE FROM messages WHERE id=$1', [msgId]);
      const io_instance = req.app.get('io');
      if (io_instance) io_instance.to(msg.conversation_id).emit('message:deleted', { message_id: msgId, conversation_id: msg.conversation_id });
    } else {
      // For just me - mark as deleted (soft delete)
      await pool.query('UPDATE messages SET content=$1, type=$2 WHERE id=$3', ['[Message deleted]', 'deleted', msgId]);
    }
    res.json({ ok: true });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// ─── CLEAR CHAT ───
app.delete('/api/conversations/:convId/messages', auth, async (req, res) => {
  const { convId } = req.params;
  try {
    const mem = await pool.query('SELECT role FROM conversation_members WHERE conversation_id=$1 AND user_id=$2', [convId, req.user.id]);
    if (!mem.rows.length) return res.status(403).json({ error: 'Not a member' });
    await pool.query('DELETE FROM messages WHERE conversation_id=$1', [convId]);
    const io_instance = req.app.get('io');
    if (io_instance) io_instance.to(convId).emit('chat:cleared', { conversation_id: convId });
    res.json({ ok: true });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// ─── LEAVE / DELETE CONVERSATION ───
app.post('/api/conversations/:convId/leave', auth, async (req, res) => {
  const { convId } = req.params;
  try {
    const mem = await pool.query(
      'SELECT role FROM conversation_members WHERE conversation_id=$1 AND user_id=$2',
      [convId, req.user.id]
    );
    if (!mem.rows.length) return res.status(403).json({ error: 'Not a member' });
    // Remove user from conversation
    await pool.query(
      'DELETE FROM conversation_members WHERE conversation_id=$1 AND user_id=$2',
      [convId, req.user.id]
    );
    // If no members left, delete the conversation
    const remaining = await pool.query(
      'SELECT COUNT(*) FROM conversation_members WHERE conversation_id=$1', [convId]
    );
    if (parseInt(remaining.rows[0].count) === 0) {
      await pool.query('DELETE FROM conversations WHERE id=$1', [convId]);
    }
    res.json({ ok: true });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});
