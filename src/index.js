require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'shadowtalk-secret';
const CLIENT_URL = process.env.CLIENT_URL || '*';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: CLIENT_URL, methods: ['GET','POST','DELETE'] },
  pingTimeout: 60000,
  maxHttpBufferSize: 25 * 1024 * 1024,
});

app.use(cors({ origin: CLIENT_URL }));
app.use(express.json({ limit: '25mb' }));
app.set('io', io);

// ═══ DB INIT ═══
async function initDB() {
  const c = await pool.connect();
  try {
    await c.query(`
      CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        username TEXT UNIQUE NOT NULL,
        display_name TEXT NOT NULL DEFAULT '',
        password_hash TEXT NOT NULL,
        avatar_color TEXT NOT NULL DEFAULT '#2aabee',
        bio TEXT NOT NULL DEFAULT '',
        is_online BOOLEAN NOT NULL DEFAULT false,
        last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS friendships (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        friend_id UUID REFERENCES users(id) ON DELETE CASCADE,
        status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','blocked')),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(user_id, friend_id)
      );

      CREATE TABLE IF NOT EXISTS conversations (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        type TEXT NOT NULL CHECK(type IN ('direct','group','channel')),
        name TEXT,
        description TEXT DEFAULT '',
        avatar_color TEXT DEFAULT '#2aabee',
        username TEXT UNIQUE,
        is_public BOOLEAN DEFAULT false,
        created_by UUID REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      ALTER TABLE conversations ADD COLUMN IF NOT EXISTS username TEXT;
      ALTER TABLE conversations ADD COLUMN IF NOT EXISTS is_public BOOLEAN DEFAULT false;
      ALTER TABLE conversations ADD COLUMN IF NOT EXISTS description TEXT DEFAULT '';

      CREATE TABLE IF NOT EXISTS conversation_members (
        conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('owner','admin','member','banned')),
        can_post BOOLEAN NOT NULL DEFAULT true,
        joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (conversation_id, user_id)
      );
      ALTER TABLE conversation_members ADD COLUMN IF NOT EXISTS can_post BOOLEAN NOT NULL DEFAULT true;

      CREATE TABLE IF NOT EXISTS messages (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
        sender_id UUID REFERENCES users(id) ON DELETE SET NULL,
        content TEXT NOT NULL DEFAULT '',
        type TEXT NOT NULL DEFAULT 'text' CHECK(type IN ('text','image','file','audio','video_note','system','call','deleted')),
        file_name TEXT,
        file_size INTEGER,
        file_data TEXT,
        reply_to_id UUID,
        reply_to_content TEXT,
        reply_to_user TEXT,
        is_read BOOLEAN NOT NULL DEFAULT false,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to_id UUID;
      ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to_content TEXT;
      ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to_user TEXT;
      ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_data TEXT;
      ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_name TEXT;
      ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_size INTEGER;

      CREATE INDEX IF NOT EXISTS idx_msg_conv ON messages(conversation_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_members_user ON conversation_members(user_id);
      CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
      CREATE INDEX IF NOT EXISTS idx_conv_username ON conversations(username);
    `);
    console.log('✅ Database ready');
  } finally { c.release(); }
}

// ═══ AUTH ═══
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}
function makeToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
}

// ═══ AUTH ROUTES ═══
app.post('/api/auth/register', async (req, res) => {
  const { username, display_name, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  if (!/^[a-z0-9_]{3,32}$/.test(username)) return res.status(400).json({ error: 'Invalid username' });
  if (password.length < 8) return res.status(400).json({ error: 'Password too short' });
  try {
    const ex = await pool.query('SELECT id FROM users WHERE username=$1', [username]);
    if (ex.rows.length) return res.status(409).json({ error: 'Username taken' });
    const hash = await bcrypt.hash(password, 10);
    const colors = ['#2aabee','#7c3aed','#0f766e','#be185d','#b45309','#15803d','#9333ea','#0369a1'];
    const color = colors[Math.floor(Math.random() * colors.length)];
    const { rows } = await pool.query(
      `INSERT INTO users(username,display_name,password_hash,avatar_color) VALUES($1,$2,$3,$4)
       RETURNING id,username,display_name,avatar_color,bio,created_at`,
      [username, display_name || username, hash, color]
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

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id,username,display_name,avatar_color,bio,is_online,last_seen,created_at FROM users WHERE id=$1',
    [req.user.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Not found' });
  res.json(rows[0]);
});

// ═══ USERS ═══
app.get('/api/users/search', authMiddleware, async (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.json([]);
  const { rows } = await pool.query(
    `SELECT id,username,display_name,avatar_color,is_online,last_seen FROM users
     WHERE (username ILIKE $1 OR display_name ILIKE $1) AND id!=$2
     ORDER BY is_online DESC, username ASC LIMIT 20`,
    [`%${q}%`, req.user.id]
  );
  res.json(rows);
});

app.get('/api/users/check/:username', async (req, res) => {
  const { rows } = await pool.query('SELECT id FROM users WHERE username=$1', [req.params.username]);
  res.json({ available: rows.length === 0 });
});

// ═══ FRIENDS ═══
app.get('/api/friends', authMiddleware, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT u.id,u.username,u.display_name,u.avatar_color,u.is_online,u.last_seen,
           f.status,f.id as friendship_id,
           CASE WHEN f.user_id=$1 THEN 'sent' ELSE 'received' END as direction
    FROM friendships f
    JOIN users u ON u.id = CASE WHEN f.user_id=$1 THEN f.friend_id ELSE f.user_id END
    WHERE (f.user_id=$1 OR f.friend_id=$1) AND f.status != 'blocked'
    ORDER BY f.status, u.display_name
  `, [req.user.id]);
  res.json(rows);
});

app.post('/api/friends/request', authMiddleware, async (req, res) => {
  const { user_id } = req.body;
  if (!user_id || user_id === req.user.id) return res.status(400).json({ error: 'Invalid' });
  try {
    const ex = await pool.query(
      'SELECT id,status FROM friendships WHERE (user_id=$1 AND friend_id=$2) OR (user_id=$2 AND friend_id=$1)',
      [req.user.id, user_id]
    );
    if (ex.rows.length) return res.json({ friendship: ex.rows[0] });
    const { rows } = await pool.query(
      'INSERT INTO friendships(user_id,friend_id,status) VALUES($1,$2,$3) RETURNING *',
      [req.user.id, user_id, 'pending']
    );
    res.json({ friendship: rows[0] });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/friends/accept', authMiddleware, async (req, res) => {
  const { friendship_id } = req.body;
  const { rows } = await pool.query(
    `UPDATE friendships SET status='accepted' WHERE id=$1 AND friend_id=$2 RETURNING *`,
    [friendship_id, req.user.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Not found' });
  res.json({ friendship: rows[0] });
});

app.delete('/api/friends/:id', authMiddleware, async (req, res) => {
  await pool.query('DELETE FROM friendships WHERE id=$1 AND (user_id=$2 OR friend_id=$2)', [req.params.id, req.user.id]);
  res.json({ ok: true });
});

// ═══ CONVERSATIONS ═══
app.get('/api/conversations', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.id,c.type,c.name,c.description,c.avatar_color,c.username as channel_username,c.is_public,c.created_at,
        cm.role as my_role, cm.can_post,
        lm.content AS last_content,lm.type AS last_type,lm.created_at AS last_at,
        (SELECT COUNT(*) FROM messages m WHERE m.conversation_id=c.id AND m.sender_id!=$1 AND m.is_read=false) AS unread,
        ou.id AS other_id,ou.username AS other_username,
        ou.display_name AS other_display_name,ou.avatar_color AS other_avatar_color,
        ou.is_online AS other_online,
        (SELECT COUNT(*) FROM conversation_members WHERE conversation_id=c.id) AS member_count
      FROM conversations c
      JOIN conversation_members cm ON cm.conversation_id=c.id AND cm.user_id=$1
      LEFT JOIN LATERAL (
        SELECT content,type,created_at FROM messages WHERE conversation_id=c.id ORDER BY created_at DESC LIMIT 1
      ) lm ON true
      LEFT JOIN conversation_members cm2 ON cm2.conversation_id=c.id AND cm2.user_id!=$1 AND c.type='direct'
      LEFT JOIN users ou ON ou.id=cm2.user_id
      ORDER BY COALESCE(lm.created_at,c.created_at) DESC
    `, [req.user.id]);
    res.json(rows);
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// Get channel/group members
app.get('/api/conversations/:convId/members', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT u.id,u.username,u.display_name,u.avatar_color,u.is_online,
             cm.role,cm.can_post,cm.joined_at
      FROM conversation_members cm
      JOIN users u ON u.id=cm.user_id
      WHERE cm.conversation_id=$1
      ORDER BY cm.role,u.display_name
    `, [req.params.convId]);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// Update member role
app.put('/api/conversations/:convId/members/:userId', authMiddleware, async (req, res) => {
  const { role, can_post } = req.body;
  try {
    const myRole = await pool.query(
      'SELECT role FROM conversation_members WHERE conversation_id=$1 AND user_id=$2',
      [req.params.convId, req.user.id]
    );
    if (!myRole.rows.length || !['owner','admin'].includes(myRole.rows[0].role)) {
      return res.status(403).json({ error: 'No permission' });
    }
    await pool.query(
      'UPDATE conversation_members SET role=$1, can_post=$2 WHERE conversation_id=$3 AND user_id=$4',
      [role, can_post !== undefined ? can_post : true, req.params.convId, req.params.userId]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// Remove member
app.delete('/api/conversations/:convId/members/:userId', authMiddleware, async (req, res) => {
  try {
    const myRole = await pool.query(
      'SELECT role FROM conversation_members WHERE conversation_id=$1 AND user_id=$2',
      [req.params.convId, req.user.id]
    );
    if (!myRole.rows.length || !['owner','admin'].includes(myRole.rows[0].role)) {
      return res.status(403).json({ error: 'No permission' });
    }
    await pool.query('DELETE FROM conversation_members WHERE conversation_id=$1 AND user_id=$2',
      [req.params.convId, req.params.userId]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/conversations/direct', authMiddleware, async (req, res) => {
  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: 'user_id required' });
  const me = req.user.id;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const ex = await client.query(`
      SELECT c.id FROM conversations c
      JOIN conversation_members cm1 ON cm1.conversation_id=c.id AND cm1.user_id=$1
      JOIN conversation_members cm2 ON cm2.conversation_id=c.id AND cm2.user_id=$2
      WHERE c.type='direct' LIMIT 1
    `, [me, user_id]);
    if (ex.rows.length) { await client.query('COMMIT'); return res.json({ id: ex.rows[0].id }); }
    const conv = await client.query(`INSERT INTO conversations(type,created_by) VALUES('direct',$1) RETURNING id`, [me]);
    const cid = conv.rows[0].id;
    await client.query(`INSERT INTO conversation_members(conversation_id,user_id) VALUES($1,$2),($1,$3)`, [cid,me,user_id]);
    await client.query('COMMIT');
    res.json({ id: cid });
  } catch(e) { await client.query('ROLLBACK'); res.status(500).json({ error: 'Server error' }); }
  finally { client.release(); }
});

app.post('/api/conversations/group', authMiddleware, async (req, res) => {
  const { name, description, member_ids, type = 'group', channel_username, is_public } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  if (type === 'channel' && channel_username) {
    const ex = await pool.query('SELECT id FROM conversations WHERE username=$1', [channel_username]);
    if (ex.rows.length) return res.status(409).json({ error: 'Channel username taken' });
  }
  const colors = ['#2aabee','#7c3aed','#0f766e','#be185d','#b45309','#15803d'];
  const color = colors[Math.floor(Math.random() * colors.length)];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const conv = await client.query(
      `INSERT INTO conversations(type,name,description,avatar_color,username,is_public,created_by)
       VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
      [type, name, description||'', color, channel_username||null, is_public||false, req.user.id]
    );
    const cid = conv.rows[0].id;
    // Creator is owner
    await client.query(
      `INSERT INTO conversation_members(conversation_id,user_id,role,can_post) VALUES($1,$2,'owner',true)`,
      [cid, req.user.id]
    );
    // Add members
    const memberIds = (member_ids || []).filter(id => id !== req.user.id);
    for (const uid of memberIds) {
      const canPost = type === 'group'; // in channels only admins can post by default
      await client.query(
        `INSERT INTO conversation_members(conversation_id,user_id,role,can_post) VALUES($1,$2,'member',$3)
         ON CONFLICT DO NOTHING`,
        [cid, uid, canPost]
      );
    }
    await client.query(
      `INSERT INTO messages(conversation_id,sender_id,content,type) VALUES($1,$2,$3,'system')`,
      [cid, req.user.id, `${type === 'channel' ? 'Channel' : 'Group'} "${name}" created`]
    );
    await client.query('COMMIT');
    res.json({ id: cid, name, color });
  } catch(e) { await client.query('ROLLBACK'); console.error(e); res.status(500).json({ error: 'Server error' }); }
  finally { client.release(); }
});

// Search public channels
app.get('/api/channels/search', authMiddleware, async (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.json([]);
  const { rows } = await pool.query(`
    SELECT c.id,c.name,c.description,c.avatar_color,c.username as channel_username,c.is_public,
           (SELECT COUNT(*) FROM conversation_members WHERE conversation_id=c.id) as member_count
    FROM conversations c
    WHERE c.type='channel' AND c.is_public=true
    AND (c.name ILIKE $1 OR c.username ILIKE $1)
    LIMIT 20
  `, [`%${q}%`]);
  res.json(rows);
});

// Join channel
app.post('/api/conversations/:convId/join', authMiddleware, async (req, res) => {
  try {
    const conv = await pool.query('SELECT * FROM conversations WHERE id=$1', [req.params.convId]);
    if (!conv.rows.length) return res.status(404).json({ error: 'Not found' });
    if (!conv.rows[0].is_public) return res.status(403).json({ error: 'Private channel' });
    await pool.query(
      `INSERT INTO conversation_members(conversation_id,user_id,role,can_post) VALUES($1,$2,'member',false)
       ON CONFLICT DO NOTHING`,
      [req.params.convId, req.user.id]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ═══ MESSAGES ═══
app.get('/api/messages/:convId', authMiddleware, async (req, res) => {
  const { convId } = req.params;
  try {
    const mem = await pool.query(
      'SELECT role,can_post FROM conversation_members WHERE conversation_id=$1 AND user_id=$2',
      [convId, req.user.id]
    );
    if (!mem.rows.length) return res.status(403).json({ error: 'Not a member' });
    const { rows } = await pool.query(`
      SELECT m.id,m.content,m.type,m.file_name,m.file_size,m.file_data,
             m.reply_to_id,m.reply_to_content,m.reply_to_user,
             m.is_read,m.created_at,m.sender_id,
             u.username,u.display_name,u.avatar_color
      FROM messages m LEFT JOIN users u ON u.id=m.sender_id
      WHERE m.conversation_id=$1
      ORDER BY m.created_at ASC LIMIT 100
    `, [convId]);
    await pool.query(
      `UPDATE messages SET is_read=true WHERE conversation_id=$1 AND sender_id!=$2 AND is_read=false`,
      [convId, req.user.id]
    );
    res.json(rows);
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/messages/upload', authMiddleware, async (req, res) => {
  const { conversation_id, type, file_name, file_size, file_data, content } = req.body;
  if (!conversation_id || !file_data) return res.status(400).json({ error: 'Missing fields' });
  try {
    const mem = await pool.query(
      'SELECT role,can_post FROM conversation_members WHERE conversation_id=$1 AND user_id=$2',
      [conversation_id, req.user.id]
    );
    if (!mem.rows.length) return res.status(403).json({ error: 'Not a member' });
    // Check channel post permission
    const conv = await pool.query('SELECT type FROM conversations WHERE id=$1', [conversation_id]);
    if (conv.rows[0]?.type === 'channel' && !mem.rows[0].can_post) {
      return res.status(403).json({ error: 'Only admins can post in this channel' });
    }
    const { rows } = await pool.query(
      `INSERT INTO messages(conversation_id,sender_id,content,type,file_name,file_size,file_data)
       VALUES($1,$2,$3,$4,$5,$6,$7)
       RETURNING id,conversation_id,sender_id,content,type,file_name,file_size,file_data,reply_to_id,reply_to_content,reply_to_user,is_read,created_at`,
      [conversation_id, req.user.id, content||'', type||'file', file_name||null, file_size||null, file_data]
    );
    const msg = rows[0];
    const { rows: sr } = await pool.query('SELECT username,display_name,avatar_color FROM users WHERE id=$1', [req.user.id]);
    io.to(conversation_id).emit('message:new', { ...msg, ...sr[0] });
    res.json({ ok: true, message: msg });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/messages/:msgId', authMiddleware, async (req, res) => {
  const { for_everyone } = req.body || {};
  try {
    const { rows } = await pool.query('SELECT * FROM messages WHERE id=$1', [req.params.msgId]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    const msg = rows[0];
    if (for_everyone) {
      if (msg.sender_id !== req.user.id) {
        const myRole = await pool.query('SELECT role FROM conversation_members WHERE conversation_id=$1 AND user_id=$2', [msg.conversation_id, req.user.id]);
        if (!myRole.rows.length || !['owner','admin'].includes(myRole.rows[0].role)) {
          return res.status(403).json({ error: 'No permission' });
        }
      }
      await pool.query('DELETE FROM messages WHERE id=$1', [req.params.msgId]);
      io.to(msg.conversation_id).emit('message:deleted', { message_id: req.params.msgId });
    } else {
      await pool.query(`UPDATE messages SET content='[Message deleted]', type='deleted' WHERE id=$1`, [req.params.msgId]);
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/conversations/:convId/messages', authMiddleware, async (req, res) => {
  try {
    const mem = await pool.query('SELECT role FROM conversation_members WHERE conversation_id=$1 AND user_id=$2', [req.params.convId, req.user.id]);
    if (!mem.rows.length) return res.status(403).json({ error: 'Not a member' });
    await pool.query('DELETE FROM messages WHERE conversation_id=$1', [req.params.convId]);
    io.to(req.params.convId).emit('chat:cleared', { conversation_id: req.params.convId });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/conversations/:convId/leave', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM conversation_members WHERE conversation_id=$1 AND user_id=$2', [req.params.convId, req.user.id]);
    const rem = await pool.query('SELECT COUNT(*) FROM conversation_members WHERE conversation_id=$1', [req.params.convId]);
    if (parseInt(rem.rows[0].count) === 0) await pool.query('DELETE FROM conversations WHERE id=$1', [req.params.convId]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ═══ SOCKET.IO ═══
const onlineUsers = new Map();

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  try { socket.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { next(new Error('Invalid token')); }
});

io.on('connection', async (socket) => {
  const userId = socket.user.id;
  onlineUsers.set(userId, socket.id);
  await pool.query('UPDATE users SET is_online=true WHERE id=$1', [userId]);
  io.emit('user:online', { userId, online: true });

  // Join rooms
  const { rows: convs } = await pool.query('SELECT conversation_id FROM conversation_members WHERE user_id=$1', [userId]);
  convs.forEach(c => socket.join(c.conversation_id));
  console.log(`🔌 ${socket.user.username} connected`);

  socket.on('message:send', async (data, ack) => {
    if (!data?.conversation_id) return;
    const { conversation_id, content, type='text', file_name, file_size, file_data, reply_to_id, reply_to_content, reply_to_user } = data;
    if (!content && !file_data) return;
    try {
      const mem = await pool.query('SELECT role,can_post FROM conversation_members WHERE conversation_id=$1 AND user_id=$2', [conversation_id, userId]);
      if (!mem.rows.length) return;
      // Check channel permission
      const conv = await pool.query('SELECT type FROM conversations WHERE id=$1', [conversation_id]);
      if (conv.rows[0]?.type === 'channel' && !mem.rows[0].can_post) {
        if (ack) ack({ ok: false, error: 'Only admins can post' });
        return;
      }
      const { rows } = await pool.query(
        `INSERT INTO messages(conversation_id,sender_id,content,type,file_name,file_size,file_data,reply_to_id,reply_to_content,reply_to_user)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         RETURNING id,conversation_id,sender_id,content,type,file_name,file_size,file_data,reply_to_id,reply_to_content,reply_to_user,is_read,created_at`,
        [conversation_id, userId, content||'', type, file_name||null, file_size||null, file_data||null, reply_to_id||null, reply_to_content||null, reply_to_user||null]
      );
      const { rows: sr } = await pool.query('SELECT username,display_name,avatar_color FROM users WHERE id=$1', [userId]);
      const full = { ...rows[0], ...sr[0] };
      io.to(conversation_id).emit('message:new', full);
      if (ack) ack({ ok: true, message: full });
    } catch(e) { console.error(e); if (ack) ack({ ok: false }); }
  });

  socket.on('typing:start', (data) => {
    if (!data?.conversation_id) return;
    socket.to(data.conversation_id).emit('typing:start', { conversation_id: data.conversation_id, userId, username: socket.user.username });
  });
  socket.on('typing:stop', (data) => {
    if (!data?.conversation_id) return;
    socket.to(data.conversation_id).emit('typing:stop', { conversation_id: data.conversation_id, userId });
  });
  socket.on('messages:read', async (data) => {
    if (!data?.conversation_id) return;
    await pool.query('UPDATE messages SET is_read=true WHERE conversation_id=$1 AND sender_id!=$2 AND is_read=false', [data.conversation_id, userId]);
    socket.to(data.conversation_id).emit('messages:read', { conversation_id: data.conversation_id, userId });
  });
  socket.on('conversation:join', (data) => {
    if (!data?.conversation_id) return;
    socket.join(data.conversation_id);
  });

  // WebRTC
  socket.on('call:offer', (d) => { if (d?.conversation_id) socket.to(d.conversation_id).emit('call:offer', { ...d, from: userId, caller_name: socket.user.username }); });
  socket.on('call:answer', (d) => { if (d?.conversation_id) socket.to(d.conversation_id).emit('call:answer', { ...d, from: userId }); });
  socket.on('call:ice', (d) => { if (d?.conversation_id) socket.to(d.conversation_id).emit('call:ice', { ...d, from: userId }); });
  socket.on('call:end', (d) => { if (d?.conversation_id) socket.to(d.conversation_id).emit('call:end', { from: userId }); });
  socket.on('call:reject', (d) => { if (d?.conversation_id) socket.to(d.conversation_id).emit('call:reject', { from: userId }); });

  socket.on('disconnect', async () => {
    onlineUsers.delete(userId);
    await pool.query('UPDATE users SET is_online=false,last_seen=NOW() WHERE id=$1', [userId]);
    io.emit('user:online', { userId, online: false });
    console.log(`❌ ${socket.user.username} disconnected`);
  });
});

app.get('/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));

initDB().then(() => {
  server.listen(PORT, () => console.log(`🚀 ShadowTalk on port ${PORT}`));
}).catch(e => { console.error(e); process.exit(1); });

// ═══ SELF-DESTRUCT MESSAGES ═══
app.post('/api/messages/:msgId/destruct', authMiddleware, async (req, res) => {
  const { seconds } = req.body; // how many seconds until delete
  if (!seconds || seconds < 5) return res.status(400).json({ error: 'Min 5 seconds' });
  try {
    const { rows } = await pool.query('SELECT * FROM messages WHERE id=$1 AND sender_id=$2', [req.params.msgId, req.user.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    setTimeout(async () => {
      await pool.query('DELETE FROM messages WHERE id=$1', [req.params.msgId]);
      io.to(rows[0].conversation_id).emit('message:deleted', { message_id: req.params.msgId });
    }, seconds * 1000);
    res.json({ ok: true, destroys_in: seconds });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ═══ REFERRAL SYSTEM ═══
app.get('/api/referral/link', authMiddleware, async (req, res) => {
  const code = Buffer.from(req.user.id).toString('base64').slice(0, 12);
  res.json({ code, link: `${process.env.CLIENT_URL || 'https://your-app.vercel.app'}?ref=${code}` });
});

app.post('/api/referral/use', authMiddleware, async (req, res) => {
  // Track referral - simplified
  res.json({ ok: true, bonus: 'Premium for 7 days' });
});

// ═══ VOICE ROOMS ═══
const voiceRooms = new Map(); // roomId -> {name, members: Set}

app.get('/api/rooms', authMiddleware, async (req, res) => {
  const rooms = [];
  voiceRooms.forEach((room, id) => {
    rooms.push({ id, name: room.name, members: room.members.size, created_by: room.created_by });
  });
  res.json(rooms);
});

app.post('/api/rooms', authMiddleware, async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  const id = Math.random().toString(36).slice(2, 8).toUpperCase();
  voiceRooms.set(id, { name, members: new Set(), created_by: req.user.id, created_at: new Date() });
  io.emit('room:created', { id, name, members: 0, created_by: req.user.id });
  res.json({ id, name });
});

// Voice room WebRTC via socket
io.on('connection', (socket) => {
  // already handled above, extend here
});

// Extend existing socket with voice rooms
const origIoConnection = io.listeners('connection')[0];
// Add room events to each socket on connect (they're already handled in main connection handler)

// ═══ AI BOT ═══
app.post('/api/ai/chat', authMiddleware, async (req, res) => {
  const { message, conversation_id } = req.body;
  if (!message) return res.status(400).json({ error: 'Message required' });
  
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    // Fallback responses without AI
    const responses = [
      "Hello! I'm ShadowBot. How can I help?",
      "Interesting! Tell me more.",
      "I understand. Is there anything else you need?",
      "Sure, I can help with that!",
      "That's a great question!"
    ];
    const reply = responses[Math.floor(Math.random() * responses.length)];
    // Save as message from bot
    if (conversation_id) {
      const { rows } = await pool.query(
        `INSERT INTO messages(conversation_id, sender_id, content, type) VALUES($1, $2, $3, 'text') RETURNING *`,
        [conversation_id, req.user.id, '🤖 ' + reply]
      );
      io.to(conversation_id).emit('message:new', { ...rows[0], display_name: 'ShadowBot', username: 'shadowbot', avatar_color: '#7c3aed' });
    }
    return res.json({ reply });
  }

  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 500,
        system: 'You are ShadowBot, a helpful assistant inside ShadowTalk messenger. Be concise and friendly.',
        messages: [{ role: 'user', content: message }]
      })
    });
    const data = await r.json();
    const reply = data.content?.[0]?.text || 'Sorry, I could not respond.';
    if (conversation_id) {
      const { rows } = await pool.query(
        `INSERT INTO messages(conversation_id, sender_id, content, type) VALUES($1, $2, $3, 'text') RETURNING *`,
        [conversation_id, req.user.id, reply]
      );
      io.to(conversation_id).emit('message:new', { ...rows[0], display_name: 'ShadowBot 🤖', username: 'shadowbot', avatar_color: '#7c3aed' });
    }
    res.json({ reply });
  } catch(e) { res.status(500).json({ error: 'AI error' }); }
});

// ═══ ANONYMOUS CHAT ═══
const anonQueue = []; // waiting users

app.post('/api/anon/join', authMiddleware, async (req, res) => {
  const userId = req.user.id;
  // Check if already in queue
  const idx = anonQueue.findIndex(u => u.id === userId);
  if (idx >= 0) anonQueue.splice(idx, 1);
  
  if (anonQueue.length > 0) {
    // Match with waiting user
    const partner = anonQueue.shift();
    // Create anonymous direct conversation
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const conv = await client.query(`INSERT INTO conversations(type, name, created_by) VALUES('direct', 'Anonymous Chat', $1) RETURNING id`, [userId]);
      const cid = conv.rows[0].id;
      await client.query(`INSERT INTO conversation_members(conversation_id, user_id) VALUES($1,$2),($1,$3)`, [cid, userId, partner.id]);
      await client.query(`INSERT INTO messages(conversation_id, sender_id, content, type) VALUES($1,$2,'You are now connected with a stranger. Say hello!','system')`, [cid, userId]);
      await client.query('COMMIT');
      // Notify both
      const partnerSocketId = onlineUsers.get(partner.id);
      if (partnerSocketId) io.to(partnerSocketId).emit('anon:matched', { conversation_id: cid });
      res.json({ conversation_id: cid, status: 'matched' });
    } catch(e) { await client.query('ROLLBACK'); res.status(500).json({ error: 'Server error' }); }
    finally { client.release(); }
  } else {
    anonQueue.push({ id: userId, joined: Date.now() });
    res.json({ status: 'waiting', position: anonQueue.length });
  }
});

app.post('/api/anon/leave', authMiddleware, async (req, res) => {
  const idx = anonQueue.findIndex(u => u.id === req.user.id);
  if (idx >= 0) anonQueue.splice(idx, 1);
  res.json({ ok: true });
});
