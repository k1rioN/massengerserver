const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const SECRET = process.env.JWT_SECRET || 'replace_this_in_prod';
const DB_FILE = path.join(__dirname, 'database.db');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' }
});

app.use(cors());
app.use(express.json());

// init db
const db = new sqlite3.Database(DB_FILE);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users (id)
  )`);
});

// helper: get user by username
function getUserByUsername(username) {
  return new Promise((resolve, reject) => {
    db.get('SELECT id, username, password_hash FROM users WHERE username = ?', [username], (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function getUserById(id) {
  return new Promise((resolve, reject) => {
    db.get('SELECT id, username FROM users WHERE id = ?', [id], (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function insertUser(username, password_hash) {
  return new Promise((resolve, reject) => {
    db.run('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, password_hash], function(err) {
      if (err) reject(err);
      else resolve({ id: this.lastID, username });
    });
  });
}

function insertMessage(sender_id, content) {
  return new Promise((resolve, reject) => {
    db.run('INSERT INTO messages (sender_id, content) VALUES (?, ?)', [sender_id, content], function(err) {
      if (err) reject(err);
      else resolve({ id: this.lastID });
    });
  });
}

function getLastMessages(limit = 100) {
  return new Promise((resolve, reject) => {
    db.all(`SELECT m.id, m.sender_id, u.username as sender, m.content, m.timestamp
            FROM messages m
            LEFT JOIN users u ON u.id = m.sender_id
            ORDER BY m.id DESC
            LIMIT ?`, [limit], (err, rows) => {
      if (err) reject(err);
      else resolve(rows.reverse()); // chronological
    });
  });
}

// routes
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });

    const existing = await getUserByUsername(username);
    if (existing) return res.status(400).json({ error: 'user exists' });

    const hash = await bcrypt.hash(password, 10);
    const user = await insertUser(username, hash);
    res.json({ success: true, user: { id: user.id, username }});
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await getUserByUsername(username);
    if (!user) return res.status(400).json({ error: 'no such user' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'invalid credentials' });

    const token = jwt.sign({ id: user.id, username: user.username }, SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username }});
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

app.get('/messages', async (req, res) => {
  try {
    const msgs = await getLastMessages(200);
    res.json(msgs);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

app.get('/me', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'no token' });
  const token = auth.split(' ')[1];
  try {
    const data = jwt.verify(token, SECRET);
    res.json({ id: data.id, username: data.username });
  } catch (e) {
    res.status(401).json({ error: 'invalid token' });
  }
});

// socket auth on connection: client should send { token } in auth
io.use((socket, next) => {
  const token = socket.handshake.auth && socket.handshake.auth.token;
  if (!token) return next(new Error('no token'));
  try {
    const data = jwt.verify(token, SECRET);
    socket.user = { id: data.id, username: data.username };
    next();
  } catch (e) {
    next(new Error('invalid token'));
  }
});

io.on('connection', (socket) => {
  console.log('socket connected', socket.user && socket.user.username);

  // send existing messages to newly connected client (server also provides /messages)
  socket.on('send_message', async (payload) => {
    try {
      const content = String(payload.content || '').trim();
      if (!content) return;
      const sender_id = socket.user.id;
      await insertMessage(sender_id, content);
      const msg = {
        id: Date.now(),
        sender_id,
        sender: socket.user.username,
        content,
        timestamp: new Date().toISOString()
      };
      io.emit('message', msg);
    } catch (e) {
      console.error(e);
    }
  });

  socket.on('disconnect', () => {
    // console.log('disconnect', socket.user && socket.user.username);
  });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log('Server listening on', PORT));
