/* ═══════════════════════════════════════════════════════════
   VoidCrew Backend — server.js
   Express + sqlite3 + Socket.IO + JWT + Nodemailer OTP
   Run: node server.js
═══════════════════════════════════════════════════════════ */
const express    = require("express");
const http       = require("http");
const cors       = require("cors");
const bcrypt     = require("bcryptjs");
const jwt        = require("jsonwebtoken");
const { Server } = require("socket.io");
const sqlite3    = require("sqlite3").verbose();
const path       = require("path");

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: "*" } });
const db     = new sqlite3.Database(path.join(__dirname, "voidcrew.db"));

const PORT   = process.env.PORT || 4000;
const SECRET = process.env.JWT_SECRET || "voidcrew_secret_change_in_prod";

/* ─── Resend Email ───────────────────────────────────────── */

/* ─── OTP Store (in-memory) ──────────────────────────────── */
const otpStore = {}; // { email: { otp, expires } }

/* ─── Middleware ─────────────────────────────────────────── */
app.use(cors());
app.use(express.json());

/* ─── Promisify DB ───────────────────────────────────────── */
const run = (sql, p=[]) => new Promise((res,rej) => db.run(sql,p, function(e){ e?rej(e):res(this); }));
const get = (sql, p=[]) => new Promise((res,rej) => db.get(sql,p, (e,r)=> e?rej(e):res(r)));
const all = (sql, p=[]) => new Promise((res,rej) => db.all(sql,p, (e,r)=> e?rej(e):res(r)));

/* ─── Database Setup ─────────────────────────────────────── */
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    nickname TEXT NOT NULL,
    avatar TEXT DEFAULT '🧑‍🚀',
    logo TEXT DEFAULT 'star',
    banner TEXT DEFAULT 'stars',
    theme TEXT DEFAULT 'void',
    xp INTEGER DEFAULT 0,
    coins INTEGER DEFAULT 150,
    level INTEGER DEFAULT 1,
    wins INTEGER DEFAULT 0,
    losses INTEGER DEFAULT 0,
    kills INTEGER DEFAULT 0,
    tasks_done INTEGER DEFAULT 0,
    clan TEXT,
    status TEXT DEFAULT 'online',
    daily_streak INTEGER DEFAULT 0,
    last_daily TEXT,
    owned_logos TEXT DEFAULT '["star"]',
    owned_themes TEXT DEFAULT '["void"]',
    owned_banners TEXT DEFAULT '["stars"]',
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT UNIQUE NOT NULL,
    host_uid TEXT NOT NULL,
    total_players INTEGER DEFAULT 8,
    map TEXT DEFAULT 'station',
    winner TEXT,
    duration INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    finished_at TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS chat (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room TEXT DEFAULT 'global',
    user_uid TEXT NOT NULL,
    nickname TEXT NOT NULL,
    avatar TEXT DEFAULT '🧑‍🚀',
    message TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS friends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_uid TEXT NOT NULL,
    friend_uid TEXT NOT NULL,
    UNIQUE(user_uid, friend_uid)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_uid TEXT NOT NULL,
    reported_uid TEXT NOT NULL,
    reason TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  console.log("✅ Database ready");
});

/* ─── Helpers ────────────────────────────────────────────── */
function makeUid() { return Math.random().toString(36).slice(2,10) + Date.now().toString(36); }
function signToken(uid) { return jwt.sign({ uid }, SECRET, { expiresIn: "30d" }); }
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: "No token" });
  try { req.uid = jwt.verify(h.replace("Bearer ",""), SECRET).uid; next(); }
  catch { res.status(401).json({ error: "Invalid token" }); }
}
function fmtUser(u) {
  if (!u) return null;
  const { password, ...safe } = u;
  return {
    ...safe,
    nick: u.nickname,
    owned_logos:   JSON.parse(u.owned_logos   || '["star"]'),
    owned_themes:  JSON.parse(u.owned_themes  || '["void"]'),
    owned_banners: JSON.parse(u.owned_banners || '["stars"]'),
  };
}

async function sendOtpEmail(email, otp) {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${process.env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: "VoidCrew <onboarding@resend.dev>",
      to: email,
      subject: "Your VoidCrew OTP Code",
      html: `
        <div style="background:#050508;padding:40px;font-family:sans-serif;color:#fff;text-align:center;border-radius:12px;">
          <div style="font-size:48px;margin-bottom:16px;">🛸</div>
          <h1 style="color:#00f5ff;font-size:28px;letter-spacing:4px;margin-bottom:8px;">VOIDCREW</h1>
          <p style="color:#aaa;margin-bottom:32px;">Your one-time password</p>
          <div style="background:#0a0a1a;border:2px solid #00f5ff44;border-radius:12px;padding:24px;margin-bottom:24px;">
            <div style="font-size:48px;font-weight:bold;letter-spacing:12px;color:#00f5ff;">${otp}</div>
          </div>
          <p style="color:#aaa;font-size:13px;">This code expires in <strong style="color:#fff;">10 minutes</strong>.</p>
          <p style="color:#555;font-size:11px;margin-top:24px;">If you didn't request this, ignore this email.</p>
        </div>
      `,
    }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.message || "Resend API error");
  }
}

/* ═══════════════════════════════════════════════════════════
   ROUTES
═══════════════════════════════════════════════════════════ */

/* Health */
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", db: "sqlite3", uptime: Math.floor(process.uptime()) });
});

/* Register */
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, nickname } = req.body;
    if (!email || !password || !nickname)
      return res.status(400).json({ error: "Email, password and nickname required" });
    if (password.length < 6)
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    const exists = await get("SELECT id FROM users WHERE email=?", [email.toLowerCase()]);
    if (exists) return res.status(409).json({ error: "Email already registered" });

    const uid  = makeUid();
    const hash = await bcrypt.hash(password, 10);
    await run("INSERT INTO users (uid,email,password,nickname) VALUES (?,?,?,?)",
      [uid, email.toLowerCase(), hash, nickname]);
    const user = await get("SELECT * FROM users WHERE uid=?", [uid]);
    res.json({ token: signToken(uid), user: fmtUser(user), isNew: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* Login */
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const u = await get("SELECT * FROM users WHERE email=?", [email?.toLowerCase()]);
    if (!u) return res.status(401).json({ error: "Invalid email or password" });
    if (!await bcrypt.compare(password, u.password))
      return res.status(401).json({ error: "Invalid email or password" });
    res.json({ token: signToken(u.uid), user: fmtUser(u), isNew: false });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* OAuth / Guest */
app.post("/api/auth/oauth", async (req, res) => {
  try {
    const { email, nickname, avatar } = req.body;
    let u = await get("SELECT * FROM users WHERE email=?", [email]);
    if (!u) {
      const uid  = makeUid();
      const hash = await bcrypt.hash(makeUid(), 10);
      await run("INSERT INTO users (uid,email,password,nickname,avatar) VALUES (?,?,?,?,?)",
        [uid, email, hash, nickname || email.split("@")[0], avatar || "🧑‍🚀"]);
      u = await get("SELECT * FROM users WHERE uid=?", [uid]);
    }
    res.json({ token: signToken(u.uid), user: fmtUser(u), isNew: false });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* ─── OTP: Send ──────────────────────────────────────────── */
app.post("/api/auth/otp/send", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email required" });

    const user = await get("SELECT id FROM users WHERE email=?", [email.toLowerCase()]);
    if (!user) return res.status(404).json({ error: "No account found with this email" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[email.toLowerCase()] = { otp, expires: Date.now() + 10 * 60 * 1000 };

    await sendOtpEmail(email, otp);
    console.log(`[OTP] Sent to ${email}`);
    res.json({ ok: true });
  } catch(e) {
    console.error("[OTP] Error:", e.message);
    res.status(500).json({ error: "Failed to send OTP email. Check server email config." });
  }
});

/* ─── OTP: Verify ────────────────────────────────────────── */
app.post("/api/auth/otp/verify", (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: "Email and OTP required" });

  const record = otpStore[email.toLowerCase()];
  if (!record) return res.status(400).json({ error: "No OTP sent for this email" });
  if (Date.now() > record.expires) {
    delete otpStore[email.toLowerCase()];
    return res.status(400).json({ error: "OTP expired. Please request a new one." });
  }
  if (record.otp !== otp.toString()) return res.status(400).json({ error: "Invalid OTP code" });

  // OTP valid — issue a reset token
  delete otpStore[email.toLowerCase()];
  const resetToken = jwt.sign({ email: email.toLowerCase(), purpose: "reset" }, SECRET, { expiresIn: "15m" });
  res.json({ ok: true, resetToken });
});

/* ─── Password Reset ─────────────────────────────────────── */
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;
    if (!resetToken || !newPassword) return res.status(400).json({ error: "Missing fields" });
    if (newPassword.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });

    let payload;
    try { payload = jwt.verify(resetToken, SECRET); }
    catch { return res.status(400).json({ error: "Reset token expired or invalid" }); }

    if (payload.purpose !== "reset") return res.status(400).json({ error: "Invalid token" });

    const hash = await bcrypt.hash(newPassword, 10);
    await run("UPDATE users SET password=? WHERE email=?", [hash, payload.email]);
    res.json({ ok: true, message: "Password reset successfully! You can now sign in." });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* Get Me */
app.get("/api/user/me", auth, async (req, res) => {
  try {
    const u = await get("SELECT * FROM users WHERE uid=?", [req.uid]);
    if (!u) return res.status(404).json({ error: "Not found" });
    res.json(fmtUser(u));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* Update Me */
app.patch("/api/user/me", auth, async (req, res) => {
  try {
    const allowed = ["nickname","avatar","logo","banner","theme","status","clan",
                     "owned_logos","owned_themes","owned_banners","coins","xp","level"];
    const fields  = Object.keys(req.body).filter(k => allowed.includes(k));
    if (!fields.length) return res.status(400).json({ error: "Nothing to update" });
    const sets = fields.map(f => `${f}=?`).join(",");
    const vals = fields.map(f => Array.isArray(req.body[f]) ? JSON.stringify(req.body[f]) : req.body[f]);
    await run(`UPDATE users SET ${sets} WHERE uid=?`, [...vals, req.uid]);
    const u = await get("SELECT * FROM users WHERE uid=?", [req.uid]);
    res.json(fmtUser(u));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* Daily Reward */
app.post("/api/user/daily", auth, async (req, res) => {
  try {
    const u     = await get("SELECT * FROM users WHERE uid=?", [req.uid]);
    const today = new Date().toISOString().slice(0,10);
    if (u.last_daily === today)
      return res.status(400).json({ error: "Already claimed today" });
    const yesterday = new Date(Date.now()-86400000).toISOString().slice(0,10);
    const streak    = u.last_daily === yesterday ? (u.daily_streak||0)+1 : 1;
    const coins     = 50 + Math.min(streak-1,6)*10;
    const xp        = 20 + streak*5;
    await run("UPDATE users SET coins=coins+?,xp=xp+?,daily_streak=?,last_daily=? WHERE uid=?",
      [coins, xp, streak, today, req.uid]);
    const updated = await get("SELECT * FROM users WHERE uid=?", [req.uid]);
    res.json({ coins, xp, streak, user: fmtUser(updated) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* Unlock Cosmetic */
app.post("/api/cosmetics/unlock", auth, async (req, res) => {
  try {
    const { type, id, cost } = req.body;
    const u    = await get("SELECT * FROM users WHERE uid=?", [req.uid]);
    if (u.coins < cost) return res.status(400).json({ error: "Not enough coins" });
    const col   = `owned_${type}s`;
    const owned = JSON.parse(u[col] || "[]");
    if (owned.includes(id)) return res.status(400).json({ error: "Already owned" });
    owned.push(id);
    await run(`UPDATE users SET ${col}=?,coins=coins-? WHERE uid=?`,
      [JSON.stringify(owned), cost, req.uid]);
    const updated = await get("SELECT * FROM users WHERE uid=?", [req.uid]);
    res.json({ ok: true, user: fmtUser(updated) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* Create Match */
app.post("/api/matches/create", auth, async (req, res) => {
  try {
    const uid = makeUid();
    const { totalPlayers=8, map="station" } = req.body;
    await run("INSERT INTO matches (uid,host_uid,total_players,map) VALUES (?,?,?,?)",
      [uid, req.uid, totalPlayers, map]);
    res.json({ matchUid: uid });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* Finish Match */
app.post("/api/matches/:uid/finish", auth, async (req, res) => {
  try {
    const { winner, duration=0, xpGained=0, coinsGained=0, kills=0, tasks=0, won=false } = req.body;
    await run("UPDATE matches SET winner=?,duration=?,finished_at=datetime('now') WHERE uid=?",
      [winner, duration, req.params.uid]);
    await run("UPDATE users SET xp=xp+?,coins=coins+?,kills=kills+?,tasks_done=tasks_done+?,wins=wins+?,losses=losses+? WHERE uid=?",
      [xpGained, coinsGained, kills, tasks, won?1:0, won?0:1, req.uid]);
    const u = await get("SELECT * FROM users WHERE uid=?", [req.uid]);
    res.json({ ok: true, user: fmtUser(u) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* Leaderboard */
app.get("/api/leaderboard", async (req, res) => {
  try {
    const rows = await all(
      "SELECT uid,nickname,avatar,logo,banner,xp,wins,kills,clan FROM users ORDER BY xp DESC LIMIT 50"
    );
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* Stats */
app.get("/api/stats/:uid", auth, async (req, res) => {
  try {
    const u = await get(
      "SELECT uid,nickname,avatar,logo,xp,wins,losses,kills,tasks_done,daily_streak,clan FROM users WHERE uid=?",
      [req.params.uid]
    );
    if (!u) return res.status(404).json({ error: "Not found" });
    const matches = await all(
      "SELECT * FROM matches WHERE host_uid=? ORDER BY created_at DESC LIMIT 20",
      [req.params.uid]
    );
    const total = u.wins + u.losses;
    res.json({ ...u, matches, winRate: total>0 ? Math.round(u.wins/total*100) : 0 });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* Send Chat */
app.post("/api/chat", auth, async (req, res) => {
  try {
    const u = await get("SELECT * FROM users WHERE uid=?", [req.uid]);
    const { message, room="global" } = req.body;
    if (!message?.trim()) return res.status(400).json({ error: "Empty message" });
    const msg = {
      uid: makeUid(), user_uid: req.uid, nickname: u.nickname,
      avatar: u.avatar, message: message.trim(), room,
      created_at: new Date().toISOString()
    };
    await run("INSERT INTO chat (room,user_uid,nickname,avatar,message) VALUES (?,?,?,?,?)",
      [room, req.uid, u.nickname, u.avatar, message.trim()]);
    io.to(room).emit("chat", msg);
    res.json(msg);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* Get Chat */
app.get("/api/chat", auth, async (req, res) => {
  try {
    const room = req.query.room || "global";
    const msgs = await all(
      "SELECT * FROM chat WHERE room=? ORDER BY created_at DESC LIMIT 50", [room]
    );
    res.json(msgs.reverse());
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* Friends */
app.post("/api/social/friend/:uid", auth, async (req, res) => {
  try {
    await run("INSERT OR IGNORE INTO friends (user_uid,friend_uid) VALUES (?,?)", [req.uid, req.params.uid]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get("/api/social/friends", auth, async (req, res) => {
  try {
    const rows = await all(`
      SELECT u.uid,u.nickname,u.avatar,u.xp,u.status,u.logo
      FROM users u INNER JOIN friends f ON f.friend_uid=u.uid
      WHERE f.user_uid=?`, [req.uid]);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/social/follow/:uid", auth, async (req, res) => {
  try {
    await run("INSERT OR IGNORE INTO friends (user_uid,friend_uid) VALUES (?,?)", [req.uid, req.params.uid]);
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Failed" }); }
});

app.post("/api/social/report", auth, async (req, res) => {
  try {
    const { reported_uid, reason } = req.body;
    await run("INSERT INTO reports (reporter_uid,reported_uid,reason) VALUES (?,?,?)",
      [req.uid, reported_uid, reason||""]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════════════════════════════════════════════════════
   ROOM MANAGEMENT API (DB-backed so rooms survive restarts)
═══════════════════════════════════════════════════════════ */
const gameRooms = {}; // in-memory cache for socket events

function makeRoomCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

// Setup rooms table
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS rooms (
    code TEXT PRIMARY KEY,
    host_uid TEXT NOT NULL,
    host_nickname TEXT,
    host_avatar TEXT,
    map TEXT DEFAULT 'station',
    status TEXT DEFAULT 'waiting',
    players TEXT DEFAULT '[]',
    spectators TEXT DEFAULT '[]',
    created_at INTEGER
  )`);
});

function parseRoom(r) {
  if (!r) return null;
  return {
    code: r.code, map: r.map, status: r.status, created: r.created_at,
    host: { uid: r.host_uid, nickname: r.host_nickname, avatar: r.host_avatar },
    players: JSON.parse(r.players || '[]'),
    spectators: JSON.parse(r.spectators || '[]'),
  };
}

// Create room
app.post("/api/rooms/create", auth, async (req, res) => {
  try {
    const u = await get("SELECT * FROM users WHERE uid=?", [req.uid]);
    let code = makeRoomCode();
    while (await get("SELECT code FROM rooms WHERE code=?", [code])) code = makeRoomCode();
    const { map = "station" } = req.body;
    const hostPlayer = { uid: u.uid, nickname: u.nickname, avatar: u.avatar, ready: true, isHost: true };
    await run(
      "INSERT INTO rooms (code, host_uid, host_nickname, host_avatar, map, status, players, spectators, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
      [code, u.uid, u.nickname, u.avatar, map, "waiting", JSON.stringify([hostPlayer]), "[]", Date.now()]
    );
    const room = parseRoom(await get("SELECT * FROM rooms WHERE code=?", [code]));
    gameRooms[code] = room;
    console.log(`🏠 Room created: ${code} by ${u.nickname}`);
    res.json({ code, room });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Get room info
app.get("/api/rooms/:code", auth, async (req, res) => {
  try {
    const code = req.params.code.toUpperCase();
    const r = await get("SELECT * FROM rooms WHERE code=?", [code]);
    if (!r) return res.status(404).json({ error: "Room not found. Check the code!" });
    // Clean up old rooms (older than 4 hours)
    if (r.created_at && Date.now() - r.created_at > 4 * 60 * 60 * 1000) {
      await run("DELETE FROM rooms WHERE code=?", [code]);
      return res.status(404).json({ error: "Room expired. Create a new one!" });
    }
    res.json(parseRoom(r));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Join room
app.post("/api/rooms/:code/join", auth, async (req, res) => {
  try {
    const code = req.params.code.toUpperCase();
    const r = await get("SELECT * FROM rooms WHERE code=?", [code]);
    if (!r) return res.status(404).json({ error: "Room not found. Check the code!" });
    if (r.status !== "waiting") return res.status(400).json({ error: "Game already started!" });
    const players = JSON.parse(r.players || "[]");
    const spectators = JSON.parse(r.spectators || "[]");
    if (players.length >= 12) return res.status(400).json({ error: "Room is full!" });
    const u = await get("SELECT * FROM users WHERE uid=?", [req.uid]);
    const { mode = "play" } = req.body;
    const player = { uid: u.uid, nickname: u.nickname, avatar: u.avatar, ready: false, isHost: false };
    let newPlayers = players, newSpectators = spectators;
    if (mode === "watch") {
      newSpectators = [...spectators.filter(s => s.uid !== u.uid), player];
    } else {
      newPlayers = [...players.filter(p => p.uid !== u.uid), player];
    }
    await run("UPDATE rooms SET players=?, spectators=? WHERE code=?",
      [JSON.stringify(newPlayers), JSON.stringify(newSpectators), code]);
    const room = parseRoom(await get("SELECT * FROM rooms WHERE code=?", [code]));
    gameRooms[code] = room;
    io.to(code).emit("room_update", room);
    console.log(`👤 ${u.nickname} joined room ${code} as ${mode}`);
    res.json({ code, room, mode });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// List active rooms (admin)
app.get("/api/rooms", auth, async (req, res) => {
  try {
    const rows = await all("SELECT * FROM rooms WHERE status != 'ended' ORDER BY created_at DESC LIMIT 50");
    res.json(rows.map(r => {
      const p = parseRoom(r);
      return { code: p.code, map: p.map, status: p.status, players: p.players.length, spectators: p.spectators.length, host: p.host?.nickname, created: p.created };
    }));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════════════════════════════════════════════════════
   SOCKET.IO
═══════════════════════════════════════════════════════════ */
io.on("connection", (socket) => {
  console.log("🔌 Player connected:", socket.id);

  socket.on("join_room", async ({ code, user }) => {
    const room = code?.toUpperCase();
    socket.join(room);
    socket.currentRoom = room;
    socket.currentUid = user?.uid;
    try {
      // Load from DB if not cached
      if (!gameRooms[room]) {
        const r = await get("SELECT * FROM rooms WHERE code=?", [room]);
        if (r) gameRooms[room] = parseRoom(r);
      }
      if (gameRooms[room]) {
        const p = gameRooms[room].players.find(p => p.uid === user?.uid);
        if (p) p.socketId = socket.id;
        io.to(room).emit("room_update", gameRooms[room]);
      }
    } catch(e) {}
  });

  socket.on("leave_room", ({ code }) => {
    const room = code?.toUpperCase();
    socket.leave(room);
    if (gameRooms[room]) {
      gameRooms[room].players = gameRooms[room].players.filter(p => p.socketId !== socket.id);
      gameRooms[room].spectators = gameRooms[room].spectators.filter(p => p.socketId !== socket.id);
      if (gameRooms[room].players.length === 0) {
        delete gameRooms[room];
        console.log(`🗑️ Room ${room} deleted (empty)`);
      } else {
        io.to(room).emit("room_update", gameRooms[room]);
      }
    }
  });

  socket.on("player_ready", ({ code, uid, ready }) => {
    const room = code?.toUpperCase();
    if (gameRooms[room]) {
      const p = gameRooms[room].players.find(p => p.uid === uid);
      if (p) p.ready = ready;
      io.to(room).emit("room_update", gameRooms[room]);
    }
  });

  socket.on("start_game", async ({ code, map }) => {
    const room = code?.toUpperCase();
    try {
      await run("UPDATE rooms SET status='playing', map=? WHERE code=?", [map || "station", room]);
      const r = parseRoom(await get("SELECT * FROM rooms WHERE code=?", [room]));
      if (r) {
        gameRooms[room] = r;
        io.to(room).emit("game_start", { room: r });
        console.log(`🎮 Game started in room ${room}`);
      }
    } catch(e) { console.error("start_game error:", e.message); }
  });

  socket.on("game_event", ({ code, room, event, data }) => {
    const r = (code || room)?.toUpperCase();
    socket.to(r).emit("game_event", { event, data });
  });

  socket.on("chat_msg", ({ code, room, msg }) => {
    const r = (code || room)?.toUpperCase();
    io.to(r).emit("chat", msg);
  });

  socket.on("kick_player", async ({ code, uid }) => {
    const room = code?.toUpperCase();
    try {
      const r = await get("SELECT * FROM rooms WHERE code=?", [room]);
      if (r) {
        const players = JSON.parse(r.players || "[]").filter(p => p.uid !== uid);
        await run("UPDATE rooms SET players=? WHERE code=?", [JSON.stringify(players), room]);
        const updated = parseRoom(await get("SELECT * FROM rooms WHERE code=?", [room]));
        gameRooms[room] = updated;
        io.to(room).emit("room_update", updated);
        io.to(room).emit("kicked", { uid });
      }
    } catch(e) {}
  });

  socket.on("disconnect", () => {
    Object.keys(gameRooms).forEach(code => {
      const room = gameRooms[code];
      if (!room) return;
      const wasPlayer = room.players.some(p => p.socketId === socket.id);
      room.players = room.players.filter(p => p.socketId !== socket.id);
      room.spectators = room.spectators.filter(p => p.socketId !== socket.id);
      if (room.players.length === 0) {
        delete gameRooms[code];
      } else if (wasPlayer) {
        io.to(code).emit("room_update", gameRooms[code]);
      }
    });
    console.log("❌ Player disconnected:", socket.id);
  });
});

/* ─── Start ──────────────────────────────────────────────── */
server.listen(PORT, () => {
  console.log(`\n🛸 VoidCrew Backend is RUNNING!`);
  console.log(`📡 API:    http://localhost:${PORT}/api/health`);
  console.log(`🔌 Socket: ws://localhost:${PORT}`);
  console.log(`\n✅ Ready for players!\n`);
});
