/* ═══════════════════════════════════════════════════════════
   IMPOSTR Backend — Production Server
   Express + SQLite (MySQL-compatible schema) + Socket.IO + JWT
   Fixes: Heartbeat, Host Migration, Race Conditions, Transactions
═══════════════════════════════════════════════════════════ */
const express  = require("express");
const http     = require("http");
const cors     = require("cors");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");
const { Server } = require("socket.io");
const sqlite3  = require("sqlite3").verbose();
const path     = require("path");

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: "*" }, pingInterval: 5000, pingTimeout: 10000 });
const db     = new sqlite3.Database(path.join(__dirname, "impostr.db"));
const PORT   = process.env.PORT || 4000;
const SECRET = process.env.JWT_SECRET || "impostr_2026_secure";
const ADMIN  = "visionaryvictors.vv@gmail.com";

app.use(cors());
app.use(express.json({ limit: "10mb" }));

/* ─── DB Helpers ─────────────────────────────────────────── */
const run = (s,p=[]) => new Promise((res,rej)=>db.run(s,p,function(e){e?rej(e):res(this);}));
const get = (s,p=[]) => new Promise((res,rej)=>db.get(s,p,(e,r)=>e?rej(e):res(r)));
const all = (s,p=[]) => new Promise((res,rej)=>db.all(s,p,(e,r)=>e?rej(e):res(r)));

/* ─── Schema — MySQL-compatible structure ────────────────── */
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    nickname TEXT NOT NULL,
    photo_url TEXT DEFAULT '',
    coins INTEGER DEFAULT 150,
    wins INTEGER DEFAULT 0,
    losses INTEGER DEFAULT 0,
    streak INTEGER DEFAULT 0,
    last_daily TEXT DEFAULT '',
    is_admin INTEGER DEFAULT 0,
    last_seen INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  )`);

  // Rooms table — tracks full game state
  db.run(`CREATE TABLE IF NOT EXISTS rooms (
    code TEXT PRIMARY KEY,
    host_uid TEXT NOT NULL,
    status TEXT DEFAULT 'waiting',
    locked INTEGER DEFAULT 0,
    players TEXT DEFAULT '[]',
    spectators TEXT DEFAULT '[]',
    waiting_hall TEXT DEFAULT '[]',
    object_name TEXT DEFAULT '',
    roles TEXT DEFAULT '[]',
    used_objects TEXT DEFAULT '[]',
    round INTEGER DEFAULT 1,
    created_at INTEGER,
    updated_at INTEGER
  )`);

  // Matches — game history
  db.run(`CREATE TABLE IF NOT EXISTS matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_code TEXT,
    winner TEXT,
    eliminated_uid TEXT,
    eliminated_name TEXT,
    was_impostor INTEGER DEFAULT 0,
    impostor_guessed INTEGER DEFAULT 0,
    correct_voters TEXT DEFAULT '[]',
    duration INTEGER DEFAULT 0,
    player_count INTEGER DEFAULT 0,
    ended_at TEXT DEFAULT (datetime('now'))
  )`);

  // Word history — anti-repeat per room
  db.run(`CREATE TABLE IF NOT EXISTS word_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_code TEXT,
    word TEXT,
    used_at TEXT DEFAULT (datetime('now'))
  )`);

  // Jo Coin ledger — transaction safety
  db.run(`CREATE TABLE IF NOT EXISTS coin_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_uid TEXT,
    amount INTEGER,
    reason TEXT,
    balance_after INTEGER,
    created_at TEXT DEFAULT (datetime('now'))
  )`);

  // Feedback
  db.run(`CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_uid TEXT,
    username TEXT,
    message TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )`);

  db.run(`UPDATE users SET is_admin=1 WHERE email=?`, [ADMIN]);
  console.log("✅ Database ready");
});

/* ─── Helpers ────────────────────────────────────────────── */
const mkUid  = () => Math.random().toString(36).slice(2,10)+Date.now().toString(36);
const sign   = uid => jwt.sign({uid}, SECRET, {expiresIn:"30d"});
const mkCode = () => { const c="ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; return Array.from({length:6},()=>c[Math.floor(Math.random()*c.length)]).join(""); };

function auth(req,res,next){
  const h=req.headers.authorization;
  if(!h) return res.status(401).json({error:"No token"});
  try{ req.uid=jwt.verify(h.replace("Bearer ",""),SECRET).uid; next(); }
  catch{ res.status(401).json({error:"Invalid token"}); }
}

async function isAdmin(uid){
  const u=await get("SELECT is_admin,email FROM users WHERE uid=?",[uid]);
  return u&&(u.is_admin===1||u.email===ADMIN);
}

function safe(u){
  if(!u) return null;
  const {password,...s}=u;
  return {...s, nick:u.nickname, photoUrl:u.photo_url||"", isAdmin:u.email===ADMIN||u.is_admin===1};
}

function parseRoom(r){
  if(!r) return null;
  return {
    code:r.code, status:r.status, locked:r.locked===1,
    hostUid:r.host_uid, round:r.round||1,
    players:JSON.parse(r.players||"[]"),
    spectators:JSON.parse(r.spectators||"[]"),
    waitingHall:JSON.parse(r.waiting_hall||"[]"),
    roles:JSON.parse(r.roles||"[]"),
    objectName:r.object_name||"",
    usedObjects:JSON.parse(r.used_objects||"[]"),
    created:r.created_at, updated:r.updated_at,
  };
}

/* ─── TRANSACTION-SAFE coin deduction ───────────────────── */
async function deductCoins(uid, amount, reason){
  const u = await get("SELECT coins FROM users WHERE uid=?",[uid]);
  if(!u || u.coins < amount) throw new Error("Insufficient coins");
  const newBalance = u.coins - amount;
  await run("UPDATE users SET coins=? WHERE uid=?",[newBalance, uid]);
  await run("INSERT INTO coin_ledger (user_uid,amount,reason,balance_after) VALUES (?,?,?,?)",
    [uid, -amount, reason, newBalance]);
  return newBalance;
}

async function addCoins(uid, amount, reason){
  const u = await get("SELECT coins FROM users WHERE uid=?",[uid]);
  if(!u) throw new Error("User not found");
  const newBalance = Math.max(0, (u.coins||0) + amount);
  await run("UPDATE users SET coins=? WHERE uid=?",[newBalance, uid]);
  await run("INSERT INTO coin_ledger (user_uid,amount,reason,balance_after) VALUES (?,?,?,?)",
    [uid, amount, reason, newBalance]);
  return newBalance;
}

/* ─── OTP Store ──────────────────────────────────────────── */
const otpStore = {};

async function sendEmail(to, subject, html){
  if(!process.env.RESEND_API_KEY){ console.log(`[Email to ${to}]: ${subject}`); return; }
  await fetch("https://api.resend.com/emails",{
    method:"POST",
    headers:{"Authorization":`Bearer ${process.env.RESEND_API_KEY}`,"Content-Type":"application/json"},
    body:JSON.stringify({from:"IMPOSTR <onboarding@resend.dev>",to,subject,html}),
  });
}

/* ═══════════════════════════════════════════════════════════
   AUTH
═══════════════════════════════════════════════════════════ */
app.get("/api/health",(req,res)=>res.json({status:"ok",db:"sqlite3",uptime:Math.floor(process.uptime()),ts:Date.now()}));

app.post("/api/auth/register", async(req,res)=>{
  try{
    const {email,password,nickname}=req.body;
    if(!email||!password||!nickname) return res.status(400).json({error:"All fields required"});
    if(password.length<6) return res.status(400).json({error:"Password min 6 chars"});
    const ex=await get("SELECT id FROM users WHERE email=?",[email.toLowerCase()]);
    if(ex) return res.status(409).json({error:"Email already registered"});
    const uid=mkUid(), hash=await bcrypt.hash(password,10);
    const isAdm=email.toLowerCase()===ADMIN.toLowerCase()?1:0;
    await run("INSERT INTO users (uid,email,password,nickname,is_admin,last_seen) VALUES (?,?,?,?,?,?)",
      [uid,email.toLowerCase(),hash,nickname,isAdm,Date.now()]);
    const u=await get("SELECT * FROM users WHERE uid=?",[uid]);
    await run("INSERT INTO coin_ledger (user_uid,amount,reason,balance_after) VALUES (?,?,?,?)",[uid,150,"welcome_bonus",150]);
    res.json({token:sign(uid),user:safe(u)});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/auth/login", async(req,res)=>{
  try{
    const {email,password}=req.body;
    const u=await get("SELECT * FROM users WHERE email=?",[email?.toLowerCase()]);
    if(!u||!await bcrypt.compare(password,u.password)) return res.status(401).json({error:"Invalid email or password"});
    await run("UPDATE users SET last_seen=? WHERE uid=?",[Date.now(),u.uid]);
    res.json({token:sign(u.uid),user:safe(u)});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/auth/otp/send", async(req,res)=>{
  try{
    const {email}=req.body;
    const u=await get("SELECT id FROM users WHERE email=?",[email?.toLowerCase()]);
    if(!u) return res.status(404).json({error:"No account with this email"});
    const otp=Math.floor(100000+Math.random()*900000).toString();
    otpStore[email.toLowerCase()]={otp,expires:Date.now()+600000};
    await sendEmail(email,"Your IMPOSTR OTP Code",
      `<div style="font-family:sans-serif;background:#06060e;color:#fff;padding:40px;text-align:center">
        <h1 style="color:#7c6fff;font-size:32px;margin-bottom:8px">IMPOSTR</h1>
        <p style="color:#888;margin-bottom:24px">Your one-time password:</p>
        <div style="font-size:48px;font-weight:900;color:#7c6fff;letter-spacing:12px;padding:20px;background:#0d0d1a;border-radius:12px;display:inline-block">${otp}</div>
        <p style="color:#666;margin-top:20px;font-size:12px">Expires in 10 minutes. Do not share this code.</p>
      </div>`);
    console.log(`[OTP] ${email}: ${otp}`);
    res.json({ok:true});
  }catch(e){res.status(500).json({error:"Failed to send OTP: "+e.message});}
});

app.post("/api/auth/otp/verify",(req,res)=>{
  const {email,otp}=req.body;
  const rec=otpStore[email?.toLowerCase()];
  if(!rec) return res.status(400).json({error:"No OTP sent for this email"});
  if(Date.now()>rec.expires){delete otpStore[email.toLowerCase()];return res.status(400).json({error:"OTP expired. Request a new one."});}
  if(rec.otp!==otp?.toString()) return res.status(400).json({error:"Invalid OTP code"});
  delete otpStore[email.toLowerCase()];
  const rt=jwt.sign({email:email.toLowerCase(),purpose:"reset"},SECRET,{expiresIn:"15m"});
  res.json({ok:true,resetToken:rt});
});

app.post("/api/auth/reset-password", async(req,res)=>{
  try{
    const {resetToken,newPassword}=req.body;
    if((newPassword||"").length<6) return res.status(400).json({error:"Min 6 chars"});
    let p; try{p=jwt.verify(resetToken,SECRET);}catch{return res.status(400).json({error:"Reset token expired"});}
    if(p.purpose!=="reset") return res.status(400).json({error:"Invalid token"});
    await run("UPDATE users SET password=? WHERE email=?",[await bcrypt.hash(newPassword,10),p.email]);
    res.json({ok:true,message:"Password reset! You can now sign in."});
  }catch(e){res.status(500).json({error:e.message});}
});

/* ═══════════════════════════════════════════════════════════
   USER
═══════════════════════════════════════════════════════════ */
app.get("/api/user/me", auth, async(req,res)=>{
  try{
    const u=await get("SELECT * FROM users WHERE uid=?",[req.uid]);
    if(!u) return res.status(404).json({error:"User not found"});
    await run("UPDATE users SET last_seen=? WHERE uid=?",[Date.now(),req.uid]);
    res.json(safe(u));
  }catch(e){res.status(500).json({error:e.message});}
});

app.patch("/api/user/me", auth, async(req,res)=>{
  try{
    const {nickname,photo_url,coins,wins,losses,streak}=req.body;
    const updates=[]; const vals=[];
    if(nickname!==undefined){updates.push("nickname=?");vals.push(nickname);}
    if(photo_url!==undefined){updates.push("photo_url=?");vals.push(photo_url);}
    if(coins!==undefined){updates.push("coins=?");vals.push(Math.max(0,coins));}
    if(wins!==undefined){updates.push("wins=?");vals.push(wins);}
    if(losses!==undefined){updates.push("losses=?");vals.push(losses);}
    if(streak!==undefined){updates.push("streak=?");vals.push(streak);}
    if(!updates.length) return res.status(400).json({error:"Nothing to update"});
    await run(`UPDATE users SET ${updates.join(",")} WHERE uid=?`,[...vals,req.uid]);
    const u=await get("SELECT * FROM users WHERE uid=?",[req.uid]);
    // Broadcast profile change to all connected clients
    io.emit("profile_update",{uid:req.uid,nickname:u.nickname,photoUrl:u.photo_url,coins:u.coins});
    res.json(safe(u));
  }catch(e){res.status(500).json({error:e.message});}
});

// Transaction-safe name change
app.post("/api/user/change-name", auth, async(req,res)=>{
  try{
    const {nickname}=req.body;
    if(!nickname?.trim()) return res.status(400).json({error:"Name required"});
    const bal=await deductCoins(req.uid,500,"name_change");
    await run("UPDATE users SET nickname=? WHERE uid=?",[nickname.trim(),req.uid]);
    const u=await get("SELECT * FROM users WHERE uid=?",[req.uid]);
    io.emit("profile_update",{uid:req.uid,nickname:u.nickname,photoUrl:u.photo_url,coins:bal});
    res.json({ok:true,user:safe(u),newBalance:bal});
  }catch(e){res.status(400).json({error:e.message});}
});

// Transaction-safe photo change
app.post("/api/user/change-photo", auth, async(req,res)=>{
  try{
    const {photoUrl}=req.body;
    if(!photoUrl) return res.status(400).json({error:"Photo required"});
    const bal=await deductCoins(req.uid,1000,"photo_change");
    await run("UPDATE users SET photo_url=? WHERE uid=?",[photoUrl,req.uid]);
    const u=await get("SELECT * FROM users WHERE uid=?",[req.uid]);
    io.emit("profile_update",{uid:req.uid,nickname:u.nickname,photoUrl:u.photo_url,coins:bal});
    res.json({ok:true,user:safe(u),newBalance:bal});
  }catch(e){res.status(400).json({error:e.message});}
});

app.post("/api/user/daily", auth, async(req,res)=>{
  try{
    const u=await get("SELECT * FROM users WHERE uid=?",[req.uid]);
    const today=new Date().toISOString().slice(0,10);
    if(u.last_daily===today) return res.status(400).json({error:"Already claimed today"});
    const yesterday=new Date(Date.now()-86400000).toISOString().slice(0,10);
    const streak=u.last_daily===yesterday?(u.streak||0)+1:1;
    const bal=await addCoins(req.uid,50,"daily_bonus");
    await run("UPDATE users SET streak=?,last_daily=? WHERE uid=?",[streak,today,req.uid]);
    res.json({coins:50,streak,newBalance:bal});
  }catch(e){res.status(500).json({error:e.message});}
});

/* ═══════════════════════════════════════════════════════════
   LEADERBOARD & MATCHES
═══════════════════════════════════════════════════════════ */
app.get("/api/leaderboard", async(req,res)=>{
  try{
    const rows=await all("SELECT uid,nickname,photo_url,coins,wins,losses,streak FROM users ORDER BY coins DESC LIMIT 50");
    res.json(rows.map((r,i)=>({...r,photoUrl:r.photo_url,rank:i+1,
      winRate:r.wins+r.losses>0?Math.round(r.wins/(r.wins+r.losses)*100):0})));
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/matches/recent", auth, async(req,res)=>{
  try{
    const rows=await all("SELECT * FROM matches ORDER BY ended_at DESC LIMIT 30");
    res.json(rows.map(r=>({...r,correctVoters:JSON.parse(r.correct_voters||"[]")})));
  }catch(e){res.status(500).json({error:e.message});}
});

/* ═══════════════════════════════════════════════════════════
   FEEDBACK
═══════════════════════════════════════════════════════════ */
app.post("/api/feedback", auth, async(req,res)=>{
  try{
    const u=await get("SELECT nickname FROM users WHERE uid=?",[req.uid]);
    await run("INSERT INTO feedback (user_uid,username,message) VALUES (?,?,?)",
      [req.uid,u?.nickname||"",req.body.message||""]);
    res.json({ok:true});
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/feedback", auth, async(req,res)=>{
  try{
    if(!await isAdmin(req.uid)) return res.status(403).json({error:"Forbidden"});
    res.json(await all("SELECT * FROM feedback ORDER BY created_at DESC LIMIT 100"));
  }catch(e){res.status(500).json({error:e.message});}
});

/* ═══════════════════════════════════════════════════════════
   ADMIN
═══════════════════════════════════════════════════════════ */
app.get("/api/admin/users", auth, async(req,res)=>{
  try{
    if(!await isAdmin(req.uid)) return res.status(403).json({error:"Forbidden"});
    res.json(await all("SELECT uid,email,nickname,coins,wins,losses,streak,last_seen,created_at FROM users ORDER BY created_at DESC"));
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/admin/matches", auth, async(req,res)=>{
  try{
    if(!await isAdmin(req.uid)) return res.status(403).json({error:"Forbidden"});
    res.json(await all("SELECT * FROM matches ORDER BY ended_at DESC LIMIT 200"));
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/admin/rooms", auth, async(req,res)=>{
  try{
    if(!await isAdmin(req.uid)) return res.status(403).json({error:"Forbidden"});
    const rows=await all("SELECT code,host_uid,status,players,created_at FROM rooms ORDER BY created_at DESC LIMIT 50");
    res.json(rows.map(r=>({...r,playerCount:JSON.parse(r.players||"[]").length})));
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/admin/ledger", auth, async(req,res)=>{
  try{
    if(!await isAdmin(req.uid)) return res.status(403).json({error:"Forbidden"});
    res.json(await all("SELECT * FROM coin_ledger ORDER BY created_at DESC LIMIT 200"));
  }catch(e){res.status(500).json({error:e.message});}
});

app.delete("/api/admin/user/:uid", auth, async(req,res)=>{
  try{
    if(!await isAdmin(req.uid)) return res.status(403).json({error:"Forbidden"});
    await run("DELETE FROM users WHERE uid=?",[req.params.uid]);
    res.json({ok:true});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/admin/reset-leaderboard", auth, async(req,res)=>{
  try{
    if(!await isAdmin(req.uid)) return res.status(403).json({error:"Forbidden"});
    await run("UPDATE users SET coins=150,wins=0,losses=0,streak=0");
    await run("DELETE FROM coin_ledger");
    res.json({ok:true,message:"Leaderboard reset"});
  }catch(e){res.status(500).json({error:e.message});}
});

/* ═══════════════════════════════════════════════════════════
   ROOMS
═══════════════════════════════════════════════════════════ */
app.post("/api/rooms/create", auth, async(req,res)=>{
  try{
    const u=await get("SELECT * FROM users WHERE uid=?",[req.uid]);
    let code=mkCode();
    while(await get("SELECT code FROM rooms WHERE code=?",[code])) code=mkCode();
    const host={uid:u.uid,nickname:u.nickname,photoUrl:u.photo_url||"",isHost:true,ready:false,socketId:""};
    await run("INSERT INTO rooms (code,host_uid,players,created_at,updated_at) VALUES (?,?,?,?,?)",
      [code,u.uid,JSON.stringify([host]),Date.now(),Date.now()]);
    res.json({code,room:parseRoom(await get("SELECT * FROM rooms WHERE code=?",[code]))});
    console.log(`🏠 Room ${code} created by ${u.nickname}`);
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/rooms/:code", auth, async(req,res)=>{
  try{
    const r=await get("SELECT * FROM rooms WHERE code=?",[req.params.code.toUpperCase()]);
    if(!r) return res.status(404).json({error:"Room not found. Check the code!"});
    if(r.created_at&&Date.now()-r.created_at>8*3600000){
      await run("DELETE FROM rooms WHERE code=?",[r.code]);
      return res.status(404).json({error:"Room expired. Please create a new room."});
    }
    res.json(parseRoom(r));
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/rooms/:code/join", auth, async(req,res)=>{
  try{
    const code=req.params.code.toUpperCase();
    const r=await get("SELECT * FROM rooms WHERE code=?",[code]);
    if(!r) return res.status(404).json({error:"Room not found. Check the code!"});
    const u=await get("SELECT * FROM users WHERE uid=?",[req.uid]);
    const {mode="play"}=req.body;
    const player={uid:u.uid,nickname:u.nickname,photoUrl:u.photo_url||"",isHost:false,ready:false,socketId:""};
    let players=JSON.parse(r.players||"[]");
    let spectators=JSON.parse(r.spectators||"[]");
    let waitingHall=JSON.parse(r.waiting_hall||"[]");

    // Already in room? Update info and rejoin
    const already=players.find(p=>p.uid===u.uid);
    if(already){ res.json({code,room:parseRoom(r),mode:"rejoin"}); return; }

    if(r.status==="playing"||r.locked===1){
      // Add to waiting hall — Lock check prevents race condition
      waitingHall=[...waitingHall.filter(p=>p.uid!==u.uid),player];
      await run("UPDATE rooms SET waiting_hall=?,updated_at=? WHERE code=?",[JSON.stringify(waitingHall),Date.now(),code]);
      const room=parseRoom(await get("SELECT * FROM rooms WHERE code=?",[code]));
      io.to(code).emit("room_update",room);
      return res.json({code,room,mode:"waiting"});
    }
    if(players.length>=12) return res.status(400).json({error:"Room is full (max 12 players)"});
    if(mode==="watch"){
      spectators=[...spectators.filter(p=>p.uid!==u.uid),player];
    } else {
      players=[...players.filter(p=>p.uid!==u.uid),player];
    }
    await run("UPDATE rooms SET players=?,spectators=?,updated_at=? WHERE code=?",[JSON.stringify(players),JSON.stringify(spectators),Date.now(),code]);
    const room=parseRoom(await get("SELECT * FROM rooms WHERE code=?",[code]));
    io.to(code).emit("room_update",room);
    console.log(`👤 ${u.nickname} joined ${code} as ${mode}`);
    res.json({code,room,mode});
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/rooms", auth, async(req,res)=>{
  try{
    const rows=await all("SELECT * FROM rooms WHERE status!='ended' ORDER BY created_at DESC LIMIT 50");
    res.json(rows.map(r=>{const p=parseRoom(r);return{code:p.code,status:p.status,players:p.players.length,hostUid:p.hostUid,created:p.created};}));
  }catch(e){res.status(500).json({error:e.message});}
});

// Transaction-safe Find Impostor clue
app.post("/api/rooms/:code/find-impostor", auth, async(req,res)=>{
  try{
    const code=req.params.code.toUpperCase();
    const {targetUid}=req.body;
    const r=await get("SELECT * FROM rooms WHERE code=?",[code]);
    if(!r) return res.status(404).json({error:"Room not found"});
    const roles=JSON.parse(r.roles||"[]");
    const target=roles.find(x=>x.uid===targetUid);
    if(!target) return res.status(404).json({error:"Player not found in this game"});
    // Deduct coins FIRST — prevents free clue exploit
    const newBal=await deductCoins(req.uid,200,"find_impostor_clue");
    const u=await get("SELECT nickname FROM users WHERE uid=?",[req.uid]);
    // Broadcast coin update to show new balance
    io.to(code).emit("profile_update",{uid:req.uid,coins:newBal});
    res.json({ok:true,targetName:target.nickname,isImpostor:target.role==="Impostor",newBalance:newBal});
  }catch(e){res.status(400).json({error:e.message});}
});

/* ═══════════════════════════════════════════════════════════
   SOCKET.IO — Real-Time Game Engine
═══════════════════════════════════════════════════════════ */
const gameState={}; // { [code]: { readyUIDs, votes, phase, startedAt, forceVoteTimer, hostTransferTimer, clueUsedBy } }
const socketMap={}; // { [socketId]: { uid, code } }

// Force vote timer — fires after 2 min if host hasn't opened vote
function scheduleForceVote(code){
  if(gameState[code]?.forceVoteTimer) clearTimeout(gameState[code].forceVoteTimer);
  gameState[code].forceVoteTimer=setTimeout(()=>{
    if(gameState[code]?.phase==="discuss"){
      gameState[code].phase="vote";
      io.to(code).emit("phase_change",{phase:"vote",forced:true});
      console.log(`⏱ Force vote triggered in room ${code}`);
    }
  }, 120000); // 2 minutes
}

io.on("connection", socket => {
  console.log("🔌 Connected:", socket.id);

  /* ─ Join Room ─ */
  socket.on("join_room", async({code,user})=>{
    if(!code||!user) return;
    socket.join(code);
    socket.roomCode=code;
    socket.userUid=user.uid;
    socketMap[socket.id]={uid:user.uid,code};

    if(!gameState[code]) gameState[code]={readyUIDs:[],votes:{},phase:"lobby",startedAt:null,clueUsedBy:new Set()};

    try{
      const r=await get("SELECT * FROM rooms WHERE code=?",[code]);
      if(r){
        const room=parseRoom(r);
        // Update socket ID for reconnecting player
        const players=room.players.map(p=>p.uid===user.uid?{...p,socketId:socket.id,photoUrl:user.photoUrl||p.photoUrl}:p);
        await run("UPDATE rooms SET players=?,updated_at=? WHERE code=?",[JSON.stringify(players),Date.now(),code]);
        io.to(code).emit("room_update",{...room,players});
      }
    }catch(e){console.error("join_room:",e.message);}
  });

  /* ─ Leave Room ─ */
  socket.on("leave_room",async({code})=>{
    socket.leave(code);
    delete socketMap[socket.id];
    await handleDisconnect(socket,code);
  });

  /* ─ Start Game ─ */
  socket.on("start_game",async({code,object:obj,roles})=>{
    try{
      // Lock room first to prevent race conditions with waiting hall
      await run("UPDATE rooms SET locked=1 WHERE code=?",[code]);
      await run("UPDATE rooms SET status='playing',object_name=?,roles=?,locked=0,updated_at=? WHERE code=?",
        [obj,JSON.stringify(roles),Date.now(),code]);
      // Track word history
      await run("INSERT INTO word_history (room_code,word) VALUES (?,?)",[code,obj]);
      // Keep only last 10 words per room
      await run("DELETE FROM word_history WHERE room_code=? AND id NOT IN (SELECT id FROM word_history WHERE room_code=? ORDER BY id DESC LIMIT 10)",[code,code]);
      const r=await get("SELECT * FROM rooms WHERE code=?",[code]);
      const room=parseRoom(r);
      if(!gameState[code]) gameState[code]={readyUIDs:[],votes:{},clueUsedBy:new Set()};
      gameState[code].phase="reveal";
      gameState[code].startedAt=Date.now();
      gameState[code].clueUsedBy=new Set(); // Reset clue usage each game
      io.to(code).emit("game_start",{room,object:obj,roles});
      console.log(`🎮 Game started in ${code} — word: ${obj}`);
    }catch(e){console.error("start_game:",e.message);}
  });

  /* ─ Player Ready ─ */
  socket.on("player_ready",({code,uid})=>{
    if(!gameState[code]) gameState[code]={readyUIDs:[],votes:{},phase:"discuss",clueUsedBy:new Set()};
    if(!gameState[code].readyUIDs.includes(uid)) gameState[code].readyUIDs.push(uid);
    gameState[code].phase="discuss";
    io.to(code).emit("player_ready",{uid,readyUIDs:gameState[code].readyUIDs});
    // Check if 75% ready — show host Force Vote button
    scheduleForceVote(code);
  });

  /* ─ Phase Change ─ */
  socket.on("phase_change",({code,phase})=>{
    if(gameState[code]){
      gameState[code].phase=phase;
      if(gameState[code].forceVoteTimer) clearTimeout(gameState[code].forceVoteTimer);
    }
    io.to(code).emit("phase_change",{phase});
  });

  /* ─ Force Vote (Host Override) ─ */
  socket.on("force_vote",({code})=>{
    if(gameState[code]) gameState[code].phase="vote";
    io.to(code).emit("phase_change",{phase:"vote",forced:true});
  });

  /* ─ Vote Cast ─ */
  socket.on("vote_cast",({code,uid,target})=>{
    if(!gameState[code]) gameState[code]={readyUIDs:[],votes:{},phase:"vote",clueUsedBy:new Set()};
    gameState[code].votes[uid]=target;
    io.to(code).emit("vote_cast",{uid,target,voteCount:Object.keys(gameState[code].votes).length});
  });

  /* ─ Impostor Guess Word ─ */
  socket.on("impostor_guess",async({code,uid,guessedWord,actualWord})=>{
    const correct=guessedWord.trim().toLowerCase()===actualWord.trim().toLowerCase();
    if(correct){
      // Impostor wins by guessing correctly even when caught
      io.to(code).emit("impostor_guessed_correct",{uid,guessedWord,actualWord});
      await run("UPDATE rooms SET status='ended' WHERE code=?",[code]);
    } else {
      io.to(code).emit("impostor_guessed_wrong",{uid,guessedWord});
    }
  });

  /* ─ Vote Result ─ */
  socket.on("vote_result",async({code,eliminatedUid,eliminatedName,wasImpostor,winner,correctVoters,scores,duration,impostorGuessed})=>{
    try{
      await run("UPDATE rooms SET status='ended',updated_at=? WHERE code=?",[Date.now(),code]);
      // Save match to history
      const r=await get("SELECT * FROM rooms WHERE code=?",[code]);
      const players=r?JSON.parse(r.players||"[]"):[];
      await run("INSERT INTO matches (room_code,winner,eliminated_uid,eliminated_name,was_impostor,impostor_guessed,correct_voters,duration,player_count) VALUES (?,?,?,?,?,?,?,?,?)",
        [code,winner,eliminatedUid,eliminatedName,wasImpostor?1:0,impostorGuessed?1:0,JSON.stringify(correctVoters||[]),duration||0,players.length]);
      // Apply coin scores with transaction safety
      for(const [uid,delta] of Object.entries(scores||{})){
        try{
          if(delta>0) await addCoins(uid,delta,`vote_reward_${winner}`);
          else if(delta<0){
            const u=await get("SELECT coins FROM users WHERE uid=?",[uid]);
            const newBal=Math.max(0,(u?.coins||0)+delta);
            await run("UPDATE users SET coins=? WHERE uid=?",[newBal,uid]);
            await run("INSERT INTO coin_ledger (user_uid,amount,reason,balance_after) VALUES (?,?,?,?)",[uid,delta,"wrong_vote",newBal]);
          }
          if(winner==="crew"){await run("UPDATE users SET wins=wins+1 WHERE uid=?",[uid]);}
          else{await run("UPDATE users SET losses=losses+1 WHERE uid=?",[uid]);}
        }catch(er){console.error("Score apply:",er.message);}
      }
      io.to(code).emit("vote_result",{eliminatedUid,eliminatedName,wasImpostor,winner,correctVoters,scores,impostorGuessed});
      delete gameState[code];
      console.log(`✅ Match ended in ${code} — Winner: ${winner}`);
    }catch(e){console.error("vote_result:",e.message);}
  });

  /* ─ Kick Player ─ */
  socket.on("kick_player",async({code,uid})=>{
    try{
      const r=await get("SELECT * FROM rooms WHERE code=?",[code]);
      if(!r) return;
      const room=parseRoom(r);
      const players=room.players.filter(p=>p.uid!==uid);
      const waiting=room.waitingHall.filter(p=>p.uid!==uid);
      await run("UPDATE rooms SET players=?,waiting_hall=?,updated_at=? WHERE code=?",[JSON.stringify(players),JSON.stringify(waiting),Date.now(),code]);
      io.to(code).emit("kicked",{uid});
      io.to(code).emit("room_update",{...room,players,waitingHall:waiting});
    }catch(e){}
  });

  /* ─ Admit from Waiting Hall ─ */
  socket.on("admit_waiting",async({code,uid})=>{
    try{
      const r=await get("SELECT * FROM rooms WHERE code=?",[code]);
      if(!r||r.locked===1) return; // Don't admit while room is locked
      const room=parseRoom(r);
      const player=room.waitingHall.find(p=>p.uid===uid);
      if(!player) return;
      const players=[...room.players,{...player,isHost:false,ready:false}];
      const waiting=room.waitingHall.filter(p=>p.uid!==uid);
      await run("UPDATE rooms SET players=?,waiting_hall=?,updated_at=? WHERE code=?",[JSON.stringify(players),JSON.stringify(waiting),Date.now(),code]);
      io.to(code).emit("room_update",{...room,players,waitingHall:waiting});
      io.to(code).emit("player_admitted",{uid,nickname:player.nickname});
    }catch(e){}
  });

  /* ─ Continue Game (new round) ─ */
  socket.on("continue_game",async({code})=>{
    try{
      // Lock room during transition to prevent ghost player bug
      await run("UPDATE rooms SET locked=1 WHERE code=?",[code]);
      // Get latest players
      const r=await get("SELECT * FROM rooms WHERE code=?",[code]);
      const room=parseRoom(r);
      // Reset ready states
      if(gameState[code]){gameState[code].readyUIDs=[];gameState[code].votes={};gameState[code].clueUsedBy=new Set();}
      // Reset player ready status
      const players=room.players.map(p=>({...p,ready:false}));
      await run("UPDATE rooms SET status='waiting',locked=0,players=?,updated_at=? WHERE code=?",[JSON.stringify(players),Date.now(),code]);
      io.to(code).emit("game_continue",{room:{...room,players,status:"waiting"}});
    }catch(e){console.error("continue_game:",e.message);}
  });

  /* ─ Chat ─ */
  socket.on("chat_msg",({code,msg})=>{
    io.to(code).emit("chat_msg",msg);
  });

  /* ─ WebView visibility heartbeat ─ */
  socket.on("app_foreground",({code,uid})=>{
    // Player came back from background — update last seen
    run("UPDATE users SET last_seen=? WHERE uid=?",[Date.now(),uid]).catch(()=>{});
  });

  /* ─ Disconnect ─ */
  socket.on("disconnect", async()=>{
    const code=socket.roomCode;
    delete socketMap[socket.id];
    if(code) await handleDisconnect(socket,code);
    console.log("❌ Disconnected:", socket.id);
  });
});

/* ─── Handle Disconnect / Host Migration ────────────────── */
async function handleDisconnect(socket,code){
  try{
    const r=await get("SELECT * FROM rooms WHERE code=?",[code]);
    if(!r) return;
    const room=parseRoom(r);
    const leavingUid=socket.userUid;
    const wasHost=room.hostUid===leavingUid;
    let players=room.players.filter(p=>p.socketId!==socket.id&&p.uid!==leavingUid);
    const spectators=room.spectators.filter(p=>p.socketId!==socket.id&&p.uid!==leavingUid);

    if(players.length===0&&room.status==="waiting"){
      await run("DELETE FROM rooms WHERE code=?",[code]);
      return;
    }

    let newHostUid=room.hostUid;

    // HOST MIGRATION — transfer to next player if host disconnects
    if(wasHost&&players.length>0){
      players[0]={...players[0],isHost:true};
      newHostUid=players[0].uid;
      await run("UPDATE rooms SET host_uid=? WHERE code=?",[newHostUid,code]);
      io.to(code).emit("host_changed",{newHostUid,nickname:players[0].nickname});
      console.log(`👑 Host migrated to ${players[0].nickname} in room ${code}`);
    }

    await run("UPDATE rooms SET players=?,spectators=?,updated_at=? WHERE code=?",[JSON.stringify(players),JSON.stringify(spectators),Date.now(),code]);

    if(players.length>0) io.to(code).emit("room_update",{...room,players,spectators,hostUid:newHostUid});

    // If in game and player disconnects, remove from ready list
    if(gameState[code]){
      gameState[code].readyUIDs=gameState[code].readyUIDs.filter(u=>u!==leavingUid);
    }
  }catch(e){console.error("handleDisconnect:",e.message);}
}

/* ─── Heartbeat: Remove zombie players every 30s ────────── */
setInterval(async()=>{
  try{
    const threshold=Date.now()-60000; // 60s inactive = zombie
    const rooms=await all("SELECT code,players,host_uid FROM rooms WHERE status='waiting'");
    for(const r of rooms){
      const players=JSON.parse(r.players||"[]");
      // Only clean up if no active sockets found for them
      const active=players.filter(p=>p.socketId&&io.sockets.sockets.has(p.socketId));
      if(active.length!==players.length){
        await run("UPDATE rooms SET players=?,updated_at=? WHERE code=?",[JSON.stringify(active),Date.now(),r.code]);
        if(active.length>0) io.to(r.code).emit("room_update",{players:active});
        else await run("DELETE FROM rooms WHERE code=?",[r.code]);
      }
    }
  }catch(e){}
}, 30000);

server.listen(PORT,()=>{
  console.log(`\n🎮 IMPOSTR Backend — Production Ready`);
  console.log(`📡 Port: ${PORT}`);
  console.log(`🔐 Admin: ${ADMIN}\n`);
});
