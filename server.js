/* ═══════════════════════════════════════════════════════════
   IMPOSTR Backend — server.js
   Express + SQLite + Socket.IO + JWT + Resend Email
   Render-compatible (SQLite acts as MySQL replacement)
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
const io     = new Server(server, { cors: { origin: "*" } });
const db     = new sqlite3.Database(path.join(__dirname, "impostr.db"));
const PORT   = process.env.PORT || 4000;
const SECRET = process.env.JWT_SECRET || "impostr_secret_2026";
const ADMIN_EMAIL = "visionaryvictors.vv@gmail.com";

app.use(cors());
app.use(express.json({ limit: "10mb" }));

/* ─── DB Helpers ─────────────────────────────────────────── */
const run = (s,p=[]) => new Promise((res,rej)=>db.run(s,p,function(e){e?rej(e):res(this);}));
const get = (s,p=[]) => new Promise((res,rej)=>db.get(s,p,(e,r)=>e?rej(e):res(r)));
const all = (s,p=[]) => new Promise((res,rej)=>db.all(s,p,(e,r)=>e?rej(e):res(r)));

/* ─── Schema ─────────────────────────────────────────────── */
db.serialize(() => {
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
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS rooms (
    code TEXT PRIMARY KEY,
    host_uid TEXT NOT NULL,
    status TEXT DEFAULT 'waiting',
    players TEXT DEFAULT '[]',
    spectators TEXT DEFAULT '[]',
    waiting_hall TEXT DEFAULT '[]',
    object_name TEXT DEFAULT '',
    roles TEXT DEFAULT '[]',
    created_at INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_code TEXT,
    winner TEXT,
    eliminated_uid TEXT,
    eliminated_name TEXT,
    was_impostor INTEGER DEFAULT 0,
    correct_voters TEXT DEFAULT '[]',
    duration INTEGER DEFAULT 0,
    player_count INTEGER DEFAULT 0,
    started_at TEXT,
    ended_at TEXT DEFAULT (datetime('now'))
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_uid TEXT,
    username TEXT,
    message TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  // Ensure admin user flag
  db.run(`UPDATE users SET is_admin=1 WHERE email=?`, [ADMIN_EMAIL]);
  console.log("✅ Database ready");
});

/* ─── Helpers ────────────────────────────────────────────── */
const uid = () => Math.random().toString(36).slice(2,10) + Date.now().toString(36);
const sign = (id) => jwt.sign({uid:id}, SECRET, {expiresIn:"30d"});
function auth(req,res,next){
  const h = req.headers.authorization;
  if(!h) return res.status(401).json({error:"No token"});
  try{ req.uid = jwt.verify(h.replace("Bearer ",""),SECRET).uid; next(); }
  catch{ res.status(401).json({error:"Invalid token"}); }
}
function safe(u){
  if(!u) return null;
  const {password,...s} = u;
  return {...s, nick:u.nickname, isAdmin: u.is_admin===1||u.email===ADMIN_EMAIL };
}
function makeCode(){
  const c="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  return Array.from({length:6},()=>c[Math.floor(Math.random()*c.length)]).join("");
}
function parseRoom(r){
  if(!r) return null;
  return {
    code:r.code, status:r.status, created:r.created_at,
    hostUid:r.host_uid,
    players:JSON.parse(r.players||"[]"),
    spectators:JSON.parse(r.spectators||"[]"),
    waitingHall:JSON.parse(r.waiting_hall||"[]"),
    objectName:r.object_name||"",
    roles:JSON.parse(r.roles||"[]"),
  };
}

/* ─── Resend Email ───────────────────────────────────────── */
const otpStore = {};
async function sendEmail(to, subject, html){
  if(!process.env.RESEND_API_KEY) return console.log("[Email] No key, skipping.");
  await fetch("https://api.resend.com/emails",{
    method:"POST",
    headers:{"Authorization":`Bearer ${process.env.RESEND_API_KEY}`,"Content-Type":"application/json"},
    body:JSON.stringify({from:"IMPOSTR <onboarding@resend.dev>",to,subject,html}),
  });
}

/* ═══════════════════════════════════════════════════════════
   AUTH ROUTES
═══════════════════════════════════════════════════════════ */
app.get("/api/health",(req,res)=>res.json({status:"ok",db:"sqlite3",uptime:Math.floor(process.uptime())}));

app.post("/api/auth/register", async(req,res)=>{
  try{
    const {email,password,nickname}=req.body;
    if(!email||!password||!nickname) return res.status(400).json({error:"All fields required"});
    if(password.length<6) return res.status(400).json({error:"Password min 6 chars"});
    const exists=await get("SELECT id FROM users WHERE email=?",[email.toLowerCase()]);
    if(exists) return res.status(409).json({error:"Email already registered"});
    const id=uid(), hash=await bcrypt.hash(password,10);
    const isAdmin=email.toLowerCase()===ADMIN_EMAIL.toLowerCase()?1:0;
    await run("INSERT INTO users (uid,email,password,nickname,is_admin) VALUES (?,?,?,?,?)",[id,email.toLowerCase(),hash,nickname,isAdmin]);
    const u=await get("SELECT * FROM users WHERE uid=?",[id]);
    res.json({token:sign(id),user:safe(u)});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/auth/login", async(req,res)=>{
  try{
    const {email,password}=req.body;
    const u=await get("SELECT * FROM users WHERE email=?",[email?.toLowerCase()]);
    if(!u||!await bcrypt.compare(password,u.password)) return res.status(401).json({error:"Invalid email or password"});
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
    await sendEmail(email,"Your IMPOSTR OTP",`<div style="font-family:sans-serif;text-align:center;padding:40px;background:#08080f;color:#fff"><h1 style="color:#6c63ff">IMPOSTR</h1><p>Your OTP:</p><div style="font-size:48px;font-weight:bold;color:#6c63ff;letter-spacing:12px">${otp}</div><p style="color:#888">Expires in 10 minutes</p></div>`);
    console.log(`[OTP] ${email}: ${otp}`);
    res.json({ok:true});
  }catch(e){res.status(500).json({error:"Failed to send OTP: "+e.message});}
});

app.post("/api/auth/otp/verify",(req,res)=>{
  const {email,otp}=req.body;
  const rec=otpStore[email?.toLowerCase()];
  if(!rec) return res.status(400).json({error:"No OTP sent"});
  if(Date.now()>rec.expires){delete otpStore[email.toLowerCase()];return res.status(400).json({error:"OTP expired"});}
  if(rec.otp!==otp?.toString()) return res.status(400).json({error:"Invalid OTP"});
  delete otpStore[email.toLowerCase()];
  const rt=jwt.sign({email:email.toLowerCase(),purpose:"reset"},SECRET,{expiresIn:"15m"});
  res.json({ok:true,resetToken:rt});
});

app.post("/api/auth/reset-password", async(req,res)=>{
  try{
    const {resetToken,newPassword}=req.body;
    if(newPassword?.length<6) return res.status(400).json({error:"Min 6 chars"});
    let p; try{p=jwt.verify(resetToken,SECRET);}catch{return res.status(400).json({error:"Token expired"});}
    if(p.purpose!=="reset") return res.status(400).json({error:"Invalid token"});
    const hash=await bcrypt.hash(newPassword,10);
    await run("UPDATE users SET password=? WHERE email=?",[hash,p.email]);
    res.json({ok:true});
  }catch(e){res.status(500).json({error:e.message});}
});

/* ═══════════════════════════════════════════════════════════
   USER ROUTES
═══════════════════════════════════════════════════════════ */
app.get("/api/user/me", auth, async(req,res)=>{
  try{
    const u=await get("SELECT * FROM users WHERE uid=?",[req.uid]);
    if(!u) return res.status(404).json({error:"Not found"});
    res.json(safe(u));
  }catch(e){res.status(500).json({error:e.message});}
});

app.patch("/api/user/me", auth, async(req,res)=>{
  try{
    const allowed=["nickname","photo_url","coins","wins","losses","streak"];
    const fields=Object.keys(req.body).filter(k=>allowed.includes(k));
    if(!fields.length) return res.status(400).json({error:"Nothing to update"});
    const sets=fields.map(f=>`${f}=?`).join(",");
    const vals=fields.map(f=>req.body[f]);
    await run(`UPDATE users SET ${sets} WHERE uid=?`,[...vals,req.uid]);
    const u=await get("SELECT * FROM users WHERE uid=?",[req.uid]);
    // Broadcast profile update to all sockets
    io.emit("profile_update",{uid:req.uid,nickname:u.nickname,photoUrl:u.photo_url,coins:u.coins});
    res.json(safe(u));
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/user/daily", auth, async(req,res)=>{
  try{
    const u=await get("SELECT * FROM users WHERE uid=?",[req.uid]);
    const today=new Date().toISOString().slice(0,10);
    if(u.last_daily===today) return res.status(400).json({error:"Already claimed"});
    const yesterday=new Date(Date.now()-86400000).toISOString().slice(0,10);
    const streak=u.last_daily===yesterday?(u.streak||0)+1:1;
    const coins=50;
    await run("UPDATE users SET coins=coins+?,streak=?,last_daily=? WHERE uid=?",[coins,streak,today,req.uid]);
    res.json({coins,streak});
  }catch(e){res.status(500).json({error:e.message});}
});

/* ═══════════════════════════════════════════════════════════
   LEADERBOARD
═══════════════════════════════════════════════════════════ */
app.get("/api/leaderboard", async(req,res)=>{
  try{
    const rows=await all("SELECT uid,nickname,photo_url,coins,wins,losses FROM users ORDER BY coins DESC LIMIT 50");
    res.json(rows.map(r=>({...r,photoUrl:r.photo_url,winRate:r.wins+r.losses>0?Math.round(r.wins/(r.wins+r.losses)*100):0})));
  }catch(e){res.status(500).json({error:e.message});}
});

/* ═══════════════════════════════════════════════════════════
   MATCHES
═══════════════════════════════════════════════════════════ */
app.get("/api/matches/recent", auth, async(req,res)=>{
  try{
    const rows=await all("SELECT * FROM matches ORDER BY ended_at DESC LIMIT 20");
    res.json(rows.map(r=>({...r,correctVoters:JSON.parse(r.correct_voters||"[]")})));
  }catch(e){res.status(500).json({error:e.message});}
});

/* ═══════════════════════════════════════════════════════════
   FEEDBACK
═══════════════════════════════════════════════════════════ */
app.post("/api/feedback", auth, async(req,res)=>{
  try{
    const u=await get("SELECT nickname FROM users WHERE uid=?",[req.uid]);
    await run("INSERT INTO feedback (user_uid,username,message) VALUES (?,?,?)",[req.uid,u?.nickname||"",req.body.message||""]);
    res.json({ok:true});
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/feedback", auth, async(req,res)=>{
  try{
    const u=await get("SELECT is_admin,email FROM users WHERE uid=?",[req.uid]);
    if(!u?.is_admin&&u?.email!==ADMIN_EMAIL) return res.status(403).json({error:"Forbidden"});
    const rows=await all("SELECT * FROM feedback ORDER BY created_at DESC LIMIT 100");
    res.json(rows);
  }catch(e){res.status(500).json({error:e.message});}
});

/* ═══════════════════════════════════════════════════════════
   ADMIN ROUTES
═══════════════════════════════════════════════════════════ */
app.get("/api/admin/users", auth, async(req,res)=>{
  try{
    const me=await get("SELECT is_admin,email FROM users WHERE uid=?",[req.uid]);
    if(!me?.is_admin&&me?.email!==ADMIN_EMAIL) return res.status(403).json({error:"Forbidden"});
    const rows=await all("SELECT uid,email,nickname,coins,wins,losses,streak,created_at FROM users ORDER BY created_at DESC");
    res.json(rows);
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/admin/rooms", auth, async(req,res)=>{
  try{
    const me=await get("SELECT is_admin,email FROM users WHERE uid=?",[req.uid]);
    if(!me?.is_admin&&me?.email!==ADMIN_EMAIL) return res.status(403).json({error:"Forbidden"});
    const rows=await all("SELECT code,status,players,host_uid,created_at FROM rooms ORDER BY created_at DESC LIMIT 50");
    res.json(rows.map(r=>({...r,playerCount:JSON.parse(r.players||"[]").length})));
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/admin/matches", auth, async(req,res)=>{
  try{
    const me=await get("SELECT is_admin,email FROM users WHERE uid=?",[req.uid]);
    if(!me?.is_admin&&me?.email!==ADMIN_EMAIL) return res.status(403).json({error:"Forbidden"});
    const rows=await all("SELECT * FROM matches ORDER BY ended_at DESC LIMIT 100");
    res.json(rows);
  }catch(e){res.status(500).json({error:e.message});}
});

app.delete("/api/admin/user/:uid", auth, async(req,res)=>{
  try{
    const me=await get("SELECT is_admin,email FROM users WHERE uid=?",[req.uid]);
    if(!me?.is_admin&&me?.email!==ADMIN_EMAIL) return res.status(403).json({error:"Forbidden"});
    await run("DELETE FROM users WHERE uid=?",[req.params.uid]);
    res.json({ok:true});
  }catch(e){res.status(500).json({error:e.message});}
});

/* ═══════════════════════════════════════════════════════════
   ROOM ROUTES
═══════════════════════════════════════════════════════════ */
app.post("/api/rooms/create", auth, async(req,res)=>{
  try{
    const u=await get("SELECT * FROM users WHERE uid=?",[req.uid]);
    let code=makeCode();
    while(await get("SELECT code FROM rooms WHERE code=?",[code])) code=makeCode();
    const host={uid:u.uid,nickname:u.nickname,photoUrl:u.photo_url||"",isHost:true,ready:false};
    await run("INSERT INTO rooms (code,host_uid,players,created_at) VALUES (?,?,?,?)",
      [code,u.uid,JSON.stringify([host]),Date.now()]);
    const room=parseRoom(await get("SELECT * FROM rooms WHERE code=?",[code]));
    console.log(`🏠 Room ${code} created by ${u.nickname}`);
    res.json({code,room});
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/rooms/:code", auth, async(req,res)=>{
  try{
    const r=await get("SELECT * FROM rooms WHERE code=?",[req.params.code.toUpperCase()]);
    if(!r) return res.status(404).json({error:"Room not found"});
    if(r.created_at&&Date.now()-r.created_at>6*60*60*1000){
      await run("DELETE FROM rooms WHERE code=?",[r.code]);
      return res.status(404).json({error:"Room expired"});
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
    const player={uid:u.uid,nickname:u.nickname,photoUrl:u.photo_url||"",isHost:false,ready:false};
    let players=JSON.parse(r.players||"[]");
    let spectators=JSON.parse(r.spectators||"[]");
    let waitingHall=JSON.parse(r.waiting_hall||"[]");
    if(r.status==="playing"){
      // Game in progress — add to waiting hall
      waitingHall=[...waitingHall.filter(p=>p.uid!==u.uid),player];
      await run("UPDATE rooms SET waiting_hall=? WHERE code=?",[JSON.stringify(waitingHall),code]);
      const room=parseRoom(await get("SELECT * FROM rooms WHERE code=?",[code]));
      io.to(code).emit("room_update",room);
      return res.json({code,room,mode:"waiting"});
    }
    if(players.length>=12) return res.status(400).json({error:"Room is full!"});
    if(mode==="watch"){
      spectators=[...spectators.filter(p=>p.uid!==u.uid),player];
    } else {
      players=[...players.filter(p=>p.uid!==u.uid),player];
    }
    await run("UPDATE rooms SET players=?,spectators=? WHERE code=?",[JSON.stringify(players),JSON.stringify(spectators),code]);
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

/* ═══════════════════════════════════════════════════════════
   SOCKET.IO — Real-Time Game Engine
═══════════════════════════════════════════════════════════ */
const gameState = {}; // in-memory game state per room

io.on("connection", socket => {
  console.log("🔌 Connected:", socket.id);

  socket.on("join_room", async({code,user})=>{
    if(!code) return;
    socket.join(code);
    socket.roomCode=code;
    socket.userUid=user?.uid;
    try{
      if(!gameState[code]) gameState[code]={readyPlayers:[],votes:{},phase:"lobby"};
      const r=await get("SELECT * FROM rooms WHERE code=?",[code]);
      if(r){
        const room=parseRoom(r);
        // Update socketId for player
        const players=room.players.map(p=>p.uid===user?.uid?{...p,socketId:socket.id}:p);
        await run("UPDATE rooms SET players=? WHERE code=?",[JSON.stringify(players),code]);
        io.to(code).emit("room_update",{...room,players});
      }
    }catch(e){console.error("join_room error:",e.message);}
  });

  socket.on("leave_room",async({code})=>{
    socket.leave(code);
    try{
      const r=await get("SELECT * FROM rooms WHERE code=?",[code]);
      if(r){
        const room=parseRoom(r);
        const players=room.players.filter(p=>p.socketId!==socket.id);
        const spectators=room.spectators.filter(p=>p.socketId!==socket.id);
        if(players.length===0){await run("DELETE FROM rooms WHERE code=?",[code]);}
        else{
          await run("UPDATE rooms SET players=?,spectators=? WHERE code=?",[JSON.stringify(players),JSON.stringify(spectators),code]);
          io.to(code).emit("room_update",{...room,players,spectators});
        }
      }
    }catch(e){}
  });

  socket.on("start_game",async({code,object:obj,roles})=>{
    try{
      await run("UPDATE rooms SET status='playing',object_name=?,roles=? WHERE code=?",[obj,JSON.stringify(roles),code]);
      const r=await get("SELECT * FROM rooms WHERE code=?",[code]);
      const room=parseRoom(r);
      gameState[code]={readyPlayers:[],votes:{},phase:"reveal",startedAt:Date.now()};
      io.to(code).emit("game_start",{room,object:obj,roles});
      console.log(`🎮 Game started in ${code} — object: ${obj}`);
    }catch(e){console.error("start_game:",e.message);}
  });

  socket.on("player_ready",({code,uid})=>{
    if(!gameState[code]) gameState[code]={readyPlayers:[],votes:{},phase:"discuss"};
    if(!gameState[code].readyPlayers.includes(uid)) gameState[code].readyPlayers.push(uid);
    io.to(code).emit("player_ready",{uid,readyCount:gameState[code].readyPlayers.length});
  });

  socket.on("phase_change",({code,phase})=>{
    if(gameState[code]) gameState[code].phase=phase;
    io.to(code).emit("phase_change",{phase});
  });

  socket.on("vote_cast",({code,uid,target})=>{
    if(!gameState[code]) gameState[code]={readyPlayers:[],votes:{},phase:"vote"};
    gameState[code].votes[uid]=target;
    io.to(code).emit("vote_cast",{uid,target,voteCount:Object.keys(gameState[code].votes).length});
  });

  socket.on("vote_result",async({code,eliminatedUid,eliminatedName,wasImpostor,winner,correctVoters,scores,duration})=>{
    try{
      await run("UPDATE rooms SET status='ended' WHERE code=?",[code]);
      await run("INSERT INTO matches (room_code,winner,eliminated_uid,eliminated_name,was_impostor,correct_voters,duration,player_count,started_at) VALUES (?,?,?,?,?,?,?,?,datetime('now'))",
        [code,winner,eliminatedUid,eliminatedName,wasImpostor?1:0,JSON.stringify(correctVoters||[]),duration||0,Object.keys(scores||{}).length]);
      // Update user coins
      for(const [uid,delta] of Object.entries(scores||{})){
        await run("UPDATE users SET coins=MAX(0,coins+?),wins=wins+? WHERE uid=?",[delta,delta>0?1:0,uid]);
      }
      io.to(code).emit("vote_result",{eliminatedUid,eliminatedName,wasImpostor,winner,correctVoters,scores});
      delete gameState[code];
    }catch(e){console.error("vote_result:",e.message);}
  });

  socket.on("kick_player",async({code,uid})=>{
    try{
      const r=await get("SELECT * FROM rooms WHERE code=?",[code]);
      if(!r) return;
      const room=parseRoom(r);
      const players=room.players.filter(p=>p.uid!==uid);
      await run("UPDATE rooms SET players=? WHERE code=?",[JSON.stringify(players),code]);
      io.to(code).emit("kicked",{uid});
      io.to(code).emit("room_update",{...room,players});
    }catch(e){}
  });

  socket.on("admit_from_waiting",async({code,uid})=>{
    try{
      const r=await get("SELECT * FROM rooms WHERE code=?",[code]);
      if(!r) return;
      const room=parseRoom(r);
      const player=room.waitingHall.find(p=>p.uid===uid);
      if(!player) return;
      const players=[...room.players,{...player,isHost:false,ready:false}];
      const waiting=room.waitingHall.filter(p=>p.uid!==uid);
      await run("UPDATE rooms SET players=?,waiting_hall=? WHERE code=?",[JSON.stringify(players),JSON.stringify(waiting),code]);
      io.to(code).emit("room_update",{...room,players,waitingHall:waiting});
      io.to(code).emit("player_admitted",{uid});
    }catch(e){}
  });

  socket.on("chat_msg",({code,msg})=>{
    io.to(code).emit("chat_msg",msg);
  });

  socket.on("disconnect",async()=>{
    const code=socket.roomCode;
    if(!code) return;
    try{
      const r=await get("SELECT * FROM rooms WHERE code=?",[code]);
      if(!r) return;
      const room=parseRoom(r);
      const players=room.players.filter(p=>p.socketId!==socket.id);
      const spectators=room.spectators.filter(p=>p.socketId!==socket.id);
      if(players.length===0&&room.status==="waiting"){
        await run("DELETE FROM rooms WHERE code=?",[code]);
      } else {
        await run("UPDATE rooms SET players=?,spectators=? WHERE code=?",[JSON.stringify(players),JSON.stringify(spectators),code]);
        io.to(code).emit("room_update",{...room,players,spectators});
      }
    }catch(e){}
    console.log("❌ Disconnected:",socket.id);
  });
});

server.listen(PORT,()=>{
  console.log(`\n🎮 IMPOSTR Backend running on port ${PORT}`);
  console.log(`📡 Health: http://localhost:${PORT}/api/health\n`);
});
