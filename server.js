// server.js
import express from "express";
import session from "express-session";
import bodyParser from "body-parser";
import { createServer } from "http";
import { Server } from "socket.io";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import crypto from "crypto";
import bcrypt from "bcryptjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_FILE = path.join(__dirname, "data.json");
const AVATAR_DIR = path.join(__dirname, "public", "avatars");
const ROOM_PFP_DIR = path.join(__dirname, "public", "room_pfps");
if (!fs.existsSync(AVATAR_DIR)) fs.mkdirSync(AVATAR_DIR, { recursive: true });
if (!fs.existsSync(ROOM_PFP_DIR)) fs.mkdirSync(ROOM_PFP_DIR, { recursive: true });

/* ---------- simple persistent store ---------- */
function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, "utf8");
      const parsed = JSON.parse(raw);
      parsed.users = parsed.users || {};
      parsed.friendRequests = parsed.friendRequests || {};
      parsed.rooms = parsed.rooms || {};
      parsed.dms = parsed.dms || {};
      parsed.notifications = parsed.notifications || {};
      parsed.blocks = parsed.blocks || {}; // who blocked whom (blocks[user] = [blockedUsernames])
      parsed.rateLimits = parsed.rateLimits || {};
      return parsed;
    }
  } catch (e) { console.error("loadData failed", e); }
  return { users: {}, friendRequests: {}, rooms: {}, dms: {}, notifications: {}, blocks: {}, rateLimits: {} };
}
function saveData() {
  try { fs.writeFileSync(DATA_FILE, JSON.stringify(store, null, 2), "utf8"); } catch(e){console.error("saveData failed", e);}
}
const store = loadData();

/* utilities */
function genId() { return crypto.randomBytes(6).toString("hex"); }
function addNotification(user, type, payload={}) {
  store.notifications[user] = store.notifications[user] || [];
  const note = { id: genId(), type, payload, time: Date.now(), read: false };
  store.notifications[user].unshift(note);
  saveData();
  return note;
}

/* express setup */
const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: "supersecret",
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false },
}));
app.use(express.static(path.join(__dirname, "public")));

const upload = multer({ dest: path.join(__dirname, "tmp_uploads") });

function requireAuth(req,res,next){ if(!req.session.user) return res.status(401).json({ loggedIn:false }); next(); }
// BANNED USERS: Auto-logout + block login
app.use((req, res, next) => {
  if (req.session.user) {
    const user = store.users[req.session.user];
    if (user?.banned) {
      req.session.destroy(); // log them out
      if (req.path === "/me" || req.path === "/login") {
        return res.status(403).json({ loggedIn: false, banned: true, message: "You are permanently banned." });
      }
      return res.send(`
        <script>
          alert("You have been permanently banned.");
          location.href = "/login.html";
        </script>
      `);
    }
  }
  next();
});

// Also block banned users on login attempt
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const u = store.users[username];
  if (!u) return res.json({ success: false, message: "Invalid credentials" });
  if (u.banned) {
    return res.json({ success: false, message: "You are permanently banned." });
  }
  const ok = await bcrypt.compare(password, u.passwordHash);
  if (!ok) return res.json({ success: false, message: "Invalid credentials" });
  req.session.user = username;
  res.json({ success: true });
});
/* ---------- AUTH ----------
 - Passwords are hashed with bcrypt
 - Users have: username, passwordHash, avatar, displayName, bio, createdAt, admin, dmPrivacy
   dmPrivacy: "any" | "friends" | "noone"
*/
app.post("/signup", async (req,res)=>{
  const { username, password, avatarUrl } = req.body;
  if(!username || !password) return res.json({ success:false, message:"Missing fields" });
  if(store.users[username]) return res.json({ success:false, message:"User exists" });
  const hash = await bcrypt.hash(password, 10);
  store.users[username] = {
    username,
    passwordHash: hash,
    avatar: avatarUrl || "/avatars/default.png",
    displayName: username,
    bio: "",
    friends: [],
    starredRooms: [],
    createdAt: Date.now(),
    admin: false,
    dmPrivacy: "any"
  };
  store.friendRequests[username] = store.friendRequests[username] || [];
  store.notifications[username] = store.notifications[username] || [];
  store.blocks[username] = store.blocks[username] || [];
  saveData();
  req.session.user = username;
  res.json({ success:true });
});

app.post("/login", async (req,res)=>{
  const { username, password } = req.body;
  const u = store.users[username];
  if(!u) return res.json({ success:false, message:"Invalid credentials" });
  const ok = await bcrypt.compare(password, u.passwordHash);
  if(!ok) return res.json({ success:false, message:"Invalid credentials" });
  req.session.user = username;
  res.json({ success:true });
});

app.post("/logout", (req,res)=> req.session.destroy(()=>res.json({ success:true })));

app.get("/me", (req,res)=>{
  if(!req.session.user) return res.json({ loggedIn:false });
  const u = store.users[req.session.user];
  if(!u) return res.json({ loggedIn:false });
  res.json({ loggedIn:true, username:u.username, avatar:u.avatar, displayName:u.displayName, bio:u.bio, admin:!!u.admin, dmPrivacy: u.dmPrivacy });
});

/* ---------- AVATAR (file upload or URL) ---------- */
app.post("/update-avatar", requireAuth, upload.single("avatar"), (req,res)=>{
  const username = req.session.user;
  let avatarUrl = null;
  if (req.file) {
    const ext = path.extname(req.file.originalname) || ".png";
    const destName = `${username}_${Date.now()}${ext}`;
    const destPath = path.join(AVATAR_DIR, destName);
    try { fs.renameSync(req.file.path, destPath); avatarUrl = `/avatars/${destName}`; }
    catch(e){ try{fs.unlinkSync(req.file.path);}catch{} return res.json({ success:false, message:"Upload failed" }); }
  } else if (req.body.avatarUrl) avatarUrl = req.body.avatarUrl;
  else return res.json({ success:false, message:"No avatar provided" });
  store.users[username].avatar = avatarUrl;
  saveData();
  res.json({ success:true, avatar:avatarUrl });
});

/* ---------- profile updates: displayName, bio, dmPrivacy ---------- */
app.post("/set-profile", requireAuth, (req,res)=>{
  const u = store.users[req.session.user];
  if(!u) return res.json({ success:false });
  const { displayName, bio, dmPrivacy } = req.body;
  if(typeof displayName === "string") u.displayName = displayName.slice(0,64);
  if(typeof bio === "string") u.bio = bio.slice(0,300);
  if(["any","friends","noone"].includes(dmPrivacy)) u.dmPrivacy = dmPrivacy;
  saveData();
  res.json({ success:true });
});

/* ---------- BLOCKING ---------- */
app.post("/block", requireAuth, (req,res)=>{
  const who = req.session.user; const target = req.body.target;
  if(!target || !store.users[target]) return res.json({ success:false, message:"User not found" });
  store.blocks[who] = store.blocks[who] || [];
  if(!store.blocks[who].includes(target)) store.blocks[who].push(target);
  saveData();
  res.json({ success:true });
});
app.post("/unblock", requireAuth, (req,res)=>{
  const who = req.session.user; const target = req.body.target;
  store.blocks[who] = store.blocks[who] || [];
  store.blocks[who] = store.blocks[who].filter(x=>x!==target);
  saveData();
  res.json({ success:true });
});

/* ---------- FRIENDS ---------- */
app.get("/friends", requireAuth, (req,res)=>{
  const username = req.session.user;
  const requests = store.friendRequests[username] || [];
  store.users[username].friends = Array.from(new Set(store.users[username].friends || []));
  const friends = (store.users[username].friends || []).map(f=>({ username: f, avatar: store.users[f]?.avatar || "/avatars/default.png" }));
  const recent = Object.values(store.users).filter(u=>u.username !== username && !store.users[username].friends.includes(u.username)).sort((a,b)=>b.createdAt - a.createdAt).slice(0,10).map(u=>({ username:u.username, avatar:u.avatar||"/avatars/default.png" }));
  res.json({ requests, friends, recent });
});

app.post("/friend-request", requireAuth, (req,res)=>{
  const from = req.session.user, to = req.body.to;
  if(!to || !store.users[to]) return res.json({ success:false, message:"User not found" });
  if(to===from) return res.json({ success:false, message:"Can't friend yourself" });
  if((store.blocks[to]||[]).includes(from) || (store.blocks[from]||[]).includes(to)) return res.json({ success:false, message:"Cannot send request (blocked)" });
  store.friendRequests[to] = store.friendRequests[to] || [];
  if(!store.friendRequests[to].includes(from) && !store.users[to].friends.includes(from)) {
    store.friendRequests[to].push(from);
    saveData();
    const note = addNotification(to, "friend_request", { from });
    io.to(to).emit("friendRequest", from);
    io.to(to).emit("inboxUpdate", note);
  }
  res.json({ success:true });
});

app.post("/accept-request", requireAuth, (req,res)=>{
  const username = req.session.user, from = req.body.from;
  store.friendRequests[username] = store.friendRequests[username] || [];
  const idx = store.friendRequests[username].indexOf(from);
  if(idx>-1) {
    store.friendRequests[username].splice(idx,1);
    store.users[username].friends = Array.from(new Set([...(store.users[username].friends||[]), from]));
    store.users[from].friends = Array.from(new Set([...(store.users[from].friends||[]), username]));
    saveData();
    io.to(from).emit("friendsUpdate");
    io.to(username).emit("friendsUpdate");
    const note = addNotification(from, "friend_accept", { by: username });
    io.to(from).emit("inboxUpdate", note);
  }
  res.json({ success:true });
});

/* ---------- ROOMS ---------- */

// ROOM MANAGEMENT — FULLY WORKING (invite, kick, ban, etc.)
// FINAL ROOM-ACTION — KICK REMOVED, EVERYTHING WORKS PERFECTLY
app.post("/room-action", requireAuth, (req, res) => {
  const { roomId, action, value, target } = req.body;
  const user = req.session.user;
  const room = store.rooms[roomId];

  if (!room) return res.json({ success: false, message: "Room not found" });

  const isOwner = room.owner === user;
  const isAdmin = store.users[user]?.admin;
  if (!isOwner && !isAdmin) return res.json({ success: false, message: "Not authorized" });

  switch (action) {
    case "setName":
      if (value?.trim()) room.name = value.trim();
      break;

    case "setDescription":
      room.description = typeof value === "string" ? value.slice(0, 300) : "";
      break;

    case "setPfp":
      if (typeof value === "string") room.pfp = value;
      break;

    case "setPrivacy":
      if (["public", "invite"].includes(value)) {
        room.inviteOnly = value === "invite";
        if (!room.inviteOnly) {
          room.invited = [room.owner]; // clear invites when public
        }
      }
      break;

    case "setCanPost":
      if (["any", "friends", "owner"].includes(value)) {
        room.canPost = value;
      }
      break;

    case "invite":
      if (target && store.users[target]) {
        room.invited = room.invited || [];
        if (!room.invited.includes(target)) {
          room.invited.push(target);
          addNotification(target, "room_invite", {
            roomId,
            roomName: room.name,
            by: user
          });
          io.to(target).emit("roomsUpdated"); // instantly appears
        }
      }
      break;

    case "ban":
      if (target) {
        room.banned = room.banned || [];
        if (!room.banned.includes(target)) room.banned.push(target);
      }
      break;

    case "unban":
      if (target) {
        room.banned = (room.banned || []).filter(u => u !== target);
      }
      break;

    default:
      return res.json({ success: false, message: "Invalid action" });
  }

  saveData();
  io.emit("roomsUpdated");
  res.json({ success: true });
});

app.get("/rooms", requireAuth, (req, res) => {
  const username = req.session.user;
  const isAdmin = store.users[username]?.admin;

  const visible = {};

  for (const [id, room] of Object.entries(store.rooms || {})) {
    // 1. Admins see EVERY room
    if (isAdmin) {
      visible[id] = { name: room.name, owner: room.owner, pfp: room.pfp || "/room_pfps/default.png" };
      continue;
    }

    // 2. Owner always sees their room
    if (room.owner === username) {
      visible[id] = { name: room.name, owner: room.owner, pfp: room.pfp || "/room_pfps/default.png" };
      continue;
    }

    // 3. PUBLIC rooms = everyone sees
    if (!room.inviteOnly) {
      visible[id] = { name: room.name, owner: room.owner, pfp: room.pfp || "/room_pfps/default.png" };
      continue;
    }

    // 4. INVITE-ONLY rooms = only invited users see
    if (room.invited?.includes(username)) {
      visible[id] = { name: room.name, owner: room.owner, pfp: room.pfp || "/room_pfps/default.png" };
    }
  }

  res.json(visible);
});
app.post("/create-room", requireAuth, (req, res) => {
  const { name } = req.body;
  if (!name?.trim()) return res.json({ success: false, message: "Room name required" });

  const lower = name.trim().toLowerCase();
  for (const r of Object.values(store.rooms || {}))
    if (r.name?.trim().toLowerCase() === lower)
      return res.json({ success: false, message: "Room name already in use" });

  const id = genId();
  store.rooms[id] = {
    name: name.trim(),
    owner: req.session.user,
    pfp: "/room_pfps/default.png",
    messages: [],
    banned: [],
    invited: [req.session.user],  // Owner is auto-invited
    inviteOnly: false  // ALL rooms are now invite-only by default
  };

  saveData();
  io.emit("roomsUpdated");
  res.json({ success: true, roomId: id });
});

app.get("/room-info/:roomId", requireAuth, (req,res)=>{
  const r = store.rooms[req.params.roomId];
  if(!r) return res.json({ success:false });
  res.json({ success:true, name:r.name, owner: r.owner||null, pfp: r.pfp||"/room_pfps/default.png", banned: r.banned||[] });
});

/* update room pfp (file or url) */
app.post("/update-room-pfp", requireAuth, upload.single("pfp"), (req,res)=>{
  const username = req.session.user;
  const roomId = req.body.roomId;
  if(!roomId || !store.rooms[roomId]) return res.json({ success:false, message:"Room not found" });
  const room = store.rooms[roomId];
  if(room.owner !== username && !store.users[username].admin) return res.status(403).json({ success:false, message:"Not allowed" });
  if(req.file) {
    const ext = path.extname(req.file.originalname) || ".png";
    const destName = `room_${roomId}_${Date.now()}${ext}`;
    const destPath = path.join(ROOM_PFP_DIR, destName);
    try { fs.renameSync(req.file.path, destPath); room.pfp = `/room_pfps/${destName}`; }
    catch(e){ try{fs.unlinkSync(req.file.path)}catch{} return res.json({ success:false, message:"Upload failed" }); }
  } else if(req.body.pfpUrl) {
    room.pfp = req.body.pfpUrl;
  } else return res.json({ success:false, message:"No pfp provided" });
  saveData();
  io.emit("roomsUpdated");
  res.json({ success:true, pfp: room.pfp });
});

/* ---------- DMs ---------- */
/* DM privacy enforcement and blocking checked here */
app.get("/dm/:friend", requireAuth, (req,res)=>{
  const me = req.session.user, friend = req.params.friend;
  if(!store.users[friend]) return res.json({ success:false, message:"User not found" });
  // if friend has blocked me or I blocked friend, show empty
  if((store.blocks[friend]||[]).includes(me) || (store.blocks[me]||[]).includes(friend)) return res.json({ success:false, message:"Cannot view (blocked)" });
  const key = [me, friend].sort().join("_");
  res.json({ success:true, messages: store.dms[key] || [] });
});

/* ---------- inbox endpoints ---------- */
app.get("/inbox", requireAuth, (req,res)=>{
  const u = req.session.user;
  res.json({ success:true, notifications: store.notifications[u] || [] });
});
app.post("/inbox/mark-read", requireAuth, (req,res)=>{
  const u = req.session.user;
  const { id } = req.body;
  if(!store.notifications[u]) return res.json({ success:false });
  if(id === "all") {
    store.notifications[u].forEach(n=>n.read = true);
    saveData();
    return res.json({ success:true });
  }
  const n = store.notifications[u].find(x=>x.id===id);
  if(n) { n.read = true; saveData(); return res.json({ success:true }); }
  res.json({ success:false });
});

/* ---------- message edit/delete endpoints (room or dm) ---------- */
app.post("/edit-message", requireAuth, (req,res)=>{
  const { id, roomId, newMsg, dmWith } = req.body;
  const user = req.session.user;
  if(roomId && store.rooms[roomId]) {
    const msg = (store.rooms[roomId].messages||[]).find(m=>m.id===id);
    if(!msg) return res.json({ success:false });
    if(msg.sender !== user && !store.users[user].admin) return res.json({ success:false });
    msg.message = newMsg;
    saveData();
    io.to(roomId).emit("updateMessage", msg);
    return res.json({ success:true });
  }
  if(dmWith) {
    const key = [user, dmWith].sort().join("_");
    const m = (store.dms[key]||[]).find(mm=>mm.id===id);
    if(!m) return res.json({ success:false });
    if(m.sender !== user && !store.users[user].admin) return res.json({ success:false });
    m.message = newMsg;
    saveData();
    io.to(user).emit("updateMessage", m);
    io.to(dmWith).emit("updateMessage", m);
    return res.json({ success:true });
  }
  res.json({ success:false });
});

app.post("/delete-message", requireAuth, (req,res)=>{
  const { id, roomId, dmWith } = req.body;
  const user = req.session.user;
  if(roomId && store.rooms[roomId]) {
    const idx = (store.rooms[roomId].messages||[]).findIndex(m=>m.id===id);
    if(idx === -1) return res.json({ success:false });
    const msg = store.rooms[roomId].messages[idx];
    if(msg.sender !== user && !store.users[user].admin) return res.json({ success:false });
    store.rooms[roomId].messages.splice(idx,1);
    saveData();
    io.to(roomId).emit("deleteMessage", id);
    return res.json({ success:true });
  }
  if(dmWith) {
    const key = [user, dmWith].sort().join("_");
    const arr = store.dms[key] || [];
    const idx = arr.findIndex(m=>m.id===id);
    if(idx === -1) return res.json({ success:false });
    const msg = arr[idx];
    if(msg.sender !== user && !store.users[user].admin) return res.json({ success:false });
    arr.splice(idx,1);
    saveData();
    io.to(user).emit("deleteMessage", id);
    io.to(dmWith).emit("deleteMessage", id);
    return res.json({ success:true });
  }
  res.json({ success:false });
});

/* ---------- basic rate limiting for messages ----------
  - allow N messages per window (per-sender)
*/
function allowMessage(sender) {
  const now = Date.now();
  store.rateLimits[sender] = store.rateLimits[sender] || [];
  // window 10s, limit 25 messages
  const WINDOW = 10_000;
  const LIMIT = 25;
  store.rateLimits[sender] = store.rateLimits[sender].filter(t => (now - t) <= WINDOW);
  if (store.rateLimits[sender].length >= LIMIT) return false;
  store.rateLimits[sender].push(now);
  saveData();
  return true;
}

/* ---------- SOCKET.IO ---------- */
io.on("connection", (socket)=>{
  socket.on("registerUser", (username) => {
    socket.username = username;
    socket.join(username);
  });

  socket.on("joinRoom", ({roomId})=>{
    if(!roomId || !store.rooms[roomId]) return;
    // check if banned
    if((store.rooms[roomId].banned||[]).includes(socket.username)) {
      socket.emit("kickedFromRoom", { roomId, reason: "banned" });
      return;
    }
    socket.join(roomId);
    const messages = store.rooms[roomId].messages || [];
    socket.emit("chatHistory", messages);
  });

  socket.on("roomMessage", ({ roomId, message })=>{
    const sender = socket.username;
    if(!sender || !roomId || !store.rooms[roomId] || !message) return;
    // prevent empty message
    const text = (""+message).trim();
    if(!text) return;
    if(!allowMessage(sender)) {
      socket.emit("rateLimited", { message: "You are sending messages too fast" });
      return;
    }
    const msgObj = { id: genId(), sender, avatar: store.users[sender]?.avatar || "/avatars/default.png", message: text, time: Date.now(), roomId };
    store.rooms[roomId].messages = store.rooms[roomId].messages || [];
    store.rooms[roomId].messages.push(msgObj);
    saveData();
    io.to(roomId).emit("roomMessage", msgObj);
  });

  // dmMessage supports optional tempId to replace optimistic message on sender
  socket.on("dmMessage", ({ to, message, tempId })=>{
    const from = socket.username;
    if(!from || !to || !store.users[to] || !message) return;
    // blocked or privacy checks
    if((store.blocks[to]||[]).includes(from) || (store.blocks[from]||[]).includes(to)) {
      socket.emit("dmFailed", { message: "Message blocked" });
      return;
    }
    const recipient = store.users[to];
    // privacy: if recipient only allows friends
    if(recipient.dmPrivacy === "friends" && !(store.users[to].friends || []).includes(from)) {
      socket.emit("dmFailed", { message: "This user only accepts DMs from friends" });
      return;
    }
    if(!allowMessage(from)) { socket.emit("rateLimited", { message:"You are sending messages too fast" }); return; }
    const text = ("" + message).trim();
    if(!text) return;
    const msg = { id: genId(), sender: from, to, avatar: store.users[from]?.avatar || "/avatars/default.png", message: text, time: Date.now() };
    const key = [from, to].sort().join("_");
    store.dms[key] = store.dms[key] || [];
    store.dms[key].push(msg);
    saveData();
    const emitMsg = Object.assign({}, msg);
    if(tempId) emitMsg.tempId = tempId;
    io.to(to).emit("dmMessage", emitMsg);
    io.to(from).emit("dmMessage", emitMsg); // sender receives authoritative message that may contain time/id
    // add inbox notification + push
    const note = addNotification(to, "dm", { from, preview: text.slice(0,120) });
    io.to(to).emit("inboxUpdate", note);
    io.to(to).emit("dmNotification", { from });
  });

  /* room owner/admin commands via socket */
  socket.on("roomCommand", ({ roomId, action, target, pfpUrl })=>{
    const user = socket.username;
    if(!user || !store.rooms[roomId]) return;
    const room = store.rooms[roomId];
    const isOwner = room.owner === user || store.users[user]?.admin;
    if(!isOwner) { socket.emit("roomCommandFailed", { message:"Not allowed" }); return; }
    if(action === "kick") {
      // kick: notify target and make them leave client-side (client handles kickedFromRoom)
      io.to(target).emit("kickedFromRoom", { roomId, by: user });
      // optionally remove from room.users list (we don't strictly maintain)
      return;
    }
    if(action === "ban") {
      room.banned = room.banned || [];
      if(!room.banned.includes(target)) room.banned.push(target);
      saveData();
      io.to(target).emit("kickedFromRoom", { roomId, by:user, reason: "banned" });
      io.emit("roomsUpdated");
      return;
    }
    if(action === "setpfp") {
      if(pfpUrl && typeof pfpUrl === 'string') {
        room.pfp = pfpUrl;
        saveData();
        io.emit("roomsUpdated");
      }
      return;
    }
  });

  socket.on("sendFriendRequest", (to) => {
    const from = socket.username;
    if(!from || !to || !store.users[to]) return;
    if((store.blocks[to]||[]).includes(from) || (store.blocks[from]||[]).includes(to)) return;
    store.friendRequests[to] = store.friendRequests[to] || [];
    if(!store.friendRequests[to].includes(from) && !store.users[to].friends.includes(from)) {
      store.friendRequests[to].push(from);
      saveData();
      const note = addNotification(to, "friend_request", { from });
      io.to(to).emit("friendRequest", from);
      io.to(to).emit("inboxUpdate", note);
    }
  });

  socket.on("fetchFriends", ()=> {
    const u = socket.username;
    if(!u || !store.users[u]) return;
    socket.emit("friendsData", { requests: store.friendRequests[u] || [], friends: (store.users[u].friends || []).map(f=>({ username: f, avatar: store.users[f]?.avatar || "/avatars/default.png"})) });
  });

});
// =========== ADMIN BACKUP & RESTORE (FINAL WORKING VERSION) ===========
const ADMIN_BACKUP_PASSWORD = "epickfr";   // ← your password

// DOWNLOAD BACKUP
app.get("/admin/download-data", requireAuth, (req, res) => {
  const user = store.users[req.session.user];
  const auth = req.headers.authorization || "";

  if (!user?.admin && auth !== ADMIN_BACKUP_PASSWORD) {
    return res.status(403).send("Wrong password or not admin");
  }

  if (!fs.existsSync(DATA_FILE)) {
    return res.status(500).send("data.json missing");
  }

  const date = new Date().toISOString().slice(0, 10);
  res.header("Content-Type", "application/json");
  res.attachment(`epick-backup-${date}.json`);
  res.sendFile(DATA_FILE);
});

// UPLOAD & RESTORE BACKUP
app.post("/admin/upload-data", requireAuth, upload.single("backup"), (req, res) => {
  const user = store.users[req.session.user];
  const auth = req.headers.authorization || "";

  if (!user?.admin && auth !== ADMIN_BACKUP_PASSWORD) {
    return res.status(403).send("Wrong password or not admin");
  }

  if (!req.file) return res.status(400).send("No file selected");

  try {
    const backup = fs.readFileSync(req.file.path, "utf8");
    JSON.parse(backup); // validate

    fs.writeFileSync(DATA_FILE, backup);           // overwrite
    console.log("Backup restored by", req.session.user || "unknown");
    fs.unlinkSync(req.file.path);                  // cleanup

    Object.assign(store, loadData());              // reload in memory

    res.send("Backup restored 100%! Refresh the page or go back.");
  } catch (e) {
    console.error("Restore failed:", e);
    try { fs.unlinkSync(req.file.path); } catch {}
    res.status(400).send("Invalid or corrupted JSON file");
  }
});
// ==================== ADMIN PANEL ROUTES (ADD THIS) ====================
// These are the ONLY routes your admin.html needs — everything else stays exactly as-is

// 1. List all users
app.get("/admin/users", requireAuth, (req, res) => {
  if (!store.users[req.session.user]?.admin) return res.status(403).send("No");
  const users = Object.values(store.users).map(u => ({
    username: u.username,
    displayName: u.displayName || u.username,
    banned: !!u.banned
  }));
  res.json(users);
});

// 2. List all rooms
app.get("/admin/rooms", requireAuth, (req, res) => {
  if (!store.users[req.session.user]?.admin) return res.status(403).send("No");
  res.json(store.rooms || {});
});

// 3. Global ban (works on any user)
app.post("/admin/ban", requireAuth, (req, res) => {
  if (!store.users[req.session.user]?.admin) return res.status(403).send("No");
  const { user } = req.body;
  if (store.users[user]) store.users[user].banned = true;
  saveData();
  res.json({ success: true });
});

// 4. Global unban
app.post("/admin/unban", requireAuth, (req, res) => {
  if (!store.users[req.session.user]?.admin) return res.status(403).send("No");
  const { user } = req.body;
  if (store.users[user]) delete store.users[user].banned;
  saveData();
  res.json({ success: true });
});

// 5. Delete any room
app.post("/admin/delete-room", requireAuth, (req, res) => {
  if (!store.users[req.session.user]?.admin) return res.status(403).send("No");
  const { roomId } = req.body;
  if (store.rooms[roomId]) {
    delete store.rooms[roomId];
    saveData();
    io.emit("roomsUpdated");
  }
  res.json({ success: true });
});

// 6. Nuke all messages
app.post("/admin/nuke-messages", requireAuth, (req, res) => {
  if (!store.users[req.session.user]?.admin) return res.status(403).send("No");
  Object.values(store.rooms).forEach(r => r.messages = []);
  Object.keys(store.dms).forEach(k => store.dms[k] = []);
  saveData();
  res.json({ success: true });
});

// 7. Wipe entire server
app.post("/admin/wipe", requireAuth, (req, res) => {
  if (!store.users[req.session.user]?.admin) return res.status(403).send("No");
  Object.keys(store).forEach(k => {
    if (k === "users") store[k] = {};
    else store[k] = {};
  });
  saveData();
  res.json({ success: true });
});

// ==================== END OF ADMIN ROUTES ====================
// ←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←
// MUST BE AFTER ALL ROUTES ! ! !
const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  console.log(`Epick Chat running on: ${PORT}`);
  console.log(`Backup password: ${ADMIN_BACKUP_PASSWORD}`);
});
