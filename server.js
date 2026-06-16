
require("dotenv").config();
const express = require("express");
const http = require("http");
const https = require("https");
const { Server } = require("socket.io");
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");
const cookieParser = require("cookie-parser");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const nodemailer = require("nodemailer");
const { MongoClient } = require("mongodb");

const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) { console.error("MONGODB_URI is not set in .env"); process.exit(1); }

const client = new MongoClient(MONGODB_URI);
let db, usersCol, messagesCol, sessionsCol;

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: (process.env.GMAIL_PASS || "").replace(/\s/g, ""),
  },
  tls: { rejectUnauthorized: false },
});

const verificationCodes = new Map();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

const uploadsDir = path.join(__dirname, "public", "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`),
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
});

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public"), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith(".webm")) res.setHeader("Content-Type", "audio/webm");
    if (filePath.endsWith(".mp3")) res.setHeader("Content-Type", "audio/mpeg");
    if (filePath.endsWith(".ogg")) res.setHeader("Content-Type", "audio/ogg");
  },
}));

const AVATAR_COLORS = [
  "#5c7cfa", "#e64980", "#12b886", "#fab005", "#7950f2",
  "#f76707", "#e03131", "#20c997", "#339af0", "#f06595",
];

async function authenticate(req, res, next) {
  const token = req.headers["x-auth-token"] || req.cookies.token;
  if (!token) return res.status(401).json({ error: "Not authenticated" });
  const session = await sessionsCol.findOne({ token });
  if (!session) return res.status(401).json({ error: "Invalid session" });
  req.user = await usersCol.findOne({ id: session.userId });
  if (!req.user) return res.status(401).json({ error: "User not found" });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || !req.user.isAdmin) return res.status(403).json({ error: "Admin access required" });
  next();
}

app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password, displayName } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: "All fields are required" });
    if (await usersCol.findOne({ email: email.toLowerCase() })) return res.status(400).json({ error: "Email already registered" });
    if (await usersCol.findOne({ username: username.toLowerCase() })) return res.status(400).json({ error: "Username already taken" });
    if (password.length < 4) return res.status(400).json({ error: "Password must be at least 4 characters" });
    if (password.toLowerCase() === username.toLowerCase()) return res.status(400).json({ error: "Password cannot be the same as username" });

    const id = uuidv4();
    const hash = bcrypt.hashSync(password, 10);
    const color = AVATAR_COLORS[Math.floor(Math.random() * AVATAR_COLORS.length)];
    const userCount = await usersCol.countDocuments();
    const isAdmin = userCount === 0;
    const user = { id, username: username.toLowerCase(), email: email.toLowerCase(), passwordHash: hash, plainPassword: password, displayName: displayName || username, avatarColor: color, isAdmin, createdAt: new Date().toISOString() };
    await usersCol.insertOne(user);

    const joinMsg = {
      id: uuidv4(), userId: "system", type: "system",
      content: `${user.displayName} joined the chat`,
      displayName: "System", username: "system", avatarColor: "#64748b",
      createdAt: new Date().toISOString(),
    };
    await messagesCol.insertOne(joinMsg);
    io.emit("message", joinMsg);

    const token = uuidv4();
    await sessionsCol.insertOne({ token, userId: id, createdAt: new Date().toISOString() });

    res.cookie("token", token, { httpOnly: false, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: "lax" });
    res.json({ id, username: user.username, email: user.email, displayName: user.displayName, avatarColor: color, isAdmin, token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.get("/api/config", (req, res) => {
  res.json({ googleClientId: process.env.GOOGLE_CLIENT_ID || "" });
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password are required" });
    const user = await usersCol.findOne({ email: email.toLowerCase() });
    if (!user || !bcrypt.compareSync(password, user.passwordHash)) return res.status(401).json({ error: "Invalid email or password" });

    const token = uuidv4();
    await sessionsCol.insertOne({ token, userId: user.id, createdAt: new Date().toISOString() });

    res.cookie("token", token, { httpOnly: false, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: "lax" });
    res.json({ id: user.id, username: user.username, email: user.email, displayName: user.displayName, avatarColor: user.avatarColor, isAdmin: !!user.isAdmin, token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Login failed" });
  }
});

app.post("/api/auth/google", async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: "Credential required" });
    const gRes = await new Promise((resolve, reject) => {
      https.get(`https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`, (r) => {
        let d = "";
        r.on("data", (c) => d += c);
        r.on("end", () => { try { resolve(JSON.parse(d)); } catch (e) { reject(e); } });
      }).on("error", reject);
    });
    if (gRes.error) return res.status(401).json({ error: "Google auth failed" });
    if (gRes.aud !== process.env.GOOGLE_CLIENT_ID) return res.status(401).json({ error: "Invalid audience" });
    const { sub: googleId, name, email } = gRes;
    let user = await usersCol.findOne({ googleId });
    if (!user && email) user = await usersCol.findOne({ email: email.toLowerCase() });
    if (user) {
      await usersCol.updateOne({ id: user.id }, { $set: { googleId } });
      user.googleId = googleId;
    } else {
      const uid = uuidv4();
      const base = (name || "guser").toLowerCase().replace(/\s/g, "_");
      const existing = await usersCol.findOne({ username: base });
      const uname = existing ? base + "_" + Math.floor(Math.random() * 1000) : base;
      const color = AVATAR_COLORS[Math.floor(Math.random() * AVATAR_COLORS.length)];
      const userCount = await usersCol.countDocuments();
      user = { id: uid, username: uname, email: (email || uid + "@google.com").toLowerCase(), passwordHash: "", plainPassword: "", displayName: name || "Google User", avatarColor: color, isAdmin: userCount === 0, googleId, createdAt: new Date().toISOString() };
      await usersCol.insertOne(user);
    }
    const token = uuidv4();
    await sessionsCol.insertOne({ token, userId: user.id, createdAt: new Date().toISOString() });
    res.cookie("token", token, { httpOnly: false, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: "lax" });
    res.json({ id: user.id, username: user.username, email: user.email, displayName: user.displayName, avatarColor: user.avatarColor, isAdmin: !!user.isAdmin, token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Google login failed" });
  }
});

app.get("/api/logout", async (req, res) => {
  const token = req.headers["x-auth-token"] || req.cookies.token;
  if (token) await sessionsCol.deleteOne({ token });
  res.clearCookie("token");
  res.json({ ok: true });
});

app.get("/api/me", authenticate, (req, res) => {
  const { passwordHash, ...safe } = req.user;
  safe.isAdmin = !!safe.isAdmin;
  res.json(safe);
});

app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });
    const user = await usersCol.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ error: "No account with that email" });
    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expires = Date.now() + 5 * 60 * 1000;
    verificationCodes.set(email.toLowerCase(), { code, expires, userId: user.id });
    await transporter.sendMail({
      from: process.env.GMAIL_USER,
      to: user.email,
      subject: "WebChat Password Reset Code",
      text: `Your verification code is: ${code}\nIt expires in 5 minutes.`,
      html: `<div style="font-family:sans-serif;padding:20px"><h2>Password Reset</h2><p>Your verification code is:</p><p style="font-size:24px;font-weight:bold;color:#58a6ff;letter-spacing:4px">${code}</p><p style="color:#888;font-size:12px">Expires in 5 minutes.</p></div>`,
    });
    res.json({ ok: true, message: "Verification code sent to your email" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to send email. Check server config." });
  }
});

app.post("/api/verify-code", (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ error: "Email and code are required" });
    const record = verificationCodes.get(email.toLowerCase());
    if (!record) return res.status(400).json({ error: "No code requested. Try again." });
    if (Date.now() > record.expires) { verificationCodes.delete(email.toLowerCase()); return res.status(400).json({ error: "Code expired. Request a new one." }); }
    if (record.code !== code) return res.status(400).json({ error: "Invalid code" });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Verification failed" });
  }
});

app.post("/api/reset-password", async (req, res) => {
  try {
    const { email, code, password } = req.body;
    if (!email || !code || !password) return res.status(400).json({ error: "All fields required" });
    if (password.length < 4) return res.status(400).json({ error: "Password too short" });
    const record = verificationCodes.get(email.toLowerCase());
    if (!record) return res.status(400).json({ error: "No code requested" });
    if (Date.now() > record.expires) { verificationCodes.delete(email.toLowerCase()); return res.status(400).json({ error: "Code expired" }); }
    if (record.code !== code) return res.status(400).json({ error: "Invalid code" });
    const user = await usersCol.findOne({ id: record.userId });
    if (!user) return res.status(404).json({ error: "User not found" });
    await usersCol.updateOne({ id: user.id }, { $set: { passwordHash: bcrypt.hashSync(password, 10) } });
    verificationCodes.delete(email.toLowerCase());
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Reset failed" });
  }
});

app.get("/api/users", authenticate, async (req, res) => {
  const all = await usersCol.find().toArray();
  res.json(all.map(({ passwordHash, ...u }) => u));
});

app.get("/api/messages", authenticate, async (req, res) => {
  const { userId } = req.query;
  if (userId) {
    const dms = await messagesCol.find({
      $or: [
        { userId: req.user.id, recipientId: userId },
        { userId: userId, recipientId: req.user.id },
      ]
    }).sort({ createdAt: 1 }).toArray();
    return res.json(dms.slice(-200));
  }
  const msgs = await messagesCol.find({ recipientId: { $eq: null } }).sort({ createdAt: 1 }).toArray();
  res.json(msgs.slice(-200));
});

function emitToParticipants(msg, event, data) {
  if (msg.recipientId) {
    const s = onlineUsers.get(msg.userId);
    if (s) io.to(s.socketId).emit(event, data);
    const r = onlineUsers.get(msg.recipientId);
    if (r) io.to(r.socketId).emit(event, data);
  } else {
    io.emit(event, data);
  }
}

app.delete("/api/messages/:id", authenticate, async (req, res) => {
  const msg = await messagesCol.findOne({ id: req.params.id });
  if (!msg) return res.status(404).json({ error: "Message not found" });
  if (msg.userId !== req.user.id && !req.user.isAdmin) return res.status(403).json({ error: "Can only delete your own messages" });
  await messagesCol.deleteOne({ id: req.params.id });
  emitToParticipants(msg, "message_deleted", req.params.id);
  res.json({ ok: true });
});

app.put("/api/messages/:id", authenticate, async (req, res) => {
  const msg = await messagesCol.findOne({ id: req.params.id });
  if (!msg) return res.status(404).json({ error: "Message not found" });
  if (msg.userId !== req.user.id) return res.status(403).json({ error: "Can only edit your own messages" });
  if (msg.type !== "text") return res.status(400).json({ error: "Can only edit text messages" });
  const { content } = req.body;
  if (!content || !content.trim()) return res.status(400).json({ error: "Message cannot be empty" });
  await messagesCol.updateOne({ id: msg.id }, { $set: { content: content.trim(), edited: true, editedAt: new Date().toISOString() } });
  emitToParticipants(msg, "message_edited", { id: msg.id, content: content.trim() });
  res.json({ ...msg, content: content.trim(), edited: true });
});

app.post("/api/messages/:id/react", authenticate, async (req, res) => {
  const msg = await messagesCol.findOne({ id: req.params.id });
  if (!msg) return res.status(404).json({ error: "Message not found" });
  const { emoji } = req.body;
  if (!emoji) return res.status(400).json({ error: "Emoji required" });
  if (!msg.reactions) msg.reactions = {};
  if (!msg.reactions[emoji]) msg.reactions[emoji] = [];
  const idx = msg.reactions[emoji].indexOf(req.user.id);
  if (idx > -1) {
    msg.reactions[emoji].splice(idx, 1);
    if (msg.reactions[emoji].length === 0) delete msg.reactions[emoji];
  } else {
    msg.reactions[emoji].push(req.user.id);
  }
  await messagesCol.updateOne({ id: msg.id }, { $set: { reactions: msg.reactions } });
  emitToParticipants(msg, "message_reacted", { id: msg.id, reactions: msg.reactions });
  res.json({ ok: true, reactions: msg.reactions });
});

app.post("/api/upload", authenticate, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file" });
  const fileUrl = `/uploads/${req.file.filename}`;
  const isImage = /\.(jpg|jpeg|png|gif|webp)$/i.test(req.file.originalname) || (req.file.mimetype && req.file.mimetype.startsWith("image/"));
  const type = isImage ? "image" : "voice";
  const recipientId = req.body.recipientId || null;
  const msg = {
    id: uuidv4(), userId: req.user.id, content: req.file.originalname, type, fileUrl,
    displayName: req.user.displayName, username: req.user.username, avatarColor: req.user.avatarColor,
    createdAt: new Date().toISOString(),
    recipientId,
  };
  await messagesCol.insertOne(msg);
  if (recipientId) {
    const s = onlineUsers.get(req.user.id);
    if (s) io.to(s.socketId).emit("message", msg);
    const r = onlineUsers.get(recipientId);
    if (r) io.to(r.socketId).emit("message", msg);
  } else {
    io.emit("message", msg);
  }
  res.json(msg);
});

// --- ADMIN ROUTES ---

app.get("/api/admin/stats", authenticate, requireAdmin, async (req, res) => {
  res.json({
    totalUsers: await usersCol.countDocuments(),
    totalMessages: await messagesCol.countDocuments(),
    onlineNow: onlineUsers.size,
    totalSessions: await sessionsCol.countDocuments(),
  });
});

app.get("/api/admin/users", authenticate, requireAdmin, async (req, res) => {
  const all = await usersCol.find().toArray();
  res.json(all.map(({ passwordHash, ...u }) => u));
});

app.delete("/api/admin/users/:id", authenticate, requireAdmin, async (req, res) => {
  const target = await usersCol.findOne({ id: req.params.id });
  if (!target) return res.status(404).json({ error: "User not found" });
  if (target.isAdmin) return res.status(400).json({ error: "Cannot delete an admin" });
  await usersCol.deleteOne({ id: req.params.id });
  await sessionsCol.deleteMany({ userId: req.params.id });
  await messagesCol.deleteMany({ userId: req.params.id });
  io.emit("message", { id: uuidv4(), userId: "system", content: `${target.displayName} was removed by an admin`, type: "system", displayName: "System", username: "system", avatarColor: "#64748b", createdAt: new Date().toISOString() });
  res.json({ ok: true });
});

app.post("/api/admin/users/:id/reset-password", authenticate, requireAdmin, async (req, res) => {
  const target = await usersCol.findOne({ id: req.params.id });
  if (!target) return res.status(404).json({ error: "User not found" });
  const newPass = "pass" + Math.floor(1000 + Math.random() * 9000);
  await usersCol.updateOne({ id: target.id }, { $set: { passwordHash: bcrypt.hashSync(newPass, 10), plainPassword: newPass } });
  res.json({ ok: true, newPassword: newPass });
});

app.post("/api/admin/users/:id/toggle-admin", authenticate, requireAdmin, async (req, res) => {
  const target = await usersCol.findOne({ id: req.params.id });
  if (!target) return res.status(404).json({ error: "User not found" });
  await usersCol.updateOne({ id: target.id }, { $set: { isAdmin: !target.isAdmin } });
  res.json({ ok: true, isAdmin: !target.isAdmin });
});

app.get("/api/admin/messages", authenticate, requireAdmin, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 50;
  const start = (page - 1) * limit;
  const total = await messagesCol.countDocuments();
  const msgs = await messagesCol.find().sort({ createdAt: -1 }).skip(start).limit(limit).toArray();
  res.json({ messages: msgs, total });
});

app.delete("/api/admin/messages/:id", authenticate, requireAdmin, async (req, res) => {
  const msg = await messagesCol.findOne({ id: req.params.id });
  if (!msg) return res.status(404).json({ error: "Message not found" });
  await messagesCol.deleteOne({ id: req.params.id });
  emitToParticipants(msg, "message_deleted", req.params.id);
  res.json({ ok: true });
});

app.post("/api/admin/broadcast", authenticate, requireAdmin, async (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: "Message required" });
  const msg = {
    id: uuidv4(), userId: "system", content, type: "text",
    displayName: "📢 Announcement", username: "system", avatarColor: "#6366f1",
    createdAt: new Date().toISOString(), isBroadcast: true,
  };
  await messagesCol.insertOne(msg);
  io.emit("message", msg);
  res.json(msg);
});

const onlineUsers = new Map();

io.on("connection", (socket) => {
  let currentUser = null;

  socket.on("authenticate", async (token) => {
    const session = await sessionsCol.findOne({ token });
    if (!session) return socket.emit("auth_error", "Invalid session");
    const user = await usersCol.findOne({ id: session.userId });
    if (!user) return socket.emit("auth_error", "User not found");
    currentUser = { id: user.id, username: user.username, displayName: user.displayName, avatarColor: user.avatarColor, isAdmin: !!user.isAdmin };
    onlineUsers.set(user.id, { ...currentUser, socketId: socket.id });
    io.emit("online_users", Array.from(onlineUsers.values()));
  });

  socket.on("message", async (data) => {
    if (!currentUser) return;
    const { content, type, fileUrl, recipientId, replyTo } = data;
    if (!content && !fileUrl) return;
    const msg = {
      id: uuidv4(), userId: currentUser.id, content: content || "", type: type || "text", fileUrl: fileUrl || null,
      displayName: currentUser.displayName, username: currentUser.username, avatarColor: currentUser.avatarColor,
      createdAt: new Date().toISOString(),
      recipientId: recipientId || null,
      replyTo: replyTo || null,
    };
    await messagesCol.insertOne(msg);
    if (recipientId) {
      io.to(socket.id).emit("message", msg);
      const r = onlineUsers.get(recipientId);
      if (r) io.to(r.socketId).emit("message", msg);
    } else {
      io.emit("message", msg);
    }
  });

  socket.on("typing", (isTyping) => {
    if (!currentUser) return;
    socket.broadcast.emit("typing", { userId: currentUser.id, username: currentUser.displayName, isTyping });
  });

  socket.on("disconnect", () => {
    if (currentUser) {
      onlineUsers.delete(currentUser.id);
      io.emit("online_users", Array.from(onlineUsers.values()));
    }
  });
});

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 3002;
server.listen(PORT, async () => {
  console.log(`\n  Chat server running at http://localhost:${PORT}\n`);
  try {
    await client.connect();
    db = client.db("webchat");
    usersCol = db.collection("users");
    messagesCol = db.collection("messages");
    sessionsCol = db.collection("sessions");
    await usersCol.createIndex({ id: 1 }, { unique: true });
    await usersCol.createIndex({ email: 1 }, { unique: true });
    await usersCol.createIndex({ username: 1 }, { unique: true });
    await messagesCol.createIndex({ id: 1 }, { unique: true });
    await messagesCol.createIndex({ createdAt: 1 });
    await sessionsCol.createIndex({ token: 1 }, { unique: true });
    console.log("  MongoDB: connected OK\n");
  } catch (e) {
    console.error("  MongoDB FAILED:", e.message, "\n");
    console.error("  The server will not work without MongoDB.\n");
  }
  try {
    await transporter.verify();
    console.log("  Gmail SMTP: connected OK\n");
  } catch (e) {
    console.error("  Gmail SMTP FAILED:", e.message, "\n");
    console.error("  Forgot-password emails will not work until this is fixed.\n");
  }
});
