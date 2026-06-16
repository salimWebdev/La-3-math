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

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS.replace(/\s/g, ""),
  },
  tls: { rejectUnauthorized: false },
});

const verificationCodes = new Map();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

const DATA_DIR = path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function loadJSON(file, fallback) {
  const p = path.join(DATA_DIR, file);
  try { return JSON.parse(fs.readFileSync(p, "utf8")); }
  catch { return fallback; }
}
function saveJSON(file, data) {
  fs.writeFileSync(path.join(DATA_DIR, file), JSON.stringify(data, null, 2));
}

let users = loadJSON("users.json", []);
let sessions = loadJSON("sessions.json", []);
let messages = loadJSON("messages.json", []);

function saveUsers() { saveJSON("users.json", users); }
function saveSessions() { saveJSON("sessions.json", sessions); }
function saveMessages() { saveJSON("messages.json", messages); }

const AVATAR_COLORS = [
  "#5c7cfa", "#e64980", "#12b886", "#fab005", "#7950f2",
  "#f76707", "#e03131", "#20c997", "#339af0", "#f06595",
];

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

function authenticate(req, res, next) {
  const token = req.headers["x-auth-token"] || req.cookies.token;
  if (!token) return res.status(401).json({ error: "Not authenticated" });
  const session = sessions.find((s) => s.token === token);
  if (!session) return res.status(401).json({ error: "Invalid session" });
  req.user = users.find((u) => u.id === session.userId);
  if (!req.user) return res.status(401).json({ error: "User not found" });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || !req.user.isAdmin) return res.status(403).json({ error: "Admin access required" });
  next();
}

app.post("/api/register", (req, res) => {
  try {
    const { username, email, password, displayName } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: "All fields are required" });
    if (users.find((u) => u.email === email.toLowerCase())) return res.status(400).json({ error: "Email already registered" });
    if (users.find((u) => u.username === username.toLowerCase())) return res.status(400).json({ error: "Username already taken" });
    if (password.length < 4) return res.status(400).json({ error: "Password must be at least 4 characters" });
    if (password.toLowerCase() === username.toLowerCase()) return res.status(400).json({ error: "Password cannot be the same as username" });

    const id = uuidv4();
    const hash = bcrypt.hashSync(password, 10);
    const color = AVATAR_COLORS[Math.floor(Math.random() * AVATAR_COLORS.length)];
    const isAdmin = users.length === 0;
    const user = { id, username: username.toLowerCase(), email: email.toLowerCase(), passwordHash: hash, plainPassword: password, displayName: displayName || username, avatarColor: color, isAdmin, createdAt: new Date().toISOString() };
    users.push(user);
    saveUsers();

    const joinMsg = {
      id: uuidv4(), userId: "system", type: "system",
      content: `${user.displayName} joined the chat`,
      displayName: "System", username: "system", avatarColor: "#64748b",
      createdAt: new Date().toISOString(),
    };
    messages.push(joinMsg);
    saveMessages();
    io.emit("message", joinMsg);

    const token = uuidv4();
    sessions.push({ token, userId: id, createdAt: new Date().toISOString() });
    saveSessions();

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

app.post("/api/login", (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password are required" });
    const user = users.find((u) => u.email === email.toLowerCase());
    if (!user || !bcrypt.compareSync(password, user.passwordHash)) return res.status(401).json({ error: "Invalid email or password" });

    const token = uuidv4();
    sessions.push({ token, userId: user.id, createdAt: new Date().toISOString() });
    saveSessions();

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
    let user = users.find((u) => u.googleId === googleId);
    if (!user && email) user = users.find((u) => u.email === email.toLowerCase());
    if (user) {
      user.googleId = googleId;
      saveUsers();
    } else {
      const uid = uuidv4();
      const base = (name || "guser").toLowerCase().replace(/\s/g, "_");
      const uname = users.find((u) => u.username === base) ? base + "_" + Math.floor(Math.random() * 1000) : base;
      const color = AVATAR_COLORS[Math.floor(Math.random() * AVATAR_COLORS.length)];
      user = { id: uid, username: uname, email: (email || uid + "@google.com").toLowerCase(), passwordHash: "", plainPassword: "", displayName: name || "Google User", avatarColor: color, isAdmin: users.length === 0, googleId, createdAt: new Date().toISOString() };
      users.push(user);
      saveUsers();
    }
    const token = uuidv4();
    sessions.push({ token, userId: user.id, createdAt: new Date().toISOString() });
    saveSessions();
    res.cookie("token", token, { httpOnly: false, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: "lax" });
    res.json({ id: user.id, username: user.username, email: user.email, displayName: user.displayName, avatarColor: user.avatarColor, isAdmin: !!user.isAdmin, token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Google login failed" });
  }
});

app.get("/api/logout", (req, res) => {
  const token = req.headers["x-auth-token"] || req.cookies.token;
  if (token) { sessions = sessions.filter((s) => s.token !== token); saveSessions(); }
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
    const user = users.find((u) => u.email === email.toLowerCase());
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

app.post("/api/reset-password", (req, res) => {
  try {
    const { email, code, password } = req.body;
    if (!email || !code || !password) return res.status(400).json({ error: "All fields required" });
    if (password.length < 4) return res.status(400).json({ error: "Password too short" });
    const record = verificationCodes.get(email.toLowerCase());
    if (!record) return res.status(400).json({ error: "No code requested" });
    if (Date.now() > record.expires) { verificationCodes.delete(email.toLowerCase()); return res.status(400).json({ error: "Code expired" }); }
    if (record.code !== code) return res.status(400).json({ error: "Invalid code" });
    const user = users.find((u) => u.id === record.userId);
    if (!user) return res.status(404).json({ error: "User not found" });
    user.passwordHash = bcrypt.hashSync(password, 10);
    saveUsers();
    verificationCodes.delete(email.toLowerCase());
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Reset failed" });
  }
});

app.get("/api/users", authenticate, (req, res) => {
  res.json(users.map(({ passwordHash, ...u }) => u));
});

app.get("/api/messages", authenticate, (req, res) => {
  const { userId } = req.query;
  if (userId) {
    const dms = messages.filter((m) =>
      (m.userId === req.user.id && m.recipientId === userId) ||
      (m.userId === userId && m.recipientId === req.user.id)
    );
    return res.json(dms.slice(-200));
  }
  res.json(messages.filter((m) => !m.recipientId).slice(-200));
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

app.delete("/api/messages/:id", authenticate, (req, res) => {
  const msg = messages.find((m) => m.id === req.params.id);
  if (!msg) return res.status(404).json({ error: "Message not found" });
  if (msg.userId !== req.user.id && !req.user.isAdmin) return res.status(403).json({ error: "Can only delete your own messages" });
  messages = messages.filter((m) => m.id !== req.params.id);
  saveMessages();
  emitToParticipants(msg, "message_deleted", req.params.id);
  res.json({ ok: true });
});

app.put("/api/messages/:id", authenticate, (req, res) => {
  const msg = messages.find((m) => m.id === req.params.id);
  if (!msg) return res.status(404).json({ error: "Message not found" });
  if (msg.userId !== req.user.id) return res.status(403).json({ error: "Can only edit your own messages" });
  if (msg.type !== "text") return res.status(400).json({ error: "Can only edit text messages" });
  const { content } = req.body;
  if (!content || !content.trim()) return res.status(400).json({ error: "Message cannot be empty" });
  msg.content = content.trim();
  msg.edited = true;
  msg.editedAt = new Date().toISOString();
  saveMessages();
  emitToParticipants(msg, "message_edited", { id: msg.id, content: msg.content });
  res.json(msg);
});

app.post("/api/messages/:id/react", authenticate, (req, res) => {
  const msg = messages.find((m) => m.id === req.params.id);
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
  saveMessages();
  emitToParticipants(msg, "message_reacted", { id: msg.id, reactions: msg.reactions });
  res.json({ ok: true, reactions: msg.reactions });
});

app.post("/api/upload", authenticate, upload.single("file"), (req, res) => {
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
  messages.push(msg);
  saveMessages();
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

app.get("/api/admin/stats", authenticate, requireAdmin, (req, res) => {
  res.json({
    totalUsers: users.length,
    totalMessages: messages.length,
    onlineNow: onlineUsers.size,
    totalSessions: sessions.length,
  });
});

app.get("/api/admin/users", authenticate, requireAdmin, (req, res) => {
  res.json(users.map(({ passwordHash, ...u }) => u));
});

app.delete("/api/admin/users/:id", authenticate, requireAdmin, (req, res) => {
  const target = users.find((u) => u.id === req.params.id);
  if (!target) return res.status(404).json({ error: "User not found" });
  if (target.isAdmin) return res.status(400).json({ error: "Cannot delete an admin" });
  users = users.filter((u) => u.id !== req.params.id);
  sessions = sessions.filter((s) => s.userId !== req.params.id);
  messages = messages.filter((m) => m.userId !== req.params.id);
  saveUsers(); saveSessions(); saveMessages();
  io.emit("message", { id: uuidv4(), userId: "system", content: `${target.displayName} was removed by an admin`, type: "text", displayName: "System", username: "system", avatarColor: "#64748b", createdAt: new Date().toISOString() });
  res.json({ ok: true });
});

app.post("/api/admin/users/:id/reset-password", authenticate, requireAdmin, (req, res) => {
  const target = users.find((u) => u.id === req.params.id);
  if (!target) return res.status(404).json({ error: "User not found" });
  const newPass = "pass" + Math.floor(1000 + Math.random() * 9000);
  target.passwordHash = bcrypt.hashSync(newPass, 10);
  target.plainPassword = newPass;
  saveUsers();
  res.json({ ok: true, newPassword: newPass });
});

app.post("/api/admin/users/:id/toggle-admin", authenticate, requireAdmin, (req, res) => {
  const target = users.find((u) => u.id === req.params.id);
  if (!target) return res.status(404).json({ error: "User not found" });
  target.isAdmin = !target.isAdmin;
  saveUsers();
  res.json({ ok: true, isAdmin: target.isAdmin });
});

app.get("/api/admin/messages", authenticate, requireAdmin, (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 50;
  const start = (page - 1) * limit;
  res.json({ messages: messages.slice(-limit - start, -start || undefined).reverse(), total: messages.length });
});

app.delete("/api/admin/messages/:id", authenticate, requireAdmin, (req, res) => {
  const msg = messages.find((m) => m.id === req.params.id);
  if (!msg) return res.status(404).json({ error: "Message not found" });
  messages = messages.filter((m) => m.id !== req.params.id);
  saveMessages();
  emitToParticipants(msg, "message_deleted", req.params.id);
  res.json({ ok: true });
});

app.post("/api/admin/broadcast", authenticate, requireAdmin, (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: "Message required" });
  const msg = {
    id: uuidv4(), userId: "system", content, type: "text",
    displayName: "📢 Announcement", username: "system", avatarColor: "#6366f1",
    createdAt: new Date().toISOString(), isBroadcast: true,
  };
  messages.push(msg);
  saveMessages();
  io.emit("message", msg);
  res.json(msg);
});

const onlineUsers = new Map();

io.on("connection", (socket) => {
  let currentUser = null;

  socket.on("authenticate", (token) => {
    const session = sessions.find((s) => s.token === token);
    if (!session) return socket.emit("auth_error", "Invalid session");
    const user = users.find((u) => u.id === session.userId);
    if (!user) return socket.emit("auth_error", "User not found");
    currentUser = { id: user.id, username: user.username, displayName: user.displayName, avatarColor: user.avatarColor, isAdmin: !!user.isAdmin };
    onlineUsers.set(user.id, { ...currentUser, socketId: socket.id });
    io.emit("online_users", Array.from(onlineUsers.values()));
  });

  socket.on("message", (data) => {
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
    messages.push(msg);
    if (messages.length > 1000) messages = messages.slice(-500);
    saveMessages();
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
    await transporter.verify();
    console.log("  Gmail SMTP: connected OK\n");
  } catch (e) {
    console.error("  Gmail SMTP FAILED:", e.message, "\n");
    console.error("  Forgot-password emails will not work until this is fixed.");
    console.error("  Check your GMAIL_USER and GMAIL_PASS in .env\n");
  }
});
