// Password Manager - local web server (http://localhost:3000). No external packages.
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const S = require("./store");
const C = require("./crypto-utils");

const PORT = +process.env.PM_PORT || 3000;
const IDLE_MS = 15 * 60 * 1000;
const sessions = new Map(); // token -> { name, key, entries, last }

// ---------- logout / close: encrypt the user's file ----------
function closeSession(token) {
  const s = sessions.get(token);
  if (!s) return;
  S.save(s.name, s.entries);
  S.lock(s.name, s.key);
  sessions.delete(token);
}
function closeAll() { for (const t of [...sessions.keys()]) closeSession(t); }

let shuttingDown = false;
function shutdown(code = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  closeAll();
  console.log("All user files encrypted. Bye.");
  process.exit(code);
}
process.on("SIGINT", () => shutdown());
process.on("SIGTERM", () => shutdown());
setInterval(() => { // auto logout when idle
  for (const [t, s] of sessions) if (Date.now() - s.last > IDLE_MS) closeSession(t);
}, 30000).unref();

// ---------- helpers ----------
const findIdx = (entries, title) => entries.findIndex((e) => e.title.toLowerCase() === String(title).trim().toLowerCase());
const publicView = (e) => ({ title: e.title, url: e.url, notes: e.notes }); // never includes the password

function cookieToken(req) {
  const m = /(?:^|;\s*)sid=([a-f0-9]{64})/.exec(req.headers.cookie || "");
  return m ? m[1] : null;
}
function needSession(req) {
  const t = cookieToken(req);
  const s = t && sessions.get(t);
  if (!s) { const e = new Error("Not logged in"); e.status = 401; throw e; }
  s.last = Date.now();
  return { token: t, s };
}
function cleanTitle(t) {
  t = String(t || "").trim();
  if (!t) throw new Error("Title is required");
  return t;
}

// ---------- API ----------
const api = {
  register: ({ username, password }) => { S.register(username, password); return { ok: true }; },

  login: ({ username, password }, req, res) => {
    const { name, key } = S.authenticate(username, password);
    for (const [t, s] of sessions) if (s.name === name) closeSession(t); // one session per user
    const entries = S.unlock(name, key); // decrypt file on login
    const token = crypto.randomBytes(32).toString("hex");
    sessions.set(token, { name, key, entries, last: Date.now() });
    res.setHeader("Set-Cookie", `sid=${token}; HttpOnly; SameSite=Strict; Path=/`);
    return { ok: true, username: name };
  },

  logout: (_b, req, res) => {
    const t = cookieToken(req);
    if (t) closeSession(t); // encrypt file on logout
    res.setHeader("Set-Cookie", "sid=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/");
    return { ok: true };
  },

  me: (_b, req) => ({ username: needSession(req).s.name }),

  search: ({ q }, req) => {
    const { s } = needSession(req);
    const needle = String(q || "").trim().toLowerCase();
    return { results: s.entries.filter((e) => e.title.toLowerCase().includes(needle)).map(publicView) };
  },

  add: ({ title, password, url, notes }, req) => {
    const { s } = needSession(req);
    title = cleanTitle(title);
    if (!password) throw new Error("Password is required");
    if (findIdx(s.entries, title) >= 0) throw new Error("An entry with this title already exists");
    s.entries.push({ title, encryptedPassword: C.encryptText(s.key, password), url: url || "", notes: notes || "" });
    S.save(s.name, s.entries);
    return { ok: true };
  },

  update: ({ title, password, url, notes }, req) => {
    const { s } = needSession(req);
    const i = findIdx(s.entries, title);
    if (i < 0) throw new Error("Entry not found");
    const e = s.entries[i];
    if (password) e.encryptedPassword = C.encryptText(s.key, password); // re-encrypted with the same method
    if (url !== undefined) e.url = url;
    if (notes !== undefined) e.notes = notes;
    S.save(s.name, s.entries);
    return { ok: true };
  },

  delete: ({ title }, req) => {
    const { s } = needSession(req);
    const i = findIdx(s.entries, title);
    if (i < 0) throw new Error("Entry not found");
    s.entries.splice(i, 1);
    S.save(s.name, s.entries); // removed from the data file
    return { ok: true };
  },

  reveal: ({ title }, req) => { // password only shown on explicit request
    const { s } = needSession(req);
    const i = findIdx(s.entries, title);
    if (i < 0) throw new Error("Entry not found");
    return { password: C.decryptText(s.key, s.entries[i].encryptedPassword) };
  },

  generate: (opts) => ({ password: C.generatePassword(opts) }),

  quit: () => { setTimeout(() => shutdown(), 100); return { ok: true }; },
};

// ---------- HTTP ----------
const server = http.createServer((req, res) => {
  const m = /^\/api\/(\w+)$/.exec(req.url);
  if (req.method === "GET" && (req.url === "/" || req.url === "/index.html")) {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.end(fs.readFileSync(path.join(__dirname, "public", "index.html")));
  }
  if (req.method === "POST" && m && api[m[1]]) {
    // JSON only: cross-site pages cannot send this without a CORS preflight, which we never allow
    if (!/^application\/json/.test(req.headers["content-type"] || "")) { res.statusCode = 415; return res.end("{}"); }
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      res.setHeader("Content-Type", "application/json");
      try { res.end(JSON.stringify(api[m[1]](body ? JSON.parse(body) : {}, req, res))); }
      catch (e) { res.statusCode = e.status || 400; res.end(JSON.stringify({ error: e.message })); }
    });
    return;
  }
  res.statusCode = 404; res.end("Not found");
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`Password Manager running at http://localhost:${PORT}`);
  console.log("Press Ctrl+C (or use Quit in the page) to close: files get encrypted with AES on exit.");
});
