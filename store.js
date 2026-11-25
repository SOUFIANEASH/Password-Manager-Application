// Data storage: users.json (hashed credentials) and one CSV file per user.
// While a user is logged in, <user>.csv exists in plain form (passwords still AES-encrypted per entry).
// On logout/close the whole file is encrypted with AES into <user>.csv.enc and the plain CSV is deleted.
const fs = require("fs");
const path = require("path");
const C = require("./crypto-utils");

const DATA_DIR = process.env.PM_DATA || path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const HEADER = ["Title", "EncryptedPassword", "URL", "Notes"];

fs.mkdirSync(DATA_DIR, { recursive: true });

const csvPath = (u) => path.join(DATA_DIR, `${u}.csv`);
const encPath = (u) => path.join(DATA_DIR, `${u}.csv.enc`);

// ---------- CSV (RFC 4180 quoting) ----------
const quote = (v) => `"${String(v).replace(/"/g, '""')}"`;
function toCsv(entries) {
  const lines = [HEADER.join(",")];
  for (const e of entries) lines.push([e.title, e.encryptedPassword, e.url, e.notes].map(quote).join(","));
  return lines.join("\n") + "\n";
}
function parseCsv(text) {
  const rows = []; let row = [], field = "", inQ = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQ) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') inQ = false;
      else field += c;
    } else if (c === '"') inQ = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field); field = ""; rows.push(row); row = [];
    } else field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows.slice(1).filter((r) => r.length >= 4)
    .map(([title, encryptedPassword, url, notes]) => ({ title, encryptedPassword, url, notes }));
}

// ---------- users ----------
const readUsers = () => (fs.existsSync(USERS_FILE) ? JSON.parse(fs.readFileSync(USERS_FILE, "utf8")) : {});
const writeUsers = (u) => fs.writeFileSync(USERS_FILE, JSON.stringify(u, null, 2));

function register(username, password) {
  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username || "")) throw new Error("Username: 3-32 letters, digits, . _ -");
  if (typeof password !== "string" || password.length < 8) throw new Error("Master password must be at least 8 characters");
  const users = readUsers();
  if (users[username.toLowerCase()]) throw new Error("Username already taken");
  users[username.toLowerCase()] = { username, auth: C.hashPassword(password), keySalt: C.newSalt() };
  writeUsers(users);
  fs.writeFileSync(csvPath(username.toLowerCase()), toCsv([])); // new data file created on first start
  // encrypt it right away so nothing sits unprotected until the first login
  const key = C.deriveKey(password, users[username.toLowerCase()].keySalt);
  lock(username.toLowerCase(), key);
}

/** Check credentials; returns { name, key } on success. */
function authenticate(username, password) {
  const rec = readUsers()[String(username).toLowerCase()];
  if (!rec || !C.verifyPassword(String(password), rec.auth)) throw new Error("Invalid username or password");
  return { name: String(username).toLowerCase(), key: C.deriveKey(String(password), rec.keySalt) };
}

// ---------- file lifecycle ----------
/** Decrypt <user>.csv.enc -> <user>.csv and load the entries. */
function unlock(name, key) {
  if (!fs.existsSync(csvPath(name))) {
    if (!fs.existsSync(encPath(name))) fs.writeFileSync(csvPath(name), toCsv([]));
    else fs.writeFileSync(csvPath(name), C.decryptBytes(key, fs.readFileSync(encPath(name))));
  }
  return parseCsv(fs.readFileSync(csvPath(name), "utf8"));
}
const save = (name, entries) => fs.writeFileSync(csvPath(name), toCsv(entries));

/** Encrypt <user>.csv with AES -> <user>.csv.enc and delete the plain CSV. */
function lock(name, key) {
  if (!fs.existsSync(csvPath(name))) return;
  fs.writeFileSync(encPath(name), C.encryptBytes(key, fs.readFileSync(csvPath(name))));
  fs.unlinkSync(csvPath(name));
}

module.exports = { register, authenticate, unlock, save, lock, toCsv, parseCsv, DATA_DIR };
