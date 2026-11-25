// Cryptography helpers: scrypt (hashing + key derivation) and AES-256-GCM (encryption).
const crypto = require("crypto");

const scrypt = (password, salt, len) =>
  crypto.scryptSync(password, salt, len, { N: 16384, r: 8, p: 1 });

/** Hash a login password with scrypt and a random salt (stored in users.json). */
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  return { salt: salt.toString("base64"), hash: scrypt(password, salt, 64).toString("base64") };
}

function verifyPassword(password, record) {
  const expected = Buffer.from(record.hash, "base64");
  const actual = scrypt(password, Buffer.from(record.salt, "base64"), 64);
  return crypto.timingSafeEqual(expected, actual);
}

/** Derive the 256-bit AES key from the master password (separate salt from the login hash). */
function deriveKey(password, saltB64) {
  return scrypt(password, Buffer.from(saltB64, "base64"), 32);
}

const newSalt = () => crypto.randomBytes(16).toString("base64");

/** AES-256-GCM. Output layout: iv (12) | auth tag (16) | ciphertext. */
function encryptBytes(key, data) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(data), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]);
}

function decryptBytes(key, blob) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, blob.subarray(0, 12));
  decipher.setAuthTag(blob.subarray(12, 28));
  return Buffer.concat([decipher.update(blob.subarray(28)), decipher.final()]);
}

const encryptText = (key, text) => encryptBytes(key, Buffer.from(text, "utf8")).toString("base64");
const decryptText = (key, b64) => decryptBytes(key, Buffer.from(b64, "base64")).toString("utf8");

/** Random password generator using a cryptographically secure RNG. */
function generatePassword({ length = 16, lower = true, upper = true, digits = true, symbols = true } = {}) {
  const sets = [];
  if (lower) sets.push("abcdefghijklmnopqrstuvwxyz");
  if (upper) sets.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
  if (digits) sets.push("0123456789");
  if (symbols) sets.push("!@#$%^&*()-_=+[]{};:,.?");
  if (!sets.length) throw new Error("Select at least one character type");
  length = Math.min(Math.max(parseInt(length) || 16, sets.length), 128);
  const all = sets.join("");
  const chars = sets.map((s) => s[crypto.randomInt(s.length)]); // at least one of each type
  while (chars.length < length) chars.push(all[crypto.randomInt(all.length)]);
  for (let i = chars.length - 1; i > 0; i--) { // Fisher-Yates shuffle
    const j = crypto.randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}

module.exports = { hashPassword, verifyPassword, deriveKey, newSalt, encryptBytes, decryptBytes, encryptText, decryptText, generatePassword };
