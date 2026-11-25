# Password Manager

Web-based password manager (Node.js 18+, no npm packages). Runs locally on http://localhost:3000.

## Run
```
node server.js
```
Open http://localhost:3000, register, log in. Close with **Quit app** or `Ctrl+C` so files get encrypted. Tests: `node test.js`.

## Features
**Mandatory**
- Data file created on first start (one CSV per user: `Title,EncryptedPassword,URL,Notes`).
- File encrypted with AES-256-GCM on close/logout (`<user>.csv.enc`, plain CSV deleted) and decrypted on login.
- Add, search by title (password hidden), update (re-encrypted), delete (removed from file).

**Optional**
- Registration/login: master password hashed with scrypt + random salt (`data/users.json`), separate data file per user.
- Decrypt on login, encrypt on logout/close/idle timeout (15 min).
- Random password generator (crypto RNG), reveal on request (auto-hides after 10 s), copy to clipboard.

## Security design
- Master password -> scrypt with a second, separate salt -> 256-bit AES key. The key lives only in memory during a session.
- Each entry password is AES-256-GCM encrypted (random IV, auth tag), stored as Base64; the whole CSV is encrypted again on logout.
- GCM authentication detects a wrong key or a modified file.
- Server listens on 127.0.0.1 only; session cookie is HttpOnly + SameSite=Strict; API accepts JSON only.
- If the master password is lost, the data cannot be recovered.
