// End-to-end test of the Password Manager (starts the server with a temporary data folder).
const { spawn } = require("child_process");
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const C = require("./crypto-utils");

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pm-"));
const PORT = 3100;
let cookie = "";
const call = async (name, body) => {
  const r = await fetch(`http://127.0.0.1:${PORT}/api/${name}`, {
    method: "POST", headers: { "Content-Type": "application/json", Cookie: cookie }, body: JSON.stringify(body || {}),
  });
  const sc = r.headers.get("set-cookie");
  if (sc) cookie = sc.split(";")[0];
  return { status: r.status, body: await r.json() };
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const start = () => spawn(process.execPath, ["server.js"], { env: { ...process.env, PM_DATA: dir, PM_PORT: PORT }, stdio: "ignore" });

// unit checks
const key = C.deriveKey("pw", C.newSalt());
assert.strictEqual(C.decryptText(key, C.encryptText(key, "secret")), "secret");
assert.throws(() => C.decryptText(C.deriveKey("other", C.newSalt()), C.encryptText(key, "secret")));
const g = C.generatePassword({ length: 20 });
assert.ok(g.length === 20 && /[a-z]/.test(g) && /[A-Z]/.test(g) && /\d/.test(g) && /[^a-zA-Z0-9]/.test(g));

(async () => {
  let srv = start();
  try {
    await sleep(1000);
    assert.strictEqual((await call("register", { username: "soufiane", password: "short" })).status, 400);
    assert.strictEqual((await call("register", { username: "soufiane", password: "MasterPass123" })).status, 200);
    // file created on first start and encrypted straight away
    assert.ok(fs.existsSync(path.join(dir, "soufiane.csv.enc")) && !fs.existsSync(path.join(dir, "soufiane.csv")));
    assert.ok(!fs.readFileSync(path.join(dir, "users.json"), "utf8").includes("MasterPass123"));

    assert.strictEqual((await call("login", { username: "soufiane", password: "wrong-password" })).status, 400);
    assert.strictEqual((await call("search", {})).status, 401); // not logged in
    assert.strictEqual((await call("login", { username: "soufiane", password: "MasterPass123" })).status, 200);
    assert.ok(fs.existsSync(path.join(dir, "soufiane.csv"))); // decrypted on login

    await call("add", { title: "Gmail", password: "p@ss-GMAIL-1", url: "https://mail.google.com", notes: "personal" });
    await call("add", { title: "GitHub", password: "p@ss-GITHUB-1", url: "https://github.com", notes: "school" });
    assert.strictEqual((await call("add", { title: "gmail", password: "x" })).status, 400); // duplicate title

    const csv = fs.readFileSync(path.join(dir, "soufiane.csv"), "utf8");
    assert.ok(csv.startsWith("Title,EncryptedPassword,URL,Notes") && !csv.includes("p@ss-GMAIL-1")); // password encrypted

    const s = (await call("search", { q: "git" })).body.results;
    assert.strictEqual(s.length, 1);
    assert.ok(!("password" in s[0]) && !JSON.stringify(s).includes("p@ss")); // not shown immediately
    assert.strictEqual((await call("reveal", { title: "GitHub" })).body.password, "p@ss-GITHUB-1");

    await call("update", { title: "GitHub", password: "NEW-pass-2", notes: "updated" });
    assert.strictEqual((await call("reveal", { title: "GitHub" })).body.password, "NEW-pass-2");
    await call("delete", { title: "Gmail" });
    assert.ok(!fs.readFileSync(path.join(dir, "soufiane.csv"), "utf8").includes("Gmail")); // removed from file
    assert.strictEqual((await call("search", { q: "" })).body.results.length, 1);

    // logout encrypts the file
    await call("logout");
    assert.ok(!fs.existsSync(path.join(dir, "soufiane.csv")));
    const enc = fs.readFileSync(path.join(dir, "soufiane.csv.enc"));
    assert.ok(!enc.toString("utf8").includes("GitHub"));

    // login again -> decrypt -> data still there; then close the app with SIGINT -> file encrypted
    await call("login", { username: "soufiane", password: "MasterPass123" });
    assert.strictEqual((await call("reveal", { title: "GitHub" })).body.password, "NEW-pass-2");
    srv.kill("SIGINT");
    await sleep(800);
    assert.ok(!fs.existsSync(path.join(dir, "soufiane.csv")) && fs.existsSync(path.join(dir, "soufiane.csv.enc")));

    // restart server: data survives
    srv = start(); await sleep(1000);
    await call("login", { username: "soufiane", password: "MasterPass123" });
    assert.strictEqual((await call("reveal", { title: "GitHub" })).body.password, "NEW-pass-2");
    console.log("all tests passed");
  } finally {
    srv.kill("SIGINT");
    await sleep(300);
    fs.rmSync(dir, { recursive: true, force: true });
  }
})().catch((e) => { console.error(e); process.exit(1); });
