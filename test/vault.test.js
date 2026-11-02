import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { createApp } from "../src/app.js";
import { Store } from "../src/store.js";
import { seal, open, hashPassword, verifyPassword } from "../src/crypto.js";

const masterKey = crypto.randomBytes(32);
const tokenSecret = "x".repeat(40);
const fresh = (extra = {}) => createApp({ store: new Store(), masterKey, tokenSecret, ...extra });
const auth = (t) => ({ authorization: `Bearer ${t}` });

async function signup(app, email = "a@example.com") {
  const r = await app.handle("POST", "/auth/register", { email, password: "correct horse battery" });
  assert.equal(r.status, 201);
  return r.body;
}

test("envelope encryption round-trips and binds to AAD", () => {
  const env = seal(Buffer.from("secret"), masterKey, "wallet:1");
  assert.equal(open(env, masterKey, "wallet:1").toString(), "secret");
  assert.throws(() => open(env, masterKey, "wallet:2"));
  assert.throws(() => open(env, crypto.randomBytes(32), "wallet:1"));
});

test("password hashing uses random salts", () => {
  const a = hashPassword("hunter2hunter2");
  assert.notEqual(a, hashPassword("hunter2hunter2"));
  assert.ok(verifyPassword("hunter2hunter2", a));
  assert.ok(!verifyPassword("wrong-password", a));
});

test("wallet private key is never stored or returned in plaintext", async () => {
  const app = fresh();
  const u = await signup(app);
  const w = await app.handle("POST", "/wallets", { label: "main" }, auth(u.accessToken));
  assert.equal(w.status, 201);
  assert.ok(!JSON.stringify(w.body).includes("envelope"));
  // ed25519 PKCS#8 DER always begins with this base64 prefix; it must not appear in storage.
  const stored = JSON.stringify(app.store.data);
  assert.ok(!stored.includes("MC4CAQAwBQYDK2VwBCIEI"));
  assert.ok(stored.includes("wrapped"));
});

test("signing and verified, signed transfers", async () => {
  const app = fresh();
  const u = await signup(app);
  const a = (await app.handle("POST", "/wallets", { label: "a" }, auth(u.accessToken))).body;
  const b = (await app.handle("POST", "/wallets", { label: "b" }, auth(u.accessToken))).body;
  await app.handle("POST", `/wallets/${a.id}/faucet`, {}, auth(u.accessToken));
  const t = await app.handle("POST", `/wallets/${a.id}/transfer`, { to: b.address, amount: 30 }, auth(u.accessToken));
  assert.equal(t.status, 201);
  const hist = await app.handle("GET", `/wallets/${b.id}/history`, {}, auth(u.accessToken));
  assert.equal(hist.body[0].verified, true);
  const list = (await app.handle("GET", "/wallets", {}, auth(u.accessToken))).body;
  assert.deepEqual(list.map((w) => w.balance).sort((x, y) => x - y), [30, 70]);
  const over = await app.handle("POST", `/wallets/${a.id}/transfer`, { to: b.address, amount: 1000 }, auth(u.accessToken));
  assert.equal(over.status, 422);
});

test("users cannot touch each other's wallets", async () => {
  const app = fresh();
  const u1 = await signup(app, "one@example.com");
  const u2 = await signup(app, "two@example.com");
  const w = (await app.handle("POST", "/wallets", {}, auth(u1.accessToken))).body;
  const r = await app.handle("POST", `/wallets/${w.id}/sign`, { message: "hi" }, auth(u2.accessToken));
  assert.equal(r.status, 404);
});

test("refresh rotation works once and reuse revokes the family", async () => {
  const app = fresh();
  const u = await signup(app);
  const r1 = await app.handle("POST", "/auth/refresh", { refreshToken: u.refreshToken });
  assert.equal(r1.status, 200);
  const replay = await app.handle("POST", "/auth/refresh", { refreshToken: u.refreshToken });
  assert.equal(replay.status, 401);
  const after = await app.handle("POST", "/auth/refresh", { refreshToken: r1.body.refreshToken });
  assert.equal(after.status, 401);
});

test("expired access tokens are rejected", async () => {
  let t = 1_000_000;
  const app = fresh({ now: () => t });
  const u = await signup(app);
  t += 11 * 60 * 1000;
  const r = await app.handle("GET", "/wallets", {}, auth(u.accessToken));
  assert.equal(r.status, 401);
});

test("auth endpoints are rate limited", async () => {
  const app = fresh({ authLimit: 3 });
  let last;
  for (let i = 0; i < 5; i++) last = await app.handle("POST", "/auth/login", { email: "x@y.zz", password: "nope" });
  assert.equal(last.status, 429);
});
