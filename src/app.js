import { hashPassword, verifyPassword, seal, open, newKeyPair, signWith, verifyWith } from "./crypto.js";
import { signToken, verifyToken, newId } from "./tokens.js";

const ACCESS_TTL = 10 * 60 * 1000;
const REFRESH_TTL = 7 * 24 * 60 * 60 * 1000;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/**
 * Framework-free request handler. `handle(method, path, body, headers, ip)`
 * returns { status, body } so it can be tested without opening a socket.
 */
export function createApp({ store, masterKey, tokenSecret, now = () => Date.now(), authLimit = 10 }) {
  const hits = new Map();

  function limit(ip) {
    const bucket = Math.floor(now() / 60000);
    const key = `${ip}:${bucket}`;
    const n = (hits.get(key) ?? 0) + 1;
    hits.set(key, n);
    for (const k of hits.keys()) if (!k.endsWith(`:${bucket}`)) hits.delete(k);
    if (n > authLimit) throw new HttpError(429, "Too many attempts, slow down");
  }

  function issuePair(userId) {
    const jti = newId();
    const t = now();
    store.data.refresh[jti] = { userId, exp: t + REFRESH_TTL, used: false };
    store.save();
    return {
      accessToken: signToken({ sub: userId, typ: "access", exp: t + ACCESS_TTL }, tokenSecret),
      refreshToken: signToken({ sub: userId, typ: "refresh", jti, exp: t + REFRESH_TTL }, tokenSecret),
    };
  }

  function authed(headers) {
    const raw = headers.authorization ?? "";
    const claims = verifyToken(raw.replace(/^Bearer /, ""), tokenSecret, now());
    if (!claims || claims.typ !== "access" || !store.data.users[claims.sub]) throw new HttpError(401, "Unauthorized");
    return claims.sub;
  }

  function ownedWallet(userId, id) {
    const w = store.data.wallets[id];
    if (!w || w.userId !== userId) throw new HttpError(404, "Wallet not found");
    return w;
  }

  const publicWallet = (w) => ({ id: w.id, label: w.label, address: w.address, balance: w.balance });

  const routes = [
    ["POST", /^\/auth\/register$/, (ctx) => {
      limit(ctx.ip);
      const { email, password } = ctx.body;
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email ?? "")) throw new HttpError(400, "Valid email required");
      if (typeof password !== "string" || password.length < 10) throw new HttpError(400, "Password needs 10+ characters");
      if (store.findUserByEmail(email.toLowerCase())) throw new HttpError(409, "Email already registered");
      const id = newId();
      store.data.users[id] = { id, email: email.toLowerCase(), passwordHash: hashPassword(password) };
      return { status: 201, body: { id, ...issuePair(id) } };
    }],
    ["POST", /^\/auth\/login$/, (ctx) => {
      limit(ctx.ip);
      const user = store.findUserByEmail(String(ctx.body.email ?? "").toLowerCase());
      const ok = user && verifyPassword(String(ctx.body.password ?? ""), user.passwordHash);
      if (!ok) throw new HttpError(401, "Invalid credentials");
      return { status: 200, body: issuePair(user.id) };
    }],
    ["POST", /^\/auth\/refresh$/, (ctx) => {
      const claims = verifyToken(ctx.body.refreshToken, tokenSecret, now());
      if (!claims || claims.typ !== "refresh") throw new HttpError(401, "Invalid refresh token");
      const record = store.data.refresh[claims.jti];
      if (!record) throw new HttpError(401, "Invalid refresh token");
      if (record.used) {
        // Reuse of a rotated token: assume theft and revoke the whole family.
        for (const [k, v] of Object.entries(store.data.refresh)) if (v.userId === record.userId) delete store.data.refresh[k];
        store.save();
        throw new HttpError(401, "Refresh token reuse detected; sessions revoked");
      }
      record.used = true;
      return { status: 200, body: issuePair(claims.sub) };
    }],
    ["POST", /^\/auth\/logout$/, (ctx) => {
      const userId = authed(ctx.headers);
      for (const [k, v] of Object.entries(store.data.refresh)) if (v.userId === userId) delete store.data.refresh[k];
      return { status: 204, body: null };
    }],
    ["POST", /^\/wallets$/, (ctx) => {
      const userId = authed(ctx.headers);
      const id = newId();
      const kp = newKeyPair();
      const envelope = seal(kp.privateDer, masterKey, `wallet:${id}`);
      kp.privateDer.fill(0);
      store.data.wallets[id] = {
        id, userId, label: String(ctx.body.label ?? "Wallet").slice(0, 40),
        address: kp.address, publicKey: kp.publicDer.toString("base64"), envelope, balance: 0,
      };
      return { status: 201, body: publicWallet(store.data.wallets[id]) };
    }],
    ["GET", /^\/wallets$/, (ctx) => {
      const userId = authed(ctx.headers);
      const list = Object.values(store.data.wallets).filter((w) => w.userId === userId).map(publicWallet);
      return { status: 200, body: list };
    }],
    ["POST", /^\/wallets\/([\w-]+)\/faucet$/, (ctx, id) => {
      const w = ownedWallet(authed(ctx.headers), id);
      w.balance += 100;
      return { status: 200, body: publicWallet(w) };
    }],
    ["POST", /^\/wallets\/([\w-]+)\/sign$/, (ctx, id) => {
      const w = ownedWallet(authed(ctx.headers), id);
      if (typeof ctx.body.message !== "string" || !ctx.body.message) throw new HttpError(400, "message required");
      const priv = open(w.envelope, masterKey, `wallet:${w.id}`);
      try {
        return { status: 200, body: { address: w.address, signature: signWith(priv, ctx.body.message).toString("base64") } };
      } finally {
        priv.fill(0);
      }
    }],
    ["POST", /^\/wallets\/([\w-]+)\/transfer$/, (ctx, id) => {
      const w = ownedWallet(authed(ctx.headers), id);
      const amount = ctx.body.amount;
      const dest = Object.values(store.data.wallets).find((x) => x.address === ctx.body.to);
      if (!dest) throw new HttpError(404, "Destination address unknown");
      if (dest.id === w.id) throw new HttpError(400, "Cannot send to the same wallet");
      if (!Number.isInteger(amount) || amount <= 0) throw new HttpError(400, "amount must be a positive integer");
      if (amount > w.balance) throw new HttpError(422, "Insufficient balance");
      const entry = { id: newId(), from: w.address, to: dest.address, amount, at: now() };
      const priv = open(w.envelope, masterKey, `wallet:${w.id}`);
      try {
        entry.signature = signWith(priv, JSON.stringify([entry.id, entry.from, entry.to, entry.amount, entry.at])).toString("base64");
      } finally {
        priv.fill(0);
      }
      w.balance -= amount;
      dest.balance += amount;
      store.data.ledger.push(entry);
      return { status: 201, body: entry };
    }],
    ["GET", /^\/wallets\/([\w-]+)\/history$/, (ctx, id) => {
      const w = ownedWallet(authed(ctx.headers), id);
      const rows = store.data.ledger.filter((e) => e.from === w.address || e.to === w.address);
      return { status: 200, body: rows.map((e) => ({ ...e, verified: verifyWith(Buffer.from(store.data.wallets[Object.keys(store.data.wallets).find((k) => store.data.wallets[k].address === e.from)].publicKey, "base64"), JSON.stringify([e.id, e.from, e.to, e.amount, e.at]), Buffer.from(e.signature, "base64")) })) };
    }],
  ];

  async function handle(method, path, body = {}, headers = {}, ip = "local") {
    try {
      for (const [m, re, fn] of routes) {
        const match = m === method && re.exec(path);
        if (match) {
          const out = fn({ body: body ?? {}, headers, ip }, ...match.slice(1));
          store.save();
          return out;
        }
      }
      throw new HttpError(404, "Not found");
    } catch (err) {
      if (err instanceof HttpError) return { status: err.status, body: { error: err.message } };
      console.error(err);
      return { status: 500, body: { error: "Internal error" } };
    }
  }

  return { handle, store };
}
