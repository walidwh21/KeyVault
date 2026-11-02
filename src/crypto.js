import crypto from "node:crypto";

const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 32, SCRYPT);
  return `scrypt$${salt.toString("base64")}$${hash.toString("base64")}`;
}

export function verifyPassword(password, stored) {
  const [scheme, saltB64, hashB64] = String(stored).split("$");
  if (scheme !== "scrypt" || !saltB64 || !hashB64) return false;
  const expected = Buffer.from(hashB64, "base64");
  const actual = crypto.scryptSync(password, Buffer.from(saltB64, "base64"), expected.length, SCRYPT);
  return crypto.timingSafeEqual(actual, expected);
}

export function parseMasterKey(hex) {
  if (typeof hex !== "string" || !/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error("VAULT_MASTER_KEY must be 64 hex characters (32 bytes)");
  }
  return Buffer.from(hex, "hex");
}

function gcmEncrypt(key, plaintext, aad) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  if (aad) cipher.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { ct: ct.toString("base64"), iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64") };
}

function gcmDecrypt(key, box, aad) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(box.iv, "base64"));
  if (aad) decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(Buffer.from(box.tag, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(box.ct, "base64")), decipher.final()]);
}

/** Envelope encryption: a fresh data key per secret, wrapped by the master key. */
export function seal(secret, masterKey, aad) {
  const dataKey = crypto.randomBytes(32);
  try {
    return { body: gcmEncrypt(dataKey, secret, aad), wrapped: gcmEncrypt(masterKey, dataKey, aad) };
  } finally {
    dataKey.fill(0);
  }
}

export function open(envelope, masterKey, aad) {
  const dataKey = gcmDecrypt(masterKey, envelope.wrapped, aad);
  try {
    return gcmDecrypt(dataKey, envelope.body, aad);
  } finally {
    dataKey.fill(0);
  }
}

export function newKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  return {
    privateDer: privateKey.export({ type: "pkcs8", format: "der" }),
    publicDer,
    address: "kv_" + crypto.createHash("sha256").update(publicDer).digest("hex").slice(0, 40),
  };
}

export function signWith(privateDer, data) {
  const key = crypto.createPrivateKey({ key: privateDer, format: "der", type: "pkcs8" });
  return crypto.sign(null, Buffer.from(data), key);
}

export function verifyWith(publicDer, data, signature) {
  const key = crypto.createPublicKey({ key: publicDer, format: "der", type: "spki" });
  return crypto.verify(null, Buffer.from(data), key, signature);
}
