import crypto from "node:crypto";

const b64 = (buf) => Buffer.from(buf).toString("base64url");

export function signToken(claims, secret) {
  const body = b64(JSON.stringify(claims));
  const mac = crypto.createHmac("sha256", secret).update(body).digest("base64url");
  return `${body}.${mac}`;
}

export function verifyToken(token, secret, now = Date.now()) {
  if (typeof token !== "string") return null;
  const [body, mac] = token.split(".");
  if (!body || !mac) return null;
  const expected = crypto.createHmac("sha256", secret).update(body).digest();
  const given = Buffer.from(mac, "base64url");
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
  try {
    const claims = JSON.parse(Buffer.from(body, "base64url").toString());
    return claims.exp > now ? claims : null;
  } catch {
    return null;
  }
}

export const newId = () => crypto.randomUUID();
