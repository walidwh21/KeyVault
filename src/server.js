import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createApp } from "./app.js";
import { Store } from "./store.js";
import { parseMasterKey } from "./crypto.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const masterKey = parseMasterKey(process.env.VAULT_MASTER_KEY);
const tokenSecret = process.env.TOKEN_SECRET;
if (!tokenSecret || tokenSecret.length < 32) throw new Error("TOKEN_SECRET must be at least 32 characters");

const app = createApp({ store: new Store(process.env.DATA_FILE ?? "./data.json"), masterKey, tokenSecret });
const page = fs.readFileSync(path.join(here, "../public/index.html"));

http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  if (req.method === "GET" && url.pathname === "/") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "x-content-type-options": "nosniff" });
    return res.end(page);
  }
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > 16_384) { res.writeHead(413).end(); return; }
    chunks.push(c);
  }
  let body = {};
  try { body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {}; }
  catch { res.writeHead(400).end(JSON.stringify({ error: "Invalid JSON" })); return; }
  const out = await app.handle(req.method, url.pathname, body, req.headers, req.socket.remoteAddress);
  res.writeHead(out.status, { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff" });
  res.end(out.body === null ? undefined : JSON.stringify(out.body));
}).listen(Number(process.env.PORT ?? 4000), () => console.log("keyvault-lite listening"));
