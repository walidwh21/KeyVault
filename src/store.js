import fs from "node:fs";

/** Tiny JSON-file store. Swap for a real database in production. */
export class Store {
  constructor(file = null) {
    this.file = file;
    this.data = { users: {}, wallets: {}, refresh: {}, ledger: [] };
    if (file && fs.existsSync(file)) this.data = JSON.parse(fs.readFileSync(file, "utf8"));
  }

  save() {
    if (!this.file) return;
    const tmp = this.file + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(this.data), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }

  findUserByEmail(email) {
    return Object.values(this.data.users).find((u) => u.email === email) ?? null;
  }
}
