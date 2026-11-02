import { exec } from "node:child_process";
import { connect, Store } from "@ap/db";
import { signIn } from "@ap/mail";
import { encryptSecret, signToken } from "./auth.ts";
import { loadConfig } from "./config.ts";
import { loadDotEnv } from "./env.ts";

loadDotEnv();
const [cmd, email, ...flags] = process.argv.slice(2);
const usage = [
  "Usage:",
  "  create-user <email> [--admin]   create a user (admins also get a new org)",
  "  token <email> [--days N]        print a session token for the extension",
  "  link-gmail <email>              authorize Gmail for the user (stores an encrypted refresh token)",
].join("\n");
if (!cmd || !email) {
  console.log(usage);
  process.exit(1);
}

const cfg = loadConfig(process.env);
const conn = await connect(cfg.databaseUrl, { dataDir: cfg.dataDir });
const store = new Store(conn.db);
try {
  if (cmd === "create-user") {
    const admin = flags.includes("--admin");
    const org = admin ? await store.createOrg(email.split("@")[1] ?? "org") : null;
    const u = await store.createUser({ email, role: admin ? "admin" : "user", orgId: org?.id });
    console.log(`Created ${u.role} ${u.email} (id ${u.id}${org ? `, org ${org.id}` : ""})`);
  } else if (cmd === "token") {
    const u = await store.getUserByEmail(email);
    if (!u) throw new Error("No such user: " + email);
    const di = flags.indexOf("--days");
    const days = di >= 0 ? Number(flags[di + 1]) : 30;
    if (!Number.isFinite(days) || days <= 0) throw new Error("--days must be a positive number");
    console.log(signToken(cfg.secret, { uid: u.id, sid: cfg.serverId, exp: Math.floor(Date.now() / 1000) + Math.round(days * 86400) }));
  } else if (cmd === "link-gmail") {
    if (!cfg.google) throw new Error("Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET first");
    const u = await store.getUserByEmail(email);
    if (!u) throw new Error("No such user: " + email);
    const tokens = await signIn(cfg.google, (url) => {
      console.log("Opening browser. If nothing opens, visit:\n" + url);
      exec(`start "" "${url}"`);
    });
    await store.setEncryptedTokens(u.id, encryptSecret(cfg.tokenKey, JSON.stringify({ refresh_token: tokens.refresh_token })));
    console.log("Gmail linked for " + u.email);
  } else console.log(usage);
} catch (e) {
  console.error((e as Error).message);
  process.exitCode = 1;
} finally {
  await conn.close();
}
