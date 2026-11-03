import { exec } from "node:child_process";
import { connect, Store } from "@ap/db";
import { MICROSOFT_SCOPE, microsoftEndpoints, signIn, type OAuthConfig } from "@ap/mail";
import { encryptSecret, signToken } from "./auth.ts";
import { rotateTokenKeys } from "./keys.ts";
import { loadConfig } from "./config.ts";
import { loadDotEnv } from "./env.ts";

loadDotEnv();
const [cmd, email, ...flags] = process.argv.slice(2);
const usage = [
  "Usage:",
  "  create-user <email> [--admin] [--provider gmail|outlook]   create a user (admins also get a new org)",
  "  token <email> [--days N]        print a session token for the extension",
  "  link-mail <email>               authorize the user's mailbox (Gmail or Outlook, per their provider)",
  "  link-gmail <email>              same as link-mail (kept for compatibility)",
  "  set-role <email> <role>         change a user's role: user | viewer | analyst | admin",
  "  rotate-keys all                 re-encrypt stored mailbox tokens under TOKEN_KEY (set TOKEN_KEY_PREVIOUS to the old key first)",
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
    const pi = flags.indexOf("--provider");
    const provider = pi >= 0 ? flags[pi + 1] : "gmail";
    if (provider !== "gmail" && provider !== "outlook") throw new Error("--provider must be gmail or outlook");
    const u = await store.createUser({ email, role: admin ? "admin" : "user", orgId: org?.id, provider });
    console.log(`Created ${u.role} ${u.email} (id ${u.id}${org ? `, org ${org.id}` : ""})`);
  } else if (cmd === "token") {
    const u = await store.getUserByEmail(email);
    if (!u) throw new Error("No such user: " + email);
    const di = flags.indexOf("--days");
    const days = di >= 0 ? Number(flags[di + 1]) : 30;
    if (!Number.isFinite(days) || days <= 0) throw new Error("--days must be a positive number");
    console.log(signToken(cfg.secret, { uid: u.id, sid: cfg.serverId, exp: Math.floor(Date.now() / 1000) + Math.round(days * 86400) }));
  } else if (cmd === "link-mail" || cmd === "link-gmail") {
    const u = await store.getUserByEmail(email);
    if (!u) throw new Error("No such user: " + email);
    let oauth: OAuthConfig;
    if (u.provider === "outlook") {
      if (!cfg.microsoft) throw new Error("Set MICROSOFT_CLIENT_ID first (see the README)");
      oauth = { clientId: cfg.microsoft.clientId, clientSecret: cfg.microsoft.clientSecret, ...microsoftEndpoints(cfg.microsoft.tenant), scope: MICROSOFT_SCOPE, redirectHost: "localhost" };
    } else {
      if (!cfg.google) throw new Error("Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET first");
      oauth = cfg.google;
    }
    const tokens = await signIn(oauth, (url) => {
      console.log("Opening browser. If nothing opens, visit:\n" + url);
      exec(`start "" "${url}"`);
    });
    await store.setEncryptedTokens(u.id, encryptSecret(cfg.tokenKey, JSON.stringify({ refresh_token: tokens.refresh_token })));
    console.log(`${u.provider} mailbox linked for ${u.email}`);
  } else if (cmd === "rotate-keys") {
    const r = await rotateTokenKeys(store, cfg.tokenKey, cfg.previousTokenKeys);
    console.log(`rotated ${r.rotated}, already on the current key ${r.alreadyCurrent}${r.unreadable.length ? `, UNREADABLE (left untouched, these users must reconnect): ${r.unreadable.join(", ")}` : ""}`);
    if (r.unreadable.length) process.exitCode = 1;
  } else if (cmd === "set-role") {
    const role = flags[0];
    if (role !== "user" && role !== "viewer" && role !== "analyst" && role !== "admin") throw new Error("role must be user, viewer, analyst or admin");
    const u = await store.getUserByEmail(email);
    if (!u) throw new Error("No such user: " + email);
    await store.setUserRole(u.id, role);
    console.log(`${u.email} is now ${role}`);
  } else console.log(usage);
} catch (e) {
  console.error((e as Error).message);
  process.exitCode = 1;
} finally {
  await conn.close();
}
