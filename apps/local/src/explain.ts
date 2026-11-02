// Dev helper: prints flag evidence (domains only) for non-safe messages. No subjects or bodies.
import { GmailProvider, loadTokens, saveTokens, tokenSource } from "@ap/mail";
import { DEFAULT_SETTINGS } from "@ap/shared";
import { scanRaw } from "@ap/pipeline";
import { readFileSync } from "node:fs";
const env: Record<string, string> = {};
for (const l of readFileSync(".env", "utf8").split(/\r?\n/)) { const m = /^\s*([A-Z_]+)\s*=\s*(.*?)\s*$/.exec(l); if (m) env[m[1]!] = m[2]!; }
const cfg = { clientId: env.GOOGLE_CLIENT_ID!, clientSecret: env.GOOGLE_CLIENT_SECRET! };
const tokens = loadTokens(".tokens.json")!;
const g = new GmailProvider(tokenSource(cfg, tokens, (t) => saveTokens(".tokens.json", t)));
for (const id of await g.listRecentInbox(25)) {
  const v = await scanRaw(await g.fetchRaw(id), id, DEFAULT_SETTINGS);
  if (v.flags.length) console.log(id, v.flags.map((f) => f.evidence).join(" | "));
}
