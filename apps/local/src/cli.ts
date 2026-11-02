import { readFileSync, existsSync } from "node:fs";
import { exec } from "node:child_process";
import { GmailProvider, loadTokens, saveTokens, signIn, tokenSource, type OAuthConfig } from "@ap/mail";
import { DEFAULT_SETTINGS } from "@ap/shared";
import { loadStore, saveStore, scanInbox } from "./runner.ts";
import { createVerdictServer } from "./server.ts";

const TOKENS = ".tokens.json";
const VERDICTS = ".verdicts.json";
const PORT = 8787;

function loadEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  if (existsSync(".env")) {
    for (const line of readFileSync(".env", "utf8").split(/\r?\n/)) {
      const m = /^\s*([A-Z_]+)\s*=\s*(.*?)\s*$/.exec(line);
      if (m) env[m[1]!] = m[2]!.replace(/^["']|["']$/g, "");
    }
  }
  return env;
}

function config(): OAuthConfig {
  const e = { ...loadEnv(), ...process.env } as Record<string, string | undefined>;
  const clientId = e.GOOGLE_CLIENT_ID ?? e.CLIENT_ID;
  const clientSecret = e.GOOGLE_CLIENT_SECRET ?? e.CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    console.error("Missing GOOGLE_CLIENT_ID and/or GOOGLE_CLIENT_SECRET in .env (see .env.example).");
    process.exit(1);
  }
  return { clientId, clientSecret };
}

const open = (url: string) => {
  console.log("Opening browser for Google sign-in. If nothing opens, visit:\n" + url);
  exec(`start "" "${url}"`);
};

const [cmd, ...args] = process.argv.slice(2);

if (cmd === "login") {
  const tokens = await signIn(config(), open);
  saveTokens(TOKENS, tokens);
  console.log("Signed in. Tokens saved to " + TOKENS + " (gitignored).");
} else if (cmd === "run") {
  const act = args.includes("--act");
  const once = args.includes("--once");
  const cfg = config();
  const tokens = loadTokens(TOKENS);
  if (!tokens) { console.error("Not signed in. Run: npm run login"); process.exit(1); }
  const provider = new GmailProvider(tokenSource(cfg, tokens, (t) => saveTokens(TOKENS, t)));
  const settings = { ...DEFAULT_SETTINGS, shadowMode: !act };
  const store = loadStore(VERDICTS);
  console.log(act ? "ACT mode: phishing is moved to the 'Phishing' label; suspicious gets 'Suspicious'." : "SHADOW mode: scoring and logging only, no mail is changed. Use --act to enable.");

  let running = false;
  const pass = async () => {
    if (running) return; // never overlap passes
    running = true;
    try {
    for (const id of await scanInbox(provider, settings, store)) {
      const s = store.get(id)!;
      console.log(`${s.verdict.verdict.padEnd(10)} ${String(s.verdict.score).padStart(3)}  ${id}  ${s.verdict.flags.map((f) => f.id).join(",")}  -> ${s.action}`);
    }
    saveStore(VERDICTS, store);
    } finally { running = false; }
  };
  await pass();
  if (!once) {
    createVerdictServer(store).listen(PORT, "127.0.0.1", () => console.log(`Verdict API on http://127.0.0.1:${PORT} (for the extension)`));
    setInterval(() => pass().catch((e) => console.error(e.message)), 60_000);
  }
} else {
  console.log("Usage: login | run [--act] [--once]");
}
