# Handoff: project state for the next agent

Last updated after the dashboard commit on branch `phase-4-orgs`. Read this first, then `plan.md` (the design and build plan, which is the spec).

## What this is

An AI-assisted anti-phishing system. Every incoming email is scored against weighted red flags; past a threshold it is moved to a Phishing folder or labelled. Rules run first, an LLM judges only the uncertain middle band. A Fastify backend stores settings, lists and feedback; a browser extension (Gmail, Firefox/Chrome) and an Outlook add-in show a banner explaining why. Self-hostable (Docker) or cloud.

## Branch and merge state

| Branch | State |
| --- | --- |
| `main` | Phases 1, 2 and 3 merged and pushed. 233 tests at merge. CI green. |
| `phase-4-orgs` | **Active.** Pushed, not merged. 373 tests pass, `tsc --noEmit` clean. |

Do not merge `phase-4-orgs` into `main` without the user's explicit say-so. They approved the earlier merges individually. The user said "just get everything done and then we'll get it going and diagnose any issues": they intend to run it themselves and report problems.

## Phase 4 status

Done and tested on `phase-4-orgs`:
- Closed older gaps: `first_time_sender` (needs 50 history rows), RDAP domain-age and Safe Browsing lookups (both opt-in), `POST /v1/rescan`.
- Admin API under `/v1/admin/*`: org-scoped stats (overview, trend, flags, targets, users, quality, ai, health), email log, audit log, release/re-quarantine, CSV export, weight suggestions (`GET /v1/settings/suggestions`), `GET /metrics`. Roles: viewer < analyst < admin. See `apps/api/src/adminRoutes.ts`.
- `daily_stats` rollup (runs before the retention purge, and catches up 3 days on each maintenance run) and `audit_log`.
- OIDC SSO for the dashboard (`apps/api/src/oidc.ts`). SAML is NOT implemented.
- Microsoft Graph provider (`packages/mail/src/graph.ts`), Microsoft OAuth, a multi-provider mailer (`apps/api/src/mailer.ts`) that persists rotated refresh tokens and unlinks revoked ones.
- Outlook id translation (`translateExchangeIds`): the add-in sends REST ids, scans are keyed by immutable ids. Requests carry `idFormat=outlook_rest`.
- Static hosting of `/admin/` and `/addin/` with strict CSP (`apps/api/src/sites.ts`); dynamic `GET /addin/manifest.xml` from `PUBLIC_URL`.
- Shared UI package `packages/ui` (banner model, connection logic, verdict client, DOM renderer with feedback buttons). The Firefox/Chrome extension and the Outlook add-in both use it.
- Outlook add-in (`apps/outlook-addin`): task pane, icons generated at build, manifest generator.

- Dashboard front-end `apps/dashboard` (React 18 + inline-SVG charts, esbuild to `apps/dashboard/dist`): overview panels with date range and CSV, email log with filters/pagination/release, org lists with bulk import, policy editor with lock checkboxes, managed-policy generator (Chrome/Edge + Firefox), audit tab; tabs hidden by role from `GET /v1/me`. Token in `sessionStorage`, taken from the `#token=` fragment and removed from the URL. Email-log rows now include `userId`.
- `npm run build:ui` (dashboard + add-in), Dockerfile builds both, compose/.env.example/README cover Phase 4 variables.

**NOT done (resume here):**
1. An independent review of the Phase 4 branch (see "Process"), then fixes.
2. (Done: docs/RUNNING.md.)
3. Dashboard is only tested with a fake API and happy-dom, never in a real browser against a real server. The generator defaults the Firefox extension id to the dev id `anti-phishing-dev@local`; change it for a signed release. The dashboard has no policy form, only a JSON editor plus lock checkboxes.

## Repo layout

```
apps/api            Fastify server: /v1 API, worker loop, CLI, OIDC, static hosting
apps/extension      Firefox + Chrome (MV3) extension: Gmail banner, options page
apps/outlook-addin  Outlook task pane + manifest generator
apps/local          Phase 1 standalone runner (Gmail polling + localhost verdict server)
apps/dashboard      Admin dashboard (React), built to dist, served at /admin/
packages/shared     Types, flag catalog and weights, Settings, defaults
packages/parser     mailparser wrapper, link extraction, trusted Authentication-Results
packages/detectors  Rule engine (pure functions) and allow/block list check
packages/scoring    Score + thresholds + AI cap
packages/pipeline   list check -> detectors -> (AI) -> score; shadow mode
packages/ai         Providers (Anthropic, OpenAI-compatible), redaction, prompt, cache/budget
packages/settings   Defaults < org < user layering, JSON Merge Patch, locks, Zod schemas
packages/db         Drizzle schema, migrations, Store, AdminQueries
packages/mail       Gmail + Graph clients, OAuth (Google + Microsoft)
packages/ui         Shared banner/connection/client code
corpus/             Labelled .eml fixtures and runners (phishing/, legit/, uncertain/, injection/)
deploy/             Dockerfile, docker-compose.yml
```

## Commands

```
npm test                 vitest run (all packages)
npm run typecheck        tsc --noEmit
npm run corpus           Phase 1 recall/FPR on corpus/
npm run corpus:ab        rules-only vs rules+AI (needs a real AI provider in env)
npm run build:ext        extension -> apps/extension/dist and dist-firefox
node apps/outlook-addin/build.mjs
npm run api              start API + worker (reads .env)
npm run api:cli -- create-user|token|link-mail|set-role ...
npm run login / start    Phase 1 local runner
```

No `pnpm`/Turborepo: npm workspaces. CI (`.github/workflows/ci.yml`) runs typecheck, tests and the corpus.

## Key design decisions (do not undo without asking)

- **The AI can only add points** (never subtract), capped at 40 total, and cannot make an email Phishing without a positive rule flag. Any failure (timeout 2.5 s, error, bad output, budget) returns the exact rules-only verdict. AI is **off by default** per user and per server.
- **Privacy:** only a redacted, truncated view reaches the model. All URLs are reduced to their host (no paths, queries or tokens). Emails, phones, IBANs, long digit runs are masked. Bodies are never stored; subjects only as a hash.
- **Auth results:** only the `Authentication-Results` header whose authserv-id is `mx.google.com` is trusted. The allowlist applies only when DMARC passed.
- **Never delete mail.** "Move" = apply label/folder and remove from inbox. Manual verdicts (feedback) pin a scan and are never re-scored.
- **Shadow mode** scores and logs but never touches mail, and does not consume a message's chance to be acted on later.
- **Scans are idempotent per (user, message id).** A stored `action` column records whether a mailbox action was applied.
- **Rule flag beats AI flag** of the same id in scoring.
- **Settings:** locks can name a setting (`ai`) or one field (`ai.monthlyBudgetUsd`). Users cannot set `ai.orgMonthlyBudgetUsd`. Server cap `AI_MAX_USER_BUDGET_USD` (default 20).
- **Rulings:** polling worker instead of BullMQ/Redis; Pub/Sub and Graph push are not implemented (polling/delta cover it); users and tokens come from the CLI, not a server-side Google sign-in; SAML not implemented; `certFingerprint` is read but cannot be enforced from an extension; the email log shows no subject (only a hash is stored).

## Configuration (env, see `apps/api/src/config.ts`)

Required: `SERVER_SECRET` (32+ chars), `TOKEN_KEY` (64 hex). Optional groups: `DATABASE_URL` (else embedded PGlite in `DATA_DIR`), `GOOGLE_CLIENT_ID/SECRET`, `MICROSOFT_CLIENT_ID/SECRET/TENANT`, `AI_PROVIDER=anthropic|openai` and its settings, `RDAP_LOOKUPS=true`, `SAFE_BROWSING_API_KEY`, `OIDC_ISSUER/CLIENT_ID/CLIENT_SECRET` + `PUBLIC_URL`, `METRICS_TOKEN`, `RETENTION_DAYS`, `POLL_SECONDS`, `ROLE=api|worker|all`. The user's `.env` is gitignored; it contains real Google credentials. Never print, commit or paste its values.

## Verification status (be honest about this)

- **Never run against real services:** Google (beyond a read-only Phase 1 scan the user ran), Microsoft Graph, Anthropic, local models, Safe Browsing, RDAP, an OIDC IdP. Everything else is tested with fakes (a fake IdP with real JWT signing, PGlite as the real SQL engine).
- **Not exercised:** the Docker image (Docker Desktop was off), the `pg` driver on real Postgres, the Outlook add-in inside Outlook, the Firefox settings page and permission flow.
- The Phase 3 gate (AI measurably raises detection) is **not met**: the A/B harness uses a keyword stand-in on 4 emails. The Phase 1 gate also needs real corpora (Nazario/PhishTank samples plus the user's own mail in `corpus/legit/`, which is gitignored).

## Process the user expects

Per phase: build test-first on a branch, commit, push, then dispatch an independent reviewer subagent (opus, fresh context, told not to edit) over `git diff base..branch`, re-grade its findings by effect, fix Critical/Important in one pass with tests that fail first, defer Minors by listing them, then report. Reviews have repeatedly found real issues (prototype pollution, URL tokens sent to the model, token sent to the wrong server). Do not skip it. Report honestly what was and was not verified.

## Environment gotchas (these cost real time)

- **Backslashes are stripped when code is written through bash heredocs or `node -e` strings.** Regexes like `/\d+/` silently become `/d+/`. Write files with the Write/Edit tools, or after any shell-based patch, grep the result for regex literals. This bit config.ts, server.ts, parser and redact multiple times.
- **Git Bash quoting:** very large multi-heredoc commands fail to parse as a whole and run nothing ("unexpected EOF"). Use the Write tool for big files. `python3` is a Windows stub that hangs; use node.
- **CRLF:** `core.autocrlf=true`, so merged files may have CRLF and multi-line string patches fail. `C:/Users/axel/AppData/Local/Temp/norm.cjs` (`node -r` it) normalises reads; it may need recreating.
- A patch script that was never executed can look done (once only a `grep` ran). Check results.
- Background servers started from the shell can outlive the command and hold ports (a stale API on 18080 once caused phantom 401s). Check `Get-NetTCPConnection -LocalPort` before blaming the code.
- PGlite needs its data directory's parent to exist (`connect()` creates it) and runs one statement per call (migrations are split on `;`).
- Zod is v4 (`z.partialRecord`, `z.strictObject`). Fastify is v5. `jose` v6.

## Deferred minors (not fixed on purpose)

Allowlist/blocklist match the spoofable From header (allowlist now needs DMARC pass); AI uncertain band is fixed at 20-80 and ignores strict thresholds; "deterministic agreement" accepts any positive rule flag; org budget check is not atomic (can overshoot by about one call per concurrent scan); org-salted cache keys; rescan drops `first_time_sender`; worker queue depth/errors are not in the dashboard health panel (only in-process `/metrics`, and only in the API process); dashboard "user group" filter not implemented; `.html` attachments always flag; only ZIP archives inspected; display-name check splits on spaces only; some tests are weaker than their names (forged-delimiter and "obedient model" tests cannot really fail).

## First things to do when resuming

1. `git checkout phase-4-orgs && npm install && npm test && npm run typecheck`.
2. `npm run build:ui`, start the API, open /admin/ and click through.
3. Run the independent review, fix, update this file.
4. Ask the user before merging to `main`.
