# Anti-Phishing Email Extension

AI-assisted browser extension and backend that scores incoming email against weighted red flags and moves likely phishing to a dedicated folder.

See [plan.md](plan.md) for the detailed design and build plan. The original design export is kept alongside it.

## Phase 1 quick start (Gmail, local)

1. Copy `.env.example` to `.env` and fill in `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` (Desktop-app OAuth client; add yourself as a test user).
2. `npm install`, then `npm run login` and approve the `gmail.modify` scope in the browser.
3. `npm start` runs in **shadow mode**: it scores your inbox and prints verdicts, and changes nothing. Add `--act` (`npm run start:act`) to apply the `Phishing` / `Suspicious` labels.
4. `npm run build:ext`, then load `apps/extension/dist-firefox/manifest.json` via `about:debugging#/runtime/this-firefox` > Load Temporary Add-on (Chrome: `apps/extension/dist` via `chrome://extensions` > Load unpacked). Open a Gmail message while `npm start` is running to see the banner.
5. `npm test` runs all tests; `npm run corpus` reports recall / false-positive rate for `corpus/`.

## Phase 2: backend server (API + worker + Postgres)

The extension talks to a `/v1` API you host yourself. Without `DATABASE_URL` the server uses an embedded database in `.data/`, which is fine for trying it out.

```bash
# 1. Configure (generate secrets: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
cp .env.example .env        # set SERVER_SECRET (32+ chars), TOKEN_KEY (64 hex), GOOGLE_CLIENT_ID/SECRET

# 2. Create a user, link their Gmail, mint a session token
npm run api:cli -- create-user you@gmail.com
npm run api:cli -- link-gmail you@gmail.com
npm run api:cli -- token you@gmail.com        # paste into the extension's settings page

# 3. Run the API and the worker (ROLE=all by default)
npm run api
```

Self-hosting with Docker (Postgres, API and worker): `docker compose -f deploy/docker-compose.yml --env-file .env up -d --build`. The API binds to `127.0.0.1` only; put a TLS reverse proxy in front before exposing it, because the extension requires HTTPS for anything but localhost.

In the extension's settings page (Firefox: `about:addons` > the extension > Preferences) enter the server address and token. The extension asks for access to that server only, checks `GET /v1/health`, and clears the token if you switch to a different server. Admins can lock the address with the managed policy in `apps/extension/managed_schema.json`.

The worker moves mail only for users who are not in shadow mode. New users should turn on `shadowMode` first (`PATCH /v1/settings {"shadowMode": true}`) and review the verdicts before enabling moves.

## Phase 3: AI layer (optional, off by default)

Rules run first. Only emails whose rule score is *uncertain* (20-80 points) go to a language model, which judges intent and social-engineering tactics the rules cannot see. The model can only **add** points (capped at 40) and can never move an email into Phishing on its own. Any failure (timeout after 2.5 s, error, bad output, budget used up) falls back to the exact rules-only verdict.

Nothing is sent anywhere until you configure a provider on the server **and** a user turns AI on (`PATCH /v1/settings {"ai": {"enabled": true}}`; admins can lock it off for an org).

```bash
# Hosted (Anthropic): prices are needed so the per-user monthly budget works
AI_PROVIDER=anthropic  ANTHROPIC_API_KEY=...  AI_PRICE_IN_PER_MTOK=...  AI_PRICE_OUT_PER_MTOK=...

# Local / self-hosted (Ollama, LM Studio, vLLM...): mail data never leaves your network
AI_PROVIDER=openai  AI_BASE_URL=http://localhost:11434/v1  AI_MODEL=llama3.1
```

Spend is bounded three ways: each user's own monthly budget, a server-wide ceiling on that budget (`AI_MAX_USER_BUDGET_USD`, default $20), and an optional pooled org budget (`ai.orgMonthlyBudgetUsd` in org policy). Admins can lock all of `ai` or a single field such as `ai.monthlyBudgetUsd`. Calls that time out are still charged at an estimate, because the provider may bill them.

What the model sees: sender name and address, reply-to, subject, the body truncated to 4,000 characters, links reduced to their host (no paths, query strings or tokens, anywhere in the text), attachment names and types, and the rule flags already fired. Email addresses, phone numbers and long digit strings are redacted first. The email is wrapped in a randomly delimited data block, the system prompt tells the model it is untrusted, and the reply must match a strict schema.

Measure it: `npm run corpus:ab` runs `corpus/uncertain` through rules-only and rules + AI and reports the recall and false-positive change (needs a provider configured in the environment). `corpus/injection` holds prompt-injection emails used in the tests.

> Agents and new contributors: read [docs/HANDOFF.md](docs/HANDOFF.md) first for the current project state, decisions and gotchas.
