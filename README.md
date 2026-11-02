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
