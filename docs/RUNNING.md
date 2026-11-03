# Run it and diagnose problems

A step-by-step guide for trying the whole system yourself. Nothing here needs Docker; the API falls back to an embedded database (PGlite) in `DATA_DIR` when `DATABASE_URL` is not set.

## 1. Set up

```
npm install
npm test && npm run typecheck        # 373 tests should pass
npm run build:ui                     # builds /admin/ and /addin/
npm run build:ext                    # builds the Firefox/Chrome extension
```

Create `.env` (see `.env.example`). Required: `SERVER_SECRET` (32+ characters) and `TOKEN_KEY` (64 hex characters). Generate each with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`. Add `GOOGLE_CLIENT_ID/SECRET` to link Gmail. Never paste `.env` values into chats or commits.

## 2. Start the server and create an admin

```
npm run api                                        # API + worker on :8080
npm run api:cli -- create-user you@example.com --admin
npm run api:cli -- link-mail you@example.com       # opens the Google (or Microsoft) consent flow
npm run api:cli -- token you@example.com           # prints a session token
```

Turn on `shadowMode` for the first days (`PATCH /v1/settings {"shadowMode": true}`): mail is scored and logged but never moved.

## 3. Check each part

| Part | How | What you should see |
| --- | --- | --- |
| Server | `curl http://localhost:8080/v1/health` | JSON with `version` and `serverId` |
| Dashboard | open `http://localhost:8080/admin/`, paste the token | Overview panels, tabs for your role |
| Extension | options page: server `http://localhost:8080` + token; open Gmail | banner on a scanned message |
| Outlook | needs `MICROSOFT_CLIENT_ID/SECRET` and an https `PUBLIC_URL`; download `/addin/manifest.xml` and sideload | task pane verdict |
| Metrics | `curl http://localhost:8080/metrics` (loopback only, or with `METRICS_TOKEN`) | Prometheus text |

Give a colleague dashboard access with `npm run api:cli -- set-role them@example.com viewer|analyst|admin`.

## 4. When something is wrong

| Symptom | Likely cause |
| --- | --- |
| Server exits at start with a list of problems | `.env` validation: read the messages (secret lengths, https-only URLs, tenant format) |
| `/admin/` is a 404 | `npm run build:ui` was not run (the server logs "Dashboard not built") |
| Dashboard keeps returning to sign-in | Token expired (SSO tokens last 8 hours) or created for another server id (`SERVER_ID`/secret changed) |
| 403 on a tab or panel | Role too low; check `GET /v1/me` |
| SSO returns "not set up for the dashboard" | The email must already exist as a user with a role; SSO never creates accounts |
| SSO redirect fails | `PUBLIC_URL` must match the redirect URI registered at the identity provider exactly |
| Phantom 401s or old behaviour | A stale API still holds the port: `Get-NetTCPConnection -LocalPort 8080` |
| Nothing is scanned | Mailbox not linked, or worker not running (`ROLE=api` runs no worker); check `POLL_SECONDS` |
| Mail is scored but never moved | `shadowMode` is on (by design) |
| Outlook pane says id cannot be resolved | Mailbox not linked on the server, or `PUBLIC_URL`/manifest mismatch |
| AI never runs | Off by default: needs `AI_PROVIDER`, the user's own `ai.enabled`, and budget left; failures silently return the rules-only verdict (see stderr logs) |
| Dashboard panels empty | Rollups cover today and yesterday on demand; older days rely on the nightly job; check the date range |

Logs go to the console of `npm run api`. Quick data checks use the dashboard's Email log (no subjects or bodies are stored, by design) and the Audit tab.

## 5. Known unverified areas

Never run against real services: Microsoft Graph, Anthropic or local models, Safe Browsing, RDAP, an OIDC provider. Not exercised: the Docker image, real Postgres via `pg`, the add-in inside Outlook, the dashboard in a real browser. Report anything odd from these first.
