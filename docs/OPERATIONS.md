# Running it in production

## What to protect

| Data | Where | Sensitivity |
| --- | --- | --- |
| Accounts, org policy, lists, scan verdicts, feedback, audit log | Postgres (or the embedded database in `DATA_DIR`) | Personal data: email addresses, sender addresses, verdicts. **No message bodies and no subjects** are stored (subjects only as a hash). |
| Mailbox refresh tokens | `users.encrypted_tokens`, AES-256-GCM under `TOKEN_KEY` | **High.** Anyone holding both the database and `TOKEN_KEY` can read and move every linked mailbox. Keep them in different places. |
| `SERVER_SECRET` | `.env` | Signs session tokens, invite links and login cookies. Changing it signs everyone out and invalidates open invites. |

## Backups

**Postgres (the Docker setup):**

```
# backup (run from the machine that runs docker compose)
docker compose -f deploy/docker-compose.yml exec -T postgres pg_dump -U phish -d phish -Fc > phish-$(date +%F).dump

# restore into an empty database
docker compose -f deploy/docker-compose.yml exec -T postgres pg_restore -U phish -d phish --clean --if-exists < phish-2026-01-31.dump
```

Run the backup nightly (cron or a scheduled task) and copy it off the machine. A restore needs the same `TOKEN_KEY` that was in use when the tokens were written, so back the key up separately and never next to the dump.

**Embedded database (`DATA_DIR`, default `.data`):** stop the server, copy the whole directory, start the server again. There is no hot backup.

Stored scan data is deleted automatically after `RETENTION_DAYS` (default 90). The dashboard's daily statistics are kept beyond that.

## Upgrading

1. Back up (above).
2. `git pull`, then `docker compose ... up -d --build` (or `npm install && npm run build:ui` and restart `npm run api`).
3. Database migrations apply automatically at startup and are safe to run twice. They are append-only; there is no automatic downgrade, so a rollback means restoring the backup.

## Moving from the embedded database to Postgres

There is no data-migration command. The supported path is to start fresh on Postgres and re-onboard: set `DATABASE_URL`, start the server, open `/setup`, and send invites from the People tab. Scan history is not carried over (it is only a rolling cache of verdicts; the next worker pass rescans the inbox). If you need the old history, keep the old directory.

## Rotating `TOKEN_KEY`

1. Generate a new key: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`.
2. Set `TOKEN_KEY_PREVIOUS` to the **old** key and `TOKEN_KEY` to the **new** one, then restart. Everything keeps working because both keys can read.
3. Run `npm run api:cli -- rotate-keys all`. It re-encrypts every mailbox token under the new key and reports any it could not read (those users must reconnect through a fresh invite; they are not deleted).
4. Remove `TOKEN_KEY_PREVIOUS` and restart.

## Revoking a leaked or lost token

Session tokens are bound to the user and expire (30 days for extension tokens by default). To cut someone off immediately: People tab > change their role to `user`, or *Erase* them. To invalidate **every** session at once, change `SERVER_SECRET` (this also invalidates open invites and signs the dashboard out).

## Monitoring

- `GET /v1/health` is unauthenticated and never rate limited: use it for uptime checks.
- Dashboard > Overview > **System health** shows scan counts, latency, and **mailbox sync lag**: how long since each linked mailbox last synced, plus how many are erroring or have never synced. Counts only; provider error text stays in the server log.
- `GET /metrics` (Prometheus text) works from the machine itself, or from elsewhere with `Authorization: Bearer $METRICS_TOKEN`. Requests that arrive through a reverse proxy are refused unless the token is present.
- Run **more than one worker** for resilience: mailboxes are leased, so two workers share the load and never process the same mailbox at once. A crashed worker's lease expires after 5 minutes.

## Limits to know about

- One worker pass reads each mailbox's newest 200 messages and scans at most 100 new ones per mailbox per pass (`POLL_SECONDS`, default 60). A burst larger than that is worked off over the next passes, newest first. Mailboxes are processed 4 at a time per worker.
- Change notifications (Gmail push, Microsoft Graph subscriptions) are not implemented; the product polls.
- Rate limits are in memory per process: 60 requests/minute per address on public pages, 600/minute per user on the API, 12 rescans/minute. Set `TRUST_PROXY=true` only when a reverse proxy you control sets `X-Forwarded-For`.
- There is no per-organization encryption key and no KMS integration: one `TOKEN_KEY` protects all tokens.
