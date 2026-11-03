# Anti-Phishing

Self-hosted, explainable phishing protection for Gmail and Outlook.

Every incoming email is scored against weighted red flags (spoofed sender, look-alike domain, mismatched links, risky attachments, urgency language...). Past a threshold it is moved to a **Phishing** folder or labelled, and a banner in your mail client says *why*. An optional language-model pass judges only the uncertain middle band, and can never lower a score.

> **Status: alpha.** Tested with fakes and a real local server, but not yet run against real Google, Microsoft or LLM services at scale. It never deletes mail and ships with a shadow mode (score and log, touch nothing), so it is safe to try. See [Project status](#project-status).

## Why this one

- **Explainable.** Every verdict lists the flags that fired and the evidence ("`paypa1-secure.net` resembles `paypal.com`"). No black box.
- **Your data stays yours.** Self-host it. Email bodies are never stored, subjects only as a hash. The AI layer is off by default and sees only a redacted, truncated view (links reduced to their host; emails, phone numbers and long digit runs masked). Point it at a local model and no mail leaves your network.
- **Conservative.** The AI can only add points (capped), and cannot make an email Phishing without a rule that also fired. Any AI failure falls back to the exact rules-only verdict. Mail is moved, never deleted, and every move is reversible.
- **Tunable.** Sensitivity presets, per-flag weights, allow/block lists, protected brand domains, and org-wide policy with per-setting locks.

## How it works

```
 Gmail / Outlook mailbox
          |  (worker polls; OAuth, mail is read and moved only)
          v
   parse  ->  rule engine  ->  [optional AI second opinion]  ->  score  ->  action
 (headers,    (20 weighted      (uncertain band only, redacted,    (0-100)   (label/move,
  links,       red flags)         adds points only)                          banner, log)
  attachments)
                                                   |
          Browser extension (Gmail) / Outlook add-in  <---  verdict + reasons
          Admin dashboard  <---  stats, email log (no subjects/bodies), audit log
```

## Quick start

You need Node.js 22+.

```bash
git clone https://github.com/axel0806/anti-phishing.git
cd anti-phishing
npm install
cp .env.example .env     # set SERVER_SECRET (32+ chars), TOKEN_KEY (64 hex), PUBLIC_URL and your Google or Microsoft app
npm run build:ui         # dashboard and Outlook add-in
npm run api              # API + worker on :8080
```

On a fresh server the log prints a one-time **setup token** and the address `…/setup`. Open it, connect the first administrator's mailbox in the browser, and you are in the dashboard. Add people from the **People** tab (invite links), no command line needed.

- Registering the Google / Microsoft app (about 15 minutes): [docs/ONBOARDING.md](docs/ONBOARDING.md)
- Trying it out, and what to check when something is wrong: [docs/RUNNING.md](docs/RUNNING.md)
- Backups, upgrades, key rotation, limits: [docs/OPERATIONS.md](docs/OPERATIONS.md)
- The optional AI layer, what it sees, and how spend is limited: [docs/AI.md](docs/AI.md)
- Docker with Postgres (and optional automatic HTTPS): `docker compose -f deploy/docker-compose.yml --env-file .env up -d --build` (add `--profile tls` for Caddy)

**Just want to see it work on your own inbox, with no server?** Create a Google "Desktop app" OAuth client, put its ID and secret in `.env`, then:

```bash
npm run login            # approve the gmail.modify scope
npm start                # shadow mode: prints verdicts, changes nothing
npm run build:ext        # then load apps/extension/dist-firefox (or dist for Chrome) as an unpacked extension
```

## What's in the box

| Part | What it does |
| --- | --- |
| `apps/api` | Fastify API and worker: scans, settings, lists, feedback, admin API, web onboarding, SSO |
| `apps/dashboard` | Admin dashboard (React): stats, email log, people, lists, policy, audit |
| `apps/extension` | Firefox and Chrome extension: banner in Gmail, feedback buttons |
| `apps/outlook-addin` | Outlook task pane and manifest generator |
| `apps/local` | Standalone Gmail runner for trying it without a server |
| `packages/detectors` | The rule engine: pure functions, one per family of red flags |
| `packages/ai` | LLM providers (Anthropic, any OpenAI-compatible server), redaction, prompt, budgets |
| `packages/*` | `parser`, `scoring`, `pipeline`, `settings`, `db`, `mail`, `shared`, `ui` |
| `corpus/` | Labelled sample emails and the recall / false-positive runner |

## Project status

Honest picture, because you are trusting this with your inbox:

- **Works and is tested (474 tests):** the scoring pipeline, the API, onboarding, the dashboard, role and org handling, rate limits, key rotation.
- **Not yet proven:** detection quality on real mail. The labelled corpus is tiny, and "the AI measurably improves detection" is **not** established. Mail already caught by Gmail or Microsoft before delivery never reaches this layer, so the real-world gain is unmeasured. Treat it as a second pair of eyes, not a gateway.
- **Never run against real services:** Microsoft Graph, Anthropic and local models, an OIDC provider, the Docker image, real Postgres, the Outlook add-in inside Outlook, and the dashboard in a real browser.
- **Not implemented:** push notifications (it polls), SAML, billing, org-wide mailbox consent.

Design decisions and gotchas are in [docs/HANDOFF.md](docs/HANDOFF.md); the original design is in [plan.md](plan.md); an honest analysis of strengths and weaknesses is in [docs/SWOT.md](docs/SWOT.md).

## Contributing

Contributions are very welcome, from a new red-flag detector to a typo fix. Start with [CONTRIBUTING.md](CONTRIBUTING.md); the highest-impact thing you can do is **send us phishing and legitimate emails (with personal details removed) for the corpus**, or run shadow mode on your own mailbox and report what it got wrong. Issues labelled `good first issue` are a gentle way in.

Found a security problem? Please follow [SECURITY.md](SECURITY.md) rather than opening a public issue.

## License

[MIT](LICENSE) © 2026 Axel Furtenbach
