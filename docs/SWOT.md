# SWOT analysis

First written 2026-11-03; **updated the same day after web onboarding and a hardening pass** (branch `phase-4-orgs`, 474 tests, typecheck clean, not merged to `main`). Items tagged **[FIXED]**, **[PARTLY]** or **[OPEN]** below carry their current status; the update summary follows. The analysis centres on the product as it exists in the repository. Market and business factors are kept to a short section at the end of each quadrant. Sources: `docs/HANDOFF.md`, `docs/RUNNING.md`, the (private) business plan, `plan.md`, `README.md` and the code. Points are ordered by importance within each section.

---

## Update: what changed since the first version

| Weakness | Status | What happened |
| --- | --- | --- |
| 1. Nothing run against real services | **[OPEN]** | Still true, and still the biggest risk. The server, migrations and static hosting were run for real; Google/Microsoft OAuth, Graph, Anthropic, Docker, real Postgres, Outlook and a real browser were not. |
| 2. Detection unmeasured, AI gate unmet | **[OPEN]** | No new corpus or A/B run. Nothing in this pass changes the evidence for or against the product's central claim. |
| 3. Ingest | **[PARTLY]** | Leased mailboxes, 4-way concurrency, a 200-message window with batched dedupe, lag and error counts in the dashboard. Still polling: no Gmail history, Graph delta or push. |
| 4. CLI-only onboarding | **[MOSTLY FIXED]** | Browser first-run setup, invite links, browser mailbox connect, People/Account tabs. Not done: self-serve signup, billing, org-wide consent (one consent per person remains). Outlook in the browser requires a single-tenant app. |
| 5. Spoofable lists, easy evasion | **[PARTLY]** | Multilingual phrases, more brands, punctuation-proof display-name check. Still no QR/image extraction, still From-header based lists, still public static rules. |
| 6. Shallow attachment inspection | **[PARTLY]** | Content-based HTML/SVG, hidden macros, executables in ZIPs; the blanket `.html` flag is gone. No hash reputation, no 7z/RAR, no sandbox. |
| 7. Thin data protection | **[PARTLY]** | Rate limits, TLS compose profile, key rotation, erasure endpoints, session revocation, extension tokens limited to user rights, single-use invites. Still one `TOKEN_KEY` for everything, no KMS, no LICENSE. |
| 8. Operational visibility | **[MOSTLY FIXED]** | Worker lag/errors in the dashboard, CSV truncation notice, backup/upgrade/rotation guide. Admin releases still count as the user's own feedback (judged acceptable). |
| 9. UX untested with real users | **[PARTLY]** | Policy form added. Still no real-browser pass, no Gmail selector canary, dev add-on id. |
| 10. Weak tests | **[MOSTLY FIXED]** | Forged-delimiter and AI-never-lowers tests rewritten so they can fail. AI budget reservation is still not atomic (bounded by worker concurrency). |

Two independent reviews of the new code found real defects that were fixed test-first, including a ReDoS (one crafted attachment could freeze the server for about 25 seconds), a rate-limit bypass through percent-encoded paths, invite replay after erasure, un-revokable tokens, and a Microsoft identity-claim weakness. That is good process evidence, and also a reminder that the code is young: two review rounds found a Critical and several Importants in work that had all tests passing.

**What did not change:** nothing here moves the commercial picture. There is still no evidence that the product catches phishing the mailbox providers miss, no customer, no licence decision and no revenue.

---

## Strengths

**1. The AI layer is structurally safe: it can only add points, and any failure falls back to rules-only.**
`packages/scoring/src/index.ts` caps AI points at 40 (`AI_POINT_CAP`) and downgrades a Phishing verdict to Suspicious when no deterministic rule flag is positive. A rule flag of the same id always beats the AI copy. The model sees only a redacted view (URLs reduced to hosts, emails/phones/digits masked, body cut to 4,000 characters, random delimiters, strict reply schema in `packages/ai/src/{redact,prompt,schema}.ts`). Prompt injection therefore cannot lower a score or create a Phishing verdict by itself.

**2. Privacy by design is real, not a slogan.**
Bodies are never stored, subjects are stored only as a hash, and AI is off by default per user and per server. A local OpenAI-compatible model (`AI_PROVIDER=openai`) keeps all mail data inside the network. RDAP and Safe Browsing lookups are opt-in because they send data out. The retention purge also expires the AI cache (`runMaintenance` in `apps/api/src/worker.ts`). The trade-off (no subject in the email log) is accepted openly in the docs.

**3. Every verdict is explainable and tunable.**
Twenty weighted flags with evidence strings (`packages/shared/src/index.ts`), per-category multipliers, presets plus custom thresholds, a one-click "why" banner, and org locks down to a single field (`ai.monthlyBudgetUsd`). The settings layering (defaults < org < user, JSON Merge Patch, Zod schemas in `packages/settings`) and the weight-suggestion endpoint built from feedback give admins levers that gateway products rarely expose.

**4. Conservative actions and recoverability.**
The product never deletes mail. "Move" is label/folder plus inbox removal. Shadow mode scores and logs without touching mail. Scans are idempotent per (user, message id). Manual feedback pins a verdict so it is never re-scored. An admin can release or re-quarantine, and the audit log records the actor. For a product that can hide a real invoice, this is the right set of safety valves.

**5. The rule engine is more careful than a keyword list.**
Detectors are pure functions (`packages/detectors/src/index.ts`) with false-positive guards: Damerau distance plus a look-alike skeleton (`paypa1`, `rn` to `m`), brand country domains (`amazon.ca`), tracking-redirect allowances, punycode script-mixing checks, whole-word phrase matching, and content flags that only fire when a sender or link signal also fired. Authentication results are trusted only from the receiving server's own `Authentication-Results` header (`mx.google.com` in `packages/parser`), and the allowlist needs DMARC pass.

**6. The architecture is clean and testable.**
npm workspaces with small packages (`shared`, `parser`, `detectors`, `scoring`, `pipeline`, `ai`, `settings`, `db`, `mail`, `ui`) and a thin API. 474 tests, CI running typecheck, tests and the corpus. A single `MailProvider` interface covers Gmail and Graph. Fakes are strong where it counts: a fake IdP with real JWT signing, PGlite as a real SQL engine. The Phase 4 independent review found no Critical issues and the Important ones were fixed test-first.

**7. Operations features exist for a self-hosted org.**
Role-based dashboard (viewer, analyst, admin) with stats, email log, CSV export, audit log, OIDC SSO, a managed-policy generator for Chrome/Edge/Firefox, daily rollups that survive retention, Prometheus `/metrics` (loopback or token), Docker/compose, and a diagnostic guide (`docs/RUNNING.md`). Admin-controlled spend is bounded three ways (user budget, server cap, org pool).

**8. Shared client code across surfaces.**
`packages/ui` backs the Gmail extension (Firefox and Chrome MV3) and the Outlook add-in. Gmail DOM knowledge is isolated in `apps/extension/src/selectors.ts` (one file, one selector). Server-side verdicts keep working if the banner breaks.

**9. It can now be set up and run without a command line.**
First-run `/setup` gated by a one-time token, signed single-use invite links, browser mailbox connection (OAuth code + PKCE in a signed cookie), role-based People and Account tabs, erasure and sign-out-everywhere, extension tokens capped at user rights, rate limits, a TLS compose profile, key rotation and an operations guide (`docs/ONBOARDING.md`, `docs/OPERATIONS.md`). Untested against real Google and Microsoft, but covered by fakes and a real-server smoke test.

**10. Market (short).** The self-host, explainable, no-vendor-in-the-data-path positioning is coherent with what is built, and the (private) business plan is candid about where it does not fit.

---

## Weaknesses

**1. Almost nothing has run against a real service.** **[OPEN]**
Microsoft Graph, Anthropic, local models, Safe Browsing and RDAP, an OIDC provider, real Postgres through `pg`, the Docker image, the Outlook add-in inside Outlook, and the dashboard in a real browser are all untested (`docs/HANDOFF.md`, "Verification status"). Gmail has had one read-only scan. Expect a batch of integration bugs (token refresh, id translation, CSP, driver differences) on first contact.
*Mitigation:* a two-week soak on your own mailbox plus two friendly ones, Docker on real Postgres, and a click-through of `/admin/` and the Outlook pane, before any further feature work. This is Phase A in the go-to-market plan.

**2. Detection quality is unmeasured, and the AI gate is not met.** **[OPEN]**
The labelled corpus is tiny: 1 phishing, 2 legit, 2 uncertain legit, 2 uncertain phishing, 3 injection `.eml` files (`corpus/`). The Phase 1 gate (recall >= 80 %, FPR <= 2 %) has no real corpus behind it. The Phase 3 A/B harness (`corpus/ab.ts`) uses a keyword stand-in on 4 emails, so "AI raises detection" is unproven. The default weights and thresholds are hand-picked.
*Mitigation:* build a corpus of >= 1,000 phish and >= 5,000 legit messages, with a frozen held-out set and, above all, a "phish that Gmail already delivered" residual set. Run the A/B with a real model (Haiku-class and one local). Publish numbers with confidence intervals. If AI fails the gate, label it experimental.

**3. Ingest is a single sequential polling loop that can miss mail.** **[PARTLY]**
`runWorkerPass` (`apps/api/src/worker.ts`) walks every mailbox in turn and reads only the latest 25 inbox ids. A burst of more than 25 messages between passes is silently missed, latency is up to `POLL_SECONDS` (60), and two workers duplicate work instead of sharing it. `deltaInbox()` exists in the Graph client but the worker does not use it, and there is no Gmail `history.list`. One worker covers roughly 200 to 300 mailboxes (estimate from the go-to-market plan, not measured).
*Mitigation:* Gmail `history.list` from a stored `historyId`, Graph delta in the worker, a leased jobs table (Postgres `SKIP LOCKED`) with sharding, and per-mailbox lag in the metrics. Add push later and keep polling as a fallback.

**4. Onboarding is CLI-only.** **[MOSTLY FIXED]**
Users, mailbox links, tokens and roles come from `npm run api:cli` (`apps/api/src/cli.ts`). There is no sign-up, invite flow, "connect your mailbox" web page, billing, or tenant provisioning, and SSO never creates accounts. Self-hosters must also create their own Google Cloud OAuth client and Entra app, which is the largest hurdle and is not yet documented step by step. A non-technical admin cannot get started.
*Mitigation:* a web "connect mailbox" and invite flow, SSO just-in-time provisioning, a 15-minute OAuth setup guide with screenshots, and an org-wide connection (Workspace domain-wide delegation, Microsoft application permission) instead of one consent per employee.

**5. The From-based lists are spoofable, and the rules are easy to evade.** **[PARTLY]**
Allowlist and blocklist match the From header (`checkLists`); the allowlist now needs DMARC pass, but the blocklist and display checks do not. The rules are public-ish, static lists: urgency, credential and greeting phrases are English-only (`URGENCY`, `CREDENTIALS`, `GREETINGS`), the display-name check splits on spaces only, and `protectedDomains` defaults to five brands. An attacker with a fresh domain that passes SPF/DKIM/DMARC, a QR code or an image-only body, or a non-English lure slips under the threshold. "Deterministic agreement" for the AI cap accepts any positive rule flag.
*Mitigation:* localised phrase lists, OCR or QR link extraction, a larger or per-org brand list, a domain-age signal turned on by default where acceptable, and a rule regression corpus built from missed phish in pilots. Treat the AI band as the answer to evasion, but only after the gate is met.

**6. Attachment inspection is shallow.** **[PARTLY]**
Only file names, extensions and ZIP encryption are checked (`packages/detectors`, `packages/parser`). Only ZIP archives are inspected; there is no content scan, hash reputation lookup (a sha256 is stored per attachment but no detector uses it), no macro inspection, and no HTML-attachment analysis. Every `.html`/`.htm` attachment flags as risky, which is noisy for legitimate invoices and receipts. Other archive formats (7z, RAR, ISO) are not looked inside.
*Mitigation:* a file-hash lookup against a threat feed, an HTML-attachment heuristic (form action, base64 redirects) instead of a blanket flag, and basic OOXML macro detection. Keep sandboxing a stated non-goal.

**7. Trust-critical data protection is thin.** **[PARTLY]**
All OAuth tokens sit under one env key (`TOKEN_KEY`) with no KMS or per-org keys, there is no rate limiting on the API (no `@fastify/rate-limit`), no account-deletion endpoint, TLS is left to the operator, and `PUBLIC_URL` is validated only when OIDC is set. A database dump leaks mailbox access for every linked user. There is no LICENSE file.
*Mitigation:* per-org data keys with KMS envelope encryption, rate limiting per IP and token, a Caddy TLS profile in compose, an erasure endpoint, a revocation playbook, and a licence decision before any public release.

**8. Operational visibility is incomplete.** **[MOSTLY FIXED]**
`/metrics` is in-process and only in the API process, so worker queue depth and errors are invisible; the dashboard health panel does not show them. Release and re-quarantine are stored as the target user's own feedback, which skews their false-positive stats and weight suggestions. The dashboard CSV button does not warn about the `x-export-truncated` header. The Postgres advisory lock and add-in race are not covered by real-service tests. There is no backup or restore tooling and no PGlite-to-Postgres migration command.
*Mitigation:* expose worker metrics and per-mailbox lag, record admin actions separately from user feedback, add backup/export commands, and test the advisory lock against real Postgres.

**9. The dashboard and extension UX are untested with real users.** **[PARTLY]**
The dashboard has only a JSON editor and lock checkboxes for policy (no form), no user-group filter, and has only been tested with a fake API in happy-dom. Gmail banner injection depends on one data attribute (`data-legacy-message-id`), the Firefox settings page and permission flow have not been exercised, and the extension uses the dev add-on id `anti-phishing-dev@local`. Token paste into a settings page is a poor consumer experience.
*Mitigation:* a policy form, a real-browser test pass (Playwright), canary tests for the Gmail selector, and a real add-on id before store submission.

**10. Some tests are weaker than their names.** **[MOSTLY FIXED]**
`HANDOFF.md` admits that the forged-delimiter and "obedient model" tests cannot really fail, and that rescan drops `first_time_sender`. The AI uncertain band is fixed at 20 to 80 and ignores strict thresholds, and the org budget check is not atomic (it can overshoot by about one call per concurrent scan).
*Mitigation:* rewrite the weak tests against a scripted adversarial model, make the band derive from the thresholds, and make the budget reservation atomic.

**11. Market (short).** One developer, no licence, no billing, no published benchmark: nothing here can be charged for yet (the (private) business plan, section 0).

---

## Opportunities

**1. A measured "residual phish" benchmark would be a genuine differentiator.**
Almost nobody publishes recall and false positives on mail that Gmail or Microsoft already delivered. The corpus runners (`corpus/run.ts`, `corpus/ab.ts`) and the injection corpus already exist. An honest benchmark, failures included, would build trust faster than any feature.

**2. Self-host with a local LLM is a real wedge for privacy-sensitive organisations.**
The code already supports it: `AI_PROVIDER=openai` with a local base URL, PGlite for trials, Postgres in Docker, OIDC, and no mail leaving the network. Self-hosters using their own Internal OAuth client also avoid Google's CASA assessment (the (private) business plan, 4.1). Law firms, clinics and NGOs fit this best.

**3. User feedback is a ready-made improvement loop.**
Feedback is already stored, pins verdicts and feeds `GET /v1/settings/suggestions`. With pilot data this can drive per-org weight tuning, a trained lightweight classifier as a rule feature, and a labelled dataset for the corpus.

**4. The banner as "training at the moment of risk".**
Because every verdict names its flags, the Gmail and Outlook banner doubles as just-in-time awareness training. This can pair with, rather than compete against, awareness-training vendors.

**5. Cheap detection upgrades are within reach.** *(Done since the first version: localised phrase lists, HTML-attachment form and script analysis, macro and archive checks, punctuation-proof display names. Still open: QR/image links, `Received` checks, BEC patterns, per-org inferred brands.)*
Safe Browsing and RDAP are built behind opt-in flags and only need real-service validation. Other high-value additions fit the existing detector shape: first-hop `Received` checks, QR code and image link extraction, HTML-attachment form analysis, localised phrase lists, per-org brand lists inferred from allowlisted senders, and a BEC pattern (reply-chain hijack, bank-detail change).

**5b. Operational reach.** *(Partly done: leased, concurrent workers; browser onboarding. Still open: Workspace delegation, Microsoft application permission, push.)*
An org-wide connection (Workspace delegation, Microsoft application permission) and push ingest (Pub/Sub, Graph subscriptions) would turn a per-employee, 60-second poller into something an IT admin can deploy in an afternoon. The code already has `ROLE=api|worker|all`, which gives a split into services for free.

**6. Market (short).** The SMB segment priced out of Abnormal and Proofpoint, MSPs wanting an explainable add-on, and a licence split (AGPL core plus commercial add-ons) all remain open. Detail and pricing are in the (private) business plan.

---

## Threats

**1. The detection gap may be small: Gmail and Microsoft already filter pre-delivery.**
This product sees only mail that the provider let through, post-delivery. If lift on the residual set is low, the product is a banner with nothing to say. This risk is rated High in the (private) business plan, section 7.4.
*Mitigation:* measure the residual set first (Weakness 2). If the lift is small, sell explainability, banners and self-hosting rather than catch rate, and never claim to beat the provider.

**2. Attackers can adapt to a rule set that is published and static.**
Open code and fixed weights let an attacker test a lure until it scores under 30. Look-alike checks only cover `protectedDomains`, content phrases are English, and clean-auth fresh domains pass the authentication flags. LLM-generated, well-written lures defeat the greeting and urgency heuristics.
*Mitigation:* keep a regression corpus of evaded samples, rely on signals that cost the attacker something (domain age, threat feeds, reply-to, link mismatch), ship rule and brand-list updates as a feed, and keep AI as a separate, non-public-weight signal once it passes the gate.

**3. A false positive that hides a critical email, with no recourse, destroys trust.**
Moves are reversible, but an invoice or legal notice in a Phishing folder can still be missed. Spoofable From-based lists and noisy flags (every `.html` attachment, link mismatch) raise this risk. Users drop tools that hide real mail.
*Mitigation:* ship in shadow mode, label-only before move, a FPR gate (<= 0.5 % at "Balanced"), a weekly digest of moved mail, and keep the one-click release path working end to end in a real client.

**4. Dependence on Gmail and Graph APIs, OAuth verification and provider policy.**
`gmail.modify` is a restricted scope. A public hosted Gmail product needs OAuth verification plus an annual CASA assessment (estimated $3k to $15k and weeks of work). Unverified apps are limited and show a warning. Microsoft blocks end-user consent for unverified multi-tenant apps. Refresh tokens can be revoked (the mailer unlinks revoked ones, but the user then silently loses protection). API quotas, scope changes or Gmail DOM changes can break the product with no warning.
*Mitigation:* self-host first (each org uses its own Internal client), start CASA early if hosting, complete Microsoft publisher verification, alert on revocation spikes, and keep the server-side verdict path independent of the banner.

**5. A token database is a high-value breach target.**
It holds mailbox write access for every linked user under a single `TOKEN_KEY`, and the dashboard token lives in `sessionStorage`. One compromise has severe impact on customers and on a solo operator.
*Mitigation:* KMS envelope encryption with per-org keys, Postgres row-level security, least-privilege DB roles, rate limiting, a published security page and an incident playbook, and the narrowest scopes available.

**6. Solo-developer bus factor and a growing support surface.**
One person must own detection, two mail providers, three front-ends, ops and compliance. Reviews already found real issues (prototype pollution, URLs with tokens sent to the model). The repository has no licence and no release process.
*Mitigation:* self-host-first to push operations onto customers, a documented runbook, a licence and signed releases, and a part-time second engineer before hosted GA.

**7. Competition and bundling (market, short).**
Sublime Security already holds the open-source detection position, Defender P1 is being bundled into M365 Business Standard, and Google's built-in filter is free. Positioning on Workspace plus self-host, SMB simplicity and privacy is the defensible response (the (private) business plan, 1 and 7.4).

**8. Scale and abuse limits of the current design.** *(Partly addressed: rate limits, link-lookup cap, leased concurrent workers. Still open: atomic AI budget, per-tenant isolation.)*
No rate limiting, a sequential worker, an AI budget check that can overshoot, and unbounded link lookups per email (Safe Browsing also receives the URL path) make a hostile or very large tenant a risk to the rest.
*Mitigation:* rate limits and quotas, a link-lookup cap, a leased and sharded worker, and an atomic budget reservation.

---

## Top 5: what to fix or build next

*Status: item 3 is partly done, item 4 mostly done, item 5 partly done. Items 1 and 2 are untouched, and they are the ones that decide whether the product has a future.*

1. **Run everything against real services and soak it.** Docker on real Postgres, Gmail act mode on your own mailbox, Graph and the Outlook pane in a real tenant, the dashboard in a real browser, and a real model. Fix what breaks. Nothing else is trustworthy until this is done.
2. **Build the real corpus and run the real A/B.** At least 1,000 phish and 5,000 legit, a frozen held-out set, a residual (provider-delivered) set, intervals on recall and FPR, and a real-model AI run. This decides whether AI ships and what the product can honestly claim.
3. **Fix ingest: Gmail history, Graph delta, leased and sharded workers.** Remove the 25-message window and the sequential loop, and expose worker lag in the metrics and dashboard.
4. **Self-serve onboarding and security hardening.** Web mailbox-connect and invites, an OAuth setup guide, rate limiting, KMS or per-org token keys, a Caddy TLS profile, an erasure endpoint, and a LICENSE.
5. **Harden detection against evasion and noise.** Stop blanket `.html` flagging, add attachment hash/HTML heuristics, localised phrases, per-org brand lists, a spoof-resistant blocklist, and a regression corpus of missed samples from pilots.

---

## Overall verdict

The product is a well-structured, privacy-conscious and unusually safe design: the AI cannot lower a score or act alone, mail is never deleted, every verdict is explained, and the code is modular, tested and reviewed. Its weaknesses are about proof, not design. Real services have barely been touched, the labelled corpus is a handful of files, the AI gate is unmet, ingest is a sequential 25-message poller, and onboarding needs a developer at a command line. The biggest strategic risk is that mail already delivered by Gmail or Microsoft may leave little for this layer to catch, so the first job is to measure that residual before building more. If the numbers hold, the self-hosted, explainable, local-LLM niche is credible and the base is good enough to build on. If they do not, the same code is still a useful explainable banner and admin tool, but it should not be sold as better detection.
