# Contributing

Thanks for helping. This project protects people's inboxes, so it values small, well-tested, explainable changes over big clever ones. You do not need to be a security expert to help.

## Ways to help (easiest first)

1. **Send us emails.** The detection corpus is tiny, and that is the project's biggest weakness. Add phishing emails you received and legitimate emails that look suspicious (newsletters, invoices, password resets). **Remove personal details first** (names, addresses, account numbers, tracking links); use `.example` domains where you can. Put them in `corpus/phishing/`, `corpus/legit/` or `corpus/uncertain/` as `.eml` files and run `npm run corpus`.
2. **Run shadow mode and report what it got wrong.** Missed phish and false alarms are the most valuable bug reports. Use the *Detection feedback* issue template: no email content, just the flags and your description.
3. **Fix a bug or improve the docs.** Look for issues labelled `good first issue` or `help wanted`.
4. **Add or improve a detector** (see below), a language's phrase list, or a brand for the protected list.
5. **Review** open pull requests.

## Set up

```bash
git clone https://github.com/<you>/anti-phishing.git && cd anti-phishing
npm install
npm test            # all tests
npm run typecheck   # tsc --noEmit
npm run corpus      # recall / false-positive rate on corpus/
```

Node.js 22+. No database or accounts are needed to run the tests (an embedded Postgres, PGlite, is used). To run the whole server, see [docs/RUNNING.md](docs/RUNNING.md).

## Making a change

1. Open an issue first for anything bigger than a small fix, so we can agree on the approach.
2. Branch from `main` and keep the pull request focused on one thing.
3. **Write the test first**, watch it fail, then make it pass. A bug fix needs a test that fails without the fix.
4. Run `npm test` and `npm run typecheck`; CI runs both, plus the corpus.
5. Describe what changed and why in the pull request. Screenshots help for dashboard changes.

## Project layout in one minute

- `packages/detectors/src/index.ts`: the rule engine. Each detector is a pure function from a parsed email to flags.
- `packages/shared/src/index.ts`: the flag catalog and default weights, types, default settings.
- `packages/scoring`, `packages/pipeline`: turning flags into a score and verdict, and the optional AI stage.
- `packages/parser`: raw MIME to a parsed email (links, attachments, trusted authentication results).
- `apps/api`: the server. `apps/dashboard`, `apps/extension`, `apps/outlook-addin`: the front ends.
- [docs/HANDOFF.md](docs/HANDOFF.md) lists the design decisions and the gotchas. Please read its "Key design decisions" section before changing behaviour.

### Adding a detector

1. Add the flag id, category and default weight to `packages/shared/src/index.ts`.
2. Write the detector in `packages/detectors/src/index.ts` and register it in `runDetectors`.
3. Test it in `packages/detectors/test/`, **including a test that a legitimate look-alike does not fire.** False positives hide real mail and cost trust; they matter more than catching one more phish.
4. Add a sample to `corpus/` and check that `npm run corpus` still shows 0 false positives.

## Rules that are not negotiable

- **The AI can only add points**, never subtract, and cannot create a Phishing verdict without a rule flag. Any AI failure returns the exact rules-only verdict.
- **Privacy:** never store message bodies, never send URL paths or tokens to a model or an outside service, and redact before anything leaves the process.
- **Never delete mail.** Moves are reversible.
- Anything that sends data to a third party must be opt-in and documented.
- **Attacker-controlled input must be bounded.** Regular expressions over attachments or bodies use bounded repetition (`{0,300}`, not `*`), because one crafted file must not be able to freeze the server.

## Style

TypeScript, strict mode. Match the surrounding code, keep functions small, and comment *why*, not what. No new dependency without a good reason. Windows, macOS and Linux all work; line-ending noise from autocrlf is common on Windows, so please do not reformat whole files.

## Conduct and security

Be kind: see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security problems go through [SECURITY.md](SECURITY.md), not public issues.

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).
