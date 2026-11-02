# Anti-Phishing Email Extension

AI-assisted browser extension and backend that scores incoming email against weighted red flags and moves likely phishing to a dedicated folder.

See [plan.md](plan.md) for the detailed design and build plan. The original design export is kept alongside it.

## Phase 1 quick start (Gmail, local)

1. Copy `.env.example` to `.env` and fill in `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` (Desktop-app OAuth client; add yourself as a test user).
2. `npm install`, then `npm run login` and approve the `gmail.modify` scope in the browser.
3. `npm start` runs in **shadow mode**: it scores your inbox and prints verdicts, and changes nothing. Add `--act` (`npm run start:act`) to apply the `Phishing` / `Suspicious` labels.
4. `npm run build:ext`, then load `apps/extension/dist` via `chrome://extensions` > Developer mode > Load unpacked. Open a Gmail message while `npm start` is running to see the banner.
5. `npm test` runs all tests; `npm run corpus` reports recall / false-positive rate for `corpus/`.
