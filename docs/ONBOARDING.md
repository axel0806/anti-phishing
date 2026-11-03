# Set up your own server and add people (about 15 minutes)

You need a server reachable over **https** (or `http://localhost` for a trial), and an app registration at Google and/or Microsoft so the server may read and sort mail on people's behalf. Each organization that self-hosts registers its **own** app, so no outside party ever sees your mail.

## 1. Server settings

Put these in `.env` (see `.env.example`):

| Setting | Value |
| --- | --- |
| `SERVER_SECRET` | 32+ random characters |
| `TOKEN_KEY` | 64 hex characters |
| `PUBLIC_URL` | The address people open, e.g. `https://phish.example.com` (no trailing slash) |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | From step 2 (Gmail / Google Workspace) |
| `MICROSOFT_CLIENT_ID` / `MICROSOFT_CLIENT_SECRET` / `MICROSOFT_TENANT` | From step 3 (Outlook / Microsoft 365) |
| `SETUP_TOKEN` (optional) | 16+ characters. If unset, one is generated and printed at startup |

Generate secrets with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`.

## 2. Google (Gmail, Google Workspace)

1. Open the Google Cloud console, create a project, and enable the **Gmail API**.
2. **OAuth consent screen**: choose *Internal* if everyone is in your Workspace domain (no Google review needed). Otherwise choose *External*; while it is in *Testing* only the test users you list can connect, and Google limits unverified apps to 100 users.
3. Add the scope `https://www.googleapis.com/auth/gmail.modify`.
4. **Credentials > Create credentials > OAuth client ID > Web application**.
5. Add the authorized redirect URI **`<PUBLIC_URL>/connect/callback`**, exactly (for a trial: `http://localhost:8080/connect/callback`).
6. Copy the client ID and secret into `.env`.

## 3. Microsoft (Outlook, Microsoft 365)

1. In the Entra admin center: **App registrations > New registration**. Supported account types: *this organization only*, and set `MICROSOFT_TENANT` to the **tenant ID** (a GUID). Browser sign-in for Outlook requires this: with `common`, `organizations` or a domain name, anyone can run their own Microsoft tenant and claim any email address, so the server cannot trust who is signing in. (Those settings still work for the command-line `link-mail`.)
2. Redirect URI, platform **Web**: **`<PUBLIC_URL>/connect/callback`**.
3. **API permissions > Microsoft Graph > Delegated**: `Mail.ReadWrite`, `offline_access`, `openid`, `email`. An admin can grant consent for everyone under *Grant admin consent*, so employees are not asked one by one.
4. **Certificates & secrets**: create a client secret and copy its *value* into `MICROSOFT_CLIENT_SECRET`.

## 4. First run: create the administrator in the browser

1. Start the server: `npm run build:ui && npm run api`.
2. On a new server the log prints `First run: open <PUBLIC_URL>/setup and enter this setup token: ...`.
3. Open that address, enter the token, and choose Gmail or Outlook. Sign in as the person who will administer the system and approve access.
4. You land in the dashboard as **admin**. Your organization was created from your email domain. `/setup` is closed from this moment on, whatever token anyone holds.

## 5. Add people

1. Dashboard > **People** > enter their email address and a role > **Create invite link**.
2. Send them the link (it works for 7 days and only for that address).
3. They open it, connect **their own mailbox**, and get a token to paste into the browser extension or Outlook add-in, together with your server's address. The link works **once**; the token it shows is an *extension token*: it can scan and read settings, but can never act as an administrator, create other tokens or erase the account.
4. Roles: `user` is a protected mailbox only; `viewer` sees the dashboard overview; `analyst` also reads the email log; `admin` manages everything.

If someone's access was revoked, or the link was used up, create a fresh invite for the same address: it reconnects them and keeps their role. To cut a person off at once, use **Sign out** (ends all their sessions and tokens) or **Erase** in the People tab; changing their role also ends their old sessions.

Prefer the command line? `npm run api:cli -- create-user ...` still works.

## 6. Removing people and erasing data

- **Admin**: People > *Erase* removes a person's account, scans, feedback and personal lists.
- **Anyone**: Account > *Erase my account* does the same for yourself. The last admin of an organization must make someone else an admin first.
- Mail is never deleted by this system. To revoke the server's access to a mailbox, remove the app under the person's Google or Microsoft account's connected apps.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `/setup` says "Mailbox connection is not set up" | `PUBLIC_URL` and a Google or Microsoft client are both required |
| Google shows `redirect_uri_mismatch` | The redirect URI in the console is not exactly `<PUBLIC_URL>/connect/callback` |
| "The provider returned no refresh token" | The account already granted access once; remove the app from its connected apps and connect again |
| Outlook is missing from the setup or join page | `MICROSOFT_TENANT` is not a tenant ID (GUID); see step 3 |
| "The Microsoft account is not from this organization's tenant" | They signed in with an account from another Microsoft tenant |
| "This invite was already used" | Invites work once. Create a new one for the same address |
| Microsoft says admin approval is required | An admin must click *Grant admin consent* in step 3 |
| Invite page says the link is invalid | It expired (7 days) or was copied incompletely |
| "This invite is for X, but you signed in as Y" | They chose a different account in the Google or Microsoft picker |
