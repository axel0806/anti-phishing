import { useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { ApiError, forgetToken, makeApi, saveToken, takeToken, visibleTabs, type Me } from "./api.ts";
import { Panel, Status, useLoad } from "./components.tsx";
import { AccountTab, AuditTab, DeployTab, EmailLog, ListsTab, Overview, PeopleTab, PolicyTab } from "./panels.tsx";

function SignIn({ onToken, notice }: { onToken: (t: string) => void; notice?: string }) {
  const [t, setT] = useState("");
  return (
    <main className="narrow">
      <Panel title="Sign in">
        {notice && <p className="error" role="alert">{notice}</p>}
        <p><a className="button" href="/admin/login">Sign in with single sign-on</a></p>
        <p className="muted">New server with no users yet? <a href="/setup">Run first-time setup</a>.</p>
        <p className="muted">If single sign-on is not set up, paste a session token (an administrator can create one with <code>npm run api:cli -- token</code>).</p>
        <form onSubmit={(e) => { e.preventDefault(); if (t.trim()) onToken(t.trim()); }}>
          <label className="block">Session token <input type="password" autoComplete="off" value={t} onChange={(e) => setT(e.target.value)} /></label>
          <button type="submit">Continue</button>
        </form>
      </Panel>
    </main>
  );
}

function Shell({ token, onSignOut }: { token: string; onSignOut: (notice?: string) => void }) {
  const api = useMemo(() => makeApi(token), [token]);
  const me = useLoad(() => api.get<Me>("/v1/me").catch((e) => { if (e instanceof ApiError && e.status === 401) onSignOut("Your session has expired. Please sign in again."); throw e; }), [api]);
  const [tab, setTab] = useState("overview");
  if (!me.data) return <main className="narrow"><Status loading={me.loading} error={me.error} /></main>;
  const u = me.data;
  const tabs = visibleTabs(u.role);
  if (!u.orgId || !tabs.length) return <main className="narrow"><Panel title="No access"><p>Your account ({u.email}) is not part of an organization with dashboard access.</p><button type="button" onClick={() => onSignOut()}>Sign out</button></Panel></main>;
  const current = tabs.some((t) => t.id === tab) ? tab : "overview";
  return (
    <>
      <header className="top">
        <strong>Anti-phishing</strong>
        <nav aria-label="Sections">{tabs.map((t) => <button key={t.id} type="button" className={t.id === current ? "tab on" : "tab"} aria-current={t.id === current} onClick={() => setTab(t.id)}>{t.label}</button>)}</nav>
        <span className="who">{u.email} · {u.role} <button type="button" className="ghost" onClick={() => onSignOut()}>Sign out</button></span>
      </header>
      <main>
        {current === "overview" && <Overview api={api} me={u} />}
        {current === "log" && <EmailLog api={api} me={u} />}
        {current === "people" && <PeopleTab api={api} me={u} />}
        {current === "lists" && <ListsTab api={api} />}
        {current === "policy" && <PolicyTab api={api} me={u} />}
        {current === "deploy" && <DeployTab />}
        {current === "audit" && <AuditTab api={api} />}
        {current === "account" && <AccountTab api={api} me={u} onErased={() => onSignOut("Your account was erased.")} onSignedOutEverywhere={() => onSignOut("You were signed out everywhere. Sign in again.")} />}
      </main>
    </>
  );
}

function App() {
  const [token, setToken] = useState<string | null>(() => {
    const t = takeToken(window.location.hash, window.sessionStorage);
    if (window.location.hash) history.replaceState(null, "", window.location.pathname + window.location.search); // never leave the token in the address bar
    return t;
  });
  const [notice, setNotice] = useState<string | undefined>();
  const signOut = (n?: string) => { forgetToken(window.sessionStorage); setToken(null); setNotice(n); };
  if (!token) return <SignIn notice={notice} onToken={(t) => { saveToken(window.sessionStorage, t); setNotice(undefined); setToken(t); }} />;
  return <Shell token={token} onSignOut={signOut} />;
}

createRoot(document.getElementById("root")!).render(<App />);
