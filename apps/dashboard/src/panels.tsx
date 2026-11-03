import { useState } from "react";
import { FLAG_IDS } from "@ap/shared";
import { LOCKABLE, checkServerUrl, chromeManagedPolicy, defaultRange, firefoxPolicy, parseBulkImport, pct, qs, toggleLock, usd, atLeast, type Api, type ListEntry, type Me, type Range } from "./api.ts";
import { BarList, CsvButton, Panel, Stat, Status, TrendChart, delta, message, useLoad } from "./components.tsx";

interface Counts { scanned: number; safe: number; suspicious: number; phishing: number; falsePositives: number; aiCalls: number; phishingRate: number }
const stats = (api: Api, panel: string, r: Range) => `/v1/admin/stats/${panel}${qs(r)}`;

export function RangePicker({ range, onChange }: { range: Range; onChange: (r: Range) => void }) {
  return (
    <div className="range">
      <label>From <input type="date" value={range.from} max={range.to} onChange={(e) => e.target.value && onChange({ ...range, from: e.target.value })} /></label>
      <label>To (exclusive) <input type="date" value={range.to} min={range.from} onChange={(e) => e.target.value && onChange({ ...range, to: e.target.value })} /></label>
      {[7, 30, 90].map((d) => <button key={d} type="button" className="ghost" onClick={() => onChange(defaultRange(d))}>{d}d</button>)}
    </div>
  );
}

export function Overview({ api, me }: { api: Api; me: Me }) {
  const [range, setRange] = useState<Range>(() => defaultRange(30));
  const ov = useLoad(() => api.get<{ current: Counts; previous: Counts }>(stats(api, "overview", range)), [range.from, range.to]);
  const trend = useLoad(() => api.get<{ rows: { date: string; suspicious: number; phishing: number }[] }>(stats(api, "trend", range)), [range.from, range.to]);
  const flags = useLoad(() => api.get<{ rows: { flagId: string; fired: number; inPhishing: number; falsePositives: number; falsePositiveRate: number }[] }>(stats(api, "flags", range)), [range.from, range.to]);
  const targets = useLoad(() => api.get<{ impersonated: { evidence: string; count: number }[]; senderDomains: { domain: string; count: number }[] }>(stats(api, "targets", range)), [range.from, range.to]);
  const quality = useLoad(() => api.get<{ falsePositives: number; missesReported: number }>(stats(api, "quality", range)), [range.from, range.to]);
  const ai = useLoad(() => api.get<{ calls: number; costUsd: number; escalated: number; scanned: number; escalatedShare: number }>(stats(api, "ai", range)), [range.from, range.to]);
  const health = useLoad(() => api.get<{ scans24h: number; p50Ms: number; p95Ms: number; lastScanAt: string | null; linkedMailboxes: number }>(stats(api, "health", range)), []);
  const users = useLoad(() => (atLeast(me.role, "admin") ? api.get<{ rows: { email: string; phishing: number; suspicious: number }[] }>(stats(api, "users", range)) : Promise.resolve(null)), [range.from, range.to, me.role]);
  const c = ov.data?.current, p = ov.data?.previous;

  return (
    <>
      <RangePicker range={range} onChange={setRange} />
      <Panel title="Summary" actions={<CsvButton api={api} path={stats(api, "overview", range)} name="overview" />}>
        <Status loading={ov.loading} error={ov.error} />
        {c && p && (
          <div className="stats">
            <Stat label="Scanned" value={c.scanned} sub={delta(c.scanned, p.scanned) ?? undefined} />
            <Stat label="Phishing" value={c.phishing} sub={delta(c.phishing, p.phishing) ?? undefined} />
            <Stat label="Suspicious" value={c.suspicious} sub={delta(c.suspicious, p.suspicious) ?? undefined} />
            <Stat label="Phishing rate" value={pct(c.phishingRate)} />
            <Stat label="Marked not phishing" value={c.falsePositives} />
            <Stat label="AI calls" value={c.aiCalls} />
          </div>
        )}
      </Panel>
      <Panel title="Detections per day" actions={<CsvButton api={api} path={stats(api, "trend", range)} name="trend" />}>
        <Status loading={trend.loading} error={trend.error} />
        {trend.data && <TrendChart rows={trend.data.rows} />}
        <p className="legend"><i className="sw phish" /> phishing <i className="sw susp" /> suspicious</p>
      </Panel>
      <div className="grid2">
        <Panel title="Top red flags" actions={<CsvButton api={api} path={stats(api, "flags", range)} name="flags" />}>
          <Status loading={flags.loading} error={flags.error} />
          {flags.data && (
            <table>
              <thead><tr><th>Flag</th><th>Fired</th><th>In phishing</th><th>False positives</th></tr></thead>
              <tbody>{flags.data.rows.map((r) => <tr key={r.flagId}><td>{r.flagId}</td><td>{r.fired}</td><td>{r.inPhishing}</td><td>{r.falsePositives} ({pct(r.falsePositiveRate)})</td></tr>)}</tbody>
            </table>
          )}
        </Panel>
        <Panel title="Impersonated brands" actions={<CsvButton api={api} path={stats(api, "targets", range)} name="targets" />}>
          <Status loading={targets.loading} error={targets.error} />
          {targets.data && <BarList items={targets.data.impersonated.map((x) => ({ label: x.evidence, value: x.count }))} />}
        </Panel>
        <Panel title="Top sender domains">
          {targets.data && <BarList items={targets.data.senderDomains.map((x) => ({ label: x.domain, value: x.count }))} />}
        </Panel>
        <Panel title="Detection quality" actions={<CsvButton api={api} path={stats(api, "quality", range)} name="quality" />}>
          <Status loading={quality.loading} error={quality.error} />
          {quality.data && <div className="stats"><Stat label="False positives reported" value={quality.data.falsePositives} /><Stat label="Misses reported" value={quality.data.missesReported} /></div>}
        </Panel>
        <Panel title="AI usage" actions={<CsvButton api={api} path={stats(api, "ai", range)} name="ai" />}>
          <Status loading={ai.loading} error={ai.error} />
          {ai.data && <div className="stats"><Stat label="Calls" value={ai.data.calls} /><Stat label="Cost" value={usd(ai.data.costUsd)} /><Stat label="Escalated share" value={pct(ai.data.escalatedShare)} sub={`${ai.data.escalated} of ${ai.data.scanned}`} /></div>}
        </Panel>
        <Panel title="System health">
          <Status loading={health.loading} error={health.error} />
          {health.data && (
            <div className="stats">
              <Stat label="Scans, last 24h" value={health.data.scans24h} />
              <Stat label="Latency p50 / p95" value={`${Math.round(health.data.p50Ms)} / ${Math.round(health.data.p95Ms)} ms`} />
              <Stat label="Linked mailboxes" value={health.data.linkedMailboxes} />
              <Stat label="Last scan" value={health.data.lastScanAt ? new Date(health.data.lastScanAt).toLocaleString() : "never"} />
            </div>
          )}
        </Panel>
      </div>
      {users.data && (
        <Panel title="Most targeted users" actions={<CsvButton api={api} path={stats(api, "users", range)} name="users" />}>
          <BarList items={users.data.rows.map((r) => ({ label: r.email, value: r.phishing + r.suspicious, note: `${r.phishing} phishing` }))} />
          <p className="muted">Viewing this list is recorded in the audit log.</p>
        </Panel>
      )}
    </>
  );
}

interface LogRow { messageId: string; userId: string; userEmail: string; sender: string | null; score: number; verdict: string; pinned: boolean; createdAt: string; flags: string[] }
const PAGE = 50;

export function EmailLog({ api, me }: { api: Api; me: Me }) {
  const [range, setRange] = useState<Range>(() => defaultRange(7));
  const [verdict, setVerdict] = useState("");
  const [flag, setFlag] = useState("");
  const [sender, setSender] = useState("");
  const [applied, setApplied] = useState({ verdict: "", flag: "", sender: "" });
  const [offset, setOffset] = useState(0);
  const [note, setNote] = useState<string | null>(null);
  const query = qs({ ...range, ...applied, limit: PAGE, offset });
  const log = useLoad(() => api.get<{ rows: LogRow[]; total: number }>(`/v1/admin/scans${query}`), [query]);
  const isAdmin = atLeast(me.role, "admin");

  const act = async (row: LogRow, verb: "release" | "requarantine") => {
    if (!window.confirm(`${verb === "release" ? "Release" : "Re-quarantine"} this message in ${row.userEmail}'s mailbox?`)) return;
    try { await api.post(`/v1/admin/users/${encodeURIComponent(row.userId)}/messages/${encodeURIComponent(row.messageId)}/${verb}`, {}); setNote(`Message ${verb === "release" ? "released" : "re-quarantined"}.`); log.reload(); }
    catch (e) { setNote(message(e)); }
  };

  return (
    <>
      <RangePicker range={range} onChange={(r) => { setOffset(0); setRange(r); }} />
      <Panel title="Email log" actions={<CsvButton api={api} path={`/v1/admin/scans${qs({ ...range, ...applied, limit: 100000 })}`} name="scans" />}>
        <form className="filters" onSubmit={(e) => { e.preventDefault(); setOffset(0); setApplied({ verdict, flag, sender }); }}>
          <label>Verdict <select value={verdict} onChange={(e) => setVerdict(e.target.value)}><option value="">any</option><option>safe</option><option>suspicious</option><option>phishing</option></select></label>
          <label>Flag <select value={flag} onChange={(e) => setFlag(e.target.value)}><option value="">any</option>{FLAG_IDS.map((f) => <option key={f}>{f}</option>)}</select></label>
          <label>Sender contains <input value={sender} maxLength={200} onChange={(e) => setSender(e.target.value)} /></label>
          <button type="submit">Filter</button>
        </form>
        <p className="muted">Opening this log is recorded in the audit log. Subjects and bodies are never stored.</p>
        {note && <p role="status">{note}</p>}
        <Status loading={log.loading} error={log.error} />
        {log.data && (
          <>
            <table>
              <thead><tr><th>When</th><th>Mailbox</th><th>Sender</th><th>Score</th><th>Verdict</th><th>Flags</th>{isAdmin && <th />}</tr></thead>
              <tbody>
                {log.data.rows.map((r) => (
                  <tr key={r.userEmail + r.messageId}>
                    <td>{new Date(r.createdAt).toLocaleString()}</td><td>{r.userEmail}</td><td>{r.sender ?? "—"}</td><td>{r.score}</td>
                    <td><span className={`pill ${r.verdict}`}>{r.verdict}</span>{r.pinned ? " (manual)" : ""}</td>
                    <td>{r.flags.join(", ")}</td>
                    {isAdmin && <td className="nowrap"><button type="button" className="ghost" onClick={() => act(r, "release")}>Release</button> <button type="button" className="ghost" onClick={() => act(r, "requarantine")}>Quarantine</button></td>}
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="pager">
              <button type="button" className="ghost" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</button>
              <span>{log.data.total === 0 ? "No results" : `${offset + 1}–${Math.min(offset + PAGE, log.data.total)} of ${log.data.total}`}</span>
              <button type="button" className="ghost" disabled={offset + PAGE >= log.data.total} onClick={() => setOffset(offset + PAGE)}>Next</button>
            </div>
          </>
        )}
      </Panel>
    </>
  );
}

interface Lists { allow: ListEntry[]; block: ListEntry[] }

export function ListsTab({ api }: { api: Api }) {
  const lists = useLoad(() => api.get<Lists>("/v1/lists?scope=org"), []);
  const [kind, setKind] = useState<"allow" | "block">("block");
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const parsed = parseBulkImport(text);

  const run = async (entries: ListEntry[], k: "allow" | "block", verb: "post" | "del") => {
    setBusy(true); setMsg(null);
    let ok = 0; const failed: string[] = [];
    for (const e of entries) {
      try { await api[verb](`/v1/lists/${k}`, { ...e, scope: "org" }); ok++; } catch (err) { failed.push(`${e.value}: ${message(err)}`); }
    }
    setBusy(false);
    setMsg(`${verb === "post" ? "Added" : "Removed"} ${ok} of ${entries.length}.${failed.length ? " Failed: " + failed.slice(0, 5).join("; ") : ""}`);
    if (verb === "post" && !failed.length) setText("");
    lists.reload();
  };

  return (
    <>
      <Panel title="Organization lists">
        <p className="muted">Entries apply to every mailbox in the organization. An allowlist entry only counts when the message passed DMARC.</p>
        <Status loading={lists.loading} error={lists.error} />
        {lists.data && (["allow", "block"] as const).map((k) => (
          <div key={k}>
            <h3>{k === "allow" ? "Allowlist" : "Blocklist"} ({lists.data![k].length})</h3>
            {lists.data![k].length === 0 ? <p className="muted">Empty.</p> : (
              <ul className="entries">
                {lists.data![k].map((e) => <li key={e.matchType + e.value}><code>{e.value}</code> <small>{e.matchType}</small> <button type="button" className="ghost" disabled={busy} onClick={() => run([e], k, "del")}>Remove</button></li>)}
              </ul>
            )}
          </div>
        ))}
      </Panel>
      <Panel title="Add or import">
        <label>List <select value={kind} onChange={(e) => setKind(e.target.value as "allow" | "block")}><option value="block">Blocklist</option><option value="allow">Allowlist</option></select></label>
        <label className="block">Addresses or domains, one per line (or comma-separated; lines starting with # are ignored)
          <textarea rows={6} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} />
        </label>
        <p className="muted">{parsed.entries.length} valid{parsed.rejected.length ? `, ${parsed.rejected.length} not recognised: ${parsed.rejected.slice(0, 5).join(", ")}` : ""}</p>
        <button type="button" disabled={busy || !parsed.entries.length} onClick={() => run(parsed.entries, kind, "post")}>Add {parsed.entries.length || ""} to {kind}list</button>
        {msg && <p role="status">{msg}</p>}
      </Panel>
    </>
  );
}

interface Policy { values: Record<string, unknown>; locked: string[] }

export function PolicyTab({ api, me }: { api: Api; me: Me }) {
  const path = `/v1/orgs/${me.orgId}/policy`;
  const pol = useLoad(() => api.get<Policy>(path), [path]);
  const [draft, setDraft] = useState<{ json: string; locked: string[] } | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  if (pol.data && !draft) setDraft({ json: JSON.stringify(pol.data.values, null, 2), locked: pol.data.locked });

  const save = async () => {
    if (!draft) return;
    setMsg(null); setErr(null);
    let values: unknown;
    try { values = JSON.parse(draft.json); } catch { return setErr("The settings are not valid JSON."); }
    try { await api.put(path, { values, locked: draft.locked }); setMsg("Policy saved."); } catch (e) { setErr(message(e)); }
  };

  return (
    <Panel title="Organization policy">
      <p className="muted">Values here become the default for every user. A locked setting cannot be changed by users (a dotted lock such as <code>ai.monthlyBudgetUsd</code> locks one field). Changes are recorded in the audit log.</p>
      <Status loading={pol.loading} error={pol.error} />
      {draft && (
        <>
          <label className="block">Settings (JSON)
            <textarea rows={14} value={draft.json} onChange={(e) => setDraft({ ...draft, json: e.target.value })} spellCheck={false} />
          </label>
          <fieldset>
            <legend>Locked for users</legend>
            {LOCKABLE.map((k) => (
              <label key={k} className="check"><input type="checkbox" checked={draft.locked.includes(k)} onChange={(e) => setDraft({ ...draft, locked: toggleLock(draft.locked, k, e.target.checked) })} /> <code>{k}</code></label>
            ))}
          </fieldset>
          <button type="button" onClick={save}>Save policy</button>
          {msg && <p role="status">{msg}</p>}
          {err && <p className="error" role="alert">{err}</p>}
        </>
      )}
    </Panel>
  );
}

const FIREFOX_ID = "anti-phishing-dev@local";

export function DeployTab() {
  const [url, setUrl] = useState(window.location.origin);
  const [lock, setLock] = useState(true);
  const [ffId, setFfId] = useState(FIREFOX_ID);
  const problem = checkServerUrl(url);
  const o = { serverUrl: url, lockServerUrl: lock };
  return (
    <>
      <Panel title="Managed policy generator">
        <p className="muted">Pre-configures the browser extension so employees do not type a server address. Deploy the Chrome/Edge JSON as the extension's managed storage policy; Firefox reads the <code>3rdparty</code> block from <code>policies.json</code>.</p>
        <label className="block">Server URL <input value={url} onChange={(e) => setUrl(e.target.value)} /></label>
        {problem && <p className="error">{problem}</p>}
        <label className="check"><input type="checkbox" checked={lock} onChange={(e) => setLock(e.target.checked)} /> Stop users changing the server URL</label>
        <label className="block">Firefox extension id <input value={ffId} onChange={(e) => setFfId(e.target.value)} /></label>
        {!problem && (
          <>
            <h3>Chrome / Edge</h3><pre>{JSON.stringify(chromeManagedPolicy(o), null, 2)}</pre>
            <h3>Firefox</h3><pre>{JSON.stringify(firefoxPolicy(o, ffId), null, 2)}</pre>
          </>
        )}
      </Panel>
      <Panel title="Outlook add-in">
        <p>Download the manifest and sideload it, or deploy it centrally in the Microsoft 365 admin center (Integrated apps).</p>
        <p><a href="/addin/manifest.xml" download>Download manifest.xml</a> <small className="muted">(requires PUBLIC_URL to be set on the server)</small></p>
      </Panel>
    </>
  );
}

export function AuditTab({ api }: { api: Api }) {
  const [offset, setOffset] = useState(0);
  const audit = useLoad(() => api.get<{ rows: { createdAt: string; actorEmail: string | null; action: string; target: string | null }[] }>(`/v1/admin/audit?limit=100&offset=${offset}`), [offset]);
  return (
    <Panel title="Audit log">
      <Status loading={audit.loading} error={audit.error} />
      {audit.data && (
        <>
          <table>
            <thead><tr><th>When</th><th>Who</th><th>Action</th><th>Detail</th></tr></thead>
            <tbody>{audit.data.rows.map((r, i) => <tr key={i}><td>{new Date(r.createdAt).toLocaleString()}</td><td>{r.actorEmail ?? "(removed user)"}</td><td>{r.action}</td><td>{r.target ?? ""}</td></tr>)}</tbody>
          </table>
          <div className="pager">
            <button type="button" className="ghost" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>Newer</button>
            <button type="button" className="ghost" disabled={audit.data.rows.length < 100} onClick={() => setOffset(offset + 100)}>Older</button>
          </div>
        </>
      )}
    </Panel>
  );
}

interface OrgUser { id: string; email: string; role: "user" | "viewer" | "analyst" | "admin"; provider: string; linked: boolean }
const ROLE_HELP: Record<string, string> = { user: "protected mailbox only", viewer: "dashboard overview", analyst: "+ email log", admin: "everything" };

/** Invite colleagues, change roles, remove people. Invites are links the invitee opens to connect their own mailbox. */
export function PeopleTab({ api, me }: { api: Api; me: Me }) {
  const people = useLoad(() => api.get<{ users: OrgUser[] }>("/v1/admin/org-users"), []);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("user");
  const [link, setLink] = useState<{ url: string; email: string; expiresAt: string } | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const run = async (fn: () => Promise<unknown>, ok: string) => {
    setMsg(null); setErr(null);
    try { await fn(); setMsg(ok); people.reload(); } catch (e) { setErr(message(e)); }
  };
  return (
    <>
      <Panel title="Invite someone">
        <p className="muted">They open the link, connect their own Gmail or Outlook mailbox, and get their extension token. The link works for 7 days and only for the address you enter.</p>
        <form className="filters" onSubmit={async (e) => {
          e.preventDefault(); setErr(null); setMsg(null); setLink(null);
          try { setLink(await api.post("/v1/admin/invites", { email, role })); setEmail(""); } catch (x) { setErr(message(x)); }
        }}>
          <label>Email <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} /></label>
          <label>Role <select value={role} onChange={(e) => setRole(e.target.value)}>{Object.entries(ROLE_HELP).map(([r, h]) => <option key={r} value={r}>{r} ({h})</option>)}</select></label>
          <button type="submit">Create invite link</button>
        </form>
        {link && <><p>Send this link to <b>{link.email}</b> (expires {new Date(link.expiresAt).toLocaleDateString()}):</p><textarea readOnly rows={3} value={link.url} onFocus={(e) => e.target.select()} /></>}
        {err && <p className="error" role="alert">{err}</p>}
      </Panel>
      <Panel title="People in your organization">
        <Status loading={people.loading} error={people.error} />
        {msg && <p role="status">{msg}</p>}
        {people.data && (
          <table>
            <thead><tr><th>Email</th><th>Role</th><th>Mailbox</th><th /></tr></thead>
            <tbody>
              {people.data.users.map((u) => (
                <tr key={u.id}>
                  <td>{u.email}{u.id === me.id ? " (you)" : ""}</td>
                  <td>{u.id === me.id ? u.role : (
                    <select value={u.role} aria-label={`Role for ${u.email}`} onChange={(e) => run(() => api.patch(`/v1/admin/users/${u.id}`, { role: e.target.value }), "Role updated.")}>
                      {Object.keys(ROLE_HELP).map((r) => <option key={r}>{r}</option>)}
                    </select>)}</td>
                  <td>{u.linked ? `${u.provider} connected` : "not connected"}</td>
                  <td>{u.id !== me.id && <button type="button" className="ghost" onClick={() => { if (window.confirm(`Erase ${u.email} and everything stored about them? This cannot be undone.`)) void run(() => api.del(`/v1/admin/users/${u.id}`), "Person erased."); }}>Erase</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </>
  );
}

/** Self-service: an extension token, and erasing your own account. */
export function AccountTab({ api, me, onErased }: { api: Api; me: Me; onErased: () => void }) {
  const [days, setDays] = useState(30);
  const [tok, setTok] = useState<{ token: string; expiresAt: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  return (
    <>
      <Panel title="Extension and add-in token">
        <p className="muted">Paste this into the browser extension or Outlook add-in settings, with this server's address. It works like a password.</p>
        <label>Valid for <select value={days} onChange={(e) => setDays(Number(e.target.value))}>{[7, 30, 90].map((d) => <option key={d} value={d}>{d} days</option>)}</select></label>
        <button type="button" onClick={() => api.post<{ token: string; expiresAt: string }>("/v1/me/token", { days }).then((t) => { setTok(t); setErr(null); }, (e) => setErr(message(e)))}>Create token</button>
        {tok && <><p>Expires {new Date(tok.expiresAt).toLocaleDateString()}. Server address: <code>{window.location.origin}</code></p><textarea readOnly rows={4} value={tok.token} onFocus={(e) => e.target.select()} /></>}
        {err && <p className="error" role="alert">{err}</p>}
      </Panel>
      <Panel title="Erase my account">
        <p className="muted">Removes {me.email}, their scan history, feedback and personal lists. Mail in the mailbox is never touched. To also revoke access, remove the app in your Google or Microsoft account settings.</p>
        <button type="button" onClick={() => { if (window.confirm("Erase your account and everything stored about it? This cannot be undone.")) void api.del("/v1/me").then(onErased, (e) => setErr(message(e))); }}>Erase my account</button>
      </Panel>
    </>
  );
}
