import { fetchVerdict, resolveConnection, setupProblem, type Connection, type ManagedPolicy, type VerdictDto } from "@ap/ui";

// `browser` exists in Firefox, `chrome` in Chrome; both accept sendResponse + `return true`.
const api = (globalThis as any).browser ?? (globalThis as any).chrome;

async function resolveNow() {
  const [local, managed] = await Promise.all([
    api.storage.local.get("connection").then((r: any) => (r.connection as Connection | undefined) ?? null),
    api.storage.managed.get(["serverUrl", "lockServerUrl", "certFingerprint"]).then((r: any) => r as ManagedPolicy, () => undefined),
  ]);
  return resolveConnection(local, managed);
}

async function currentConnection(): Promise<Connection> {
  return (await resolveNow()).connection;
}

/** Shows a badge when the extension cannot work yet (no permission for the server, or an invalid managed URL). */
async function refreshSetupBadge(): Promise<void> {
  try {
    const r = await resolveNow();
    const has = r.connection.serverUrl ? await api.permissions.contains({ origins: [r.connection.serverUrl + "/*"] }) : false;
    const problem = setupProblem(r, has);
    await api.action.setBadgeText({ text: problem ? "!" : "" });
    await api.action.setTitle({ title: problem ?? "Anti-Phishing" });
  } catch { /* badge is best-effort */ }
}
api?.action?.onClicked.addListener(() => api.runtime.openOptionsPage());
api?.permissions?.onAdded?.addListener(() => void refreshSetupBadge());
api?.storage?.onChanged?.addListener(() => void refreshSetupBadge());
void refreshSetupBadge();

api?.runtime?.onMessage.addListener((msg: any, _sender: unknown, sendResponse: (r: VerdictDto | null) => void) => {
  if (msg?.type !== "verdict" || typeof msg.id !== "string") return false;
  void currentConnection().then((c) => fetchVerdict(msg.id, c)).then(sendResponse, () => sendResponse(null));
  return true;
});
