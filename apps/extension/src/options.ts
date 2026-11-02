import { applyConnection, handshake, normalizeServerUrl, resolveConnection, type Connection, type ManagedPolicy } from "@ap/ui";

const api = (globalThis as any).browser ?? (globalThis as any).chrome;
const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const status = (msg: string, kind: "ok" | "error" | "" = "") => {
  const el = $("status");
  el.textContent = msg; // textContent only: server-provided strings are untrusted
  el.className = kind;
};

async function load(): Promise<{ local: Connection | null; managed: ManagedPolicy | undefined }> {
  const local = ((await api.storage.local.get("connection")).connection as Connection | undefined) ?? null;
  const managed = await api.storage.managed.get(["serverUrl", "lockServerUrl", "certFingerprint"]).then((r: ManagedPolicy) => r, () => undefined);
  return { local, managed };
}

async function init() {
  const { local, managed } = await load();
  const { connection, locked, error } = resolveConnection(local, managed);
  if (error) status(error, "error");
  $<HTMLInputElement>("url").value = connection.serverUrl;
  $<HTMLInputElement>("token").value = connection.token;
  if (locked) {
    $<HTMLInputElement>("url").disabled = true;
    $("managed").style.display = "block";
  }
}

$("form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const { local, managed } = await load();
    const locked = resolveConnection(local, managed).locked;
    const checked = normalizeServerUrl(locked ? resolveConnection(local, managed).connection.serverUrl : $<HTMLInputElement>("url").value);
    if (!checked.ok) return status(checked.error, "error");

    // Host access is requested at runtime, only for the chosen server (called directly from the submit gesture).
    const granted = await api.permissions.request({ origins: [checked.url + "/*"] });
    if (!granted) return status("Permission to contact that server was not granted.", "error");

    const hs = await handshake(checked.url);
    if (!hs.ok) return status(hs.error, "error");

    const { connection, cleared } = applyConnection(local, { serverUrl: checked.url, serverId: hs.serverId, token: $<HTMLInputElement>("token").value.trim() });
    await api.storage.local.set({ connection });
    status(`Connected to server ${hs.serverId ?? "(local runner)"} v${hs.version}.${cleared ? " The previous session token was cleared because the server changed." : ""}`, "ok");
  } catch (e) {
    status("Something went wrong: " + (e as Error).message, "error");
  }
});

void init();
