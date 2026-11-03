import type { FetchLike, MailProvider } from "./gmail.ts";

const BASE = "https://graph.microsoft.com/v1.0";
const enc = encodeURIComponent;

/**
 * Microsoft Graph (Outlook / Microsoft 365 mail). "Folders" are real mail folders; "labels" are Outlook categories.
 * Every request asks for immutable ids: without that, Graph gives a message a NEW id when it is moved, which would
 * break idempotency (the same mail would look unscanned again after being moved to Phishing).
 */
export class GraphProvider implements MailProvider {
  private folderIds = new Map<string, string>(); // lowercase display name -> id
  private folderNames = new Map<string, string>(); // id -> display name

  constructor(private getAccessToken: () => Promise<string>, private fetchImpl: FetchLike = fetch as unknown as FetchLike, private base = BASE) {}

  private async raw(url: string, init: { method?: string; body?: unknown } = {}) {
    // Every request carries the bearer token, including ones whose URL came out of a previous response (paging links).
    if (!url.startsWith(this.base + "/")) throw new Error("Refusing a request outside Microsoft Graph");
    const res = await this.fetchImpl(url, {
      method: init.method ?? "GET",
      headers: { Authorization: "Bearer " + (await this.getAccessToken()), "Content-Type": "application/json", Prefer: 'IdType="ImmutableId"' },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    });
    if (!res.ok) throw new Error(`Graph API ${init.method ?? "GET"} ${url.replace(this.base, "")} failed: ${res.status} ${(await res.text()).slice(0, 200)}`);
    return res;
  }
  private async api(path: string, init: { method?: string; body?: unknown } = {}): Promise<any> {
    return (await this.raw(this.base + path, init)).json();
  }

  async fetchRaw(messageId: string): Promise<Buffer> {
    const res = await this.raw(`${this.base}/me/messages/${enc(messageId)}/$value`);
    // Bytes, not text: decoding as UTF-8 first would replace 8-bit or non-UTF-8 parts with U+FFFD before the parser sees them.
    return res.arrayBuffer ? Buffer.from(await res.arrayBuffer()) : Buffer.from(await res.text(), "utf8");
  }

  async ensureFolder(name: string): Promise<string> {
    const key = name.toLowerCase();
    const cached = this.folderIds.get(key);
    if (cached) return cached;
    const filter = enc(`displayName eq '${name.replace(/'/g, "''")}'`);
    const found = (await this.api(`/me/mailFolders?$top=10&$filter=${filter}`)).value as { id: string; displayName: string }[] | undefined;
    const hit = found?.find((f) => f.displayName.toLowerCase() === key);
    const folder = hit ?? (await this.api("/me/mailFolders", { method: "POST", body: { displayName: name } })) as { id: string; displayName: string };
    this.folderIds.set(key, folder.id);
    this.folderNames.set(folder.id, folder.displayName);
    return folder.id;
  }

  async move(messageId: string, folder: string): Promise<void> {
    await this.api(`/me/messages/${enc(messageId)}/move`, { method: "POST", body: { destinationId: await this.ensureFolder(folder) } });
  }

  async unmove(messageId: string, _folder: string): Promise<void> {
    await this.api(`/me/messages/${enc(messageId)}/move`, { method: "POST", body: { destinationId: "inbox" } });
  }

  async addLabel(messageId: string, label: string): Promise<void> {
    const cur = ((await this.api(`/me/messages/${enc(messageId)}?$select=categories`)).categories ?? []) as string[];
    const next = cur.some((c) => c.toLowerCase() === label.toLowerCase()) ? cur : [...cur, label];
    await this.api(`/me/messages/${enc(messageId)}`, { method: "PATCH", body: { categories: next } });
  }

  async listRecentInbox(maxResults = 25): Promise<string[]> {
    const ids: string[] = [];
    let url: string | undefined = `${this.base}/me/mailFolders/inbox/messages?$select=id&$top=${Math.min(100, maxResults)}&$orderby=${enc("receivedDateTime desc")}`;
    while (url && ids.length < maxResults) {
      const j = (await (await this.raw(url)).json()) as { value?: { id: string }[]; "@odata.nextLink"?: string };
      for (const m of j.value ?? []) ids.push(m.id);
      url = j["@odata.nextLink"];
    }
    return ids.slice(0, maxResults);
  }

  /**
   * Outlook add-ins can only produce ordinary REST ids, but scans are keyed by immutable ids (they survive moves).
   * Graph's translateExchangeIds converts one into the other.
   */
  async resolveId(id: string, format: string | undefined): Promise<string> {
    if (format === undefined) return id;
    if (format !== "outlook_rest") throw new Error(`Unsupported id format: ${format}`);
    const j = await this.api("/me/translateExchangeIds", { method: "POST", body: { inputIds: [id], sourceIdType: "restId", targetIdType: "restImmutableEntryId" } });
    const target = (j.value as { targetId?: string }[] | undefined)?.[0]?.targetId;
    if (!target) throw new Error("Graph could not translate that message id");
    return target;
  }

  async getLabelNames(messageId: string): Promise<string[]> {
    const m = await this.api(`/me/messages/${enc(messageId)}?$select=categories,parentFolderId`);
    const names: string[] = [];
    if (m.parentFolderId) {
      let n = this.folderNames.get(m.parentFolderId);
      if (!n) {
        n = (await this.api(`/me/mailFolders/${enc(m.parentFolderId)}?$select=displayName`)).displayName as string | undefined;
        if (n) this.folderNames.set(m.parentFolderId, n);
      }
      if (n) names.push(n);
    }
    return [...names, ...((m.categories ?? []) as string[])];
  }

  /**
   * Delta polling: the fallback when change notifications cannot reach a private server. Pass the previous `next` to
   * get only what changed since. A delta link must stay on Graph, because we send our access token to it.
   */
  async deltaInbox(resumeFrom?: string): Promise<{ ids: string[]; next: string | undefined }> {
    if (resumeFrom && !resumeFrom.startsWith(this.base + "/")) throw new Error("Refusing a delta link outside Microsoft Graph");
    let url: string | undefined = resumeFrom ?? `${this.base}/me/mailFolders/inbox/messages/delta?$select=id`;
    const ids: string[] = [];
    let next: string | undefined;
    while (url) {
      const j = (await (await this.raw(url)).json()) as { value?: { id: string }[]; "@odata.nextLink"?: string; "@odata.deltaLink"?: string };
      for (const m of j.value ?? []) ids.push(m.id);
      next = j["@odata.deltaLink"] ?? next;
      url = j["@odata.nextLink"];
      if (url && !url.startsWith(this.base + "/")) throw new Error("Refusing a page link outside Microsoft Graph");
    }
    return { ids, next };
  }

  async watch(): Promise<void> {
    throw new Error("Change notifications need a public HTTPS endpoint; use deltaInbox() or listRecentInbox() polling instead.");
  }
}
