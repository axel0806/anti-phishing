export interface MailProvider {
  fetchRaw(messageId: string): Promise<Buffer>;
  move(messageId: string, folder: string): Promise<void>;
  addLabel(messageId: string, label: string): Promise<void>;
  ensureFolder(name: string): Promise<string>;
  listRecentInbox(maxResults?: number): Promise<string[]>;
  getLabelNames(messageId: string): Promise<string[]>;
  watch(): Promise<void>;
}

export type FetchLike = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) =>
  Promise<{ ok: boolean; status: number; json(): Promise<any>; text(): Promise<string> }>;

const BASE = "https://gmail.googleapis.com/gmail/v1/users/me";

export class GmailProvider implements MailProvider {
  private labelIds = new Map<string, string>();

  constructor(private getAccessToken: () => Promise<string>, private fetchImpl: FetchLike = fetch as unknown as FetchLike) {}

  private async api(path: string, init: { method?: string; body?: unknown } = {}): Promise<any> {
    const res = await this.fetchImpl(BASE + path, {
      method: init.method ?? "GET",
      headers: { Authorization: "Bearer " + (await this.getAccessToken()), "Content-Type": "application/json" },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    });
    if (!res.ok) throw new Error(`Gmail API ${init.method ?? "GET"} ${path} failed: ${res.status} ${await res.text()}`);
    return res.json();
  }

  async fetchRaw(messageId: string): Promise<Buffer> {
    const m = await this.api(`/messages/${encodeURIComponent(messageId)}?format=raw`);
    return Buffer.from(m.raw as string, "base64url");
  }

  private async loadLabels(): Promise<void> {
    const list = await this.api("/labels");
    for (const l of list.labels as { id: string; name: string }[]) this.labelIds.set(l.name, l.id);
  }

  /** Returns the label ID, creating the label if needed. Never creates duplicates. */
  async ensureFolder(name: string): Promise<string> {
    const cached = this.labelIds.get(name);
    if (cached) return cached;
    await this.loadLabels();
    const found = this.labelIds.get(name);
    if (found) return found;
    const created = await this.api("/labels", {
      method: "POST",
      body: { name, labelListVisibility: "labelShow", messageListVisibility: "show" },
    });
    this.labelIds.set(name, created.id);
    return created.id as string;
  }

  async addLabel(messageId: string, label: string): Promise<void> {
    const id = await this.ensureFolder(label);
    await this.api(`/messages/${encodeURIComponent(messageId)}/modify`, { method: "POST", body: { addLabelIds: [id] } });
  }

  /** "Move" = apply the folder label and remove INBOX. The message is never deleted. */
  async move(messageId: string, folder: string): Promise<void> {
    const id = await this.ensureFolder(folder);
    await this.api(`/messages/${encodeURIComponent(messageId)}/modify`, {
      method: "POST",
      body: { addLabelIds: [id], removeLabelIds: ["INBOX"] },
    });
  }

  async listRecentInbox(maxResults = 25): Promise<string[]> {
    const r = await this.api(`/messages?labelIds=INBOX&maxResults=${maxResults}`);
    return ((r.messages ?? []) as { id: string }[]).map((m) => m.id);
  }

  async getLabelNames(messageId: string): Promise<string[]> {
    const m = await this.api(`/messages/${encodeURIComponent(messageId)}?format=minimal`);
    if (this.labelIds.size === 0) await this.loadLabels();
    const byId = new Map([...this.labelIds].map(([n, i]) => [i, n]));
    return ((m.labelIds ?? []) as string[]).map((i) => byId.get(i) ?? i);
  }

  async watch(): Promise<void> {
    throw new Error("Push notifications arrive in Phase 2; Phase 1 polls with listRecentInbox().");
  }
}
