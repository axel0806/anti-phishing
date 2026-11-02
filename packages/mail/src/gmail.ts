export interface MailProvider {
  fetchRaw(messageId: string): Promise<Buffer>;
  move(messageId: string, folder: string): Promise<void>;
  /** Undo a move: remove the folder label and return the message to the inbox. Never deletes. */
  unmove(messageId: string, folder: string): Promise<void>;
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
  private labelIds = new Map<string, string>(); // lowercase name -> id (Gmail label names are case-insensitive)
  private labelNames = new Map<string, string>(); // id -> display name

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

  private remember(name: string, id: string): void {
    this.labelIds.set(name.toLowerCase(), id);
    this.labelNames.set(id, name);
  }

  private forgetLabels(): void {
    this.labelIds.clear();
    this.labelNames.clear();
  }

  private async loadLabels(): Promise<void> {
    const list = await this.api("/labels");
    for (const l of list.labels as { id: string; name: string }[]) this.remember(l.name, l.id);
  }

  /** Returns the label ID, creating the label if needed. Never creates duplicates. */
  async ensureFolder(name: string): Promise<string> {
    const cached = this.labelIds.get(name.toLowerCase());
    if (cached) return cached;
    await this.loadLabels();
    const found = this.labelIds.get(name.toLowerCase());
    if (found) return found;
    const created = await this.api("/labels", {
      method: "POST",
      body: { name, labelListVisibility: "labelShow", messageListVisibility: "show" },
    });
    this.remember(name, created.id);
    return created.id as string;
  }

  /** Applies a label change; if Gmail rejects a cached label id (label deleted mid-run), refresh and retry once. */
  private async modify(messageId: string, label: string, removeInbox: boolean): Promise<void> {
    for (let attempt = 0; ; attempt++) {
      const id = await this.ensureFolder(label);
      try {
        await this.api(`/messages/${encodeURIComponent(messageId)}/modify`, {
          method: "POST",
          body: removeInbox ? { addLabelIds: [id], removeLabelIds: ["INBOX"] } : { addLabelIds: [id] },
        });
        return;
      } catch (err) {
        if (attempt > 0 || !/ (400|404) /.test((err as Error).message)) throw err;
        this.forgetLabels();
      }
    }
  }

  async addLabel(messageId: string, label: string): Promise<void> {
    await this.modify(messageId, label, false);
  }

  /** "Move" = apply the folder label and remove INBOX. The message is never deleted. */
  async move(messageId: string, folder: string): Promise<void> {
    await this.modify(messageId, folder, true);
  }

  async unmove(messageId: string, folder: string): Promise<void> {
    if (this.labelIds.size === 0) await this.loadLabels();
    const id = this.labelIds.get(folder.toLowerCase());
    if (!id) return; // the folder never existed, so there is nothing to undo
    await this.api(`/messages/${encodeURIComponent(messageId)}/modify`, { method: "POST", body: { addLabelIds: ["INBOX"], removeLabelIds: [id] } });
  }

  /** Newest-first inbox message ids, following pages until `maxResults` ids are collected. */
  async listRecentInbox(maxResults = 25): Promise<string[]> {
    const ids: string[] = [];
    let token: string | undefined;
    do {
      const page = Math.min(100, maxResults - ids.length);
      const r = await this.api(`/messages?labelIds=INBOX&maxResults=${page}${token ? "&pageToken=" + encodeURIComponent(token) : ""}`);
      for (const m of (r.messages ?? []) as { id: string }[]) ids.push(m.id);
      token = r.nextPageToken as string | undefined;
    } while (token && ids.length < maxResults);
    return ids.slice(0, maxResults);
  }

  async getLabelNames(messageId: string): Promise<string[]> {
    const m = await this.api(`/messages/${encodeURIComponent(messageId)}?format=minimal`);
    if (this.labelIds.size === 0) await this.loadLabels();
    return ((m.labelIds ?? []) as string[]).map((i) => this.labelNames.get(i) ?? i);
  }

  async watch(): Promise<void> {
    throw new Error("Push notifications arrive in Phase 2; Phase 1 polls with listRecentInbox().");
  }
}
