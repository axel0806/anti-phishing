import { createHash } from "node:crypto";
import type { MailProvider } from "@ap/mail";
import { parseEmail } from "@ap/parser";
import { actionFor, scanParsed, offlineLookups } from "@ap/pipeline";
import type { DetectorContext } from "@ap/detectors";
import { resolveSettings } from "@ap/settings";
import { DEFAULT_SETTINGS, type Settings, type Verdict } from "@ap/shared";
import type { Store, StoredScan, User } from "@ap/db";

export const PHISHING_FOLDER = "Phishing";
export const SUSPICIOUS_LABEL = "Suspicious";

export class ScanInProgress extends Error {}
export class MailUnavailable extends Error {}

export interface ScanServiceDeps {
  store: Store;
  /** Returns a mail client for the user, or null if their mailbox isn't linked. */
  mailFor: (user: User) => MailProvider | null;
  lookups?: DetectorContext["lookups"];
}

export interface Effective { settings: Settings; lockedFields: string[]; version: number }
export type FeedbackMailAction = "restored" | "moved" | "none" | "failed";
export interface ScanOutcome { scan: StoredScan; action: ReturnType<typeof actionFor>; cached: boolean }

/** Stable positive int derived from the effective settings, stored with each scan so old verdicts stay explainable. */
const versionOf = (s: Settings): number => createHash("sha256").update(JSON.stringify(s)).digest().readUInt32BE(0) & 0x7fffffff;

export class ScanService {
  private busy = new Set<string>();
  constructor(private deps: ScanServiceDeps) {}

  async effectiveSettings(user: User): Promise<Effective> {
    const [policy, lists] = await Promise.all([this.deps.store.getOrgPolicy(user.orgId), this.deps.store.listsFor(user)]);
    const r = resolveSettings(DEFAULT_SETTINGS, policy, user.overrides);
    const settings: Settings = { ...r.settings, allowlist: lists.allow, blocklist: lists.block };
    return { settings, lockedFields: r.lockedFields, version: versionOf(settings) };
  }

  /**
   * Applies the mailbox action for a verdict. In shadow mode (or when disabled) nothing is touched and the scan stays un-acted,
   * so turning shadow mode off later can still act on it. Otherwise the outcome is recorded so it is never applied twice.
   */
  private async act(user: User, settings: Settings, verdict: Verdict, messageId: string, mail: MailProvider): Promise<ScanOutcome["action"]> {
    const action = actionFor(verdict, settings);
    if (settings.shadowMode || !settings.enabled) return "none";
    if (action === "move_to_phishing") {
      if (!(await mail.getLabelNames(messageId)).includes(PHISHING_FOLDER)) await mail.move(messageId, PHISHING_FOLDER);
    } else if (action === "label_suspicious") await mail.addLabel(messageId, SUSPICIOUS_LABEL);
    await this.deps.store.setScanAction(user.id, messageId, action);
    return action;
  }

  /** Records the user's judgement, then best-effort puts the mailbox in line with it. A mailbox failure never loses the feedback. */
  async applyFeedback(user: User, messageId: string, label: "not_phishing" | "phishing"): Promise<{ scan: StoredScan; mailAction: FeedbackMailAction } | null> {
    const scan = await this.deps.store.addFeedback(user.id, messageId, label);
    if (!scan) return null;
    const mail = this.deps.mailFor(user);
    if (!mail) return { scan, mailAction: "none" };
    try {
      if (label === "not_phishing") { await mail.unmove(messageId, PHISHING_FOLDER); return { scan, mailAction: "restored" }; }
      if (!(await mail.getLabelNames(messageId)).includes(PHISHING_FOLDER)) await mail.move(messageId, PHISHING_FOLDER);
      return { scan, mailAction: "moved" };
    } catch {
      return { scan, mailAction: "failed" };
    }
  }

  /**
   * Scan one message. Idempotent per message: a stored verdict is returned unless `rescan` is set, and a user-pinned
   * (manually judged) verdict is never replaced. `mode: "act"` also moves/labels the mail unless shadow mode is on.
   */
  async scan(user: User, messageId: string, opts: { mode?: "dry_run" | "act"; rescan?: boolean } = {}): Promise<ScanOutcome> {
    const key = `${user.id}:${messageId}`;
    if (this.busy.has(key)) throw new ScanInProgress();
    this.busy.add(key);
    try {
      const eff = await this.effectiveSettings(user);
      const existing = await this.deps.store.getScan(user.id, messageId);
      if (existing && (!opts.rescan || existing.pinned)) {
        // A stored verdict (e.g. from the extension's dry run) may still be waiting for its mailbox action.
        if (opts.mode === "act" && !existing.pinned && existing.action === null) {
          const mail = this.deps.mailFor(user);
          if (mail) return { scan: existing, action: await this.act(user, eff.settings, existing.verdict, messageId, mail), cached: true };
        }
        return { scan: existing, action: "none", cached: true };
      }

      const mail = this.deps.mailFor(user);
      if (!mail) throw new MailUnavailable("Mailbox not linked for this user");
      const started = performance.now();
      const email = await parseEmail(await mail.fetchRaw(messageId), messageId);
      const history = await this.deps.store.getSenderHistory(user.id, email.from.address);
      const verdict = await scanParsed(email, eff.settings, { lookups: this.deps.lookups ?? offlineLookups, senderHistory: history });
      verdict.settingsVersion = eff.version;

      const scan = await this.deps.store.saveScan(user.id, messageId, verdict, {
        latencyMs: performance.now() - started, sender: email.from.address,
        subjectHash: createHash("sha256").update(email.subject).digest("hex"),
      });
      if (!existing) await this.deps.store.recordSender(user.id, email.from.address);

      const action = opts.mode === "act" ? await this.act(user, eff.settings, verdict, messageId, mail) : ("none" as const);
      return { scan, action, cached: false };
    } finally {
      this.busy.delete(key);
    }
  }
}
