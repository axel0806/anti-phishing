import { createHash } from "node:crypto";
import type { MailProvider } from "@ap/mail";
import { parseEmail } from "@ap/parser";
import { actionFor, scanParsed, offlineLookups } from "@ap/pipeline";
import type { DetectorContext } from "@ap/detectors";
import { resolveSettings } from "@ap/settings";
import { DEFAULT_SETTINGS, type Settings } from "@ap/shared";
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
      if (existing && (!opts.rescan || existing.pinned)) return { scan: existing, action: "none", cached: true };

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

      let action: ScanOutcome["action"] = "none";
      if (opts.mode === "act") {
        action = actionFor(verdict, eff.settings);
        if (action === "move_to_phishing") {
          if (!(await mail.getLabelNames(messageId)).includes(PHISHING_FOLDER)) await mail.move(messageId, PHISHING_FOLDER);
        } else if (action === "label_suspicious") await mail.addLabel(messageId, SUSPICIOUS_LABEL);
      }
      return { scan, action, cached: false };
    } finally {
      this.busy.delete(key);
    }
  }
}
