import type { FastifyReply } from "fastify";

export type Code =
  | "locked_field" | "validation" | "unauthorized" | "forbidden" | "rate_limited" | "scan_in_progress"
  | "not_found" | "not_scanned" | "mail_unavailable";

const STATUS: Record<Code, number> = {
  locked_field: 409, validation: 422, unauthorized: 401, forbidden: 403, rate_limited: 429, scan_in_progress: 409,
  not_found: 404, not_scanned: 404, mail_unavailable: 503,
};

/** The API's single error envelope: { error: { code, message, fields? } }. */
export function fail(reply: FastifyReply, code: Code, message: string, fields?: string[]) {
  return reply.code(STATUS[code]).send({ error: { code, message, ...(fields?.length ? { fields } : {}) } });
}
