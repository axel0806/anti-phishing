import { z } from "zod";

export const TACTICS = [
  "urgency", "authority_impersonation", "credential_request", "payment_redirect", "gift_card", "fear_threat", "too_good_to_be_true",
] as const;
export type Tactic = (typeof TACTICS)[number];

/**
 * What the model must return. Extra keys are dropped, so nothing an email talks the model into adding can reach the scorer.
 * An over-long explanation is truncated rather than rejected: a verbose model should not cost us the verdict.
 */
export const AiVerdictSchema = z.object({
  riskScore: z.number().min(0).max(1),
  tactics: z.array(z.enum(TACTICS)),
  impersonatedEntity: z.string().nullable(),
  explanation: z.string().transform((s) => s.slice(0, 300)),
});
export type AiVerdict = z.infer<typeof AiVerdictSchema>;

/** JSON Schema for providers that enforce structured output (tool calls). Mirrors AiVerdictSchema. */
export const AI_VERDICT_JSON_SCHEMA = {
  type: "object",
  properties: {
    riskScore: { type: "number", minimum: 0, maximum: 1, description: "Probability the email is phishing or social engineering." },
    tactics: { type: "array", items: { type: "string", enum: [...TACTICS] } },
    impersonatedEntity: { type: ["string", "null"], description: "Brand or person being impersonated, if any." },
    explanation: { type: "string", maxLength: 300, description: "One or two plain sentences for the end user." },
  },
  required: ["riskScore", "tactics", "impersonatedEntity", "explanation"],
  additionalProperties: false,
} as const;
