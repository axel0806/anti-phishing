import { buildPrompt } from "./prompt.ts";
import { AI_VERDICT_JSON_SCHEMA, type AiVerdict } from "./schema.ts";
import type { AiProvider, AiResult } from "./analyze.ts";
import type { AiInput } from "./redact.ts";

type FetchLike = typeof fetch;
const TOOL = "report_verdict";

/** Anthropic Messages API with a forced tool call, so the reply is structured data and never free-form text. */
export class AnthropicProvider implements AiProvider {
  readonly name: string;
  private fetchImpl: FetchLike;
  constructor(private cfg: { apiKey: string; model: string; baseUrl?: string; fetch?: FetchLike }) {
    this.name = `anthropic:${cfg.model}`;
    this.fetchImpl = cfg.fetch ?? fetch;
  }

  async analyze(input: AiInput, opts: { signal: AbortSignal }): Promise<AiResult> {
    const p = buildPrompt(input);
    const res = await this.fetchImpl(`${this.cfg.baseUrl ?? "https://api.anthropic.com"}/v1/messages`, {
      method: "POST",
      signal: opts.signal,
      headers: { "x-api-key": this.cfg.apiKey, "anthropic-version": "2023-06-01", "content-type": "application/json" },
      body: JSON.stringify({
        model: this.cfg.model, max_tokens: 400, temperature: 0, system: p.system,
        messages: [{ role: "user", content: p.user }],
        tools: [{ name: TOOL, description: "Report your assessment of the email.", input_schema: AI_VERDICT_JSON_SCHEMA }],
        tool_choice: { type: "tool", name: TOOL },
      }),
    });
    if (!res.ok) throw new Error(`Anthropic API error ${res.status}`); // body deliberately not included: it may echo the request
    const j = (await res.json()) as { content?: { type: string; name?: string; input?: unknown }[]; usage?: { input_tokens?: number; output_tokens?: number } };
    const call = j.content?.find((c) => c.type === "tool_use" && c.name === TOOL);
    if (!call) throw new Error("Model did not return the required tool call");
    return {
      verdict: call.input as AiVerdict, // validated by analyze()
      usage: j.usage ? { inputTokens: j.usage.input_tokens ?? 0, outputTokens: j.usage.output_tokens ?? 0 } : undefined,
    };
  }
}
