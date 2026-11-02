import { buildPrompt } from "./prompt.ts";
import type { AiVerdict } from "./schema.ts";
import type { AiProvider, AiResult } from "./analyze.ts";
import type { AiInput } from "./redact.ts";

type FetchLike = typeof fetch;

/**
 * Any OpenAI-compatible /chat/completions endpoint: Ollama, LM Studio, vLLM, llama.cpp server, or a hosted one.
 * Lets self-hosted installs keep all mail data on their own network.
 */
export class OpenAiCompatibleProvider implements AiProvider {
  readonly name: string;
  private fetchImpl: FetchLike;
  constructor(private cfg: { baseUrl: string; model: string; apiKey?: string; fetch?: FetchLike }) {
    this.name = `openai-compatible:${cfg.model}`;
    this.fetchImpl = cfg.fetch ?? fetch;
  }

  async analyze(input: AiInput, opts: { signal: AbortSignal }): Promise<AiResult> {
    const p = buildPrompt(input);
    const res = await this.fetchImpl(`${this.cfg.baseUrl.replace(/\/+$/, "")}/chat/completions`, {
      method: "POST",
      signal: opts.signal,
      headers: { "content-type": "application/json", ...(this.cfg.apiKey ? { Authorization: `Bearer ${this.cfg.apiKey}` } : {}) },
      body: JSON.stringify({
        model: this.cfg.model, temperature: 0, max_tokens: 400, response_format: { type: "json_object" },
        messages: [{ role: "system", content: p.system }, { role: "user", content: p.user }],
      }),
    });
    if (!res.ok) throw new Error(`Model server error ${res.status}`);
    const j = (await res.json()) as { choices?: { message?: { content?: string } }[]; usage?: { prompt_tokens?: number; completion_tokens?: number } };
    const text = j.choices?.[0]?.message?.content ?? "";
    // Some local models wrap the object in a code fence or add a sentence around it: take the outermost braces.
    const start = text.indexOf("{"), end = text.lastIndexOf("}");
    let verdict: AiVerdict;
    try {
      if (start < 0 || end < start) throw new Error("no object");
      verdict = JSON.parse(text.slice(start, end + 1)) as AiVerdict;
    } catch {
      throw new Error("Model did not return valid JSON");
    }
    return { verdict, usage: j.usage ? { inputTokens: j.usage.prompt_tokens ?? 0, outputTokens: j.usage.completion_tokens ?? 0 } : undefined };
  }
}
