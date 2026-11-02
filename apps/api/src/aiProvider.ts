import { AnthropicProvider, OpenAiCompatibleProvider, type AiProvider } from "@ap/ai";
import type { AiConfig } from "./config.ts";

export function aiProviderFromConfig(cfg: AiConfig): AiProvider {
  return cfg.kind === "anthropic"
    ? new AnthropicProvider({ apiKey: cfg.apiKey!, model: cfg.model })
    : new OpenAiCompatibleProvider({ baseUrl: cfg.baseUrl!, model: cfg.model, apiKey: cfg.apiKey });
}
