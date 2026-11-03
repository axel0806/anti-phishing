# The AI layer (optional, off by default)

Rules run first. Only emails whose rule score is *uncertain* go to a language model, which judges intent and social-engineering tactics the rules cannot see. The uncertain band follows your sensitivity thresholds (from 10 points below "suspicious" to 20 above "phishing"; 20 to 80 with the default balanced preset). The model can only **add** points (capped at 40) and can never move an email into Phishing on its own. Any failure (timeout after 2.5 s, error, bad output, budget used up) falls back to the exact rules-only verdict.

Nothing is sent anywhere until you configure a provider on the server **and** a user turns AI on (`PATCH /v1/settings {"ai": {"enabled": true}}`; admins can lock it off for an org, or set it in the dashboard's Policy tab).

```bash
# Hosted (Anthropic): prices are needed so the per-user monthly budget works
AI_PROVIDER=anthropic  ANTHROPIC_API_KEY=...  AI_PRICE_IN_PER_MTOK=...  AI_PRICE_OUT_PER_MTOK=...

# Local / self-hosted (Ollama, LM Studio, vLLM...): mail data never leaves your network
AI_PROVIDER=openai  AI_BASE_URL=http://localhost:11434/v1  AI_MODEL=llama3.1
```

## Spend limits

Spend is bounded three ways: each user's own monthly budget, a server-wide ceiling on that budget (`AI_MAX_USER_BUDGET_USD`, default $20), and an optional pooled org budget (`ai.orgMonthlyBudgetUsd` in org policy). Admins can lock all of `ai` or a single field such as `ai.monthlyBudgetUsd`. Calls that time out are still charged at an estimate, because the provider may bill them.

## What the model sees

Sender name and address, reply-to, subject, the body truncated to 4,000 characters, links reduced to their host (no paths, query strings or tokens, anywhere in the text), attachment names and types, and the rule flags already fired. Email addresses, phone numbers and long digit strings are redacted first. The email is wrapped in a randomly delimited data block, the system prompt tells the model it is untrusted, and the reply must match a strict schema.

## Measuring it

`npm run corpus:ab` runs `corpus/uncertain` through rules-only and rules + AI and reports the recall and false-positive change (needs a provider configured in the environment). Be aware that the bundled harness uses a small sample: **whether the AI layer measurably improves detection has not been established.** `corpus/injection` holds prompt-injection emails used in the tests. Contributions of real, sanitised emails are the most useful thing you can add here.
