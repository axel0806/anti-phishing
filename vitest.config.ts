import { defineConfig } from "vitest/config";
export default defineConfig({ test: { include: ["packages/*/test/**/*.test.ts", "apps/*/test/**/*.test.{ts,tsx}", "packages/*/test/**/*.test.ts", "corpus/**/*.test.ts"] } });
