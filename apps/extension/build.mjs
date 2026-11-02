import { build } from "esbuild";
import { copyFileSync, mkdirSync } from "node:fs";
mkdirSync("apps/extension/dist", { recursive: true });
await build({ entryPoints: ["apps/extension/src/content.ts"], bundle: true, outfile: "apps/extension/dist/content.js", target: "chrome120", format: "iife" });
copyFileSync("apps/extension/manifest.json", "apps/extension/dist/manifest.json");
console.log("Built apps/extension/dist - load it via chrome://extensions > Load unpacked");
