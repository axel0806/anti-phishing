import { build } from "esbuild";
import { copyFileSync, mkdirSync } from "node:fs";
for (const [dir, manifest] of [["dist", "manifest.json"], ["dist-firefox", "manifest.firefox.json"]]) {
  mkdirSync("apps/extension/" + dir, { recursive: true });
  await build({
    entryPoints: { content: "apps/extension/src/content.ts", background: "apps/extension/src/background.ts", options: "apps/extension/src/options.ts" },
    bundle: true, outdir: "apps/extension/" + dir, target: "es2022", format: "iife",
  });
  copyFileSync("apps/extension/" + manifest, "apps/extension/" + dir + "/manifest.json");
  for (const f of ["options.html", "managed_schema.json"]) copyFileSync("apps/extension/" + f, "apps/extension/" + dir + "/" + f);
}
console.log("Built apps/extension/dist (Chrome) and apps/extension/dist-firefox (Firefox)");
