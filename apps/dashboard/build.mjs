import { build } from "esbuild";
import { copyFileSync, mkdirSync } from "node:fs";

const out = "apps/dashboard/dist";
mkdirSync(out, { recursive: true });
await build({
  entryPoints: { main: "apps/dashboard/src/main.tsx" }, bundle: true, outdir: out, target: "es2020", format: "iife", minify: true,
  jsx: "automatic", define: { "process.env.NODE_ENV": '"production"' }, logLevel: "warning",
});
copyFileSync("apps/dashboard/index.html", out + "/index.html");
copyFileSync("apps/dashboard/dashboard.css", out + "/dashboard.css");
console.log("Built apps/dashboard/dist (served at /admin/)");
