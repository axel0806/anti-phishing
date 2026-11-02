import { build } from "esbuild";
import { copyFileSync, mkdirSync, writeFileSync } from "node:fs";
import { solidPng } from "./src/png.ts";

const out = "apps/outlook-addin/dist";
mkdirSync(out, { recursive: true });
await build({ entryPoints: { taskpane: "apps/outlook-addin/src/taskpane.ts" }, bundle: true, outdir: out, target: "es2019", format: "iife", logLevel: "warning" });
copyFileSync("apps/outlook-addin/taskpane.html", out + "/taskpane.html");
// Office needs icons; generate plain ones rather than shipping binaries.
for (const size of [32, 64, 128]) writeFileSync(`${out}/icon-${size}.png`, solidPng(size, [200, 30, 30]));
console.log("Built apps/outlook-addin/dist (the manifest is served by the API at /addin/manifest.xml)");
