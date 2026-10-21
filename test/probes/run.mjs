// 真浏览器探针：无头 Chromium（playwright 借 WeebPaint 的 node_modules，家族惯例）跑 test/probes/page.html 三步：
//   记住 → 重开页 recall → 忘记 → 重开页仍 null → deleteDatabase 不被堵。created 20261021 by Claude Fable 5.1（user 10-21「encryption 做，不要等我真机」）
// 用法：npm run build && node test/probes/run.mjs。WebKit 本机没装（只有 chromium），iPad Edge（WebKit 壳）仍是真机零——如实。
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const require = createRequire(path.resolve(root, "../20260524 WeebPaint/package.json"));
const { chromium } = require("playwright");
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8" };
const server = createServer(async (req, res) => {
  try {
    const rel = decodeURIComponent(new URL(req.url, "http://x").pathname).replace(/^\/+/, "");
    const file = path.resolve(root, rel);
    if (!file.startsWith(root + path.sep)) { res.writeHead(403).end(); return; }
    res.writeHead(200, { "content-type": TYPES[path.extname(file)] ?? "application/octet-stream" }).end(await readFile(file));
  } catch { res.writeHead(404).end(); }
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;
const browser = await chromium.launch();
let failed = 0;
try {
  const ctx = await browser.newContext();      // 同一个 context = 同一份存储；每步新开页 = 「关页重开」
  for (const step of ["1", "2", "3"]) {
    const page = await ctx.newPage();
    const errs = [];
    page.on("pageerror", (e) => errs.push(String(e)));
    await page.goto(`http://127.0.0.1:${port}/test/probes/page.html?step=${step}`);
    await page.waitForFunction(() => window.__PROBE__, null, { timeout: 30_000 });
    const results = await page.evaluate(() => window.__PROBE__);
    for (const r of results) { if (!r.ok) failed++; console.log(`${r.ok ? "✓" : "✗"} [step ${step}] ${r.name}${r.info ? `  (${r.info})` : ""}`); }
    for (const e of errs) { failed++; console.log(`✗ [step ${step}] pageerror: ${e}`); }
    await page.close();
  }
} finally { await browser.close(); server.close(); }
console.log(failed ? `${failed} failed` : "all probes passed (chromium " + (await (async () => { try { return require("playwright/package.json").version; } catch { return "?"; } })()) + ")");
process.exit(failed ? 1 : 0);
