// @internal/encryption 测试入口。runner = 家规版（实时耗时 + 每测 10s 超时墙）。
import { run } from "./runner.mjs";
import "./encryption.test.mjs";
import "./remember.test.mjs";
await run();
// 全绿也要明说 0：错密码测试里 7-Zip（7z-wasm）以状态 2 退出，emscripten 把它写进 process.exitCode——
// 不清掉的话 `npm test` 全过仍 rc=2，release.sh 的 set -e 会在 pnpm pack 之前静默停掉（2026-10-17 查出，Claude Fable 5.1）。
// run() 有失败时自己 process.exit(1)，走到这里 = 全过。
process.exitCode = 0;
