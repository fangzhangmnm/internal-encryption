// @internal/encryption 测试入口。runner = 家规版（实时耗时 + 每测 10s 超时墙）。
import { run } from "./runner.mjs";
import "./encryption.test.mjs";
await run();
