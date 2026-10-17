# @internal/encryption

PWA 家族内容加密库。容器 = 明文 zip 外壳 + 7z AES-256 payload（`data.bin`+`meta.bin`）+ 尾部加密 peek
（PBKDF2×250k + AES-GCM，byte-range 一发命中）。**7-Zip 输密码可直接恢复**（anti-abandonware）。

```ts
import { createEncryption } from "@internal/encryption";
const enc = createEncryption({ codec: { zipPack, zipUnpack, pack7z, unpack7z }, reportError });
await enc.isEncryptedBlob(blob);                 // 探测（零 codec 也能用）
await enc.tryDecryptEncryptedBlob(blob, pw);     // null = 错密码/非容器
await enc.packContainer({ dataBytes, fileName, peek, password });
```

`@internal/store` 经 `config.encryption`（结构端口）收同一实例——两包零依赖。

**「在这台设备上记住口令」**（0.2.0，`ai-docs/adr/0001-device-remembers-password.md`；user 2026-10-15 / 10-17 拍板）：

```ts
import { createPasswordKeeper, MAX_REMEMBER_MS } from "@internal/encryption";
const keeper = createPasswordKeeper({ dbName: "<app>.remember" });        // 本机 IDB；不同步、不上云、不是正本
const { expiresAt } = await keeper.remember(pw, { ttlMs: 7 * 86400_000 }); // 缺省 = 上限 30 天；超上限钳到上限
const pw = await keeper.recall();   // null = 没记 / 过期 / 记录不对（已自动删）；调用方照旧先验（verifier / peek），不对 → forget()
await keeper.status();              // { remembered, expiresAt }——面板上写「记到 X 月 X 日」
await keeper.forget();              // 「忘记」/「立即锁定」/ 退出登录 / 还原出厂
```

盘上没有明文：口令用同库里一把**不可导出**的 AES-GCM 钥匙封起来，过期时间进 additionalData（改了就解不开）。
拿着已解锁设备的人本来就能开——这只是把「会话结束后口令还在」这段时间封顶。消费方规矩（默认不勾、一直有「忘记」、
锁定 / 退出即忘、清缓存不清它、还原出厂清它、app 侧一个接缝文件）见 ADR-0001 落地清单。
发版 = `npm run release`（version≠0.0.0 才准）；收货 = 消费方仓根跑 `scripts/pull-package.sh`。
