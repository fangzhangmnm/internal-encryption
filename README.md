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
发版 = `npm run release`（version≠0.0.0 才准）；收货 = 消费方仓根跑 `scripts/pull-package.sh`。
