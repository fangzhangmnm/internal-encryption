# 20260828 internal-encryption — 本库规则（@internal/encryption）

家族总规则见 `../CLAUDE.md`。这里只写本库特有的。

- **本库 = 家族内容加密库**（2026-08-28 自 `@internal/store` crypto-container.ts 立户；user 拍板
  「encryption 从 store 上面独立出来」——store 单一职责=同步，加密是纯内容操作零持久化依赖）。
  格式 = ADR-0012（store 仓）：明文 zip 外壳 + 7z AES-256 payload + 尾部加密 peek；**7-Zip 输密码可开
  = anti-abandonware 承重项，改格式前 escalate human**。
- **唯一入口 = `createEncryption({codec, reportError})`**（模块单例已退役——没有静默替身：无 codec
  探测照常、pack/unpack 响亮抛）。codec（zip.js + 7z-wasm）由宿主 vendor 注入；本仓 `vendor/`
  只是测试夹具，不进 tgz。
- **消费方**：app 直接用（无库模式加密探测/解密即靠它）；`@internal/store` 经自己的 EncryptionPort
  收实例（依赖倒置，两包零依赖——app 组装时把同一实例喂给 store config.encryption）。
- **只出货不送货**（对齐 store/Colors 契约）：交付物 = `npm run release` 的 tgz；消费方跑本仓
  `scripts/pull-package.sh`。开发期 version 钉 `0.0.0`；版本号只在人类过目真实 exports 后才花。
- 测试 `npm test`（node runner 家规版）；构建 `npm run build`（tsc → dist）。
- `journal/` 人类区，AI 永不写（硬规则 #2）。
