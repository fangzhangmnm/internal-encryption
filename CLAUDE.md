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
- **「在这台设备上记住口令」= `createPasswordKeeper({ dbName })`**（0.2.0，2026-10-17，Claude Fable 5.1；自 KudsRocket
  `remember-password.ts` 搬进库，user 10-15「按设备 opt-in……同意」、10-17「口令加一个过期时间，最多一个月」「升级加密库同意」）。
  这是对 store 仓 ADR-0012「口令只在内存、永不持久化」那一行的**有意吃书**，决策与威胁模型 = 本仓 `ai-docs/adr/0001-device-remembers-password.md`。
  硬的几条：盘上无明文（不可导出 AES-GCM 钥匙封装）；**上限 30 天**（`MAX_REMEMBER_MS`，超了钳住，不是可配置的天花板）；过期时间进 AAD；
  recall 永不抛、对不上就自删；本模块永不打印口令。**改上限 / 改封装方式 = 红线，先问 user。** 消费方：默认不勾、一直有「忘记」、
  锁定 / 退出 = forget、清缓存不清它、还原出厂清它、app 侧只准一个接缝文件碰它并登记进该 app 的持久层白名单。
- **只出货不送货**（对齐 store/Colors 契约）：交付物 = `npm run release` 的 tgz；消费方跑本仓
  `scripts/pull-package.sh`。开发期 version 钉 `0.0.0`；版本号只在人类过目真实 exports 后才花。
- 测试 `npm test`（node runner 家规版）；构建 `npm run build`（tsc → dist）。
- `journal/` 人类区，AI 永不写（硬规则 #2）。
