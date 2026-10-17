// @internal/encryption —— 唯一公开入口。created 2026-08-28 by Claude Fable 5.
export { createEncryption, makeGuid, encryptPeek, scanEncPeekFromEnd, decryptPeek,
  PEEK_MAGIC, PEEK_TAIL_WINDOW, ENC_PEEK_MIME, CONTAINER_PEEK_ENTRY, CONTAINER_PEEK_ENTRIES } from "./encryption.ts";
export type { Encryption, CryptoCodec, EncPeekParsed, ContainerMeta, PackOpts, UnpackResult } from "./encryption.ts";
// 0.2.0：「在这台设备上记住口令」（ADR-0001；user 2026-10-15 / 10-17 拍板）。added 2026-10-17 by Claude Fable 5.1
export { createPasswordKeeper, idbSecretStore, MAX_REMEMBER_MS } from "./remember.ts";
export type { PasswordKeeper, PasswordKeeperOpts, RememberOpts, RememberedStatus, SecretStore } from "./remember.ts";
