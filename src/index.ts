// @internal/encryption —— 唯一公开入口。created 2026-08-28 by Claude Fable 5.
export { createEncryption, makeGuid, encryptPeek, scanEncPeekFromEnd, decryptPeek,
  PEEK_MAGIC, PEEK_TAIL_WINDOW, ENC_PEEK_MIME, CONTAINER_PEEK_ENTRY, CONTAINER_PEEK_ENTRIES } from "./encryption.ts";
export type { Encryption, CryptoCodec, EncPeekParsed, ContainerMeta, PackOpts, UnpackResult } from "./encryption.ts";
