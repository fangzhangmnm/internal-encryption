// @internal/encryption —— 家族内容加密库（2026-08-28 自 @internal/store crypto-container.ts 立户）。
// created 2026-08-28 by Claude Fable 5. 出处 = user 拍板「encryption 从 store 上面独立出来，一个新的 internal 库」
//   （store 单一职责 = 同步；加密是纯内容操作，blob 进 blob 出，零 provider/持久化依赖——
//   挂在 Store 实例上导致无库模式探测不了加密件，WeebPaint ambient 退役轮实锤）。
//
// 容器格式（ADR-0012，格式盲：data.bin 是不透明字节，peek 也是不透明字节——app 自定义语义）：
//
//   <name>.zip           ← 外层：明文 STORE zip。central directory 100% 干净
//     ├── <GUID>            payload = 加密 .7z（AES-256 + 强 KDF + 加密头 -mhe）：
//     │       ├── data.bin     原始文件字节，扩展名混淆
//     │       └── meta.bin     "WPMETA1\n" + JSON {v,name,ext}（恢复时改回真名用）
//     └── peek              ← 加密旁路小块，**最后一个 entry**：
//           [MAGIC 8][ver 1][salt 16][iv 12][len 4LE][AES-GCM(不透明字节)]
//           一次 byte-range 拉尾部 → 扫 MAGIC → 解密，无需全量下载。peek 兼任「这是加密容器」探测标记，永远写。
//
// 恢复（anti-abandonware）：7-Zip 开 <name>.zip → 取 <GUID> → 改名 .7z → 输密码 → data.bin（按 meta 改回真名）。
// KDF：payload = 7z AES-256 强 KDF；peek = PBKDF2-SHA256×250k + AES-GCM（GCM tag 兼任密码验证器）。
// 无密钥托管、无 salt 文件（salt 在各自 header），换/丢设备零迁移。GUID 只是混淆名非身份（0607 否决）。
//
// HOST-SEAM：zip/7z codec 由 createEncryption 注入（vendored zip.js + 7z-wasm 归宿主）；
//   不注入 codec = 探测类照常工作、pack/unpack 响亮抛——**没有静默替身**（null-store 教训，2026-08-27/28）。

/** 宿主注入的 zip/7z codec（不提供 = 只探测不加解密）。 */
export interface CryptoCodec {
  /** 打包明文 zip（外层容器）。 */
  zipPack(entries: { path: string; data: Uint8Array | string }[]): Promise<Blob>;
  /** 解开明文 zip（path 到字节的记录）。 */
  zipUnpack(blob: Blob): Promise<Record<string, Uint8Array>>;
  /** 打包加密 .7z（AES-256 + 强 KDF + 加密头）。 */
  pack7z(entries: { path: string; data: Uint8Array | string }[], password: string): Promise<Uint8Array>;
  /** 解开加密 .7z（也认老 WinZip-AES zip）。 */
  unpack7z(bytes: Uint8Array, password: string): Promise<Record<string, Uint8Array>>;
}

// payload 永远走 unpack7z（7z-wasm = 真 7-Zip）——既认 .7z 也认老 WinZip-AES zip（实测逐位还原）。
const SEVENZ_MAGIC = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
const ZIP_MAGIC = [0x50, 0x4b, 0x03, 0x04];
function _startsWith(u8: Uint8Array, sig: number[]): boolean {
  if (u8.length < sig.length) return false;
  for (let i = 0; i < sig.length; i++) if (u8[i] !== sig[i]) return false;
  return true;
}

// 尾部 peek blob 的 MAGIC（8 字节；首字节非文本防 false-match）
export const PEEK_MAGIC = [0x9e, 0x57, 0x50, 0x54, 0x48, 0x0d, 0x0a, 0x1a];
const PEEK_VER = 1;
const PEEK_HEADER_LEN = 8 + 1 + 16 + 12 + 4;   // MAGIC + ver + salt + iv + len
const PEEK_MAX_LEN = 8 * 1024 * 1024;
const PBKDF2_ITERS = 250_000;

/** 尾部扫描窗口：peek（≤70KB 自适应缩略图）+ 外层 CD/EOCD 余量。与 80KB byte-range 预算兼容。 */
export const PEEK_TAIL_WINDOW = 98304;
/** 加密 peek blob 的 Blob.type 标记——byte-range 管线/缓存层靠它区分明文与密文（不解释内容）。 */
export const ENC_PEEK_MIME = "application/x-sync-store-enc-peek";
/** 加密容器外层 zip 里「加密旁路小块」entry 名。按名命中 =「这是加密容器」。 */
export const CONTAINER_PEEK_ENTRY = "peek";
export const CONTAINER_PEEK_ENTRIES: readonly string[] = [CONTAINER_PEEK_ENTRY];

const META_MAGIC = "WPMETA1\n";

export interface EncPeekParsed {
  start: number; end: number; ver: number;
  salt: Uint8Array; iv: Uint8Array; ct: Uint8Array;
}
export interface ContainerMeta { v: number; name: string | null; ext: string; }

export function makeGuid(): string {
  return (globalThis.crypto && crypto.randomUUID) ? crypto.randomUUID()
    : "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
        const r = (Math.random() * 16) | 0; return (c === "x" ? r : (r & 3) | 8).toString(16);
      });
}

// ---- peek blob：强 KDF + AES-GCM（进出都是不透明字节；纯 WebCrypto，零 codec）----

const _keyCache = new Map<string, CryptoKey>();   // `${password}\x00${saltHex}` → CryptoKey
function _hex(u8: Uint8Array): string { return [...u8].map((b) => b.toString(16).padStart(2, "0")).join(""); }

async function _deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const cacheKey = `${password}\x00${_hex(salt)}`;
  const hit = _keyCache.get(cacheKey);
  if (hit) return hit;
  const subtle = globalThis.crypto.subtle;
  const base = await subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations: PBKDF2_ITERS },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
  _keyCache.set(cacheKey, key);
  return key;
}

/** 不透明字节（可空）→ 完整加密 peek blob 字节（含 MAGIC 头）。空也加密（探测标记必须在）。 */
export async function encryptPeek(bytes: Uint8Array | null, password: string): Promise<Uint8Array> {
  const plain = bytes && bytes.length ? bytes : new Uint8Array(0);
  const salt = new Uint8Array(16), iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(salt);
  globalThis.crypto.getRandomValues(iv);
  const key = await _deriveKey(password, salt);
  const ct = new Uint8Array(await globalThis.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource }, key, plain as BufferSource));
  const out = new Uint8Array(PEEK_HEADER_LEN + ct.length);
  out.set(PEEK_MAGIC, 0);
  out[8] = PEEK_VER;
  out.set(salt, 9);
  out.set(iv, 25);
  new DataView(out.buffer).setUint32(37, ct.length, true);
  out.set(ct, PEEK_HEADER_LEN);
  return out;
}

/** 从字节流**末尾向前**扫加密 peek blob。带 sanity（ver/len/边界），false-positive 继续向前。找不到返 null。 */
export function scanEncPeekFromEnd(u8: Uint8Array): EncPeekParsed | null {
  const n = u8.length;
  outer: for (let i = n - PEEK_HEADER_LEN; i >= 0; i--) {
    for (let k = 0; k < 8; k++) if (u8[i + k] !== PEEK_MAGIC[k]) continue outer;
    const ver = u8[i + 8];
    if (ver !== PEEK_VER) continue;
    const len = new DataView(u8.buffer, u8.byteOffset + i + 37, 4).getUint32(0, true);
    if (len < 16 || len > PEEK_MAX_LEN || i + PEEK_HEADER_LEN + len > n) continue;   // GCM tag 至少 16B
    return {
      start: i,
      end: i + PEEK_HEADER_LEN + len,
      ver,
      salt: u8.slice(i + 9, i + 25),
      iv: u8.slice(i + 25, i + 37),
      ct: u8.slice(i + PEEK_HEADER_LEN, i + PEEK_HEADER_LEN + len),
    };
  }
  return null;
}

/** 解密 peek → 不透明字节（可能为空）。密码错 → throw code=WRONG_PASSWORD（GCM tag 即验证器）。 */
export async function decryptPeek(parsed: EncPeekParsed, password: string): Promise<Uint8Array> {
  const key = await _deriveKey(password, parsed.salt);
  try {
    return new Uint8Array(await globalThis.crypto.subtle.decrypt({ name: "AES-GCM", iv: parsed.iv as BufferSource }, key, parsed.ct as BufferSource));
  } catch {
    const err = new Error("wrong password") as Error & { code?: string };
    err.code = "WRONG_PASSWORD";
    throw err;
  }
}

async function _tailBytes(blobOrBytes: Blob | Uint8Array, window = PEEK_TAIL_WINDOW): Promise<Uint8Array> {
  if (blobOrBytes instanceof Uint8Array) {
    return blobOrBytes.length <= window ? blobOrBytes : blobOrBytes.slice(blobOrBytes.length - window);
  }
  const blob = blobOrBytes.slice(Math.max(0, blobOrBytes.size - window));
  return new Uint8Array(await blob.arrayBuffer());
}

export interface PackOpts {
  dataBytes: Uint8Array;        // 原始文件字节（进 data.bin；格式不透明）
  fileName?: string | null;     // 真名（进 meta.bin，无 app 恢复时改回真名用）
  ext?: string;                 // 真扩展名（meta.bin）
  guid?: string;                // 混淆名（不透明 token，非身份；缺省现生成）
  peek?: Uint8Array | null;     // 不透明旁路字节（可空；空也写探测标记）
  password: string;
}
export interface UnpackResult { dataBlob: Blob; meta: ContainerMeta | null; guid: string; }

/** 实例面（app 与 store 共用同一形）。探测类零 codec；pack/unpack 无 codec 响亮抛。 */
export interface Encryption {
  // ── 探测（便宜；零 codec 零解密）──
  /** 这份字节是不是加密容器？①尾部 peek MAGIC（app 容器必带）②offset0=.7z magic（裸 7z mock）。 */
  looksEncryptedContainer(b: Blob | Uint8Array): Promise<boolean>;
  /** 这块 blob 是不是密文 peek（type=ENC_PEEK_MIME）。纯类型判定。 */
  isEncryptedPeekBlob(b: Blob | null | undefined): boolean;
  scanEncPeekFromEnd(u8: Uint8Array): EncPeekParsed | null;
  // ── peek crypto（WebCrypto，零 codec）──
  encryptPeek(bytes: Uint8Array | null, password: string): Promise<Uint8Array>;
  decryptPeek(parsed: EncPeekParsed, password: string): Promise<Uint8Array>;
  // ── 容器（需 codec）──
  packContainer(opts: PackOpts): Promise<Blob>;
  unpackContainer(blob: Blob | Uint8Array, password: string): Promise<UnpackResult>;
  // ── app 便捷面（与旧 store.encryption 三件同名同形）──
  isEncryptedBlob(b: Blob | Uint8Array): Promise<boolean>;
  /** 验密码 + 解出明文合一（一次尝试 = 一次解密，成功的明文直接复用）。null = 错密码/不是容器。 */
  tryDecryptEncryptedBlob(blob: Blob, pw: string): Promise<Blob | null>;
  // ── 格式常量（随实例走，port 单对象）──
  readonly PEEK_TAIL_WINDOW: number;
  readonly ENC_PEEK_MIME: string;
  readonly CONTAINER_PEEK_ENTRIES: readonly string[];
}

/** 工厂。codec 缺省 null = 只探测；reportError 缺省吞噬降级为静默 false（探测容错路径），建议注入 app 的 funnel。 */
export function createEncryption(opts: { codec?: CryptoCodec | null; reportError?: (e: unknown) => void } = {}): Encryption {
  const _codec = opts.codec ?? null;
  const report = opts.reportError ?? (() => {});
  const codec = (): CryptoCodec => {
    if (!_codec) throw new Error("encryption codec not configured (createEncryption({codec}) missing) — detection works, pack/unpack unavailable");
    return _codec;
  };

  async function looksEncryptedContainer(blobOrBytes: Blob | Uint8Array): Promise<boolean> {
    try {
      const head = blobOrBytes instanceof Uint8Array ? blobOrBytes.slice(0, 6)
        : new Uint8Array(await blobOrBytes.slice(0, 6).arrayBuffer());
      if (_startsWith(head, SEVENZ_MAGIC)) return true;                  // 裸 .7z
      return scanEncPeekFromEnd(await _tailBytes(blobOrBytes)) != null;  // app 容器（peek MAGIC）
    } catch (e) { report(e); return false; }
  }

  async function packContainer({ dataBytes, fileName, ext = "bin", guid, peek = null, password }: PackOpts): Promise<Blob> {
    if (!password) throw new Error("cannot encrypt without a password");
    const metaJson = JSON.stringify({ v: 1, name: fileName || null, ext });
    const payloadBytes = await codec().pack7z([
      { path: "data.bin", data: dataBytes },
      { path: "meta.bin", data: META_MAGIC + metaJson },
    ], password);
    const peekEnc = await encryptPeek(peek, password);
    // peek 必须最后（byte-range 尾部一发命中 + 容器探测）；外层全 STORE（zipPack level:0）
    return await codec().zipPack([
      { path: guid || makeGuid(), data: payloadBytes },
      { path: CONTAINER_PEEK_ENTRY, data: peekEnc },
    ]);
  }

  function _pickData(inner: Record<string, Uint8Array>): Uint8Array | null {
    if (inner["data.bin"]) return inner["data.bin"];
    const names = Object.keys(inner).filter((n) => n !== "meta.bin");
    return names.length ? inner[names[0]] : null;
  }
  function _readMeta(inner: Record<string, Uint8Array>): ContainerMeta | null {
    if (!inner["meta.bin"]) return null;
    try {
      const text = new TextDecoder().decode(inner["meta.bin"]);
      if (text.startsWith(META_MAGIC)) return JSON.parse(text.slice(META_MAGIC.length));
    } catch (e) { report(e); /* meta 是恢复辅助件，坏了不阻断 */ }
    return null;
  }

  /** 向后兼容 + 容错（详容器格式头注释）：外壳明文 zip → 取 payload；裸 .7z/裸 WinZip-AES → 整块 unpack7z。 */
  async function unpackContainer(blob: Blob | Uint8Array, password: string): Promise<UnpackResult> {
    const whole = blob instanceof Uint8Array ? blob : new Uint8Array(await blob.arrayBuffer());
    let payload: Uint8Array | null = null, guid = "";
    if (_startsWith(whole, ZIP_MAGIC)) {
      try {
        const outer = await codec().zipUnpack(blob instanceof Blob ? blob : new Blob([whole as BlobPart]));
        const g = Object.keys(outer).find((n) => !CONTAINER_PEEK_ENTRIES.includes(n));   // 非 peek 旁路 = payload
        if (g && outer[g] && (_startsWith(outer[g], SEVENZ_MAGIC) || _startsWith(outer[g], ZIP_MAGIC))) {
          payload = outer[g]; guid = g;
        }
      } catch (e) { report(e); /* 外层 entries 加密（裸 WinZip-AES）→ payload 留 null，整块解 */ }
    }
    const inner = await codec().unpack7z(payload ?? whole, password);
    const data = _pickData(inner);
    if (!data) throw new Error("encrypted container has no readable payload");
    return { dataBlob: new Blob([data as BlobPart], { type: "application/zip" }), meta: _readMeta(inner), guid };
  }

  return {
    looksEncryptedContainer,
    isEncryptedPeekBlob: (b) => !!b && b.type === ENC_PEEK_MIME,
    scanEncPeekFromEnd,
    encryptPeek,
    decryptPeek,
    packContainer,
    unpackContainer,
    isEncryptedBlob: (b) => looksEncryptedContainer(b),
    async tryDecryptEncryptedBlob(blob, pw) {
      if (!pw) return null;
      if (!(await looksEncryptedContainer(blob))) return null;
      try { return (await unpackContainer(blob, pw)).dataBlob; } catch { return null; }
    },
    PEEK_TAIL_WINDOW,
    ENC_PEEK_MIME,
    CONTAINER_PEEK_ENTRIES,
  };
}
