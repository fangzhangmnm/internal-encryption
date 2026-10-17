// @internal/encryption —— 「在这台设备上记住口令」：口令按设备落盘、有过期时间。created 2026-10-17 by Claude Fable 5.1
//
// 出处：KudsRocket `src/app/remember-password.ts`（2026-10-15 user「还是允许设备记住密码，每次进来不用输吧……仔细想想安全问题」
//   →「按设备 opt-in……那么做，同意」）整文件搬进库；2026-10-17 user 批 WXHW 同款 +「口令加一个过期时间，最多一个月」+「升级加密库同意」。
//   ADR = 本仓 ai-docs/adr/0001-device-remembers-password.md（对 store 仓 ADR-0012「口令只在内存、永不持久化」那一行的有意吃书）。
//
// 威胁模型（对齐家族 `ai-docs/20261016-data-safety-model.md` §2 第 4 条、§3 A11 / D1、四等公民表）：
//   · 加密防的是云端那一方（微软 / 网盘泄露 / 误分享 / 内容审查）。拿着已解锁设备的人本来就什么都看得见（OneDrive app、浏览器都登着）——
//     记住口令不新增信任方，新增的只是「时间」：会话结束后口令还留在这台设备上。过期时间就是给这段时间封顶（≤ 30 天）。
//   · 盘上**没有明文口令**：口令用一把同库里的**不可导出** AES-GCM 钥匙封起来再存。同源脚本能用那把钥匙解（和它能读到页面内存里的口令一样），
//     但拿不走钥匙本身；别的 origin、别的 app 碰不到。拷走整个浏览器 profile 的人能不能解，看平台——**按能解来算**，不当承诺。
//   · 过期时间和记录版本进 AES-GCM 的 additionalData：在库里改 expiresAt 就解不开 → 当没记。时钟往回拨能延命，接受（拿着设备的人本来就能开）；
//     但 expiresAt 比「现在 + 上限」还远 = 时钟被拨过 / 记录不对 → 当没记（保守方向：多问一次口令，不会少问）。
//   · 记着的口令只是「第一把试的钥匙」：调用方照旧先验（verifier / 容器 peek），对不上就 forget() 再弹框。它永不驱动破坏性操作（四等公民）。
//   · 本模块永不打印口令，抛出的错误里也没有口令。
// 给消费方的规矩：默认不记（面板一个勾，默认不勾）；记了就一直有「忘记」；「立即锁定」/ 退出登录 = forget()；清缓存 / 强制更新**不**清它
//   （它不是缓存）；还原出厂清它；换口令 = remember() 新的。库名由 app 给（`<app>.remember`），不同步、不上云、不是正本；app 侧只准一个接缝文件碰它。

/** 记住的上限：30 天（user 2026-10-17「最多一个月」）。ttlMs 超过它一律钳到它。 */
export const MAX_REMEMBER_MS = 30 * 24 * 60 * 60 * 1000;
const RECORD_VERSION = 1;
const AAD_TAG = "internal-encryption.remember.v1";
/** expiresAt 比「现在 + 上限」还远这么多 = 时钟被拨过 / 记录不对 → 当没记。 */
const CLOCK_SLACK_MS = 24 * 60 * 60 * 1000;
const STORE_NAME = "secret";
const RECORD_KEY = "password";

interface RememberedRecord { v: typeof RECORD_VERSION; key: CryptoKey; iv: Uint8Array; ct: ArrayBuffer; expiresAt: number }

/** 存一条记录的地方。默认 = IDB 一库一表一键（idbSecretStore）；测试注入内存版。 */
export interface SecretStore {
  get(): Promise<unknown>;
  put(record: unknown): Promise<void>;
  delete(): Promise<void>;
}

export interface PasswordKeeperOpts {
  /** IDB 库名，app 自己的前缀（如 `webxiaoheiwu.remember`）。只在没注入 store 时用。 */
  dbName: string;
  /** 换掉默认的 IDB 存储（测试 / 别的持久层）。 */
  store?: SecretStore;
  /** 时钟（测试）。 */
  now?: () => number;
}
export interface RememberOpts {
  /** 多久以后忘掉（毫秒）。缺省 = 上限 30 天；超上限钳到上限；≤ 0 / NaN 抛 RangeError。 */
  ttlMs?: number;
}
export interface RememberedStatus { remembered: boolean; expiresAt: number | null }

export interface PasswordKeeper {
  /** 记住：每次生成一把新的不可导出钥匙，口令封好，钥匙 + 密文 + 过期时间一起存（覆盖旧记录）。返回过期时刻（epoch ms）。 */
  remember(password: string, opts?: RememberOpts): Promise<{ expiresAt: number }>;
  /** 记着的口令；没记 / 过期 / 记录不对（改过、解不开）→ null，并把记录删掉。永不抛。 */
  recall(): Promise<string | null>;
  /** 记没记、记到什么时候。不解密。过期的当没记（并删掉）。永不抛。 */
  status(): Promise<RememberedStatus>;
  /** 忘记（删记录；钥匙跟着没了）。存储层的错误原样抛给调用方。 */
  forget(): Promise<void>;
}

/** 默认存储：IndexedDB `dbName` 里一个表一个键。事务 complete 才算成功（写在配额墙上可能 success 之后又 abort，不能当成功）。 */
export function idbSecretStore(dbName: string, factory?: IDBFactory): SecretStore {
  const idb = factory ?? (globalThis as { indexedDB?: IDBFactory }).indexedDB;
  if (!idb) throw new Error("idbSecretStore: IndexedDB is not available here (inject a SecretStore instead)");
  let dbp: Promise<IDBDatabase> | null = null;
  const db = (): Promise<IDBDatabase> => {
    dbp ??= new Promise((resolve, reject) => {
      const req = idb.open(dbName, 1);
      req.onupgradeneeded = () => { req.result.createObjectStore(STORE_NAME); };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    dbp.catch(() => { dbp = null; });
    return dbp;
  };
  async function tx<T>(mode: IDBTransactionMode, body: (s: IDBObjectStore) => IDBRequest<T>): Promise<T | undefined> {
    const d = await db();
    return new Promise<T | undefined>((resolve, reject) => {
      const t = d.transaction(STORE_NAME, mode);
      let result: T | undefined;
      const req = body(t.objectStore(STORE_NAME));
      req.onsuccess = () => { result = req.result; };
      t.oncomplete = () => resolve(result);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error ?? new Error("remember: transaction aborted"));
    });
  }
  return {
    get: () => tx<unknown>("readonly", (s) => s.get(RECORD_KEY)),
    put: async (rec) => { await tx("readwrite", (s) => s.put(rec, RECORD_KEY)); },
    delete: async () => { await tx("readwrite", (s) => s.delete(RECORD_KEY)); },
  };
}

export function createPasswordKeeper(opts: PasswordKeeperOpts): PasswordKeeper {
  const store = opts.store ?? idbSecretStore(opts.dbName);
  const now = opts.now ?? (() => Date.now());
  const aad = (expiresAt: number): BufferSource => new TextEncoder().encode(`${AAD_TAG}|${expiresAt}`);
  const isRecord = (x: unknown): x is RememberedRecord => {
    const r = x as Partial<RememberedRecord> | null;
    return r != null && typeof r === "object" && r.v === RECORD_VERSION && typeof r.key === "object" && r.key != null
      && r.iv instanceof Uint8Array && r.iv.length === 12 && r.ct instanceof ArrayBuffer
      && typeof r.expiresAt === "number" && Number.isFinite(r.expiresAt);
  };
  const forget = async (): Promise<void> => { await store.delete(); };
  const quietForget = (): Promise<void> => forget().catch(() => { /* 记录本来就要当没有；删不掉下次 recall 再删 */ });
  /** 读记录；没有 / 过期 / 不对 → 删掉、回 null。不解密。 */
  async function live(): Promise<RememberedRecord | null> {
    let rec: unknown;
    try { rec = await store.get(); } catch { return null; }
    if (rec == null) return null;
    const t = now();
    if (!isRecord(rec) || rec.expiresAt <= t || rec.expiresAt > t + MAX_REMEMBER_MS + CLOCK_SLACK_MS) { await quietForget(); return null; }
    return rec;
  }
  return {
    async remember(password, o = {}) {
      if (typeof password !== "string" || password.length === 0) throw new TypeError("remember: password must be a non-empty string");
      const ttl = o.ttlMs ?? MAX_REMEMBER_MS;
      if (typeof ttl !== "number" || !Number.isFinite(ttl) || ttl <= 0) throw new RangeError("remember: ttlMs must be a positive number of milliseconds");
      const expiresAt = Math.round(now() + Math.min(ttl, MAX_REMEMBER_MS));
      const subtle = globalThis.crypto.subtle;
      const key = await subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
      const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
      const ct = await subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource, additionalData: aad(expiresAt) }, key, new TextEncoder().encode(password) as BufferSource);
      const rec: RememberedRecord = { v: RECORD_VERSION, key, iv, ct, expiresAt };
      await store.put(rec);
      return { expiresAt };
    },
    async recall() {
      const rec = await live();
      if (!rec) return null;
      try {
        const plain = await globalThis.crypto.subtle.decrypt({ name: "AES-GCM", iv: rec.iv as BufferSource, additionalData: aad(rec.expiresAt) }, rec.key, rec.ct);
        return new TextDecoder().decode(plain);
      } catch { await quietForget(); return null; }
    },
    async status() {
      const rec = await live();
      return rec ? { remembered: true, expiresAt: rec.expiresAt } : { remembered: false, expiresAt: null };
    },
    forget,
  };
}
