// 「在这台设备上记住口令」验收（createPasswordKeeper / idbSecretStore）。created 2026-10-17 by Claude Fable 5.1
// 真 WebCrypto；存储 = 内存版 SecretStore（逻辑）+ 最小 IndexedDB 假货（idbSecretStore 的事务语义）。
import { describe, it, assert, eq } from "./runner.mjs";

const { createPasswordKeeper, idbSecretStore, MAX_REMEMBER_MS } = await import("../src/index.ts");
const { createFakeIndexedDB } = await import("./fixtures/fake-idb.ts");

const HOUR = 3600_000, DAY = 24 * HOUR;
const PW = "口令 pass-phrase 123";

function memStore() {
  let rec;
  return { get: async () => rec, put: async (r) => { rec = r; }, delete: async () => { rec = undefined; }, peek: () => rec, poke: (r) => { rec = r; } };
}
function clock(start = 1_700_000_000_000) {
  let t = start;
  const c = () => t;
  c.advance = (ms) => { t += ms; };
  c.set = (v) => { t = v; };
  return c;
}
const keeper = (store = memStore(), now = clock()) => ({ k: createPasswordKeeper({ dbName: "test.remember", store, now }), store, now });
const includesBytes = (hay, needle) => {
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
};

describe("remember · 记住 / 想起 / 忘记", () => {
  it("remember → recall 原样回来；status 带过期时间；缺省 ttl = 上限 30 天", async () => {
    const { k, now } = keeper();
    const { expiresAt } = await k.remember(PW);
    eq(expiresAt, now() + MAX_REMEMBER_MS, "缺省过期 = 现在 + 30 天");
    eq(await k.recall(), PW);
    const st = await k.status();
    eq(st.remembered, true); eq(st.expiresAt, expiresAt);
  });
  it("没记 → recall null / status false，不抛", async () => {
    const { k } = keeper();
    eq(await k.recall(), null);
    const st = await k.status();
    eq(st.remembered, false); eq(st.expiresAt, null);
  });
  it("forget → 记录没了", async () => {
    const { k, store } = keeper();
    await k.remember(PW);
    await k.forget();
    eq(store.peek(), undefined, "记录删掉");
    eq(await k.recall(), null);
  });
  it("再 remember 换掉旧的（换口令）", async () => {
    const { k } = keeper();
    await k.remember(PW);
    await k.remember("new-" + PW);
    eq(await k.recall(), "new-" + PW);
  });
});

describe("remember · 过期（user 2026-10-17「最多一个月」）", () => {
  it("ttl 1 小时：差 1ms 还在，到点就忘（记录一起删掉）", async () => {
    const { k, store, now } = keeper();
    await k.remember(PW, { ttlMs: HOUR });
    now.advance(HOUR - 1);
    eq(await k.recall(), PW, "差 1ms 还在");
    now.advance(1);
    eq(await k.recall(), null, "到点就忘");
    eq(store.peek(), undefined, "过期记录删掉");
    eq((await k.status()).remembered, false);
  });
  it("status 也按过期算，不解密也会把过期记录删掉", async () => {
    const { k, store, now } = keeper();
    await k.remember(PW, { ttlMs: DAY });
    now.advance(DAY + 1);
    eq((await k.status()).remembered, false);
    eq(store.peek(), undefined);
  });
  it("ttl 超过 30 天 → 钳到 30 天", async () => {
    const { k, now } = keeper();
    const { expiresAt } = await k.remember(PW, { ttlMs: 365 * DAY });
    eq(expiresAt, now() + MAX_REMEMBER_MS);
    now.advance(MAX_REMEMBER_MS);
    eq(await k.recall(), null, "30 天到点忘");
  });
  it("ttl ≤ 0 / NaN → RangeError；空口令 → TypeError；都不写记录", async () => {
    const { k, store } = keeper();
    for (const ttlMs of [0, -1, NaN, Infinity]) {
      let err = null;
      try { await k.remember(PW, { ttlMs }); } catch (e) { err = e; }
      assert(err instanceof RangeError, `ttlMs=${ttlMs} 应抛 RangeError`);
    }
    let err = null;
    try { await k.remember(""); } catch (e) { err = e; }
    assert(err instanceof TypeError, "空口令应抛 TypeError");
    eq(store.peek(), undefined);
  });
  it("过期时间比「现在 + 上限 + 1 天」还远（时钟被往回拨 / 记录不对）→ 当没记并删掉", async () => {
    const { k, store, now } = keeper();
    await k.remember(PW);
    now.advance(-2 * DAY);   // 记完之后时钟被拨回两天
    eq(await k.recall(), null);
    eq(store.peek(), undefined);
  });
  it("时钟只拨回几小时（在 1 天宽限内）→ 还认", async () => {
    const { k, now } = keeper();
    await k.remember(PW);
    now.advance(-3 * HOUR);
    eq(await k.recall(), PW);
  });
});

describe("remember · 盘上没有明文、改不了", () => {
  it("记录里：钥匙不可导出；密文里没有口令字节；除钥匙外没有等于口令的字段", async () => {
    const { k, store } = keeper();
    await k.remember(PW);
    const rec = store.peek();
    eq(rec.key.extractable, false, "钥匙不可导出");
    assert(!includesBytes(new Uint8Array(rec.ct), new TextEncoder().encode(PW)), "密文里不能有口令字节");
    assert(!Object.values(rec).some((v) => v === PW), "没有明文字段");
    assert(!JSON.stringify({ ...rec, key: undefined, ct: undefined }).includes(PW), "可序列化部分不含口令");
  });
  it("改库里的 expiresAt（延命）→ 解不开 → 当没记并删掉", async () => {
    const { k, store } = keeper();
    await k.remember(PW, { ttlMs: HOUR });
    const rec = store.peek();
    store.poke({ ...rec, expiresAt: rec.expiresAt + DAY });
    eq(await k.recall(), null, "AAD 对不上");
    eq(store.peek(), undefined, "坏记录删掉");
  });
  it("版本不对 / 垃圾记录 → 当没记并删掉", async () => {
    for (const bad of [{ v: 2 }, "junk", 42, { v: 1, key: {}, iv: new Uint8Array(12), ct: new ArrayBuffer(8), expiresAt: "soon" }]) {
      const { k, store } = keeper();
      store.poke(bad);
      eq(await k.recall(), null, `垃圾 ${JSON.stringify(bad)} → null`);
      eq(store.peek(), undefined, "垃圾删掉");
    }
  });
  it("钥匙对不上密文（库被动过）→ null 并删掉", async () => {
    const a = keeper(), b = keeper();
    await a.k.remember(PW); await b.k.remember(PW);
    a.store.poke({ ...a.store.peek(), key: b.store.peek().key });
    eq(await a.k.recall(), null);
    eq(a.store.peek(), undefined);
  });
  it("存储读失败 → recall / status 不抛；写失败 → remember 抛；删失败 → forget 抛", async () => {
    const broken = { get: async () => { throw new Error("idb down"); }, put: async () => { throw new Error("idb down"); }, delete: async () => { throw new Error("idb down"); } };
    const k = createPasswordKeeper({ dbName: "x", store: broken });
    eq(await k.recall(), null);
    eq((await k.status()).remembered, false);
    let threw = false;
    try { await k.remember(PW); } catch { threw = true; }
    assert(threw, "写失败要响亮");
    threw = false;
    try { await k.forget(); } catch { threw = true; }
    assert(threw, "删失败要响亮（调用方要知道没忘掉）");
  });
});

describe("remember · idbSecretStore（IndexedDB 事务语义）", () => {
  it("put / get / delete 往返；两个 store 实例看同一个库", async () => {
    const idb = createFakeIndexedDB();
    const s = idbSecretStore("x.remember", idb);
    eq(await s.get(), undefined);
    await s.put({ a: 1 });
    eq((await s.get()).a, 1);
    eq((await idbSecretStore("x.remember", idb).get()).a, 1, "同库另一个实例也读到");
    await s.delete();
    eq(await s.get(), undefined);
  });
  it("request success 之后事务 abort（配额墙）→ put 必须 reject，不能当成功", async () => {
    const idb = createFakeIndexedDB({ abortAfterPut: true });
    const s = idbSecretStore("x.remember", idb);
    let threw = false;
    try { await s.put({ a: 1 }); } catch { threw = true; }
    assert(threw, "abort 的写不能 resolve");
    eq(await s.get(), undefined, "值没进去");
  });
  it("整条链在假 IDB 上跑通：remember → recall → forget", async () => {
    const idb = createFakeIndexedDB();
    const k = createPasswordKeeper({ dbName: "x.remember", store: idbSecretStore("x.remember", idb) });
    await k.remember(PW);
    eq(await k.recall(), PW);
    await k.forget();
    eq(await k.recall(), null);
  });
  it("别处 deleteDatabase（还原出厂）→ 开着的连接让位，删得掉；之后再用自动重开（0.2.1）", async () => {
    const idb = createFakeIndexedDB();
    const s = idbSecretStore("x.remember", idb);
    await s.put({ a: 1 });                       // 连接已开着
    const outcome = await new Promise((resolve) => {
      const req = idb.deleteDatabase("x.remember");
      req.onsuccess = () => resolve("deleted");
      req.onblocked = () => resolve("blocked");
    });
    eq(outcome, "deleted", "连接没让位 = 还原出厂会被堵");
    eq(idb.dbs.has("x.remember"), false);
    eq(await s.get(), undefined, "删后重开是空库");
    await s.put({ b: 2 });
    eq((await s.get()).b, 2, "重开后照常写");
  });
  it("没有 IndexedDB 又没注入 store → 建 keeper 当场抛（不静默替身）", () => {
    assert(typeof globalThis.indexedDB === "undefined", "node 里本来就没有 indexedDB");
    let threw = false;
    try { createPasswordKeeper({ dbName: "x.remember" }); } catch { threw = true; }
    assert(threw);
  });
});
