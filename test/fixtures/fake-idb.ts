// 最小 IndexedDB 假货——只覆盖 idbSecretStore 用到的面：open / onupgradeneeded / createObjectStore / transaction /
// get / put / delete / oncomplete / onabort。事件用 queueMicrotask 异步派发，模拟真 IDB 的回调顺序。
// created 2026-10-17 by Claude Fable 5.1
/* eslint-disable @typescript-eslint/no-explicit-any */
export interface FakeIdbOpts {
  /** readwrite 事务里 put 的 request 先 success、随后整个事务 abort（配额墙上的真实行为）；写进去的值回滚。 */
  abortAfterPut?: boolean;
}

export function createFakeIndexedDB(opts: FakeIdbOpts = {}): IDBFactory & { dbs: Map<string, Map<string, Map<IDBValidKey, unknown>>> } {
  const dbs = new Map<string, Map<string, Map<IDBValidKey, unknown>>>();
  const later = (fn: () => void) => queueMicrotask(fn);
  class Req { result: any = undefined; error: any = null; onsuccess: any = null; onerror: any = null; onupgradeneeded: any = null; }

  function makeTx(stores: Map<string, Map<IDBValidKey, unknown>>, mode: string) {
    const tx: any = { error: null, oncomplete: null, onerror: null, onabort: null, mode };
    let pending = 0, aborted = false;
    const op = (fn: (req: Req) => void, abortAfter = false) => {
      const req = new Req();
      pending++;
      later(() => {
        fn(req);
        req.onsuccess?.();
        pending--;
        if (abortAfter && !aborted) { aborted = true; tx.error = new Error("QuotaExceededError (fake)"); later(() => tx.onabort?.()); return; }
        if (pending === 0 && !aborted) later(() => tx.oncomplete?.());
      });
      return req;
    };
    tx.objectStore = (name: string) => {
      const m = stores.get(name);
      if (!m) throw new Error(`fake idb: no object store ${name}`);
      return {
        get: (k: IDBValidKey) => op((r) => { r.result = m.get(k); }),
        put: (v: unknown, k: IDBValidKey) => op((r) => {
          if (mode !== "readwrite") throw new Error("fake idb: put in a readonly transaction");
          if (!opts.abortAfterPut) m.set(k, v);   // abort 的写回滚 = 干脆不写
          r.result = k;
        }, !!opts.abortAfterPut),
        delete: (k: IDBValidKey) => op((r) => { m.delete(k); r.result = undefined; }),
      };
    };
    return tx;
  }

  const conns = new Map<string, Set<any>>();   // 库名 → 开着的连接（deleteDatabase 要等它们 close）
  const factory: any = {
    dbs,
    open(name: string) {
      const req = new Req();
      later(() => {
        let stores = dbs.get(name);
        const fresh = !stores;
        if (!stores) { stores = new Map(); dbs.set(name, stores); }
        const s = stores;
        const conn: any = {
          onversionchange: null,
          close: () => { conns.get(name)?.delete(conn); },
          createObjectStore: (n: string) => { s.set(n, new Map()); },
          transaction: (n: string, mode: string) => makeTx(s, mode),
        };
        if (!conns.has(name)) conns.set(name, new Set());
        conns.get(name)!.add(conn);
        req.result = conn;
        if (fresh) req.onupgradeneeded?.();
        req.onsuccess?.();
      });
      return req;
    },
    /** 真 IDB 语义的子集：先给开着的连接发 versionchange；还有没 close 的 → 一直挂着（blocked，不 success）。 */
    deleteDatabase(name: string) {
      const req: any = new Req();
      req.onblocked = null;
      later(() => {
        for (const c of [...(conns.get(name) ?? [])]) c.onversionchange?.();
        if ((conns.get(name)?.size ?? 0) > 0) { req.onblocked?.(); return; }
        dbs.delete(name);
        req.onsuccess?.();
      });
      return req;
    },
  };
  return factory;
}
