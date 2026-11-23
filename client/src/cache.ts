// Persistent per-app row cache. Rows are stored exactly as the server sent
// them, ciphertext included: the on-device cache is as opaque as the server's
// database, and decryption happens in memory on read.
import type { WireRow } from './wire.js'

export interface CacheMeta {
  appId: string
  /** Cached ciphertext is only valid for this key epoch. */
  dekVersion: number
  /** Retention the cache was filled with (null = everything). */
  retentionDays: number | null
  /** Server time of the last sync start; next sync asks for edits since then. */
  watermark: string | null
  deletedWatermark: string | null
}

export interface CacheStore {
  getMeta(appId: string): Promise<CacheMeta | undefined>
  setMeta(meta: CacheMeta): Promise<void>
  getRows(appId: string): Promise<WireRow[]>
  putRows(appId: string, rows: WireRow[]): Promise<void>
  deleteRows(appId: string, ids: string[]): Promise<void>
  clearApp(appId: string): Promise<void>
  /** Drop everything (e.g. on sign-out). */
  destroy(): Promise<void>
}

export class MemoryCacheStore implements CacheStore {
  private meta = new Map<string, CacheMeta>()
  private rows = new Map<string, Map<string, WireRow>>()

  async getMeta(appId: string) {
    return this.meta.get(appId)
  }
  async setMeta(meta: CacheMeta) {
    this.meta.set(meta.appId, { ...meta })
  }
  async getRows(appId: string) {
    return [...(this.rows.get(appId)?.values() ?? [])]
  }
  async putRows(appId: string, rows: WireRow[]) {
    let m = this.rows.get(appId)
    if (!m) this.rows.set(appId, (m = new Map()))
    for (const r of rows) m.set(r.id, r)
  }
  async deleteRows(appId: string, ids: string[]) {
    const m = this.rows.get(appId)
    for (const id of ids) m?.delete(id)
  }
  async clearApp(appId: string) {
    this.meta.delete(appId)
    this.rows.delete(appId)
  }
  async destroy() {
    this.meta.clear()
    this.rows.clear()
  }
}

type StoredRow = WireRow & { appId: string }

function promisify<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

function done(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve()
    tx.onerror = () => reject(tx.error)
    tx.onabort = () => reject(tx.error)
  })
}

/** One IndexedDB database per user, so accounts sharing a browser never mix. */
export class IndexedDbCacheStore implements CacheStore {
  private dbPromise: Promise<IDBDatabase> | null = null

  constructor(private readonly name: string) {}

  static isAvailable(): boolean {
    return typeof indexedDB !== 'undefined'
  }

  private db(): Promise<IDBDatabase> {
    if (!this.dbPromise) {
      this.dbPromise = new Promise((resolve, reject) => {
        const req = indexedDB.open(this.name, 1)
        req.onupgradeneeded = () => {
          const db = req.result
          const rows = db.createObjectStore('rows', { keyPath: ['appId', 'id'] })
          rows.createIndex('appId', 'appId')
          db.createObjectStore('meta', { keyPath: 'appId' })
        }
        req.onsuccess = () => resolve(req.result)
        req.onerror = () => reject(req.error)
      })
    }
    return this.dbPromise
  }

  async getMeta(appId: string) {
    const db = await this.db()
    return (await promisify(db.transaction('meta').objectStore('meta').get(appId))) as CacheMeta | undefined
  }

  async setMeta(meta: CacheMeta) {
    const db = await this.db()
    const tx = db.transaction('meta', 'readwrite')
    tx.objectStore('meta').put(meta)
    await done(tx)
  }

  async getRows(appId: string) {
    const db = await this.db()
    const stored = (await promisify(
      db.transaction('rows').objectStore('rows').index('appId').getAll(appId),
    )) as StoredRow[]
    return stored.map(({ appId: _appId, ...row }) => row)
  }

  async putRows(appId: string, rows: WireRow[]) {
    if (!rows.length) return
    const db = await this.db()
    const tx = db.transaction('rows', 'readwrite')
    const store = tx.objectStore('rows')
    for (const r of rows) store.put({ ...r, appId })
    await done(tx)
  }

  async deleteRows(appId: string, ids: string[]) {
    if (!ids.length) return
    const db = await this.db()
    const tx = db.transaction('rows', 'readwrite')
    const store = tx.objectStore('rows')
    for (const id of ids) store.delete([appId, id])
    await done(tx)
  }

  async clearApp(appId: string) {
    const db = await this.db()
    const tx = db.transaction(['rows', 'meta'], 'readwrite')
    tx.objectStore('meta').delete(appId)
    tx.objectStore('rows').delete(IDBKeyRange.bound([appId], [appId, []]))
    await done(tx)
  }

  async destroy() {
    if (this.dbPromise) {
      ;(await this.dbPromise).close()
      this.dbPromise = null
    }
    await new Promise<void>((resolve) => {
      const req = indexedDB.deleteDatabase(this.name)
      req.onsuccess = req.onerror = req.onblocked = () => resolve()
    })
  }
}
