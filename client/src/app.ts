// One app instance, decrypted. Everything an app needs goes through here:
// metadata, data rows (with caching), members, key rotation and the legacy
// data migration. Callers only ever see plaintext; the DEK stays inside.
import * as crypto from './crypto.js'
import { isConflict, SealbaseError } from './http.js'
import type { CacheMeta, CacheStore } from './cache.js'
import type { Session } from './session.js'
import type { Api, Role, Status, WireApp, WireBatch, WireBatchResult, WireRow } from './wire.js'

export type DateInput = Date | string

export interface Entry<T = unknown> {
  id: string
  /** The plaintext type (never sent to the server since format 2). */
  type: string
  data: T
  /** Client-controlled, plaintext and queryable on the server. */
  date: string
  /** Server time of the last write. */
  editedAt: string
  /** Optimistic-concurrency counter: updates/deletes must quote it. */
  version: number
  /** 1 = legacy plaintext type on the server, 2 = blind type tag. */
  format: 1 | 2
}

/** What updates and deletes need from an entry. */
export type EntryRef = Pick<Entry, 'id' | 'version'>

export interface NewEntry<T = unknown> {
  type: string
  data: T
  /** Defaults to now. */
  date?: DateInput
  /** Defaults to a random UUIDv7. Use `app.idFor(key)` for idempotent imports. */
  id?: string
}

export interface EntryUpdate<T = unknown> {
  entry: Pick<Entry, 'id' | 'version' | 'type'>
  data: T
  /** Moves the entry's date; omit to keep it. */
  date?: DateInput
  /** Changes the entry's type; omit to keep it. */
  type?: string
}

export interface ListQuery {
  type?: string | string[]
  /** Inclusive lower bound on `date`. */
  from?: DateInput
  /** Inclusive upper bound on `date`. */
  to?: DateInput
  limit?: number
}

export interface Member {
  userId: string
  username: string
  role: Role
  status: Status
  lastEditAt: string | null
  /**
   * True when the server now reports a different public key than the one
   * pinned in this app's metadata when the member was added. Rotation
   * refuses to seal to such a member: it means a misbehaving server.
   */
  keyMismatch: boolean
}

export interface CacheOptions {
  /** Default true when a cache store is configured. */
  enabled?: boolean
  /** Keep rows whose `date` is within this many days; null = everything. */
  retentionDays?: number | null
  /** Skip a sync if the last one finished less than this long ago. */
  minSyncIntervalMs?: number
}

export interface AppContext {
  api: Api
  session: Session
  store: CacheStore | null
}

interface DirectoryEntry {
  username: string
  publicKeyB64: string
}

/** Reserved metadata keys start with `_`; apps never see them. */
interface SystemMetadata {
  _directory?: Record<string, DirectoryEntry>
  _secret?: string
  /** 2 once every data row uses blind type tags. */
  _format?: 2
}
type RawMetadata = SystemMetadata & Record<string, unknown>

const PAGE_SIZE = 1000
const BATCH_CHUNK = 500
/** Re-read this much before the last watermark: covers transactions that
 *  started before it but committed after (their edited_at is their start). */
const SYNC_OVERLAP_MS = 2 * 60 * 1000
const DAY_MS = 24 * 60 * 60 * 1000

function toIso(d: DateInput): string {
  const date = d instanceof Date ? d : new Date(d)
  if (Number.isNaN(date.getTime())) throw new Error(`invalid date: ${String(d)}`)
  return date.toISOString()
}

function userFields(raw: RawMetadata): Record<string, unknown> {
  return Object.fromEntries(Object.entries(raw).filter(([k]) => !k.startsWith('_')))
}

function systemFields(raw: RawMetadata): SystemMetadata {
  return Object.fromEntries(Object.entries(raw).filter(([k]) => k.startsWith('_'))) as SystemMetadata
}

function isNewer(a: WireRow, b: WireRow | undefined): boolean {
  if (!b) return true
  const ta = Date.parse(a.edited_at)
  const tb = Date.parse(b.edited_at)
  return ta > tb || (ta === tb && a.version >= b.version)
}

/** A one-row batch conflict on a row that no longer exists reads as a 404,
 *  like the single-row REST endpoints. */
async function singleRow<T>(p: Promise<T>): Promise<T> {
  try {
    return await p
  } catch (e) {
    const conflicts = isConflict(e, 'version_conflict') ? e.details?.conflicts : undefined
    if (Array.isArray(conflicts) && conflicts.length === 1 && conflicts[0].current_version === null) {
      throw new SealbaseError(404, 'not found')
    }
    throw e
  }
}

function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = []
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size))
  return out
}

export class AppHandle {
  readonly id: string
  readonly slug: string
  role!: Role
  status!: Status
  metadataVersion!: number
  dekVersion!: number
  lastEditAt!: string | null

  private dek!: Uint8Array
  private raw!: RawMetadata
  private keys: crypto.AppKeys | null = null
  private readonly cacheOpts: Required<CacheOptions>

  // In-memory mirror of the persistent cache (ciphertext rows) + decrypted memo.
  private rows: Map<string, WireRow> | null = null
  private memo = new Map<string, { stamp: string; entry: Entry }>()
  private syncPromise: Promise<void> | null = null
  private lastSyncAt = 0

  /** @internal Use `client.getApp()` / `client.listApps()`. */
  constructor(
    private readonly ctx: AppContext,
    wire: WireApp,
    cacheOpts: Required<CacheOptions>,
  ) {
    this.id = wire.app_id
    this.slug = wire.slug
    this.cacheOpts = cacheOpts
    this.applyWire(wire)
  }

  /** @internal */
  applyWire(w: WireApp): void {
    const { publicKey, privateKey } = this.ctx.session.getVault()
    const rotated = this.dekVersion !== undefined && w.dek_version !== this.dekVersion
    this.dek = crypto.openSealBox(publicKey, privateKey, crypto.b64decode(w.wrapped_dek))
    this.raw = crypto.decryptJson<RawMetadata>(this.dek, crypto.b64decode(w.encrypted_metadata), crypto.AAD.appMetadata(this.id))
    this.role = w.role
    this.status = w.status
    this.metadataVersion = w.metadata_version
    this.dekVersion = w.dek_version
    this.lastEditAt = w.last_edit_at
    this.keys = this.raw._secret ? crypto.deriveAppKeys(crypto.b64decode(this.raw._secret)) : null
    if (rotated) this.dropMemoryCache()
  }

  // --- identity & metadata ------------------------------------------------------

  get name(): string {
    return typeof this.raw.name === 'string' ? this.raw.name : ''
  }

  /** The app's own metadata fields (reserved `_` keys stripped). */
  get metadata(): Record<string, unknown> {
    return userFields(this.raw)
  }

  get canWrite(): boolean {
    return this.role === 'owner' || this.role === 'editor'
  }

  get isOwner(): boolean {
    return this.role === 'owner'
  }

  /** Reloads the app row (metadata, role, key). */
  async refresh(): Promise<this> {
    this.applyWire(await this.ctx.api.getApp(this.id))
    return this
  }

  /**
   * Read-modify-write of the metadata, retried on concurrent edits: `update`
   * receives the latest metadata and returns the new one (or a partial
   * object, merged in).
   */
  async updateMetadata(
    update: Record<string, unknown> | ((current: Record<string, unknown>) => Record<string, unknown>),
  ): Promise<void> {
    await this.mutateRaw((raw) => {
      const next = typeof update === 'function' ? update(userFields(raw)) : { ...userFields(raw), ...update }
      return { ...userFields(next), ...systemFields(raw) }
    })
  }

  rename(name: string): Promise<void> {
    return this.updateMetadata({ name })
  }

  private async mutateRaw(fn: (raw: RawMetadata) => RawMetadata, attempts = 4): Promise<void> {
    for (let i = 0; ; i++) {
      const next = fn(this.raw)
      try {
        const res = await this.ctx.api.patchApp(this.id, {
          encrypted_metadata: crypto.b64encode(crypto.encryptJson(this.dek, next, crypto.AAD.appMetadata(this.id))),
          expected_version: this.metadataVersion,
          dek_version: this.dekVersion,
        })
        this.raw = next
        this.metadataVersion = res.metadata_version
        this.keys = next._secret ? crypto.deriveAppKeys(crypto.b64decode(next._secret)) : null
        return
      } catch (e) {
        if (i + 1 < attempts && (isConflict(e, 'version_conflict') || isConflict(e, 'stale_dek'))) {
          await this.refresh()
          continue
        }
        throw e
      }
    }
  }

  /**
   * Makes sure the app has its per-app secret (needed for blind type tags and
   * `idFor`). Apps created by this lib always do; a legacy app gets one the
   * first time an owner or editor opens it.
   */
  async ensureSecret(): Promise<void> {
    if (this.keys || !this.canWrite) return
    await this.mutateRaw((raw) => (raw._secret ? raw : { ...raw, _secret: crypto.b64encode(crypto.generateAppSecret()) }))
  }

  private requireKeys(): crypto.AppKeys {
    if (!this.keys) throw new Error('this app has no secret yet; call `await app.ensureSecret()` as an owner or editor')
    return this.keys
  }

  /**
   * Deterministic id for a natural key (e.g. a bank transaction id): create
   * with `{ id: app.idFor(key) }` and `onConflict: 'skip'` to import
   * idempotently. Stable across key rotations.
   */
  idFor(naturalKey: string): string {
    return crypto.deterministicId(this.requireKeys(), naturalKey)
  }

  // --- row crypto ------------------------------------------------------------------

  private encryptEntry(id: string, type: string, data: unknown, dek = this.dek) {
    const tag = crypto.typeTag(this.requireKeys(), type)
    const blob = crypto.encryptJson(dek, { t: type, d: data }, crypto.AAD.appDataV2(this.id, id, tag))
    return { type: tag, format: 2 as const, encrypted_json: crypto.b64encode(blob) }
  }

  private decryptRow<T>(row: WireRow, dek = this.dek): Entry<T> {
    const blob = crypto.b64decode(row.encrypted_json)
    let type: string
    let data: T
    if (row.format === 1) {
      type = row.type
      data = crypto.decryptJson<T>(dek, blob, crypto.AAD.appDataV1(this.id, row.id, row.type))
    } else {
      const inner = crypto.decryptJson<{ t: string; d: T }>(dek, blob, crypto.AAD.appDataV2(this.id, row.id, row.type))
      if (this.keys && crypto.typeTag(this.keys, inner.t) !== row.type) {
        throw new Error(`row ${row.id}: type tag does not match its content`)
      }
      type = inner.t
      data = inner.d
    }
    return { id: row.id, type, data, date: row.date, editedAt: row.edited_at, version: row.version, format: row.format }
  }

  private decryptCached<T>(row: WireRow): Entry<T> {
    const stamp = `${this.dekVersion}|${row.version}|${row.edited_at}`
    const hit = this.memo.get(row.id)
    if (hit && hit.stamp === stamp) return hit.entry as Entry<T>
    const entry = this.decryptRow<T>(row)
    this.memo.set(row.id, { stamp, entry })
    return entry
  }

  /** Server-side `type` filter values: blind tags, plus the plaintext while
   *  legacy rows may remain (SPEC.md §4, format 1). */
  private serverTypes(types: string[]): string[] {
    const out: string[] = []
    for (const t of types) {
      if (this.keys) out.push(crypto.typeTag(this.keys, t))
      if (this.raw._format !== 2) out.push(t)
    }
    return out
  }

  // --- writes ----------------------------------------------------------------------

  /** Sends a batch, rebuilding it once with the new key if the app was rotated. */
  private async send(build: () => WireBatch): Promise<WireBatchResult> {
    let result: WireBatchResult
    try {
      result = await this.ctx.api.batch(this.id, build())
    } catch (e) {
      if (!isConflict(e, 'stale_dek')) throw e
      await this.refresh()
      result = await this.ctx.api.batch(this.id, build())
    }
    await this.writeThrough([...result.created, ...result.updated], result.deleted)
    return result
  }

  async create<T>(type: string, data: T, opts: { date?: DateInput; id?: string } = {}): Promise<Entry<T>> {
    const { created } = await this.createMany<T>([{ type, data, ...opts }])
    return created[0]!
  }

  /**
   * Creates many entries, in chunks of 500 (each chunk is atomic). With
   * `onConflict: 'skip'`, ids that already exist in this app are skipped and
   * returned in `skipped` instead of failing.
   */
  async createMany<T>(
    items: NewEntry<T>[],
    opts: { onConflict?: 'error' | 'skip' } = {},
  ): Promise<{ created: Entry<T>[]; skipped: string[] }> {
    const created: Entry<T>[] = []
    const skipped: string[] = []
    for (const part of chunk(items, BATCH_CHUNK)) {
      const prepared = part.map((item) => ({ ...item, id: item.id ?? crypto.randomUuidV7(), date: toIso(item.date ?? new Date()) }))
      const res = await this.send(() => ({
        dek_version: this.dekVersion,
        on_conflict: opts.onConflict ?? 'error',
        create: prepared.map((p) => ({ id: p.id, date: p.date, ...this.encryptEntry(p.id, p.type, p.data) })),
      }))
      const byId = new Map(prepared.map((p) => [p.id, p]))
      for (const row of res.created) {
        const p = byId.get(row.id)!
        created.push({ id: row.id, type: p.type, data: p.data, date: row.date, editedAt: row.edited_at, version: row.version, format: 2 })
      }
      skipped.push(...res.skipped)
    }
    return { created, skipped }
  }

  /**
   * Compare-and-swap update: 409 `version_conflict` if the entry changed
   * meanwhile, 404 if it was deleted.
   */
  async update<T>(entry: Pick<Entry, 'id' | 'version' | 'type'>, data: T, opts: { date?: DateInput; type?: string } = {}): Promise<Entry<T>> {
    const { updated } = await singleRow(this.batch<T>({ update: [{ entry, data, ...opts }] }))
    return updated[0]!
  }

  /** Compare-and-swap delete: 409 if the entry changed meanwhile, 404 if already gone. */
  async delete(entry: EntryRef): Promise<void> {
    await singleRow(this.batch({ delete: [entry] }))
  }

  /** Atomic mix of creates, updates and deletes (at most 1000 operations). */
  async batch<T>(
    ops: { create?: NewEntry<T>[]; update?: EntryUpdate<T>[]; delete?: EntryRef[] },
    opts: { onConflict?: 'error' | 'skip' } = {},
  ): Promise<{ created: Entry<T>[]; skipped: string[]; updated: Entry<T>[]; deleted: string[] }> {
    const creates = (ops.create ?? []).map((c) => ({ ...c, id: c.id ?? crypto.randomUuidV7(), date: toIso(c.date ?? new Date()) }))
    const updates = ops.update ?? []
    const deletes = ops.delete ?? []
    const res = await this.send(() => ({
      dek_version: this.dekVersion,
      on_conflict: opts.onConflict ?? 'error',
      create: creates.map((c) => ({ id: c.id, date: c.date, ...this.encryptEntry(c.id, c.type, c.data) })),
      update: updates.map((u) => ({
        id: u.entry.id,
        expected_version: u.entry.version,
        date: u.date === undefined ? undefined : toIso(u.date),
        ...this.encryptEntry(u.entry.id, u.type ?? u.entry.type, u.data),
      })),
      delete: deletes.map((d) => ({ id: d.id, expected_version: d.version })),
    }))
    const plain = new Map<string, { type: string; data: T }>()
    for (const c of creates) plain.set(c.id, { type: c.type, data: c.data })
    for (const u of updates) plain.set(u.entry.id, { type: u.type ?? u.entry.type, data: u.data })
    const toEntry = (row: WireRow): Entry<T> => {
      const p = plain.get(row.id)!
      return { id: row.id, type: p.type, data: p.data, date: row.date, editedAt: row.edited_at, version: row.version, format: 2 }
    }
    return { created: res.created.map(toEntry), skipped: res.skipped, updated: res.updated.map(toEntry), deleted: res.deleted }
  }

  // --- reads -----------------------------------------------------------------------

  /**
   * All entries matching the query, sorted by (date, id). Served from the
   * cache (after an incremental sync) when the query lies inside the cached
   * window; otherwise fetched from the server, page by page.
   */
  async list<T>(query: ListQuery = {}): Promise<Entry<T>[]> {
    const types = query.type === undefined ? undefined : [query.type].flat()
    const from = query.from === undefined ? undefined : toIso(query.from)
    const to = query.to === undefined ? undefined : toIso(query.to)

    if (this.cacheCovers(from)) {
      await this.sync()
      const fromMs = from ? Date.parse(from) : -Infinity
      const toMs = to ? Date.parse(to) : Infinity
      const typeSet = types ? new Set(types) : null
      // Pre-filter on the stored type so non-matching rows are never
      // decrypted: legacy rows store the plaintext, current ones a blind tag.
      // Without the app secret, tags can't be computed and format 2 rows fall
      // back to decrypt-then-check.
      const keys = this.keys
      const tagSet = typeSet && keys ? new Set(types!.map((t) => crypto.typeTag(keys, t))) : null
      const out: Entry<T>[] = []
      for (const row of this.rows!.values()) {
        const t = Date.parse(row.date)
        if (t < fromMs || t > toMs) continue
        if (typeSet && (row.format === 1 ? !typeSet.has(row.type) : tagSet !== null && !tagSet.has(row.type))) continue
        const entry = this.decryptCached<T>(row)
        if (typeSet && !typeSet.has(entry.type)) continue
        out.push(entry)
      }
      out.sort((a, b) => Date.parse(a.date) - Date.parse(b.date) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
      return query.limit ? out.slice(0, query.limit) : out
    }

    const out: Entry<T>[] = []
    let cursor: string | undefined
    do {
      const page = await this.page<T>({ ...query, cursor })
      out.push(...page.entries)
      cursor = page.nextCursor ?? undefined
    } while (cursor && (!query.limit || out.length < query.limit))
    return query.limit ? out.slice(0, query.limit) : out
  }

  /** One raw page from the server (no cache), for custom pagination. */
  async page<T>(query: ListQuery & { cursor?: string }): Promise<{ entries: Entry<T>[]; nextCursor: string | null }> {
    const types = query.type === undefined ? undefined : [query.type].flat()
    const page = await this.ctx.api.listData(this.id, {
      type: types ? this.serverTypes(types) : undefined,
      date_from: query.from === undefined ? undefined : toIso(query.from),
      date_to: query.to === undefined ? undefined : toIso(query.to),
      limit: Math.min(query.limit ?? PAGE_SIZE, PAGE_SIZE),
      cursor: query.cursor,
    })
    await this.checkDekVersion(page.dek_version)
    const typeSet = types ? new Set(types) : null
    const entries = page.data.map((r) => this.decryptRow<T>(r)).filter((e) => !typeSet || typeSet.has(e.type))
    return { entries, nextCursor: page.next_cursor }
  }

  private async checkDekVersion(serverDekVersion: number): Promise<void> {
    if (serverDekVersion !== this.dekVersion) await this.refresh()
  }

  // --- cache -----------------------------------------------------------------------

  get cacheEnabled(): boolean {
    return this.ctx.store !== null && this.cacheOpts.enabled
  }

  private horizonMs(): number | null {
    const days = this.cacheOpts.retentionDays
    return days === null ? null : Date.now() - days * DAY_MS
  }

  private cacheCovers(from: string | undefined): boolean {
    if (!this.cacheEnabled) return false
    const horizon = this.horizonMs()
    return horizon === null || (from !== undefined && Date.parse(from) >= horizon)
  }

  private dropMemoryCache() {
    this.rows = null
    this.memo.clear()
    this.lastSyncAt = 0
  }

  /**
   * Brings the cache up to date: a full fill of the retention window the
   * first time (or after a key rotation / retention change), then only rows
   * edited and ids deleted since the last sync.
   */
  async sync(opts: { force?: boolean } = {}): Promise<void> {
    if (!this.cacheEnabled) return
    if (this.syncPromise) return this.syncPromise
    if (!opts.force && this.rows && Date.now() - this.lastSyncAt < this.cacheOpts.minSyncIntervalMs) return
    this.syncPromise = this.doSync().finally(() => (this.syncPromise = null))
    return this.syncPromise
  }

  private async doSync(): Promise<void> {
    const store = this.ctx.store!
    const api = this.ctx.api
    const retentionDays = this.cacheOpts.retentionDays

    let meta = await store.getMeta(this.id)
    if (!meta || meta.dekVersion !== this.dekVersion || meta.retentionDays !== retentionDays) {
      await store.clearApp(this.id)
      this.rows = new Map()
      this.memo.clear()
      meta = { appId: this.id, dekVersion: this.dekVersion, retentionDays, watermark: null, deletedWatermark: null }
    } else if (!this.rows) {
      this.rows = new Map((await store.getRows(this.id)).map((r) => [r.id, r]))
    }
    const rows = this.rows!
    const horizon = this.horizonMs()
    const put: WireRow[] = []
    const removed: string[] = []
    let next: CacheMeta

    if (!meta.watermark) {
      let cursor: string | undefined
      let first: string | undefined
      do {
        const page = await api.listData(this.id, {
          order: 'date',
          date_from: horizon === null ? undefined : new Date(horizon).toISOString(),
          limit: PAGE_SIZE,
          cursor,
        })
        if (page.dek_version !== this.dekVersion) return this.restartAfterRotation()
        first ??= page.server_time
        for (const r of page.data) {
          rows.set(r.id, r)
          put.push(r)
        }
        cursor = page.next_cursor ?? undefined
      } while (cursor)
      next = { ...meta, watermark: first!, deletedWatermark: first! }
    } else {
      const since = (w: string) => new Date(Date.parse(w) - SYNC_OVERLAP_MS).toISOString()
      let cursor: string | undefined
      let first: string | undefined
      do {
        const res = await api.listData(this.id, { order: 'edited', edited_from: since(meta.watermark), limit: PAGE_SIZE, cursor })
        if (res.dek_version !== this.dekVersion) return this.restartAfterRotation()
        first ??= res.server_time
        for (const r of res.data) {
          if (horizon !== null && Date.parse(r.date) < horizon) {
            if (rows.delete(r.id)) removed.push(r.id)
          } else if (isNewer(r, rows.get(r.id))) {
            rows.set(r.id, r)
            put.push(r)
          }
        }
        cursor = res.next_cursor ?? undefined
      } while (cursor)

      let dCursor: string | undefined
      let dFirst: string | undefined
      do {
        const res = await api.listDeleted(this.id, { since: since(meta.deletedWatermark ?? meta.watermark), cursor: dCursor })
        dFirst ??= res.server_time
        for (const t of res.deleted) {
          if (rows.delete(t.id)) removed.push(t.id)
        }
        dCursor = res.next_cursor ?? undefined
      } while (dCursor)
      next = { ...meta, watermark: first!, deletedWatermark: dFirst! }
    }

    // The window slides forward: forget rows that fell out of it.
    if (horizon !== null) {
      for (const [id, r] of rows) {
        if (Date.parse(r.date) < horizon) {
          rows.delete(id)
          removed.push(id)
        }
      }
    }
    for (const id of removed) this.memo.delete(id)

    await store.putRows(this.id, put.filter((r) => rows.get(r.id) === r))
    await store.deleteRows(this.id, removed)
    await store.setMeta(next)
    this.lastSyncAt = Date.now()
  }

  private async restartAfterRotation(): Promise<void> {
    await this.refresh() // new DEK + dekVersion; drops the memory cache
    return this.doSync() // sees the dekVersion mismatch and refills
  }

  private async writeThrough(upserts: WireRow[], deletedIds: string[]): Promise<void> {
    if (!this.cacheEnabled || !this.rows) return
    const horizon = this.horizonMs()
    const put: WireRow[] = []
    const removed = [...deletedIds]
    for (const r of upserts) {
      if (horizon !== null && Date.parse(r.date) < horizon) removed.push(r.id)
      else if (isNewer(r, this.rows.get(r.id))) put.push(r)
    }
    for (const r of put) this.rows.set(r.id, r)
    for (const id of removed) {
      this.rows.delete(id)
      this.memo.delete(id)
    }
    try {
      await this.ctx.store!.putRows(this.id, put)
      await this.ctx.store!.deleteRows(this.id, removed)
    } catch {
      // The server write succeeded; a failed cache write only costs a refetch.
      this.dropMemoryCache()
      await this.ctx.store!.clearApp(this.id).catch(() => {})
    }
  }

  /** Forgets this app's cached rows (memory and persistent). */
  async clearCache(): Promise<void> {
    this.dropMemoryCache()
    await this.ctx.store?.clearApp(this.id)
  }

  // --- members & sharing --------------------------------------------------------------

  /** Owner only. */
  async members(): Promise<Member[]> {
    const rows = await this.ctx.api.listMembers(this.id)
    const dir = this.raw._directory ?? {}
    return rows.map((m) => ({
      userId: m.user_id,
      username: m.username,
      role: m.role,
      status: m.status,
      lastEditAt: m.last_edit_at,
      keyMismatch: dir[m.user_id] !== undefined && dir[m.user_id]!.publicKeyB64 !== m.public_key,
    }))
  }

  /**
   * Invites a user (owner only). Their public key is pinned in the app
   * metadata so later rotations seal to the key seen today.
   */
  async share(username: string, role: 'editor' | 'viewer' = 'editor'): Promise<void> {
    const user = await this.ctx.api.userByName(username)
    const wrapped = crypto.sealBox(crypto.b64decode(user.public_key), this.dek)
    await this.mutateRaw((raw) => ({
      ...raw,
      _directory: { ...(raw._directory ?? {}), [user.user_id]: { username, publicKeyB64: user.public_key } },
    }))
    await this.ctx.api.share(this.id, { recipient_user_id: user.user_id, wrapped_dek: crypto.b64encode(wrapped), role })
  }

  /** Switches a member between editor and read-only viewer (owner only). */
  async setRole(userId: string, role: 'editor' | 'viewer'): Promise<void> {
    await this.ctx.api.setRole(this.id, userId, role)
  }

  /**
   * Removes a member's access row without rotating the key: right for
   * cancelling a pending invite, NOT a real revocation (they still hold the
   * DEK). Use `revoke()` for that.
   */
  async removeMember(userId: string): Promise<void> {
    await this.ctx.api.removeMember(this.id, userId)
  }

  /** True revocation: rotates the key, re-sealing it to everyone but `userId`. */
  revoke(userId: string): Promise<void> {
    return this.rotateKey({ exclude: [userId] })
  }

  /**
   * Staged DEK rotation (SPEC.md §3.1), owner only: re-encrypts every row
   * under a new key in chunks, then commits atomically. Concurrent writes
   * keep working; rows they touch are re-staged and the commit retried.
   * Legacy rows are upgraded to blind type tags on the way.
   */
  async rotateKey(opts: { exclude?: string[]; onProgress?: (staged: number) => void | Promise<void> } = {}): Promise<void> {
    if (!this.isOwner) throw new Error('only the owner can rotate the key')
    const exclude = new Set(opts.exclude ?? [])
    const me = this.ctx.session.user!.id
    if (exclude.has(me)) throw new Error('the owner cannot exclude themselves')
    await this.ensureSecret()

    const api = this.ctx.api
    const oldDek = this.dek
    const newDek = crypto.generateKey()
    const reencrypt = (rows: WireRow[]) =>
      rows.map((r) => {
        const e = this.decryptRow(r, oldDek)
        return { id: r.id, expected_version: r.version, ...this.encryptEntry(r.id, e.type, e.data, newDek) }
      })

    const { rotation_id: rotationId, started_at: startedAt } = await api.beginRotation(this.id)
    try {
      let staged = 0
      let cursor: string | undefined
      do {
        const page = await api.listData(this.id, { order: 'date', limit: PAGE_SIZE, cursor })
        if (page.data.length) await api.stageRotation(this.id, rotationId, reencrypt(page.data))
        staged += page.data.length
        await opts.onProgress?.(staged)
        cursor = page.next_cursor ?? undefined
      } while (cursor)

      for (let attempt = 0; attempt < 6; attempt++) {
        const wire = await api.getApp(this.id)
        if (wire.dek_version !== this.dekVersion) throw new Error('the app was rotated concurrently')
        const raw = crypto.decryptJson<RawMetadata>(oldDek, crypto.b64decode(wire.encrypted_metadata), crypto.AAD.appMetadata(this.id))
        const members = (await api.listMembers(this.id)).filter((m) => !exclude.has(m.user_id))
        const access = members.map((m) => {
          const pinned = raw._directory?.[m.user_id]?.publicKeyB64
          if (pinned && pinned !== m.public_key) {
            throw new Error(`the server reports a different public key for ${m.username}; refusing to rotate`)
          }
          return { user_id: m.user_id, wrapped_dek: crypto.b64encode(crypto.sealBox(crypto.b64decode(pinned ?? m.public_key), newDek)) }
        })
        const directory = Object.fromEntries(Object.entries(raw._directory ?? {}).filter(([id]) => !exclude.has(id)))
        const newRaw: RawMetadata = { ...raw, _directory: directory, _format: 2 }
        try {
          const res = await api.commitRotation(this.id, rotationId, {
            encrypted_metadata: crypto.b64encode(crypto.encryptJson(newDek, newRaw, crypto.AAD.appMetadata(this.id))),
            expected_metadata_version: wire.metadata_version,
            access,
          })
          this.dek = newDek
          this.raw = newRaw
          this.dekVersion = res.dek_version
          this.metadataVersion = res.metadata_version
          await this.clearCache()
          return
        } catch (e) {
          if (isConflict(e, 'rotation_incomplete')) {
            // Rows created or edited since staging began: edited_at >= start.
            const since = new Date(Date.parse(startedAt) - SYNC_OVERLAP_MS).toISOString()
            let c: string | undefined
            do {
              const page = await api.listData(this.id, { order: 'edited', edited_from: since, limit: PAGE_SIZE, cursor: c })
              if (page.data.length) await api.stageRotation(this.id, rotationId, reencrypt(page.data))
              c = page.next_cursor ?? undefined
            } while (c)
            continue
          }
          if (isConflict(e, 'version_conflict')) continue
          throw e
        }
      }
      throw new Error('rotation kept conflicting with concurrent writes; try again')
    } catch (e) {
      await api.abortRotation(this.id, rotationId).catch(() => {})
      throw e
    }
  }

  // --- legacy data migration ------------------------------------------------------

  /** True until `migrate()` has run: rows with a plaintext `type` (format 1) may remain. */
  get needsMigration(): boolean {
    return this.raw._format !== 2
  }

  /** How many rows still have a plaintext type on the server. Counts up to `max`. */
  async legacyRowCount(max = PAGE_SIZE): Promise<number> {
    const page = await this.ctx.api.listData(this.id, { format: 1, limit: max })
    return page.data.length
  }

  /**
   * Re-encrypts every legacy row so the server only sees blind type tags,
   * then marks the app as migrated (owner or editor). Safe to interrupt and
   * re-run; concurrent edits are retried. Returns the number of rows migrated.
   */
  async migrate(onProgress?: (migrated: number) => void): Promise<number> {
    if (!this.canWrite) throw new Error('read-only members cannot migrate')
    await this.ensureSecret()
    let migrated = 0
    for (;;) {
      const page = await this.ctx.api.listData(this.id, { format: 1, order: 'date', limit: BATCH_CHUNK })
      await this.checkDekVersion(page.dek_version)
      if (!page.data.length) break
      try {
        await this.send(() => ({
          dek_version: this.dekVersion,
          update: page.data.map((r) => {
            const e = this.decryptRow(r)
            return { id: r.id, expected_version: r.version, ...this.encryptEntry(r.id, e.type, e.data) }
          }),
        }))
        migrated += page.data.length
        onProgress?.(migrated)
      } catch (e) {
        if (!isConflict(e, 'version_conflict')) throw e // re-read the page and retry
      }
    }
    if (this.raw._format !== 2) await this.mutateRaw((raw) => ({ ...raw, _format: 2 }))
    return migrated
  }

  // --- lifecycle --------------------------------------------------------------------

  /** Non-owners: drop your own access. */
  async leave(): Promise<void> {
    await this.ctx.api.leaveApp(this.id)
    await this.clearCache()
  }

  /** Owner only: deletes the app and its data for every member. */
  async deleteApp(): Promise<void> {
    await this.ctx.api.deleteApp(this.id)
    await this.clearCache()
  }
}
