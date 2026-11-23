import { AppHandle, type AppContext, type CacheOptions } from './app.js'
import { IndexedDbCacheStore, MemoryCacheStore, type CacheStore } from './cache.js'
import * as crypto from './crypto.js'
import { Http } from './http.js'
import { Session } from './session.js'
import { defaultStorage, type KeyValueStorage } from './storage.js'
import { Api, type Role } from './wire.js'

export interface SealbaseClientOptions {
  /** Backend origin, e.g. `https://api.example.com`. */
  baseUrl: string
  /** Session persistence; defaults to `localStorage`, else memory. */
  storage?: KeyValueStorage
  /**
   * Row cache. `'indexeddb'` (default where available) persists across
   * reloads, `'memory'` lasts for the page, `false` disables it. Pass a
   * function to supply your own store per user.
   */
  cacheStore?: 'indexeddb' | 'memory' | false | ((userId: string) => CacheStore)
  /** Defaults for every app; override per slug with `apps`. */
  cache?: CacheOptions
  /** Per app-type (slug) settings, e.g. `{ finance: { cache: { retentionDays: 365 } } }`. */
  apps?: Record<string, { cache?: CacheOptions }>
  /** Wipe the user's cache on logout (default true). */
  clearCacheOnLogout?: boolean
  fetch?: typeof fetch
}

export interface PendingShare {
  appId: string
  slug: string
  role: Role
  createdAt: string
}

const DEFAULT_CACHE: Required<CacheOptions> = { enabled: true, retentionDays: 60, minSyncIntervalMs: 2000 }

export class SealbaseClient {
  readonly session: Session
  /** Raw endpoint wrappers, for anything the high-level API doesn't cover. */
  readonly api: Api
  private readonly opts: SealbaseClientOptions
  private store: CacheStore | null = null
  private storeUser: string | null = null
  private readonly handles = new Map<string, AppHandle>()

  constructor(opts: SealbaseClientOptions) {
    this.opts = opts
    this.api = new Api(new Http(opts.baseUrl, opts.fetch))
    this.session = new Session(this.api, opts.storage ?? defaultStorage())
    this.session.onSignOut = async (userId) => {
      this.handles.clear()
      const store = this.store
      this.store = null
      this.storeUser = null
      if (store && userId && this.opts.clearCacheOnLogout !== false) await store.destroy().catch(() => {})
    }
  }

  /** Restores a persisted session (`locked` until `session.unlock()`). */
  init(): Promise<void> {
    return this.session.init()
  }

  private cacheStore(): CacheStore | null {
    const user = this.session.user
    if (!user) return null
    if (this.store && this.storeUser === user.id) return this.store
    const choice = this.opts.cacheStore ?? 'indexeddb'
    if (choice === false) return null
    this.store =
      typeof choice === 'function'
        ? choice(user.id)
        : choice === 'indexeddb' && IndexedDbCacheStore.isAvailable()
          ? new IndexedDbCacheStore(`sealbase-cache:${user.id}`)
          : new MemoryCacheStore()
    this.storeUser = user.id
    return this.store
  }

  private cacheOptionsFor(slug: string): Required<CacheOptions> {
    return { ...DEFAULT_CACHE, ...this.opts.cache, ...this.opts.apps?.[slug]?.cache }
  }

  private context(): AppContext {
    return { api: this.api, session: this.session, store: this.cacheStore() }
  }

  private handleFor(wire: Parameters<AppHandle['applyWire']>[0]): AppHandle {
    const existing = this.handles.get(wire.app_id)
    if (existing) {
      existing.applyWire(wire)
      return existing
    }
    const handle = new AppHandle(this.context(), wire, this.cacheOptionsFor(wire.slug))
    this.handles.set(wire.app_id, handle)
    return handle
  }

  /** Every app the user is an active member of, optionally of one slug. */
  async listApps(slug?: string): Promise<AppHandle[]> {
    const rows = await this.api.listApps(slug)
    return rows.map((w) => this.handleFor(w))
  }

  /** One app, decrypted. Writers also get its per-app secret ensured. */
  async getApp(appId: string): Promise<AppHandle> {
    const handle = this.handleFor(await this.api.getApp(appId))
    await handle.ensureSecret()
    return handle
  }

  /**
   * Creates a new app owned by the caller. `metadata` is the app's own
   * (encrypted) settings; `name` is the conventional display name.
   */
  async createApp(slug: string, metadata: Record<string, unknown> = {}): Promise<AppHandle> {
    const user = this.session.user
    if (!user) throw new Error('not signed in')
    const { publicKey } = this.session.getVault()
    const appId = crypto.randomUuidV7()
    const dek = crypto.generateKey()
    const raw = {
      ...Object.fromEntries(Object.entries(metadata).filter(([k]) => !k.startsWith('_'))),
      _directory: { [user.id]: { username: user.username, publicKeyB64: user.publicKeyB64 } },
      _secret: crypto.b64encode(crypto.generateAppSecret()),
      _format: 2,
    }
    const wire = await this.api.createApp({
      app_id: appId,
      slug,
      encrypted_metadata: crypto.b64encode(crypto.encryptJson(dek, raw, crypto.AAD.appMetadata(appId))),
      wrapped_dek: crypto.b64encode(crypto.sealBox(publicKey, dek)),
    })
    return this.handleFor(wire)
  }

  async pendingShares(): Promise<PendingShare[]> {
    const rows = await this.api.pendingShares()
    return rows.map((r) => ({ appId: r.app_id, slug: r.slug, role: r.role, createdAt: r.created_at }))
  }

  /** Accepts an invite and returns the now-accessible app. */
  async acceptShare(appId: string): Promise<AppHandle> {
    const { wrapped_dek } = await this.api.acceptShare(appId)
    // Fail loudly now if the sealed DEK isn't ours, not on first open.
    const { publicKey, privateKey } = this.session.getVault()
    crypto.openSealBox(publicKey, privateKey, crypto.b64decode(wrapped_dek))
    return this.getApp(appId)
  }

  declineShare(appId: string): Promise<void> {
    return this.api.declineShare(appId)
  }
}

export function createClient(opts: SealbaseClientOptions): SealbaseClient {
  return new SealbaseClient(opts)
}
