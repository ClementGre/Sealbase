// Session/auth (SPEC.md §3 key hierarchy + §5 Auth/Users). The one place
// allowed to hold key material: kek, UMK and the X25519 private key live in
// memory only. Persisted: bearer tokens and the already-wrapped key blobs the
// server holds anyway, so a reload needs the passphrase again ("locked") but
// no network round trip to unlock.
import * as crypto from './crypto.js'
import type { KeyValueStorage } from './storage.js'
import type { Api } from './wire.js'

export type SessionStatus = 'signed-out' | 'locked' | 'unlocked'

export interface SessionUser {
  id: string
  username: string
  publicKeyB64: string
}

export interface SessionState {
  status: SessionStatus
  user: SessionUser | null
}

export interface Vault {
  kek: Uint8Array
  umk: Uint8Array
  privateKey: Uint8Array
  publicKey: Uint8Array
}

interface Persisted {
  accessToken: string
  refreshToken: string
  userId: string
  username: string
  publicKey: string
  kdfSalt: string
  kdfParams: crypto.KdfParams
  wrappedUmk: string
  wrappedPrivkey: string
}

const STORAGE_KEY = 'sealbase.session.v1'

export class Session {
  private state: SessionState = { status: 'signed-out', user: null }
  private listeners = new Set<(s: SessionState) => void>()
  private vault: Vault | null = null
  private persisted: Persisted | null = null
  private refreshInFlight: Promise<string | null> | null = null
  /** Called on sign-out so dependents (e.g. the cache) can wipe. */
  onSignOut: (userId: string | null) => Promise<void> | void = () => {}

  constructor(
    private readonly api: Api,
    private readonly storage: KeyValueStorage,
  ) {
    api.http.setAuth({
      getAccessToken: () => this.persisted?.accessToken ?? null,
      refresh: () => {
        if (!this.persisted?.refreshToken) return Promise.resolve(null)
        if (!this.refreshInFlight) this.refreshInFlight = this.doRefresh().finally(() => (this.refreshInFlight = null))
        return this.refreshInFlight
      },
    })
  }

  get current(): Readonly<SessionState> {
    return this.state
  }

  get user(): SessionUser | null {
    return this.state.user
  }

  /** Subscribe to state changes; returns an unsubscribe function. Fires immediately. */
  subscribe(listener: (s: SessionState) => void): () => void {
    this.listeners.add(listener)
    listener(this.state)
    return () => this.listeners.delete(listener)
  }

  private set(next: SessionState) {
    this.state = next
    for (const l of this.listeners) l(next)
  }

  /** Restores a persisted session as `locked` (or `signed-out` if none). */
  async init(): Promise<void> {
    await crypto.ready()
    const raw = this.storage.getItem(STORAGE_KEY)
    if (!raw) return this.set({ status: 'signed-out', user: null })
    const p = JSON.parse(raw) as Persisted
    this.persisted = p
    this.set({ status: 'locked', user: { id: p.userId, username: p.username, publicKeyB64: p.publicKey } })
  }

  private save(p: Persisted | null) {
    this.persisted = p
    if (p) this.storage.setItem(STORAGE_KEY, JSON.stringify(p))
    else this.storage.removeItem(STORAGE_KEY)
  }

  private async doRefresh(): Promise<string | null> {
    try {
      const res = await this.api.refresh(this.persisted!.refreshToken)
      this.save({ ...this.persisted!, accessToken: res.access_token, refreshToken: res.refresh_token })
      return res.access_token
    } catch {
      await this.signOutLocal()
      return null
    }
  }

  private async signOutLocal() {
    const userId = this.state.user?.id ?? null
    this.vault = null
    this.save(null)
    this.set({ status: 'signed-out', user: null })
    await this.onSignOut(userId)
  }

  async register(username: string, passphrase: string): Promise<void> {
    await crypto.ready()
    const kdfSalt = crypto.b64encode(crypto.generateSalt())
    const { authKey, kek } = await crypto.derivePassphraseKeys(passphrase, kdfSalt, crypto.DEFAULT_KDF_PARAMS)
    const umk = crypto.generateKey()
    const keyPair = crypto.generateKeyPair()
    await this.api.register({
      username,
      auth_key: crypto.b64encode(authKey),
      kdf_salt: kdfSalt,
      wrapped_umk: crypto.b64encode(crypto.encryptBytes(kek, umk, crypto.AAD.umk(username))),
      public_key: crypto.b64encode(keyPair.publicKey),
      wrapped_privkey: crypto.b64encode(crypto.encryptBytes(umk, keyPair.privateKey, crypto.AAD.privkey(username))),
    })
  }

  async login(username: string, passphrase: string): Promise<void> {
    await crypto.ready()
    const lookup = await this.api.userByName(username)
    const { authKey, kek } = await crypto.derivePassphraseKeys(passphrase, lookup.kdf_salt, lookup.kdf_params)
    const res = await this.api.login({ username, auth_key: crypto.b64encode(authKey) })

    const umk = crypto.decryptBytes(kek, crypto.b64decode(res.wrapped_umk), crypto.AAD.umk(username))
    const privateKey = crypto.decryptBytes(umk, crypto.b64decode(res.wrapped_privkey), crypto.AAD.privkey(username))
    this.vault = { kek, umk, privateKey, publicKey: crypto.b64decode(res.public_key) }

    // Persist tokens first so /users/me is authenticated.
    this.save({
      accessToken: res.access_token,
      refreshToken: res.refresh_token,
      userId: '',
      username,
      publicKey: res.public_key,
      kdfSalt: res.kdf_salt,
      kdfParams: res.kdf_params,
      wrappedUmk: res.wrapped_umk,
      wrappedPrivkey: res.wrapped_privkey,
    })
    const me = await this.api.me()
    this.save({ ...this.persisted!, userId: me.user_id, username: me.username })
    this.set({ status: 'unlocked', user: { id: me.user_id, username: me.username, publicKeyB64: res.public_key } })
  }

  /** Re-derives the vault from the persisted wrapped blobs after a reload. */
  async unlock(passphrase: string): Promise<void> {
    const p = this.persisted
    if (!p) throw new Error('no session to unlock')
    const { kek } = await crypto.derivePassphraseKeys(passphrase, p.kdfSalt, p.kdfParams)
    let umk: Uint8Array
    try {
      umk = crypto.decryptBytes(kek, crypto.b64decode(p.wrappedUmk), crypto.AAD.umk(p.username))
    } catch {
      throw new Error('wrong passphrase')
    }
    const privateKey = crypto.decryptBytes(umk, crypto.b64decode(p.wrappedPrivkey), crypto.AAD.privkey(p.username))
    this.vault = { kek, umk, privateKey, publicKey: crypto.b64decode(p.publicKey) }
    this.set({ status: 'unlocked', user: this.state.user })
  }

  /** Drops keys from memory but keeps the session (passphrase needed again). */
  lock(): void {
    if (this.state.status !== 'unlocked') return
    this.vault = null
    this.set({ status: 'locked', user: this.state.user })
  }

  async logout(): Promise<void> {
    try {
      if (this.persisted?.refreshToken) await this.api.logout(this.persisted.refreshToken)
    } catch {
      // best effort; sign out locally regardless
    }
    await this.signOutLocal()
  }

  async changePassphrase(currentPassphrase: string, newPassphrase: string): Promise<void> {
    const p = this.persisted
    if (!this.vault || !p) throw new Error('not unlocked')
    const current = await crypto.derivePassphraseKeys(currentPassphrase, p.kdfSalt, p.kdfParams)
    const newSalt = crypto.b64encode(crypto.generateSalt())
    const next = await crypto.derivePassphraseKeys(newPassphrase, newSalt, p.kdfParams)
    const newWrappedUmk = crypto.b64encode(crypto.encryptBytes(next.kek, this.vault.umk, crypto.AAD.umk(p.username)))
    await this.api.changePassphrase({
      current_auth_key: crypto.b64encode(current.authKey),
      new_auth_key: crypto.b64encode(next.authKey),
      new_kdf_salt: newSalt,
      new_wrapped_umk: newWrappedUmk,
    })
    this.vault.kek = next.kek
    // Other sessions are revoked server-side; this one stays valid.
    this.save({ ...p, kdfSalt: newSalt, wrappedUmk: newWrappedUmk })
  }

  /** Deletes the account and every app it owns, for every member. */
  async deleteAccount(currentPassphrase: string): Promise<void> {
    const p = this.persisted
    if (!p) throw new Error('not signed in')
    const { authKey } = await crypto.derivePassphraseKeys(currentPassphrase, p.kdfSalt, p.kdfParams)
    await this.api.deleteMe(crypto.b64encode(authKey))
    await this.signOutLocal()
  }

  /** @internal */
  getVault(): Vault {
    if (!this.vault) throw new Error('vault is locked; call unlock() first')
    return this.vault
  }
}
