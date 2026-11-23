// All content cryptography (SPEC.md §2/§3) lives here and only here. The
// server never sees any of these keys; it only stores and serves the outputs.
//
// Primitives (must match SPEC.md §2 for interop with any libsodium client):
//   - Argon2id (crypto_pwhash, ALG_ARGON2ID13) for passphrase stretching
//   - XChaCha20-Poly1305 (crypto_aead_xchacha20poly1305_ietf), wire format
//     `nonce(24B) || ciphertext || tag`
//   - X25519 sealed boxes (crypto_box_seal) for wrapping a DEK to a user
//   - BLAKE2b (crypto_generichash) keyed with a per-app secret for blind type
//     tags and deterministic ids, subkeys via crypto_kdf_derive_from_key
import sodium from 'libsodium-wrappers-sumo'

let readyPromise: Promise<void> | null = null

export function ready(): Promise<void> {
  if (!readyPromise) readyPromise = sodium.ready
  return readyPromise
}

const encoder = new TextEncoder()
const decoder = new TextDecoder()

// --- base64 ------------------------------------------------------------------
// Standard padded base64 matches the server's wire format (api::bytes::B64).

export function b64encode(bytes: Uint8Array): string {
  return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL)
}

export function b64decode(str: string): Uint8Array {
  return sodium.from_base64(str, sodium.base64_variants.ORIGINAL)
}

function b64url(bytes: Uint8Array): string {
  return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING)
}

// --- AAD -----------------------------------------------------------------------
// Authenticated but never stored (SPEC.md §2.1): recomputed at decrypt time
// from the row's identity. UUIDs, legacy types and base64url tags never
// contain ':' so joining on it is unambiguous.

function aad(parts: string[]): Uint8Array {
  return encoder.encode(parts.join(':'))
}

export const AAD = {
  appMetadata: (appId: string) => aad([appId, 'metadata']),
  /** Format 1 (legacy): the plaintext type is the column value. */
  appDataV1: (appId: string, dataId: string, type: string) => aad([appId, dataId, type]),
  /** Format 2: the column holds a blind tag; the real type is inside. */
  appDataV2: (appId: string, dataId: string, tag: string) => aad([appId, dataId, 'v2', tag]),
  // Bound to username rather than user_id: the id is only assigned once
  // /auth/register returns, after these blobs must already exist.
  umk: (username: string) => aad([username, 'umk']),
  privkey: (username: string) => aad([username, 'privkey']),
}

// --- KDF (client-side passphrase stretching, SPEC.md §3/§7) ---------------------

export interface KdfParams {
  algorithm: string
  mem_cost_kib: number
  time_cost: number
  parallelism: number
  version?: number
}

/** The framework's fixed parameters (mirror of src/crypto.rs). */
export const DEFAULT_KDF_PARAMS: KdfParams = { algorithm: 'argon2id', mem_cost_kib: 19456, time_cost: 2, parallelism: 1 }

// Hard floor: refuse to derive with weaker params, even if a (possibly
// malicious) server advertises less.
const MIN_MEM_COST_KIB = 19_456
const MIN_TIME_COST = 2

function assertParamsSafe(params: KdfParams): void {
  if (params.algorithm !== 'argon2id') throw new Error(`unsupported KDF algorithm: ${params.algorithm}`)
  if (params.mem_cost_kib < MIN_MEM_COST_KIB || params.time_cost < MIN_TIME_COST) {
    throw new Error('server-advertised KDF params are below the safe floor; refusing to derive')
  }
  // libsodium's Argon2id only supports parallelism = 1.
  if (params.parallelism !== 1) throw new Error(`unsupported KDF parallelism: ${params.parallelism}`)
}

/** First/second half of the 64-byte Argon2id output (SPEC.md §3). */
export async function derivePassphraseKeys(
  passphrase: string,
  kdfSaltB64: string,
  params: KdfParams,
): Promise<{ authKey: Uint8Array; kek: Uint8Array }> {
  await ready()
  assertParamsSafe(params)
  const out = sodium.crypto_pwhash(
    64,
    passphrase,
    b64decode(kdfSaltB64),
    params.time_cost,
    params.mem_cost_kib * 1024,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  )
  return { authKey: out.slice(0, 32), kek: out.slice(32, 64) }
}

export function generateSalt(): Uint8Array {
  return sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES)
}

// --- symmetric encryption (XChaCha20-Poly1305) ------------------------------------

export function generateKey(): Uint8Array {
  return sodium.crypto_aead_xchacha20poly1305_ietf_keygen()
}

export function encryptBytes(key: Uint8Array, plaintext: Uint8Array, aadBytes: Uint8Array): Uint8Array {
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
  const sealed = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aadBytes, null, nonce, key)
  const out = new Uint8Array(nonce.length + sealed.length)
  out.set(nonce, 0)
  out.set(sealed, nonce.length)
  return out
}

export function decryptBytes(key: Uint8Array, blob: Uint8Array, aadBytes: Uint8Array): Uint8Array {
  const n = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, blob.slice(n), aadBytes, blob.slice(0, n), key)
}

export function encryptJson(key: Uint8Array, value: unknown, aadBytes: Uint8Array): Uint8Array {
  return encryptBytes(key, encoder.encode(JSON.stringify(value)), aadBytes)
}

export function decryptJson<T = unknown>(key: Uint8Array, blob: Uint8Array, aadBytes: Uint8Array): T {
  return JSON.parse(decoder.decode(decryptBytes(key, blob, aadBytes))) as T
}

// --- asymmetric (X25519 + sealed boxes) ----------------------------------------------

export function generateKeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const kp = sodium.crypto_box_keypair()
  return { publicKey: kp.publicKey, privateKey: kp.privateKey }
}

export function sealBox(recipientPublicKey: Uint8Array, message: Uint8Array): Uint8Array {
  return sodium.crypto_box_seal(message, recipientPublicKey)
}

export function openSealBox(publicKey: Uint8Array, privateKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return sodium.crypto_box_seal_open(ciphertext, publicKey, privateKey)
}

// --- per-app secret: blind type tags + deterministic ids -----------------------------
// Each app's metadata carries a random 32-byte `_secret`, stable across DEK
// rotations (so deterministic ids stay stable). Two subkeys derive from it.

const KDF_CONTEXT = 'sealbase' // crypto_kdf contexts are exactly 8 bytes
const SUBKEY_TYPE_TAG = 1
const SUBKEY_ID = 2

export function generateAppSecret(): Uint8Array {
  return sodium.randombytes_buf(32)
}

export interface AppKeys {
  typeKey: Uint8Array
  idKey: Uint8Array
}

export function deriveAppKeys(secret: Uint8Array): AppKeys {
  return {
    typeKey: sodium.crypto_kdf_derive_from_key(32, SUBKEY_TYPE_TAG, KDF_CONTEXT, secret),
    idKey: sodium.crypto_kdf_derive_from_key(32, SUBKEY_ID, KDF_CONTEXT, secret),
  }
}

/**
 * Blind index for a type: what the server stores and filters on instead of
 * the plaintext. Deterministic (so `?type=` still works) and opaque without
 * the app secret. 128 bits, base64url: 22 characters.
 */
export function typeTag(keys: AppKeys, type: string): string {
  return b64url(sodium.crypto_generichash(16, encoder.encode(type), keys.typeKey))
}

function formatUuid(bytes: Uint8Array): string {
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

/**
 * Deterministic UUIDv8 for a natural key (e.g. a bank transaction id), so
 * re-importing the same item maps to the same row and dedupes server-side.
 * Keyed: the server cannot guess or confirm ids from natural keys.
 */
export function deterministicId(keys: AppKeys, naturalKey: string): string {
  const h = sodium.crypto_generichash(16, encoder.encode(naturalKey), keys.idKey)
  h[6] = (h[6]! & 0x0f) | 0x80
  h[8] = (h[8]! & 0x3f) | 0x80
  return formatUuid(h)
}

/** UUIDv7: 48-bit ms timestamp + random tail, so ids stay time-ordered. */
export function randomUuidV7(): string {
  const bytes = sodium.randombytes_buf(16)
  const ts = BigInt(Date.now())
  for (let i = 0; i < 6; i++) bytes[i] = Number((ts >> BigInt(8 * (5 - i))) & 0xffn)
  bytes[6] = (bytes[6]! & 0x0f) | 0x70
  bytes[8] = (bytes[8]! & 0x3f) | 0x80
  return formatUuid(bytes)
}
