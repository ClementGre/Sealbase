// Seeds a v0.2 server with data exactly as the old
// example frontend wrote it: plaintext `type`, AAD `app_id:data_id:type`,
// `data_id`/`created_at` wire fields, role 'member'. Used to check that a
// database upgraded by migration 0002 stays readable and migratable.
//
//   BASE_URL=http://127.0.0.1:8090 node test/legacy-seed.mjs
import sodium from 'libsodium-wrappers-sumo'

const BASE = process.env.BASE_URL ?? 'http://127.0.0.1:8090'
const PARAMS = { mem_cost_kib: 19456, time_cost: 2 }
const enc = new TextEncoder()
const b64 = (u) => sodium.to_base64(u, sodium.base64_variants.ORIGINAL)
const unb64 = (s) => sodium.from_base64(s, sodium.base64_variants.ORIGINAL)
const aad = (...parts) => enc.encode(parts.join(':'))

async function call(method, path, body, token) {
  const res = await fetch(BASE + path, {
    method,
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await res.text()
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status} ${text}`)
  return text ? JSON.parse(text) : undefined
}

function seal(key, bytes, ad) {
  const nonce = sodium.randombytes_buf(24)
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(bytes, ad, null, nonce, key)
  const out = new Uint8Array(24 + ct.length)
  out.set(nonce)
  out.set(ct, 24)
  return out
}

function derive(pass, salt) {
  const out = sodium.crypto_pwhash(64, pass, salt, PARAMS.time_cost, PARAMS.mem_cost_kib * 1024, sodium.crypto_pwhash_ALG_ARGON2ID13)
  return { authKey: out.slice(0, 32), kek: out.slice(32) }
}

function uuidv7() {
  const b = sodium.randombytes_buf(16)
  const ts = BigInt(Date.now())
  for (let i = 0; i < 6; i++) b[i] = Number((ts >> BigInt(8 * (5 - i))) & 0xffn)
  b[6] = (b[6] & 0x0f) | 0x70
  b[8] = (b[8] & 0x3f) | 0x80
  const h = [...b].map((x) => x.toString(16).padStart(2, '0')).join('')
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`
}

async function registerAndLogin(username, pass) {
  const salt = sodium.randombytes_buf(16)
  const { authKey, kek } = derive(pass, salt)
  const umk = sodium.crypto_aead_xchacha20poly1305_ietf_keygen()
  const kp = sodium.crypto_box_keypair()
  await call('POST', '/auth/register', {
    username,
    auth_key: b64(authKey),
    kdf_salt: b64(salt),
    wrapped_umk: b64(seal(kek, umk, aad(username, 'umk'))),
    public_key: b64(kp.publicKey),
    wrapped_privkey: b64(seal(umk, kp.privateKey, aad(username, 'privkey'))),
  })
  const login = await call('POST', '/auth/login', { username, auth_key: b64(authKey) })
  const me = await call('GET', '/users/me', undefined, login.access_token)
  return { token: login.access_token, id: me.user_id, publicKey: kp.publicKey }
}

await sodium.ready
const stamp = Date.now().toString(36)
const alice = await registerAndLogin(`alice_${stamp}`, 'alice passphrase')
const bob = await registerAndLogin(`bob_${stamp}`, 'bob passphrase')

const appId = uuidv7()
const dek = sodium.crypto_aead_xchacha20poly1305_ietf_keygen()
const metadata = {
  name: 'Legacy readings',
  _directory: {
    [alice.id]: { username: `alice_${stamp}`, publicKeyB64: b64(alice.publicKey) },
    [bob.id]: { username: `bob_${stamp}`, publicKeyB64: b64(bob.publicKey) },
  },
}
await call(
  'POST',
  '/apps',
  {
    app_id: appId,
    slug: 'demo',
    encrypted_metadata: b64(seal(dek, enc.encode(JSON.stringify(metadata)), aad(appId, 'metadata'))),
    wrapped_dek: b64(sodium.crypto_box_seal(dek, alice.publicKey)),
  },
  alice.token,
)

const rows = [
  ...[1, 2, 3, 4, 5].map((v, i) => ({ type: 'reading', json: { value: v * 10, label: `r${v}` }, daysAgo: i })),
  { type: 'note', json: { text: 'first note' }, daysAgo: 1 },
  { type: 'note', json: { text: 'old note' }, daysAgo: 400 },
]
for (const r of rows) {
  const dataId = uuidv7()
  await call(
    'POST',
    `/apps/${appId}/data`,
    {
      data_id: dataId,
      type: r.type,
      encrypted_json: b64(seal(dek, enc.encode(JSON.stringify(r.json)), aad(appId, dataId, r.type))),
      created_at: new Date(Date.now() - r.daysAgo * 86400_000).toISOString(),
    },
    alice.token,
  )
}

await call('POST', `/apps/${appId}/shares`, { recipient_user_id: bob.id, wrapped_dek: b64(sodium.crypto_box_seal(dek, bob.publicKey)) }, alice.token)
await call('POST', `/apps/${appId}/shares/accept`, undefined, bob.token)

console.log(JSON.stringify({ appId, alice: `alice_${stamp}`, bob: `bob_${stamp}`, rows: rows.length }))
