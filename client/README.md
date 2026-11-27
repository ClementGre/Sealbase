# sealbase-client

TypeScript client for a [Sealbase](../README.md) backend: zero-knowledge
auth, encrypted per-app storage, sharing with read-only members, key
rotation, and a local cache with incremental sync. Works in browsers and
Node ≥ 20.

All cryptography happens here (libsodium): the server only ever sees
ciphertext, wrapped keys and blind tags. You work with plaintext objects.

```sh
npm install sealbase-client
```

## Quick start

```js
import { createClient } from 'sealbase-client'

const client = createClient({
  baseUrl: 'https://api.example.com',
  // Optional per app type (slug) settings:
  apps: { finance: { cache: { retentionDays: 365 } } },
})
await client.init() // restores a saved session as 'locked'

client.session.subscribe(({ status, user }) => {
  // status: 'signed-out' | 'locked' | 'unlocked'
})

await client.session.register('alice', passphrase) // once
await client.session.login('alice', passphrase)
// After a reload: await client.session.unlock(passphrase)

const app = await client.createApp('finance', { name: 'Household' })
```

There is **no passphrase recovery**: tell your users.

## Calling your own backend

If your app has its own API next to Sealbase, authenticate requests with the
user's Sealbase access token as a Bearer token:

```js
async function callApi(path, init = {}) {
  const send = (token) =>
    fetch(path, { ...init, headers: { ...init.headers, authorization: `Bearer ${token}` } })

  let token = await client.session.getAccessToken()
  if (!token) throw new Error('signed out')
  let res = await send(token)
  if (res.status === 401) {
    token = await client.session.getAccessToken({ refresh: true })
    if (token) res = await send(token)
  }
  return res
}
```

`getAccessToken()` returns the current token, or `null` when signed out. It
works while the session is `locked` (the token is saved, the keys are not), so
it carries no access to encrypted data. Access tokens are short-lived: on a
401, `getAccessToken({ refresh: true })` rotates the refresh token and returns
a new access token. Concurrent refreshes, yours and the client's own, share one
request. If the refresh fails, the session signs out and you get `null`.

The token is a credential: send it only over HTTPS, and never log it or put it
in a URL.

## Data

Each app holds entries: `{ id, type, data, date, editedAt, version }`.
`type` is your own label (encrypted; the server sees an opaque tag), `data`
any JSON value, `date` a client-controlled, queryable timestamp.

```js
const e = await app.create('txn', { amount: -42, label: 'Groceries' }, { date: '2026-11-20' })

await app.list({ type: 'txn', from: '2026-11-01', to: '2026-11-30' }) // sorted by (date, id)

const e2 = await app.update(e, { ...e.data, label: 'Food' }) // compare-and-swap on e.version
const e3 = await app.update(e2, e2.data, { date: '2026-11-21' }) // move it
await app.delete(e3)

// Atomic mix, up to 1000 operations:
await app.batch({ create: [...], update: [{ entry, data }], delete: [entry] })
```

Updates and deletes fail with a 409 `version_conflict` if someone changed the
entry since you read it (and 404 if it's gone): re-read and retry. Nothing is
ever silently overwritten.

### Idempotent imports

`app.idFor(naturalKey)` gives a deterministic id, stable across key rotations
and unguessable by the server. Combined with `onConflict: 'skip'`, re-imports
dedupe:

```js
const { created, skipped } = await app.createMany(
  bankTxns.map((t) => ({ id: app.idFor(`bank:${t.id}`), type: 'txn', data: t, date: t.bookedAt })),
  { onConflict: 'skip' },
)
```

`createMany` sends chunks of 500; each chunk is atomic.

## Metadata

```js
app.name            // conventional display name
app.metadata        // your own fields (keys starting with `_` are reserved)
await app.rename('Family budget')
await app.updateMetadata((m) => ({ ...m, currency: 'EUR' })) // retried on concurrent edits
```

## Cache

Rows are cached per app (IndexedDB in browsers, memory elsewhere) **as
ciphertext**, so the device cache is as opaque as the server. `list()` serves
queries whose `from` lies inside the retention window from the cache, after
an incremental sync (rows edited and ids deleted since last time); anything
older goes to the server.

```js
createClient({
  baseUrl,
  cache: { retentionDays: 60, minSyncIntervalMs: 2000 }, // defaults
  apps: { finance: { cache: { retentionDays: null } } },   // null = keep everything
  cacheStore: 'indexeddb', // or 'memory', false, or (userId) => yourStore
})

await app.sync({ force: true })
await app.clearCache()
```

A key rotation or a retention change refills the cache. Signing out deletes
the user's cache (`clearCacheOnLogout: false` to keep it).

## Sharing

```js
await app.share('bob', 'viewer')   // or 'editor' (default); owner only
await app.setRole(bobId, 'editor')
await app.members()                // [{ userId, username, role, status, keyMismatch }]
await app.revoke(bobId)            // rotates the key, re-sealed to everyone else
await app.removeMember(userId)     // cancel a pending invite (no key change)

await client.pendingShares()
const shared = await client.acceptShare(appId)
shared.canWrite // false for viewers; the server rejects their writes
```

Members' public keys are pinned when you share. `keyMismatch: true` means the
server now reports a different key, and rotation refuses to proceed.

## Key rotation

```js
await app.rotateKey({ exclude: [userId], onProgress: (n) => console.log(n) })
```

Staged: rows are re-encrypted and uploaded in chunks while the app stays
writable; one atomic commit swaps everything. Writes that land meanwhile are
re-staged automatically. Other members' handles pick up the new key on their
next read or write.

## Upgrading apps created before Sealbase v0.3

Old apps work as they are. To hide their row types from the server:

```js
if (app.needsMigration && app.canWrite) await app.migrate((n) => console.log(n))
```

Safe to interrupt and run again.

## Errors

Every server error is a `SealbaseError` with `status`, and for 409s a `code`
(`version_conflict`, `stale_dek`, `duplicate_id`, ...) and `details`.
`isConflict(err, code?)` is a shorthand. `status: 0` means the network
failed.

## Lower level

`client.api` exposes every endpoint with wire field names, for anything the
high-level API doesn't cover. See [doc/SPEC.md](../doc/SPEC.md).

## Development

```sh
npm run build                         # tsc → dist/
BASE_URL=http://127.0.0.1:8080 npm test   # end-to-end against a running server
```

The server's login rate limit must allow a few dozen logins per minute for the
tests (`LOGIN_RATE_LIMIT_MAX_ATTEMPTS`). `test/legacy-seed.mjs` writes data the
way a v0.2 server and client did, for upgrade tests (see its header).
