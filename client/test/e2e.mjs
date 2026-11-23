// End-to-end checks of the lib against a running Sealbase server.
//
//   BASE_URL=http://127.0.0.1:8080 node test/e2e.mjs
//   LEGACY='{"appId":...,"alice":...,"bob":...}' ...   (output of legacy-seed.mjs,
//      run against the old server before upgrading) also checks migration.
//
// The server's login rate limit must allow a few dozen logins per minute.
import assert from 'node:assert/strict'
import { createClient, isConflict, MemoryStorage, SealbaseError } from '../dist/index.js'

const BASE = process.env.BASE_URL ?? 'http://127.0.0.1:8080'
const DAY = 86400_000
const stamp = Date.now().toString(36)
let failures = 0

async function step(name, fn) {
  try {
    await fn()
    console.log(`  ✓ ${name}`)
  } catch (e) {
    failures++
    console.log(`  ✗ ${name}\n    ${e.stack ?? e}`)
  }
}

function client(opts = {}) {
  return createClient({ baseUrl: BASE, storage: new MemoryStorage(), cacheStore: 'memory', ...opts })
}

async function user(name, opts) {
  const c = client(opts)
  await c.init()
  const username = `${name}_${stamp}`
  await c.session.register(username, `${name} passphrase`)
  await c.session.login(username, `${name} passphrase`)
  return { c, username, id: c.session.user.id }
}

async function login(username, passphrase, opts) {
  const c = client(opts)
  await c.init()
  await c.session.login(username, passphrase)
  return c
}

async function expectStatus(promise, status, code) {
  try {
    await promise
  } catch (e) {
    assert.ok(e instanceof SealbaseError, `expected SealbaseError, got ${e}`)
    assert.equal(e.status, status, `expected ${status}, got ${e.status} ${e.message}`)
    if (code) assert.equal(e.code, code)
    return e
  }
  assert.fail(`expected HTTP ${status}${code ? ` ${code}` : ''}, but it succeeded`)
}

// --- legacy database upgraded in place ---------------------------------------------
if (process.env.LEGACY) {
  const seed = JSON.parse(process.env.LEGACY)
  console.log('legacy data (written by the v0.2 server)')
  const alice = await login(seed.alice, 'alice passphrase')
  const bob = await login(seed.bob, 'bob passphrase')

  await step('session still unlocks and the legacy app is listed', async () => {
    const apps = await alice.listApps('demo')
    const app = apps.find((a) => a.id === seed.appId)
    assert.ok(app, 'legacy app missing')
    assert.equal(app.name, 'Legacy readings')
    assert.equal(app.needsMigration, true)
  })

  await step("'member' became 'editor'", async () => {
    const app = await bob.getApp(seed.appId)
    assert.equal(app.role, 'editor')
  })

  await step('legacy rows decrypt; type and date filters work before migration', async () => {
    const app = await alice.getApp(seed.appId)
    const readings = await app.list({ type: 'reading' })
    assert.equal(readings.length, 5)
    assert.ok(readings.every((e) => e.format === 1 && e.type === 'reading' && typeof e.data.value === 'number'))
    const notes = await app.list({ type: 'note', from: new Date(Date.now() - 30 * DAY) })
    assert.equal(notes.length, 1, 'cached window should hold the recent note only')
    assert.equal((await app.list({ type: 'note' })).length, 2)
  })

  await step('new rows written before migration are found alongside legacy ones', async () => {
    const app = await bob.getApp(seed.appId)
    await app.create('reading', { value: 99 })
    const readings = await app.list({ type: 'reading' })
    assert.equal(readings.length, 6)
    assert.equal(readings.filter((e) => e.format === 2).length, 1)
  })

  await step('migrate() hides every plaintext type from the server', async () => {
    const app = await alice.getApp(seed.appId)
    assert.equal(await app.legacyRowCount(), 7)
    const migrated = await app.migrate()
    assert.equal(migrated, 7)
    assert.equal(await app.legacyRowCount(), 0)
    assert.equal(app.needsMigration, false)
    const raw = await alice.api.listData(seed.appId, { limit: 100 })
    assert.ok(raw.data.every((r) => r.format === 2 && r.type !== 'reading' && r.type !== 'note'))
    assert.equal((await app.list({ type: 'reading' })).length, 6)
    assert.equal((await app.list({ type: 'note' })).length, 2)
  })

  await step('the other member sees migrated data (with only tag queries now)', async () => {
    const app = await bob.getApp(seed.appId)
    assert.equal(app.needsMigration, false)
    assert.equal((await app.list({ type: 'note' })).length, 2)
  })
}

// --- fresh apps ------------------------------------------------------------------------
console.log('fresh apps')
const carol = await user('carol')
const dave = await user('dave')
const erin = await user('erin')
const frank = await user('frank')
let app

await step('create app, rename it, metadata keeps reserved keys hidden', async () => {
  app = await carol.c.createApp('demo', { name: 'Readings', unit: 'kg' })
  assert.equal(app.role, 'owner')
  await app.rename('Weight')
  assert.equal(app.name, 'Weight')
  assert.deepEqual(app.metadata, { name: 'Weight', unit: 'kg' })
  const again = await carol.c.api.getApp(app.id)
  assert.equal(again.metadata_version, app.metadataVersion)
})

await step('server never sees the plaintext type', async () => {
  await app.create('reading', { value: 1 })
  const raw = await carol.c.api.listData(app.id, {})
  assert.equal(raw.data.length, 1)
  assert.notEqual(raw.data[0].type, 'reading')
  assert.equal(raw.data[0].format, 2)
  assert.match(raw.data[0].type, /^[A-Za-z0-9_-]{22}$/)
})

await step('createMany chunks past the 500-row batch size', async () => {
  const items = Array.from({ length: 1203 }, (_, i) => ({ type: 'bulk', data: { i }, date: new Date(Date.now() - (i % 90) * DAY) }))
  const { created, skipped } = await app.createMany(items)
  assert.equal(created.length, 1203)
  assert.equal(skipped.length, 0)
  assert.equal((await app.list({ type: 'bulk' })).length, 1203)
})

await step('deterministic ids dedupe: skip reports, error mode fails with duplicate_id', async () => {
  const ids = ['tx-1', 'tx-2', 'tx-3'].map((k) => app.idFor(k))
  assert.equal(app.idFor('tx-1'), ids[0], 'idFor must be stable')
  const items = ids.map((id, i) => ({ id, type: 'txn', data: { amount: i } }))
  const first = await app.createMany(items, { onConflict: 'skip' })
  assert.equal(first.created.length, 3)
  const second = await app.createMany([...items, { id: app.idFor('tx-4'), type: 'txn', data: { amount: 4 } }], { onConflict: 'skip' })
  assert.equal(second.created.length, 1)
  assert.deepEqual(second.skipped.sort(), [...ids].sort())
  const err = await expectStatus(app.create('txn', {}, { id: ids[0] }), 409, 'duplicate_id')
  assert.deepEqual(err.details.ids, [ids[0]])
})

await step('versions: a stale update or delete is rejected', async () => {
  const e = await app.create('note', { text: 'v1' })
  const e2 = await app.update(e, { text: 'v2' })
  assert.equal(e2.version, e.version + 1)
  const err = await expectStatus(app.update(e, { text: 'lost update' }), 409, 'version_conflict')
  assert.equal(err.details.conflicts[0].current_version, e2.version)
  await expectStatus(app.delete(e), 409, 'version_conflict')
  await app.delete(e2)
  await expectStatus(app.update(e2, { text: 'gone' }), 404)
})

await step('batch is atomic: one bad op rolls back the rest', async () => {
  const before = (await app.list({ type: 'atomic' })).length
  const e = await app.create('atomic', { n: 0 })
  await expectStatus(
    app.batch({ create: [{ type: 'atomic', data: { n: 1 } }], update: [{ entry: { ...e, version: 99 }, data: { n: 2 } }] }),
    409,
    'version_conflict',
  )
  assert.equal((await app.list({ type: 'atomic' })).length, before + 1)
})

await step('metadata writes are compare-and-swap and retried by updateMetadata', async () => {
  const other = await carol.c.api.getApp(app.id)
  await app.updateMetadata((m) => ({ ...m, goal: 70 }))
  await expectStatus(
    carol.c.api.patchApp(app.id, { encrypted_metadata: other.encrypted_metadata, expected_version: other.metadata_version, dek_version: other.dek_version }),
    409,
    'version_conflict',
  )
  assert.equal(app.metadata.goal, 70)
})

let daveApp
await step('viewer share: can read, cannot write (server-enforced)', async () => {
  await app.share(dave.username, 'viewer')
  assert.equal((await dave.c.pendingShares())[0].role, 'viewer')
  daveApp = await dave.c.acceptShare(app.id)
  assert.equal(daveApp.role, 'viewer')
  assert.equal(daveApp.canWrite, false)
  assert.equal(daveApp.name, 'Weight')
  assert.equal((await daveApp.list({ type: 'reading' })).length, 1)
  await expectStatus(dave.c.api.batch(app.id, { dek_version: daveApp.dekVersion, create: [{ id: crypto.randomUUID(), type: 'x', format: 2, encrypted_json: 'AAAA', date: new Date().toISOString() }] }), 403)
  await expectStatus(daveApp.rename('hacked'), 403)
  const [r] = await daveApp.list({ type: 'reading' })
  await expectStatus(dave.c.api.batch(app.id, { delete: [{ id: r.id, expected_version: r.version }] }), 403)
})

await step('owner promotes viewer to editor', async () => {
  await app.setRole(dave.id, 'editor')
  await daveApp.refresh()
  assert.equal(daveApp.role, 'editor')
  await daveApp.create('reading', { value: 2 })
  const members = await app.members()
  assert.equal(members.find((m) => m.userId === dave.id).role, 'editor')
  assert.ok(members.every((m) => !m.keyMismatch))
})

await step('rename is visible to other members', async () => {
  await app.rename('Body weight')
  await daveApp.refresh()
  assert.equal(daveApp.name, 'Body weight')
})

await step('cache: incremental sync picks up others’ edits, deletes and date moves', async () => {
  // carol's reads go through her (memory) cache; dave writes behind her back.
  const from = new Date(Date.now() - 30 * DAY)
  const before = await app.list({ type: 'reading', from })
  assert.equal(before.length, 2)
  const created = await daveApp.create('reading', { value: 3 })
  const [first] = await daveApp.list({ type: 'reading', from })
  const edited = await daveApp.update(first, { value: 111 })
  await app.sync({ force: true })
  let now = await app.list({ type: 'reading', from })
  assert.equal(now.length, 3)
  assert.equal(now.find((e) => e.id === edited.id).data.value, 111)
  await daveApp.delete(created)
  await daveApp.update(edited, edited.data, { date: new Date(Date.now() - 200 * DAY) }) // out of the 60-day window
  await app.sync({ force: true })
  now = await app.list({ type: 'reading', from })
  assert.equal(now.length, 1, 'deleted and out-of-window rows must leave the cache')
  const all = await app.list({ type: 'reading' }) // no `from`: goes to the server
  assert.equal(all.length, 2)
})

await step('cached type queries only decrypt matching rows', async () => {
  // A fresh client: empty memo, so every decryption shows up. The cache
  // holds ~1200 'bulk' rows next to a few 'reading' ones.
  const c = await login(carol.username, 'carol passphrase')
  const fresh = await c.getApp(app.id)
  let decrypted = 0
  const real = fresh.decryptRow
  fresh.decryptRow = function (...args) {
    decrypted++
    return real.apply(this, args)
  }
  const readings = await fresh.list({ type: 'reading', from: new Date(Date.now() - 30 * DAY) })
  assert.ok(readings.length > 0)
  assert.equal(decrypted, readings.length, 'non-matching rows must not be decrypted')
})

await step('cache retention is per app type', async () => {
  const c = client({ cache: { retentionDays: 7 }, apps: { finance: { cache: { retentionDays: null } } } })
  await c.init()
  await c.session.login(carol.username, 'carol passphrase')
  const fin = await c.createApp('finance', { name: 'Money' })
  await fin.createMany([{ type: 't', data: {}, date: new Date(Date.now() - 900 * DAY) }, { type: 't', data: {} }])
  await fin.sync({ force: true })
  assert.equal((await fin.list({ type: 't' })).length, 2, 'retentionDays:null caches everything')
  // Same app through a 7-day cache vs carol's 60-day one: inside the window
  // it's served from cache, outside it falls back to the server; both agree.
  const weekly = await c.getApp(app.id)
  for (const days of [3, 30]) {
    const from = new Date(Date.now() - days * DAY)
    const a = await weekly.list({ type: 'bulk', from })
    const b = await app.list({ type: 'bulk', from })
    assert.ok(a.length > 0)
    assert.deepEqual(a.map((e) => e.id), b.map((e) => e.id))
  }
})

await step('pending invite and staged rotation with a concurrent write', async () => {
  await app.share(erin.username, 'editor')
  await erin.c.acceptShare(app.id)
  await app.share(frank.username, 'viewer') // stays pending across the rotation
  const dekBefore = app.dekVersion
  const [oldest] = await daveApp.list({ type: 'bulk', limit: 1 }) // lands in the first staged page
  let injected = false
  let commits = 0
  const realCommit = carol.c.api.commitRotation.bind(carol.c.api)
  carol.c.api.commitRotation = (...args) => (commits++, realCommit(...args))
  await app.rotateKey({
    exclude: [erin.id],
    onProgress: async () => {
      if (injected) return
      injected = true
      // Both edit an already-staged row and add a new one while staging runs.
      await daveApp.update(oldest, { i: 'edited mid-rotation' })
      await daveApp.create('reading', { value: 'written mid-rotation' })
    },
  })
  carol.c.api.commitRotation = realCommit
  assert.equal(app.dekVersion, dekBefore + 1)
  assert.ok(commits >= 2, `the first commit should have been rejected as incomplete (commits: ${commits})`)
  const all = await app.list({ type: 'reading' })
  assert.ok(all.some((e) => e.data.value === 'written mid-rotation'), 'mid-rotation create must survive under the new key')
  const bulk = await app.list({ type: 'bulk' })
  assert.equal(bulk.length, 1203)
  assert.equal(bulk.find((e) => e.id === oldest.id).data.i, 'edited mid-rotation', 'mid-rotation edit must survive')
})

await step('revoked member loses access; pending invitee can still accept', async () => {
  await expectStatus(erin.c.getApp(app.id), 404)
  const fApp = await frank.c.acceptShare(app.id)
  assert.equal(fApp.role, 'viewer')
  assert.equal((await fApp.list({ type: 'bulk' })).length, 1203)
})

await step('a member holding the old key recovers automatically', async () => {
  // daveApp still has the pre-rotation DEK: the write gets stale_dek, the
  // handle reloads the app and re-encrypts.
  const e = await daveApp.create('reading', { value: 'after rotation' })
  assert.equal(daveApp.dekVersion, app.dekVersion)
  const seen = await app.list({ type: 'reading' })
  assert.ok(seen.some((x) => x.id === e.id))
})

await step('stale_dek is enforced for raw writes', async () => {
  await expectStatus(
    carol.c.api.batch(app.id, { dek_version: app.dekVersion - 1, create: [{ id: crypto.randomUUID(), type: 'x', format: 2, encrypted_json: 'AAAA', date: new Date().toISOString() }] }),
    409,
    'stale_dek',
  )
})

await step('ids are deterministic across rotations', async () => {
  const fresh = await carol.c.getApp(app.id)
  assert.equal(fresh.idFor('tx-1'), app.idFor('tx-1'))
  const { skipped } = await fresh.createMany([{ id: fresh.idFor('tx-1'), type: 'txn', data: {} }], { onConflict: 'skip' })
  assert.equal(skipped.length, 1)
})

await step('leave and delete', async () => {
  await fApp_leave()
  await app.deleteApp()
  await expectStatus(carol.c.getApp(app.id), 404)
})

async function fApp_leave() {
  const fApp = await frank.c.getApp(app.id)
  await fApp.leave()
  await expectStatus(frank.c.getApp(app.id), 404)
}

console.log(failures ? `\n${failures} failed` : '\nall passed')
process.exit(failures ? 1 : 0)
