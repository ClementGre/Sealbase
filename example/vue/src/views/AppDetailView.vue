<script setup>
// Management page for one app instance: everything independent of the app's
// own UI — rename, members & roles, encryption upgrade, leave/delete.
import { ref, shallowRef, computed, onMounted, markRaw } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { client, pathFor } from '../sealbase.js'
import { errorMessage } from '../errors.js'
import { getAppDefinition } from '../apps/registry.js'

const route = useRoute()
const router = useRouter()
const appId = computed(() => route.params.id)

const app = shallowRef(null)
// AppHandle isn't reactive: bump this after mutating it to re-render.
const tick = ref(0)
const loading = ref(true)
const error = ref('')
const openPath = ref(null)

const definition = computed(() => (app.value ? getAppDefinition(app.value.slug) : null))
const view = computed(() => {
  tick.value
  const a = app.value
  return a && { name: a.name, role: a.role, isOwner: a.isOwner, canWrite: a.canWrite, needsMigration: a.needsMigration }
})

async function load() {
  loading.value = true
  error.value = ''
  try {
    app.value = markRaw(await client.getApp(appId.value))
    openPath.value = pathFor(app.value, await client.listApps(app.value.slug))
    nameDraft.value = app.value.name
    tick.value++
    if (app.value.isOwner) await loadMembers()
  } catch (e) {
    error.value = e.status === 403 ? 'Access pending — accept the share first.' : errorMessage(e)
  } finally {
    loading.value = false
  }
}

onMounted(load)

// --- rename ---
const nameDraft = ref('')
const renaming = ref(false)
async function rename() {
  renaming.value = true
  error.value = ''
  try {
    await app.value.rename(nameDraft.value.trim())
    tick.value++
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    renaming.value = false
  }
}

// --- members ---
const members = ref([])
const shareUsername = ref('')
const shareRole = ref('editor')
const busy = ref(null) // user id or 'share' while an action runs
const shareError = ref('')

async function loadMembers() {
  members.value = await app.value.members()
}

async function run(key, fn) {
  busy.value = key
  shareError.value = ''
  try {
    await fn()
    await loadMembers()
    tick.value++
  } catch (e) {
    shareError.value = e.status === 404 ? 'No such user' : errorMessage(e)
  } finally {
    busy.value = null
  }
}

const submitShare = () =>
  run('share', async () => {
    await app.value.share(shareUsername.value.trim(), shareRole.value)
    shareUsername.value = ''
  })
const setRole = (m, role) => run(m.userId, () => app.value.setRole(m.userId, role))
// Pending invites can simply be cancelled; active members get a real
// revocation (key rotation).
const remove = (m) => run(m.userId, () => (m.status === 'pending' ? app.value.removeMember(m.userId) : app.value.revoke(m.userId)))

// --- encryption upgrade (legacy apps) ---
const migrating = ref(false)
const migrated = ref(null)
async function migrate() {
  migrating.value = true
  error.value = ''
  try {
    migrated.value = await app.value.migrate()
    tick.value++
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    migrating.value = false
  }
}

// --- leave / delete ---
const leaving = ref(false)
async function leave() {
  leaving.value = true
  try {
    await app.value.leave()
    router.push('/apps')
  } catch (e) {
    error.value = errorMessage(e)
    leaving.value = false
  }
}

const deleting = ref(false)
const confirmingDelete = ref(false)
async function destroy() {
  deleting.value = true
  try {
    await app.value.deleteApp()
    router.push('/apps')
  } catch (e) {
    error.value = errorMessage(e)
    deleting.value = false
  }
}

const roleLabel = (r) => (r === 'viewer' ? 'read-only' : r)
</script>

<template>
  <div class="mx-auto max-w-2xl space-y-4 p-4 pb-24">
    <button class="bg-transparent p-0 text-sm text-neutral-500 underline" @click="router.push('/apps')">← Apps</button>

    <p v-if="error" class="rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">{{ error }}</p>
    <p v-if="loading" class="text-sm text-neutral-500">Loading…</p>

    <template v-if="view && !loading">
      <div class="flex items-center justify-between gap-2" :style="{ borderBottom: `3px solid ${definition?.color || '#666'}` }">
        <h1 class="flex min-w-0 items-center gap-2 py-2 text-xl font-semibold">
          <span>{{ definition?.icon }}</span>
          <span class="truncate">{{ view.name || definition?.displayName || app.slug }}</span>
        </h1>
        <router-link v-if="openPath" :to="openPath" class="btn-primary shrink-0 text-sm">Open app →</router-link>
      </div>
      <p class="text-sm text-neutral-500">Your access: {{ roleLabel(view.role) }}</p>

      <section v-if="view.canWrite" class="card space-y-2">
        <h2 class="text-sm font-semibold text-neutral-600">Name</h2>
        <form class="flex gap-2" @submit.prevent="rename">
          <input v-model="nameDraft" type="text" required maxlength="120" />
          <button class="btn-primary shrink-0" :disabled="renaming || nameDraft.trim() === view.name">
            {{ renaming ? 'Saving…' : 'Rename' }}
          </button>
        </form>
        <p class="text-xs text-neutral-400">The name is encrypted like the rest of the app; every member sees the new one.</p>
      </section>

      <section v-if="view.canWrite && view.needsMigration" class="card space-y-2 border-amber-300 bg-amber-50">
        <h2 class="text-sm font-semibold text-amber-800">Encryption upgrade available</h2>
        <p class="text-sm text-amber-900">
          This app was created before entry types were encrypted, so the server can still see type names. Upgrading
          re-encrypts entries in place; it's safe to interrupt and run again.
        </p>
        <button class="btn-primary" :disabled="migrating" @click="migrate">{{ migrating ? 'Upgrading…' : 'Upgrade now' }}</button>
      </section>
      <p v-if="migrated !== null" class="text-sm text-green-700">Upgraded {{ migrated }} entries.</p>

      <section v-if="view.isOwner" class="card space-y-3">
        <h2 class="text-sm font-semibold text-neutral-600">Members</h2>
        <ul class="divide-y divide-neutral-100">
          <li v-for="m in members" :key="m.userId" class="flex flex-wrap items-center justify-between gap-2 py-2 text-sm">
            <div class="min-w-0">
              <span class="font-medium">{{ m.username }}</span>
              <span class="ml-2 text-xs text-neutral-500">{{ m.status === 'pending' ? 'invited' : '' }}</span>
              <span v-if="m.keyMismatch" class="ml-2 text-xs text-red-600">key changed on server!</span>
            </div>
            <span v-if="m.role === 'owner'" class="text-xs text-neutral-500">owner</span>
            <div v-else class="flex items-center gap-2">
              <select
                class="w-auto py-1 text-sm"
                :value="m.role"
                :disabled="busy === m.userId"
                @change="setRole(m, $event.target.value)"
              >
                <option value="editor">editor</option>
                <option value="viewer">read-only</option>
              </select>
              <button class="btn-danger py-1 text-xs" :disabled="busy === m.userId" @click="remove(m)">
                {{ busy === m.userId ? '…' : m.status === 'pending' ? 'Cancel' : 'Revoke' }}
              </button>
            </div>
          </li>
        </ul>

        <form class="flex flex-col gap-2 pt-2 sm:flex-row" @submit.prevent="submitShare">
          <input v-model="shareUsername" type="text" placeholder="Username to share with" required />
          <select v-model="shareRole" class="sm:w-36">
            <option value="editor">editor</option>
            <option value="viewer">read-only</option>
          </select>
          <button class="btn-primary shrink-0" :disabled="busy === 'share'">{{ busy === 'share' ? 'Sharing…' : 'Share' }}</button>
        </form>
        <p v-if="shareError" class="text-sm text-red-600">{{ shareError }}</p>
        <p class="text-xs text-neutral-400">
          Read-only is enforced by the server. Revoke rotates the encryption key in place and re-seals it to everyone
          else, so the removed member loses access to future changes (they may already have copied past data).
        </p>
      </section>

      <section class="card space-y-2">
        <h2 class="text-sm font-semibold text-neutral-600">Danger zone</h2>
        <button v-if="!view.isOwner" class="btn-secondary w-full" :disabled="leaving" @click="leave">
          {{ leaving ? 'Leaving…' : 'Leave this app' }}
        </button>
        <template v-else>
          <button v-if="!confirmingDelete" class="btn-danger w-full" @click="confirmingDelete = true">Delete this app…</button>
          <div v-else class="space-y-2">
            <p class="text-sm text-neutral-600">
              This deletes the app for every member, including anyone it's shared with. This cannot be undone.
            </p>
            <div class="flex gap-2">
              <button class="btn-secondary flex-1" @click="confirmingDelete = false">Cancel</button>
              <button class="btn-danger flex-1" :disabled="deleting" @click="destroy">
                {{ deleting ? 'Deleting…' : 'Confirm delete' }}
              </button>
            </div>
          </div>
        </template>
      </section>
    </template>
  </div>
</template>
