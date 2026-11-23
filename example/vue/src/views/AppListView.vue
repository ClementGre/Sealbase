<script setup>
import { ref, computed, onMounted, markRaw } from 'vue'
import { useRouter } from 'vue-router'
import { client, pathFor } from '../sealbase.js'
import { errorMessage } from '../errors.js'
import { listAppDefinitions, getAppDefinition } from '../apps/registry.js'

const router = useRouter()
// AppHandles are plain class instances holding keys and caches: keep them
// out of Vue's deep reactivity.
const myApps = ref([])
const pending = ref([])
const loading = ref(true)
const error = ref('')
const busyAppId = ref(null)
const showCreate = ref(false)

async function loadAll() {
  loading.value = true
  error.value = ''
  try {
    const [active, pendingRows] = await Promise.all([client.listApps(), client.pendingShares()])
    myApps.value = active.map(markRaw)
    pending.value = pendingRows
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    loading.value = false
  }
}

onMounted(loadAll)

function def(slug) {
  return getAppDefinition(slug) || { displayName: slug, color: '#666', icon: '📦' }
}

const rows = computed(() => myApps.value.map((app) => ({ app, path: pathFor(app, myApps.value) })))

async function accept(appId) {
  busyAppId.value = appId
  try {
    await client.acceptShare(appId)
    await loadAll()
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busyAppId.value = null
  }
}

async function decline(appId) {
  busyAppId.value = appId
  try {
    await client.declineShare(appId)
    await loadAll()
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busyAppId.value = null
  }
}

const creating = ref(false)
async function createApp(slug) {
  creating.value = true
  error.value = ''
  try {
    const created = await client.createApp(slug, getAppDefinition(slug).defaultMetadata())
    const all = await client.listApps()
    router.push(pathFor(created, all))
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    creating.value = false
  }
}
</script>

<template>
  <div class="mx-auto max-w-2xl space-y-6 p-4 pb-24">
    <div class="flex items-center justify-between">
      <h1 class="text-xl font-semibold">Your apps</h1>
      <router-link to="/account" class="text-sm text-neutral-500 underline">Account</router-link>
    </div>

    <p v-if="error" class="rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">{{ error }}</p>

    <section v-if="pending.length" class="space-y-2">
      <h2 class="text-sm font-semibold text-neutral-600">Pending shares</h2>
      <div v-for="row in pending" :key="row.appId" class="card flex items-center justify-between gap-2">
        <div class="flex items-center gap-2">
          <span class="text-xl">{{ def(row.slug).icon }}</span>
          <div>
            <div class="font-medium">{{ def(row.slug).displayName }}</div>
            <div class="text-xs text-neutral-500">shared with you · {{ row.role === 'viewer' ? 'read-only' : row.role }}</div>
          </div>
        </div>
        <div class="flex gap-2">
          <button class="btn-secondary text-sm" :disabled="busyAppId === row.appId" @click="decline(row.appId)">Decline</button>
          <button class="btn-primary text-sm" :disabled="busyAppId === row.appId" @click="accept(row.appId)">Accept</button>
        </div>
      </div>
    </section>

    <section class="space-y-2">
      <div class="flex items-center justify-between">
        <h2 class="text-sm font-semibold text-neutral-600">Apps</h2>
        <button class="btn-primary text-sm" @click="showCreate = !showCreate">+ New app</button>
      </div>

      <div v-if="showCreate" class="card space-y-2">
        <p class="text-sm text-neutral-600">Choose an app to create:</p>
        <div class="flex flex-wrap gap-2">
          <button
            v-for="d in listAppDefinitions()"
            :key="d.slug"
            class="btn-secondary text-sm"
            :disabled="creating"
            @click="createApp(d.slug)"
          >
            {{ d.icon }} {{ d.displayName }}
          </button>
        </div>
      </div>

      <p v-if="loading" class="text-sm text-neutral-500">Loading…</p>
      <p v-else-if="!myApps.length" class="text-sm text-neutral-500">No apps yet.</p>
      <div
        v-for="{ app, path } in rows"
        :key="app.id"
        class="card flex items-center gap-3"
        :style="{ borderLeft: `4px solid ${def(app.slug).color}` }"
      >
        <button class="flex min-w-0 flex-1 items-center gap-3 text-left" @click="router.push(path)">
          <span class="text-2xl">{{ def(app.slug).icon }}</span>
          <div class="min-w-0 flex-1">
            <div class="truncate font-medium">{{ app.name || def(app.slug).displayName }}</div>
            <div class="text-xs text-neutral-500">
              {{ def(app.slug).displayName }} · {{ app.role === 'viewer' ? 'read-only' : app.role }}
            </div>
          </div>
        </button>
        <button class="btn-secondary shrink-0 text-sm" @click="router.push(`/manage/${app.id}`)">Manage</button>
      </div>
    </section>
  </div>
</template>
