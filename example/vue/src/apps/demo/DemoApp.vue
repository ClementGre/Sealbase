<script setup>
// Example app: timestamped numeric readings stored as entries of type
// "reading". Everything goes through the `app` prop (a sealbase-client
// AppHandle): plaintext in, plaintext out, the key never leaves it.
//
// The last 60 days come from the on-device cache (registry: retentionDays),
// synced incrementally on each load; "Load older" asks the server directly.
import { ref, reactive, computed, onMounted } from 'vue'
import { errorMessage } from '../../errors.js'
import AppTopBar from '../AppTopBar.vue'

const props = defineProps({
  app: { type: Object, required: true }, // AppHandle
  icon: { type: String, default: '' },
  color: { type: String, default: '#666' },
  displayName: { type: String, default: '' },
})

const WINDOW_DAYS = 60
const windowStart = () => new Date(Date.now() - WINDOW_DAYS * 86400_000)

const entries = ref([])
const olderLoaded = ref(false)
const loading = ref(true)
const error = ref('')
const canWrite = computed(() => props.app.canWrite)

const newValue = ref('')
const newLabel = ref('')
const newTime = ref(toLocalInput(new Date()))
const submitting = ref(false)
const timeDrafts = reactive({}) // id -> datetime-local draft
const busy = reactive({}) // id -> true while deleting/saving

// <input type="datetime-local"> is local time without a zone.
function toLocalInput(d) {
  const dt = new Date(d)
  const pad = (n) => String(n).padStart(2, '0')
  return `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())}T${pad(dt.getHours())}:${pad(dt.getMinutes())}`
}

const sorted = computed(() => [...entries.value].sort((a, b) => Date.parse(b.date) - Date.parse(a.date)))

function upsert(entry) {
  entries.value = [...entries.value.filter((e) => e.id !== entry.id), entry]
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    entries.value = await props.app.list({ type: 'reading', from: windowStart() })
    olderLoaded.value = false
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    loading.value = false
  }
}

async function loadOlder() {
  try {
    const older = await props.app.list({ type: 'reading', to: windowStart() })
    for (const e of older) upsert(e)
    olderLoaded.value = true
  } catch (e) {
    error.value = errorMessage(e)
  }
}

onMounted(load)

async function addReading() {
  const value = Number(newValue.value)
  if (Number.isNaN(value)) return (error.value = 'Value must be a number')
  submitting.value = true
  error.value = ''
  try {
    const entry = await props.app.create('reading', { value, label: newLabel.value || null }, { date: new Date(newTime.value) })
    upsert(entry)
    newValue.value = ''
    newLabel.value = ''
    newTime.value = toLocalInput(new Date())
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    submitting.value = false
  }
}

async function saveTime(entry) {
  busy[entry.id] = true
  error.value = ''
  try {
    // Same data, new date. Fails with a conflict if someone edited it meanwhile.
    upsert(await props.app.update(entry, entry.data, { date: new Date(timeDrafts[entry.id]) }))
    delete timeDrafts[entry.id]
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    delete busy[entry.id]
  }
}

async function removeReading(entry) {
  busy[entry.id] = true
  try {
    await props.app.delete(entry)
    entries.value = entries.value.filter((e) => e.id !== entry.id)
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    delete busy[entry.id]
  }
}

const formatTime = (iso) => new Date(iso).toLocaleString()
</script>

<template>
  <div class="min-h-screen bg-amber-50">
    <AppTopBar :app-id="app.id" :icon="icon" :color="color" :title="app.name || displayName" />

    <div class="mx-auto max-w-2xl space-y-4 p-4">
      <p v-if="error" class="rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">{{ error }}</p>
      <p v-if="!canWrite" class="rounded-md bg-neutral-100 px-3 py-2 text-sm text-neutral-600">
        Read-only: this app was shared with you as a viewer.
      </p>

      <section v-if="canWrite" class="card space-y-3">
        <h2 class="text-sm font-semibold text-neutral-600">Add reading</h2>
        <div class="flex flex-col gap-2 sm:flex-row">
          <input v-model="newValue" type="number" step="any" placeholder="Value" class="sm:w-32" />
          <input v-model="newLabel" type="text" placeholder="Label (optional)" />
          <button class="btn-primary shrink-0" :disabled="submitting || newValue === ''" @click="addReading">Add</button>
        </div>
        <label class="block">
          <span class="field-label">Date (client-set, backdate freely)</span>
          <input v-model="newTime" type="datetime-local" />
        </label>
      </section>

      <section class="card">
        <div class="mb-2 flex items-center justify-between">
          <h2 class="text-sm font-semibold text-neutral-600">Readings</h2>
          <button class="btn-secondary py-1 text-xs" :disabled="loading" @click="load">Refresh</button>
        </div>
        <p v-if="loading" class="text-sm text-neutral-500">Loading…</p>
        <p v-else-if="!entries.length" class="text-sm text-neutral-500">No readings in the last {{ WINDOW_DAYS }} days.</p>
        <ul v-else class="divide-y divide-neutral-100">
          <li v-for="entry in sorted" :key="entry.id" class="py-2">
            <div class="flex items-center justify-between gap-2">
              <div class="min-w-0">
                <div class="font-medium">{{ entry.data.value }}</div>
                <div class="truncate text-xs text-neutral-500">
                  {{ entry.data.label ? entry.data.label + ' · ' : '' }}{{ formatTime(entry.date) }}
                </div>
              </div>
              <div v-if="canWrite" class="flex shrink-0 gap-2">
                <button
                  v-if="timeDrafts[entry.id] === undefined"
                  class="btn-secondary text-sm"
                  @click="timeDrafts[entry.id] = toLocalInput(entry.date)"
                >
                  Edit date
                </button>
                <button class="btn-secondary text-sm" :disabled="busy[entry.id]" @click="removeReading(entry)">Delete</button>
              </div>
            </div>
            <div v-if="timeDrafts[entry.id] !== undefined" class="mt-2 flex items-center gap-2">
              <input v-model="timeDrafts[entry.id]" type="datetime-local" />
              <button class="btn-primary shrink-0 text-sm" :disabled="busy[entry.id]" @click="saveTime(entry)">Save</button>
              <button class="btn-secondary shrink-0 text-sm" @click="delete timeDrafts[entry.id]">Cancel</button>
            </div>
          </li>
        </ul>
        <button v-if="!loading && !olderLoaded" class="mt-3 w-full bg-transparent text-sm text-neutral-500 underline" @click="loadOlder">
          Load readings older than {{ WINDOW_DAYS }} days
        </button>
      </section>
    </div>
  </div>
</template>
