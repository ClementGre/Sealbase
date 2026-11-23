// The one place this example touches the Sealbase client lib directly: a
// shared client instance, its session mirrored into Vue reactivity, and a
// few UI helpers. App components receive an `AppHandle` and use it for
// everything else (see apps/demo/DemoApp.vue).
import { reactive, readonly } from 'vue'
import { createClient } from 'sealbase-client'
import { appCacheConfig } from './apps/registry.js'

// window.__ENV__ (public/env.js) is rewritten at container start, so the API
// URL can change without rebuilding; import.meta.env is the build-time value.
function readEnv(key) {
  return window.__ENV__?.[key] || import.meta.env[key]
}

export const client = createClient({
  baseUrl: readEnv('VITE_API_BASE_URL') || 'http://localhost:8080',
  // Per app type cache retention, declared next to each app in the registry.
  apps: appCacheConfig(),
})

const state = reactive({ status: 'loading', user: null })

/** Reactive, read-only view of the session: { status, user }. */
export const session = readonly(state)

export async function initSession() {
  await client.init()
  client.session.subscribe((s) => {
    state.status = s.status
    state.user = s.user
  })
}

// --- URLs: /<slug> is the first instance of a slug, /<slug>/<n> the nth ---------
// UUIDv7 ids sort by creation time, so ordering by id gives every instance a
// stable index without a backend field.

export function sortByCreation(apps) {
  return [...apps].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
}

export function slugPath(slug, index) {
  return index > 0 ? `/${slug}/${index}` : `/${slug}`
}

export function pathFor(app, allApps) {
  const sameSlug = sortByCreation(allApps.filter((a) => a.slug === app.slug))
  return slugPath(app.slug, Math.max(0, sameSlug.findIndex((a) => a.id === app.id)))
}
