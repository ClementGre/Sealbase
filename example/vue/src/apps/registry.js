// The plug-in point: build an app component under src/apps/<slug>/, then add
// one entry here. It shows up in the "+ New app" picker and app list.
//
// `slug` is the app TYPE (which component loads); each instance of it is its
// own app with its own id, data and members. Components receive the instance
// as an `app` prop (a sealbase-client AppHandle), so data access is always
// scoped to that instance.
import DemoApp from './demo/DemoApp.vue'

export const appRegistry = {
  demo: {
    slug: 'demo',
    displayName: 'Demo',
    description: 'Record timestamped numeric readings.',
    color: '#edb43a',
    icon: '📈',
    component: DemoApp,
    defaultMetadata: () => ({ name: 'New demo app' }),
    // Readings from the last 60 days are cached on this device and synced
    // incrementally; older ones are fetched on demand.
    cache: { retentionDays: 60 },
  },
}

export function getAppDefinition(slug) {
  return appRegistry[slug] || null
}

export function listAppDefinitions() {
  return Object.values(appRegistry)
}

/** `{ [slug]: { cache } }` for createClient({ apps }). */
export function appCacheConfig() {
  return Object.fromEntries(Object.values(appRegistry).map((d) => [d.slug, { cache: d.cache ?? {} }]))
}
