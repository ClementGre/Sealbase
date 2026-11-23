# Sealbase example (Vue + Vite + Tailwind)

A small app on top of [`sealbase-client`](../../client/README.md): sign-up,
sign-in and unlock, an app list with invites, a management page (rename,
members and read-only roles, revoke, encryption upgrade, delete), and one demo
app recording timestamped readings. All crypto runs in the browser, inside the
lib.

## Running

From the repository root (npm workspace):

```sh
npm install
npm run dev:example
```

`dev` builds the client lib first. Point it at a backend via `.env`:

```
VITE_API_BASE_URL=http://localhost:8080
```

The backend must allow this origin in `CORS_ALLOWED_ORIGINS`. In Docker, the
entrypoint rewrites `public/env.js` from `VITE_API_BASE_URL` at startup.

## Layout

```
src/
  sealbase.js     the shared client, its session mirrored into Vue reactivity,
                   URL helpers (/<slug>, /<slug>/<n>)
  errors.js       lib errors → UI messages
  apps/
    registry.js   the plug-in point: one entry per app type (+ its cache settings)
    demo/         the demo app
    AppTopBar.vue optional back/title/manage bar for apps
  views/          auth screens, app list, manage page, full-screen app host
  router/         routes and session guards
```

## Adding an app

1. Build a component under `src/apps/<slug>/`. It receives `app`, an
   `AppHandle`, and uses it for everything: `app.list()`, `app.create()`,
   `app.update()`, `app.delete()`, `app.name`, `app.canWrite`, ... (see the
   [lib README](../../client/README.md)).
2. Register it in `src/apps/registry.js`:
   ```js
   notes: {
     slug: 'notes',
     displayName: 'Notes',
     color: '#2563eb',
     icon: '🗒️',
     component: NotesApp,
     defaultMetadata: () => ({ name: 'New notes' }),
     cache: { retentionDays: null }, // cache every note on the device
   }
   ```

The `AppHandle` is a plain class instance holding keys and caches: pass it
around with `markRaw`/`shallowRef` rather than making it deeply reactive, and
keep the entries you display in your own refs (see `DemoApp.vue`).
