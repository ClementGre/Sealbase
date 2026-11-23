# Sealbase implementation notes

This document covers the parts of the implementation that aren't dictated by
[SPEC.md](SPEC.md): module layout, wire format, and decisions the spec left
to the implementer.

## Repository layout

```
src/           Rust backend (crate `sealbase`)
migrations/    0001_init.sql (v0.2, never edit: sqlx checksums applied migrations)
               0002_sealbase_v03.sql (in-place upgrade to v0.3)
client/        `sealbase-client`, the TypeScript client lib (npm package)
example/vue/   Vue example app built on the lib
doc/           SPEC.md (protocol) + this file
package.json   npm workspace root (client + example)
```

## Backend modules

```
src/
  main.rs          entry point: env/config, DB pool, migrations, router, serve
  config.rs        Config::from_env(): all runtime env vars in one place
  error.rs         AppError -> HTTP status/JSON; 409s carry a `code` (+ details);
                     unique violations (23505) map to 409 `duplicate_id`
  state.rs         AppState (pool + config + login rate limiter)
  crypto.rs        server-side crypto only (Argon2id verifier, JWTs, refresh tokens)
  models.rs        row structs + `role` helpers (can_write, is_grantable)
  repository/      one file per table, sqlx::query!/query_as! only (compile-time checked)
    apps.rs          incl. the FOR SHARE / FOR UPDATE locks on the app row
    apps_access.rs   memberships, roles, rotation's in-place re-seal
    apps_data.rs     UNNEST bulk insert, CAS update/delete + tombstones, listings
    rotations.rs     staged rotation: staging rows, mismatch check, apply
  service/         business logic: transactions and authorization
    data.rs          `apply_batch`: the one write path for data (single-row
                       endpoints are 1-op batches)
    apps.rs          apps, metadata CAS, staged rotation
    shares.rs        sharing and roles
  api/             axum handlers, request/response DTOs, router assembly
```

`repository` functions take `&PgPool`, `&mut PgConnection` or a generic
`impl PgExecutor<'_>` when the service needs them inside a transaction.

## Write path and locking

Every data write is a batch (`service::data::apply_batch`), in one transaction:

1. membership check (owner/editor, active);
2. `SELECT dek_version FROM apps … FOR SHARE`, compared with the request's;
3. creates via one `INSERT … SELECT FROM UNNEST(…) ON CONFLICT (id) DO NOTHING
   RETURNING …`, then a lookup to tell same-app duplicates (skippable) from ids
   taken by another app (always an error);
4. updates/deletes as `… WHERE id = $ AND version = $expected`; misses are
   collected and reported together as one `version_conflict`;
5. `last_edit_at` bump, commit.

Rotation commit takes the same app row `FOR UPDATE`, so it serializes against all
writes without locking data rows. Metadata PATCH is a single CAS `UPDATE … WHERE
metadata_version = $ AND dek_version = $`.

## Wire format

Binary fields (ciphertext, keys, sealed boxes) are standard padded base64 in JSON
(`api::bytes::B64`). Timestamps are RFC 3339.

`GET /apps/:id/data` parses its query string by hand (`serde_urlencoded` into
pairs) because `type` may repeat. Unknown parameters are a 400, so typos don't
silently widen a query.

## Pagination cursor

Opaque to clients: `base64url(json({"o": order, "k": key, "id": id}))`, where
`o` is `date`, `edited` or `deleted` and `k` is the sort key of the last row. A
cursor used with a different `order` is rejected. `next_cursor` is null once a
page is short of `limit`.

## CORS

`CORS_ALLOWED_ORIGINS`: `*` or a comma-separated exact list; methods
GET/POST/PATCH/DELETE/OPTIONS, headers `authorization` and `content-type`. No
credentials (bearer auth, not cookies). Unset = no cross-origin requests.

## Login rate limiting

In-memory sliding window keyed by `user:<username>` and `ip:<addr>`;
single-instance, resets on restart.

## Refresh token reuse detection

Each login/refresh creates a session row with `parent_id`. Presenting a token
whose session is already revoked revokes the entire lineage (recursive CTE in
both directions).

## Account/app deletion

Handled by `ON DELETE CASCADE` (sessions, owned apps and their data, access
rows, tombstones, staged rotations). The service only checks the passphrase or
ownership first.

## Client lib (`client/`)

```
src/
  crypto.ts    libsodium primitives, AAD, blind tags, deterministic ids
  http.ts      fetch wrapper: bearer auth, single-flight refresh on 401, SealbaseError
  wire.ts      typed raw endpoints (field names as on the wire)
  session.ts   register/login/unlock/lock/logout/change passphrase; keys in memory only
  storage.ts   session persistence (localStorage-shaped)
  cache.ts     CacheStore: IndexedDB (one DB per user) or memory; rows kept as ciphertext
  app.ts       AppHandle: metadata, data, cache sync, members, rotation, migration
  client.ts    createClient(): apps, invites, per-slug cache settings
```

Caching: the handle keeps the server's rows verbatim (ciphertext) in the store
and decrypts in memory with a memo keyed on `(dek_version, version, edited_at)`.
A query is served from the cache when its `from` is inside the retention window
(or retention is unlimited); otherwise it goes to the server. The first sync
fills the window ordered by date; later ones fetch rows edited and ids deleted
since the last `server_time` minus a two-minute overlap, merging by
`(edited_at, version)`. A changed `dek_version` or retention setting clears the
app's cache. On sign-out the user's cache database is deleted.

## Running locally

```
docker compose up -d postgres  # per compose.yaml
cp .env.example .env           # edit JWT_SECRET etc.
sqlx migrate run
cargo run
```

`sqlx::query!` is compile-time checked against a live database (`DATABASE_URL`),
or against `.sqlx/` with `SQLX_OFFLINE=true` (as in the Dockerfile). After
changing a query, run `cargo sqlx prepare` and commit `.sqlx/`.
