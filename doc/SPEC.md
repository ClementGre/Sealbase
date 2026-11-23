# Sealbase — Spec v0.3

A self-hostable Rust backend providing authentication, app data storage, sharing
and zero-knowledge encryption for any frontend that wants secure, shareable,
per-app storage without trusting the server with plaintext.

v0.3 adds: blind type tags, optimistic concurrency (row and
metadata versions), key epochs, atomic batches, idempotent creates, read-only
members, staged rotation and incremental sync. Migration `0002` upgrades a v0.2
database in place; see §10.

## 1. Design principles

- **Zero-knowledge (for content)**: the server never sees a passphrase, a KEK, a
  User Master Key (UMK), a private key, or a Data Encryption Key (DEK) in plaintext.
  It only ever stores/serves ciphertext, wrapped keys and opaque tags.
- **No recovery**: losing the passphrase means permanent loss of access to all
  encrypted data for that user (same model as Bitwarden's default). Frontends must
  communicate this clearly to end users.
- **One wrapping mechanism, not two**: every app's DEK is sealed individually to
  each user who has access (owner included) via that user's own X25519 public
  key. Ownership and sharing are the same mechanism — a row in `apps_access` with a
  sealed copy of the DEK.
- **Client does all crypto.** The server is ciphertext-blind and orchestration-only.
  The client also generates all resource UUIDs (`apps.id`, `apps_data.id`) so it can
  bind them into ciphertext AAD before upload (§2).

### 1.1 Trust model (read this before calling it "zero-knowledge")

Confidentiality of **content** (app metadata, app data, and since v0.3 the data
`type`) does not depend on trusting the server. Everything else does. A malicious or
compromised server can:

- Substitute its own X25519 public key in `GET /users/:username` and MITM a share
  (sealed boxes provide no sender authentication). Mitigation: clients pin each
  member's public key in the app metadata when sharing and refuse to rotate to a key
  that changed (§3.1).
- Fabricate pending shares — membership rows are server-asserted.
- Serve stale ciphertext, drop writes, or lie about membership and roles.
- Ignore roles: **read-only (`viewer`) is a server-enforced permission, not a
  cryptographic one.** A viewer holds the DEK and could forge ciphertext; an honest
  server just refuses their writes.
- Downgrade KDF parameters at login (mitigated by a client-side floor, §7).

The server also sees **metadata**: who is a member of what, how many rows an app
has, each row's `date`, `edited_at`, size, and which rows share a type (equal blind
tags), but not which type that is.

This residual trust surface is acceptable for a self-hosted deployment where the
operator and the users trust each other.

## 2. Cryptographic primitives

| Purpose | Primitive |
|---|---|
| Passphrase stretching (client-side) | Argon2id (per-user random salt, **fixed framework cost params**, §7) |
| Symmetric encryption (data, metadata, UMK, privkey) | XChaCha20-Poly1305 (24-byte random nonce) with AAD binding |
| Asymmetric key wrapping (DEK → user) | X25519 sealed boxes (libsodium `crypto_box_seal`) |
| Blind type tags, deterministic ids | BLAKE2b (`crypto_generichash`) keyed with subkeys of the per-app secret (`crypto_kdf_derive_from_key`, context `"sealbase"`) |
| Login verifier hashing (server-side) | Argon2id over the client-supplied `auth_key`, per-user server-side salt |

Ciphertext encoding: every encrypted blob is `nonce (24B) || ciphertext || tag`.

### 2.1 AAD binding

Every content ciphertext is encrypted with Additional Authenticated Data that ties it
to its logical location. AAD is recomputed from row identity at decrypt time (never
stored), so a ciphertext relocated to another row, app or type fails to decrypt.
Parts are joined with `:` (UUIDs, tags and legacy types never contain one).

| Encrypted field | AAD |
|---|---|
| `apps.encrypted_metadata` | `app_id:metadata` |
| `apps_data.encrypted_json`, format 1 (legacy) | `app_id:data_id:type` |
| `apps_data.encrypted_json`, format 2 | `app_id:data_id:v2:tag` |
| `users.wrapped_umk` | `username:umk` |
| `users.wrapped_privkey` | `username:privkey` |

The user blobs bind the **username**, not `user_id`: the id is only assigned once
`/auth/register` returns, after these blobs must already exist. Usernames are
immutable, so this is equally stable.

### 2.2 Per-app secret, blind type tags, deterministic ids

Each app's (encrypted) metadata holds a random 32-byte `_secret`. It is stable across
DEK rotations. Two subkeys derive from it: `type_key` (id 1) and `id_key` (id 2).

- **Blind type tag** (format 2): `tag = base64url(BLAKE2b-128(type_key, type))`,
  22 characters. The server stores and filters on the tag; the plaintext type lives
  inside the ciphertext as `{"t": type, "d": data}`. Equal types give equal tags, so
  `?type=` filtering still works server-side. Clients check that the decrypted `t`
  hashes to the row's tag.
- **Deterministic id**: `UUIDv8(BLAKE2b-128(id_key, natural_key))`. Re-importing the
  same item (e.g. a bank transaction id) maps to the same row, so creates can be
  idempotent (§5, `on_conflict: "skip"`). Keyed, so the server cannot guess or
  confirm ids from natural keys.

Format 1 rows (written before v0.3) keep a plaintext `type` until migrated (§10).

## 3. Key hierarchy

```
passphrase
   │  Argon2id(passphrase, per-user kdf_salt, fixed params)
   ▼
64 bytes ──► auth_key (32B)  ── sent to server; server stores
        │                       auth_hash = Argon2id(auth_key, per-user auth_salt)
        │
        └──► kek (32B)  (never leaves client)
                   │ unwraps
                   ▼
         User Master Key (UMK) ── random 32B, stored as wrapped_umk = Enc(kek, UMK)
         │ unwraps
         ▼
   X25519 private key ── stored as wrapped_privkey = Enc(UMK, privkey)
                          (public key stored in plaintext)
```

**Login verifier.** The client sends `auth_key`, never `auth_hash`; the server applies
its own Argon2id before storing/comparing, so a database dump yields no login
credential (no pass-the-hash). `kek` is the other half and never leaves the client.

Per app:

```
DEK (random 32B, generated client-side at app creation; replaced on rotation)
   ├─► sealed_box(owner_pubkey, DEK)    → apps_access row, role='owner'
   ├─► sealed_box(memberA_pubkey, DEK)  → apps_access row, role='editor'
   └─► sealed_box(memberB_pubkey, DEK)  → apps_access row, role='viewer'

DEK encrypts: apps.encrypted_metadata + every apps_data.encrypted_json
metadata._secret (inside the metadata) keys the blind tags and deterministic ids
```

**Roles.** `owner` (one per app: shares, rotates, deletes), `editor` (reads and
writes data and metadata), `viewer` (reads only; enforced server-side, §1.1).

**Passphrase change**: only `wrapped_umk` (and `auth_hash`/`auth_salt`/`kdf_salt`)
change. Requires proof of the current passphrase; revokes all other sessions.

**Sharing** (owner-only): the owner seals the raw DEK to the recipient's public key
and submits it as a `pending` row with a role. On accept the row turns `active`.
Clients pin the recipient's public key in the app metadata (`_directory`) at share
time.

> **Pending is a cryptographic grant, not a social one.** The sealed DEK in a
> pending row is decryptable by the recipient the moment it exists. The server only
> hands it out in the accept response, as defense in depth. An owner who cancels an
> invite they no longer want honored should rotate (§3.1).

### 3.1 DEK rotation (revocation) — staged, atomic commit

Revocation and any "the DEK might be exposed" event rotate the DEK in place, keeping
`app_id`, every `data_id`, `date` and `edited_at`. The owner's client:

1. `POST /apps/:id/rotations` → `{ rotation_id, started_at }`. Starts (or restarts)
   the app's single in-flight rotation.
2. Generates a new DEK, pages through every row, re-encrypts it under the new DEK
   (upgrading format 1 rows to format 2 on the way) and uploads them in chunks:
   `POST /apps/:id/rotations/:rid/rows`. Each staged row carries the
   `expected_version` it was read at. Writes by other members continue meanwhile.
3. `POST /apps/:id/rotations/:rid/commit` with the metadata re-encrypted under the
   new DEK, the `expected_metadata_version`, and the new DEK sealed to every member
   who keeps access (pending invitees included, to their **pinned** keys; clients
   refuse if the server reports a different key than the pinned one).

The commit runs in **one transaction** holding the app row `FOR UPDATE` (every data
or metadata write takes it `FOR SHARE`, so nothing interleaves). It verifies that
every live row is staged at its current version. If not, it fails with
`rotation_incomplete` listing `missing` and `stale` rows; the client re-stages rows
edited since `started_at` and commits again. On success it swaps all staged
ciphertexts, the metadata, and the sealed DEKs; drops members left out of the list;
keeps everyone else's role and status; and increments `dek_version`.

Why staged rather than one big request or a cross-request SQL transaction: request
size stays bounded (≤ 1000 rows per chunk) whatever the app size; no database
connection or lock is held across HTTP requests; and an interrupted rotation just
leaves a staging row set, discarded on the next begin or by `DELETE`.

Revocation is **forward-only**: a revoked user may already have copied plaintext.

## 4. Database schema

`migrations/0001_init.sql` (v0.2) + `migrations/0002_sealbase_v03.sql`. Resulting
shape of the app tables (`users`, `sessions`, `audit_log` are unchanged):

```sql
CREATE TABLE apps (
    id                  UUID PRIMARY KEY,                 -- client-generated
    owner_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    slug                TEXT NOT NULL,                    -- plaintext app-TYPE id, not unique
    encrypted_metadata  BYTEA NOT NULL,                   -- Enc(DEK, {name, ..., _secret, _directory, _format})
    metadata_version    BIGINT NOT NULL DEFAULT 1,        -- CAS counter for metadata writes
    dek_version         BIGINT NOT NULL DEFAULT 1,        -- key epoch, bumped by each rotation
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE apps_access (
    app_id        UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_dek   BYTEA NOT NULL,                         -- sealed_box(user's pubkey, DEK)
    role          TEXT NOT NULL DEFAULT 'editor' CHECK (role IN ('owner','editor','viewer')),
    status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('pending','active')),
    last_edit_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (app_id, user_id)
);

CREATE TABLE apps_data (
    id              UUID PRIMARY KEY,                     -- client-generated (v7 random, or v8 deterministic)
    app_id          UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    type            TEXT NOT NULL,                        -- format 2: blind tag; format 1: plaintext
    format          SMALLINT NOT NULL DEFAULT 1,          -- 1 legacy, 2 blind tag (CHECK 1|2)
    encrypted_json  BYTEA NOT NULL,                       -- AAD per §2.1
    date            TIMESTAMPTZ NOT NULL,                 -- client-controlled, editable, queryable
    edited_at       TIMESTAMPTZ NOT NULL DEFAULT now(),   -- server time of the last write
    version         BIGINT NOT NULL DEFAULT 1             -- CAS counter, bumped on every write
);
-- indexes: (app_id, type, date), (app_id, date), (app_id, edited_at, id)

CREATE TABLE apps_data_tombstones (                       -- deletions, for incremental sync
    app_id      UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    id          UUID NOT NULL,
    deleted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (app_id, id)
);

CREATE TABLE app_rotations (                              -- at most one in flight per app
    id UUID PRIMARY KEY, app_id UUID NOT NULL UNIQUE REFERENCES apps(id) ON DELETE CASCADE,
    base_dek_version BIGINT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE app_rotation_rows (
    rotation_id UUID NOT NULL REFERENCES app_rotations(id) ON DELETE CASCADE,
    data_id UUID NOT NULL, expected_version BIGINT NOT NULL,
    type TEXT NOT NULL, format SMALLINT NOT NULL, encrypted_json BYTEA NOT NULL,
    PRIMARY KEY (rotation_id, data_id)
);
```

Notes:
- **Ownership** is authoritative on `apps.owner_id`, mirrored by the `role='owner'`
  access row. Deleting a user cascades to the apps they own.
- **`date`** (named `created_at` before v0.3) is client-controlled: set on create,
  movable on update, not part of any AAD. `edited_at` is always server time, also on
  create, so a backdated row still appears in an `edited_from` sync.
- **Reserved metadata keys** start with `_`: `_secret` (§2.2), `_directory` (pinned
  `{user_id: {username, publicKeyB64}}`), `_format` (`2` once no format 1 rows remain).

## 5. Endpoints

All authenticated endpoints take `Authorization: Bearer <access_token>`. Errors are
`{ "error": message }`; 409s add a machine-readable `code` and optional `details`:

| `code` | Meaning | Client reaction |
|---|---|---|
| `version_conflict` | a row or the metadata changed since it was read (`details.conflicts: [{id, current_version}]` or `details.current_version`) | re-read, re-apply, retry |
| `stale_dek` | the write quoted an old `dek_version` | reload the app (new DEK), re-encrypt, retry |
| `duplicate_id` | create with an id that exists (`details.ids`) | — or use `on_conflict: "skip"` |
| `rotation_incomplete` | rows changed during staging (`details.missing`, `details.stale`) | re-stage, commit again |
| `stale_rotation` | another rotation committed first | start over |
| `already_member`, `username_taken` | as named | — |

```
Auth  (unchanged from v0.2)
  POST   /auth/register              { username, auth_key, kdf_salt, wrapped_umk, public_key, wrapped_privkey }
  POST   /auth/login                 { username, auth_key } -> { access_token, refresh_token, kdf_salt,
                                        kdf_params, wrapped_umk, wrapped_privkey, public_key }
  POST   /auth/refresh               { refresh_token } -> { access_token, refresh_token }
  POST   /auth/logout                { refresh_token }
  POST   /auth/change-passphrase     { current_auth_key, new_auth_key, new_kdf_salt, new_wrapped_umk }

Users  (unchanged)
  GET    /users/me                   -> { user_id, username, public_key, created_at }
  GET    /users/:username            -> { user_id, public_key, kdf_salt, kdf_params }   (unauthenticated)
  DELETE /users/me                   { current_auth_key }

Apps
  GET    /apps[?slug=]               -> [App]      caller's active memberships
  POST   /apps                       { app_id, slug, encrypted_metadata, wrapped_dek } -> App
  GET    /apps/:id                   -> App        active members only
     App = { app_id, slug, encrypted_metadata, metadata_version, dek_version,
             role, status, wrapped_dek, last_edit_at }
  PATCH  /apps/:id                   { encrypted_metadata, expected_version, dek_version }
                                      -> { metadata_version }     owner/editor; compare-and-swap
  DELETE /apps/:id                   owner only; cascades
  POST   /apps/:id/leave             non-owner removes their own access

Rotation  (owner only, §3.1)
  POST   /apps/:id/rotations                   -> { rotation_id, base_dek_version, started_at }
  POST   /apps/:id/rotations/:rid/rows         { rows: [{ id, expected_version, type, format, encrypted_json }] }
                                                (≤ 1000 per request; re-staging an id overwrites it)
  POST   /apps/:id/rotations/:rid/commit       { encrypted_metadata, expected_metadata_version,
                                                  access: [{ user_id, wrapped_dek }] }
                                                -> { metadata_version, dek_version }
  DELETE /apps/:id/rotations/:rid              abort

App data
  GET    /apps/:id/data?type=&type=&format=&date_from=&date_to=&edited_from=&edited_to=
                        &order=date|edited&limit=&cursor=
                                      -> { data: [Row], next_cursor, server_time, dek_version }
     Row = { id, type, format, encrypted_json, date, edited_at, version }
     Active members (any role). `type` may repeat (OR). Keyset pagination on
     (date, id) or (edited_at, id); limit defaults to 100, max 1000.
  GET    /apps/:id/data/deleted?since=&limit=&cursor=
                                      -> { deleted: [{ id, deleted_at }], next_cursor, server_time, dek_version }
  POST   /apps/:id/data/batch        { dek_version, on_conflict: "error"|"skip",
                                        create: [{ id, type, format, encrypted_json, date }],
                                        update: [{ id, expected_version, encrypted_json, type?, format?, date? }],
                                        delete: [{ id, expected_version }] }
                                      -> { created: [Row], skipped: [id], updated: [Row], deleted: [id] }
     Owner/editor. ≤ 1000 operations, all-or-nothing. `dek_version` is required
     when creating or updating. Updates and deletes are compare-and-swap.
     `skip` tolerates ids that already exist in this app (idempotent imports).
  POST   /apps/:id/data              { id, type, format, encrypted_json, date, dek_version } -> 201 Row
  PATCH  /apps/:id/data/:data_id     { expected_version, dek_version, encrypted_json, type?, format?, date? } -> Row
  DELETE /apps/:id/data/:data_id?version=N
     Single-row shorthands for the batch; a missing row is 404.

Sharing
  POST   /apps/:id/shares            { recipient_user_id, wrapped_dek, role: "editor"|"viewer" } -> pending row
  GET    /apps/:id/shares            owner: [{ user_id, username, public_key, role, status, last_edit_at, created_at }]
  PATCH  /apps/:id/shares/:user_id   { role: "editor"|"viewer" }   owner only
  DELETE /apps/:id/shares/:user_id   owner removes a row (no key change: use rotation to revoke)
  GET    /shares/pending             caller's invites (no wrapped_dek)
  POST   /apps/:id/shares/accept     -> { wrapped_dek }
  POST   /apps/:id/shares/decline
```

**Status semantics.** A `pending` member cannot read or write data or metadata and is
not listed in `GET /apps`.

**`type` changes.** Because the AAD binds the type (or its tag), changing a row's
type means re-encrypting it, which is why `type`/`format` can only change together
with `encrypted_json` (used by the format 1 → 2 migration).

## 6. Concurrency and sync

- **Rows**: every write bumps `version`; updates and deletes must quote the version
  they read. There is no blind overwrite.
- **Metadata**: same, with `metadata_version`.
- **Key epoch**: every ciphertext write quotes `dek_version`. After a rotation, a
  client still holding the old DEK gets `stale_dek` instead of writing data nobody
  can decrypt; listings return `dek_version` so readers notice too.
- **Incremental sync**: a client remembers the `server_time` of its last listing
  and next asks `order=edited&edited_from=<watermark - overlap>` plus
  `/data/deleted?since=…`. `server_time` is read before the query; the overlap
  (two minutes in the reference client) covers transactions that started before the
  watermark but committed after it (their `edited_at` is their start time).
  Re-created ids drop their tombstone. Rotation does not touch `edited_at`, so
  caches must key on `dek_version` and refill after a rotation.

## 7. Sessions, tokens, KDF, rate limiting, enumeration

Unchanged from v0.2:

- **Access token**: HS256 JWT (`sub`, `sid`, `iat`, `exp` ~15 min).
- **Refresh token**: opaque, stored as SHA-256, ~30 days, rotated on every use; reuse
  of a consumed token revokes the whole session lineage.
- **Fixed KDF params** `{argon2id, 19456 KiB, t=2, p=1}`, returned with a `version`;
  clients refuse anything below the floor.
- **Login rate limiting** per username and per IP (default 10 per minute).
- **Enumeration is not defended**: registration, user lookup and sharing reveal
  whether a username exists.

## 8. Audit logging

`share`, `accept`, `decline`, `revoke`, `role.change`, `rotate`, `leave` and
`app.delete` events are recorded with actor, app, target user and time —
metadata only.

## 9. Edge cases

- Deleting an account deletes the apps it owns; there is no ownership transfer.
- Only the owner issues shares (keeps revocation tractable).
- A rotation re-seals pending invites too, so they stay acceptable afterwards.
- The JWT signing secret comes from the environment; if absent, a random one is
  generated at each start.

## 10. Upgrading from v0.2

Migration `0002` runs automatically at startup and rewrites no ciphertext:

- role `member` → `editor`; `apps_data.created_at` → `date`; new columns default to
  `metadata_version = dek_version = version = 1` and `format = 1`.
- Existing rows stay format 1 and keep working: the reference client queries both
  the blind tag and the plaintext type until the app is migrated.
- `AppHandle.migrate()` (owner or editor) adds the app's `_secret` if missing,
  re-encrypts every format 1 row as format 2 via compare-and-swap batches (safe to
  interrupt and resume), then sets `_format: 2`. A rotation also upgrades all rows.
- The v0.2 HTTP API is not kept: field names changed (`data_id` → `id`,
  `created_at` → `date`), and writes now require versions.
