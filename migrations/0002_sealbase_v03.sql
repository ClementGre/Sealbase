-- Sealbase v0.3 — see doc/SPEC.md. Applies in place on a v0.2 database
-- without touching any ciphertext: every existing row stays readable.

-- ---------------------------------------------------------------------------
-- 1. Roles: 'member' becomes 'editor', and a read-only 'viewer' is added.
-- ---------------------------------------------------------------------------
ALTER TABLE apps_access DROP CONSTRAINT IF EXISTS apps_access_role_check;
UPDATE apps_access SET role = 'editor' WHERE role = 'member';
ALTER TABLE apps_access ALTER COLUMN role SET DEFAULT 'editor';
ALTER TABLE apps_access
    ADD CONSTRAINT apps_access_role_check CHECK (role IN ('owner', 'editor', 'viewer'));

-- ---------------------------------------------------------------------------
-- 2. Apps: optimistic-concurrency counter for metadata, and a key epoch.
--    dek_version is bumped by every rotation; writes must quote the current
--    value so a client still holding the previous DEK cannot write ciphertext
--    nobody can decrypt any more.
-- ---------------------------------------------------------------------------
ALTER TABLE apps ADD COLUMN metadata_version BIGINT NOT NULL DEFAULT 1;
ALTER TABLE apps ADD COLUMN dek_version      BIGINT NOT NULL DEFAULT 1;

-- ---------------------------------------------------------------------------
-- 3. App data
--    - created_at -> date: it was always client-controlled and editable.
--    - version: optimistic concurrency, bumped on every write.
--    - format: 1 = legacy (plaintext `type`, AAD = app_id:data_id:type),
--              2 = blind type tag (`type` holds a keyed hash; the real type
--                  lives inside the ciphertext). Existing rows are format 1.
-- ---------------------------------------------------------------------------
ALTER TABLE apps_data RENAME COLUMN created_at TO date;
ALTER TABLE apps_data ADD COLUMN version BIGINT   NOT NULL DEFAULT 1;
ALTER TABLE apps_data ADD COLUMN format  SMALLINT NOT NULL DEFAULT 1;
ALTER TABLE apps_data ADD CONSTRAINT apps_data_format_check CHECK (format IN (1, 2));

-- idx_apps_data_app_type follows the column rename automatically.
ALTER INDEX idx_apps_data_app_created RENAME TO idx_apps_data_app_date;
CREATE INDEX idx_apps_data_app_edited ON apps_data(app_id, edited_at, id);

-- Deleted rows leave a tombstone so cached clients can sync deletions.
-- Only ids and timestamps: nothing that wasn't already visible.
CREATE TABLE apps_data_tombstones (
    app_id      UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    id          UUID NOT NULL,
    deleted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (app_id, id)
);
CREATE INDEX idx_apps_data_tombstones_app_deleted ON apps_data_tombstones(app_id, deleted_at, id);

-- ---------------------------------------------------------------------------
-- 4. Staged DEK rotation: the owner uploads re-encrypted rows in chunks, then
--    a single commit swaps everything in one transaction. At most one
--    rotation in flight per app.
-- ---------------------------------------------------------------------------
CREATE TABLE app_rotations (
    id                UUID PRIMARY KEY,
    app_id            UUID NOT NULL UNIQUE REFERENCES apps(id) ON DELETE CASCADE,
    base_dek_version  BIGINT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE app_rotation_rows (
    rotation_id       UUID NOT NULL REFERENCES app_rotations(id) ON DELETE CASCADE,
    data_id           UUID NOT NULL,
    expected_version  BIGINT NOT NULL,
    type              TEXT NOT NULL,
    format            SMALLINT NOT NULL CHECK (format IN (1, 2)),
    encrypted_json    BYTEA NOT NULL,
    PRIMARY KEY (rotation_id, data_id)
);
