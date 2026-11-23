// Raw endpoint wrappers (SPEC.md §5). Binary fields are base64 strings, field
// names are the server's. No crypto, no state.
import type { Http } from './http.js'
import type { KdfParams } from './crypto.js'

export type Role = 'owner' | 'editor' | 'viewer'
export type Status = 'pending' | 'active'

export interface WireApp {
  app_id: string
  slug: string
  encrypted_metadata: string
  metadata_version: number
  dek_version: number
  role: Role
  status: Status
  wrapped_dek: string
  last_edit_at: string | null
}

export interface WireRow {
  id: string
  type: string
  format: 1 | 2
  encrypted_json: string
  date: string
  edited_at: string
  version: number
}

export interface WireCreate {
  id: string
  type: string
  format: 1 | 2
  encrypted_json: string
  date: string
}

export interface WireUpdate {
  id: string
  expected_version: number
  encrypted_json: string
  type?: string
  format?: 1 | 2
  date?: string
}

export interface WireBatch {
  dek_version?: number
  on_conflict?: 'error' | 'skip'
  create?: WireCreate[]
  update?: WireUpdate[]
  delete?: { id: string; expected_version: number }[]
}

export interface WireBatchResult {
  created: WireRow[]
  skipped: string[]
  updated: WireRow[]
  deleted: string[]
}

export interface WireListQuery {
  type?: string[]
  format?: 1 | 2
  date_from?: string
  date_to?: string
  edited_from?: string
  edited_to?: string
  order?: 'date' | 'edited'
  limit?: number
  cursor?: string
}

export interface WirePage {
  data: WireRow[]
  next_cursor: string | null
  server_time: string
  dek_version: number
}

export interface WireDeletedPage {
  deleted: { id: string; deleted_at: string }[]
  next_cursor: string | null
  server_time: string
  dek_version: number
}

export interface WireMember {
  user_id: string
  username: string
  public_key: string
  role: Role
  status: Status
  last_edit_at: string | null
  created_at: string
}

export interface WirePendingShare {
  app_id: string
  slug: string
  role: Role
  created_at: string
}

export interface WireLogin {
  access_token: string
  refresh_token: string
  kdf_salt: string
  kdf_params: KdfParams
  wrapped_umk: string
  wrapped_privkey: string
  public_key: string
}

export interface WirePublicUser {
  user_id: string
  public_key: string
  kdf_salt: string
  kdf_params: KdfParams
}

export class Api {
  constructor(readonly http: Http) {}

  // --- auth & users ---
  register(body: {
    username: string
    auth_key: string
    kdf_salt: string
    wrapped_umk: string
    public_key: string
    wrapped_privkey: string
  }) {
    return this.http.post<unknown>('/auth/register', body, { auth: false })
  }
  login(body: { username: string; auth_key: string }) {
    return this.http.post<WireLogin>('/auth/login', body, { auth: false })
  }
  refresh(refreshToken: string) {
    return this.http.post<{ access_token: string; refresh_token: string }>(
      '/auth/refresh',
      { refresh_token: refreshToken },
      { auth: false },
    )
  }
  logout(refreshToken: string) {
    return this.http.post<void>('/auth/logout', { refresh_token: refreshToken }, { auth: false })
  }
  changePassphrase(body: {
    current_auth_key: string
    new_auth_key: string
    new_kdf_salt: string
    new_wrapped_umk: string
  }) {
    return this.http.post<void>('/auth/change-passphrase', body)
  }
  me() {
    return this.http.get<{ user_id: string; username: string; public_key: string; created_at: string }>('/users/me')
  }
  userByName(username: string) {
    return this.http.get<WirePublicUser>(`/users/${encodeURIComponent(username)}`, { auth: false })
  }
  deleteMe(currentAuthKey: string) {
    return this.http.request<void>('DELETE', '/users/me', { body: { current_auth_key: currentAuthKey } })
  }

  // --- apps ---
  listApps(slug?: string) {
    return this.http.get<WireApp[]>('/apps', { query: { slug } })
  }
  getApp(appId: string) {
    return this.http.get<WireApp>(`/apps/${appId}`)
  }
  createApp(body: { app_id: string; slug: string; encrypted_metadata: string; wrapped_dek: string }) {
    return this.http.post<WireApp>('/apps', body)
  }
  patchApp(appId: string, body: { encrypted_metadata: string; expected_version: number; dek_version: number }) {
    return this.http.patch<{ metadata_version: number }>(`/apps/${appId}`, body)
  }
  deleteApp(appId: string) {
    return this.http.delete<void>(`/apps/${appId}`)
  }
  leaveApp(appId: string) {
    return this.http.post<void>(`/apps/${appId}/leave`)
  }

  // --- rotation ---
  beginRotation(appId: string) {
    return this.http.post<{ rotation_id: string; base_dek_version: number; started_at: string }>(
      `/apps/${appId}/rotations`,
    )
  }
  stageRotation(
    appId: string,
    rotationId: string,
    rows: { id: string; expected_version: number; type: string; format: 1 | 2; encrypted_json: string }[],
  ) {
    return this.http.post<void>(`/apps/${appId}/rotations/${rotationId}/rows`, { rows })
  }
  commitRotation(
    appId: string,
    rotationId: string,
    body: { encrypted_metadata: string; expected_metadata_version: number; access: { user_id: string; wrapped_dek: string }[] },
  ) {
    return this.http.post<{ metadata_version: number; dek_version: number }>(
      `/apps/${appId}/rotations/${rotationId}/commit`,
      body,
    )
  }
  abortRotation(appId: string, rotationId: string) {
    return this.http.delete<void>(`/apps/${appId}/rotations/${rotationId}`)
  }

  // --- data ---
  listData(appId: string, query: WireListQuery = {}) {
    return this.http.get<WirePage>(`/apps/${appId}/data`, { query: { ...query } })
  }
  listDeleted(appId: string, query: { since?: string; cursor?: string; limit?: number } = {}) {
    return this.http.get<WireDeletedPage>(`/apps/${appId}/data/deleted`, { query })
  }
  batch(appId: string, body: WireBatch) {
    return this.http.post<WireBatchResult>(`/apps/${appId}/data/batch`, body)
  }

  // --- sharing ---
  listMembers(appId: string) {
    return this.http.get<WireMember[]>(`/apps/${appId}/shares`)
  }
  share(appId: string, body: { recipient_user_id: string; wrapped_dek: string; role: 'editor' | 'viewer' }) {
    return this.http.post<unknown>(`/apps/${appId}/shares`, body)
  }
  setRole(appId: string, userId: string, role: 'editor' | 'viewer') {
    return this.http.patch<unknown>(`/apps/${appId}/shares/${userId}`, { role })
  }
  removeMember(appId: string, userId: string) {
    return this.http.delete<void>(`/apps/${appId}/shares/${userId}`)
  }
  pendingShares() {
    return this.http.get<WirePendingShare[]>('/shares/pending')
  }
  acceptShare(appId: string) {
    return this.http.post<{ wrapped_dek: string }>(`/apps/${appId}/shares/accept`)
  }
  declineShare(appId: string) {
    return this.http.post<void>(`/apps/${appId}/shares/decline`)
  }
}
