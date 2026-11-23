import { SealbaseError } from 'sealbase-client'

/** A human-readable message for any error thrown by the lib. */
export function errorMessage(e) {
  if (e instanceof SealbaseError) {
    if (e.status === 0) return 'Cannot reach the server.'
    if (e.status === 403) return 'You don’t have permission to do that.'
    if (e.code === 'version_conflict') return 'Someone else changed this meanwhile. Reload and try again.'
    return e.message
  }
  return e?.message || String(e)
}
