// Thin fetch wrapper: bearer auth, one refresh-and-retry on 401, and typed
// errors. Knows nothing about crypto or app state.

export class SealbaseError extends Error {
  /** HTTP status, or 0 for a network failure. */
  readonly status: number
  /** Machine-readable code on 409s: `version_conflict`, `stale_dek`, `duplicate_id`, ... */
  readonly code: string | undefined
  readonly details: any

  constructor(status: number, message: string, code?: string, details?: unknown) {
    super(message)
    this.name = 'SealbaseError'
    this.status = status
    this.code = code
    this.details = details
  }
}

export function isConflict(err: unknown, code?: string): err is SealbaseError {
  return err instanceof SealbaseError && err.status === 409 && (code === undefined || err.code === code)
}

export type QueryValue = string | number | boolean | null | undefined | Array<string | number>

export interface RequestOptions {
  query?: Record<string, QueryValue>
  body?: unknown
  /** Defaults to true. */
  auth?: boolean
}

export interface AuthHooks {
  getAccessToken(): string | null
  /** Called once on a 401; returns a fresh access token or null. */
  refresh(): Promise<string | null>
}

export class Http {
  private readonly baseUrl: string
  private auth: AuthHooks = { getAccessToken: () => null, refresh: async () => null }
  private readonly fetchImpl: typeof fetch

  constructor(baseUrl: string, fetchImpl?: typeof fetch) {
    this.baseUrl = baseUrl.replace(/\/+$/, '')
    this.fetchImpl = fetchImpl ?? globalThis.fetch.bind(globalThis)
  }

  setAuth(hooks: AuthHooks): void {
    this.auth = hooks
  }

  get<T>(path: string, opts?: RequestOptions) {
    return this.request<T>('GET', path, opts)
  }
  post<T>(path: string, body?: unknown, opts?: RequestOptions) {
    return this.request<T>('POST', path, { ...opts, body })
  }
  patch<T>(path: string, body?: unknown, opts?: RequestOptions) {
    return this.request<T>('PATCH', path, { ...opts, body })
  }
  delete<T>(path: string, opts?: RequestOptions) {
    return this.request<T>('DELETE', path, opts)
  }

  async request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
    const useAuth = opts.auth !== false
    let res = await this.send(method, path, opts, useAuth ? this.auth.getAccessToken() : null)
    if (res.status === 401 && useAuth) {
      const token = await this.auth.refresh()
      if (token) res = await this.send(method, path, opts, token)
    }
    if (!res.ok) {
      let payload: any = null
      try {
        payload = await res.json()
      } catch {
        // non-JSON error body
      }
      throw new SealbaseError(res.status, payload?.error ?? res.statusText, payload?.code, payload?.details)
    }
    if (res.status === 204) return undefined as T
    const text = await res.text()
    return (text ? JSON.parse(text) : undefined) as T
  }

  private async send(method: string, path: string, opts: RequestOptions, token: string | null): Promise<Response> {
    const url = new URL(this.baseUrl + path)
    for (const [key, value] of Object.entries(opts.query ?? {})) {
      if (value === undefined || value === null) continue
      if (Array.isArray(value)) value.forEach((v) => url.searchParams.append(key, String(v)))
      else url.searchParams.set(key, String(value))
    }
    const headers: Record<string, string> = {}
    if (token) headers.authorization = `Bearer ${token}`
    if (opts.body !== undefined) headers['content-type'] = 'application/json'
    try {
      return await this.fetchImpl(url, {
        method,
        headers,
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      })
    } catch (e) {
      throw new SealbaseError(0, `network error: ${(e as Error).message}`)
    }
  }
}
