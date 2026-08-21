let csrfToken = sessionStorage.getItem('seccheck_csrf') || ''

export class ApiError extends Error {
  status: number
  code: string
  details: unknown
  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message)
    this.status = status
    this.code = code
    this.details = details
  }
}

export function setCSRF(value: string) {
  csrfToken = value
  if (value) sessionStorage.setItem('seccheck_csrf', value)
  else sessionStorage.removeItem('seccheck_csrf')
}

// A session can end while the tab is open — the idle timeout expires it, an
// administrator revokes it, a password change ends the others. Every request
// then fails with 401, and without central handling each screen just shows an
// error toast and the person is left on a page that no longer works. The
// events below let the shell react once instead.
type SessionEvent = 'expired' | 'enrollment-required'
const sessionListeners = new Set<(event: SessionEvent) => void>()
export function onSessionEvent(listener: (event: SessionEvent) => void) {
  sessionListeners.add(listener)
  return () => { sessionListeners.delete(listener) }
}
function announce(event: SessionEvent) { sessionListeners.forEach(listener => listener(event)) }

// Sign-in and the public config legitimately answer 401/403 to an anonymous
// caller; those must not be read as a session ending.
const anonymousPaths = ['/api/v1/auth/login', '/api/v1/public/config']

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  if (init.body && !(init.body instanceof FormData)) headers.set('Content-Type', 'application/json')
  if (csrfToken && init.method && !['GET', 'HEAD'].includes(init.method)) headers.set('X-CSRF-Token', csrfToken)
  headers.set('Accept', 'application/json')
  const response = await fetch(path, { ...init, headers, credentials: 'same-origin' })
  if (response.status === 204) return undefined as T
  const type = response.headers.get('content-type') || ''
  const value = type.includes('json') ? await response.json() : await response.text()
  if (!response.ok) {
    const problem = value?.error || {}
    const error = new ApiError(response.status, problem.code || 'REQUEST_FAILED', problem.message || String(value), problem.details)
    if (!anonymousPaths.some(p => path.startsWith(p))) {
      if (response.status === 401) { setCSRF(''); announce('expired') }
      else if (error.code === 'TOTP_ENROLLMENT_REQUIRED') announce('enrollment-required')
    }
    throw error
  }
  return value as T
}

export const get = <T>(path: string) => api<T>(path)
export const post = <T>(path: string, data?: unknown) => api<T>(path, { method: 'POST', body: data === undefined ? undefined : JSON.stringify(data) })
export const put = <T>(path: string, data: unknown) => api<T>(path, { method: 'PUT', body: JSON.stringify(data) })
export const patch = <T>(path: string, data: unknown) => api<T>(path, { method: 'PATCH', body: JSON.stringify(data) })
export const del = <T>(path: string) => api<T>(path, { method: 'DELETE' })
export const upload = <T>(path: string, form: FormData) => api<T>(path, { method: 'POST', body: form })

export function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : '요청을 처리하지 못했습니다.'
}
