// Somebody already signed in at the identity provider should land on the
// dashboard, not on this service's login screen. Before the login screen is
// drawn, the browser can go to the provider once with prompt=none: it answers
// from a session it already holds, or comes straight back refused. That
// refusal is the ordinary answer for a signed-out person -- and asking again
// after it is how the browser ends up bouncing between the provider and this
// service forever, with nothing on screen but a flicker. Everything here is
// about asking at most once.
//
// The attempt is a top-level navigation rather than a hidden iframe, so it
// works where third-party cookies are blocked and never depends on whether
// the provider allows being framed.

// sessionStorage, not localStorage: the mark belongs to this tab's session, so
// a new tab tries again while a reload after a refusal does not.
const ATTEMPTED_KEY = 'seccheck_sso_attempted'
const SIGNED_OUT_KEY = 'seccheck_sso_signed_out'

type Flags = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>
type Place = { pathname: string; search: string; hash?: string }

function flags(): Flags { return window.sessionStorage }
function here(): Place { return window.location }

function readFlag(store: Flags, key: string): boolean {
  try {
    return store.getItem(key) === '1'
  } catch {
    // Private browsing and blocked site data throw here. Reading that as "not
    // yet attempted" would attempt on every load, which is the loop this file
    // exists to prevent; "already attempted" is the side that fails closed.
    return true
  }
}

function writeFlag(store: Flags, key: string, value: boolean) {
  try {
    if (value) store.setItem(key, '1')
    else store.removeItem(key)
  } catch {
    // Nothing to do: readFlag already answers "attempted" when storage is out.
  }
}

/** Remembers that the person signed out on purpose, so they are not signed straight back in. */
export function markSignedOut(store: Flags = flags()) {
  writeFlag(store, SIGNED_OUT_KEY, true)
  writeFlag(store, ATTEMPTED_KEY, true)
}

/** Forgets the marks once a session exists again. */
export function clearSilentSso(store: Flags = flags()) {
  writeFlag(store, SIGNED_OUT_KEY, false)
  writeFlag(store, ATTEMPTED_KEY, false)
}

// Places the attempt must never start from. The sign-in round trip itself and
// its landing pages are where a loop would begin, and the API, MCP, health and
// proxy paths are not browser navigations at all.
const excludedPaths = ['/login', '/api', '/mcp', '/health', '/ready', '/metrics', '/momento']

/** Only an absolute path inside this service is a place worth returning to. */
export function safeReturnTo(value: string): string {
  if (!value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\') || /[\r\n]/.test(value)) return '/'
  return value
}

/**
 * Decides whether to ask the provider silently instead of drawing the login
 * screen. Three separate marks each say no on their own: the tab already
 * asked, the person signed out, or the address carries the refusal the
 * callback appended (`sso=none`) -- the last survives storage being wiped.
 */
export function shouldAttemptSilentSso(config: { oidc_enabled: boolean; oidc_auto_login?: boolean }, store: Flags = flags(), place: Place = here()): boolean {
  if (!config.oidc_enabled || !config.oidc_auto_login) return false
  const pathname = place.pathname || '/'
  if (excludedPaths.some(path => pathname === path || pathname.startsWith(path + '/'))) return false
  const params = new URLSearchParams(place.search)
  if (params.has('sso') || params.has('error')) return false
  if (readFlag(store, SIGNED_OUT_KEY)) return false
  if (readFlag(store, ATTEMPTED_KEY)) return false
  return true
}

/** The address the browser is sent to for one silent attempt that comes back to `place`. */
export function silentSsoAddress(place: Place = here()): string {
  const returnTo = safeReturnTo((place.pathname || '/') + (place.search || '') + (place.hash || ''))
  return `/api/v1/auth/oidc/start?prompt=none&return_to=${encodeURIComponent(returnTo)}`
}

/** Marks this tab as having asked, then hands the browser to the provider. */
export function beginSilentSso(store: Flags = flags(), place: Place = here()) {
  writeFlag(store, ATTEMPTED_KEY, true)
  window.location.assign(silentSsoAddress(place))
}
