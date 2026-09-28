// With SSO configured, the organization account is the way almost everybody
// gets in, and the identity provider is where password policy, lockout and
// the second factor actually live. The login screen puts that button first
// and folds the local form away behind it -- but folding it away for the
// people who do sign in locally would cost them a click on every visit, so
// the screen remembers which way worked last.

const LAST_METHOD_KEY = 'seccheck_login_method'

type Flags = Pick<Storage, 'getItem' | 'setItem'>
type Place = { search: string }

function memory(): Flags { return window.localStorage }
function here(): Place { return window.location }

/** Records that this browser signed in with an id and a password. */
export function rememberLocalLogin(store: Flags = memory()) {
  try {
    store.setItem(LAST_METHOD_KEY, 'local')
  } catch {
    // Private browsing and blocked site data throw. The form simply starts
    // folded next time, which costs one click and breaks nothing.
  }
}

function signedInLocallyBefore(store: Flags): boolean {
  try {
    return store.getItem(LAST_METHOD_KEY) === 'local'
  } catch {
    return false
  }
}

/**
 * Whether the id-and-password form is open when the screen is drawn. It is,
 * unless the organization account is the obvious way in: SSO configured, this
 * browser never signed in locally, and nothing on the address bar says the
 * round trip just failed. A failed SSO attempt opens it, because otherwise
 * the only offer on the screen is the one that just did not work.
 */
export function localFormStartsOpen(config: { oidc_enabled: boolean }, store: Flags = memory(), place: Place = here()): boolean {
  if (!config.oidc_enabled) return true
  if (new URLSearchParams(place.search).has('error')) return true
  return signedInLocallyBefore(store)
}

/** The host an operator configured, for the line under the button. Empty when it is not a readable address. */
export function issuerLabel(issuer?: string): string {
  if (!issuer) return ''
  try {
    return new URL(issuer).host
  } catch {
    return ''
  }
}
