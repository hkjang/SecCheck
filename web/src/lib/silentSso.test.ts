import { describe, expect, it } from 'vitest'
import { clearSilentSso, markSignedOut, safeReturnTo, shouldAttemptSilentSso, silentSsoAddress } from './silentSso'

// prompt=none never draws a screen: the provider either signs the person in
// or comes straight back with login_required. Trying again after that answer
// is what bounces the browser between the provider and this service without
// end, so every rule here is a reason not to try.

function memory(): Storage {
  const values = new Map<string, string>()
  return {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => { values.set(key, value) },
    removeItem: key => { values.delete(key) },
    clear: () => values.clear(),
    key: () => null,
    get length() { return values.size },
  }
}

// Private browsing and blocked site data throw on every access.
function broken(): Storage {
  const refuse = () => { throw new DOMException('The operation is insecure.', 'SecurityError') }
  return { getItem: refuse, setItem: refuse, removeItem: refuse, clear: refuse, key: refuse, length: 0 }
}

const on = { oidc_enabled: true, oidc_auto_login: true }
const home = { pathname: '/', search: '' }

describe('shouldAttemptSilentSso', () => {
  it('is off unless SSO is on and the administrator turned auto_login on', () => {
    expect(shouldAttemptSilentSso({ oidc_enabled: false, oidc_auto_login: true }, memory(), home)).toBe(false)
    expect(shouldAttemptSilentSso({ oidc_enabled: true, oidc_auto_login: false }, memory(), home)).toBe(false)
    expect(shouldAttemptSilentSso({ oidc_enabled: true }, memory(), home)).toBe(false)
    expect(shouldAttemptSilentSso(on, memory(), home)).toBe(true)
  })

  it('asks once per tab session, and a reload after the answer does not ask again', () => {
    const store = memory()
    expect(shouldAttemptSilentSso(on, store, home)).toBe(true)
    // beginSilentSso marks the tab before navigating; the mark alone is the rule.
    store.setItem('seccheck_sso_attempted', '1')
    expect(shouldAttemptSilentSso(on, store, home)).toBe(false)
    // A new tab has its own sessionStorage and asks again.
    expect(shouldAttemptSilentSso(on, memory(), home)).toBe(true)
  })

  it('does not sign somebody back in right after they signed out, until a session exists again', () => {
    const store = memory()
    markSignedOut(store)
    expect(shouldAttemptSilentSso(on, store, home)).toBe(false)
    clearSilentSso(store)
    expect(shouldAttemptSilentSso(on, store, home)).toBe(true)
  })

  it('reads the refusal the callback left in the address, even with storage wiped', () => {
    expect(shouldAttemptSilentSso(on, memory(), { pathname: '/login', search: '?sso=none' })).toBe(false)
    expect(shouldAttemptSilentSso(on, memory(), { pathname: '/', search: '?sso=none' })).toBe(false)
    // An outright provider error is shown on the login screen; it is not a
    // reason to go and ask again either.
    expect(shouldAttemptSilentSso(on, memory(), { pathname: '/', search: '?error=access_denied' })).toBe(false)
  })

  it('treats storage it cannot read as already attempted', () => {
    expect(shouldAttemptSilentSso(on, broken(), home)).toBe(false)
    // And the marks that cannot be written do not throw out of the caller.
    expect(() => markSignedOut(broken())).not.toThrow()
    expect(() => clearSilentSso(broken())).not.toThrow()
  })

  it('never starts from the sign-in round trip or from paths that are not screens', () => {
    for (const pathname of ['/login', '/api/v1/auth/oidc/callback', '/api', '/mcp', '/mcp/sse', '/health', '/ready', '/metrics', '/momento/x']) {
      expect(shouldAttemptSilentSso(on, memory(), { pathname, search: '' }), pathname).toBe(false)
    }
    for (const pathname of ['/', '/reviews/abc', '/admin/settings', '/apiary']) {
      expect(shouldAttemptSilentSso(on, memory(), { pathname, search: '' }), pathname).toBe(true)
    }
  })
})

describe('silentSsoAddress', () => {
  it('asks with prompt=none and carries the deep link back', () => {
    expect(silentSsoAddress({ pathname: '/reviews/abc', search: '?item=7', hash: '#top' }))
      .toBe('/api/v1/auth/oidc/start?prompt=none&return_to=' + encodeURIComponent('/reviews/abc?item=7#top'))
    expect(silentSsoAddress(home)).toBe('/api/v1/auth/oidc/start?prompt=none&return_to=%2F')
  })
})

describe('safeReturnTo', () => {
  it('keeps only an absolute path inside this service', () => {
    expect(safeReturnTo('/reviews/abc?x=1')).toBe('/reviews/abc?x=1')
    for (const outside of ['', 'reviews', 'https://evil.example/', '//evil.example/x', '/\\evil.example', '/x\r\nSet-Cookie: a=b']) {
      expect(safeReturnTo(outside), JSON.stringify(outside)).toBe('/')
    }
  })
})
