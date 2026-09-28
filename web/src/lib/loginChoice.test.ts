import { describe, expect, it } from 'vitest'
import { issuerLabel, localFormStartsOpen, rememberLocalLogin } from './loginChoice'

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

const clean = { search: '' }

describe('localFormStartsOpen', () => {
  it('shows the form outright where there is nothing else to offer', () => {
    expect(localFormStartsOpen({ oidc_enabled: false }, memory(), clean)).toBe(true)
  })

  it('folds it away when the organization account is the way in', () => {
    expect(localFormStartsOpen({ oidc_enabled: true }, memory(), clean)).toBe(false)
  })

  it('leaves it open for a browser that signs in with an id and a password', () => {
    const store = memory()
    rememberLocalLogin(store)
    expect(localFormStartsOpen({ oidc_enabled: true }, store, clean)).toBe(true)
  })

  // Otherwise the only offer on the screen is the one that just failed.
  it('opens it when the round trip came back with an error', () => {
    expect(localFormStartsOpen({ oidc_enabled: true }, memory(), { search: '?error=oidc_unavailable' })).toBe(true)
  })

  // A provider that simply had no session is the ordinary answer, not a
  // failure, so the organization account stays the offer.
  it('keeps it folded after a silent attempt found no session', () => {
    expect(localFormStartsOpen({ oidc_enabled: true }, memory(), { search: '?sso=none' })).toBe(false)
  })

  it('survives storage that refuses to answer', () => {
    expect(() => rememberLocalLogin(broken())).not.toThrow()
    expect(localFormStartsOpen({ oidc_enabled: true }, broken(), clean)).toBe(false)
    expect(localFormStartsOpen({ oidc_enabled: false }, broken(), clean)).toBe(true)
  })
})

describe('issuerLabel', () => {
  it('names the host an operator configured', () => {
    expect(issuerLabel('https://keycloak.example.com/realms/corp')).toBe('keycloak.example.com')
  })
  it('says nothing when there is nothing readable to say', () => {
    expect(issuerLabel('')).toBe('')
    expect(issuerLabel(undefined)).toBe('')
    expect(issuerLabel('not a url')).toBe('')
  })
})
