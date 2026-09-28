import { describe, expect, it } from 'vitest'
import { announcesSessionEnd, countsAsActivity } from './sessionPaths'

// A 401 means "you are not signed in", which is the ordinary answer to an
// anonymous caller as well as the news that a session has ended. Reading the
// first as the second told a first-time visitor their session had expired --
// and, because the shell treats an ended session as a deliberate sign-out so
// that an idle timeout cannot be undone by signing straight back in, it also
// switched off the silent SSO attempt before it could ever run.
describe('announcesSessionEnd', () => {
  it('leaves the calls a signed-out visitor makes on every load alone', () => {
    expect(announcesSessionEnd('/api/v1/me')).toBe(false)
    expect(announcesSessionEnd('/api/v1/public/config')).toBe(false)
    expect(announcesSessionEnd('/api/v1/auth/login')).toBe(false)
  })

  it('still reports a 401 from anywhere only a signed-in caller goes', () => {
    expect(announcesSessionEnd('/api/v1/review-requests')).toBe(true)
    expect(announcesSessionEnd('/api/v1/dashboard')).toBe(true)
    expect(announcesSessionEnd('/api/v1/admin/users')).toBe(true)
  })
})

// Loading the shell is somebody using the service; the idle clock must not
// treat it as silence just because its 401 is unremarkable.
describe('countsAsActivity', () => {
  it('counts the shell loading and every signed-in call', () => {
    expect(countsAsActivity('/api/v1/me')).toBe(true)
    expect(countsAsActivity('/api/v1/review-requests')).toBe(true)
  })
  it('does not count signing in or reading the public config', () => {
    expect(countsAsActivity('/api/v1/auth/login')).toBe(false)
    expect(countsAsActivity('/api/v1/public/config')).toBe(false)
  })
})
