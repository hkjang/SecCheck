// A 401 means "you are not signed in". That is the news that a session has
// ended, and it is equally the ordinary answer to somebody who has not signed
// in yet -- so which of the two it is depends entirely on the path.
//
// /api/v1/me is the first call the shell makes on every load, including the
// very first one by a visitor who has never signed in. Reading that 401 as an
// ended session told them their session had expired when they had never had
// one, and, because the shell treats an ended session as a deliberate
// sign-out so that an idle timeout cannot be undone by signing straight back
// in, it also marked the tab signed out -- which switched off the silent SSO
// attempt before it could ever run. The shell remembers whether it ever held
// a session and decides for itself; this list only says the 401 is
// unremarkable on its own.
const anonymousPaths = ['/api/v1/auth/login', '/api/v1/public/config', '/api/v1/me']

/** Whether a 401 on this path is the end of a session rather than the state of an anonymous caller. */
export function announcesSessionEnd(path: string): boolean {
  return !anonymousPaths.some(p => path.startsWith(p))
}

// Loading the shell is somebody using the service, so /api/v1/me still counts
// against the idle timeout even though its 401 says nothing about a session.
const inactivePaths = anonymousPaths.filter(p => p !== '/api/v1/me')

/** Whether a call to this path is somebody using the service, for the idle timeout. */
export function countsAsActivity(path: string): boolean {
  return !inactivePaths.some(p => path.startsWith(p))
}
