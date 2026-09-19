import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { literalCalls, normalise, repoRoot, sourceFiles, webRoot } from '../../test/sourceScan'

// payloads.test.ts checks the body a screen sends; nothing checked the path
// it sends it to, nor the paths of `get`/`del`/`upload`, which carry no body.
// A route renamed on the server or misspelt on a screen therefore showed up
// only as a 404 at runtime. Every route is registered in one place --
// `s.handle("METHOD", "/path", ...)` in internal/web/server.go -- so this
// reads that table and holds every literal path the screens call against it.

type Route = { method: string; segments: string[] }

// One entry per registration, with `{id}`-style segments made comparable to
// the screens' `${...}`.
function serverRoutes(): Route[] {
  const source = readFileSync(join(repoRoot, 'internal/web/server.go'), 'utf8')
  const routes: Route[] = []
  for (const match of source.matchAll(/^\s*s\.handle\("([A-Z]+)", "([^"]+)"/gm)) routes.push({ method: match[1], segments: normalise(match[2]).split('/') })
  return routes
}

// The route a screen path names once its query string is dropped. A template
// tail glued straight onto a segment (`verify${full ? '?full=1' : ''}`) is
// a query string too -- a path segment would come after a `/` -- so it is
// dropped as well, and the `?` inside it never reaches the split.
function routeOf(path: string) {
  return normalise(path).split('?')[0].replace(/(?<!\/)\{\*\}$/, '')
}

// A `${...}` segment on the screen is usually an id, but ReviewDetail also
// spells the action name that way (`/review-requests/${id}/${path}` with
// `path` one of submit, approve, ...). This cannot read which, so a variable
// segment on either side matches anything in that position; every literal
// segment still has to be spelt exactly as the server registers it.
function registered(routes: Route[], method: string, path: string) {
  const segments = routeOf(path).split('/')
  return routes.some(r => r.method === method && r.segments.length === segments.length && r.segments.every((s, i) => s === segments[i] || s === '{*}' || segments[i] === '{*}'))
}

describe('API paths the screens write out', () => {
  const routes = serverRoutes()
  const calls = sourceFiles(join(webRoot, 'src')).flatMap(literalCalls)

  it('found the routes and the calls', () => {
    // Fewer than this means the parser stopped recognising the registrations,
    // not that the server lost routes.
    expect(routes.length).toBeGreaterThan(100)
    // Likewise fewer calls than this means the scanner broke, not that the
    // screens stopped calling the API.
    expect(calls.length).toBeGreaterThanOrEqual(40)
    expect(calls.filter(c => ['GET', 'DELETE'].includes(c.method)).length).toBeGreaterThanOrEqual(30)
  })

  it('go to a route the server registers', () => {
    const missing = calls
      .filter(c => !registered(routes, c.method, c.path))
      .map(c => `${c.file}:${c.line} ${c.method} ${c.path} (${c.fn}) — internal/web/server.go 에 등록된 라우트가 없습니다`)
    expect(missing).toEqual([])
  })
})
