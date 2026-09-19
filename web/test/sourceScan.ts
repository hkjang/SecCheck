import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

// The static-contract tests (payloads.test.ts, routes.test.ts) read the
// screens' source and hold what they find against the server. Both must read
// a call the same way -- a path parsed differently by the two of them is the
// same bug they exist to catch -- so the reading lives here, once.
//
// This file sits outside `src` because the app's tsconfig type-checks
// everything under it and the build has no Node typings for `node:fs`; vitest
// transpiles it fine from here.

export const webRoot = fileURLToPath(new URL('..', import.meta.url))
export const repoRoot = join(webRoot, '..')

// `{id}` on the server and `${review.id}` on the screen name the same
// segment; neither side's spelling matters for finding the row.
export function normalise(route: string) {
  return route.replace(/\$?\{[^}]*\}/g, '{*}')
}

export function sourceFiles(dir: string): string[] {
  const out: string[] = []
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    if (statSync(full).isDirectory()) out.push(...sourceFiles(full))
    else if (/\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name) && full !== join(webRoot, 'src/lib/api.ts')) out.push(full)
  }
  return out
}

// Reads a balanced run of source starting at `at` (which must be the opening
// bracket or quote) and returns the index just past its close. Strings and
// template literals are skipped as units so a brace inside a message does
// not count.
export function skipBalanced(src: string, at: number): number {
  const open = src[at]
  if (open === "'" || open === '"') {
    for (let i = at + 1; i < src.length; i++) {
      if (src[i] === '\\') i++
      else if (src[i] === open) return i + 1
    }
    throw new Error(`unterminated string at ${at}`)
  }
  if (open === '`') {
    for (let i = at + 1; i < src.length; i++) {
      if (src[i] === '\\') i++
      else if (src[i] === '$' && src[i + 1] === '{') i = skipBalanced(src, i + 1) - 1
      else if (src[i] === '`') return i + 1
    }
    throw new Error(`unterminated template at ${at}`)
  }
  const close = { '{': '}', '(': ')', '[': ']', '<': '>' }[open]
  if (!close) throw new Error(`not a bracket: ${open}`)
  let depth = 0
  for (let i = at; i < src.length; i++) {
    const c = src[i]
    if (c === "'" || c === '"' || c === '`') { i = skipBalanced(src, i) - 1; continue }
    if (c === open) depth++
    else if (c === close && --depth === 0) return i + 1
  }
  throw new Error(`unbalanced ${open} at ${at}`)
}

export function pathOf(src: string, at: number): { path: string; end: number } | null {
  const quote = src[at]
  if (quote !== "'" && quote !== '"' && quote !== '`') return null
  const end = skipBalanced(src, at)
  return { path: src.slice(at + 1, end - 1), end }
}

export function lineOf(src: string, at: number) { return src.slice(0, at).split('\n').length }

export type Call = { file: string; line: number; fn: string; method: string; path: string }

const methodOf: Record<string, string> = { get: 'GET', post: 'POST', put: 'PUT', patch: 'PATCH', del: 'DELETE', upload: 'POST' }

// Every `get(path)`, `post`, `put`, `patch`, `del`, `upload` and every
// `api(path, { method: 'X' })` whose path is written out at the call. A call
// whose path is a variable (`get(path)`) or whose method is computed is not a
// contract this can read and is skipped. Member calls such as
// `search.get('item')` or `headers.get(...)` are not the API helpers.
export function literalCalls(file: string): Call[] {
  const src = readFileSync(file, 'utf8')
  const rel = file.slice(webRoot.length)
  const calls: Call[] = []
  const call = /(?<![.\w$])(get|post|put|patch|del|upload|api)(?=<|\()/g
  for (const match of src.matchAll(call)) {
    let i = match.index! + match[0].length
    if (src[i] === '<') i = skipBalanced(src, i)
    if (src[i] !== '(') continue
    let j = i + 1
    while (/\s/.test(src[j])) j++
    const first = pathOf(src, j)
    if (!first || !first.path.startsWith('/')) continue
    const line = lineOf(src, match.index!)
    if (match[1] !== 'api') {
      calls.push({ file: rel, line, fn: match[1], method: methodOf[match[1]], path: first.path })
      continue
    }
    // api(path, { method: 'DELETE' })
    j = first.end
    while (/\s/.test(src[j])) j++
    if (src[j] !== ',') continue
    j++
    while (/\s/.test(src[j])) j++
    if (src[j] !== '{') continue
    const init = src.slice(j, skipBalanced(src, j))
    const method = /method:\s*'(GET|POST|PUT|PATCH|DELETE)'/.exec(init)
    if (!method) continue
    calls.push({ file: rel, line, fn: 'api', method: method[1], path: first.path })
  }
  return calls
}
