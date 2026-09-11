import { describe, expect, it } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

// The server decodes a request body into named fields and silently drops
// whatever else arrives. A screen that sends `comment` to an endpoint that
// reads `reason` therefore does not get an error about the field -- it gets
// "reason is required" every time, as the withdraw and reopen dialogs did
// until 008c9ec. The table in internal/web/payloads.go says what each
// endpoint reads (and a Go test keeps that table honest against the
// handlers); this reads every literal body the screens send and checks each
// key against it. Bodies built elsewhere (`post(path, form)`) cannot be read
// here and are left alone.

const webRoot = fileURLToPath(new URL('../..', import.meta.url))
const repoRoot = join(webRoot, '..')

type Body = { file: string; line: number; method: string; path: string; keys: string[] }

function serverPayloads(): Map<string, string[]> {
  const source = readFileSync(join(repoRoot, 'internal/web/payloads.go'), 'utf8')
  const table = new Map<string, string[]>()
  const entry = /^\s*"((?:POST|PUT|PATCH) \S+)":\s*\{((?:\{"[^"]+", "[^"]+"\},? ?)+)\},$/gm
  for (const match of source.matchAll(entry)) {
    const names = [...match[2].matchAll(/\{"([^"]+)", "[^"]+"\}/g)].map(m => m[1])
    table.set(normalise(match[1]), names)
  }
  return table
}

// `{id}` on the server and `${review.id}` on the screen name the same
// segment; neither side's spelling matters for finding the row.
function normalise(route: string) {
  return route.replace(/\$?\{[^}]*\}/g, '{*}')
}

function sourceFiles(dir: string): string[] {
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
function skipBalanced(src: string, at: number): number {
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

// The keys an object literal spells out. A spread or a computed key means
// the literal does not say everything it sends; the keys it does name are
// still checked.
function literalKeys(literal: string): string[] {
  const inner = literal.slice(1, -1)
  const parts: string[] = []
  let depth = 0, start = 0
  for (let i = 0; i < inner.length; i++) {
    const c = inner[i]
    if (c === "'" || c === '"' || c === '`') { i = skipBalanced(inner, i) - 1; continue }
    if ('{([<'.includes(c)) depth++
    else if ('})]>'.includes(c)) depth--
    else if (c === ',' && depth === 0) { parts.push(inner.slice(start, i)); start = i + 1 }
  }
  parts.push(inner.slice(start))
  const keys: string[] = []
  for (const part of parts) {
    const text = part.trim()
    if (!text || text.startsWith('...') || text.startsWith('[')) continue
    const named = /^(?:([A-Za-z_$][\w$]*)|'([^']+)'|"([^"]+)")\s*(?::|$)/.exec(text)
    if (named) keys.push(named[1] ?? named[2] ?? named[3])
  }
  return keys
}

function pathOf(src: string, at: number): { path: string; end: number } | null {
  const quote = src[at]
  if (quote !== "'" && quote !== '"' && quote !== '`') return null
  const end = skipBalanced(src, at)
  return { path: src.slice(at + 1, end - 1), end }
}

function lineOf(src: string, at: number) { return src.slice(0, at).split('\n').length }

// Every `post(path, { ... })`, `put`, `patch`, and every `api(path, { method,
// body: JSON.stringify({ ... }) })` whose body is written out at the call.
function literalBodies(file: string): Body[] {
  const src = readFileSync(file, 'utf8')
  const rel = file.slice(webRoot.length)
  const bodies: Body[] = []
  const call = /\b(post|put|patch|api)(?=<|\()/g
  for (const match of src.matchAll(call)) {
    let i = match.index! + match[0].length
    if (src[i] === '<') i = skipBalanced(src, i)
    if (src[i] !== '(') continue
    let j = i + 1
    while (/\s/.test(src[j])) j++
    const first = pathOf(src, j)
    if (!first) continue
    j = first.end
    while (/\s/.test(src[j])) j++
    if (src[j] !== ',') continue
    j++
    while (/\s/.test(src[j])) j++
    if (src[j] !== '{') continue
    const literal = src.slice(j, skipBalanced(src, j))
    const line = lineOf(src, match.index!)
    if (match[1] !== 'api') {
      bodies.push({ file: rel, line, method: match[1].toUpperCase(), path: first.path, keys: literalKeys(literal) })
      continue
    }
    // api(path, { method: 'PATCH', body: JSON.stringify({ ... }) })
    const method = /method:\s*'(POST|PUT|PATCH)'/.exec(literal)
    const stringify = literal.indexOf('JSON.stringify(')
    if (!method || stringify < 0) continue
    let k = stringify + 'JSON.stringify('.length
    while (/\s/.test(literal[k])) k++
    if (literal[k] !== '{') continue
    bodies.push({ file: rel, line, method: method[1], path: first.path, keys: literalKeys(literal.slice(k, skipBalanced(literal, k))) })
  }
  return bodies
}

describe('request bodies the screens write out', () => {
  const table = serverPayloads()
  const bodies = sourceFiles(join(webRoot, 'src')).flatMap(literalBodies)

  it('found the table and the calls', () => {
    expect(table.size).toBeGreaterThan(30)
    // Fewer than this means the scanner stopped recognising the calls, not
    // that the screens stopped sending bodies.
    expect(bodies.length).toBeGreaterThanOrEqual(15)
  })

  it('go to an endpoint the server decodes a body for', () => {
    const unknown = bodies
      .filter(b => !table.has(`${b.method} ${normalise(b.path)}`))
      .map(b => `${b.file}:${b.line} ${b.method} ${b.path} sends { ${b.keys.join(', ')} } but internal/web/payloads.go lists no body for it`)
    expect(unknown).toEqual([])
  })

  it('name only fields the server reads', () => {
    const wrong: string[] = []
    for (const b of bodies) {
      const fields = table.get(`${b.method} ${normalise(b.path)}`)
      if (!fields) continue
      for (const key of b.keys) {
        if (!fields.includes(key)) wrong.push(`${b.file}:${b.line} sends \`${key}\` to ${b.method} ${b.path}, which reads only: ${fields.join(', ')}`)
      }
    }
    expect(wrong).toEqual([])
  })
})
