import type { ComponentType } from 'react'
import { renderToString } from 'react-dom/server'
import { MemoryRouter } from 'react-router-dom'

/**
 * Shared case runner for tools/intel-ops-render. A case describes what each
 * live hook returns (keyed by the SSE event name the real hook subscribes to)
 * and what the rendered text must / must not contain.
 */

export type LiveState = 'loading' | 'success' | 'error'
export type LiveTransport = 'connecting' | 'stream' | 'polling' | 'offline'

export interface LiveCase {
  /** The model the page receives; null = the server has not answered. */
  payload: unknown
  state?: LiveState
  transport?: LiveTransport
  error?: string | null
  lastVerifiedAt?: string | null
}

export interface RenderCase {
  name: string
  /** Keyed by SSE event name (`drift`, `correlation`, `orchestrator`, …). */
  live: Record<string, LiveCase>
  /** Other stubbed hooks: `scanner` (useScannerIntelligence), `workflow` (useMigrationWorkflow). */
  hooks?: Record<string, unknown>
  expect?: string[]
  forbid?: string[]
}

export interface PageCases {
  page: string
  path: string
  Page: ComponentType
  cases: RenderCase[]
  /** Strings that must never render in ANY case — removed defects. */
  forbidAlways?: string[]
}

function textOf(html: string): string {
  return html
    .replace(/<style[\s\S]*?<\/style>/g, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&#x27;|&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ')
}

function forbiddenPattern(value: string): RegExp {
  const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return new RegExp(`(?<![A-Za-z0-9])${escaped}(?![A-Za-z0-9])`)
}

export function renderCases(spec: PageCases): void {
  let failures = 0
  const consoleErrors: string[] = []
  const originalError = console.error
  console.error = (...args: unknown[]) => { consoleErrors.push(args.map(String).join(' ')) }

  for (const c of spec.cases) {
    ;(globalThis as Record<string, unknown>).__LIVE_CASE__ = c.live
    ;(globalThis as Record<string, unknown>).__HOOK_FIXTURES__ = c.hooks || {}
    consoleErrors.length = 0
    let html = ''
    let crash = ''
    try {
      html = renderToString(<MemoryRouter initialEntries={[spec.path]}><spec.Page /></MemoryRouter>)
    } catch (error) {
      crash = error instanceof Error ? `${error.message}\n${error.stack?.split('\n').slice(1, 5).join('\n')}` : String(error)
    }
    const text = textOf(html)
    const lower = text.toLowerCase()
    // CSS `uppercase` does not change markup, but labels are matched case-insensitively anyway.
    const missing = (c.expect || []).filter((e) => !lower.includes(e.toLowerCase()))
    // Forbidden strings match case-sensitively on token boundaries: a
    // case-insensitive 'NaN' matched every 'tenant'.
    const forbidden = [...(c.forbid || []), ...(spec.forbidAlways || [])].filter((f) => forbiddenPattern(f).test(text))
    const ok = !crash && !missing.length && !forbidden.length && consoleErrors.length === 0
    if (!ok) failures += 1
    process.stdout.write(`  ${ok ? 'PASS' : 'FAIL'}  [${c.name}] ${spec.path}  (${html.length} bytes)\n`)
    if (crash) process.stdout.write(`        crash: ${crash}\n`)
    if (missing.length) process.stdout.write(`        missing text: ${missing.join(' | ')}\n`)
    if (forbidden.length) process.stdout.write(`        forbidden text rendered: ${forbidden.join(' | ')}\n`)
    for (const f of forbidden) {
      const at = text.search(forbiddenPattern(f))
      process.stdout.write(`          …${text.slice(Math.max(0, at - 90), at + 40)}…\n`)
    }
    for (const e of consoleErrors.slice(0, 3)) process.stdout.write(`        console.error: ${e.slice(0, 400)}\n`)
  }
  console.error = originalError
  process.stdout.write(`  ${spec.cases.length} render(s) for ${spec.page} — ${failures} failed\n`)
  process.exitCode = failures ? 1 : 0
}
