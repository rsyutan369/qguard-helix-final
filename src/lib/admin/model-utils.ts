// Shared helpers for the Owner Admin console models (src/lib/admin/*).
// Pure and isomorphic: no Node or browser APIs.

import { csvCell } from '@/lib/csv'

export function text(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

export function lower(value: unknown): string {
  return text(value).toLowerCase()
}

export function timeOf(value: string | null | undefined): number | null {
  if (!value) return null
  const ms = Date.parse(value)
  return Number.isFinite(ms) ? ms : null
}

export function latestIso(...values: Array<string | null | undefined>): string | null {
  let best: number | null = null
  for (const value of values) {
    const ms = timeOf(value)
    if (ms !== null && (best === null || ms > best)) best = ms
  }
  return best === null ? null : new Date(best).toISOString()
}

export function fnv1a(input: string): string {
  let hash = 0x811c9dc5
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index)
    hash = Math.imul(hash, 0x01000193) >>> 0
  }
  return hash.toString(16).padStart(8, '0')
}

/** Deterministic JSON (sorted keys) — the input to versions and evidence hashes. */
export function canonicalJson(value: unknown, omitKeys: ReadonlySet<string> = new Set()): string {
  const seen = new WeakSet<object>()
  const walk = (node: unknown): unknown => {
    if (node === null || typeof node !== 'object') return node
    if (seen.has(node as object)) return null
    seen.add(node as object)
    if (Array.isArray(node)) return node.map(walk)
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(node as Record<string, unknown>).sort()) {
      if (omitKeys.has(key)) continue
      const child = (node as Record<string, unknown>)[key]
      if (child === undefined) continue
      out[key] = walk(child)
    }
    return out
  }
  return JSON.stringify(walk(value))
}

const CLOCK_KEYS = new Set(['generatedAt', 'measuredAt'])

/** A version that changes only when the model's DATA changes, never with the clock. */
export function modelVersion(value: unknown): string {
  return fnv1a(canonicalJson(value, CLOCK_KEYS))
}

export { csvCell }

export function toCsv<T>(columns: Array<{ header: string; value: (row: T) => unknown }>, rows: T[]): string {
  const lines = [columns.map((column) => csvCell(column.header)).join(',')]
  for (const row of rows) lines.push(columns.map((column) => csvCell(column.value(row))).join(','))
  return `﻿${lines.join('\r\n')}\r\n`
}

export function paginate<T>(rows: T[], pageInput: unknown, limitInput: unknown, maxLimit = 100) {
  const limit = Math.min(maxLimit, Math.max(1, Math.floor(Number(limitInput) || 25)))
  const totalPages = Math.max(1, Math.ceil(rows.length / limit))
  const page = Math.min(totalPages, Math.max(1, Math.floor(Number(pageInput) || 1)))
  const from = (page - 1) * limit
  return { rows: rows.slice(from, from + limit), pagination: { page, limit, total: rows.length, totalPages } }
}

export interface IntegrityCheck {
  id: string
  label: string
  ok: boolean
  detail: string
}

export type Severity = 'critical' | 'high' | 'warning' | 'info' | 'success'

/** One severity vocabulary for every event source (no invented escalation). */
export function normalizeSeverity(value: unknown): Severity {
  const raw = lower(value)
  if (raw === 'critical' || raw === 'severe') return 'critical'
  if (raw === 'high' || raw === 'error') return 'high'
  if (raw === 'warning' || raw === 'warn' || raw === 'medium' || raw === 'moderate') return 'warning'
  if (raw === 'success' || raw === 'ok') return 'success'
  return 'info'
}

export const SEVERITY_RANK: Record<Severity, number> = { critical: 5, high: 4, warning: 3, info: 2, success: 1 }
