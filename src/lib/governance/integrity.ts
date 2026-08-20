/**
 * Evidence integrity — content digests and what they honestly prove.
 *
 * Every evidence record carries a SHA3-256 digest computed over the CANONICAL
 * (sorted-key) form of the fields that constitute the evidence. That digest is
 * recomputed on every read.
 *
 * WHAT THIS PROVES
 * ----------------
 * When a digest has been ANCHORED — persisted at first observation in
 * `governance_evidence_anchors` — a later read that produces a different digest
 * proves the source record changed after it was anchored. That is genuine
 * tamper-evidence for the evidence content.
 *
 * WHAT THIS DOES NOT PROVE
 * ------------------------
 * It does not make the underlying row immutable, and it does not prove the row
 * existed at the anchored time to any third party. The anchor store lives in the
 * same database as the evidence. The UI must therefore say "tamper-evident" and
 * never "immutable", and must show `unanchored` records as exactly that rather
 * than implying verification. `assuranceFor()` returns that wording so no
 * caller has to invent it.
 */

import { sha3_256 } from '@noble/hashes/sha3.js'
import type { EvidenceIntegrity, IntegrityState } from './types'

/** Deterministic JSON with sorted keys — the canonical form that gets hashed. */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null)
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalize(entry)).join(',')}]`
  const record = value as Record<string, unknown>
  const keys = Object.keys(record).sort()
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`).join(',')}}`
}

function toHex(bytes: Uint8Array): string {
  let out = ''
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0')
  return out
}

/** SHA3-256 over the canonical form of `payload`. */
export function contentDigest(payload: unknown): string {
  return toHex(sha3_256(new TextEncoder().encode(canonicalize(payload))))
}

export const ASSURANCE: Record<IntegrityState, string> = {
  verified:
    'Content digest recomputed at read time matches the digest anchored when this evidence was first observed — the record has not changed since anchoring.',
  mismatch:
    'Content digest recomputed at read time DIFFERS from the anchored digest — the source record changed after it was anchored. Investigate before relying on it.',
  unanchored:
    'A content digest was computed at read time, but this record has never been anchored, so there is no earlier digest to compare it against. Anchor it to make future changes detectable.',
  unavailable:
    'The evidence anchor store is not available in this environment, so integrity cannot be established. Apply the governance schema to enable tamper-evident anchoring.',
}

export function assuranceFor(state: IntegrityState): string {
  return ASSURANCE[state]
}

export interface AnchorRow {
  evidence_id?: unknown
  digest?: unknown
  algorithm?: unknown
  anchored_at?: unknown
  created_at?: unknown
}

/**
 * Builds the integrity block for one evidence record.
 *
 * `anchors` is null when the anchor store is unavailable — which yields
 * `unavailable`, never a false `verified`.
 */
export function buildIntegrity(
  evidenceId: string,
  payload: unknown,
  anchors: Map<string, { digest: string; anchoredAt: string | null }> | null,
  now: number,
): EvidenceIntegrity {
  const digest = contentDigest(payload)
  const computedAt = new Date(now).toISOString()

  if (!anchors) {
    return {
      algorithm: 'SHA3-256',
      digest,
      computedAt,
      state: 'unavailable',
      anchoredAt: null,
      assurance: ASSURANCE.unavailable,
    }
  }

  const anchor = anchors.get(evidenceId)
  if (!anchor) {
    return {
      algorithm: 'SHA3-256',
      digest,
      computedAt,
      state: 'unanchored',
      anchoredAt: null,
      assurance: ASSURANCE.unanchored,
    }
  }

  const state: IntegrityState = anchor.digest === digest ? 'verified' : 'mismatch'
  return {
    algorithm: 'SHA3-256',
    digest,
    computedAt,
    state,
    anchoredAt: anchor.anchoredAt,
    assurance: ASSURANCE[state],
  }
}
