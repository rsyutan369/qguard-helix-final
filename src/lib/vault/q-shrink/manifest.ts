/**
 * Q-Shrink Vault Engine™ — Hashing & Chunk-Level Merkle Integrity
 *
 * Uses the same SHA3-256 primitive as the rest of the vault. Provides:
 *  - hex helpers,
 *  - a chunk-level Merkle root over unique-chunk hashes (integrity that is
 *    independent of, and additional to, the envelope Merkle that
 *    `encryptFileLocal` builds over the sealed package).
 */

import { sha3_256 } from '@noble/hashes/sha3.js'

export function toHex(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0')
  return out
}

export function fromHex(hex: string): Uint8Array {
  const matches = hex.match(/.{1,2}/g)
  if (!matches) return new Uint8Array(0)
  return new Uint8Array(matches.map((b) => parseInt(b, 16)))
}

export function sha3Hex(data: Uint8Array): string {
  return toHex(sha3_256(data))
}

function hashPair(leftHex: string, rightHex: string): string {
  const left = fromHex(leftHex)
  const right = fromHex(rightHex)
  const combined = new Uint8Array(left.length + right.length)
  combined.set(left, 0)
  combined.set(right, left.length)
  return toHex(sha3_256(combined))
}

/**
 * SHA3-256 Merkle root over an ordered list of leaf hashes (hex). Odd nodes are
 * promoted unchanged — identical to the construction in `merkle-tree.ts`, kept
 * local so this module operates over hashes rather than raw data. Empty input
 * yields the hash of the empty string for a well-defined commitment.
 */
export function merkleRootFromLeafHashes(leaves: string[]): string {
  if (leaves.length === 0) return sha3Hex(new Uint8Array(0))
  let layer = leaves
  while (layer.length > 1) {
    const next: string[] = []
    for (let i = 0; i < layer.length; i += 2) {
      next.push(i + 1 < layer.length ? hashPair(layer[i], layer[i + 1]) : layer[i])
    }
    layer = next
  }
  return layer[0]
}
