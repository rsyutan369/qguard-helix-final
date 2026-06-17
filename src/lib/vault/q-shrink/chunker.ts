/**
 * Q-Shrink Vault Engine™ — Content-Defined Chunking (FastCDC)
 *
 * Splits data on *content* boundaries (a rolling gear hash) rather than fixed
 * offsets. Content-defined boundaries are shift-resistant: inserting a byte near
 * the start of a file only re-chunks the region around the insertion, so
 * unchanged regions still produce identical chunks and deduplicate cleanly
 * across file versions and across files in a folder bundle.
 *
 * Correctness note: restoration never re-runs the chunker. The manifest records
 * the exact (offset, length) of every chunk, so reconstruction is byte-exact
 * regardless of chunker tuning. The gear table is generated deterministically
 * from a fixed seed purely so analysis runs are reproducible.
 */

export interface ChunkBoundary {
  start: number
  end: number
}

export interface ChunkerParams {
  minSize: number
  avgSize: number
  maxSize: number
}

// Tuned for vault objects: small enough to expose duplicate blocks in backups,
// logs, and DB dumps; large enough to keep manifest/sequence overhead modest.
export const DEFAULT_CHUNKER_PARAMS: ChunkerParams = {
  minSize: 2 * 1024, // 2 KiB
  avgSize: 8 * 1024, // 8 KiB target
  maxSize: 64 * 1024, // 64 KiB
}

/**
 * Deterministic 256-entry gear table of 32-bit values, derived from a fixed
 * seed via splitmix32. Deterministic so that the same bytes always chunk the
 * same way (reproducible analysis, stable cross-file dedup).
 */
const GEAR = buildGearTable(0x1f83d9ab)

function buildGearTable(seed: number): Uint32Array {
  const table = new Uint32Array(256)
  let state = seed >>> 0
  for (let i = 0; i < 256; i++) {
    // splitmix32
    state = (state + 0x9e3779b9) >>> 0
    let z = state
    z = Math.imul(z ^ (z >>> 16), 0x21f0aaad) >>> 0
    z = Math.imul(z ^ (z >>> 15), 0x735a2d97) >>> 0
    table[i] = (z ^ (z >>> 15)) >>> 0
  }
  return table
}

// Normalized chunking masks. Below the average size we use a stricter mask
// (more zero bits required → cuts are rarer → chunks grow toward the average);
// above the average we relax it so a boundary is found soon after the target.
const MASK_S = (1 << 15) - 1 // 15 bits: P(cut) ≈ 2^-15 before avg
const MASK_L = (1 << 11) - 1 // 11 bits: P(cut) ≈ 2^-11 after avg

/** Find the next content-defined cut point in `[start, n)`. */
function nextCut(data: Uint8Array, start: number, params: ChunkerParams): number {
  const n = data.length
  let remaining = n - start
  if (remaining <= params.minSize) return n

  const maxEnd = Math.min(n, start + params.maxSize)
  const normalEnd = Math.min(maxEnd, start + params.avgSize)

  let hash = 0
  let i = start + params.minSize // skip the minimum run; never cut below minSize

  for (; i < normalEnd; i++) {
    hash = ((hash << 1) + GEAR[data[i]]) >>> 0
    if ((hash & MASK_S) === 0) return i + 1
  }
  for (; i < maxEnd; i++) {
    hash = ((hash << 1) + GEAR[data[i]]) >>> 0
    if ((hash & MASK_L) === 0) return i + 1
  }
  return maxEnd
}

/**
 * Chunk `data` into content-defined boundaries. Empty input yields a single
 * empty chunk so that zero-byte files still round-trip through the manifest.
 */
export function chunkData(
  data: Uint8Array,
  params: ChunkerParams = DEFAULT_CHUNKER_PARAMS,
): ChunkBoundary[] {
  if (data.length === 0) return [{ start: 0, end: 0 }]

  const boundaries: ChunkBoundary[] = []
  let offset = 0
  while (offset < data.length) {
    const end = nextCut(data, offset, params)
    boundaries.push({ start: offset, end })
    offset = end
  }
  return boundaries
}
