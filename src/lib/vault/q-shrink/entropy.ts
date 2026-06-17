/**
 * Q-Shrink Vault Engine™ — Entropy Analysis
 *
 * Estimates Shannon entropy so the compression decision tree can *skip* data
 * that is already compressed or encrypted (images, video, archives, prior
 * ciphertext). Spending CPU deflating high-entropy data wastes time and can even
 * inflate it; entropy gating avoids that and is a core part of "compress only
 * when beneficial".
 */

const FULL_SCAN_LIMIT = 1 << 20 // 1 MiB: scan everything below this
const SAMPLE_WINDOW = 1 << 16 // 64 KiB windows sampled from large inputs
const SAMPLE_WINDOWS = 8 // head, tail, and evenly spread interior windows

/**
 * Shannon entropy in bits/byte (0–8). For inputs larger than 1 MiB this samples
 * representative windows (head, tail, interior) instead of the whole buffer so
 * the cost stays bounded regardless of file size.
 */
export function estimateEntropy(data: Uint8Array): number {
  if (data.length === 0) return 0

  const counts = new Uint32Array(256)
  let total = 0

  if (data.length <= FULL_SCAN_LIMIT) {
    for (let i = 0; i < data.length; i++) counts[data[i]]++
    total = data.length
  } else {
    const windows = Math.min(SAMPLE_WINDOWS, Math.ceil(data.length / SAMPLE_WINDOW))
    for (let w = 0; w < windows; w++) {
      // Spread windows across the buffer: 0, then evenly toward the end.
      const start = Math.min(
        data.length - SAMPLE_WINDOW,
        Math.floor((data.length - SAMPLE_WINDOW) * (w / Math.max(1, windows - 1))),
      )
      const end = start + SAMPLE_WINDOW
      for (let i = start; i < end; i++) counts[data[i]]++
      total += SAMPLE_WINDOW
    }
  }

  if (total === 0) return 0

  let entropy = 0
  for (let s = 0; s < 256; s++) {
    const c = counts[s]
    if (c === 0) continue
    const p = c / total
    entropy -= p * Math.log2(p)
  }
  return entropy
}

/**
 * Entropy at/above this threshold (bits/byte) is treated as effectively
 * incompressible. 7.85 keeps a margin below the theoretical max of 8 so that
 * genuinely random/encrypted data is skipped while structured text (typically
 * 3.5–6.5) is still compressed.
 */
export const INCOMPRESSIBLE_ENTROPY_THRESHOLD = 7.85

/** True when `data` is unlikely to benefit from general-purpose compression. */
export function looksIncompressible(data: Uint8Array): boolean {
  if (data.length < 64) return true // too small to amortize codec overhead
  return estimateEntropy(data) >= INCOMPRESSIBLE_ENTROPY_THRESHOLD
}

/**
 * MIME / extension families that are already entropy-coded. Used as a fast,
 * type-aware pre-filter before the (more expensive) entropy sample.
 */
// Only types that are DEFINITELY already entropy-coded belong here. Note the
// deliberate absence of 'application/octet-stream': that is the generic "type
// unknown" fallback browsers assign to folder (webkitdirectory) and drag-drop
// uploads — and that vault uploads default to — so it overwhelmingly covers
// ordinary, compressible files (text, logs, CSV/JSON, source). Such unknown-type
// inputs must fall through to the entropy gate, which measures the real data and
// still skips genuinely random/encrypted blobs (entropy ≥ threshold).
const PRECOMPRESSED_MIME = [
  'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/avif', 'image/heic',
  'video/', 'audio/',
  'application/zip', 'application/x-7z-compressed', 'application/x-rar-compressed',
  'application/gzip', 'application/x-bzip2', 'application/x-xz', 'application/zstd',
  'application/pdf',
]

const PRECOMPRESSED_EXT = [
  'jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'heic',
  'mp4', 'mkv', 'mov', 'webm', 'avi', 'mp3', 'aac', 'ogg', 'flac',
  'zip', '7z', 'rar', 'gz', 'bz2', 'xz', 'zst', 'br',
  'pdf', 'docx', 'xlsx', 'pptx', 'jar', 'apk',
]

/** Heuristic: does the file type suggest the bytes are already compressed? */
export function isPrecompressedType(path?: string, mime?: string): boolean {
  if (mime) {
    const m = mime.toLowerCase()
    if (PRECOMPRESSED_MIME.some((p) => m.startsWith(p) || m === p)) return true
  }
  if (path) {
    const dot = path.lastIndexOf('.')
    if (dot >= 0) {
      const ext = path.slice(dot + 1).toLowerCase()
      if (PRECOMPRESSED_EXT.includes(ext)) return true
    }
  }
  return false
}
