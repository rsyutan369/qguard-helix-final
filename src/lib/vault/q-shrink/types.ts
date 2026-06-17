/**
 * Q-Shrink Vault Engine™ — Shared Types
 *
 * Quantum-Safe Storage Reduction and Integrity-Native Knowledge Engine.
 *
 * Q-Shrink performs *pre-encryption data reduction with exact post-decryption
 * restoration*. It optimizes plaintext locally (content-defined chunking →
 * deduplication → adaptive compression → manifest + Merkle integrity) and emits
 * a self-describing `QSHRN1` container. That container is what the existing
 * zero-knowledge envelope (`encryptFileLocal`: X25519 + ML-KEM-1024 +
 * AES-256-GCM) seals. Encryption is always applied to the *reduced* package —
 * never the other way around — because high-entropy ciphertext cannot be
 * meaningfully compressed.
 *
 * Reversibility contract: `restore(optimize(x)) === x` byte-for-byte, proven by
 * a per-file SHA3-256 digest committed inside the (encrypted) manifest.
 */

/** Compression codec identifiers stored in the container header + manifest. */
export const QShrinkCodec = {
  /** No compression — payload stored verbatim (already-compressed / high-entropy data). */
  STORE: 0,
  /** RFC 1951 raw DEFLATE via the browser-native `CompressionStream('deflate-raw')`. */
  DEFLATE_RAW: 1,
  /** RFC 1952 gzip via `CompressionStream('gzip')`. */
  GZIP: 2,
  // Reserved for a future native/WASM backend without breaking stored objects:
  /** Reserved — Zstandard. */
  ZSTD: 3,
  /** Reserved — Brotli. */
  BROTLI: 4,
} as const

export type QShrinkCodecId = (typeof QShrinkCodec)[keyof typeof QShrinkCodec]

export const QSHRINK_CODEC_NAMES: Record<number, string> = {
  0: 'store',
  1: 'deflate-raw',
  2: 'gzip',
  3: 'zstd',
  4: 'brotli',
}

export const QSHRINK_ALGORITHM = 'q-shrink-vault-engine/v1'
export const QSHRINK_HASH = 'SHA3-256' as const

/** A unique deduplicated chunk's location inside the concatenated dedup blob. */
export interface ChunkSlot {
  /** Byte offset of this chunk within the (pre-compression) dedup blob. */
  o: number
  /** Byte length of this chunk. */
  l: number
}

/** One logical file inside a Q-Shrink package (single-file or folder bundle). */
export interface ManifestFile {
  /** Original path / filename (preserves folder structure on restore). */
  path: string
  /** Exact original byte length. */
  size: number
  /** SHA3-256 of the original file bytes (byte-for-byte restoration proof). */
  hash: string
  /** Original MIME type, when known. */
  mime?: string
  /** Ordered indices into `dedup.table` reconstructing this file's bytes. */
  seq: number[]
}

/**
 * The Q-Shrink manifest. Lives *inside* the container, so it is confidential and
 * integrity-protected by the surrounding AES-256-GCM envelope once sealed.
 */
export interface QShrinkManifest {
  v: 1
  algo: typeof QSHRINK_ALGORITHM
  hashAlgo: typeof QSHRINK_HASH
  chunker: {
    algo: 'fastcdc-v1' | 'fixed-v1'
    minSize: number
    avgSize: number
    maxSize: number
  }
  codecId: QShrinkCodecId
  codecName: string
  dedup: {
    /** Unique chunks, in storage order, located within the dedup blob. */
    table: ChunkSlot[]
    /** SHA3-256 Merkle root over the unique-chunk hashes (chunk-level integrity). */
    merkleRoot: string
  }
  files: ManifestFile[]
  totals: {
    /** Sum of original file sizes. */
    logicalSize: number
    /** Concatenated unique-chunk blob size (post-dedup, pre-compression). */
    dedupedBlobSize: number
    /** Total chunks across all files before deduplication. */
    totalChunks: number
    /** Distinct chunks after deduplication. */
    uniqueChunks: number
  }
}

/**
 * Non-secret optimization summary. Persisted to `vault_files.envelope_meta.qshrink`
 * and surfaced in the dashboard. Contains only sizes/ratios/labels — never content.
 */
export interface QShrinkReport {
  applied: boolean
  algorithm: typeof QSHRINK_ALGORITHM
  /** Original logical size (sum of input file sizes). */
  logicalSize: number
  /** Size of the container actually handed to the encryptor (what gets stored). */
  optimizedSize: number
  /** (1 - optimizedSize / logicalSize) * 100, clamped at 0. */
  reductionPercent: number
  fileCount: number
  totalChunks: number
  uniqueChunks: number
  /** logicalSize - dedupedBlobSize. */
  dedupSavedBytes: number
  /** totalChunks / uniqueChunks (1 = no duplicate blocks found). */
  dedupRatio: number
  codec: string
  /** dedupedBlobSize / compressedPayloadSize (1 = stored, no compression gain). */
  compressionRatio: number
  /** Shannon entropy of the sampled dedup blob, in bits/byte (0–8). */
  entropyBitsPerByte: number
  chunker: 'fastcdc-v1' | 'fixed-v1'
  avgChunkSize: number
  /** Chunk-level Merkle root (SHA3-256). */
  merkleRoot: string
}

/** A logical input to the engine (single file or one entry of a folder bundle). */
export interface QShrinkInput {
  path: string
  data: Uint8Array
  mime?: string
}

/** Result of optimizing input(s) into a sealable package. */
export interface OptimizeResult {
  /**
   * Bytes to encrypt. When `applied` is true this is a `QSHRN1` container;
   * when false (optimization yielded no benefit) this is the original bytes
   * verbatim, so the package is never larger than the input.
   */
  package: Uint8Array
  applied: boolean
  report: QShrinkReport
}

/** Per-file dry-run analysis used by the interactive analyzer (no encryption). */
export interface QShrinkAnalysis extends QShrinkReport {
  /** Round-trip restore reproduced every input byte-for-byte. */
  reversible: boolean
  /** Per-file breakdown for display. */
  files: Array<{ path: string; size: number; chunks: number }>
  /** Milliseconds spent optimizing (measured by the caller, optional). */
  elapsedMs?: number
}
