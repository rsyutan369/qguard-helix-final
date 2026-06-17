/**
 * Q-Shrink Vault Engine™ — Public API
 *
 * Pre-encryption data reduction with exact post-decryption restoration:
 *
 *   optimize:  File/Folder → chunk → dedup → compress → manifest+Merkle → QSHRN1
 *   restore:   QSHRN1 → decompress → rehydrate → verify → File/Folder
 *
 * The package emitted by {@link optimizeFile} / {@link optimizeBundle} is the
 * plaintext that the zero-knowledge envelope (`encryptFileLocal`) then seals.
 * Encryption is always applied to the *reduced* package — never the reverse.
 *
 * Reversibility is guaranteed by a per-file SHA3-256 digest committed in the
 * manifest and re-checked on restore; a chunk-level Merkle root provides
 * additional, independent integrity over the deduplicated blocks.
 */

import { chunkData, DEFAULT_CHUNKER_PARAMS, type ChunkerParams } from './chunker'
import { compress, compressionAvailable, decompress } from './codec'
import {
  decodeManifest,
  encodeManifest,
  isQShrinkPackage,
  packContainer,
  parseContainer,
  MAX_SECTION_BYTES,
} from './container'
import { estimateEntropy, isPrecompressedType, looksIncompressible } from './entropy'
import { merkleRootFromLeafHashes, sha3Hex } from './manifest'
import {
  QSHRINK_ALGORITHM,
  QSHRINK_HASH,
  QShrinkCodec,
  QSHRINK_CODEC_NAMES,
  type ChunkSlot,
  type ManifestFile,
  type OptimizeResult,
  type QShrinkAnalysis,
  type QShrinkCodecId,
  type QShrinkInput,
  type QShrinkManifest,
  type QShrinkReport,
} from './types'

export { isQShrinkPackage } from './container'
export { estimateEntropy, isPrecompressedType } from './entropy'
export type {
  OptimizeResult,
  QShrinkAnalysis,
  QShrinkInput,
  QShrinkManifest,
  QShrinkReport,
} from './types'

export interface OptimizeOptions {
  path?: string
  mime?: string
  params?: ChunkerParams
}

interface BuiltContainer {
  container: Uint8Array
  manifest: QShrinkManifest
  /** Stored payload section length (post-compression). */
  payloadStoredSize: number
  entropy: number
}

/**
 * Core builder: chunk → dedup → (entropy-gated) compress → manifest → QSHRN1.
 * Always produces a container; callers decide whether wrapping is worthwhile.
 */
async function buildContainer(
  inputs: QShrinkInput[],
  params: ChunkerParams = DEFAULT_CHUNKER_PARAMS,
): Promise<BuiltContainer> {
  // ── Chunk + content-addressed deduplication across every input ──────────
  const tableIndexByHash = new Map<string, number>()
  const table: ChunkSlot[] = []
  const uniqueHashes: string[] = []
  const uniqueChunks: Uint8Array[] = []
  const files: ManifestFile[] = []
  let blobOffset = 0
  let totalChunks = 0
  let logicalSize = 0

  for (const input of inputs) {
    logicalSize += input.data.length
    if (logicalSize > MAX_SECTION_BYTES) throw new Error('QSHRINK_TOO_LARGE')

    const seq: number[] = []
    for (const b of chunkData(input.data, params)) {
      totalChunks++
      const chunk = input.data.subarray(b.start, b.end)
      const h = sha3Hex(chunk)
      let idx = tableIndexByHash.get(h)
      if (idx === undefined) {
        idx = table.length
        tableIndexByHash.set(h, idx)
        const len = b.end - b.start
        table.push({ o: blobOffset, l: len })
        uniqueHashes.push(h)
        uniqueChunks.push(chunk)
        blobOffset += len
      }
      seq.push(idx)
    }

    files.push({
      path: input.path,
      size: input.data.length,
      hash: sha3Hex(input.data),
      mime: input.mime,
      seq,
    })
  }

  const dedupedBlobSize = blobOffset
  if (dedupedBlobSize > MAX_SECTION_BYTES) throw new Error('QSHRINK_TOO_LARGE')

  const dedupedBlob = new Uint8Array(dedupedBlobSize)
  let p = 0
  for (const c of uniqueChunks) {
    dedupedBlob.set(c, p)
    p += c.length
  }

  const merkleRoot = merkleRootFromLeafHashes(uniqueHashes)

  // ── Adaptive, entropy-gated compression of the whole dedup blob ─────────
  const entropy = estimateEntropy(dedupedBlob)
  const typeIncompressible = inputs.length > 0 && inputs.every((i) => isPrecompressedType(i.path, i.mime))

  let codec: QShrinkCodecId = QShrinkCodec.STORE
  let payloadBytes = dedupedBlob
  let payloadCompressed = false

  if (compressionAvailable() && !typeIncompressible && !looksIncompressible(dedupedBlob)) {
    const compressed = await compress(dedupedBlob, QShrinkCodec.DEFLATE_RAW)
    // Guard: only keep compression if it actually shrank the blob.
    if (compressed.length < dedupedBlob.length) {
      codec = QShrinkCodec.DEFLATE_RAW
      payloadBytes = compressed
      payloadCompressed = true
    }
  }

  const manifest: QShrinkManifest = {
    v: 1,
    algo: QSHRINK_ALGORITHM,
    hashAlgo: QSHRINK_HASH,
    chunker: {
      algo: 'fastcdc-v1',
      minSize: params.minSize,
      avgSize: params.avgSize,
      maxSize: params.maxSize,
    },
    codecId: codec,
    codecName: QSHRINK_CODEC_NAMES[codec] ?? 'store',
    dedup: { table, merkleRoot },
    files,
    totals: {
      logicalSize,
      dedupedBlobSize,
      totalChunks,
      uniqueChunks: table.length,
    },
  }

  // ── Manifest is compressed independently with deflate-raw when it helps ──
  let manifestBytes = encodeManifest(manifest)
  let manifestCompressed = false
  if (compressionAvailable()) {
    const compressedManifest = await compress(manifestBytes, QShrinkCodec.DEFLATE_RAW)
    if (compressedManifest.length < manifestBytes.length) {
      manifestBytes = compressedManifest
      manifestCompressed = true
    }
  }

  const container = packContainer({
    codec,
    manifestCompressed,
    payloadCompressed,
    manifestBytes,
    payloadBytes,
  })

  return { container, manifest, payloadStoredSize: payloadBytes.length, entropy }
}

function buildReport(
  built: BuiltContainer,
  applied: boolean,
  optimizedSize: number,
): QShrinkReport {
  const { manifest, payloadStoredSize, entropy } = built
  const { logicalSize, dedupedBlobSize, totalChunks, uniqueChunks } = manifest.totals
  return {
    applied,
    algorithm: QSHRINK_ALGORITHM,
    logicalSize,
    optimizedSize,
    reductionPercent:
      logicalSize > 0 ? Math.max(0, (1 - optimizedSize / logicalSize) * 100) : 0,
    fileCount: manifest.files.length,
    totalChunks,
    uniqueChunks,
    dedupSavedBytes: Math.max(0, logicalSize - dedupedBlobSize),
    dedupRatio: uniqueChunks > 0 ? totalChunks / uniqueChunks : 1,
    codec: applied ? manifest.codecName : 'store',
    compressionRatio: payloadStoredSize > 0 ? dedupedBlobSize / payloadStoredSize : 1,
    entropyBitsPerByte: entropy,
    chunker: 'fastcdc-v1',
    avgChunkSize: manifest.chunker.avgSize,
    merkleRoot: applied ? manifest.dedup.merkleRoot : '',
  }
}

/**
 * Optimize a single file for the vault. If the resulting container is not
 * smaller than the original, returns the original bytes with `applied:false`
 * so the package is never larger than the input (no inflation, ever).
 */
export async function optimizeFile(data: Uint8Array, opts: OptimizeOptions = {}): Promise<OptimizeResult> {
  const input: QShrinkInput = { path: opts.path ?? 'file', data, mime: opts.mime }
  const built = await buildContainer([input], opts.params)
  const beneficial = built.container.length < data.length

  // Raw passthrough is only safe when the plaintext cannot be mistaken for one of
  // our own containers on the way back. If the original bytes happen to begin with
  // the QSHRN1 magic (a real binary asset, or a re-uploaded vault container), we
  // MUST wrap them — otherwise restore would mis-detect the raw file as a container
  // and corrupt/destroy it. Wrapping costs a small header for that rare file but
  // keeps the magic authoritative on restore, with no dependency on mutable
  // metadata. The overwhelmingly common no-inflation case still passes through with
  // zero overhead.
  if (!beneficial && !isQShrinkPackage(data)) {
    return {
      package: data,
      applied: false,
      report: buildReport(built, false, data.length),
    }
  }
  return {
    package: built.container,
    applied: true,
    report: buildReport(built, true, built.container.length),
  }
}

/**
 * Optimize multiple files / a folder into one deduplicated, integrity-native
 * container (cross-file deduplication). Always wraps, since the bundle carries
 * structure that a flat blob cannot represent.
 */
export async function optimizeBundle(
  inputs: QShrinkInput[],
  params?: ChunkerParams,
): Promise<{ package: Uint8Array; report: QShrinkReport; manifest: QShrinkManifest }> {
  const built = await buildContainer(inputs, params)
  return {
    package: built.container,
    report: buildReport(built, true, built.container.length),
    manifest: built.manifest,
  }
}

/**
 * Restore every file from a `QSHRN1` container, verifying each file's SHA3-256
 * digest and the chunk-level Merkle root. Throws on any integrity mismatch.
 */
export async function restorePackage(data: Uint8Array): Promise<QShrinkInput[]> {
  const parsed = parseContainer(data)

  const manifestBytes = parsed.manifestCompressed
    ? await decompress(parsed.manifestBytes, QShrinkCodec.DEFLATE_RAW)
    : parsed.manifestBytes
  const manifest = decodeManifest(manifestBytes)

  const dedupedBlob = parsed.payloadCompressed
    ? await decompress(parsed.payloadBytes, parsed.codec)
    : parsed.payloadBytes

  // Independent chunk-level integrity: recompute the Merkle root over the
  // reconstructed unique chunks and compare to the committed root.
  const leaves = manifest.dedup.table.map((slot) =>
    sha3Hex(dedupedBlob.subarray(slot.o, slot.o + slot.l)),
  )
  if (merkleRootFromLeafHashes(leaves) !== manifest.dedup.merkleRoot) {
    throw new Error('QSHRINK_MERKLE_INTEGRITY_FAILED')
  }

  const out: QShrinkInput[] = []
  for (const file of manifest.files) {
    const bytes = new Uint8Array(file.size)
    let pos = 0
    for (const idx of file.seq) {
      const slot = manifest.dedup.table[idx]
      if (!slot) throw new Error('QSHRINK_CHUNK_REF_INVALID')
      bytes.set(dedupedBlob.subarray(slot.o, slot.o + slot.l), pos)
      pos += slot.l
    }
    if (pos !== file.size) throw new Error('QSHRINK_SIZE_MISMATCH')
    if (sha3Hex(bytes) !== file.hash) throw new Error('QSHRINK_INTEGRITY_FAILED')
    out.push({ path: file.path, data: bytes, mime: file.mime })
  }
  return out
}

/**
 * Restore the original bytes of a single sealed vault object.
 *
 * The `QSHRN1` magic is authoritative: a real container always carries it, and
 * {@link optimizeFile} guarantees that a raw, non-optimized passthrough is *never*
 * emitted when its bytes begin with the magic (such inputs are wrapped instead).
 * Restore therefore decides solely on the self-describing, GCM-authenticated
 * container bytes — never on the mutable `envelope_meta.qshrink` flag — so a
 * tampered/incorrect flag can never cause the wrong bytes to be returned, and a
 * raw user file that merely starts with the magic bytes can never be mis-parsed.
 * Legacy/pre-Q-Shrink files (no magic) pass through unchanged. `qshrinkMeta` is
 * accepted for API compatibility and ignored here.
 */
export async function restoreFile(
  data: Uint8Array,
  _qshrinkMeta?: { applied?: boolean } | null,
): Promise<Uint8Array> {
  if (!isQShrinkPackage(data)) return data
  const files = await restorePackage(data)
  if (files.length === 0) throw new Error('QSHRINK_EMPTY_PACKAGE')
  return files[0].data
}

/**
 * Dry-run analysis for the interactive analyzer: optimizes the inputs, restores
 * them, and confirms byte-for-byte reversibility — without any encryption.
 */
export async function analyzeFiles(inputs: QShrinkInput[]): Promise<QShrinkAnalysis> {
  const built = await buildContainer(inputs)
  const beneficial = built.container.length < built.manifest.totals.logicalSize
  const report = buildReport(built, beneficial, built.container.length)

  // Prove reversibility against the live engine path.
  let reversible = true
  try {
    const restored = await restorePackage(built.container)
    if (restored.length !== inputs.length) reversible = false
    for (let i = 0; reversible && i < inputs.length; i++) {
      const a = inputs[i].data
      const b = restored[i].data
      if (a.length !== b.length) { reversible = false; break }
      for (let j = 0; j < a.length; j++) {
        if (a[j] !== b[j]) { reversible = false; break }
      }
    }
  } catch {
    reversible = false
  }

  return {
    ...report,
    reversible,
    files: built.manifest.files.map((f) => ({
      path: f.path,
      size: f.size,
      chunks: f.seq.length,
    })),
  }
}

/** Decode a stored `envelope_meta.qshrink` value into a typed report (UI helper). */
export function decodeReport(value: unknown): QShrinkReport | null {
  if (!value || typeof value !== 'object') return null
  const v = value as Record<string, unknown>
  if (typeof v.applied !== 'boolean' || typeof v.optimizedSize !== 'number') return null
  return v as unknown as QShrinkReport
}
