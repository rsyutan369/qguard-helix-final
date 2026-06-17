/**
 * Q-Shrink Vault Engine™ — Compression Codecs
 *
 * Backend is the browser-/Node-native `CompressionStream` (gzip / deflate-raw),
 * so there is zero third-party / supply-chain surface. The container records a
 * codec id, so a native or WASM Zstandard/Brotli backend can be slotted in later
 * without breaking previously stored vault objects.
 *
 * `deflate-raw` (RFC 1951, no gzip/zlib wrapper) is preferred — it omits the
 * ~18-byte header/trailer, which matters because Q-Shrink compresses the whole
 * deduplicated blob as a single stream.
 */

import { QShrinkCodec, type QShrinkCodecId } from './types'

/** True when a working `CompressionStream` is available in this runtime. */
export function compressionAvailable(): boolean {
  return typeof CompressionStream !== 'undefined' && typeof DecompressionStream !== 'undefined'
}

async function streamThrough(
  data: Uint8Array,
  stream: GenericTransformStream,
): Promise<Uint8Array> {
  // Manually pump the transform: read and write concurrently (backpressure-safe),
  // and on error settle BOTH sides before rethrowing. We deliberately avoid
  // `new Response(stream.readable)` here: when a DecompressionStream errors on
  // corrupt/tampered input, that adapter can leave a dangling, unhandled stream
  // 'error' event that crashes the process on a later tick (Node webstreams bug).
  const reader = (stream.readable as ReadableStream<Uint8Array>).getReader()
  const writer = (stream.writable as WritableStream<Uint8Array>).getWriter()

  const pump = (async () => {
    const chunks: Uint8Array[] = []
    let total = 0
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      if (value) {
        chunks.push(value)
        total += value.length
      }
    }
    const out = new Uint8Array(total)
    let offset = 0
    for (const chunk of chunks) {
      out.set(chunk, offset)
      offset += chunk.length
    }
    return out
  })()

  const write = (async () => {
    await writer.write(data)
    await writer.close()
  })()

  try {
    const [out] = await Promise.all([pump, write])
    return out
  } catch (err) {
    // Settle both halves so neither leaves an unhandled rejection / error event.
    try {
      await reader.cancel()
    } catch {
      /* already errored */
    }
    try {
      await writer.abort(err)
    } catch {
      /* already errored */
    }
    await Promise.allSettled([pump, write])
    throw err instanceof Error ? err : new Error('QSHRINK_STREAM_ERROR')
  }
}

/** Compress `data` with the given codec. `STORE` returns the input unchanged. */
export async function compress(data: Uint8Array, codec: QShrinkCodecId): Promise<Uint8Array> {
  if (data.length === 0) return new Uint8Array(0)
  switch (codec) {
    case QShrinkCodec.STORE:
      return data
    case QShrinkCodec.DEFLATE_RAW:
      return streamThrough(data, new CompressionStream('deflate-raw'))
    case QShrinkCodec.GZIP:
      return streamThrough(data, new CompressionStream('gzip'))
    default:
      throw new Error(`QSHRINK_CODEC_UNSUPPORTED:${codec}`)
  }
}

/** Decompress `data` previously produced by {@link compress}. */
export async function decompress(data: Uint8Array, codec: QShrinkCodecId): Promise<Uint8Array> {
  if (data.length === 0) return new Uint8Array(0)
  switch (codec) {
    case QShrinkCodec.STORE:
      return data
    case QShrinkCodec.DEFLATE_RAW:
      return streamThrough(data, new DecompressionStream('deflate-raw'))
    case QShrinkCodec.GZIP:
      return streamThrough(data, new DecompressionStream('gzip'))
    default:
      throw new Error(`QSHRINK_CODEC_UNSUPPORTED:${codec}`)
  }
}

/**
 * The default codec for compressible payloads. `deflate-raw` is the smallest
 * native option; falls back to STORE when no CompressionStream exists.
 */
export function defaultCodec(): QShrinkCodecId {
  return compressionAvailable() ? QShrinkCodec.DEFLATE_RAW : QShrinkCodec.STORE
}
