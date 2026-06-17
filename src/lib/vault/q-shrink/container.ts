/**
 * Q-Shrink Vault Engine™ — `QSHRN1` Container Format
 *
 * A self-describing binary container produced before encryption and consumed
 * after decryption. Layout (all integers little-endian):
 *
 *   offset  size  field
 *   ------  ----  -----------------------------------------------------------
 *   0       6     magic  = "QSHRN1" (0x51 53 48 52 4E 31)
 *   6       1     version = 1
 *   7       1     flags  (bit0: manifest compressed, bit1: payload compressed)
 *   8       1     codec  (QShrinkCodec id used for compressed sections)
 *   9       1     reserved = 0
 *   10      4     manifestLength (uint32)
 *   14      4     payloadLength  (uint32)
 *   18      M     manifest bytes  (UTF-8 JSON, deflate-raw if flags.bit0)
 *   18+M    P     payload bytes   (dedup blob, codec-compressed if flags.bit1)
 *
 * Section lengths are uint32 (max ~4 GiB each). Single vault objects live well
 * within that; a future `QSHRN2` can widen to 64-bit for streamed multi-GiB
 * uploads. The manifest is confidential once the container is sealed by the
 * AES-256-GCM envelope.
 */

import type { QShrinkCodecId, QShrinkManifest } from './types'

export const QSHRINK_MAGIC = new Uint8Array([0x51, 0x53, 0x48, 0x52, 0x4e, 0x31]) // "QSHRN1"
export const QSHRINK_VERSION = 1
const HEADER_BYTES = 18
const FLAG_MANIFEST_COMPRESSED = 0x01
const FLAG_PAYLOAD_COMPRESSED = 0x02
export const MAX_SECTION_BYTES = 0xffffffff

/** Fast, allocation-free check for the `QSHRN1` magic + supported version. */
export function isQShrinkPackage(data: Uint8Array): boolean {
  if (data.length < HEADER_BYTES) return false
  for (let i = 0; i < QSHRINK_MAGIC.length; i++) {
    if (data[i] !== QSHRINK_MAGIC[i]) return false
  }
  return data[6] === QSHRINK_VERSION
}

export interface ContainerSections {
  codec: QShrinkCodecId
  manifestCompressed: boolean
  payloadCompressed: boolean
  /** Manifest bytes exactly as they should be written (already compressed if flagged). */
  manifestBytes: Uint8Array
  /** Payload bytes exactly as they should be written (already compressed if flagged). */
  payloadBytes: Uint8Array
}

/** Serialize header + manifest + payload into a single `QSHRN1` buffer. */
export function packContainer(sections: ContainerSections): Uint8Array {
  const { manifestBytes, payloadBytes } = sections
  if (manifestBytes.length > MAX_SECTION_BYTES || payloadBytes.length > MAX_SECTION_BYTES) {
    throw new Error('QSHRINK_SECTION_TOO_LARGE')
  }

  const total = HEADER_BYTES + manifestBytes.length + payloadBytes.length
  const buf = new Uint8Array(total)
  const view = new DataView(buf.buffer)

  buf.set(QSHRINK_MAGIC, 0)
  buf[6] = QSHRINK_VERSION
  buf[7] =
    (sections.manifestCompressed ? FLAG_MANIFEST_COMPRESSED : 0) |
    (sections.payloadCompressed ? FLAG_PAYLOAD_COMPRESSED : 0)
  buf[8] = sections.codec
  buf[9] = 0
  view.setUint32(10, manifestBytes.length, true)
  view.setUint32(14, payloadBytes.length, true)

  buf.set(manifestBytes, HEADER_BYTES)
  buf.set(payloadBytes, HEADER_BYTES + manifestBytes.length)
  return buf
}

export interface ParsedContainer {
  codec: QShrinkCodecId
  manifestCompressed: boolean
  payloadCompressed: boolean
  manifestBytes: Uint8Array
  payloadBytes: Uint8Array
}

/** Validate + split a `QSHRN1` buffer into its raw sections. */
export function parseContainer(data: Uint8Array): ParsedContainer {
  if (!isQShrinkPackage(data)) throw new Error('QSHRINK_BAD_MAGIC')

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const flags = data[7]
  const codec = data[8] as QShrinkCodecId
  const manifestLength = view.getUint32(10, true)
  const payloadLength = view.getUint32(14, true)

  const manifestStart = HEADER_BYTES
  const payloadStart = manifestStart + manifestLength
  if (payloadStart + payloadLength > data.length) {
    throw new Error('QSHRINK_TRUNCATED')
  }

  return {
    codec,
    manifestCompressed: (flags & FLAG_MANIFEST_COMPRESSED) !== 0,
    payloadCompressed: (flags & FLAG_PAYLOAD_COMPRESSED) !== 0,
    manifestBytes: data.slice(manifestStart, payloadStart),
    payloadBytes: data.slice(payloadStart, payloadStart + payloadLength),
  }
}

export function encodeManifest(manifest: QShrinkManifest): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(manifest))
}

export function decodeManifest(bytes: Uint8Array): QShrinkManifest {
  return JSON.parse(new TextDecoder().decode(bytes)) as QShrinkManifest
}
