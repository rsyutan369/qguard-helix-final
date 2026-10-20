/**
 * QGuard Messaging → Helix evidence (messenger roadmap 10.1).
 *
 * The messenger and Helix share one Supabase project and one login, so Helix
 * derives a user's messenger posture itself — from the device rows the
 * messenger publishes (`messaging_devices`), read with the user's own token —
 * instead of trusting numbers a client reports. Each active device becomes one
 * evidence row per primitive it publishes, graded by the normal evidence
 * pipeline (hybrid → quantum-safe path; classical → a finding).
 *
 * Only cryptographic configuration leaves the messenger tables: never message
 * content, contacts or conversation metadata.
 */

export const MESSAGING_EVIDENCE_TYPE = 'messaging-device-crypto'

/** What the FIPS 203 build writes; its absence means pre-standard Kyber (see the messenger's kem-suite.ts). */
const FIPS_203_KEM = 'ML-KEM-1024'
const FIPS_203_STANDARD = 'FIPS-203'

export interface MessagingDeviceRow {
  id: string
  device_label?: string | null
  suite?: Record<string, unknown> | null
  trust_state?: string | null
  revoked_at?: string | null
  last_seen_at?: string | null
}

export interface MessagingEvidenceInput {
  evidenceType: typeof MESSAGING_EVIDENCE_TYPE
  assetName: string
  assetType: 'messaging-device'
  target: string
  protocol: 'qguard-messaging'
  observedAlgorithm: string
  confidence: 'high' | 'medium'
  rawEvidence: Record<string, unknown>
  observedAt: string
}

function text(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim().slice(0, 100) : null
}

export function isActiveMessagingDevice(device: MessagingDeviceRow): boolean {
  return !device.revoked_at && String(device.trust_state || '').toLowerCase() !== 'revoked'
}

/**
 * The key-establishment algorithm a device's published suite really provides.
 * A device without the FIPS 203 marker runs pre-standard Kyber, which cannot
 * interoperate with current builds: it is graded by its classical half only,
 * never as post-quantum (CLAUDE.md: never mark PQC-ready without validation).
 */
export function messagingKeyEstablishment(suite: Record<string, unknown> | null | undefined): { algorithm: string; note: string | null } {
  const classical = text(suite?.classical_kex) || 'X25519'
  const pq = text(suite?.pq_kem)
  if (pq === FIPS_203_KEM && text(suite?.pq_kem_standard) === FIPS_203_STANDARD) {
    return { algorithm: `${classical} + ${FIPS_203_KEM}`, note: null }
  }
  if (pq) {
    return {
      algorithm: classical,
      note: 'The post-quantum half is pre-FIPS-203 Kyber-1024, which current builds cannot interoperate with; graded as classical until the device is re-keyed.',
    }
  }
  return { algorithm: classical, note: 'No post-quantum key establishment published.' }
}

export function messagingSignature(suite: Record<string, unknown> | null | undefined): string | null {
  const classical = text(suite?.classical_signature)
  const pq = text(suite?.pq_signature)
  if (classical && pq) return `${classical} + ${pq}`
  return pq || classical
}

/** Evidence inputs for every active device; revoked devices are left out. */
export function messagingDeviceEvidence(devices: MessagingDeviceRow[], observedAt: string): MessagingEvidenceInput[] {
  const out: MessagingEvidenceInput[] = []
  for (const device of devices) {
    if (!device?.id || !isActiveMessagingDevice(device)) continue
    const suite = device.suite && typeof device.suite === 'object' ? device.suite : null
    const label = text(device.device_label) || `Device ${String(device.id).slice(0, 8)}`
    const base = {
      evidenceType: MESSAGING_EVIDENCE_TYPE as typeof MESSAGING_EVIDENCE_TYPE,
      assetName: `QGuard Messaging · ${label}`,
      assetType: 'messaging-device' as const,
      target: `qguard-messaging:device:${device.id}`,
      protocol: 'qguard-messaging' as const,
      observedAt,
    }
    const kex = messagingKeyEstablishment(suite)
    out.push({
      ...base,
      observedAlgorithm: kex.algorithm,
      confidence: 'high',
      rawEvidence: {
        component: 'key-establishment',
        source: 'messaging_devices.suite',
        deviceId: device.id,
        pqKemStandard: text(suite?.pq_kem_standard),
        kemCombiner: text(suite?.kem_combiner),
        lastSeenAt: device.last_seen_at ?? null,
        ...(kex.note ? { note: kex.note } : {}),
      },
    })
    const signature = messagingSignature(suite)
    if (signature) {
      out.push({ ...base, observedAlgorithm: signature, confidence: 'high', rawEvidence: { component: 'signature', source: 'messaging_devices.suite', deviceId: device.id } })
    }
    const symmetric = text(suite?.symmetric)
    if (symmetric) {
      out.push({ ...base, observedAlgorithm: symmetric, confidence: 'high', rawEvidence: { component: 'message-encryption', source: 'messaging_devices.suite', deviceId: device.id } })
    }
    const kdf = text(suite?.kdf)
    if (kdf) {
      out.push({ ...base, observedAlgorithm: kdf, confidence: 'high', rawEvidence: { component: 'key-derivation', source: 'messaging_devices.suite', deviceId: device.id } })
    }
  }
  return out
}
