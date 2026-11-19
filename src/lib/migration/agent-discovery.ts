import type { ScannerEvidenceRecord, ScanFinding } from '@/types/scanner.types'

export const AGENT_DISCOVERY_EVENT = 'agent.evidence_observed'

export type AgentDiscovery = {
  id: string
  kind: 'endpoint' | 'certificate' | 'algorithm'
  label: string
  asset: string
  evidenceType: string
  observedAt: string | null
  protocol?: string
  algorithm?: string
  fingerprint?: string
  validUntil?: string
  severity?: ScanFinding['severity']
  description?: string
  recommendation?: string
}

export type ReportedAgentDiscovery = AgentDiscovery & { agentId: string; receivedAt: string }

function displayTarget(value: string): string {
  // Endpoint URLs can contain credentials, signed paths, and query tokens.
  if (value.includes('://')) {
    try { return new URL(value).host } catch { return '' }
  }
  return value.split(/[?#]/, 1)[0].replace(/^[^/\s@]+@/, '').slice(0, 180)
}

export function projectAgentDiscovery(
  evidence: ScannerEvidenceRecord,
  finding: ScanFinding | undefined,
  vulnerable: boolean,
  validUntil: string | null,
): AgentDiscovery[] {
  if (!evidence.id) return []
  const host = evidence.host ? displayTarget(evidence.host) : ''
  const endpoint = host ? (evidence.port ? `${host.includes(':') && !host.startsWith('[') ? `[${host}]` : host}:${evidence.port}` : host) : displayTarget(evidence.target || '')
  const asset = endpoint || displayTarget(evidence.assetName) || 'Reported asset'
  const observedAlgorithm = evidence.observedAlgorithm?.trim().slice(0, 160)
  const algorithm = evidence.evidenceType === 'tls-protocol' || /^(unknown|unavailable|none)$/i.test(observedAlgorithm || '') ? undefined : observedAlgorithm
  const protocol = (evidence.evidenceType === 'tls-protocol' ? observedAlgorithm : evidence.protocol)?.slice(0, 60)
  const certificate = evidence.evidenceType === 'tls-certificate' || evidence.evidenceType === 'certificate-file'
  const observedAt = evidence.observedAt && Number.isFinite(Date.parse(evidence.observedAt)) ? evidence.observedAt : null
  const expired = Boolean(observedAt && validUntil && Date.parse(validUntil) <= Date.parse(observedAt))
  const risk = vulnerable && finding
    ? { severity: finding.severity, description: finding.description, recommendation: finding.recommendation }
    : {}
  const base = { asset, algorithm, protocol, evidenceType: evidence.evidenceType, observedAt }
  const discoveries: AgentDiscovery[] = []
  if (endpoint && (evidence.evidenceType.startsWith('tls-') || evidence.evidenceType === 'ssh-metadata')) {
    discoveries.push({ ...base, id: `${evidence.id}:endpoint`, kind: 'endpoint', label: endpoint, ...risk })
  }
  if (certificate && (evidence.certificateFingerprint || validUntil || algorithm)) {
    discoveries.push({
      ...base,
      id: `${evidence.id}:certificate`,
      kind: 'certificate',
      label: asset,
      fingerprint: evidence.certificateFingerprint || undefined,
      validUntil: validUntil || undefined,
      ...risk,
      ...(expired && {
        severity: 'critical',
        description: 'The certificate had expired at the time of observation.',
        recommendation: 'Renew or replace the certificate, deploy the updated chain, and verify the certificate presented to clients.',
      }),
    })
  }
  if (algorithm) {
    discoveries.push({ ...base, id: `${evidence.id}:algorithm`, kind: 'algorithm', label: algorithm, ...risk })
  }
  return discoveries
}
