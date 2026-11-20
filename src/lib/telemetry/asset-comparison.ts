import type { EncryptionIntelligence } from '@/lib/encryption/types'
import type { SourceRead } from '@/lib/source-read'
import type { TlsPkiIntelligence } from '@/lib/tls-pki/types'

export interface TelemetryAsset {
  id: string
  name: string
  type: string
  environment: string
}

export function compareTelemetryAssets(
  assets: TelemetryAsset[],
  tls: TlsPkiIntelligence & { reads: SourceRead[] },
  encryption: EncryptionIntelligence & { reads: SourceRead[] },
) {
  const recent = <T>(rows: T[], observedAt: (row: T) => string | null) => rows
    .slice().sort((a, b) => (Date.parse(observedAt(b) ?? '') || 0) - (Date.parse(observedAt(a) ?? '') || 0)).slice(0, 25)
  return {
    generatedAt: new Date(Math.max(Date.parse(tls.generatedAt), Date.parse(encryption.generatedAt))).toISOString(),
    tlsSnapshot: { generatedAt: tls.generatedAt },
    encryptionSnapshot: { generatedAt: encryption.generatedAt },
    incompleteSources: [...new Set([...tls.reads, ...encryption.reads]
      .filter((read) => read.state === 'truncated' || read.state === 'unavailable').map((read) => read.key))],
    assets: assets.map((asset) => {
      const endpoints = tls.endpoints.filter((row) => row.assetId === asset.id && row.hasTransportEvidence)
      const certificates = tls.certificates.filter((row) => row.assetId === asset.id)
      const transport = tls.observations.filter((row) => row.assetId === asset.id)
      const ssh = tls.protocol.ssh.filter((row) => row.assetId === asset.id)
      const protection = encryption.observations.filter((row) => row.assetId === asset.id)
      const findings = [
        ...tls.findings.filter((row) => row.assetId === asset.id).map((row) => ({ ...row, domain: 'TLS / PKI' })),
        ...encryption.findings.filter((row) => row.assetId === asset.id).map((row) => ({ ...row, domain: 'Data protection' })),
      ]
      return {
        ...asset,
        counts: { endpoints: endpoints.length, certificates: certificates.length, transport: transport.length,
          ssh: ssh.length, protection: protection.length, tlsFindings: findings.filter((row) => row.domain === 'TLS / PKI').length,
          protectionFindings: findings.filter((row) => row.domain === 'Data protection').length },
        endpoints: endpoints.slice(0, 25),
        certificates: recent(certificates, (row) => row.lastObservedAt),
        transport: recent(transport, (row) => row.observedAt),
        ssh: recent(ssh, (row) => row.observedAt),
        protection: recent(protection, (row) => row.observedAt),
        findings: recent(findings, (row) => row.lastObservedAt),
        changes: recent(tls.orchestration.drift.filter((row) => row.assetId === asset.id), (row) => row.detectedAt),
      }
    }),
  }
}

export type AssetTelemetryComparison = ReturnType<typeof compareTelemetryAssets>
