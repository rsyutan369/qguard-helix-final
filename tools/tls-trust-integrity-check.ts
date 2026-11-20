/**
 * TLS / PKI / Trust Fabric — offline integrity check.
 *
 *     npx tsx tools/tls-trust-integrity-check.ts
 *
 * Exercises the pure builders behind seven pages (TLS Telemetry, PKI
 * Visibility, Protocol Analytics, TLS Orchestrator, Encryption Monitoring is
 * covered by its own router path, Trust Dashboard, Trust-State Discovery) with
 * controlled fixtures — no network, no database. Each section guards a defect
 * found on live tenants by the 2026-10-28 audit (Technical_Audit_3):
 *
 *   A. "Scanner agent offline" (agent-heartbeat) and a config-file RSA finding
 *      were filed as TLS findings, inflating totals and spiking the timeline.
 *   B. Substring relevance: "dhe" matched "adhere", "kem" matched "kemp".
 *   C. An issuer known only by name was labelled a ROOT CA, so the
 *      Intermediate CA check PASSED with "issued directly by a root".
 *   D. "Quantum vulnerable endpoints" excluded legacy endpoints, printing 0
 *      beside "2 classical-only" for the same endpoints.
 *   E. Scanner-probe facts were labelled "negotiated"; they are what the
 *      server ACCEPTS, not what clients negotiate.
 *   F. A still-valid certificate 5 days from expiry was counted "Invalid" and
 *      raised a "Trust-chain failure" event.
 */
import { buildTlsPkiIntelligence, isTransportAlert, isTransportRelevant } from '../src/lib/tls-pki/intelligence'
import { buildTrustFabricIntelligence, failedTrustChecks } from '../src/lib/trust-fabric/intelligence'
import { discoveryLinks } from '../src/lib/trust-fabric/graph'
import { buildEncryptionIntelligence } from '../src/lib/encryption/intelligence'
import { compareTelemetryAssets } from '../src/lib/telemetry/asset-comparison'
import { countTelemetrySources } from '../src/lib/telemetry/source-health'
import { buildAssetPortfolio } from '../src/lib/migration/asset-intelligence'
import { EventEmitter } from 'node:events'
import type { Request, Response } from 'express'
import { payloadFingerprint, streamLiveSnapshot } from '../src/api-server/live-snapshot-stream'
import { createSourceLedger } from '../src/api-server/source-ledger'
import { readTelemetrySource } from '../src/api-server/telemetry-source-rows'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}

const NOW = Date.parse('2026-10-28T12:00:00Z')
const AT = '2026-10-20T10:00:00.000Z'
const days = (n: number) => new Date(NOW + n * 86_400_000).toISOString()

/* ---- Fixtures (controlled, labelled test data) -------------------- */
const inventory = [
  // legacy.example.test — the scanner enumerated TLS 1.0 and TLS 1.2 (probe results).
  { id: 'inv-1', asset_id: null, item_type: 'protocol', name: 'TLS protocol', algorithm: 'TLS 1.0', protocol: 'TLS 1.0', metadata: { host: 'legacy.example.test' }, discovered_at: AT },
  { id: 'inv-2', asset_id: null, item_type: 'protocol', name: 'TLS protocol', algorithm: 'TLS 1.2', protocol: 'TLS 1.2', metadata: { host: 'legacy.example.test' }, discovered_at: AT },
  { id: 'inv-3', asset_id: null, item_type: 'cipher_suite', name: 'Cipher suite', algorithm: 'TLS_RSA_WITH_AES_128_CBC_SHA', protocol: 'TLS 1.2', metadata: { host: 'legacy.example.test' }, discovered_at: AT },
  // modern.example.test — TLS 1.3 with classical ECDHE only (probe).
  { id: 'inv-4', asset_id: null, item_type: 'key_exchange', name: 'Key exchange', algorithm: 'ECDHE x25519', protocol: 'TLS 1.3', metadata: { host: 'modern.example.test' }, discovered_at: AT },
]
const runtimeEvents = [
  // live.example.test — a runtime agent saw a real hybrid handshake.
  { id: 'rt-1', asset_id: null, event_type: 'tls_handshake', host: 'live.example.test', port: 443, protocol: 'TLS', tls_version: 'TLS 1.3', key_exchange_algorithm: 'X25519MLKEM768', cipher_suite: 'TLS_AES_256_GCM_SHA384', metadata: {}, observed_at: AT },
]
const certificates = [
  // Leaf whose issuer certificate was never collected (a public intermediate).
  { id: 'c-leaf', asset_id: null, name: 'TLS certificate for legacy.example.test', algorithm: 'RSA', key_size: 2048, issuer: "C=US, O=Let's Encrypt, CN=R11", subject: 'CN=legacy.example.test', serial_number: '01', not_before: days(-60), not_after: days(30 + 60), status: 'active', metadata: { host: 'legacy.example.test' }, updated_at: AT },
  // Still valid, 5 days left — expiring, NOT invalid.
  { id: 'c-soon', asset_id: null, name: 'TLS certificate for modern.example.test', algorithm: 'ECDSA', key_size: 256, issuer: 'C=US, O=Google Trust Services, CN=WE1', subject: 'CN=modern.example.test', serial_number: '02', not_before: days(-80), not_after: days(5), status: 'active', metadata: { host: 'modern.example.test' }, updated_at: AT },
  // A genuine self-signed certificate — the one case that IS a root.
  { id: 'c-self', asset_id: null, name: 'Internal root', algorithm: 'RSA', key_size: 4096, issuer: 'CN=Acme Internal Root', subject: 'CN=Acme Internal Root', serial_number: '03', not_before: days(-300), not_after: days(3000), status: 'active', metadata: {}, updated_at: AT },
  // A self-signed certificate SERVED by an endpoint: no external authority vouches for it.
  { id: 'c-selfleaf', asset_id: null, name: 'TLS certificate for selfsigned.example.test', algorithm: 'RSA', key_size: 2048, issuer: 'CN=selfsigned.example.test', subject: 'CN=selfsigned.example.test', serial_number: '04', not_before: days(-30), not_after: days(300), status: 'active', metadata: { host: 'selfsigned.example.test' }, updated_at: AT },
]
const scannerAlerts = [
  { id: 'al-heartbeat', category: 'agent-heartbeat', title: 'Scanner agent offline: Collector 1', message: 'Agent has not sent a heartbeat since 2026-09-24.', recommendation: 'Verify the local scanner service has outbound HTTPS access to QGuard.', severity: 'high', metadata: {}, updated_at: days(0) },
  { id: 'al-config', category: 'critical-infrastructure-scanner', title: 'RSA detected on build-host', message: 'RSA-2048 is classically secure but quantum-vulnerable.', recommendation: 'Migrate to ML-KEM key encapsulation.', severity: 'high', metadata: { evidence: { source: 'local-agent:config-reference', detail: 'server.conf' } }, updated_at: days(0) },
  // These two mention TLS in their OWN text, so only the category / evidence gate can exclude them.
  { id: 'al-heartbeat-tls', category: 'agent-heartbeat', title: 'Collector cannot reach QGuard', message: 'TLS connection to the QGuard API failed: certificate verify error.', recommendation: '', severity: 'high', metadata: {}, updated_at: days(0) },
  { id: 'al-config-tls', category: 'critical-infrastructure-scanner', title: 'Weak ssl_ciphers directive in nginx.conf', message: 'The TLS cipher list in a config file allows RSA key transport.', recommendation: '', severity: 'medium', metadata: { evidence: { source: 'local-agent:config-reference', detail: 'nginx.conf' } }, updated_at: days(0) },
  { id: 'al-tls', category: 'certificate-authority-trust-scanner', title: 'Weak cipher suite accepted on legacy.example.test', message: 'TLS_RSA_WITH_AES_128_CBC_SHA has no forward secrecy.', recommendation: 'Disable RSA key transport suites.', severity: 'high', metadata: { algorithm: 'TLS_RSA_WITH_AES_128_CBC_SHA' }, updated_at: AT },
]

const tlsInputs: Parameters<typeof buildTlsPkiIntelligence>[0] = {
  assets: [],
  snapshot: { quantumReadiness: 40, quantumRisk: 60, quantumRiskLevel: 'High', assetsAssessed: 3 },
  runtimeEvents, cryptoInventory: inventory, certificates, scannerEvidence: [], scanResults: [], cryptoExposures: [], scannerAlerts,
  securityEvents: [], migrationJobs: [], migrationPlans: [], scanSessions: [], scannerAgents: [], connectorAccounts: [], agentHeartbeats: [],
  validationLogs: [], queuedAssetIds: [], now: NOW,
}
const tls = buildTlsPkiIntelligence(tlsInputs)

/* ------------------------------------------------------------------ */
console.log('\nA. Only transport / PKI alerts become TLS findings')
{
  const alert = (id: string) => scannerAlerts.find((a) => a.id === id)!
  assert(!isTransportAlert(alert('al-heartbeat'), {}), 'an agent-heartbeat alert is not a TLS finding')
  assert(!isTransportAlert(alert('al-config'), alert('al-config').metadata as Record<string, unknown>), 'a finding from a config file is not a TLS finding')
  assert(isTransportAlert(alert('al-tls'), alert('al-tls').metadata as Record<string, unknown>), 'a genuine TLS alert is admitted')
  const ids = tls.findings.flatMap((f) => f.evidence.map((e) => e.recordId))
  assert(!ids.includes('al-heartbeat') && !ids.includes('al-config'), 'neither excluded alert appears in the model findings', ids.join(','))
  assert(!ids.includes('al-heartbeat-tls'), 'an agent-health alert is excluded even when its own text mentions TLS')
  assert(!ids.includes('al-config-tls'), 'a config-file finding is excluded even when its own text mentions TLS ciphers')
  assert(ids.includes('al-tls'), 'the genuine TLS alert does appear')
  const today = tls.timeline[tls.timeline.length - 1]
  assert(today.findings === 0, 'the heartbeat touch no longer spikes today\'s timeline', `today findings = ${today.findings}`)
}

/* ------------------------------------------------------------------ */
console.log('\nB. Relevance is word-bounded and ignores remediation prose')
{
  assert(!isTransportRelevant('Please adhere to the retention policy'), '"adhere" does not match DHE')
  assert(!isTransportRelevant('Kemp load balancer firmware out of date'), '"Kemp" does not match KEM')
  assert(isTransportRelevant('Weak cipher suite accepted'), 'cipher suite text is relevant')
  assert(isTransportRelevant('Server does not offer ML-KEM key exchange'), 'ML-KEM key exchange is relevant')
  assert(isTransportRelevant('Expired certificate'), 'certificate text is relevant')
}

/* ------------------------------------------------------------------ */
console.log('\nC. An issuer known only by name is an issuing CA, never a root')
{
  const le = tls.trustChains.find((n) => /Let's Encrypt|R11/.test(n.label))
  assert(Boolean(le) && le!.kind === 'intermediate' && !le!.measured, "the uncollected Let's Encrypt R11 issuer is an unmeasured intermediate", `${le?.kind}/${le?.measured}`)
  const self = tls.trustChains.find((n) => /Acme Internal Root/.test(n.label))
  assert(Boolean(self) && self!.kind === 'root', 'a self-signed certificate is the one case shown as a root', self?.kind)

  const trust = buildTrustFabricIntelligence({
    tlsPki: tls, assets: [],
    snapshot: { quantumReadiness: 40, quantumRisk: 60, quantumRiskLevel: 'High', assetsAssessed: 3, certificatesAnalyzed: 3, complianceScore: null, vulnerableComponents: 2, totalComponents: 4, pqcReadyComponents: 0 },
    assetRows: [], assetRelationships: [], connectorAccounts: [], securityEvents: [], scanSessions: [], migrationJobs: [], scannerAgents: [], complianceEvidence: [], cryptoInventory: [], runtimeEvents: [], now: NOW,
  })
  const caNodes = trust.nodes.filter((n) => n.kind === 'root-ca' || n.kind === 'intermediate-ca')
  const leNode = caNodes.find((n) => /Let's Encrypt|R11/.test(n.label))
  assert(Boolean(leNode) && leNode!.kind === 'intermediate-ca', 'trust graph files the uncollected issuer as an intermediate CA', leNode?.kind)
  // Trust records are keyed by certificate id; resolve through the certificate list.
  const trustFor = (pattern: RegExp) => {
    const cert = tls.certificates.find((c) => pattern.test(c.subject))
    return cert ? trust.certificateTrust.find((r) => r.certificateId === cert.id) : undefined
  }
  const leafTrust = trustFor(/legacy\.example\.test/)
  const inter = leafTrust?.checks.find((c) => c.key === 'intermediate-ca')
  assert(Boolean(inter) && inter!.status !== 'pass', 'the Intermediate CA check no longer PASSES for an uncollected issuer', `${inter?.status}: ${inter?.detail}`)
  assert(!/directly by a root/i.test(inter?.detail || ''), 'it no longer claims "issued directly by a root authority"')
  const rev = leafTrust?.checks.find((c) => c.key === 'revocation')
  assert(rev?.status === 'not-evaluated', 'revocation stays "not evaluated" without an OCSP/CRL result', rev?.status)

  /* ---------------------------------------------------------------- */
  console.log('\nF. Near-expiry is "expiring", not "invalid" or a chain failure')
  const soon = trustFor(/modern\.example\.test/)
  assert(Boolean(soon) && soon!.checks.some((c) => c.key === 'validity' && c.status === 'fail'), 'the 5-day certificate fails the validity-window check (control)')
  assert(soon ? failedTrustChecks(soon).length === 0 : false, 'but has no failed TRUST check')
  const invalidKpi = trust.kpis.find((k) => k.key === 'invalid')
  assert(Boolean(soon) && !(invalidKpi?.scopeIds ?? []).includes(soon!.certificateId), 'the Invalid KPI does not count it', `invalid scope = ${(invalidKpi?.scopeIds ?? []).join(',')}`)
  const anchor = tls.certificates.find((c) => /Acme Internal Root/.test(c.subject))
  assert(Boolean(anchor) && !(invalidKpi?.scopeIds ?? []).includes(anchor!.id), 'a self-signed ROOT held in inventory is a trust anchor, not invalid (control)')
  const selfLeaf = tls.certificates.find((c) => /selfsigned.example.test/.test(c.subject))
  assert(Boolean(selfLeaf) && (invalidKpi?.scopeIds ?? []).includes(selfLeaf!.id), 'a self-signed certificate SERVED by an endpoint counts as invalid', selfLeaf?.id)
  // An endpoint accepting TLS 1.0 is a protocol finding, not a defect of the certificate it serves.
  assert(leafTrust?.checks.some((c) => c.key === 'tls-compatibility' && c.status === 'fail') === true, 'the TLS 1.0 endpoint\'s certificate fails tls-compatibility (control)')
  assert(Boolean(leafTrust) && !(invalidKpi?.scopeIds ?? []).includes(leafTrust!.certificateId), 'that certificate is NOT counted invalid for its endpoint\'s protocol')
  const chainFailure = trust.events.find((e) => e.kind === 'trust-chain-failure' && /modern\.example\.test/.test(e.title))
  assert(!chainFailure, 'no "Trust-chain failure" event is raised for it')
  const expiredKpi = trust.kpis.find((k) => k.key === 'expired')
  assert(!/already fail/i.test(expiredKpi?.detail || ''), 'the Expired KPI no longer claims handshakes "already fail"', expiredKpi?.detail)
}

/* ------------------------------------------------------------------ */
console.log('\nD. Every classical-only endpoint counts as quantum-vulnerable')
{
  const legacy = tls.endpoints.find((e) => e.host === 'legacy.example.test')
  assert(legacy?.posture === 'legacy', 'the TLS 1.0 endpoint has the exclusive "legacy" posture (control)', legacy?.posture)
  assert(tls.posture.quantumVulnerableEndpoints === tls.posture.classicalOnlyEndpoints, 'quantum-vulnerable equals classical-only', `${tls.posture.quantumVulnerableEndpoints} vs ${tls.posture.classicalOnlyEndpoints}`)
  assert(tls.posture.quantumVulnerableEndpoints >= 1, 'the legacy endpoint is counted', `${tls.posture.quantumVulnerableEndpoints}`)
}

/* ------------------------------------------------------------------ */
console.log('\nE. Probe facts are "accepted", live facts are "negotiated"')
{
  const legacy = tls.endpoints.find((e) => e.host === 'legacy.example.test')
  const live = tls.endpoints.find((e) => e.host === 'live.example.test')
  assert(legacy?.transportBasis === 'scanner-probe', 'scanner-enumerated versions are a scanner probe', legacy?.transportBasis ?? 'null')
  assert(live?.transportBasis === 'live-traffic', 'a runtime handshake is live traffic', live?.transportBasis ?? 'null')
  const probeObs = tls.observations.find((o) => o.endpointId === legacy?.id && o.kind === 'protocol' && o.observed === 'TLS 1.0')
  assert(probeObs?.basis === 'scanner-probe' && /accepted/i.test(probeObs.evidence.detail) && !/^Negotiated/i.test(probeObs.evidence.detail), 'a probed version is described as accepted, not negotiated', probeObs?.evidence.detail)
  assert(tls.observations.every((o) => ['live-traffic', 'scanner-probe', 'inventory-record'].includes(o.basis)), 'every observation carries a basis')
}

console.log('\nG. Listener measurements and certificate identities stay separate')
{
  const result = buildTlsPkiIntelligence({
    ...tlsInputs,
    runtimeEvents: [
      { ...runtimeEvents[0], metadata: { handshakes: 10 } },
      { ...runtimeEvents[0], id: 'second-listener', port: 8443, key_exchange_algorithm: 'X25519', observed_at: days(-2) },
      { id: 'failed-listener-attempt', host: 'live.example.test', port: 443, event_type: 'tls_handshake_failed', observed_at: days(-1) },
      { ...runtimeEvents[0], id: 'latest-primary', key_exchange_algorithm: 'X25519', observed_at: days(-1) },
    ],
    certificates: [
      certificates[0],
      { ...certificates[0], id: 'same-serial-different-issuer', issuer: 'CN=Other Root', not_before: days(10) },
    ],
  })
  const listeners = result.endpoints.filter((row) => row.host === 'live.example.test')
  const primary = listeners.find((row) => row.port === 443)
  assert(listeners.length === 2, 'the same host on 443 and 8443 remains two listeners')
  assert(primary?.handshakeCount === 12, 'ten aggregated and two individual attempts count once each', String(primary?.handshakeCount))
  assert(result.protocol.handshakeFailures === 1, 'a failure with no negotiated version or cipher still counts')
  assert(primary?.posture === 'quantum-vulnerable', 'the newest valid handshake sets current key exchange posture', primary?.posture)
  assert(result.certificates.length === 2, 'identical serial numbers under different issuers remain separate')
  assert(result.pki.lifecycle.notYetValid === 1, 'a future notBefore is reported as not yet valid')
}

console.log('\nH. Discovery scopes relationship limits to the visible subjects')
{
  const link = {
    id: 'stored-edge', from: 'cert:leaf', to: 'endpoint:service', kind: 'protects',
    label: 'protects', state: 'unknown', reason: 'Certificate inventory record',
    source: 'certificate-chain', measured: false,
  } as const
  const subjects = [{ id: link.from }, { id: link.to }]
  const otherLinks = Array.from({ length: 230 }, (_, index) => ({
    ...link, id: `outside-${index}`, to: 'endpoint:other',
  }))
  const scoped = discoveryLinks(subjects, [...otherLinks, link])
  assert(scoped.matchingRelationships === 1 && scoped.relationships[0] === link,
    'unrelated links cannot exhaust the graph limit or alter link direction or provenance')
  const capped = discoveryLinks(subjects, Array.from({ length: 221 }, (_, index) => ({ ...link, id: `visible-${index}` })))
  assert(capped.relationships.length === 220 && capped.matchingRelationships === 221, 'the graph reports limits separately from matching links')
  assert(discoveryLinks([subjects[0]], [link]).matchingRelationships === 0, 'links never point at a subject outside the graph')
}

console.log(failures === 0 ? '\n✓ TLS / PKI / TRUST INTEGRITY INVARIANTS HOLD\n' : `\n✗ ${failures} CHECK(S) FAILED\n`)
console.log('\nI. Account-scoped telemetry and measured operational status')
{
  const linked = 'fixture-asset-a'
  const runtime = [
    { ...runtimeEvents[0], asset_id: linked },
    { ...runtimeEvents[0], id: 'same-asset-second-listener', asset_id: linked, port: 8443 },
    { ...runtimeEvents[0], id: 'different-asset', asset_id: 'fixture-other', host: 'other.example.test' },
  ]
  const portfolio = buildAssetPortfolio({
    assets: [
      { id: linked, name: 'live.example.test', type: 'service' },
      { id: 'fixture-other', name: 'other.example.test', type: 'service' },
      { id: 'unobserved', name: 'unobserved.example.test', type: 'service' },
    ],
    cryptoInventory: [], scanResults: [], cryptoExposures: [], certificates: [], runtimeEvents: runtime,
    relationships: [], migrationJobs: [], validationLogs: [], complianceEvidence: [], now: NOW,
  })
  const model = buildTlsPkiIntelligence({
    ...tlsInputs, assets: portfolio.assets,
    runtimeEvents: runtime,
    cryptoInventory: [
      { id: 'ssh-one', asset_id: linked, name: 'SSH Key Exchange: curve25519-sha256', algorithm: 'curve25519-sha256', protocol: 'SSH',
        metadata: { category: 'SSH Key Exchange', target: 'ssh://live.example.test:22', raw: { banner: 'SSH-2.0-test-fixture' } }, discovered_at: AT },
    ],
    certificates: [
      { ...certificates[0], id: 'legacy-field', asset_id: linked, algorithm: 'SHA256withRSA', not_after: days(-1) },
      { ...certificates[0], id: 'explicit-key', asset_id: linked, serial_number: '05', algorithm: 'SHA384withRSA', metadata: { ...certificates[0].metadata, public_key_algorithm: 'ECDSA' } },
    ],
    queuedAssetIds: [linked, linked, 'unobserved'],
    migrationJobs: [
      { id: 'completed', asset_id: linked, status: 'completed', updated_at: days(-2) },
      { id: 'running', asset_id: linked, status: 'running', updated_at: days(-2) },
      { id: 'simulation', asset_id: linked, status: 'running', metadata: { dryRun: true }, updated_at: days(-1) },
    ],
    validationLogs: [
      { migration_id: 'completed', status: 'passed', created_at: days(-2) },
      { migration_id: 'completed', status: 'invalid', created_at: days(-1) },
      { migration_id: 'running', status: 'validated', created_at: days(-1) },
      { migration_id: 'simulation', status: 'passed', created_at: days(-1) },
    ],
  })
  const legacyCert = model.certificates.find((row) => row.serialNumber === '01')
  const explicitCert = model.certificates.find((row) => row.serialNumber === '05')
  assert(legacyCert?.signatureAlgorithm === 'SHA256withRSA' && legacyCert.publicKeyAlgorithm === 'Not observed', 'legacy signature does not establish a public key')
  assert(explicitCert?.signatureAlgorithm === 'SHA384withRSA' && explicitCert.publicKeyAlgorithm === 'ECDSA', 'explicit leaf key remains distinct from issuer signature')
  assert(Boolean(legacyCert && model.findings.some((row) => row.certificateId === legacyCert.id &&
    row.evidence.some((item) => item.recordId === 'legacy-field'))), 'certificate finding is linked to the exact certificate')
  const operations = model.orchestration
  assert(operations.queueDepth === 1 && operations.queuedAssetIds[0] === linked, 'one queued asset with multiple listeners counts once')
  assert(operations.activeJobCount === 1 && operations.activeJobs.every((row) => row.id !== 'simulation'), 'a simulated job never contributes to live operations')
  assert(operations.validation.validated === 0 && operations.validation.failed === 1 && !operations.validation.lastValidatedAt,
    'latest failed validation supersedes old pass; running and simulated jobs do not validate')
  const sources = {
    scannerAgents: [{ status: 'online', last_seen_at: days(-1) }, { status: 'online', last_seen_at: days(0) }, { status: 'offline', last_seen_at: days(0) }],
    connectorAccounts: [{ status: 'inactive' }, { status: 'disconnected' }, { status: 'active' }],
    scanSessions: [{ status: 'queued' }, { status: 'running' }, { status: 'not_running' }],
  }
  const health = countTelemetrySources(sources, NOW)
  assert(health.agentsOnline === 1 && health.connectorsActive === 1 && health.runningScans === 1,
    'source health excludes stale agents, negative connector statuses and queued scans')
  const encryption = buildEncryptionIntelligence({
    ...sources, now: NOW, assets: portfolio.assets, snapshot: { ...tlsInputs.snapshot, hndlRisk: 0, hndlRiskLevel: 'Unknown' },
    cryptoInventory: [], runtimeEvents: runtime, scannerEvidence: [], generatedKeys: [], vaultFiles: [], cryptoExposures: [],
    scanResults: [], scannerAlerts: [], securityEvents: [],
  })
  const scope = compareTelemetryAssets([
    { id: linked, name: 'Registered TLS', type: 'service', environment: 'test' },
    { id: 'unobserved', name: 'Unobserved asset', type: 'service', environment: 'test' },
  ], { ...model, reads: [] }, { ...encryption, reads: [] })
  assert(scope.assets[0].counts.endpoints >= 2 && scope.assets[0].transport.every((row) => row.assetId === linked),
    'comparison links evidence by asset ID and excludes the other observed asset')
  assert(scope.assets[1].counts.transport === 0 && scope.assets[1].counts.certificates === 0 &&
    scope.assets[0].counts.protection === 0, 'unobserved assets stay empty and TLS handshakes do not establish data protection')
  assert(model.posture.assetsWithoutTransportEvidence === 1 && model.posture.transportCoveragePercent < 100,
    'asset coverage counts registered assets once even when one has several TLS listeners')
  assert(scope.assets[0].ssh[0]?.version === '2.0' && scope.assets[0].ssh[0]?.algorithm === 'curve25519-sha256' &&
    !scope.assets[0].transport.some((row) => row.evidence.recordId === 'ssh-one'),
    'persisted SSH advertisements retain their scanner evidence and never enter TLS distributions')
}

async function checkPipeline() {
  console.log('\nJ. Source windows and SSE delivery')
  const ledger = createSourceLedger('telemetry-test')
  const records = Array.from({ length: 1_050 }, (_, id) => ({ id }))
  const client = { from: () => ({
    select: (_columns: string, options: { count?: string }) => {
      const q = { order: () => q, range: (start: number, end: number) => Promise.resolve({
        data: records.slice(start, Math.min(end + 1, start + 500)),
        count: options.count ? records.length : null,
      }) }
      return q
    },
  }) }
  const rows = await readTelemetrySource(ledger, client, 'fixture', 'id', 1_025, (query) => query)
  assert(rows.length === 1_025 && rows.at(-1)?.id === 1_024 && ledger.reads[0]?.state === 'truncated',
    'multi-page input honors the backend row limit and records incomplete coverage')

  const req = Object.assign(new EventEmitter(), { headers: {} }) as unknown as Request
  const events: string[] = []
  const content = { generatedAt: days(0), tlsSnapshot: { generatedAt: days(0) }, assets: [{ id: 'fixture-asset', count: 1 }] }
  const changed = { ...content, assets: [{ id: 'fixture-asset', count: 2 }] }
  let builds = 0
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      req.emit('close')
      reject(new Error('Timed out while checking SSE frames'))
    }, 1_000)
    const res = {
      status() {},
      setHeader() {},
      write(frame: string) {
        events.push(frame)
        if (events.length === 3) {
          req.emit('close')
          clearTimeout(timeout)
          resolve()
        }
      },
    } as unknown as Response
    streamLiveSnapshot(req, res, {
      event: 'asset-telemetry', intervalMs: 15,
      async build() {
        builds += 1
        if (builds === 1) return content
        if (builds === 2) return { ...content, generatedAt: days(1), tlsSnapshot: { generatedAt: days(1) } }
        return changed
      },
    })
  })
  assert(events[0].includes(payloadFingerprint(content)) && events[1].startsWith('event: asset-telemetry-unchanged') &&
    events[2].includes(payloadFingerprint(changed)), 'REST and SSE fingerprints agree, duplicate checks stay compact and changes publish new content')
  await new Promise((resolve) => setTimeout(resolve, 35))
  assert(builds === 3, 'closing a stream stops subsequent model builds')
}

await checkPipeline()
console.log(failures === 0 ? '\n✓ TELEMETRY AUDIT CHECKS PASSED' : `\n✗ ${failures} invariant(s) failed`)
process.exitCode = failures === 0 ? 0 : 1
