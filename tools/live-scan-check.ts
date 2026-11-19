/**
 * Real Time Scanning — contract checks.
 *
 *   npx tsx tools/live-scan-check.ts            # pure checks only
 *   npx tsx tools/live-scan-check.ts --network [fixture]  # + real engine checks
 *
 * Pure checks: event ordering, replay, duplicate and out-of-order delivery,
 * idempotent graph updates, summary derivation (unknown is never safe),
 * finding classification, and the observation processor's relationship rules
 * (name-only issuer links are inferred, failed signature links are failed,
 * self-signed never becomes a trusted root, no finding without evidence).
 *
 * Network checks run the UNCHANGED `executeWebScan` engine with the live
 * observer against badssl.com — public endpoints maintained as TLS test
 * fixtures — and assert the graph that results from real handshakes.
 */

import { createHash } from 'node:crypto'
import { applyEvents, buildGraph, clusterFindings, emptyGraph, findingsForNode, liveFrameLength, summarize, trace } from '@/lib/live-scan/graph-reducer'
import { TargetObserver, type ObserverSink } from '@/lib/live-scan/observations'
import { classifyEngineFinding, statusForFinding } from '@/lib/live-scan/policy'
import type { LiveEvent, LiveEventPayload, LiveEventType, ActivityLine, LiveNode, RunMeta } from '@/lib/live-scan/types'
import type { EdgeIntelligence } from '@/lib/scanner/web-scanner/edge-intelligence-model'
import type { CertificateInfo, TlsAnalysisResult } from '@/lib/scanner/web-scanner/types'

let passed = 0
let failed = 0
function check(name: string, condition: unknown, detail?: unknown) {
  if (condition) { passed += 1; console.log(`  PASS  ${name}`) } else { failed += 1; console.log(`  FAIL  ${name}${detail !== undefined ? ` — ${JSON.stringify(detail)}` : ''}`) }
}

/* ------------------------------------------------------------------ */
/* A sink identical in behaviour to the router's                       */
/* ------------------------------------------------------------------ */

function stable(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null)
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`
  return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${JSON.stringify(k)}:${stable(v)}`).join(',')}}`
}

function makeRun(targets: string[]) {
  const events: LiveEvent[] = []
  let state = emptyGraph()
  const meta: RunMeta = {
    id: 'run-test', name: 'test', status: 'running', stage: '', createdAt: new Date().toISOString(), startedAt: new Date().toISOString(),
    endedAt: null, targets, completedTargets: [], failedTargets: [], activeTargets: [], sessionId: null, persistence: 'none', errorSummary: null,
    config: { name: 'test', targets, concurrency: 1, targetTimeoutSec: 45, expiringWithinDays: 30, trustStore: 'platform-default' },
  }
  const emit = (type: LiveEventType, payload: LiveEventPayload, activity: ActivityLine | null, entityId: string | null) => {
    const event: LiveEvent = { id: `run-test:${events.length + 1}`, scanId: 'run-test', tenantId: 'tenant-a', seq: events.length + 1, type, at: new Date().toISOString(), entityId, version: 1, payload, activity }
    events.push(event)
    state = applyEvents(state, [event])
    return event
  }
  emit('scan.started', { run: meta }, null, null)
  emit('asset.discovered', { node: { id: 'scanner:helix', kind: 'scanner', label: 'Helix Scanner', status: 'active', targets: [], observedAt: '', firstSeq: 0, lastSeq: 0, evidenceIds: [], data: {} } }, null, 'scanner:helix')
  const sink: ObserverSink = {
    emit,
    hash: (value) => createHash('sha256').update(typeof value === 'string' ? value : stable(value)).digest('hex'),
    now: () => new Date().toISOString(),
    getNode: (id) => state.nodes[id],
    getEdge: (id) => state.edges[id],
    getFinding: (id) => state.findings[id],
  }
  return { events, sink, get state() { return state }, emit }
}

/* ------------------------------------------------------------------ */
/* Fixtures (shapes the engine produces)                               */
/* ------------------------------------------------------------------ */

function cert(over: Partial<CertificateInfo> = {}): CertificateInfo {
  return {
    subject: { CN: 'fixture.example' }, issuer: { CN: 'Fixture Intermediate CA', O: 'Fixture Trust Co' },
    publicKeyAlgorithm: 'RSA-2048', publicKeySize: 2048, signatureAlgorithm: 'sha256WithRSAEncryption', signatureOid: '1.2.840.113549.1.1.11',
    publicKeyOid: '1.2.840.113549.1.1.1', publicKeyCurveOid: null, validFrom: '2026-01-01', validTo: new Date(Date.now() + 200 * 86_400_000).toISOString(),
    serialNumber: '01', fingerprint: 'AA:BB:CC:01', isExpired: false, isSelfSigned: false, detectedOids: [],
    chain: [
      { subject: 'CN=fixture.example', issuer: 'CN=Fixture Intermediate CA, O=Fixture Trust Co', signatureAlgorithm: 'sha256WithRSAEncryption', publicKeyAlgorithm: 'RSA-2048', publicKeySize: 2048, validTo: '2027-01-01', isExpired: false, fingerprint256: 'AA:BB:CC:01', signatureVerifiedByNext: true },
      { subject: 'CN=Fixture Intermediate CA, O=Fixture Trust Co', issuer: 'CN=Fixture Root', signatureAlgorithm: 'sha384WithRSAEncryption', publicKeyAlgorithm: 'RSA-4096', publicKeySize: 4096, validTo: '2030-01-01', isExpired: false, fingerprint256: 'AA:BB:CC:02', signatureVerifiedByNext: null },
      { subject: 'CN=Fixture Root', issuer: 'CN=Fixture Root', signatureAlgorithm: 'sha384WithRSAEncryption', publicKeyAlgorithm: 'RSA-4096', publicKeySize: 4096, validTo: '2035-01-01', isExpired: false, fingerprint256: 'AA:BB:CC:03', signatureVerifiedByNext: null, selfSignatureValid: true },
    ],
    ...over,
  }
}

function edgeIntel(over: { chainTrusted?: boolean | null; trustError?: string | null; hostnameMatches?: boolean | null; hybrid?: boolean; settled?: boolean } = {}): EdgeIntelligence {
  const hybrid = over.hybrid ?? false
  return {
    host: 'fixture.example', port: 443, probedAt: '', durationMs: 1, confidence: 90, notes: [],
    pqKeyAgreement: {
      value: hybrid ? 'Applied' : 'Not offered', state: hybrid ? 'pass' : 'fail', detail: '', evidence: [],
      hybridGroups: hybrid ? ['X25519MLKEM768'] : [], pureKemGroups: [], classicalGroups: ['x25519', 'secp256r1'],
      primaryGroup: hybrid ? 'X25519MLKEM768' : 'x25519', kemParameterSets: hybrid ? ['ML-KEM-768'] : [], classicalComponent: hybrid ? 'X25519' : null,
      postQuantumComponent: hybrid ? 'ML-KEM-768' : null, probed: true, hybridProbed: true,
      hybridGroupsSettled: over.settled === false ? [] : ['X25519MLKEM768'], hybridGroupsInconclusive: [], handshakes: 12,
      inconclusiveGroups: [], unstableGroups: [], untestableGroups: [], confidence: 90,
    },
    transport: {
      negotiatedProtocol: 'TLSv1.3', supportedProtocols: ['TLSv1.3', 'TLSv1.2'], legacyProtocols: [], negotiatedCipher: 'TLS_AES_256_GCM_SHA384',
      keyExchange: 'ECDHE (TLS 1.3 key_share)', forwardSecrecy: true, forwardSecrecyBasis: '', staticRsaAccepted: false, alpn: 'h2', alpnOffered: [],
      http2: true, alpnProbed: true, sessionTickets: null, sessionReuse: null, handshakeMs: 42, error: null,
    },
    certificate: {
      probed: true, ocspStapled: false, ocspResponderState: '', ocspResponderDetail: null, ocspUri: null, mustStaple: false, crlDistributionPoints: [],
      sctPresent: true, sctCount: 2, subjectAltNames: ['fixture.example'], sanCount: 1, isWildcard: false, chainDepth: 3,
      chainTrusted: over.chainTrusted === undefined ? true : over.chainTrusted, trustError: over.trustError ?? null,
      hostnameMatches: over.hostnameMatches === undefined ? true : over.hostnameMatches, daysRemaining: 200, validityDays: 365, error: null,
    },
    dns: { probed: true, addresses: ['93.184.216.34'], addressCount: 1, caaQueryable: true, caaPresent: true, caaRecords: [], caaSource: null, caaAtName: null, caaClimbComplete: true, dnssecQueryable: true, dnssecSigned: false, dnssecValidated: false, spf: null, dmarc: null, transports: [], resolvedVia: 'udp', error: null },
    http: {
      finalUrl: 'https://fixture.example/',
      probed: true, reachable: true, statusCode: 200, httpVersion: 'HTTP/2', hsts: { present: true, status: '', raw: null, maxAge: null, includeSubDomains: false, preload: false, preloadEligible: false, preloadBlockers: [] },
      headers: [], hardenedCount: 0, applicableCount: 0,
      fingerprint: { server: 'cloudflare', poweredBy: null, cdn: 'Cloudflare', waf: null, cloudProvider: null, reverseProxy: null, signals: ['cf-ray'] }, error: null,
    },
    quantum: {
      hybridObserved: hybrid, pqSignatureObserved: false, keyExchange: '', keyExchangeClass: '', forwardSecrecy: '', kemParameterSets: [], postQuantumReadiness: hybrid ? 60 : 10,
      readinessReasons: [], quantumRisk: 'High', quantumRiskScore: 70, riskFactors: [], vulnerability: hybrid ? 'Hybrid-protected' : 'Classical only', vulnerabilityReason: 'fixture', migrationTargets: [],
    },
  }
}

function handshake(c: CertificateInfo): TlsAnalysisResult {
  return {
    tlsVersion: 'TLSv1.3', cipherSuite: 'TLS_AES_256_GCM_SHA384', keyExchange: 'ECDHE (TLS 1.3 key_share)', signatureAlgorithm: c.signatureAlgorithm,
    supportedProtocols: ['TLSv1.3'], protocolSupport: [], negotiatedCurve: null, serverName: 'fixture.example', peerCertificate: c, cipherSuites: [], ephemeralKeyType: null, ephemeralKeySize: null,
  }
}

function observe(over: Parameters<typeof edgeIntel>[0] = {}, certOver: Partial<CertificateInfo> = {}) {
  const run = makeRun(['fixture.example'])
  const observer = new TargetObserver(run.sink, { scanId: 'run-test', target: 'fixture.example', host: 'fixture.example', port: 443, expiringWithinDays: 30, inventory: null })
  observer.discovered(['93.184.216.34'])
  const c = cert(certOver)
  observer.edgeEvidence(edgeIntel(over), handshake(c), null)
  return { run, observer }
}

/* ------------------------------------------------------------------ */
/* Pure checks                                                         */
/* ------------------------------------------------------------------ */

console.log('\n[1] Reducer: ordering, replay, duplicates, out-of-order')
{
  const { run } = observe()
  const all = run.events
  const shuffled = [...all].reverse()
  const fromShuffled = applyEvents(emptyGraph(), shuffled)
  const fromOrdered = buildGraph(all)
  let stepped = emptyGraph()
  let maxNewCards = 0
  const buffered = [...all]
  while (buffered.length) {
    const frame = buffered.splice(0, liveFrameLength(stepped, buffered))
    const next = applyEvents(stepped, frame)
    maxNewCards = Math.max(maxNewCards, Object.keys(next.nodes).length - Object.keys(stepped.nodes).length)
    stepped = next
  }
  check('buffered live frames reveal at most one new card and preserve the full recording',
    maxNewCards === 1 && stepped.lastSeq === fromOrdered.lastSeq && stable(stepped.nodes) === stable(fromOrdered.nodes))
  check('shuffled delivery converges to the same graph', stable(Object.keys(fromShuffled.nodes).sort()) === stable(Object.keys(fromOrdered.nodes).sort()) && Object.keys(fromShuffled.edges).length === Object.keys(fromOrdered.edges).length)
  const doubled = applyEvents(fromOrdered, all)
  check('re-applying the whole log is a no-op (same object)', doubled === fromOrdered)
  check('applied count equals distinct events', fromOrdered.applied === all.length && fromOrdered.lastSeq === all.length)
  const half = Math.floor(all.length / 2)
  const resumed = applyEvents(applyEvents(emptyGraph(), all.slice(0, half + 3)), all.slice(half)) // overlapping replay after reconnect
  check('snapshot + overlapping stream resume has no gaps or duplicates', resumed.applied === all.length && Object.keys(resumed.nodes).length === Object.keys(fromOrdered.nodes).length)
  const prefix = buildGraph(all, 5)
  check('timeline prefix only contains events ≤ seq', prefix.lastSeq === 5)
  // An older update for an existing node must not roll it back.
  const nodeId = 'asset:fixture.example'
  const later = fromOrdered.nodes[nodeId]
  const stale: LiveEvent = { ...all[0], seq: 1, id: 'x', payload: { node: { ...later, status: 'observed', label: 'STALE' } } }
  const afterStale = applyEvents({ ...fromOrdered, appliedSeqs: new Set([...fromOrdered.appliedSeqs].filter((s) => s !== 1)) }, [stale])
  check('a stale (lower-seq) node update is ignored', afterStale.nodes[nodeId].label !== 'STALE')
}

console.log('\n[2] Relationship rules')
{
  const run = makeRun(['fixture.example'])
  const observer = new TargetObserver(run.sink, { scanId: 'run-test', target: 'fixture.example', host: 'fixture.example', port: 443, expiringWithinDays: 30, inventory: null })
  observer.discovered([])
  const expired = cert({ validTo: '2024-01-01', isExpired: true })
  const intel = edgeIntel({ chainTrusted: false, trustError: 'CERT_HAS_EXPIRED', settled: false })
  intel.transport.negotiatedProtocol = null
  intel.transport.keyExchange = 'unknown'
  intel.pqKeyAgreement.primaryGroup = null
  intel.pqKeyAgreement.classicalGroups = []
  observer.edgeEvidence(intel, null, null, expired)
  const leaf = Object.values(run.state.nodes).find((node) => node.kind === 'certificate')
  const expiry = Object.values(run.state.findings).find((finding) => finding.type === 'CERTIFICATE_EXPIRED')
  check('certificate-only probe creates a critical leaf with its observed expiry', leaf?.status === 'critical' && leaf.data.validTo === expired.validTo)
  check('expired leaf evidence links to the actual certificate card', Boolean(leaf && expiry && findingsForNode(run.state, leaf).includes(expiry)))
  check('asset and certificate expose the same expiry record', Boolean(expiry && findingsForNode(run.state, run.state.nodes['asset:fixture.example']).includes(expiry)))
  check('unknown transport does not create a classical key establishment node', !Object.values(run.state.edges).some((edge) => edge.type === 'NEGOTIATED_KEY_ESTABLISHMENT'))
  observer.engineFinding({ phase: 'cert-analysis', algorithm: 'Expired Certificate', category: 'Certificate', threatLevel: 'CRITICAL',
    location: 'fixture.example', description: 'Expired', recommendation: 'Renew', quantumBreakTime: 'N/A', classicalBreakTime: 'N/A' } as never)
  check('engine expiry does not duplicate the certificate policy finding', Object.values(run.state.findings).filter((finding) => finding.type === 'CERTIFICATE_EXPIRED').length === 1)
}
{
  const { run } = observe()
  const s = run.state
  const leaf = Object.values(s.nodes).find((n) => n.kind === 'certificate')!
  const issued = Object.values(s.edges).find((e) => e.type === 'ISSUED_BY')!
  check('leaf→intermediate link is validated when signature verified', issued?.verification === 'validated')
  const signed = Object.values(s.edges).find((e) => e.type === 'SIGNED_BY')
  check('intermediate→root link without DER verification is inferred (dashed), not validated', signed?.verification === 'inferred', signed?.verification)
  check('endpoint PRESENTS_CERTIFICATE is directly observed', Object.values(s.edges).some((e) => e.type === 'PRESENTS_CERTIFICATE' && e.verification === 'observed' && e.target === leaf.id))
  check('path acceptance names the store without claiming a specific anchor', Object.values(s.edges).some((e) => e.type === 'CHAIN_VALIDATED_TO' && e.target === 'truststore:platform-default')
    && !Object.values(s.edges).some((e) => e.type === 'TRUSTED_BY_STORE'))
  check('CA organization is an inferred attribution', Object.values(s.edges).some((e) => e.type === 'MANAGED_BY_VENDOR' && e.verification === 'inferred'))
  check('CDN attributed from headers is an inferred edge', Object.values(s.edges).some((e) => e.type === 'BACKED_BY' && e.verification === 'inferred'))
  check('public key, signature and key-establishment are separate algorithm roles',
    ['public-key', 'signature', 'key-establishment'].every((role) => Object.values(s.nodes).some((n) => n.kind === 'algorithm' && n.data.roleKey === role)))
  check('RSA-2048 public key is classified as quantum exposure', Object.values(s.nodes).some((n) => n.kind === 'algorithm' && n.label === 'RSA-2048' && n.status === 'exposure'))
  check('every edge carries scan id, evidence and basis', Object.values(s.edges).every((e) => e.scanId === 'run-test' && e.basis && e.observedAt))

  const failedLink = observe({}, { chain: cert().chain.map((entry, index) => (index === 0 ? { ...entry, signatureVerifiedByNext: false } : entry)) })
  check('a failed signature verification draws a failed (red) link', Object.values(failedLink.run.state.edges).some((e) => e.type === 'ISSUED_BY' && e.verification === 'failed' && e.risk === 'critical'))

  const selfSigned = observe({ chainTrusted: false, trustError: 'DEPTH_ZERO_SELF_SIGNED_CERT' }, {
    isSelfSigned: true, issuer: { CN: 'fixture.example' },
    chain: [{ subject: 'CN=fixture.example', issuer: 'CN=fixture.example', signatureAlgorithm: 'sha256WithRSAEncryption', publicKeyAlgorithm: 'RSA-2048', publicKeySize: 2048, validTo: '2030-01-01', isExpired: false, selfSignatureValid: true, signatureVerifiedByNext: null }],
  })
  const ss = selfSigned.run.state
  check('self-signed leaf: no trust store node, no CHAIN_VALIDATED_TO', !ss.nodes['truststore:platform-default'] && !Object.values(ss.edges).some((e) => e.type === 'CHAIN_VALIDATED_TO'))
  check('self-signed leaf raises UNTRUSTED_CERTIFICATE_AUTHORITY with evidence', Object.values(ss.findings).some((f) => f.type === 'UNTRUSTED_CERTIFICATE_AUTHORITY' && f.evidenceIds.length > 0))

  const mismatch = observe({ hostnameMatches: false })
  check('hostname mismatch raises HOSTNAME_VALIDATION_FAILED', Object.values(mismatch.run.state.findings).some((f) => f.type === 'HOSTNAME_VALIDATION_FAILED'))

  const expiring = observe({}, { validTo: new Date(Date.now() + 10 * 86_400_000).toISOString() })
  check('certificate inside the window raises CERTIFICATE_EXPIRING', Object.values(expiring.run.state.findings).some((f) => f.type === 'CERTIFICATE_EXPIRING'))

  const hybrid = observe({ hybrid: true })
  const kex = Object.values(hybrid.run.state.nodes).find((n) => n.kind === 'algorithm' && n.data.roleKey === 'key-establishment')
  check('measured hybrid ML-KEM is validated, not exposure', kex?.label === 'X25519MLKEM768' && kex.status === 'validated', kex?.status)

  const unsettled = observe({ settled: false })
  check('unsettled PQ probe yields PQC_READINESS_UNKNOWN (status unknown), never a negative claim',
    Object.values(unsettled.run.state.findings).some((f) => f.type === 'PQC_READINESS_UNKNOWN' && f.status === 'unknown'))
  check('vendor dependency finding only when classical KEX was SETTLED', !Object.values(unsettled.run.state.findings).some((f) => f.type === 'VENDOR_MIGRATION_DEPENDENCY')
    && Object.values(observe().run.state.findings).some((f) => f.type === 'VENDOR_MIGRATION_DEPENDENCY'))
  const redirected = makeRun(['fixture.example'])
  const observer = new TargetObserver(redirected.sink, { scanId: 'run-test', target: 'fixture.example', host: 'fixture.example', port: 443, expiringWithinDays: 30, inventory: null })
  observer.discovered([])
  const intel = edgeIntel()
  intel.http.finalUrl = 'https://redirect.example/login'
  observer.edgeEvidence(intel, handshake(cert()), null)
  check('redirect vendor attribution belongs to the observed response origin', Object.values(redirected.state.edges)
    .some((edge) => edge.type === 'BACKED_BY' && edge.source === 'app:https://redirect.example' && edge.verification === 'inferred'))
  check('redirect headers cannot trigger a vendor dependency finding for the scanned TLS endpoint', !Object.values(redirected.state.findings)
    .some((finding) => finding.type === 'VENDOR_MIGRATION_DEPENDENCY'))
}

console.log('\n[3] Findings + summary')
{
  const { run, observer } = observe()
  observer.engineFinding({ id: 'f1', phase: 'cert-analysis', algorithm: 'RSA-2048', location: 'Certificate', threatLevel: 'HIGH', category: 'RSA', description: 'RSA key', recommendation: 'Migrate to ML-DSA', quantumBreakTime: '', classicalBreakTime: '' })
  observer.engineFinding({ id: 'f2', phase: 'cert-analysis', algorithm: 'RSA-2048', location: 'Certificate', threatLevel: 'HIGH', category: 'RSA', description: 'RSA key dup', recommendation: 'Migrate', quantumBreakTime: '', classicalBreakTime: '' })
  observer.engineFinding({ id: 'f3', phase: 'key-exchange', algorithm: 'X25519MLKEM768', location: 'TLS', threatLevel: 'SAFE', category: 'Key Exchange', description: 'hybrid', recommendation: '', quantumBreakTime: '', classicalBreakTime: '' })
  const findings = Object.values(run.state.findings)
  const rsa = findings.filter((f) => f.type === 'QUANTUM_VULNERABLE_PUBLIC_KEY')
  check('identical engine findings collapse into one finding node', rsa.length === 1)
  check('RSA finding links to the leaf certificate AND the RSA-2048 algorithm node', rsa[0]?.affectedNodeIds.some((id) => id.startsWith('cert:')) && rsa[0]?.affectedNodeIds.some((id) => id.startsWith('alg:public-key')))
  check('SAFE engine results never become findings', !findings.some((f) => f.title.includes('X25519MLKEM768')))
  check('no finding without an evidence record', findings.every((f) => f.evidenceIds.length > 0 && f.evidenceIds.every((id) => run.state.evidence[id])))
  check('quantum-migration edges use REQUIRES_MIGRATION', Object.values(run.state.edges).some((e) => e.type === 'REQUIRES_MIGRATION' && e.target === rsa[0].id))
  observer.completed(null, 'engine crashed')
  const sum = summarize(run.state)
  check('a failed target is counted as unknown, never as safe', sum.unknownAssessments >= 1)
  check('quantum-exposed asset count derived from findings', sum.quantumExposedAssets === 1)
  const traced = trace(run.state, 'asset:fixture.example', 'downstream')
  check('downstream trace reaches the certificate and its CA', [...traced].some((id) => id.startsWith('cert:')) && [...traced].some((id) => id.startsWith('ca:')))
}

console.log('\n[3b] Finding groups (presentation only)')
{
  const { run, observer } = observe()
  for (const suite of ['TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256']) {
    observer.engineFinding({ id: suite, phase: 'cipher-enum', algorithm: suite, location: 'Cipher', threatLevel: 'HIGH', category: 'Cipher Suite', description: suite, recommendation: 'disable', quantumBreakTime: '', classicalBreakTime: '' })
  }
  const before = run.state
  const display = clusterFindings(before, new Set())
  const group = Object.values(display.nodes).find((n) => n.id.startsWith('group:'))
  const members = (group?.data.memberIds as string[] | undefined) ?? []
  check('4 same-type findings on one endpoint collapse into one group node', members.length === 4, members.length)
  check('grouping never mutates the record', Object.keys(before.findings).length === Object.keys(display.findings).length && Boolean(before.nodes[members[0]]))
  check('edges into members are re-pointed at the group', Object.values(display.edges).some((e) => e.target === group?.id) && !Object.values(display.edges).some((e) => members.includes(e.target)))
  check('expanding a group restores its members', Boolean(group) && Boolean(clusterFindings(before, new Set([group!.id])).nodes[members[0]]))
  check('summary counts read records, not groups', summarize(display).findingsTotal === summarize(before).findingsTotal)
}

console.log('\n[4] Policy classification')
{
  check('expired certificate → CERTIFICATE_EXPIRED / invalid cryptography', classifyEngineFinding({ phase: 'cert-analysis', category: 'Certificate', algorithm: 'Expired Certificate', threatLevel: 'CRITICAL' }).type === 'CERTIFICATE_EXPIRED')
  check('TLS 1.0 → LEGACY_TLS_CONFIGURATION', classifyEngineFinding({ phase: 'tls-handshake', category: 'Protocol Support', algorithm: 'TLSv1', threatLevel: 'CRITICAL' }).type === 'LEGACY_TLS_CONFIGURATION')
  check('connectivity failure → SCAN_INCOMPLETE (unknown, not safe)', classifyEngineFinding({ phase: 'tls-handshake', category: 'Connectivity', algorithm: 'TLS Connection Failed', threatLevel: 'MEDIUM' }).exposure === 'unknown-migration-status')
  check('symmetric AES is not quantum-migration exposure', classifyEngineFinding({ phase: 'cipher-enum', category: 'Cipher Suite', algorithm: 'AES-128-GCM', threatLevel: 'LOW' }).exposure !== 'quantum-migration')
  check('HIGH quantum-migration exposure renders orange, not red', statusForFinding('high', 'quantum-migration') === 'exposure')
  check('TLS 1.2 is NOT labelled legacy', classifyEngineFinding({ phase: 'tls-handshake', category: 'Protocol', algorithm: 'TLSv1.2', threatLevel: 'MEDIUM' }).type !== 'LEGACY_TLS_CONFIGURATION')
  check('certificate-risk rule on RSA key → quantum-vulnerable public key', classifyEngineFinding({ phase: 'risk-calculation', category: 'Rule (Certificate Risk)', algorithm: 'Weak RSA Key Size', threatLevel: 'HIGH' }).type === 'QUANTUM_VULNERABLE_PUBLIC_KEY')
  check('RSA-2048 (Certificate) in cert phase → quantum-vulnerable public key', classifyEngineFinding({ phase: 'cert-analysis', category: 'Certificate', algorithm: 'RSA-2048 (Certificate)', threatLevel: 'HIGH' }).type === 'QUANTUM_VULNERABLE_PUBLIC_KEY')
}

/* ------------------------------------------------------------------ */
/* Network: real engine, real handshakes                               */
/* ------------------------------------------------------------------ */

async function networkChecks() {
  const { executeWebScan } = await import('@/lib/scanner/web-scanner/scan-orchestrator')
  const { verifyPublicHost } = await import('@/lib/scanner/public-scan/safe-dns')
  type Expect = (s: ReturnType<typeof makeRun>['state']) => Array<[string, boolean, unknown?]>
  const cases: Array<[string, Expect]> = [
    ['sha256.badssl.com', (s) => {
      const ep = s.nodes['endpoint:sha256.badssl.com:443']
      return [
        ['valid chain: endpoint chainTrusted === true', ep?.data.chainTrusted === true, ep?.data.chainTrusted],
        ['valid chain: CHAIN_VALIDATED_TO present', Object.values(s.edges).some((e) => e.type === 'CHAIN_VALIDATED_TO')],
        ['valid chain: at least one signature-verified issuer link', Object.values(s.edges).some((e) => (e.type === 'ISSUED_BY' || e.type === 'SIGNED_BY') && e.verification === 'validated')],
        ['chain CA signature algorithms are parsed (not "unknown")', Object.values(s.nodes).filter((n) => n.kind === 'ca').every((n) => n.data.signatureAlgorithm && n.data.signatureAlgorithm !== 'unknown')],
      ]
    }],
    ['expired.badssl.com', (s) => [
      ['expired: an expiry finding exists', Object.values(s.findings).some((f) => f.type === 'CERTIFICATE_EXPIRED'), Object.values(s.findings).map((f) => f.type)],
      ['expired: certificate card is linked to the expiry finding', Object.values(s.nodes).some((node) => node.kind === 'certificate' && node.data.expirationStatus === 'Expired' && findingsForNode(s, node).some((finding) => finding.type === 'CERTIFICATE_EXPIRED'))],
      ['expired: chain NOT validated', s.nodes['endpoint:expired.badssl.com:443']?.data.chainTrusted !== true],
    ]],
    ['self-signed.badssl.com', (s) => [
      ['self-signed: untrusted CA finding', Object.values(s.findings).some((f) => f.type === 'UNTRUSTED_CERTIFICATE_AUTHORITY' || f.type === 'CERTIFICATE_CHAIN_INVALID')],
      ['self-signed: no trust store anchor', !Object.values(s.edges).some((e) => e.type === 'TRUSTED_BY_STORE')],
    ]],
    ['wrong.host.badssl.com', (s) => [
      ['wrong host: HOSTNAME_VALIDATION_FAILED', Object.values(s.findings).some((f) => f.type === 'HOSTNAME_VALIDATION_FAILED'), Object.values(s.findings).map((f) => f.type)],
    ]],
    ['untrusted-root.badssl.com', (s) => [
      ['untrusted root: chain not validated + finding', s.nodes['endpoint:untrusted-root.badssl.com:443']?.data.chainTrusted === false && Object.values(s.findings).some((f) => f.type === 'UNTRUSTED_CERTIFICATE_AUTHORITY' || f.type === 'CERTIFICATE_CHAIN_INVALID')],
    ]],
    ['ecc256.badssl.com', (s) => [
      ['EC key: ECDSA P-256 public-key node, quantum exposure', Object.values(s.nodes).some((n) => n.kind === 'algorithm' && /ECDSA P-256/.test(n.label) && n.status === 'exposure')],
    ]],
    ['rsa2048.badssl.com', (s) => [
      ['RSA key: RSA-2048 public-key node, quantum exposure', Object.values(s.nodes).some((n) => n.kind === 'algorithm' && n.label === 'RSA-2048' && n.status === 'exposure')],
    ]],
  ]
  const requested = process.argv[process.argv.indexOf('--network') + 1]
  const selected = requested ? cases.filter(([host]) => host === requested) : cases
  if (!selected.length) throw new Error('Unknown BadSSL fixture')
  for (const [host, expect] of selected) {
    console.log(`\n[net] ${host}`)
    const run = makeRun([host])
    const observer = new TargetObserver(run.sink, { scanId: 'run-test', target: host, host, port: 443, expiringWithinDays: 30, inventory: null })
    const verdict = await verifyPublicHost(host)
    if (!verdict.ok) { check(`${host} resolves publicly`, false, verdict.message); continue }
    observer.discovered(verdict.addresses ?? [])
    let certificateBeforeBundle = false
    const result = await executeWebScan(host, 'domain', (event) => {
      if (event.type === 'finding' && event.finding) observer.engineFinding(event.finding as never)
    }, 30_000, {
      onCertificateEvidence: (evidence) => observer.certificateEvidence(evidence),
      onHttpEvidence: (evidence) => observer.httpEvidence(evidence),
      onEdge: ({ intelligence, handshake: hs, certificate, error }) => {
        certificateBeforeBundle = Object.values(run.state.nodes).some((node) => node.kind === 'certificate')
        observer.edgeEvidence(intelligence, hs, error, certificate)
      },
      onTls: (tls) => observer.tlsEvidence(tls),
    }).catch((error) => { console.log('    engine error', (error as Error).message); return null })
    observer.completed(result, result ? null : 'engine error')
    const s = run.state
    console.log(`    ${Object.keys(s.nodes).length} nodes · ${Object.keys(s.edges).length} edges · ${Object.keys(s.findings).length} findings · ${run.events.length} events`)
    for (const [name, ok, detail] of expect(s)) check(`${host}: ${name}`, ok, detail)
    if (host === 'expired.badssl.com') check('expired certificate was published before the edge bundle completed', certificateBeforeBundle)
    check(`${host}: every finding has evidence`, Object.values(s.findings).every((f) => f.evidenceIds.every((id) => s.evidence[id])))
  }
}

;(async () => {
  if (process.argv.includes('--network')) await networkChecks()
  console.log(`\n${passed} passed, ${failed} failed`)
  process.exit(failed ? 1 : 0)
})()
