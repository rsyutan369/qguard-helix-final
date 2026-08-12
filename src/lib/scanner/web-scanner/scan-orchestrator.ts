/**
 * QGuard Web Scanner — Scan Orchestrator
 * Coordinates all scanner modules and streams results via SSE
 */

import type {
  WebScanTargetType,
  WebScanCompleteResult,
  WebScanFinding,
  TlsAnalysisResult,
  CertificateInfo,
  GitRepoScanResult,
  WebCryptoScanResult,
  ApiSecurityResult,
  SSEEvent,
  ThreatLevel,
  DetectionRuleResult,
  CipherSuiteDetail,
  PQCMigrationDetail,
  WebScanRiskBreakdown,
} from './types'
import { parseTarget, analyzeTls } from './tls-analyzer'
import { collectEdgeIntelligence, type EdgeIntelligence } from './edge-intelligence'
import { measuredKeyAgreement } from './edge-intelligence-model'
import { pqcReplacementFor } from './oid-database'
import { leafRestatedOids } from './certificate-parser'
import { analyzeCipherSuites } from './cipher-suite-analyzer'
import { scanRepository, repositoryProvider } from './repo-scanner'
import { PROVIDER_LABEL } from './repo-providers'
import { scanWebCrypto } from './web-crypto-scanner'
import { scanApiSecurity } from './api-security-scanner'
import { evaluateDetectionRules } from './detection-rules'
import { calculateRiskScore, calculateNistComplianceScore, calculateConfidenceScore } from './risk-scoring'
import { generatePqcRecommendations } from './pqc-recommendations'
import { getScannerRuntimeHealth } from './runtime-health'

/**
 * Wall-clock ceiling for one target.
 *
 * Lowered from 210s once the edge phase stopped being the bottleneck. Named-group
 * probing used to spend 40 sequential handshakes with a fixed 150ms gap between
 * each, which made that one phase 85-97% of a scan; it now discovers
 * concurrently and re-probes only the falsifiable results (see the TLS engine),
 * and a healthy target finishes the whole edge pass in 3-6s. This is a backstop
 * for a pathological endpoint, not the shape of a normal scan.
 */
const SCAN_TIMEOUT = 120_000
const MODULE_TIMEOUT = 15_000 // 15 seconds per individual module
const TLS_MODULE_TIMEOUT = 45_000 // TLS needs room for primary handshake + protocol/cipher probes
/**
 * Outer guard for the whole edge phase: TLS enumeration + named groups +
 * session + certificate chain/OCSP + DNS + HTTP. The engines carry their own
 * DEGRADE-BY budget (`EDGE_BUDGET_MS`, or a per-target share handed down by a
 * multi-target run) and return partial evidence when it expires, so this fires
 * only if one of them wedges — never as part of a normal scan.
 */
const EDGE_MODULE_TIMEOUT = 60_000

/**
 * Default degrade-by budget for one target's edge probing when the caller does
 * not divide a run budget across a queue.
 */
export const EDGE_BUDGET_MS = 45_000
const TLS_MAX_RETRIES = 1
const MAX_RETRIES = 2 // Retry failed modules up to 2 times
const RETRY_DELAY = 500 // 500ms between retries

/**
 * Marker prefix for a module that did not run because it does not apply to the
 * evidence available, as opposed to one that ran and failed.
 *
 * The orchestrator used to signal both conditions through the same free-text
 * `error` field, and the API layer sniffed the substring "skipped" to decide
 * which it was. That is why "Transport & Ciphers" and "Certificates & Keys"
 * reported SKIPPED with no explanation the operator could act on. A module is
 * now either Completed / No findings / Failed, or explicitly Not applicable
 * WITH the reason attached — never an unexplained skip.
 */
export const NOT_APPLICABLE_PREFIX = 'not-applicable:'

/** Compose the documented not-applicable signal for `moduleComplete`. */
function notApplicable(reason: string): string {
  return `${NOT_APPLICABLE_PREFIX} ${reason}`
}

/**
 * The repository module's display name, naming the platform actually detected.
 *
 * The catalog id stays `github-scanner` — it is the stable routing key into the
 * module ledger — but the operator sees "GitLab Repository Scanner" when they
 * scanned GitLab. Reporting every platform as "GitHub" was accurate only for
 * one of the five now supported.
 */
function repoScannerName(target: string): string {
  const provider = repositoryProvider(target)
  return provider ? `${PROVIDER_LABEL[provider]} Repository Scanner` : 'Repository Scanner'
}

// ─── Module Retry Wrapper ───────────────────────────────────────────────────

/**
 * Execute a scanner module with retry logic and timeout
 */
async function withRetry<T>(
  fn: () => Promise<T>,
  moduleName: string,
  retries: number = MAX_RETRIES,
  timeout: number = MODULE_TIMEOUT
): Promise<{ result: T | null; attempts: number; error: string | null }> {
  let lastError: string | null = null
  for (let attempt = 1; attempt <= retries + 1; attempt++) {
    try {
      let timer: ReturnType<typeof setTimeout> | undefined
      const result = await new Promise<T>((resolve, reject) => {
        let settled = false
        timer = setTimeout(() => {
          if (settled) return
          settled = true
          reject(new Error(`${moduleName} timed out after ${timeout}ms`))
        }, timeout)

        fn()
          .then((value) => {
            if (settled) return
            settled = true
            if (timer) clearTimeout(timer)
            resolve(value)
          })
          .catch((err) => {
            if (settled) return
            settled = true
            if (timer) clearTimeout(timer)
            reject(err)
          })
      })
      return { result, attempts: attempt, error: null }
    } catch (err) {
      lastError = (err as Error).message
      if (attempt <= retries) {
        await new Promise(resolve => setTimeout(resolve, RETRY_DELAY * attempt))
      }
    }
  }
  return { result: null, attempts: retries + 1, error: lastError }
}

/**
 * Calculate HNDL (Harvest Now, Decrypt Later) risk timeline
 *
 * `kemApplied` is the MEASURED verdict from the edge engine's named-group
 * probing, not a substring test on the key-exchange label. Node's
 * `getEphemeralKeyInfo()` returns an empty object for a TLS 1.3 handshake, so
 * the label degrades to the generic "ECDHE (TLS 1.3 key_share)" on every modern
 * endpoint — including ones that negotiated a hybrid ML-KEM group. Deciding
 * harvest-now exposure from that string reported endpoints with live hybrid PQ
 * key agreement as fully harvestable.
 */
function calculateHndlTimeline(
  keyExchange: string,
  certAlg: string,
  keySize: number,
  kemApplied = false
): { yearsToQuantumThreat: number; dataShelfLife: string; urgency: 'IMMEDIATE' | 'HIGH' | 'MEDIUM' | 'LOW' } {
  // Estimate years until CRQC can break the algorithm
  let yearsToBreak = 15 // default conservative estimate

  if (keyExchange.includes('RSA') || certAlg.includes('RSA')) {
    if (keySize <= 1024) yearsToBreak = 3
    else if (keySize <= 2048) yearsToBreak = 7
    else if (keySize <= 4096) yearsToBreak = 10
    else yearsToBreak = 12
  }

  if (keyExchange.includes('ECDHE') || certAlg.includes('EC')) {
    yearsToBreak = 8 // ECC is more efficient for quantum attacks
  }

  if (kemApplied || keyExchange.includes('Kyber') || keyExchange.includes('ML-KEM')) {
    yearsToBreak = 50 // session secrets are not recoverable by Shor
  }

  let urgency: 'IMMEDIATE' | 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW'
  let dataShelfLife = '< 1 year'

  if (yearsToBreak <= 5) {
    urgency = 'IMMEDIATE'
    dataShelfLife = 'Data with >5 year confidentiality at risk NOW'
  } else if (yearsToBreak <= 8) {
    urgency = 'HIGH'
    dataShelfLife = 'Data with >8 year confidentiality at risk'
  } else if (yearsToBreak <= 12) {
    urgency = 'MEDIUM'
    dataShelfLife = 'Plan migration within 2-3 years'
  } else {
    dataShelfLife = 'Low immediate risk — monitor quantum computing progress'
  }

  return { yearsToQuantumThreat: yearsToBreak, dataShelfLife, urgency }
}

// ─── Orchestrator ───────────────────────────────────────────────────────────

/**
 * Execute a full web scan and stream results via the onEvent callback
 */
export async function executeWebScan(
  target: string,
  targetType: WebScanTargetType,
  onEvent: (event: SSEEvent) => void,
  /**
   * Degrade-by budget for this target's edge probing. A queue of assets divides
   * the run's budget across its targets and passes each one its share, so the
   * total stays predictable however many assets were submitted.
   */
  edgeBudgetMs: number = EDGE_BUDGET_MS
): Promise<WebScanCompleteResult> {
  const scanId = crypto.randomUUID()
  const startTime = Date.now()
  const findings: WebScanFinding[] = []
  let findingCounter = 0

  let tlsResult: TlsAnalysisResult | null = null
  let certInfo: CertificateInfo | null = null
  let repoResult: GitRepoScanResult | null = null
  let webCryptoResult: WebCryptoScanResult | null = null
  let apiResult: ApiSecurityResult | null = null
  let cipherSuiteBreakdown: CipherSuiteDetail[] = []
  let ruleResults: DetectionRuleResult[] = []
  let pqcRecommendations: PQCMigrationDetail[] = []
  let edgeIntelligence: EdgeIntelligence | null = null
  const runtimeHealth = getScannerRuntimeHealth()

  // Helper to emit events
  function emit(data: Partial<SSEEvent> & { type: SSEEvent['type'] }) {
    onEvent({
      scanId,
      timestamp: new Date().toISOString(),
      ...data,
    } as SSEEvent)
  }

  // Helper to add a finding and emit it
  function addFinding(finding: Omit<WebScanFinding, 'id'>): WebScanFinding {
    findingCounter++
    const f: WebScanFinding = { ...finding, id: `ws-finding-${findingCounter}` }
    findings.push(f)
    emit({
      type: 'finding',
      phase: finding.phase,
      finding: f,
      metrics: buildLiveMetrics(findings, startTime),
    })
    return f
  }

  // Helper for phase events
  function phaseStart(phase: string, label: string, progress: number) {
    emit({ type: 'phase-start', phase, label, progress, metrics: buildLiveMetrics(findings, startTime, progress) })
  }

  function phaseComplete(phase: string, label: string, progress: number) {
    emit({ type: 'phase-complete', phase, label, progress, metrics: buildLiveMetrics(findings, startTime, progress) })
  }

  function moduleStart(moduleId: string, moduleName: string, targetName: string, progress: number) {
    emit({
      type: 'module-start',
      moduleId,
      moduleName,
      target: targetName,
      progress,
      queueState: 'running',
      metrics: buildLiveMetrics(findings, startTime, progress),
    })
  }

  function moduleComplete(moduleId: string, moduleName: string, targetName: string, progress: number, findingCount: number, error?: string | null) {
    emit({
      type: 'module-complete',
      moduleId,
      moduleName,
      target: targetName,
      progress,
      findingCount,
      queueState: 'running',
      error: error || undefined,
      metrics: buildLiveMetrics(findings, startTime, progress),
    })
  }

  /**
   * Close out the four edge modules against the evidence bundle.
   *
   * FINDING OWNERSHIP
   * -----------------
   * Each module emits only the claims NOTHING ELSE emits, so a single
   * observation is never counted twice across the assessment:
   *
   *  • The post-quantum prober emits only the POSITIVE result. The negative —
   *    "no hybrid group accepted" — is already owned by detection rules
   *    PQC-001/002/003, which now read this same measurement. Publishing it
   *    here as well would double the penalty for one fact.
   *  • Revocation and transparency emit OCSP and SCT findings, which no other
   *    module produces.
   *  • DNS security emits CAA and DNSSEC findings, which no other module
   *    produces.
   *  • Edge attribution emits none: naming a CDN is context, not a defect.
   *
   * A module with nothing to report ends `No findings` — a measured terminal
   * state — and a module whose evidence never arrived ends with the reason
   * attached, never silently.
   */
  function emitEdgeModuleStates(
    edge: EdgeIntelligence | null,
    edgeError: string | null,
    hostname: string,
    port: number,
  ) {
    const unavailable = edgeError
      ? `public-edge probing did not complete: ${edgeError}`
      : 'the public-edge intelligence engine returned no evidence for this target'

    /* ── DNS security: CAA + DNSSEC ─────────────────────────────────────── */
    const dnsFindingStart = findings.length
    if (edge?.dns.probed) {
      if (edge.dns.caaQueryable && !edge.dns.caaPresent) {
        addFinding({
          phase: 'edge-intelligence',
          algorithm: 'No CAA Issuance Policy',
          location: `DNS — ${hostname}`,
          threatLevel: 'LOW',
          category: 'DNS Security',
          description: `No CAA record is published for ${edge.dns.caaAtName || hostname}, so any public CA may issue a certificate for this name. Answered authoritatively via ${edge.dns.caaSource || 'DNS'}.`,
          recommendation: 'Publish a CAA record naming the authorized issuers, and add an iodef contact for violation reports.',
          quantumBreakTime: 'N/A',
          classicalBreakTime: 'N/A',
        })
      }
      if (edge.dns.dnssecQueryable && !edge.dns.dnssecSigned) {
        addFinding({
          phase: 'edge-intelligence',
          algorithm: 'Zone Not DNSSEC-Signed',
          location: `DNS — ${hostname}`,
          threatLevel: 'LOW',
          category: 'DNS Security',
          description:
            'No DNSKEY record was returned for the zone, so DNS answers for this name are not origin-authenticated and can be spoofed on the resolution path.',
          recommendation: 'Sign the zone with DNSSEC and publish the DS record at the parent.',
          quantumBreakTime: 'N/A',
          classicalBreakTime: 'N/A',
        })
      }
    }
    moduleComplete(
      'dns-security-analyzer',
      'DNS Security Analyzer',
      hostname,
      14,
      findings.length - dnsFindingStart,
      edge?.dns.probed
        ? null
        : notApplicable(`CAA and DNSSEC could not be read — ${edge ? edge.dns.error || 'no resolver answered for this name' : unavailable}`),
    )

    /* ── Post-quantum key agreement ─────────────────────────────────────── */
    const pqFindingStart = findings.length
    if (edge?.pqKeyAgreement.probed && edge.pqKeyAgreement.state === 'pass') {
      const pq = edge.pqKeyAgreement
      addFinding({
        phase: 'edge-intelligence',
        algorithm: pq.postQuantumComponent || 'ML-KEM',
        location: `TLS key_share — ${hostname}:${port}`,
        threatLevel: 'SAFE',
        category: 'Post-Quantum Key Agreement',
        description: `Hybrid post-quantum key agreement is applied: ${pq.primaryGroup} accepted when offered in isolation under a TLS 1.3 floor across ${pq.handshakes} handshake(s). ${pq.classicalComponent} protects the session classically; ${pq.postQuantumComponent} defeats harvest-now-decrypt-later.`,
        recommendation: 'No action required for key establishment. Extend the same hybrid posture to internal services and plan the ML-DSA certificate migration.',
        quantumBreakTime: 'Not recoverable by Shor',
        classicalBreakTime: '> 10^28 years',
      })
    } else if (edge?.pqKeyAgreement.probed && edge.pqKeyAgreement.pureKemGroups.length) {
      addFinding({
        phase: 'edge-intelligence',
        algorithm: edge.pqKeyAgreement.kemParameterSets.join(', ') || 'ML-KEM',
        location: `TLS key_share — ${hostname}:${port}`,
        threatLevel: 'LOW',
        category: 'Post-Quantum Key Agreement',
        description: `Standalone ML-KEM accepted (${edge.pqKeyAgreement.pureKemGroups.join(', ')}) with no classical hedge. Post-quantum key agreement is in use, but a break in ML-KEM would leave nothing underneath it.`,
        recommendation: 'Prefer the hybrid X25519MLKEM768 group so a future ML-KEM weakness cannot strip the session of all protection.',
        quantumBreakTime: 'Not recoverable by Shor',
        classicalBreakTime: 'No classical hedge',
      })
    }
    moduleComplete(
      'pq-key-agreement-analyzer',
      'Post-Quantum Key Agreement Prober',
      `${hostname}:${port}`,
      15,
      findings.length - pqFindingStart,
      edge?.pqKeyAgreement.probed
        ? null
        : notApplicable(`named-group probing requires a completed TLS handshake — ${edge ? edge.transport.error || 'no handshake completed' : unavailable}`),
    )

    /* ── Revocation & transparency: OCSP + SCT ──────────────────────────── */
    const revocationFindingStart = findings.length
    if (edge?.certificate.probed) {
      const cert = edge.certificate
      if (cert.mustStaple && !cert.ocspStapled) {
        addFinding({
          phase: 'edge-intelligence',
          algorithm: 'Must-Staple Violated',
          location: `Certificate — ${hostname}`,
          threatLevel: 'HIGH',
          category: 'Certificate Revocation',
          description:
            'The certificate carries the OCSP must-staple extension but the server did not staple a response. Conforming clients are required to hard-fail this connection.',
          recommendation: 'Enable OCSP stapling on the terminating server, or reissue without the must-staple extension.',
          quantumBreakTime: 'N/A',
          classicalBreakTime: 'N/A',
        })
      } else if (!cert.ocspStapled) {
        addFinding({
          phase: 'edge-intelligence',
          algorithm: 'No OCSP Stapling',
          location: `Certificate — ${hostname}`,
          threatLevel: 'LOW',
          category: 'Certificate Revocation',
          description:
            cert.ocspResponderState === 'not-advertised'
              ? 'No OCSP response was stapled to the handshake and the certificate advertises no OCSP responder, so clients have no online revocation path at all.'
              : `No OCSP response was stapled to the handshake. Revocation checking falls back to a client-side fetch of ${cert.ocspUri || 'the advertised responder'}, which leaks browsing metadata and is soft-failed by most clients (responder state: ${cert.ocspResponderState}).`,
          recommendation: 'Enable OCSP stapling so revocation status is delivered in the handshake.',
          quantumBreakTime: 'N/A',
          classicalBreakTime: 'N/A',
        })
      }
      if (!cert.sctPresent) {
        addFinding({
          phase: 'edge-intelligence',
          algorithm: 'No Certificate Transparency SCTs',
          location: `Certificate — ${hostname}`,
          threatLevel: 'MEDIUM',
          category: 'Certificate Transparency',
          description:
            'No Signed Certificate Timestamps were found in the certificate, the TLS handshake or a stapled OCSP response. Misissuance for this name would not be publicly auditable, and Chrome rejects publicly-trusted certificates without SCTs.',
          recommendation: 'Obtain the certificate from a CA that submits to Certificate Transparency logs and embeds SCTs.',
          quantumBreakTime: 'N/A',
          classicalBreakTime: 'N/A',
        })
      }
    }
    moduleComplete(
      'revocation-transparency-analyzer',
      'Revocation & Transparency Analyzer',
      `${hostname}:${port}`,
      16,
      findings.length - revocationFindingStart,
      edge?.certificate.probed
        ? null
        : notApplicable(`OCSP and SCT extraction requires a served certificate chain — ${edge ? edge.certificate.error || 'no chain was returned' : unavailable}`),
    )

    /* ── Edge attribution ───────────────────────────────────────────────── */
    moduleComplete(
      'edge-infrastructure-analyzer',
      'Edge Infrastructure Analyzer',
      hostname,
      17,
      0,
      edge?.http.reachable
        ? null
        : notApplicable(`CDN, WAF and proxy attribution is read from response headers — ${edge ? edge.http.error || 'the origin did not answer over HTTPS' : unavailable}`),
    )
  }

  const isGitHub = targetType === 'github'

  try {
    let scanTimeout: ReturnType<typeof setTimeout> | undefined

    const scanPromise = (async () => {
      // ─── Phase 1: Initialization ────────────────────────────────────
      emit({
        type: 'scan-start',
        target,
        targetType,
        totalPhases: isGitHub ? 5 : 9,
        queueState: 'accepted',
      })

      emit({
        type: 'engine-status',
        status: runtimeHealth.status,
        engines: runtimeHealth.components,
        enterpriseEngines: runtimeHealth.enterpriseEngines,
        modulesLoaded: runtimeHealth.enterpriseScanner.modules,
        webModulesLoaded: runtimeHealth.webScanner.modules,
        detectionRulesLoaded: runtimeHealth.enterpriseScanner.detectionRules,
        webDetectionRulesLoaded: runtimeHealth.webScanner.detectionRules,
        fingerprintsLoaded: runtimeHealth.enterpriseScanner.cryptoFingerprints,
        cryptoPatternsLoaded: runtimeHealth.webScanner.cryptoPatterns,
        payloadPacksLoaded: runtimeHealth.payloadSystem.packs,
        payloadsLoaded: runtimeHealth.payloadSystem.payloads,
        templatesLoaded: runtimeHealth.templateSystem.templates,
        issues: runtimeHealth.issues,
      })

      phaseStart('initializing', 'Initializing Scanner Engine', 5)
      moduleStart('target-parser', 'Target Parser', target, 5)
      const { hostname, port } = parseTarget(target, targetType)
      moduleComplete('target-parser', 'Target Parser', target, 10, 0)
      phaseComplete('initializing', 'Scanner Engine Initialized', 10)

      if (!isGitHub) {
        // ─── Phase 2: Public Edge Intelligence ────────────────────────
        // One probe pass over the public edge, shared by every control that
        // follows. This is the SAME engine bundle /public-scan runs — DNS
        // (with a DNS-over-HTTPS fallback so CAA and DNSSEC answer on networks
        // that block UDP/53), HTTP over a permissive agent (so headers are
        // readable on an expired or untrusted chain), the TLS engine including
        // per-group post-quantum probing, and the certificate engine including
        // OCSP and SCT extraction.
        //
        // Its handshake is reused as this scan's TLS evidence below rather than
        // re-running `analyzeTls`, which would double the socket count against
        // the target for an identical answer.
        phaseStart('edge-intelligence', 'Public Edge Intelligence', 12)
        moduleStart('dns-security-analyzer', 'DNS Security Analyzer', hostname, 12)
        moduleStart('pq-key-agreement-analyzer', 'Post-Quantum Key Agreement Prober', `${hostname}:${port}`, 12)
        moduleStart('revocation-transparency-analyzer', 'Revocation & Transparency Analyzer', `${hostname}:${port}`, 12)
        moduleStart('edge-infrastructure-analyzer', 'Edge Infrastructure Analyzer', hostname, 12)

        const edgeAttempt = await withRetry(
          () => collectEdgeIntelligence(hostname, port, undefined, edgeBudgetMs),
          'Public Edge Intelligence Engine',
          0, // the engines retry their own transient failures internally
          // Never below the engines' own degrade-by budget, or the outer guard
          // would kill a scan that was about to return its partial evidence.
          Math.max(EDGE_MODULE_TIMEOUT, edgeBudgetMs + 15_000),
        )
        edgeIntelligence = edgeAttempt.result?.intelligence ?? null
        const edgeHandshake = edgeAttempt.result?.handshake ?? null
        const edgeError = edgeAttempt.error

        emitEdgeModuleStates(edgeIntelligence, edgeError, hostname, port)
        phaseComplete('edge-intelligence', 'Public Edge Intelligence Complete', 17)

        // ─── Phase 3: TLS Handshake Analysis ──────────────────────────
        phaseStart('tls-handshake', 'TLS Handshake Analysis', 18)
        moduleStart('tls-analyzer', 'TLS Analyzer', `${hostname}:${port}`, 18)
        const tlsFindingStart = findings.length
        try {
          /* The edge phase already completed the full protocol and cipher
             enumeration. Re-running it would open another dozen sockets at the
             target for an answer already in hand — so it is reused, and the
             direct call survives only as the fallback for an edge phase that
             timed out or was never reached. */
          const tlsAttempt = edgeHandshake
            ? { result: edgeHandshake, attempts: 1, error: null as string | null }
            : await withRetry(
                () => analyzeTls(hostname, port),
                'TLS Analyzer',
                TLS_MAX_RETRIES,
                TLS_MODULE_TIMEOUT
              )
          tlsResult = tlsAttempt.result

          if (!tlsResult) {
            throw new Error(
              tlsAttempt.error || edgeError || 'TLS Analyzer completed without handshake metadata'
            )
          }

          if (tlsAttempt.attempts > 1 && tlsResult) {
            addFinding({
              phase: 'tls-handshake',
              algorithm: 'TLS Connection Retry',
              location: `${hostname}:${port}`,
              threatLevel: 'LOW',
              category: 'Connectivity',
              description: `TLS handshake succeeded after ${tlsAttempt.attempts} attempt(s) — may indicate intermittent connectivity`,
              recommendation: 'Monitor server TLS stability',
              quantumBreakTime: 'N/A',
              classicalBreakTime: 'N/A',
            })
          }

          // Generate findings from TLS analysis
          if (tlsResult) {
            // TLS version finding
            addFinding({
              phase: 'tls-handshake',
              algorithm: tlsResult.tlsVersion,
              location: `Protocol — ${target}`,
              threatLevel: getTlsVersionThreat(tlsResult.tlsVersion),
              category: 'Protocol',
              description: getTlsVersionDescription(tlsResult.tlsVersion),
              recommendation: tlsResult.tlsVersion.includes('1.3')
                ? 'Enable PQC hybrid cipher suites for TLS 1.3'
                : 'Upgrade to TLS 1.3 with PQC hybrid cipher suites',
              quantumBreakTime: 'N/A (protocol level)',
              classicalBreakTime: 'N/A',
            })

            for (const protocolProbe of tlsResult.protocolSupport) {
              if (!protocolProbe.supported) continue
              const protocolThreat = getTlsVersionThreat(protocolProbe.protocol)
              if (protocolThreat === 'CRITICAL' || protocolProbe.protocol !== tlsResult.tlsVersion) {
                addFinding({
                  phase: 'tls-handshake',
                  algorithm: protocolProbe.protocol,
                  location: `Supported Protocol — ${target}`,
                  threatLevel: protocolThreat,
                  category: 'Protocol Support',
                  description: `${protocolProbe.protocol} is supported by the endpoint${protocolProbe.cipherSuite ? ` with ${protocolProbe.cipherSuite}` : ''}`,
                  recommendation: protocolProbe.protocol.includes('1.3')
                    ? 'Enable hybrid PQC key exchange for TLS 1.3'
                    : 'Disable deprecated protocol support and require TLS 1.3',
                  quantumBreakTime: 'N/A (protocol level)',
                  classicalBreakTime: protocolThreat === 'CRITICAL' ? 'Deprecated protocol' : 'N/A',
                })
              }
            }

            // Certificate info from TLS. The HNDL timeline is derived from the
            // key agreement and the certificate key, so it is produced by — and
            // counted against — the key exchange analyzer below.
            certInfo = tlsResult.peerCertificate
          }
          moduleComplete('tls-analyzer', 'TLS Analyzer', `${hostname}:${port}`, 28, findings.length - tlsFindingStart, tlsAttempt.error)
        } catch (err) {
          const message = (err as Error).message || 'TLS handshake failed'
          addFinding({
            phase: 'tls-handshake',
            algorithm: 'TLS Connection Failed',
            location: `${hostname}:${port}`,
            threatLevel: 'MEDIUM',
            category: 'Connectivity',
            description: `TLS handshake could not be completed from this scanner runtime: ${message}`,
            recommendation: 'Verify the target accepts inbound TLS from the scanner runtime or deploy a tenant collector agent from an authorized network path.',
            quantumBreakTime: 'N/A',
            classicalBreakTime: 'N/A',
          })
          moduleComplete('tls-analyzer', 'TLS Analyzer', `${hostname}:${port}`, 28, findings.length - tlsFindingStart, message)
        }
        phaseComplete('tls-handshake', 'TLS Analysis Complete', 30)

        // ─── Phase 3b: Key Exchange & Forward Secrecy ─────────────────
        // A first-class module rather than a side effect of the TLS pass. It
        // owns the negotiated key agreement, the named group / ephemeral key
        // material and the forward-secrecy verdict, so "Key exchange scanner"
        // has a real producer and can report a real terminal state.
        phaseStart('key-exchange', 'Key Exchange & Forward Secrecy Analysis', 30)
        moduleStart('key-exchange-analyzer', 'Key Exchange Analyzer', target, 30)
        const kexFindingStart = findings.length
        /* The negotiated key agreement is what the EDGE ENGINE MEASURED, never
           what the socket happened to be able to name.

           `tlsResult.keyExchange` is derived from `getEphemeralKeyInfo()`,
           which Node returns EMPTY for a TLS 1.3 handshake — so on every modern
           endpoint the label degrades to the generic "ECDHE (TLS 1.3
           key_share)" whether the group was P-256 or X25519MLKEM768. The edge
           phase above already resolved the real group by offering each named
           group in isolation under a TLS 1.3 floor, across dozens of
           handshakes, and that measurement is authoritative here.

           Reading the label instead of the measurement is what reported
           endpoints with live hybrid post-quantum key agreement — Cloudflare
           among them — as classical-only, HIGH severity, harvest-now exposed. */
        const pqAgreement = edgeIntelligence?.pqKeyAgreement ?? null
        const hybridApplied = Boolean(
          pqAgreement?.probed && pqAgreement.state === 'pass' && pqAgreement.hybridGroups.length > 0,
        )
        const pureKemApplied = Boolean(
          pqAgreement?.probed && !hybridApplied && pqAgreement.pureKemGroups.length > 0,
        )
        const kemApplied = hybridApplied || pureKemApplied

        if (tlsResult && tlsResult.keyExchange && tlsResult.keyExchange !== 'unknown') {
          // The measured group outranks the socket label; `negotiatedCurve` is
          // the fallback for a scan whose edge phase never completed.
          const group = pqAgreement?.primaryGroup ?? tlsResult.negotiatedCurve
          const ephemeral = tlsResult.ephemeralKeyType
            ? `${tlsResult.ephemeralKeyType}${tlsResult.ephemeralKeySize ? ` ${tlsResult.ephemeralKeySize}-bit` : ''}`
            : null
          const observed = [
            group ? `named group ${group}` : null,
            ephemeral ? `ephemeral ${ephemeral}` : null,
            kemApplied && pqAgreement?.handshakes ? `confirmed across ${pqAgreement.handshakes} handshake(s)` : null,
          ].filter(Boolean).join(', ')

          if (hybridApplied && pqAgreement) {
            addFinding({
              phase: 'key-exchange',
              algorithm: pqAgreement.primaryGroup || 'Hybrid ML-KEM',
              location: `TLS Handshake — ${target}`,
              threatLevel: 'SAFE',
              category: 'Key Exchange',
              description:
                `Hybrid post-quantum key agreement is applied. ${pqAgreement.classicalComponent || 'The classical half'} protects the session classically and ` +
                `${pqAgreement.postQuantumComponent || 'ML-KEM'} makes the session secret unrecoverable by Shor's algorithm` +
                `${observed ? ` (${observed})` : ''}.`,
              recommendation:
                'No action required for key establishment. Extend the same hybrid posture to internal services and plan the ML-DSA (FIPS 204) certificate migration.',
              quantumBreakTime: 'Not recoverable by Shor',
              classicalBreakTime: '> 10^28 years',
            })
          } else if (pureKemApplied && pqAgreement) {
            addFinding({
              phase: 'key-exchange',
              algorithm: pqAgreement.pureKemGroups[0] || 'ML-KEM',
              location: `TLS Handshake — ${target}`,
              threatLevel: 'LOW',
              category: 'Key Exchange',
              description:
                `Standalone ML-KEM key agreement is applied (${pqAgreement.pureKemGroups.join(', ')}) with no classical hedge. ` +
                `Post-quantum key agreement IS in use, but a future weakness in ML-KEM would leave nothing underneath it${observed ? ` (${observed})` : ''}.`,
              recommendation:
                'Prefer the hybrid X25519MLKEM768 group so a future ML-KEM weakness cannot strip the session of all protection.',
              quantumBreakTime: 'Not recoverable by Shor',
              classicalBreakTime: 'No classical hedge',
            })
          } else {
            const kexThreat = getKeyExchangeThreat(tlsResult.keyExchange)
            addFinding({
              phase: 'key-exchange',
              algorithm: tlsResult.keyExchange,
              location: `TLS Handshake — ${target}`,
              threatLevel: kexThreat,
              category: 'Key Exchange',
              description: `${getKeyExchangeDescription(tlsResult.keyExchange, kexThreat)}${observed ? ` (${observed})` : ''}${
                pqAgreement?.hybridProbed
                  ? `. Every hybrid ML-KEM group was offered in isolation and refused across ${pqAgreement.handshakes} handshake(s)`
                  : ''
              }`,
              recommendation: getKeyExchangeRecommendation(kexThreat),
              quantumBreakTime: kexThreat === 'SAFE' ? 'N/A' : '~2-8 hours (CRQC)',
              classicalBreakTime: '> 10^28 years',
            })
          }

          /* Harvest-Now-Decrypt-Later horizon for this key agreement.

             Suppressed outright when post-quantum key agreement is MEASURED as
             applied: the session secret of a hybrid handshake is not derivable
             from recorded ciphertext by a CRQC, so there is no harvest-now
             exposure on this channel to report. Certificate and signature
             exposure is a separate surface and is still reported by the
             certificate modules. */
          const hndlTimeline = calculateHndlTimeline(
            tlsResult.keyExchange,
            certInfo?.publicKeyAlgorithm || '',
            certInfo?.publicKeySize || 2048,
            kemApplied,
          )
          if (!kemApplied && (hndlTimeline.urgency === 'IMMEDIATE' || hndlTimeline.urgency === 'HIGH')) {
            addFinding({
              phase: 'key-exchange',
              algorithm: `HNDL Risk: ${hndlTimeline.urgency}`,
              location: `Traffic — ${target}`,
              threatLevel: hndlTimeline.urgency === 'IMMEDIATE' ? 'CRITICAL' : 'HIGH',
              category: 'Key Exchange (Harvest Now Decrypt Later)',
              description: `${hndlTimeline.dataShelfLife}. Estimated ${hndlTimeline.yearsToQuantumThreat} years until CRQC threat materializes.`,
              recommendation:
                'Deploy hybrid post-quantum key exchange (X25519MLKEM768 — ML-KEM-768, FIPS 203) to protect data in transit against harvest-now-decrypt-later.',
              quantumBreakTime: `~${hndlTimeline.yearsToQuantumThreat} years (estimated)`,
              classicalBreakTime: '> 10^28 years',
            })
          }
        }
        moduleComplete(
          'key-exchange-analyzer',
          'Key Exchange Analyzer',
          target,
          31,
          findings.length - kexFindingStart,
          tlsResult
            ? tlsResult.keyExchange && tlsResult.keyExchange !== 'unknown'
              ? null
              : notApplicable('the handshake did not expose a key agreement algorithm this scanner can classify')
            : notApplicable('key agreement analysis requires a completed TLS handshake')
        )
        phaseComplete('key-exchange', 'Key Exchange Analysis Complete', 31)

        // ─── Phase 4: Certificate Analysis ────────────────────────────
        phaseStart('cert-analysis', 'Certificate Chain Inspection', 32)
        moduleStart('certificate-parser', 'Certificate Chain Audit', target, 32)
        const certFindingStart = findings.length
        if (certInfo) {
          /* ONE FACT, ONE FINDING.
             `detectedOids` contains every OID parsed out of the certificate,
             which includes the ones that merely RESTATE the leaf's own key and
             signature: `ecPublicKey` and `secp256r1 (P-256)` are the algorithm
             and curve of the very key reported below, and the signature OID is
             the algorithm reported by the signature analyzer. Emitting all of
             them turned one certificate — two facts — into FIVE HIGH findings,
             which then inflated every count, every per-surface mean and the
             severity mass behind the surface verdict. The restated OIDs are
             folded into the two dedicated findings as provenance instead. */
          const leafKeyOids = [certInfo.publicKeyOid, certInfo.publicKeyCurveOid].filter(
            (oid): oid is string => Boolean(oid),
          )
          const restatedOids = leafRestatedOids(certInfo)
          const keyOidNames = certInfo.detectedOids
            .filter((entry) => leafKeyOids.includes(entry.oid))
            .map((entry) => `${entry.name} (${entry.oid})`)

          // Public key algorithm finding
          addFinding({
            phase: 'cert-analysis',
            algorithm: `${certInfo.publicKeyAlgorithm} (Certificate)`,
            location: `Certificate — ${target}`,
            threatLevel: getCertAlgorithmThreat(certInfo.publicKeyAlgorithm),
            category: 'Certificate',
            description: keyOidNames.length
              ? `${getCertAlgorithmDescription(certInfo)}. Key encoded as ${keyOidNames.join(' / ')}.`
              : getCertAlgorithmDescription(certInfo),
            recommendation: getCertRecommendation(certInfo.publicKeyAlgorithm),
            quantumBreakTime: certInfo.publicKeyAlgorithm.includes('RSA') ? '~4-8 hours (CRQC)' : '~2-4 hours (CRQC)',
            classicalBreakTime: '> 300 trillion years',
            oid: certInfo.publicKeyOid || certInfo.signatureOid || undefined,
          })

          // Expiry finding
          if (certInfo.isExpired) {
            addFinding({
              phase: 'cert-analysis',
              algorithm: 'Expired Certificate',
              location: `Certificate — ${target}`,
              threatLevel: 'CRITICAL',
              category: 'Certificate',
              description: `Certificate expired on ${certInfo.validTo}`,
              recommendation: 'Renew certificate immediately with PQC-ready CA',
              quantumBreakTime: 'N/A',
              classicalBreakTime: 'N/A',
            })
          }

          // OID-based findings. Hash OIDs belong to the hash algorithm
          // analyzer below — one observation, one owning module, so a finding
          // is never counted against two surfaces.
          for (const oid of certInfo.detectedOids) {
            if (oid.category === 'hash') continue
            // Already reported by the public-key finding above or by the
            // signature analyzer below. Skipping them is what makes the
            // per-surface mean a measurement rather than a count of synonyms.
            if (restatedOids.has(oid.oid)) continue
            if (oid.quantumVulnerable && oid.category !== 'extension' && oid.category !== 'ca-identifier') {
              addFinding({
                phase: 'cert-analysis',
                algorithm: oid.name,
                location: `OID ${oid.oid} — ${target}`,
                threatLevel: oid.quantumThreat === 'shor' ? 'HIGH' : (oid.quantumThreat === 'classical-broken' ? 'CRITICAL' : 'MEDIUM'),
                category: `OID (${oid.category.toUpperCase()})`,
                description: oid.description,
                recommendation: pqcReplacementFor(oid, 'signature'),
                quantumBreakTime: oid.quantumThreat === 'shor' ? '~2-8 hours (CRQC)' : 'N/A',
                classicalBreakTime: oid.quantumThreat === 'classical-broken' ? 'Already broken' : '> 10^20 years',
                oid: oid.oid,
              })
            }
          }
        }
        moduleComplete(
          'certificate-parser',
          'Certificate Chain Audit',
          target,
          42,
          findings.length - certFindingStart,
          certInfo
            ? null
            : notApplicable('certificate metadata was unavailable because the TLS handshake did not return a peer certificate')
        )

        // ─── Phase 4b: Certificate Signature Algorithms ───────────────
        // The signature analyzer owns the leaf signature and every distinct
        // issuer signature in the chain. Previously the leaf signature was
        // filed under the certificate parser and the catalog's "Signature
        // algorithm scanner" never reported at all, which is why
        // "Certificates & Keys" showed 2/3 modules and read SKIPPED.
        moduleStart('signature-algorithm-analyzer', 'Signature Algorithm Analyzer', target, 43)
        const signatureFindingStart = findings.length
        if (certInfo) {
          if (certInfo.signatureAlgorithm && certInfo.signatureAlgorithm !== 'unknown') {
            addFinding({
              phase: 'cert-analysis',
              algorithm: `${certInfo.signatureAlgorithm} (Signature)`,
              location: `Certificate Signature — ${target}`,
              threatLevel: getSignatureThreat(certInfo.signatureAlgorithm),
              category: 'Certificate Signature',
              description: `Certificate signed with ${certInfo.signatureAlgorithm}`,
              recommendation: 'Migrate to ML-DSA (FIPS 204) certificate signatures',
              quantumBreakTime: '~4-8 hours (CRQC)',
              classicalBreakTime: '> 10^28 years',
              oid: certInfo.signatureOid || undefined,
            })
          }

          // Issuer signatures in the chain, deduplicated against the leaf: a
          // quantum-safe leaf signed by an RSA intermediate is still exposed.
          const seenChainSignatures = new Set([certInfo.signatureAlgorithm])
          for (const entry of certInfo.chain ?? []) {
            const algorithm = entry.signatureAlgorithm
            if (!algorithm || algorithm === 'unknown' || seenChainSignatures.has(algorithm)) continue
            seenChainSignatures.add(algorithm)
            addFinding({
              phase: 'cert-analysis',
              algorithm: `${algorithm} (Chain Signature)`,
              location: `Chain — ${entry.subject || entry.issuer || target}`,
              threatLevel: getSignatureThreat(algorithm),
              category: 'Certificate Signature',
              description: `Chain certificate "${entry.subject || 'issuer'}" is signed with ${algorithm}`,
              recommendation: 'Require a PQC-ready issuing CA (ML-DSA, FIPS 204) for the full chain',
              quantumBreakTime: '~4-8 hours (CRQC)',
              classicalBreakTime: '> 10^28 years',
            })
          }
        }
        moduleComplete(
          'signature-algorithm-analyzer',
          'Signature Algorithm Analyzer',
          target,
          44,
          findings.length - signatureFindingStart,
          certInfo
            ? null
            : notApplicable('signature analysis requires a peer certificate, which the TLS handshake did not return')
        )

        // ─── Phase 4c: Hash Algorithm Analysis ────────────────────────
        moduleStart('hash-algorithm-analyzer', 'Hash Algorithm Analyzer', target, 45)
        const hashFindingStart = findings.length
        if (certInfo) {
          for (const oid of certInfo.detectedOids) {
            if (oid.category !== 'hash' || !oid.quantumVulnerable) continue
            addFinding({
              phase: 'cert-analysis',
              algorithm: oid.name,
              location: `OID ${oid.oid} — ${target}`,
              threatLevel: oid.quantumThreat === 'classical-broken' ? 'CRITICAL' : oid.quantumThreat === 'shor' ? 'HIGH' : 'MEDIUM',
              category: 'OID (HASH)',
              description: oid.description,
              recommendation: oid.pqcReplacement ? `Migrate to ${oid.pqcReplacement}` : 'Move to SHA-384 or SHA3-384 for Grover margin',
              quantumBreakTime: oid.quantumThreat === 'grover' ? 'Halved security margin (Grover)' : 'N/A',
              classicalBreakTime: oid.quantumThreat === 'classical-broken' ? 'Already broken' : '> 10^20 years',
              oid: oid.oid,
            })
          }
        }
        moduleComplete(
          'hash-algorithm-analyzer',
          'Hash Algorithm Analyzer',
          target,
          46,
          findings.length - hashFindingStart,
          certInfo
            ? null
            : notApplicable('hash analysis reads the certificate signature OIDs, which require a peer certificate')
        )
        phaseComplete('cert-analysis', 'Certificate Inspection Complete', 47)

        // ─── Phase 5: Cipher Suite Enumeration ────────────────────────
        phaseStart('cipher-enum', 'Cipher Suite Enumeration', 48)
        moduleStart('cipher-suite-analyzer', 'Cipher Suite Enumeration', target, 48)
        const cipherFindingStart = findings.length
        if (tlsResult) {
          const cipherNames = tlsResult.cipherSuites.length > 0
            ? tlsResult.cipherSuites.map((suite) => suite.standardName)
            : [tlsResult.cipherSuite]
          /* The measured group re-rates the TLS 1.3 rows. Without it every TLS 1.3
             suite carries the fingerprint database's classical-ECDHE assumption,
             which is how a panel reported "8 accepted · 8 quantum-vulnerable"
             two rows below "Post-quantum key agreement: Applied". */
          cipherSuiteBreakdown = analyzeCipherSuites(
            cipherNames,
            tlsResult.tlsVersion,
            measuredKeyAgreement(edgeIntelligence),
          )

          for (const suite of cipherSuiteBreakdown) {
            addFinding({
              phase: 'cipher-enum',
              algorithm: suite.standardName,
              location: `Cipher Suite — ${target}`,
              threatLevel: suite.riskLevel,
              category: 'Cipher Suite',
              description: suite.description,
              recommendation: suite.quantumVulnerable
                ? 'Migrate to PQC hybrid cipher suites'
                : 'No action required',
              quantumBreakTime: suite.quantumVulnerable ? 'Vulnerable (Shor\'s)' : 'Quantum-safe',
              classicalBreakTime: 'Classically secure',
              cipherSuiteDetail: suite,
            })
          }
        }
        moduleComplete(
          'cipher-suite-analyzer',
          'Cipher Suite Enumeration',
          target,
          54,
          findings.length - cipherFindingStart,
          tlsResult ? null : notApplicable('cipher suite enumeration requires a completed TLS handshake')
        )
        phaseComplete('cipher-enum', 'Cipher Suite Analysis Complete', 55)

        // ─── Phase 6: Security Header & API Analysis ──────────────────
        phaseStart('header-inspection', 'Security Header & API Analysis', 58)
        moduleStart('api-security-scanner', 'Security Header & API Scanner', hostname, 58)
        const apiFindingStart = findings.length
        try {
          const apiAttempt = await withRetry(
            /* The edge observation is passed as a fallback because this scanner
               reads headers with Node's `fetch()`, which refuses to connect over
               an untrusted chain — the exact targets whose headers matter most.
               Without it, expired.badssl.com produced an empty header set and
               the dashboard rendered "Not observed" for headers the origin had
               plainly sent. */
            () =>
              scanApiSecurity(
                hostname,
                edgeIntelligence
                  ? {
                      reachable: edgeIntelligence.http.reachable,
                      headers: edgeIntelligence.http.headers,
                      server: edgeIntelligence.http.fingerprint.server,
                      poweredBy: edgeIntelligence.http.fingerprint.poweredBy,
                    }
                  : null,
              ),
            'API Security Scanner'
          )
          apiResult = apiAttempt.result

          // Security header findings
          if (!apiResult) throw new Error(apiAttempt.error || 'API scan failed')
          for (const header of apiResult.securityHeaders) {
            if (header.required && !header.present) {
              addFinding({
                phase: 'header-inspection',
                algorithm: `Missing: ${header.name}`,
                location: `HTTP Headers — ${target}`,
                threatLevel: 'MEDIUM',
                category: 'Security Headers',
                description: `Required security header "${header.name}" is not present`,
                recommendation: header.recommendation,
                quantumBreakTime: 'N/A',
                classicalBreakTime: 'N/A',
              })
            }
          }

          // API-specific findings
          for (const apiFinding of apiResult.apiFindings) {
            addFinding({
              phase: 'header-inspection',
              algorithm: apiFinding.algorithm,
              location: `API ${apiFinding.endpoint} — ${target}`,
              threatLevel: apiFinding.threatLevel,
              category: 'API Security',
              description: apiFinding.description,
              recommendation: apiFinding.recommendation,
              quantumBreakTime: apiFinding.threatLevel === 'HIGH' ? '~4-8 hours (CRQC)' : 'N/A',
              classicalBreakTime: 'N/A',
            })
          }
          moduleComplete('api-security-scanner', 'Security Header & API Scanner', hostname, 64, findings.length - apiFindingStart, apiAttempt.error)
        } catch (err) {
          moduleComplete(
            'api-security-scanner',
            'Security Header & API Scanner',
            hostname,
            64,
            findings.length - apiFindingStart,
            `API/header probe failed: ${(err as Error).message || 'request failed'}`
          )
          // API scan failed — non-critical, continue
        }
        phaseComplete('header-inspection', 'Header & API Analysis Complete', 65)

        // ─── Phase 7: Deep Cryptographic Pattern Scan ─────────────────
        phaseStart('deep-scan', 'Deep Cryptographic Pattern Scan', 68)
        moduleStart('web-crypto-scanner', 'Web Crypto Scanner', target, 68)
        const webCryptoFindingStart = findings.length
        try {
          // Only scan web crypto for URL targets
          if (targetType === 'url') {
            const cryptoAttempt = await withRetry(
              () => scanWebCrypto(target),
              'Web Crypto Scanner'
            )
            webCryptoResult = cryptoAttempt.result

            if (webCryptoResult) for (const pattern of webCryptoResult.patterns) {
              addFinding({
                phase: 'deep-scan',
                algorithm: pattern.algorithm,
                location: `${pattern.source} (line ${pattern.line})`,
                threatLevel: pattern.threatLevel,
                category: `Web Crypto (${pattern.category})`,
                description: pattern.description,
                recommendation: 'Migrate client-side cryptography to PQC algorithms',
                quantumBreakTime: pattern.threatLevel === 'CRITICAL' ? '~4-8 hours (CRQC)' : 'N/A',
                classicalBreakTime: 'N/A',
              })
            }
          }
          moduleComplete('web-crypto-scanner', 'Web Crypto Scanner', target, 74, findings.length - webCryptoFindingStart, targetType === 'url' ? null : notApplicable(`client-side crypto analysis needs a fetchable page; the target is a ${targetType}, not a URL`))
        } catch {
          moduleComplete('web-crypto-scanner', 'Web Crypto Scanner', target, 74, findings.length - webCryptoFindingStart, 'Web crypto scan failed')
          // Web crypto scan failed — non-critical
        }

        /* AES-256-GCM read from the NEGOTIATED CIPHER SUITE.
           Filed under `cipher-enum`, the phase that actually measured it. It sat
           in `deep-scan` — the client-side code phase — which made it the only
           finding on the Code & Dependencies surface and, being SAFE, scored that
           surface "Elite 100" for targets whose source had never been read. A
           finding's phase is part of its provenance, not a convenience. */
        if (tlsResult?.cipherSuite.includes('AES_256_GCM') || tlsResult?.cipherSuite.includes('AES-256-GCM')) {
          addFinding({
            phase: 'cipher-enum',
            algorithm: 'AES-256-GCM',
            location: `Cipher Suite — ${target}`,
            threatLevel: 'SAFE',
            category: 'Symmetric Encryption',
            description: 'AES-256-GCM provides 128-bit quantum security — meets PQC threshold',
            recommendation: 'No action required. AES-256 is quantum-safe for symmetric encryption.',
            quantumBreakTime: '~2^128 (Grover)',
            classicalBreakTime: '> 2^256 operations',
          })
        }

        // The repository scanner has no repository on a network target. Report
        // it explicitly so the module ledger has a terminal state for every
        // catalogued module rather than an unexplained gap.
        moduleStart('github-scanner', repoScannerName(target), target, 75)
        moduleComplete(
          'github-scanner',
          repoScannerName(target),
          target,
          75,
          0,
          notApplicable(`repository analysis needs a source repository; the target is a ${targetType}`)
        )

        phaseComplete('deep-scan', 'Deep Scan Complete', 75)
      } else {
        // ─── GitHub Repository Scan Path ──────────────────────────────
        // Every transport-layer module is inapplicable to a repository URL.
        // Declaring that up front, with the reason, is what keeps "not
        // measured" distinguishable from "measured and clean".
        for (const [moduleId, moduleName] of [
          ['tls-analyzer', 'TLS Analyzer'],
          ['key-exchange-analyzer', 'Key Exchange Analyzer'],
          ['certificate-parser', 'Certificate Chain Audit'],
          ['signature-algorithm-analyzer', 'Signature Algorithm Analyzer'],
          ['hash-algorithm-analyzer', 'Hash Algorithm Analyzer'],
          ['cipher-suite-analyzer', 'Cipher Suite Enumeration'],
          ['api-security-scanner', 'Security Header & API Scanner'],
          ['web-crypto-scanner', 'Web Crypto Scanner'],
          ['dns-security-analyzer', 'DNS Security Analyzer'],
          ['pq-key-agreement-analyzer', 'Post-Quantum Key Agreement Prober'],
          ['revocation-transparency-analyzer', 'Revocation & Transparency Analyzer'],
          ['edge-infrastructure-analyzer', 'Edge Infrastructure Analyzer'],
        ] as const) {
          moduleStart(moduleId, moduleName, target, 18)
          moduleComplete(
            moduleId,
            moduleName,
            target,
            18,
            0,
            notApplicable('a source repository exposes no TLS endpoint to probe')
          )
        }

        phaseStart('repo-scan', 'Repository Cryptography Analysis', 20)
        moduleStart('github-scanner', repoScannerName(target), target, 20)
        const repoFindingStart = findings.length
        try {
          const repoAttempt = await withRetry(
            () => scanRepository(target),
            'Repository Scanner',
            1, // Only 1 retry for repo scans (rate limiting)
            30_000 // 30s timeout for repo scans
          )
          repoResult = repoAttempt.result
          if (!repoResult) throw new Error(repoAttempt.error || 'Repository scan failed')

          for (const pattern of repoResult.patterns) {
            addFinding({
              phase: 'repo-scan',
              algorithm: pattern.algorithm,
              location: `${pattern.file}:${pattern.line}`,
              threatLevel: pattern.threatLevel,
              category: `Source Code (${pattern.category})`,
              description: pattern.description,
              recommendation: 'Migrate to post-quantum cryptographic algorithms',
              quantumBreakTime: pattern.threatLevel === 'CRITICAL' ? '~4-8 hours (CRQC)' : 'Varies',
              classicalBreakTime: '> 10^20 years',
              repoFilePath: pattern.file,
              lineNumber: pattern.line,
            })
          }

          // Graceful access limitation (private repo without a token, not
          // found, rate-limited or empty) — surface it as an actionable notice,
          // NOT a module failure. The scan still completes for every other
          // target and module.
          if (repoResult.accessible === false && repoResult.notice) {
            addFinding({
              phase: 'repo-scan',
              algorithm: 'Repository Access Notice',
              location: repoResult.repoUrl || target,
              threatLevel: 'LOW',
              category: 'Repository Access',
              description: repoResult.notice,
              recommendation: repoResult.recommendation || 'Verify the repository URL, or provide a GitHub token (GITHUB_TOKEN) to scan private repositories.',
              quantumBreakTime: 'N/A',
              classicalBreakTime: 'N/A',
            })
          }

          // repoAttempt.error is null for graceful outcomes, so the module
          // completes rather than being marked FAILED.
          moduleComplete('github-scanner', repoScannerName(target), target, 64, findings.length - repoFindingStart, repoAttempt.error)
        } catch (err) {
          moduleComplete('github-scanner', repoScannerName(target), target, 64, findings.length - repoFindingStart, (err as Error).message)
          addFinding({
            phase: 'repo-scan',
            algorithm: 'Repository Scan Failed',
            location: target,
            threatLevel: 'LOW',
            /* Names its own provenance rather than relying on the phase. Ownership
               used to fall back to `detectionMethod.includes('repo')`, which also
               matched the string "report-generation" — so any finding emitted while
               the report was being composed was filed under the code scanner. */
            category: 'Repository Scan Error',
            description: `Repository scan failed: ${(err as Error).message}`,
            recommendation: 'Verify repository URL and accessibility',
            quantumBreakTime: 'N/A',
            classicalBreakTime: 'N/A',
          })
        }
        phaseComplete('repo-scan', 'Repository Analysis Complete', 65)
      }

      // ─── Phase 8: Detection Rules ─────────────────────────────────
      phaseStart('risk-calculation', 'Quantum Vulnerability Detection & Risk Scoring', 78)
      moduleStart('detection-rules', 'Detection Rules Engine', target, 78)
      const ruleFindingStart = findings.length
      ruleResults = evaluateDetectionRules({
        findings,
        tlsResult,
        certInfo,
        apiResult,
        repoResult,
        webCryptoResult,
        edgeIntelligence,
      })

      // Add rule-triggered findings
      for (const rule of ruleResults) {
        addFinding({
          phase: 'risk-calculation',
          algorithm: rule.ruleName,
          location: `Detection Rule ${rule.ruleId}`,
          threatLevel: rule.severity,
          category: `Rule (${formatCategory(rule.category)})`,
          description: rule.details,
          recommendation: rule.remediation,
          quantumBreakTime: 'N/A (rule-based)',
          classicalBreakTime: 'N/A',
        })
      }
      moduleComplete('detection-rules', 'Detection Rules Engine', target, 86, findings.length - ruleFindingStart)

      // ─── Phase 9: Risk Scoring & Recommendations ──────────────────
      moduleStart('risk-scoring-engine', 'Risk Scoring Engine', target, 87)
      /* `edgeIntelligence` is what lets the published categories score the
         MEASURED key agreement instead of the socket's generic TLS 1.3 label.
         Without it a live X25519MLKEM768 endpoint scored 70/100 on key exchange,
         forfeited the 55-point hybrid readiness allowance, and had its hybrid
         group counted as a quantum-vulnerable algorithm — three penalties for
         having migrated. */
      const riskScore = calculateRiskScore(
        findings, tlsResult, certInfo, apiResult, repoResult, webCryptoResult, ruleResults, edgeIntelligence
      )

      moduleStart('pqc-recommendations', 'PQC Recommendation Engine', target, 89)
      pqcRecommendations = generatePqcRecommendations(findings)

      // Calculate NIST compliance score
      const nistCompliance = calculateNistComplianceScore(findings, tlsResult, certInfo, ruleResults)

      // Calculate scan confidence score
      const scanConfidence = calculateConfidenceScore(tlsResult, certInfo, apiResult, repoResult, webCryptoResult)

      // Add NIST compliance finding if gaps detected
      if (nistCompliance.gaps.length > 0 && nistCompliance.score < 70) {
        addFinding({
          phase: 'risk-calculation',
          algorithm: `NIST Compliance: Grade ${nistCompliance.grade}`,
          location: `Compliance Assessment — ${target}`,
          threatLevel: nistCompliance.score < 40 ? 'CRITICAL' : nistCompliance.score < 60 ? 'HIGH' : 'MEDIUM',
          category: 'NIST Compliance',
          description: `NIST compliance score: ${nistCompliance.score}/100 (Grade ${nistCompliance.grade}). Gaps: ${nistCompliance.gaps.slice(0, 3).join('; ')}`,
          recommendation: 'Address NIST SP 800-57 and SP 800-52r2 compliance gaps — prioritize key sizes and TLS configuration',
          quantumBreakTime: 'N/A (compliance)',
          classicalBreakTime: 'N/A',
        })
      }

      // Attach PQC recommendations to relevant findings
      for (const finding of findings) {
        const rec = pqcRecommendations.find(r =>
          finding.algorithm.includes(r.currentAlgorithm) ||
          r.currentAlgorithm.includes(finding.algorithm.split(' ')[0])
        )
        if (rec) {
          finding.pqcRecommendation = rec
        }
      }

      moduleComplete('pqc-recommendations', 'PQC Recommendation Engine', target, 94, pqcRecommendations.length)
      moduleComplete('risk-scoring-engine', 'Risk Scoring Engine', target, 95, 0)
      phaseComplete('risk-calculation', 'Risk Score Calculated', 95)

      // ─── Phase 10: Report Generation ──────────────────────────────
      phaseStart('report-generation', 'Generating Vulnerability Report', 96)
      moduleStart('report-generator', 'Structured Report Generator', target, 96)

      const duration = (Date.now() - startTime) / 1000
      const criticalCount = findings.filter(f => f.threatLevel === 'CRITICAL').length
      const highCount = findings.filter(f => f.threatLevel === 'HIGH').length
      const mediumCount = findings.filter(f => f.threatLevel === 'MEDIUM').length
      const lowCount = findings.filter(f => f.threatLevel === 'LOW').length
      const safeCount = findings.filter(f => f.threatLevel === 'SAFE').length

      const result: WebScanCompleteResult = {
        scanId,
        target,
        targetType,
        scanDuration: duration,
        totalFindings: findings.length,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        safeCount,
        overallRiskScore: riskScore.overallScore,
        riskLevel: riskScore.riskLevel,
        quantumReadinessScore: riskScore.quantumReadinessScore,
        quantumReadinessLevel: riskScore.quantumReadinessLevel,
        legacyQScore: riskScore.legacyQScore,
        findings,
        tlsAnalysis: tlsResult,
        certificateInfo: certInfo,
        cipherSuiteBreakdown,
        repoScanResult: repoResult,
        webCryptoResult,
        apiSecurityResult: apiResult,
        pqcRecommendations,
        riskBreakdown: riskScore.breakdown,
        riskBreakdownApplicable: riskScore.breakdownApplicable,
        scoreCategories: riskScore.scoreCategories,
        riskMeasuredWeight: riskScore.measuredWeight,
        detectionRuleResults: ruleResults,
        runtimeHealth,
        scanConfidence,
        edgeIntelligence,
      }

      moduleComplete('report-generator', 'Structured Report Generator', target, 100, findings.length)
      phaseComplete('report-generation', 'Report Generated', 100)

      // Emit scan-complete with full result
      emit({
        type: 'scan-complete',
        target,
        targetType,
        progress: 100,
        result,
      })

      return result
    })()

    // Race scan against timeout
    return await Promise.race([
      scanPromise,
      new Promise<never>((_, reject) => {
        scanTimeout = setTimeout(() => reject(new Error('Scan timeout exceeded')), SCAN_TIMEOUT)
      }),
    ]).finally(() => {
      if (scanTimeout) clearTimeout(scanTimeout)
    })
  } catch (err) {
    const duration = (Date.now() - startTime) / 1000

    emit({
      type: 'error',
      message: (err as Error).message || 'Scan failed',
    })

    // Return partial results on error
    const criticalCount = findings.filter(f => f.threatLevel === 'CRITICAL').length
    const highCount = findings.filter(f => f.threatLevel === 'HIGH').length
    const mediumCount = findings.filter(f => f.threatLevel === 'MEDIUM').length
    const lowCount = findings.filter(f => f.threatLevel === 'LOW').length
    const safeCount = findings.filter(f => f.threatLevel === 'SAFE').length

    const partialResult: WebScanCompleteResult = {
      scanId,
      target,
      targetType,
      scanDuration: duration,
      totalFindings: findings.length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      safeCount,
      overallRiskScore: 0,
      riskLevel: 'MEDIUM',
      quantumReadinessScore: 0,
      quantumReadinessLevel: 'critical-risk',
      legacyQScore: 0,
      findings,
      tlsAnalysis: tlsResult,
      certificateInfo: certInfo,
      cipherSuiteBreakdown,
      repoScanResult: repoResult,
      webCryptoResult,
      apiSecurityResult: apiResult,
      pqcRecommendations,
      riskBreakdown: { certificateRisk: 0, tlsConfigRisk: 0, cipherSuiteRisk: 0, appCryptoRisk: 0, pqcReadiness: 0 },
      // A failed/partial scan measured nothing — every dimension is explicitly
      // inapplicable so no consumer reads those zeros as a clean posture.
      riskBreakdownApplicable: { certificateRisk: false, tlsConfigRisk: false, cipherSuiteRisk: false, appCryptoRisk: false, pqcReadiness: false },
      riskMeasuredWeight: 0,
      detectionRuleResults: ruleResults,
      runtimeHealth,
      // Whatever the edge phase managed to observe before the scan aborted is
      // still real evidence and is preserved, so a truncated run degrades to
      // partial coverage rather than to a blank surface.
      edgeIntelligence,
    }

    emit({
      type: 'scan-complete',
      target,
      targetType,
      progress: 100,
      result: partialResult,
    })

    return partialResult
  }
}

// ─── Helper Functions ───────────────────────────────────────────────────────

function buildLiveMetrics(findings: WebScanFinding[], startTime: number, progress = 0) {
  const critical = findings.filter(f => f.threatLevel === 'CRITICAL').length
  const high = findings.filter(f => f.threatLevel === 'HIGH').length
  const medium = findings.filter(f => f.threatLevel === 'MEDIUM').length
  const low = findings.filter(f => f.threatLevel === 'LOW').length
  const safe = findings.filter(f => f.threatLevel === 'SAFE').length
  const penalty = Math.min(1000, critical * 180 + high * 110 + medium * 55 + low * 20 - safe * 10)
  const quantumReadinessScore = Math.max(0, Math.min(1000, 1000 - penalty))
  const elapsedSeconds = Math.max(0, (Date.now() - startTime) / 1000)
  const etaSeconds = progress > 0 && progress < 100
    ? Math.max(1, Math.round((elapsedSeconds / progress) * (100 - progress)))
    : 0

  return {
    findingsCount: findings.length,
    critical,
    high,
    medium,
    low,
    safe,
    quantumReadinessScore,
    legacyQScore: Math.round(quantumReadinessScore / 10),
    elapsedSeconds,
    etaSeconds,
  }
}

function getKeyExchangeThreat(kex: string): ThreatLevel {
  if (kex.includes('Kyber') || kex.includes('ML-KEM')) return 'SAFE'
  if (kex === 'RSA' || kex === 'unknown') return 'CRITICAL'
  if (kex.includes('ECDHE') || kex.includes('ECDH')) return 'HIGH'
  if (kex.includes('DHE') || kex.includes('DH')) return 'HIGH'
  return 'MEDIUM'
}

function getKeyExchangeDescription(kex: string, threat: ThreatLevel): string {
  if (threat === 'SAFE') return `${kex} — post-quantum key exchange detected`
  if (kex.includes('ECDHE')) return `${kex} — quantum-vulnerable via Shor's algorithm on ECDLP`
  if (kex.includes('DHE')) return `${kex} — quantum-vulnerable via Shor's algorithm on DLP`
  if (kex === 'RSA') return 'Static RSA key exchange — no forward secrecy + quantum-vulnerable'
  return `${kex} — evaluate quantum resistance`
}

function getKeyExchangeRecommendation(threat: ThreatLevel): string {
  if (threat === 'SAFE') return 'No action required — post-quantum key agreement is active'
  // X25519Kyber768 was the pre-standardisation draft name. The standardised
  // group is X25519MLKEM768 (ML-KEM-768, FIPS 203) and that is what operators
  // have to enable today, so that is what the recommendation must say.
  return 'Enable the X25519MLKEM768 hybrid key exchange group (ML-KEM-768, FIPS 203) for post-quantum resistance'
}

function getTlsVersionThreat(version: string): ThreatLevel {
  if (version === 'TLSv1' || version === 'TLSv1.1') return 'CRITICAL'
  if (version === 'TLSv1.2') return 'MEDIUM'
  if (version === 'TLSv1.3') return 'LOW'
  return 'MEDIUM'
}

function getTlsVersionDescription(version: string): string {
  if (version === 'TLSv1' || version === 'TLSv1.1') return `${version} — deprecated, classically insecure`
  if (version === 'TLSv1.2') return `${version} — lacks native PQC cipher suite support`
  if (version === 'TLSv1.3') return `${version} — supports PQC hybrid extensions, recommended protocol`
  return `${version} — evaluate protocol security`
}

function getCertAlgorithmThreat(alg: string): ThreatLevel {
  if (alg.includes('ML-KEM') || alg.includes('ML-DSA') || alg.includes('Kyber')) return 'SAFE'
  const lower = alg.toLowerCase()
  if (lower.includes('rsa') && parseInt(alg.match(/\d+/)?.[0] || '2048') <= 1024) return 'CRITICAL'
  if (lower.includes('rsa')) return 'HIGH'
  if (lower.includes('ec') || lower.includes('ecdsa')) return 'HIGH'
  if (lower.includes('dsa')) return 'HIGH'
  return 'MEDIUM'
}

function getCertAlgorithmDescription(cert: CertificateInfo): string {
  const alg = cert.publicKeyAlgorithm
  if (alg.includes('RSA')) {
    return `Certificate uses ${alg} — breakable by Shor's algorithm on CRQC (${cert.publicKeySize}-bit key)`
  }
  if (alg.includes('EC') || alg.includes('ECDSA')) {
    return `Certificate uses ${alg} — ECDLP breakable by Shor's algorithm`
  }
  return `Certificate uses ${alg} — evaluate quantum resistance`
}

/**
 * The migration target for a certificate's public key.
 *
 * A certificate key AUTHENTICATES. The replacement is therefore a signature
 * algorithm — ML-DSA (FIPS 204), or SLH-DSA (FIPS 205) where a conservative
 * hash-based scheme is required — never ML-KEM, which is key establishment and
 * cannot sign. The RSA branch recommended "ML-KEM-768 (FIPS 203) hybrid
 * certificate", which is not a thing that can exist.
 */
function getCertRecommendation(alg: string): string {
  const hybrid = 'deploy hybrid (classical + ML-DSA) while relying parties catch up'
  if (alg.includes('RSA')) return `Migrate the certificate to ML-DSA-65 (FIPS 204) — ${hybrid}`
  if (alg.includes('EC') || alg.includes('ECDSA')) return `Migrate the certificate to ML-DSA-65 (FIPS 204) — ${hybrid}`
  return 'Evaluate PQC certificate alternatives: ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)'
}

function getSignatureThreat(sigAlg: string): ThreatLevel {
  const lower = sigAlg.toLowerCase()
  if (lower.includes('md5') || lower.includes('md2')) return 'CRITICAL'
  if (lower.includes('sha1') || lower.includes('sha-1')) return 'CRITICAL'
  if (lower.includes('rsa') || lower.includes('ecdsa')) return 'HIGH'
  return 'MEDIUM'
}

function formatCategory(category: string): string {
  return category.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')
}
