/**
 * QGuard Helix — Public Quantum Exposure Assessment™
 * Orchestration: drives the Public Scan Intelligence Engine and hands the
 * resulting evidence bundle to the pure report engine.
 *
 * The scan itself lives in `engines/` as a set of independent modules (DNS,
 * TLS, Certificate, HTTP Security, Cryptographic Intelligence). This file owns
 * only workflow: run the modules, map their output onto the report contract,
 * and stream stage progress.
 */

import { randomUUID } from 'node:crypto'
import { parseTarget } from '../web-scanner/tls-analyzer'
import { runScanEngines, type ObservationSink, type ScanEvidenceBundle } from './engines'
import {
  buildControlStates,
  buildExecutiveSummary,
  buildFootprint,
  buildGovernance,
  buildHandshakeSteps,
  buildIntelligence,
  buildRecommendations,
  buildScope,
  buildSophia,
  buildTimeline,
  computePostQuantumReadiness,
  sortFindings,
  toAttackSurface,
  toFindings,
} from './engine'
import { buildScoreCategories } from './grading-model'
import {
  PUBLIC_SCAN_STAGES,
  type PublicScanEvidence,
  type PublicScanReport,
  type PublicScanStage,
  type PublicScanStageKey,
} from './types'

export interface AssessOptions {
  input: string
  host: string
  port: number
  /** Called as each workflow stage transitions, for SSE streaming. */
  onStage?: (stage: PublicScanStage) => void
  /**
   * Called as individual measurements land, for the live visualization. This is
   * finer-grained than `onStage`: the named-group phase alone reports a dozen
   * separate facts over several seconds inside a single stage.
   */
  onObservation?: ObservationSink
  /**
   * Wall-clock budget for the measurement phase. The engines DEGRADE when it
   * expires — unmeasured groups become inconclusive and the report says so —
   * rather than the assessment throwing. A visitor gets a partial answer with
   * its limits stated, never a spinner that ends in an error.
   */
  budgetMs?: number
  signal?: AbortSignal
}

const STAGE_BY_KEY = new Map(PUBLIC_SCAN_STAGES.map((stage) => [stage.key, stage]))

function stage(key: PublicScanStageKey, state: PublicScanStage['state'], detail?: string): PublicScanStage {
  const meta = STAGE_BY_KEY.get(key)
  return {
    key,
    label: meta?.label ?? key,
    description: meta?.description ?? '',
    state,
    detail,
    ...(state === 'running' ? { startedAt: new Date().toISOString() } : {}),
    ...(state === 'complete' || state === 'failed' ? { completedAt: new Date().toISOString() } : {}),
  }
}

/** Engine id → the workflow stage it drives in the UI rail. */
const ENGINE_STAGE: Record<string, PublicScanStageKey> = {
  'dns-intelligence': 'dns',
  'tls-intelligence': 'tls',
  'certificate-intelligence': 'certificate',
  'http-security': 'headers',
  'cryptographic-intelligence': 'quantum',
}

/**
 * Flatten the engine bundle onto the report's evidence contract. Keeping these
 * field names stable is what let the modular engine replace the previous
 * single-file probe without touching a single panel.
 */
export function toReportEvidence(bundle: ScanEvidenceBundle): PublicScanEvidence {
  const { dns, tls, certificate, http } = bundle

  return {
    tls: tls.data.handshake,
    certificate: certificate.data.certificate,
    certificateExtras: certificate.ok
      ? {
          subjectAltNames: certificate.data.subjectAltNames,
          sanCount: certificate.data.sanCount,
          ocspStapled: certificate.data.ocspStapled,
          ocspUri: certificate.data.ocspUri,
          ocspResponderState: certificate.data.ocspResponderState,
          ocspResponderDetail: certificate.data.ocspResponderDetail,
          mustStaple: certificate.data.mustStaple,
          signedCertificateTimestamps: certificate.data.signedCertificateTimestamps,
          sctCount: certificate.data.sctCount,
          chainDepth: certificate.data.chainDepth,
          daysRemaining: certificate.data.daysRemaining,
          validityDays: certificate.data.validityDays,
          isWildcard: certificate.data.isWildcard,
          chainTrusted: certificate.data.chainTrusted === true,
          trustError: certificate.data.trustError,
        }
      : null,
    cipherSuites: tls.data.cipherSuites,
    keyAgreement: {
      probed: tls.data.groupsProbed,
      hybridGroups: tls.data.hybridGroups,
      pureKemGroups: tls.data.pureKemGroups,
      classicalGroups: tls.data.classicalGroups,
      primaryGroup: tls.data.primaryGroup,
      forwardSecrecy: tls.data.forwardSecrecy,
      forwardSecrecyBasis: tls.data.forwardSecrecyBasis,
    },
    dns: {
      addresses: dns.data.addresses,
      addressCount: dns.data.addressCount,
      caaRecords: dns.data.caaRecords.map((record) => record.raw),
      caaPresent: dns.data.caaPresent,
      caaQueryable: dns.data.caaQueryable,
      resolverAvailable: dns.data.systemResolverAvailable || dns.data.dohAvailable,
      nameservers: dns.data.nameservers,
      mxHosts: dns.data.mailExchangers.map((mx) => mx.exchange),
      resolvedVia: dns.data.resolvedVia,
      error: dns.data.error,
    },
    http: {
      reachable: http.data.reachable,
      statusCode: http.data.statusCode,
      finalUrl: http.data.finalUrl,
      redirected: http.data.redirected,
      redirectedToHttps: http.data.redirectedToHttps,
      responseMs: http.data.responseMs,
      server: http.data.fingerprint.server,
      poweredBy: http.data.fingerprint.poweredBy,
      alpn: tls.data.alpn,
      headers: http.data.headers.map((header) => ({
        name: header.name,
        value: header.value,
        present: header.present,
        secure: header.status === 'Healthy',
        required: header.group === 'Critical',
        recommendation: header.recommendation,
        applicable: header.status !== 'Not Applicable',
        supersededBy: header.supersededBy ?? null,
      })),
      error: http.data.error,
    },
    timing: {
      tcpConnectMs: tls.data.timing.tcpConnectMs,
      tlsHandshakeMs: tls.data.timing.tlsHandshakeMs,
      totalMs: tls.data.timing.totalMs,
      httpResponseMs: http.data.responseMs,
    },
    port: bundle.port,
    alpn: tls.data.alpn,
    engines: bundle,
  }
}

/**
 * Run a complete public assessment. Never throws for a partially reachable
 * target: the report is emitted in a `degraded` state with the reason, because
 * "we could not read X" is itself an executive-relevant result.
 */
export async function assessPublicTarget(options: AssessOptions): Promise<PublicScanReport> {
  const { input, host, port, onStage } = options
  const scanId = randomUUID()
  const startedAt = new Date()
  const emit = (value: PublicScanStage) => onStage?.(value)

  // Stages are marked running when their engine ACTUALLY starts. Flipping all
  // four to running up front made the rail claim four concurrent modules from
  // the first frame, and left every card sitting on "Analyzing" for the whole
  // run regardless of what was really executing.
  const bundle = await runScanEngines({
    host,
    port,
    onEngineStart: (engine) => {
      const key = ENGINE_STAGE[engine]
      if (key) emit(stage(key, 'running'))
    },
    onEngine: (engine, ok, detail) => {
      const key = ENGINE_STAGE[engine]
      if (key) emit(stage(key, ok ? 'complete' : 'failed', detail))
    },
    onObservation: options.onObservation,
    budgetMs: options.budgetMs,
  })

  const evidence = toReportEvidence(bundle)

  // ── Quantum assessment ────────────────────────────────────────────────────
  // Controls are evaluated exactly once. Every panel below is a projection of
  // this array, so the same control cannot report different verdicts in the
  // Attack Surface, the Findings table and the score decomposition.
  const controls = buildControlStates(evidence)
  const scoreComponents = buildScoreCategories(evidence, controls, computePostQuantumReadiness(evidence).score)
  const findings = sortFindings(toFindings(controls))
  const attackSurface = toAttackSurface(controls)
  const executive = buildExecutiveSummary(evidence, scoreComponents, findings)
  // Hoisted so Sophia can read the same array the Recommendations panel renders
  // rather than being handed a second, independently-built one.
  const recommendations = buildRecommendations(evidence, controls, scoreComponents)
  // The quantum stage is already completed by the cryptographic-intelligence
  // engine's own callback. Emitting it a second time here published two
  // identical completions for one module and double-counted it in the rail.

  // ── Executive report ──────────────────────────────────────────────────────
  emit(stage('report', 'running'))
  const report: PublicScanReport = {
    scanId,
    target: {
      input,
      host,
      port,
      displayUrl: port === 443 ? `https://${host}` : `https://${host}:${port}`,
    },
    startedAt: startedAt.toISOString(),
    completedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt.getTime(),
    cached: false,
    degraded: !bundle.tls.ok,
    degradedReason: bundle.tls.ok ? null : bundle.tls.error || 'TLS handshake failed',
    executive,
    scoreComponents,
    handshake: buildHandshakeSteps(evidence),
    findings,
    intelligence: buildIntelligence(evidence, executive.confidence),
    attackSurface,
    timeline: buildTimeline(evidence),
    recommendations,
    governance: buildGovernance(),
    footprint: buildFootprint(evidence),
    // Sophia is composed last and reads the finished findings and
    // recommendations, so her narrative can only cite what those panels show.
    sophia: buildSophia(evidence, executive, findings, recommendations),
    scope: buildScope(),
    evidence,
  }
  emit(stage('report', 'complete', `Assessment ready in ${(report.durationMs / 1000).toFixed(1)}s`))

  return report
}

export { parseTarget }
