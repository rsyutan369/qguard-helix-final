/**
 * PQAuth™ Identity Migration Engine — offline evidence-honesty check.
 *
 * Exercises the pure derivations behind the three PQAuth surfaces that publish
 * a verdict: `/dashboard/pqauth/compatibility`, `/dashboard/pqauth/compliance`
 * and `/dashboard/pqauth/runtime-telemetry`. No Supabase / server required:
 *
 *     npx tsx tools/pqauth-check.ts
 *
 * Every assertion below exists because getting it wrong publishes a false
 * statement about a customer's identity layer. Specifically, each one guards a
 * defect that was actually shipped:
 *
 *   1. A compatibility surface with NO matched evidence was still scored from
 *      the estate readiness score, so a surface the tenant has never deployed
 *      rendered as a percentage with a coloured bar — absence read as a pass.
 *   2. A compliance framework with NO matching evidence borrowed the tenant's
 *      unrelated compliance / vault-audit / security-event row count and
 *      presented it as that framework's own evidence, attributing other
 *      frameworks' records to it.
 *   3. The runtime telemetry tiles were static inventory counts wearing runtime
 *      labels: "Trust Failures" was the quantum-vulnerable ALGORITHM count and
 *      "Identity Drift" was the vulnerable COMPONENT count, so a tenant with
 *      zero runtime telemetry still saw non-zero runtime failures.
 */
import {
  deriveCompatibilitySurfaces,
  deriveComplianceRows,
  deriveRuntimeMetrics,
} from '../src/api-server/pqauth-dashboard'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}

/* ------------------------------------------------------------------ */
/* 1. Compatibility surfaces — no evidence means Not Assessed          */
/* ------------------------------------------------------------------ */
console.log('\n[1] Compatibility surfaces are scored only where evidence exists')

// A tenant running web apps and APIs behind a gateway. No mobile app, no
// service mesh, nothing in a cloud identity provider.
const compatEvidence = [
  { sourceTable: 'assets', name: 'checkout-application', asset_type: 'application', observed_at: '2026-08-20T10:00:00Z' },
  { sourceTable: 'assets', name: 'payments API endpoint', asset_type: 'api', observed_at: '2026-08-20T10:05:00Z' },
  { sourceTable: 'scanner_evidence', name: 'nginx ingress gateway', observed_at: '2026-08-20T10:10:00Z' },
]
const surfaces = deriveCompatibilitySurfaces(compatEvidence, 72, 3)
const byId = Object.fromEntries(surfaces.map((s) => [s.id, s]))

assert(byId.apps.assessed && byId.apps.count > 0, 'a surface WITH evidence is assessed', `apps count ${byId.apps.count}`)
assert(byId.apps.score > 0, 'an assessed surface carries a score', `${byId.apps.score}`)
assert(!byId.mobile.assessed, 'a surface with no evidence is NOT assessed', 'mobile')
assert(byId.mobile.score === 0, 'an unassessed surface publishes no score', `mobile score ${byId.mobile.score}`)
assert(byId.mobile.count === 0 && byId.mobile.sourceTables.length === 0, 'an unassessed surface cites no evidence', 'mobile')
assert(!byId.mesh.assessed && byId.mesh.score === 0, 'service mesh with no sidecar evidence is unassessed')
assert(byId.gateways.assessed, 'the gateway surface matches ingress/nginx evidence')
assert(
  surfaces.every((s) => s.assessed === s.count > 0),
  'assessed is exactly "matched at least one evidence row" for every surface',
  `${surfaces.filter((s) => s.assessed).length}/${surfaces.length} assessed`,
)
assert(
  deriveCompatibilitySurfaces([], 88, 0).every((s) => !s.assessed && s.score === 0),
  'an empty estate scores NO surface, however high the readiness score is',
)

/* ------------------------------------------------------------------ */
/* 2. Compliance frameworks — evidence is never borrowed               */
/* ------------------------------------------------------------------ */
console.log('\n[2] A framework is scored only from evidence naming that framework')

const complianceEvidence = [
  { sourceTable: 'compliance_evidence', framework: 'ISO 27001', control: 'A.10.1 cryptographic controls', created_at: '2026-08-01T00:00:00Z' },
  { sourceTable: 'compliance_evidence', framework: 'ISO 27001', control: 'A.10.2 key management', created_at: '2026-08-02T00:00:00Z' },
  { sourceTable: 'compliance_evidence', framework: 'PCI-DSS', control: 'Requirement 4 transmission encryption', created_at: '2026-08-03T00:00:00Z' },
]
const compliance = deriveComplianceRows(complianceEvidence, 60)
const cByLabel = Object.fromEntries(compliance.map((c) => [c.label, c]))

assert(cByLabel['ISO 27001'].assessed, 'a framework with its own evidence is assessed')
assert(cByLabel['ISO 27001'].evidenceCount === 2, 'evidence count is its OWN matching rows', `${cByLabel['ISO 27001'].evidenceCount}`)
assert(cByLabel['ISO 27001'].score > 0, 'an assessed framework carries a score', `${cByLabel['ISO 27001'].score}`)
assert(!cByLabel.FedRAMP.assessed, 'a framework with no matching evidence is NOT assessed', 'FedRAMP')
assert(
  cByLabel.FedRAMP.evidenceCount === 0,
  'an unassessed framework does NOT borrow the other frameworks’ row count',
  `FedRAMP cites ${cByLabel.FedRAMP.evidenceCount} of ${complianceEvidence.length} available rows`,
)
assert(cByLabel.FedRAMP.score === 0, 'an unassessed framework publishes no score')
assert(cByLabel.FedRAMP.sourceTables.length === 0 && cByLabel.FedRAMP.latestAt === null, 'an unassessed framework cites no source table and no timestamp')
assert(
  compliance.reduce((sum, c) => sum + c.evidenceCount, 0) === complianceEvidence.length,
  'evidence is attributed exactly once across all frameworks — none double-counted, none invented',
  `${compliance.reduce((sum, c) => sum + c.evidenceCount, 0)} attributed of ${complianceEvidence.length}`,
)

/* ------------------------------------------------------------------ */
/* 3. Runtime telemetry — measured, never substituted from inventory   */
/* ------------------------------------------------------------------ */
console.log('\n[3] Runtime identity tiles are measured from runtime evidence only')

const runtimeEvents = [
  { sourceTable: 'runtime_crypto_events', event_type: 'token_validation', operation_type: 'verify', algorithm: 'RS256', certificate_fingerprint: 'aa:bb:01', observed_at: '2026-08-26T09:00:00Z' },
  { sourceTable: 'runtime_crypto_events', event_type: 'tls_handshake', operation_type: 'key_exchange', algorithm: 'ECDHE-P256', certificate_fingerprint: 'aa:bb:02', downgrade_detected: true, observed_at: '2026-08-26T09:01:00Z' },
  { sourceTable: 'runtime_crypto_events', event_type: 'jwt_sign', operation_type: 'sign', algorithm: 'ES256', certificate_fingerprint: 'aa:bb:01', shadow_crypto: true, observed_at: '2026-08-26T09:02:00Z' },
]
const identityRows = runtimeEvents
const metrics = deriveRuntimeMetrics(identityRows, runtimeEvents)
const mById = Object.fromEntries(metrics.map((m) => [m.id, m]))

assert(metrics.every((m) => m.measured), 'with runtime evidence every tile reports measured')
assert(mById['runtime-events'].value === 3, 'runtime events counts observed identity events', `${mById['runtime-events'].value}`)
assert(mById['token-validation'].value === 2, 'token validation counts token/JWT operations only', `${mById['token-validation'].value}`)
assert(
  mById['certificate-usage'].value === 2,
  'certificate usage counts DISTINCT certificates presented, not events',
  `${mById['certificate-usage'].value} distinct of ${runtimeEvents.length} events`,
)
assert(mById['trust-failures'].value === 1, 'trust failures counts observed downgrades/rejections', `${mById['trust-failures'].value}`)
assert(mById['identity-drift'].value === 1, 'identity drift counts observed shadow/legacy crypto', `${mById['identity-drift'].value}`)

// The defect this file exists for: a tenant with a fully-scanned, deeply
// vulnerable estate but NO runtime telemetry must not see runtime failures.
const noTelemetry = deriveRuntimeMetrics([], [])
assert(noTelemetry.every((m) => !m.measured), 'with NO runtime evidence every tile reports unmeasured')
assert(
  noTelemetry.every((m) => m.value === 0),
  'with NO runtime evidence no tile invents a value from inventory',
  noTelemetry.map((m) => `${m.id}=${m.value}`).join(' '),
)
assert(
  noTelemetry.find((m) => m.id === 'trust-failures')!.value === 0,
  'quantum-vulnerable algorithms are NOT republished as runtime trust failures',
)
assert(
  noTelemetry.find((m) => m.id === 'identity-drift')!.value === 0,
  'vulnerable components are NOT republished as runtime identity drift',
)

// Certificate usage is measured against the raw runtime event set, so identity
// filtering must not silence it, and an empty event set must not claim measured.
const certOnly = deriveRuntimeMetrics([], runtimeEvents)
assert(
  certOnly.find((m) => m.id === 'certificate-usage')!.measured,
  'certificate usage is measured whenever runtime events exist',
)
assert(
  !certOnly.find((m) => m.id === 'trust-failures')!.measured,
  'identity-scoped tiles stay unmeasured when no identity event matched',
)

console.log(
  failures === 0
    ? '\n✓ ALL PQAUTH EVIDENCE-HONESTY INVARIANTS HOLD\n'
    : `\n${failures} CHECK(S) FAILED ✗\n`,
)
process.exit(failures === 0 ? 0 : 1)
