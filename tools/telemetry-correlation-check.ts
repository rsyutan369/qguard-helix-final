/**
 * Telemetry Correlation engine — offline invariant check.
 *
 *   1. NO SCORE FLOOR. With no source reporting, the coverage score is `null`.
 *      The implementation this replaces published `clamp(52 + …)`, so a tenant
 *      QGuard Helix was completely blind to scored 52/100 and read "Needs
 *      Attention" — absence of telemetry rendered as mediocre telemetry.
 *   2. COVERAGE IS MEASURED AGAINST THE ESTATE, not against whatever reported.
 *      An asset no channel has seen is a BLIND SPOT, and a blind spot is
 *      "unknown", never "safe".
 *   3. CORROBORATION REQUIRES INDEPENDENCE. Two readings from the same channel
 *      are one source, not two.
 *   4. CONFLICTS NEED TWO DIFFERENT CHANNELS. One channel reporting both a safe
 *      and a vulnerable algorithm for an asset is normal (assets run several
 *      algorithms) and must not be reported as disagreement.
 *   5. `unknown` IS NOT DISAGREEMENT. "We could not classify it" differs from
 *      "we disagree".
 *   6. ROLL-UPS RECONCILE with the asset inventory.
 *
 * Run: npx tsx tools/telemetry-correlation-check.ts
 */

import { buildAssetPortfolio, type Row } from '../src/lib/migration/asset-intelligence'
import {
  buildCorrelationIntelligence,
  filterObservations,
  EMPTY_CORRELATION_FILTERS,
  type CorrelationInputs,
} from '../src/lib/telemetry/correlation-intelligence'

let failures = 0
function assert(condition: boolean, label: string, extra = '') {
  console.log(`  ${condition ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!condition) failures += 1
}

const NOW = Date.parse('2026-08-13T12:00:00Z')
const minutesAgo = (n: number) => new Date(NOW - n * 60_000).toISOString()
const daysAgo = (n: number) => new Date(NOW - n * 86_400_000).toISOString()

/* ------------------------------------------------------------------ */
/* Fixture                                                             */
/* ------------------------------------------------------------------ */

const assets: Row[] = [
  // Seen by three channels ⇒ corroborated.
  { id: 'a-edge', name: 'edge.example.com', type: 'web-service', environment: 'production', service_owner: 'Platform', criticality: 'high', metadata: { hostname: 'edge.example.com', internet_facing: true }, created_at: daysAgo(60), updated_at: daysAgo(1) },
  // Seen by one channel only ⇒ single source.
  { id: 'a-batch', name: 'batch.example.com', type: 'service', environment: 'staging', service_owner: 'Data', criticality: 'medium', metadata: { hostname: 'batch.example.com' }, created_at: daysAgo(60), updated_at: daysAgo(1) },
  // Seen by NOBODY ⇒ blind spot, and it is internet-facing and critical.
  { id: 'a-dark', name: 'legacy.example.com', type: 'server', environment: 'production', service_owner: 'Infra', criticality: 'critical', metadata: { hostname: 'legacy.example.com', internet_facing: true }, created_at: daysAgo(60), updated_at: daysAgo(1) },
  // Discovery says post-quantum, runtime says classical ⇒ CONFLICT.
  { id: 'a-conflict', name: 'api.example.com', type: 'api', environment: 'production', service_owner: 'Payments', criticality: 'critical', metadata: { hostname: 'api.example.com', internet_facing: true }, created_at: daysAgo(60), updated_at: daysAgo(1) },
]

const portfolio = buildAssetPortfolio({
  assets, cryptoInventory: [], scanResults: [], cryptoExposures: [], certificates: [], runtimeEvents: [],
  relationships: [], migrationJobs: [], validationLogs: [], complianceEvidence: [], now: NOW,
})

const scannerEvidence: Row[] = [
  { id: 'se1', asset_name: 'edge.example.com', host: 'edge.example.com', protocol: 'TLS', observed_algorithm: 'X25519MLKEM768', observed_at: minutesAgo(30), created_at: minutesAgo(30) },
  { id: 'se2', asset_name: 'api.example.com', host: 'api.example.com', protocol: 'TLS', observed_algorithm: 'X25519MLKEM768', observed_at: minutesAgo(30), created_at: minutesAgo(30) },
  // Same channel, second reading on edge — must NOT count as a second source.
  { id: 'se3', asset_name: 'edge.example.com', host: 'edge.example.com', protocol: 'TLS', observed_algorithm: 'AES-256-GCM', observed_at: minutesAgo(25), created_at: minutesAgo(25) },
]

const runtimeEvents: Row[] = [
  { id: 'rt1', asset_id: 'a-edge', asset_name: 'edge.example.com', agent_id: 'agent-1', key_exchange_algorithm: 'X25519MLKEM768', protocol: 'TLS', observed_at: minutesAgo(5), created_at: minutesAgo(5) },
  // Runtime disagrees with discovery on api.example.com.
  { id: 'rt2', asset_id: 'a-conflict', asset_name: 'api.example.com', agent_id: 'agent-1', key_exchange_algorithm: 'X25519', protocol: 'TLS', observed_at: minutesAgo(5), created_at: minutesAgo(5) },
  // An unclassifiable reading — must never be treated as disagreement.
  { id: 'rt3', asset_id: 'a-edge', asset_name: 'edge.example.com', agent_id: 'agent-1', algorithm: 'proprietary-wrapper', observed_at: minutesAgo(4), created_at: minutesAgo(4) },
]

const cryptoInventory: Row[] = [
  { id: 'ci1', asset_id: 'a-edge', item_type: 'protocol', name: 'edge tls', algorithm: 'X25519MLKEM768', protocol: 'TLS 1.3', discovered_at: daysAgo(2), created_at: daysAgo(2) },
  { id: 'ci2', asset_id: 'a-batch', item_type: 'algorithm', name: 'batch signing', algorithm: 'RSA-2048', discovered_at: daysAgo(2), created_at: daysAgo(2) },
]

const scannerAgents: Row[] = [
  { id: 'agent-1', name: 'collector-01', status: 'active', hostname: 'host-1', platform: 'linux', last_seen_at: minutesAgo(2) },
  // Gone quiet for days ⇒ silent.
  { id: 'agent-2', name: 'collector-02', status: 'active', hostname: 'host-2', platform: 'windows', last_seen_at: daysAgo(9) },
]

const connectorAccounts: Row[] = [{ id: 'cn1', provider: 'aws', status: 'connected' }]
const scanSessions: Row[] = [{ id: 's1', status: 'completed', completed_at: daysAgo(2), created_at: daysAgo(2) }]

const base: CorrelationInputs = {
  assets: portfolio.assets, scannerEvidence, runtimeEvents, cryptoInventory,
  scannerAgents, connectorAccounts, scanSessions, now: NOW,
}
const model = buildCorrelationIntelligence(base)

/* ------------------------------------------------------------------ */
/* 1. No score floor                                                   */
/* ------------------------------------------------------------------ */
console.log('\n1. Absence of telemetry is never scored as partial telemetry')
{
  const blind = buildCorrelationIntelligence({
    ...base, scannerEvidence: [], runtimeEvents: [], cryptoInventory: [],
    scannerAgents: [], connectorAccounts: [], scanSessions: [],
  })
  assert(!blind.hasTelemetry, 'no source ⇒ hasTelemetry false')
  assert(blind.coverageScore.score === null, 'and NO coverage score — not 52, not 0', String(blind.coverageScore.score))
  assert(blind.coverageScore.level === 'No Telemetry', 'the level says so in words', blind.coverageScore.level)
  assert(blind.kpis.blindSpots === portfolio.assets.length, 'every asset is a blind spot', String(blind.kpis.blindSpots))
  assert(blind.kpis.assetsCovered === 0, 'and none is reported as covered')
  assert(/never scored/i.test(blind.coverageScore.basis), 'the basis states the rule')

  const noAssets = buildCorrelationIntelligence({ ...base, assets: [] })
  assert(noAssets.coverageScore.score === null, 'no assets ⇒ no denominator ⇒ no score', String(noAssets.coverageScore.score))

  assert(model.coverageScore.score !== null, 'with sources reporting a score IS published', String(model.coverageScore.score))
  assert(model.coverageScore.score! >= 0 && model.coverageScore.score! <= 100, 'and it is bounded')
}

/* ------------------------------------------------------------------ */
/* 2. Coverage is measured against the estate                          */
/* ------------------------------------------------------------------ */
console.log('\n2. Coverage is measured against the estate, not against what reported')
{
  assert(model.kpis.assetsTotal === 4, 'the denominator is the discovered asset count', String(model.kpis.assetsTotal))
  assert(model.kpis.blindSpots === 1, 'the unobserved asset is a blind spot', String(model.kpis.blindSpots))
  assert(model.blindSpots[0].assetName === 'legacy.example.com', 'and it is named', model.blindSpots[0].assetName)
  assert(/unknown, not safe/i.test(model.blindSpots[0].why), 'a blind spot reads as unknown, never safe', model.blindSpots[0].why.slice(-30))
  assert(model.blindSpots[0].internetFacing, 'internet-facing blind spots surface first')
  assert(model.kpis.assetsCovered === 3, 'three of four assets are covered', String(model.kpis.assetsCovered))
  assert(model.kpis.assetsCovered + model.kpis.blindSpots === model.kpis.assetsTotal, 'covered + blind = total')
}

/* ------------------------------------------------------------------ */
/* 3. Corroboration requires independent channels                      */
/* ------------------------------------------------------------------ */
console.log('\n3. Two readings from one channel are ONE source')
{
  assert(model.kpis.corroboratedAssets === 2, 'edge and api are each seen by 2+ channels', String(model.kpis.corroboratedAssets))

  const batch = model.observations.find((o) => o.assetName === 'batch.example.com')!
  assert(batch.sourceCount === 1, 'batch is seen by a single channel', String(batch.sourceCount))
  assert(batch.sources.length === 1, 'and lists exactly one source', batch.sources.join(','))

  // edge got TWO scanner-evidence rows plus runtime plus CBOM. The hybrid group
  // observation must count Scanner Evidence once, not twice.
  const edgeHybrid = model.observations.find((o) => o.assetName === 'edge.example.com' && o.algorithm === 'X25519MLKEM768')!
  assert(edgeHybrid.sourceCount === 3, 'edge hybrid confirmed by 3 DISTINCT channels', `${edgeHybrid.sourceCount}: ${edgeHybrid.sources.join(', ')}`)
  assert(new Set(edgeHybrid.sources).size === edgeHybrid.sources.length, 'source names are never repeated')

  const tiers = model.coverage.reduce((s, c) => s + c.count, 0)
  assert(tiers === model.kpis.assetsTotal, 'coverage tiers sum to the asset count', `${tiers} vs ${model.kpis.assetsTotal}`)
}

/* ------------------------------------------------------------------ */
/* 4-5. Conflicts need two different channels; unknown is not conflict */
/* ------------------------------------------------------------------ */
console.log('\n4-5. Disagreement means two channels, and unknown is not disagreement')
{
  assert(model.kpis.conflicts === 1, 'exactly one conflict on this fixture', String(model.kpis.conflicts))
  const conflict = model.conflicts[0]
  assert(conflict.assetName === 'api.example.com', 'and it is the asset where runtime contradicts discovery', conflict.assetName)
  assert(conflict.severity === 'critical', 'runtime contradicting discovery on an internet-facing asset is critical', conflict.severity)
  assert(/configured and what is actually executing/i.test(conflict.why), 'the explanation names the real problem')
  assert(conflict.readings.length >= 2, 'both readings are shown', String(conflict.readings.length))
  assert(
    new Set(conflict.readings.map((r) => r.source)).size >= 2,
    'from at least two distinct sources',
  )

  // edge has a hybrid reading AND an unclassifiable one from the same channel.
  assert(
    !model.conflicts.some((c) => c.assetName === 'edge.example.com'),
    'an unclassifiable reading is NOT reported as disagreement',
  )

  // One channel reporting two different postures is normal, not a conflict.
  const singleChannel = buildCorrelationIntelligence({
    ...base,
    scannerEvidence: [
      { id: 'x1', asset_name: 'batch.example.com', host: 'batch.example.com', observed_algorithm: 'ML-KEM-768', observed_at: minutesAgo(5), created_at: minutesAgo(5) },
      { id: 'x2', asset_name: 'batch.example.com', host: 'batch.example.com', observed_algorithm: 'RSA-2048', observed_at: minutesAgo(5), created_at: minutesAgo(5) },
    ],
    runtimeEvents: [], cryptoInventory: [],
  })
  assert(
    singleChannel.conflicts.length === 0,
    'one channel seeing both a safe and a vulnerable algorithm is normal, not a conflict',
    String(singleChannel.conflicts.length),
  )
}

/* ------------------------------------------------------------------ */
/* 6. Source health and roll-ups                                       */
/* ------------------------------------------------------------------ */
console.log('\n6. Source health is honest and roll-ups reconcile')
{
  const active = model.sources.find((s) => s.name === 'collector-01')!
  const quiet = model.sources.find((s) => s.name === 'collector-02')!
  assert(active.health === 'reporting', 'a collector seen minutes ago is reporting', active.health)
  assert(quiet.health === 'silent', 'a collector last seen nine days ago is SILENT, not reporting', quiet.health)
  assert(model.kpis.activeSources < model.kpis.totalSources, 'the active count excludes silent sources', `${model.kpis.activeSources}/${model.kpis.totalSources}`)
  assert(model.sources.some((s) => s.kind === 'scanner'), 'the scanner is registered as a source')
  assert(model.sources.some((s) => s.kind === 'cloud-connector'), 'the connector is registered as a source')

  assert(model.observations.every((o) => o.sourceCount === o.sources.length), 'every observation\'s source count matches its list')
  assert(model.observations.every((o) => o.observations >= 1), 'no observation claims zero sightings')

  const all = filterObservations(model.observations, EMPTY_CORRELATION_FILTERS)
  assert(all.length === model.observations.length, 'the empty filter is a no-op')
  const corroborated = filterObservations(model.observations, { ...EMPTY_CORRELATION_FILTERS, tier: 'corroborated' })
  assert(corroborated.every((o) => o.sourceCount >= 2), 'the corroborated filter is exact')
  const single = filterObservations(model.observations, { ...EMPTY_CORRELATION_FILTERS, tier: 'single-source' })
  assert(single.every((o) => o.sourceCount === 1), 'the single-source filter is exact')
  assert(corroborated.length + single.length === model.observations.length, 'the two tiers partition the observations')

  const bySource = filterObservations(model.observations, { ...EMPTY_CORRELATION_FILTERS, source: 'Runtime Telemetry' })
  assert(bySource.every((o) => o.sources.includes('Runtime Telemetry')), 'the source filter is exact')
}

/* ------------------------------------------------------------------ */
/* 7. Shared classification                                            */
/* ------------------------------------------------------------------ */
console.log('\n7. Verdicts come from the shared decomposer')
{
  const hybrid = model.observations.find((o) => o.algorithm === 'X25519MLKEM768')!
  assert(hybrid.quantumClass === 'hybrid', 'X25519MLKEM768 reads hybrid, as everywhere else', hybrid.quantumClass)
  const classical = model.observations.find((o) => o.algorithm === 'X25519')!
  assert(classical.quantumClass === 'vulnerable', 'bare X25519 reads vulnerable', classical.quantumClass)
  const aes = model.observations.find((o) => o.algorithm === 'AES-256-GCM')!
  assert(aes.quantumClass === 'safe', 'AES-256-GCM reads safe, never vulnerable', aes.quantumClass)
  const rsa = model.observations.find((o) => o.algorithm === 'RSA-2048')!
  assert(rsa.quantumClass === 'vulnerable', 'RSA-2048 reads vulnerable', rsa.quantumClass)
}

console.log(`\n${failures === 0 ? '✓ All telemetry correlation invariants hold.' : `✗ ${failures} invariant(s) FAILED.`}`)
process.exit(failures === 0 ? 0 : 1)
