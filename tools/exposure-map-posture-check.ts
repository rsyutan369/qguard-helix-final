/**
 * Offline check — Node Inspector "Quantum Risk Posture" scoring.
 *
 * Guards the defect this file was written for: the dashboard exposure-map
 * endpoint kept a PRIVATE unbounded risk accumulator (+3 per finding, no cap),
 * so the Node Inspector rendered values like "3047.0 exposure index" and every
 * asset with more than a handful of findings saturated to Critical. The fix
 * routes the endpoint through the shared asset-intelligence engine that the
 * Quantum Readiness snapshot and the Migration Planner already use.
 *
 * Run:  npx tsx tools/exposure-map-posture-check.ts
 */
import {
  RISK_BANDS,
  UNASSESSED_BAND,
  deriveAssetPostureModel,
  levelFromRisk,
  riskBandFor,
  type Row,
} from '../src/lib/migration/asset-intelligence'

let failures = 0
function check(name: string, condition: boolean, detail = '') {
  if (condition) {
    console.log(`  PASS  ${name}`)
  } else {
    failures += 1
    console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`)
  }
}

/* ------------------------------------------------------------------ */
/* 1. The regression: scores must stay on a bounded 0–100 scale        */
/* ------------------------------------------------------------------ */
console.log('\n[1] Bounded 0-100 score (the "3047.0" defect)')

const HEAVY_ASSET = 'asset-heavy'
const heavyAssets: Row[] = [{ id: HEAVY_ASSET, name: 'expired.badssl.com', type: 'application', environment: 'production' }]
// 1,000 critical findings — under the old accumulator this produced 3,000+.
const heavyFindings: Row[] = Array.from({ length: 1000 }, (_, i) => ({
  id: `f-${i}`, asset_id: HEAVY_ASSET, algorithm: 'RSA-2048', threat_level: 'critical',
}))

const heavy = deriveAssetPostureModel({
  assets: heavyAssets, scanResults: heavyFindings, cryptoExposures: [], cryptoInventory: [], runtimeEvents: [],
})
const heavyScore = heavy.assetRisk.get(HEAVY_ASSET) ?? 0

check('1,000 critical findings stay <= 100', heavyScore <= 100, `got ${heavyScore}`)
check('worst-case saturates AT 100 (not above)', heavyScore === 100, `got ${heavyScore}`)
check('score is displayable as a percentage', Number.isFinite(heavyScore) && heavyScore >= 0)
check('posture is quantum-vulnerable', heavy.assetPosture.get(HEAVY_ASSET) === 'vulnerable')

// Adding MORE evidence must not inflate the score — the old bug was additive.
const heavier = deriveAssetPostureModel({
  assets: heavyAssets,
  scanResults: [...heavyFindings, ...heavyFindings],
  cryptoExposures: heavyFindings.map((f) => ({ ...f, severity: 'critical' })),
  cryptoInventory: [], runtimeEvents: [],
})
check('doubling evidence does not inflate the score', (heavier.assetRisk.get(HEAVY_ASSET) ?? 0) === heavyScore)

/* ------------------------------------------------------------------ */
/* 2. Discrimination — different severities must produce different bands */
/* ------------------------------------------------------------------ */
console.log('\n[2] Bands discriminate (old thresholds made everything Critical)')

const cases: Array<{ id: string; sev: string; expect: string }> = [
  { id: 'a-crit', sev: 'critical', expect: 'Critical' },
  { id: 'a-high', sev: 'high', expect: 'High' },
  { id: 'a-med', sev: 'medium', expect: 'Elevated' },
  { id: 'a-low', sev: 'low', expect: 'Moderate' },
]
const mixed = deriveAssetPostureModel({
  assets: cases.map((c) => ({ id: c.id, name: c.id, type: 'server', environment: 'production' })),
  scanResults: cases.map((c) => ({ id: `r-${c.id}`, asset_id: c.id, algorithm: 'RSA-2048', threat_level: c.sev })),
  cryptoExposures: [], cryptoInventory: [], runtimeEvents: [],
})
for (const c of cases) {
  const score = Math.round(mixed.assetRisk.get(c.id) ?? 0)
  check(`${c.sev} -> ${c.expect} (${score}/100)`, levelFromRisk(score) === c.expect, `got ${levelFromRisk(score)}`)
}
const distinctBands = new Set(cases.map((c) => levelFromRisk(Math.round(mixed.assetRisk.get(c.id) ?? 0))))
check('four severities produce four distinct bands', distinctBands.size === 4, `got ${distinctBands.size}`)

/* ------------------------------------------------------------------ */
/* 3. Unmeasured is not zero, and never a green pass                   */
/* ------------------------------------------------------------------ */
console.log('\n[3] Unassessed assets (data-integrity rule 3)')

const bare = deriveAssetPostureModel({
  assets: [{ id: 'a-bare', name: 'never-scanned', type: 'server', environment: 'production' }],
  scanResults: [], cryptoExposures: [], cryptoInventory: [], runtimeEvents: [],
})
check('no evidence yields no risk entry', !bare.assetRisk.has('a-bare'))
check('unassessed colour is not the "minimal" green', UNASSESSED_BAND.hex !== RISK_BANDS[0].hex)
check('unassessed label states the absence', /not assessed/i.test(UNASSESSED_BAND.label))

/* ------------------------------------------------------------------ */
/* 4. Band table integrity                                             */
/* ------------------------------------------------------------------ */
console.log('\n[4] RISK_BANDS table')

check('bands ascend by threshold', RISK_BANDS.every((b, i) => i === 0 || b.min > RISK_BANDS[i - 1].min))
check('band colours are unique', new Set(RISK_BANDS.map((b) => b.hex)).size === RISK_BANDS.length)
check('lowest band starts at 0', RISK_BANDS[0].min === 0)
check('highest band is Critical at 80', RISK_BANDS[RISK_BANDS.length - 1].min === 80)
check('every 0-100 score resolves to a band', Array.from({ length: 101 }, (_, i) => riskBandFor(i)).every(Boolean))
check('riskBandFor and levelFromRisk agree', Array.from({ length: 101 }, (_, i) => i).every((i) => riskBandFor(i).label === levelFromRisk(i)))

/* ------------------------------------------------------------------ */
/* 5. Regression guard on the canonical function                       */
/*    QR + Migration Planner already depend on levelFromRisk. Rewriting */
/*    it in terms of RISK_BANDS must not have changed ANY answer.       */
/* ------------------------------------------------------------------ */
console.log('\n[5] levelFromRisk parity with its original implementation')

function levelFromRiskOriginal(score: number): string {
  if (score >= 80) return 'Critical'
  if (score >= 60) return 'High'
  if (score >= 40) return 'Elevated'
  if (score >= 20) return 'Moderate'
  if (score > 0) return 'Low'
  return 'Minimal'
}

const probes = [
  ...Array.from({ length: 101 }, (_, i) => i),
  0.1, 0.5, 0.9, 1.5, 19.9, 20.1, 39.9, 59.9, 79.9, 80.1, 99.9,
]
const drift = probes.filter((p) => riskBandFor(p).label !== levelFromRiskOriginal(p))
check(
  `no drift across ${probes.length} probes (incl. fractional)`,
  drift.length === 0,
  drift.length ? `diverged at ${drift.slice(0, 5).join(', ')}` : '',
)

/* ------------------------------------------------------------------ */
console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED' : `${failures} CHECK(S) FAILED`}\n`)
process.exit(failures === 0 ? 0 : 1)
