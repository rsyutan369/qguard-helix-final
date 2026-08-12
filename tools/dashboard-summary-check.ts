/**
 * Dashboard summary scale/direction check.
 *
 *   npx tsx tools/dashboard-summary-check.ts [baseUrl]
 *
 * Pins the contract of `GET /api/v1/dashboard/summary` after the fix for the
 * two defects below. Both were invisible to `tsc` and to reading the endpoint
 * in isolation — they only show up when you compare the payload against the
 * canonical band tables and against `/dashboard/executive`:
 *
 *  1. `quantumRiskScore` published a HIGHER-better posture composite on a
 *     private 0–1000 scale under a risk name, with its own band table. The
 *     frontend "converted" it by guessing (`score > 100 ? score / 10 : score`),
 *     so a Critical estate rendered as "23/100" risk beside "Band: Critical".
 *  2. `newVulnerableAssets` returned a raw finding count, so one asset with 98
 *     recent findings reported "98 new vulnerable assets" beside "1 vulnerable
 *     asset".
 *
 * Runs two controls, because a check that only ever sees a populated estate
 * cannot catch "unmeasured rendered as a pass":
 *   POSITIVE — an account WITH scan data: scores banded, risk agrees with the
 *              executive KPI in both scale and direction.
 *   NEGATIVE — an account WITHOUT scan data: hasBaseline false and both bands
 *              read "No Baseline", so the UI shows "--" rather than a 0 that
 *              would read as a perfect score on a lower-better scale.
 *
 * Requires the dev server running and service-role creds in .env. Sessions are
 * minted with admin magic links — no passwords are needed or stored.
 */
import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'
import { riskBandFor, levelFromReadiness } from '@/lib/migration/asset-intelligence'

const BASE = process.argv[2] || 'http://localhost:3000'
const URL = process.env.VITE_SUPABASE_URL || ''
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || ''
const ANON_KEY = process.env.VITE_SUPABASE_ANON_KEY || ''

/** Account expected to HAVE scan data, and one expected to have NONE. */
const POSITIVE_EMAIL = process.env.CHECK_POSITIVE_EMAIL || 'zachmatthew369@gmail.com'
const NEGATIVE_EMAIL = process.env.CHECK_NEGATIVE_EMAIL || 'threathunter369@gmail.com'

if (!URL || !SERVICE_KEY || !ANON_KEY) {
  console.error('Missing VITE_SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY / VITE_SUPABASE_ANON_KEY in .env')
  process.exit(1)
}

const admin = createClient(URL, SERVICE_KEY, { auth: { persistSession: false, autoRefreshToken: false } })

let failures = 0
function assert(name: string, ok: boolean, detail: string) {
  if (!ok) failures++
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name.padEnd(54)} ${detail}`)
}

/** Mint a real user session without knowing the password (admin magic link). */
async function sessionFor(email: string): Promise<string> {
  const { data: link, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email })
  if (error) throw new Error(`generateLink(${email}): ${error.message}`)
  const hashed = (link as any)?.properties?.hashed_token
  const anon = createClient(URL, ANON_KEY, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data, error: otpErr } = await anon.auth.verifyOtp({ token_hash: hashed, type: 'magiclink' })
  if (otpErr) throw new Error(`verifyOtp(${email}): ${otpErr.message}`)
  return data.session!.access_token
}

async function getJson(path: string, token: string) {
  const res = await fetch(BASE + path, { headers: { Authorization: `Bearer ${token}` } })
  if (!res.ok) throw new Error(`${path} -> HTTP ${res.status}`)
  return (await res.json()).data
}

async function main() {
  console.log(`\n=== dashboard summary scale/direction check (${BASE}) ===`)

  // ---- POSITIVE control: an estate with measurements -----------------------
  console.log(`\n[positive] ${POSITIVE_EMAIL} — expects a measured estate`)
  const posToken = await sessionFor(POSITIVE_EMAIL)
  const s = await getJson('/api/v1/dashboard/summary', posToken)
  const exec = await getJson('/api/v1/dashboard/executive', posToken)
  const execRisk = (exec?.kpis || []).find((k: any) => k.id === 'quantum-risk')

  console.log(`  risk ${s.quantumRiskScore} (${s.riskBand}) | readiness ${s.quantumReadinessScore} (${s.readinessBand}) | exec KPI ${execRisk?.value} (${execRisk?.level})`)

  if (!s.hasBaseline) {
    console.log('  SKIP — this account has no scan data; positive control cannot run.')
    console.log('         Run a scan, or set CHECK_POSITIVE_EMAIL to a populated account.')
  } else {
    assert('risk is on the canonical 0-100 scale', s.quantumRiskScore >= 0 && s.quantumRiskScore <= 100, `${s.quantumRiskScore}`)
    assert('readiness is on the canonical 0-100 scale', s.quantumReadinessScore >= 0 && s.quantumReadinessScore <= 100, `${s.quantumReadinessScore}`)
    assert('risk is the complement of readiness', s.quantumRiskScore + s.quantumReadinessScore === 100, `${s.quantumRiskScore} + ${s.quantumReadinessScore}`)
    // The band must come from the SHARED table, not a private copy — this is
    // what stops the summary drifting from the exposure map and node inspector.
    assert('riskBand derives from RISK_BANDS', s.riskBand === riskBandFor(s.quantumRiskScore).label, `${s.riskBand} == ${riskBandFor(s.quantumRiskScore).label}`)
    assert('readinessBand derives from levelFromReadiness', s.readinessBand === levelFromReadiness(s.quantumReadinessScore), `${s.readinessBand} == ${levelFromReadiness(s.quantumReadinessScore)}`)
    // Same population, same scale, same direction: these must not contradict.
    assert('risk agrees with the executive KPI (<=15 apart)', Math.abs(s.quantumRiskScore - Number(execRisk?.value ?? -999)) <= 15, `summary=${s.quantumRiskScore} exec=${execRisk?.value}`)
    assert('executive KPI is lower-better', execRisk?.direction === 'lower-better', `${execRisk?.direction}`)
    // A high risk score must never carry a reassuring band, and vice versa.
    const bandSaysBad = /High|Critical|Elevated/.test(String(s.riskBand))
    assert('band agrees with the score', s.quantumRiskScore >= 40 ? bandSaysBad : !bandSaysBad, `${s.quantumRiskScore} -> ${s.riskBand}`)
    // Counting rule: recent subjects are a subset of all vulnerable subjects.
    assert('newVulnerableAssets <= vulnerableAssetsCount', s.newVulnerableAssets <= s.vulnerableAssetsCount, `${s.newVulnerableAssets} <= ${s.vulnerableAssetsCount}`)
    assert('newVulnerableAssets counts SUBJECTS not findings', s.newFindings >= s.newVulnerableAssets, `findings ${s.newFindings} >= assets ${s.newVulnerableAssets}`)
  }

  // ---- NEGATIVE control: unmeasured must not read as a pass ----------------
  console.log(`\n[negative] ${NEGATIVE_EMAIL} — expects an unmeasured estate`)
  const negToken = await sessionFor(NEGATIVE_EMAIL)
  const n = await getJson('/api/v1/dashboard/summary', negToken)
  console.log(`  hasBaseline=${n.hasBaseline} risk=${n.quantumRiskScore} (${n.riskBand}) readiness=${n.quantumReadinessScore} (${n.readinessBand})`)

  if (n.hasBaseline) {
    console.log('  SKIP — this account now HAS scan data; negative control cannot run.')
    console.log('         Set CHECK_NEGATIVE_EMAIL to an account with no scans.')
  } else {
    assert('hasBaseline is false', n.hasBaseline === false, `${n.hasBaseline}`)
    assert('riskBand reports No Baseline', n.riskBand === 'No Baseline', `${n.riskBand}`)
    assert('readinessBand reports No Baseline', n.readinessBand === 'No Baseline', `${n.readinessBand}`)
    assert('no fabricated counts', n.vulnerableAssetsCount === 0 && n.newVulnerableAssets === 0, `${n.vulnerableAssetsCount}/${n.newVulnerableAssets}`)
  }

  console.log(failures ? `\n${failures} CHECK(S) FAILED\n` : '\nALL CHECKS PASSED\n')
  process.exit(failures ? 1 : 0)
}

main().catch((err) => {
  console.error('\ncheck failed to run:', err instanceof Error ? err.message : err)
  process.exit(1)
})
