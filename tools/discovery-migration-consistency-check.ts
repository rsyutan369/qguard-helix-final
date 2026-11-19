/**
 * Cross-page consistency check for the five discovery → migration surfaces:
 *
 *   /dashboard/assets                  (scanner intelligence → asset register)
 *   /dashboard/cbom                    (scanner intelligence CBOM)
 *   /dashboard/migration-intelligence  (shared-responsibility model)
 *   /dashboard/migration-planner       (plan + per-asset portfolio)
 *   /dashboard/migration-sandbox       (sandbox snapshot)
 *
 * It signs in as a tenant, reads the SAME endpoints the pages read, and asserts
 * that every figure two pages both show is the same figure. Run it against a
 * live API after changing any of these routers or the engines behind them:
 *
 *   npx tsx tools/discovery-migration-consistency-check.ts [email] [origin]
 *
 * Each assertion below records a contradiction that was really on screen
 * (2026-11-11): the Sandbox read "PQC Readiness 49%" against 22% everywhere
 * else, the Planner listed 42 components on an asset the Asset Inventory listed
 * with 19, its heatmap tile said "Blocked 1" above zero Blocked rows, and a
 * domain with no findings read "100 · Quantum-Ready".
 */
import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'
import { buildAssetRegister } from '@/lib/assets/asset-register'

const EMAIL = process.argv[2] || 'zachmatthew369@gmail.com'
const BASE = process.argv[3] || process.env.ORIGIN || 'http://localhost:3000'
const SUPA = process.env.VITE_SUPABASE_URL!

type Json = Record<string, any>
let failed = 0
let passed = 0
function check(label: string, ok: boolean, detail: string) {
  if (ok) passed += 1
  else failed += 1
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `\n      ${detail}`}`)
}
const eq = (label: string, a: unknown, b: unknown, names: [string, string]) =>
  check(label, a === b, `${names[0]} = ${JSON.stringify(a)}  vs  ${names[1]} = ${JSON.stringify(b)}`)

async function main() {
  const admin = createClient(SUPA, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data: link, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email: EMAIL })
  if (error) throw error
  const anon = createClient(SUPA, process.env.VITE_SUPABASE_ANON_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data: session, error: otpError } = await anon.auth.verifyOtp({ token_hash: (link as any).properties.hashed_token, type: 'magiclink' })
  if (otpError) throw otpError
  const token = session.session!.access_token
  const headers = { Authorization: `Bearer ${token}` }

  const get = async (path: string): Promise<Json> => {
    const res = await fetch(BASE + path, { headers })
    const json = (await res.json()) as Json
    if (!res.ok) throw new Error(`${path} → HTTP ${res.status} ${JSON.stringify(json).slice(0, 200)}`)
    return json.data && typeof json.data === 'object' && !Array.isArray(json.data) ? json.data : json
  }

  /** First frame of an SSE route, read with the header-only auth the pages use. */
  const firstFrame = async (path: string, event: string, withQueryToken = false): Promise<{ status: number; event?: string; fingerprint?: string }> => {
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), 30_000)
    try {
      const res = await fetch(BASE + path + (withQueryToken ? `?token=${encodeURIComponent(token)}` : ''), {
        headers: withQueryToken ? { Accept: 'text/event-stream' } : { ...headers, Accept: 'text/event-stream' },
        signal: ctrl.signal,
      })
      if (!res.ok || !res.body) return { status: res.status }
      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      for (;;) {
        const { value, done } = await reader.read()
        if (done) return { status: res.status }
        buffer += decoder.decode(value, { stream: true })
        let boundary = buffer.indexOf('\n\n')
        while (boundary !== -1) {
          const frame = buffer.slice(0, boundary)
          buffer = buffer.slice(boundary + 2)
          boundary = buffer.indexOf('\n\n')
          const name = /^event:\s*(.+)$/m.exec(frame)?.[1]?.trim()
          if (name === event) {
            const data = frame.split('\n').filter((l) => l.startsWith('data:')).map((l) => l.slice(5)).join('\n')
            return { status: res.status, event: name, fingerprint: JSON.parse(data).fingerprint }
          }
        }
      }
    } catch {
      return { status: 0 }
    } finally {
      clearTimeout(timer)
      ctrl.abort()
    }
  }

  try {
    const [intel, qr, mi, plan, portfolio, sandbox, workflow] = await Promise.all([
      get('/api/v1/scanner/intelligence'),
      get('/api/v1/quantum-readiness'),
      get('/api/v1/migration-intelligence'),
      get('/api/v1/migration-planner'),
      get('/api/v1/migration-planner/assets?limit=400&sort=priority&posture=all&environment=all&priority=all&status=all&search='),
      get('/api/v1/sandbox/snapshot'),
      get('/api/v1/migration-workflow'),
    ])

    const register = buildAssetRegister({
      snapshot: intel as any,
      qr: {
        resolved: true,
        hasData: Boolean(qr.hasData),
        readiness: qr.scores?.quantumReadiness ?? null,
        readinessLevel: qr.scores?.quantumReadinessLevel ?? null,
        risk: qr.scores?.quantumRisk ?? null,
        components: qr.inventory?.cryptoComponents ?? null,
        vulnerableComponents: qr.inventory?.vulnerableComponents ?? null,
      },
      workflowStates: workflow.assetStates ?? null,
      now: Date.now(),
    })

    console.log(`\nTenant ${EMAIL} @ ${BASE} — ${register.rows.length} asset(s), ${register.totals.components.total} CBOM component(s)\n`)

    /* ---- Assets ↔ CBOM ↔ Quantum Readiness ---- */
    eq('Assets register components = CBOM components', register.totals.components.total, intel.cbom?.stats?.totalComponents, ['register', 'cbom'])
    eq('Assets register vulnerable = CBOM vulnerable', register.totals.components.vulnerable, intel.cbom?.stats?.quantumVulnerableComponents, ['register', 'cbom'])
    eq('CBOM components = Quantum Readiness components', intel.cbom?.stats?.totalComponents, qr.inventory?.cryptoComponents, ['cbom', 'qr'])
    eq('CBOM vulnerable = Quantum Readiness vulnerable', intel.cbom?.stats?.quantumVulnerableComponents, qr.inventory?.vulnerableComponents, ['cbom', 'qr'])
    eq('Assets count = Quantum Readiness assets assessed', register.rows.length, qr.inventory?.assetsAssessed, ['register', 'qr'])

    /* ---- Migration Planner ↔ the above ---- */
    eq('Planner hero vulnerable components = Quantum Readiness', plan.hero?.vulnerableComponents, qr.inventory?.vulnerableComponents, ['planner', 'qr'])
    eq('Planner hero readiness = Quantum Readiness', plan.hero?.readinessScore, qr.scores?.quantumReadiness, ['planner', 'qr'])
    eq('Planner hero quantum risk = Quantum Readiness', plan.hero?.quantumRisk, qr.scores?.quantumRisk, ['planner', 'qr'])
    eq('Planner hero critical findings = scanner critical', plan.hero?.criticalFindingsRemaining, intel.severityCounts?.critical, ['planner', 'scanner'])
    eq('Planner portfolio assets = Assets register', portfolio.totalUnfiltered, register.rows.length, ['planner', 'register'])

    const planned = new Map<string, Json>((portfolio.assets as Json[]).map((a) => [a.id, a]))
    for (const row of register.rows) {
      const asset = planned.get(row.id)
      if (!asset) { check(`Planner lists asset ${row.name}`, false, 'missing from the planner portfolio'); continue }
      eq(`${row.name}: Planner components = Assets register`, asset.componentCount, row.components.total, ['planner', 'register'])
      eq(`${row.name}: Planner vulnerable = Assets register`, asset.vulnerableComponentCount, row.components.vulnerable, ['planner', 'register'])
    }
    const attributedVulnerable = register.totals.components.vulnerable - register.unattributed.vulnerable
    eq('Σ Planner per-asset vulnerable = CBOM vulnerable attached to assets', portfolio.reconciliation?.portfolio?.vulnerableComponents, attributedVulnerable, ['Σ planner', 'cbom'])
    const perAssetCritical = (portfolio.assets as Json[]).reduce((sum, a) => sum + Number(a.severityCounts?.critical || 0), 0)
    check('Σ Planner per-asset critical ≤ scanner critical (no re-counting across scans)', perAssetCritical <= Number(intel.severityCounts?.critical || 0),
      `Σ per-asset critical ${perAssetCritical} > estate critical ${intel.severityCounts?.critical}`)

    const heat = plan.heatmap || {}
    const rows: Json[] = heat.rows || []
    const countState = (state: string) => rows.filter((r) => r.state === state).length
    if (rows.length === (qr.exposureGraph?.nodes?.length ?? rows.length) && rows.length <= 30) {
      eq('Planner heatmap "Blocked" tile = Blocked rows', heat.blocked, countState('Blocked'), ['tile', 'rows'])
      eq('Planner heatmap "Needs Upgrade" tile = Needs Upgrade rows', heat.needsUpgrade, countState('Needs Upgrade'), ['tile', 'rows'])
    }
    check('Planner dependency chains come from recorded relationships only',
      !(plan.dependencyAnalysis?.chains || []).some((c: Json) => /CDN -> Load Balancer/.test(String(c.path))),
      'a stock "Users -> CDN -> Load Balancer -> …" chain is still being published')
    const edges = plan.dependencyGraph?.edges?.length ?? 0
    if (edges === 0) {
      check('Planner reports no blast radius when no relationships are recorded',
        (plan.dependencyAnalysis?.chains || []).every((c: Json) => c.blastRadius === 0),
        `chains: ${JSON.stringify(plan.dependencyAnalysis?.chains)}`)
    }

    /* Workflow strip: a stage is "In Progress" only on a real record. */
    const stageOf = (key: string): Json => (plan.stages || []).find((st: Json) => st.key === key) || {}
    const simulations = Number(sandbox.summary?.totalSimulations || 0)
    if (simulations === 0) {
      check('Planner "Simulate" is not in progress while the Sandbox has no simulations',
        stageOf('simulate').status === 'Ready' || stageOf('simulate').status === 'Pending',
        `planner stage = ${stageOf('simulate').status}, sandbox simulations = 0`)
    }
    const plansStage = (workflow.stages || []).find((st: Json) => st.id === 'planning')
    if ((plan.stages || []).length && stageOf('plan').assetCount === 0) {
      check('Planner "Plan" is not in progress while no plan exists',
        stageOf('plan').status !== 'In Progress' && stageOf('plan').status !== 'Complete',
        `planner stage = ${stageOf('plan').status} with 0 plans (workflow rail planning = ${plansStage?.status})`)
      check('Planner "Approve" is pending while no plan exists', stageOf('approve').status === 'Pending', `planner stage = ${stageOf('approve').status}`)
    }

    /* ---- Migration Intelligence ↔ the above ---- */
    eq('Migration Intelligence findings = scanner findings', mi.totals?.findings, intel.summary?.totalFindings, ['mi', 'scanner'])
    eq('Migration Intelligence overall readiness = Quantum Readiness', mi.readiness?.overall?.score, qr.scores?.quantumReadiness, ['mi', 'qr'])
    eq('Migration Intelligence baseline = Quantum Readiness', mi.baseline?.quantumReadiness, qr.scores?.quantumReadiness, ['mi', 'qr'])
    eq('Planner shared-responsibility block = Migration Intelligence totals', JSON.stringify(plan.sharedResponsibility?.totals), JSON.stringify(mi.totals), ['planner', 'mi'])
    const domains = ['customer', 'provider', 'ecosystem'] as const
    eq('Migration Intelligence domains sum to total findings', domains.reduce((s, d) => s + Number(mi.totals?.[d] || 0), 0), mi.totals?.findings, ['Σ domains', 'total'])
    for (const d of domains) {
      const r = mi.readiness?.[d] || {}
      if (r.total === 0 && mi.hasData) eq(`Migration Intelligence ${d} domain with no findings is "Not applicable"`, r.level, 'Not applicable', ['level', 'expected'])
    }
    const sevCritical = domains.reduce((s, d) => s + Number(mi.severityByDomain?.[d]?.critical || 0), 0)
    eq('Migration Intelligence critical (all domains) = scanner critical', sevCritical, intel.severityCounts?.critical, ['mi', 'scanner'])

    /* ---- Migration Sandbox ↔ the above ---- */
    // The sandbox deliberately WITHHOLDS its risk score (null, "Awaiting
    // assessment") while the Quantum Readiness engine is still computing, rather
    // than publish a locally derived number that would then jump. Wait it out.
    let s: Json = sandbox.summary || {}
    for (let attempt = 0; attempt < 6 && s.quantumRiskSource === 'awaiting-quantum-readiness'; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 4000))
      s = (await get('/api/v1/sandbox/snapshot')).summary || {}
    }
    eq('Sandbox assets = Assets register', s.totalAssets, register.rows.length, ['sandbox', 'register'])
    eq('Sandbox critical exposures = scanner critical', s.criticalExposures, intel.severityCounts?.critical, ['sandbox', 'scanner'])
    eq('Sandbox high exposures = scanner high', s.highExposures, intel.severityCounts?.high, ['sandbox', 'scanner'])
    eq('Sandbox quantum risk = Quantum Readiness', s.quantumRiskScore, qr.scores?.quantumRisk, ['sandbox', 'qr'])
    eq('Sandbox components = CBOM components', s.cryptoComponents, intel.cbom?.stats?.totalComponents, ['sandbox', 'cbom'])
    eq('Sandbox vulnerable components = CBOM vulnerable', s.vulnerableComponents, intel.cbom?.stats?.quantumVulnerableComponents, ['sandbox', 'cbom'])
    eq('Sandbox PQC readiness = scanner PQC readiness', s.pqcReadiness, intel.summary?.pqcReadiness, ['sandbox', 'scanner'])
    eq('Sandbox PQC readiness = Quantum Readiness PQC adoption', s.pqcReadiness, qr.scores?.pqcAdoption, ['sandbox', 'qr'])
    const vulnFactor = (sandbox.riskFactors || []).find((f: Json) => /Vulnerable Components/i.test(f.label))
    if (s.vulnerableComponents > 0) eq('Sandbox risk-factor vulnerable components = CBOM vulnerable', vulnFactor?.count, intel.cbom?.stats?.quantumVulnerableComponents, ['sandbox', 'cbom'])

    /* ---- Live streams: header auth only, change-only frames ---- */
    const [miStream, planStream, sbStream, sbQuery] = await Promise.all([
      firstFrame('/api/v1/migration-intelligence/stream', 'migration-intelligence'),
      firstFrame('/api/v1/migration-planner/stream', 'migration-plan'),
      firstFrame('/api/v1/sandbox/stream', 'sandbox-update'),
      firstFrame('/api/v1/sandbox/stream', 'sandbox-update', true),
    ])
    check('Migration Intelligence stream delivers a fingerprinted first frame', Boolean(miStream.fingerprint), JSON.stringify(miStream))
    check('Migration Planner stream delivers a fingerprinted first frame', Boolean(planStream.fingerprint), JSON.stringify(planStream))
    check('Sandbox stream delivers a fingerprinted first frame (header auth)', Boolean(sbStream.fingerprint), JSON.stringify(sbStream))
    eq('Sandbox stream refuses a token in the URL', sbQuery.status, 401, ['status', 'expected'])

    console.log(`\n${passed} passed, ${failed} failed`)
  } finally {
    await anon.auth.signOut({ scope: 'local' }).catch(() => undefined)
  }
  process.exit(failed ? 1 : 0)
}

main().catch((err) => { console.error(err); process.exit(1) })
