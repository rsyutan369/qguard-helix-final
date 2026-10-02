/**
 * /dashboard live reconciliation — every panel that counts the same thing must
 * print the same number, on REAL tenants.
 *
 *   npx tsx tools/dashboard-live-reconcile.ts [baseUrl] [email,email,…]
 *
 * The offline suites (estate-workflow-check, executive-dashboard-check) prove
 * the RULES. This proves the RESULT: it signs in as each tenant (admin magic
 * link — no passwords are used or stored), reads the endpoints /dashboard
 * renders plus the canonical engines they must agree with, and asserts:
 *
 *   • Estate Workflow open findings  == Open Findings KPI == scanner intelligence (non-SAFE)
 *   • Estate Workflow CBOM components == Cryptographic Inventory KPI == CBOM page total
 *   • Estate Workflow certificates   == the tenant's certificate rows
 *   • every drawn finding has a finding-sheet record
 *   • no PQC/resistant algorithm carries a severity no finding gave it
 *   • finding-backed recommendations == Remediation lens actions
 *   • Shared Responsibility "Actionable Now" never exceeds the open findings
 *   • Asset Inventory "at risk" == Quantum-Vulnerable Assets KPI
 *   • no KPI claims a trend it has no history for
 *
 * Requires the dev server and service-role creds in .env.
 */
import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'

const BASE = process.argv[2] || 'http://localhost:3000'
const EMAILS = (process.argv[3] || process.env.CHECK_RECONCILE_EMAILS || 'threathunter369@gmail.com,zachmatthew369@gmail.com,teslagreat101@gmail.com')
  .split(',').map((e) => e.trim()).filter(Boolean)
const URL = process.env.VITE_SUPABASE_URL || ''
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || ''
const ANON_KEY = process.env.VITE_SUPABASE_ANON_KEY || ''
if (!URL || !SERVICE_KEY || !ANON_KEY) {
  console.error('Missing VITE_SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY / VITE_SUPABASE_ANON_KEY in .env')
  process.exit(1)
}
const admin = createClient(URL, SERVICE_KEY, { auth: { persistSession: false, autoRefreshToken: false } })

let failures = 0
function assert(name: string, ok: boolean, detail: string) {
  if (!ok) failures++
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name.padEnd(62)} ${detail}`)
}

async function sessionFor(email: string) {
  const { data: link, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email })
  if (error) throw new Error(`generateLink(${email}): ${error.message}`)
  const anon = createClient(URL, ANON_KEY, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data, error: otpErr } = await anon.auth.verifyOtp({ token_hash: (link as any).properties.hashed_token, type: 'magiclink' })
  if (otpErr) throw new Error(`verifyOtp(${email}): ${otpErr.message}`)
  return { token: data.session!.access_token, userId: data.user!.id, client: anon }
}

async function getJson(path: string, token: string) {
  const res = await fetch(BASE + path, { headers: { Authorization: `Bearer ${token}` } })
  if (!res.ok) throw new Error(`${path} -> HTTP ${res.status}`)
  const json = await res.json()
  return json.data ?? json
}

async function main() {
  console.log(`\n=== /dashboard live reconciliation (${BASE}) ===`)
  for (const email of EMAILS) {
    console.log(`\n[${email}]`)
    const { token, userId, client } = await sessionFor(email)
    try {
    const [exec, workflow, intel, recs, sr] = await Promise.all([
      getJson('/api/v1/dashboard/executive', token),
      getJson('/api/v1/dashboard/estate-workflow', token),
      getJson('/api/v1/scanner/intelligence', token),
      getJson('/api/v1/dashboard/recommendations', token),
      getJson('/api/v1/migration-intelligence', token),
    ])
    const { count: certRows } = await admin.from('certificates').select('id', { count: 'exact', head: true }).eq('user_id', userId)
    const kpi = (id: string) => exec.kpis.find((k: any) => k.id === id)
    const est = workflow.estate
    const intelOpen = ['critical', 'high', 'medium', 'low'].reduce((sum, key) => sum + Number(intel.severityCounts?.[key] || 0), 0)

    assert('workflow open findings == Open Findings KPI', est.openFindings === kpi('open-findings')?.value, `${est.openFindings} vs ${kpi('open-findings')?.value}`)
    assert('Open Findings KPI == scanner intelligence (non-SAFE)', kpi('open-findings')?.value === intelOpen, `${kpi('open-findings')?.value} vs ${intelOpen}`)
    assert('workflow CBOM components == Cryptographic Inventory KPI', est.components === kpi('crypto-inventory')?.value, `${est.components} vs ${kpi('crypto-inventory')?.value}`)
    assert('Cryptographic Inventory KPI == CBOM page total', kpi('crypto-inventory')?.value === intel.summary?.totalComponents, `${kpi('crypto-inventory')?.value} vs ${intel.summary?.totalComponents}`)
    assert('workflow certificates == certificate rows', est.certificates === (certRows ?? 0), `${est.certificates} vs ${certRows}`)
    assert('workflow reconciliation balances (no silent drop)',
      workflow.truncation.truncated || (workflow.reconciliation.findingsProjected === est.openFindings && workflow.reconciliation.componentsProjected === est.components),
      `${workflow.reconciliation.findingsProjected}/${est.openFindings} findings · ${workflow.reconciliation.componentsProjected}/${est.components} components`)
    const findingNodes = workflow.nodes.filter((n: any) => n.kind === 'finding')
    assert('every drawn finding has a finding-sheet record', findingNodes.every((n: any) => workflow.findingCorpus.some((f: any) => f.id === n.findingIds[0])), `${findingNodes.length} nodes · ${workflow.findingCorpus.length} records`)
    const lentSeverity = workflow.nodes.filter((n: any) => n.kind === 'algorithm' && ['pqc', 'resistant', 'hybrid'].includes(n.quantumStatus) && n.severity !== null && n.findingIds.length === 0)
    assert('no safe algorithm carries a severity no finding gave it', lentSeverity.length === 0, lentSeverity.map((n: any) => n.label).join(', ') || 'none')
    const remediationNodes = workflow.nodes.filter((n: any) => n.kind === 'remediation').length
    const findingActions = Number(recs.findingActions)
    const remediationCapped = workflow.truncation.dropped.some((d: any) => d.kind === 'remediation')
    assert('finding-backed recommendations == Remediation lens actions',
      remediationCapped ? findingActions >= remediationNodes : findingActions === remediationNodes,
      `${findingActions} vs ${remediationNodes}`)
    const open = Math.max(0, Number(sr.totals?.findings || 0) - Number(sr.totals?.resolved || 0))
    assert('SR Actionable Now ≤ open findings', Number(sr.widgets?.actionableFindings || 0) <= open, `${sr.widgets?.actionableFindings} ≤ ${open}`)
    const atRisk = exec.assetInventory.categories
      .filter((c: any) => !['certificates', 'secrets', 'cloud_accounts'].includes(c.key))
      .reduce((sum: number, c: any) => sum + c.atRisk, 0)
    assert('Asset Inventory at-risk == Quantum-Vulnerable Assets KPI', atRisk === exec.inventory.quantumVulnerableAssets, `${atRisk} vs ${exec.inventory.quantumVulnerableAssets}`)
    const borrowed = exec.kpis.filter((k: any) => k.trendBasis !== 'history' && (k.sparkline?.length || 0) > 0)
    assert('no KPI draws a trend it has no history for', borrowed.length === 0, borrowed.map((k: any) => k.id).join(', ') || 'none')
    console.log(`        estate: ${est.assets} assets · ${est.openFindings} open (${est.pqcConfirmations} PQC-ready) · ${est.components} components/${est.componentInstances} instances · ${est.certificates} certs · ${workflow.nodes.length} nodes`)
    } finally {
      // A minted session left open shows up as a live session in Admin > Users.
      await client.auth.signOut({ scope: 'local' }).catch(() => undefined)
    }
  }
  console.log(failures === 0 ? '\n✓ every /dashboard panel agrees with every other, on every tenant\n' : `\n${failures} RECONCILIATION FAILURE(S)\n`)
  process.exit(failures === 0 ? 0 : 1)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
