// TEMP audit probe (deleted after the audit). Read-only.
import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'
const SUPA = process.env.VITE_SUPABASE_URL!
const admin = createClient(SUPA, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
const BASE = 'http://localhost:3000'
const PAGES = ['tls-telemetry', 'pki-visibility', 'protocol-analytics', 'encryption-monitoring', 'tls-orchestrator', 'trust-dashboard', 'trust-state-discovery']
const SENS = ['session_token_hash', 'token_hash', 'ip_address', 'user_agent', 'token_ref', 'private_key', 'secret', 'raw_evidence', 'fingerprint', 'serial_number']
const detail = process.argv[2] === 'detail'
async function signIn(email: string) {
  const { data: link } = await admin.auth.admin.generateLink({ type: 'magiclink', email })
  const anon = createClient(SUPA, process.env.VITE_SUPABASE_ANON_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data } = await anon.auth.verifyOtp({ token_hash: (link as any).properties.hashed_token, type: 'magiclink' })
  return { anon, token: data.session!.access_token }
}
const pick = (o: any, keys: string[]) => Object.fromEntries(keys.filter((k) => o && k in o).map((k) => [k, o[k]]))
;(async () => {
  for (const email of (process.argv[3] || 'threathunter369@gmail.com,teslagreat101@gmail.com,zachmatthew369@gmail.com').split(',')) {
    const { anon, token } = await signIn(email)
    console.log(`\n######## ${email.slice(0, 6)}`)
    try {
      for (const page of PAGES) {
        const q = await fetch(`${BASE}/api/v1/dashboard/${page}?token=${encodeURIComponent(token)}`)
        const t0 = Date.now()
        const h = await fetch(`${BASE}/api/v1/dashboard/${page}`, { headers: { Authorization: `Bearer ${token}` } })
        const raw = await h.text()
        const ms = Date.now() - t0
        let d: any = {}
        try { d = JSON.parse(raw).data || {} } catch {}
        console.log(`\n== ${page}: ?token=→${q.status} header→${h.status} ${(raw.length / 1024).toFixed(0)}KB ${ms}ms | sensitive: ${SENS.filter((k) => raw.includes(`"${k}"`)).join(',') || 'none'}`)
        await q.body?.cancel().catch(() => {})
        if (!h.ok) { console.log('  ', raw.slice(0, 150)); continue }
        console.log('  keys:', Object.keys(d).join(','))
        console.log('  hasData', d.hasData, '| totals', JSON.stringify(d.totals))
        if (d.posture) console.log('  posture', JSON.stringify(d.posture).slice(0, 600))
        if (d.scores) console.log('  scores', JSON.stringify(d.scores).slice(0, 600))
        if (d.telemetry) console.log('  telemetry', JSON.stringify(d.telemetry).slice(0, 700))
        if (detail) {
          if (d.endpoints) console.log('  endpoint[0]', JSON.stringify(d.endpoints[0]).slice(0, 1500))
          if (d.certificates) console.log('  cert[0]', JSON.stringify(d.certificates[0]).slice(0, 1500))
          if (d.findings) console.log('  findings', d.findings.slice(0, 6).map((f: any) => `[${f.severity}] ${f.title} :: ${f.observed ?? ''} (${f.source ?? f.provenance ?? ''})`).join('\n     '))
          if (d.handshake) console.log('  handshake', JSON.stringify(d.handshake))
          if (d.versionDistribution) console.log('  versions', JSON.stringify(d.versionDistribution).slice(0, 600))
          if (d.protocol) console.log('  protocol keys', Object.keys(d.protocol).join(','), JSON.stringify(pick(d.protocol, ['versionDistribution', 'forwardSecrecy', 'handshakeFailures', 'handshakeFailuresMeasured', 'denominator'])).slice(0, 800))
          if (d.lifecycle) console.log('  lifecycle', JSON.stringify(d.lifecycle).slice(0, 600))
          if (d.trustChains) console.log('  trustChains', JSON.stringify(d.trustChains).slice(0, 900))
          if (d.orchestration) console.log('  orchestration', JSON.stringify(pick(d.orchestration, ['statusCounts', 'stages', 'summary'])).slice(0, 900), '\n   item0', JSON.stringify(d.orchestration.items?.[0]).slice(0, 1200))
          if (d.kpis) console.log('  kpis', JSON.stringify(d.kpis).slice(0, 1200))
          if (d.stateDistribution) console.log('  stateDist', JSON.stringify(d.stateDistribution).slice(0, 600))
          if (d.certificateIntel) console.log('  certIntel', JSON.stringify(d.certificateIntel).slice(0, 900))
          if (d.trend) console.log('  trend', JSON.stringify(d.trend).slice(0, 500))
          if (d.events) console.log('  events', d.events.slice(0, 4).map((e: any) => JSON.stringify(e).slice(0, 250)).join('\n     '))
          if (d.nodes) console.log('  nodes', d.nodes.slice(0, 5).map((n: any) => `${n.kind}:${n.label}:${n.state}:${n.stateReason ?? ''}`).join(' | '))
          if (d.relationships) console.log('  rels', d.relationships.slice(0, 5).map((r: any) => JSON.stringify(r).slice(0, 220)).join('\n     '))
          if (d.discovery) console.log('  discovery', JSON.stringify(d.discovery).slice(0, 900))
          if (d.symmetric) console.log('  symmetric', d.symmetric.slice(0, 5).map((a: any) => `${a.label}:${a.strength?.strength}:${a.observations}`).join(' '))
          if (d.keys) console.log('  keys', JSON.stringify(pick(d.keys, ['total', 'lifecycle', 'summary'])).slice(0, 400))
          if (d.atRest) console.log('  atRest', JSON.stringify(pick(d.atRest, ['summary', 'coverage'])).slice(0, 400))
          if (d.operations) console.log('  operations', JSON.stringify(d.operations).slice(0, 500))
          if (d.timeline) console.log('  timeline', JSON.stringify(d.timeline).slice(0, 300))
        }
      }
    } finally { await anon.auth.signOut({ scope: 'local' }).catch(() => {}) }
  }
})()
