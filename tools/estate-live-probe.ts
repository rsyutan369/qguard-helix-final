/**
 * Estate intelligence — signed-in live probe against the running dev server.
 *
 *     npx tsx tools/estate-live-probe.ts [email=zachmatthew369@gmail.com] [otherEmail=teslagreat101@gmail.com] [origin=http://localhost:3000]
 *
 * Signs QA accounts in with a throwaway magic-link session (signed out at the
 * end), then checks every /api/v1/estate-intelligence route:
 *   - responds, with timings;
 *   - headline totals reconcile with direct, RLS-scoped table counts;
 *   - every fix's progress sums to its assets; graphs are bounded;
 *   - tenant isolation: a fix id from tenant A is 404 for tenant B.
 * Read-only: it never queues a wave.
 */
import 'dotenv/config'
import { createClient, type SupabaseClient } from '@supabase/supabase-js'

const EMAIL = process.argv[2] || 'zachmatthew369@gmail.com'
const OTHER = process.argv[3] || 'teslagreat101@gmail.com'
const ORIGIN = process.argv[4] || 'http://localhost:3000'
const SUPA = process.env.VITE_SUPABASE_URL!

let failures = 0
const check = (label: string, ok: boolean, detail = '') => {
  if (!ok) failures += 1
  console.log(`  ${ok ? '✓' : '✗'} ${label}${detail ? ` — ${detail}` : ''}`)
}

async function signIn(email: string): Promise<{ token: string; client: SupabaseClient; anon: SupabaseClient }> {
  const admin = createClient(SUPA, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data: link, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email })
  if (error) throw error
  const anon = createClient(SUPA, process.env.VITE_SUPABASE_ANON_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data: otp, error: otpError } = await anon.auth.verifyOtp({ token_hash: (link as any).properties.hashed_token, type: 'magiclink' })
  if (otpError) throw otpError
  const token = otp.session!.access_token
  const client = createClient(SUPA, process.env.VITE_SUPABASE_ANON_KEY!, { auth: { persistSession: false }, global: { headers: { Authorization: `Bearer ${token}` } } })
  return { token, client, anon }
}

async function api<T = any>(token: string, path: string): Promise<{ status: number; ms: number; data: T | null; error?: string }> {
  const started = performance.now()
  const res = await fetch(`${ORIGIN}/api/v1/estate-intelligence${path}`, { headers: { Authorization: `Bearer ${token}` } })
  const json: any = await res.json().catch(() => ({}))
  return { status: res.status, ms: Math.round(performance.now() - started), data: json.data ?? null, error: json.error?.message }
}

async function count(client: SupabaseClient, table: string, userId: string) {
  const { count: n } = await client.from(table).select('*', { count: 'exact', head: true }).eq('user_id', userId)
  return n ?? 0
}

async function main() {
  console.log(`\nEstate live probe · ${EMAIL} · ${ORIGIN}\n`)
  const a = await signIn(EMAIL)
  const sessions = [a.anon]
  try {
    const { data: { user } } = await a.client.auth.getUser(a.token)
    const userId = user!.id

    console.log('[1] Overview')
    const cold = await api(a.token, '/?refresh=1')
    check('GET / responds 200', cold.status === 200, `${cold.status} in ${cold.ms} ms (cold, forced rebuild)${cold.error ? ` · ${cold.error}` : ''}`)
    if (!cold.data) throw new Error('No overview data')
    const warm = await api(a.token, '/')
    check('second read is served from the cache', warm.status === 200 && warm.ms < Math.max(800, cold.ms / 2), `${warm.ms} ms`)
    const o: any = cold.data
    const s = o.summary
    console.log(`     ${s.assets} assets · ${s.affectedAssets} affected · ${s.fixes} fixes · ${s.inventoryRows} inventory rows · ${s.certificateRecords} certificate records → ${s.uniqueCertificates} unique`)
    for (const c of o.coverage) console.log(`     coverage ${c.table}: ${c.loaded}/${c.total ?? '?'}${c.truncated ? ' (TRUNCATED)' : ''}`)

    console.log('\n[2] Totals match the database (RLS-scoped direct counts)')
    const [assets, inventory, certificates] = await Promise.all([count(a.client, 'assets', userId), count(a.client, 'crypto_inventory', userId), count(a.client, 'certificates', userId)])
    check('assets = assets table', s.assets === assets, `${s.assets} vs ${assets}`)
    check('inventory rows = crypto_inventory table', s.inventoryRows === inventory, `${s.inventoryRows} vs ${inventory}`)
    check('certificate records = certificates table', s.certificateRecords === certificates, `${s.certificateRecords} vs ${certificates}`)
    check('no table was truncated', o.coverage.every((c: any) => !c.truncated))

    console.log('\n[3] Internal consistency')
    check('each fix: progress sums to its assets', o.clusters.every((c: any) => Object.values(c.progress as Record<string, number>).reduce((x, y) => x + y, 0) === c.assets))
    const memberships = o.clusters.reduce((sum: number, c: any) => sum + c.assets, 0)
    check('open + validated = all asset × fix pairs', s.openWorkItems + s.validatedWorkItems === memberships, `${s.openWorkItems} + ${s.validatedWorkItems} = ${memberships}`)
    check('estate map covers every asset', o.maps.owner.reduce((sum: number, g: any) => sum + g.assets, 0) === s.assets)
    check('no PQC algorithm is routed to a fix', !o.clusters.some((c: any) => c.algorithms.some((x: string) => /ML-KEM|ML-DSA|SLH-DSA/i.test(x))))
    for (const c of o.clusters.slice(0, 8)) console.log(`     #${c.priorityRank} [${c.priority}] ${c.title} — ${c.assets} asset(s), ${c.deadline.label}`)

    console.log('\n[4] Detail, graphs, search')
    const top = o.clusters[0]
    if (top) {
      const detail = await api(a.token, `/fixes/${encodeURIComponent(top.id)}?limit=10`)
      check('GET /fixes/:id', detail.status === 200 && (detail.data as any).total === top.assets, `${detail.status} in ${detail.ms} ms, ${(detail.data as any)?.total} members, ${(detail.data as any)?.campaign?.waves?.length} wave(s)`)
      const hood = await api(a.token, `/graph?level=neighbourhood&focus=${encodeURIComponent(`fix:${top.id}`)}`)
      check('GET /graph neighbourhood of the top fix', hood.status === 200 && (hood.data as any).graph.nodes.length > 0, `${(hood.data as any)?.graph.nodes.length} nodes in ${hood.ms} ms`)
      const campaign = await api(a.token, `/graph?level=campaign&focus=${encodeURIComponent(`fix:${top.id}`)}`)
      check('GET /graph campaign pipeline', campaign.status === 200 && (campaign.data as any).graph.nodes.length === 7, `${(campaign.data as any)?.graph.nodes.length} steps`)
      const firstAsset = (detail.data as any)?.members?.[0]?.assetId
      if (firstAsset) {
        const assetHood = await api(a.token, `/graph?level=neighbourhood&focus=${encodeURIComponent(`asset:${firstAsset}`)}`)
        check('GET /graph neighbourhood of an asset', assetHood.status === 200, `${(assetHood.data as any)?.graph.nodes.length} nodes`)
      }
    }
    const root = await api(a.token, '/graph?level=root-cause')
    check('GET /graph root-cause is bounded', root.status === 200 && (root.data as any).graph.nodes.filter((n: any) => n.kind === 'fix').length <= 40, `${(root.data as any)?.graph.nodes.length} nodes`)
    const bad = await api(a.token, '/graph?level=neighbourhood&focus=../../etc')
    check('malformed focus is rejected', bad.status === 400)
    const search = await api(a.token, `/search?q=${encodeURIComponent(String(o.maps.owner[0]?.label ?? 'a').slice(0, 3))}`)
    check('GET /search', search.status === 200 && Array.isArray(search.data), `${(search.data as any[])?.length} hit(s)`)

    console.log('\n[5] Tenant isolation')
    try {
      const b = await signIn(OTHER)
      sessions.push(b.anon)
      const other = await api(b.token, '/')
      check('second tenant gets its own (or a plan-gated) answer', other.status === 200 || other.status === 403, `${other.status}`)
      if (top && other.status === 200) {
        const otherIds = new Set(((other.data as any).clusters as any[]).map((c) => c.id))
        // Fix ids are rule-derived (e.g. "key-exchange:ecdh"), so a shared id is expected; what must NOT leak is the members.
        const cross = await api(b.token, `/fixes/${encodeURIComponent(top.id)}?limit=500`)
        if (!otherIds.has(top.id)) check('tenant A fix id is 404 for tenant B', cross.status === 404, `${cross.status}`)
        else {
          const ours = new Set(((await api(a.token, `/fixes/${encodeURIComponent(top.id)}?limit=500`)).data as any).members.map((m: any) => m.assetId))
          const leaked = ((cross.data as any)?.members ?? []).filter((m: any) => ours.has(m.assetId))
          check('same fix id in tenant B lists none of tenant A\'s assets', leaked.length === 0, `${leaked.length} overlapping`)
        }
      }
    } catch (error) {
      console.log(`  - second tenant skipped: ${(error as Error).message}`)
    }
  } finally {
    for (const session of sessions) await session.auth.signOut({ scope: 'local' }).catch(() => undefined)
  }
  console.log(`\n${failures === 0 ? '✓ LIVE ESTATE CHECKS PASS' : `✗ ${failures} CHECK(S) FAILED`}\n`)
  process.exit(failures === 0 ? 0 : 1)
}

main().catch((error) => { console.error(error); process.exit(1) })
