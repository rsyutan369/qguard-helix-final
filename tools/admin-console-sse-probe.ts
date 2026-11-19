/**
 * Owner Admin > Roles, Tenants, Plans & Billing, Security, Governance, History —
 * SSE probe.
 *
 *   npx tsx tools/admin-console-sse-probe.ts
 *
 * Opens /api/v1/admin/stream as the owner and proves, for every console frame:
 *   1. it is delivered on the stream,
 *   2. its `version` is stable while nothing changes (no refresh storm — the
 *      client refetches a tab only when its version changes),
 *   3. a write to that tab's data changes its version, pushed within seconds
 *      (invalidateAdminModels -> pushNow), with the stats moving accordingly.
 * Writes are DISPOSABLE (a role, a tenant, a policy, a user with a manual
 * Starter plan) and removed before exit.
 */
import 'dotenv/config'
import assert from 'node:assert/strict'
import { createClient } from '@supabase/supabase-js'
import { ADMIN_OWNER_EMAIL } from '@/lib/admin-access'

const BASE = process.env.ADMIN_CHECK_BASE || 'http://localhost:3000'
const URL_ = process.env.VITE_SUPABASE_URL || ''
const SERVICE = process.env.SUPABASE_SERVICE_ROLE_KEY || ''
const ANON = process.env.VITE_SUPABASE_ANON_KEY || ''
const CONSOLE_FRAMES = ['admin-roles', 'admin-tenants', 'admin-billing', 'admin-security', 'admin-governance', 'admin-history'] as const
// Real sign-ins / other open consoles legitimately move these, so their idle
// stability is reported rather than asserted.
const ENVIRONMENT_SENSITIVE = new Set(['admin-security', 'admin-history'])

type Frame = { event: string; data: any; at: number }

/** Open a stream the way the browser does: header-auth ticket, then ?ticket=. */
async function ticketUrl(stream: string, token: string): Promise<string> {
  const minted = await fetch(`${BASE}/api/v1/stream-tickets`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ stream }),
  })
  const body = await minted.json() as any
  if (!minted.ok) throw new Error(`stream ticket refused: HTTP ${minted.status} ${JSON.stringify(body)}`)
  return `${BASE}${body.data.path}?ticket=${encodeURIComponent(body.data.ticket)}`
}

let failures = 0
function result(ok: boolean, label: string, detail = '') {
  if (!ok) failures += 1
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ` — ${detail}` : ''}`)
}

async function main() {
  const admin = createClient(URL_, SERVICE, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data: link, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email: ADMIN_OWNER_EMAIL })
  if (error) throw error
  const client = createClient(URL_, ANON, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data: session, error: otpError } = await client.auth.verifyOtp({ token_hash: (link as any).properties.hashed_token, type: 'magiclink' })
  if (otpError || !session.session) throw otpError || new Error('no session')
  const token = session.session.access_token

  const frames: Frame[] = []
  const controller = new AbortController()
  const response = await fetch(await ticketUrl('admin', token), { signal: controller.signal })
  assert.equal(response.status, 200)
  const reader = response.body!.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  const pump = (async () => {
    try {
      for (;;) {
        const { value, done } = await reader.read()
        if (done) return
        buffer += decoder.decode(value, { stream: true })
        let index
        while ((index = buffer.indexOf('\n\n')) >= 0) {
          const block = buffer.slice(0, index)
          buffer = buffer.slice(index + 2)
          const event = /^event: (.+)$/m.exec(block)?.[1]
          const data = /^data: (.+)$/m.exec(block)?.[1]
          if (event && data) frames.push({ event, data: JSON.parse(data), at: Date.now() })
        }
      }
    } catch {
      // aborted
    }
  })()

  const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
  const nextFrame = async (event: string, after: number, predicate: (frame: Frame) => boolean = () => true, timeoutMs = 25_000) => {
    const deadline = Date.now() + timeoutMs
    while (Date.now() < deadline) {
      const frame = frames.find((candidate) => candidate.event === event && candidate.at > after && predicate(candidate))
      if (frame) return frame
      await wait(200)
    }
    return null
  }
  const call = (method: string, path: string, body?: unknown) => fetch(`${BASE}${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  }).then(async (res) => ({ status: res.status, json: await res.json().catch(() => null) }))

  /** Perform a write, then wait for `event` with a NEW version; returns [frame, latency]. */
  const expectPush = async (event: string, baseline: string, write: () => Promise<unknown>) => {
    await write()
    const at = Date.now()
    const frame = await nextFrame(event, at - 1, (candidate) => candidate.data.version !== baseline, 15_000)
    return { frame, latency: frame ? frame.at - at : null }
  }

  const stamp = Date.now()
  const cleanup: Array<() => Promise<unknown>> = []
  try {
    console.log('\nDelivery + idle stability')
    // Tick 1 may be served from the 8s bundle cache built before this probe's own
    // connect audit row; compare ticks 2 and 3.
    const tick1 = await nextFrame('admin-history', 0)
    const tick2 = tick1 && await nextFrame('admin-history', tick1.at)
    const tick3 = tick2 && await nextFrame('admin-history', tick2.at)
    assert.ok(tick3, 'three stream ticks within 75s')
    const latest = (event: string, before: number) => [...frames].reverse().find((frame) => frame.event === event && frame.at <= before + 50)
    const baseline: Record<string, string> = {}
    for (const event of CONSOLE_FRAMES) {
      const a = latest(event, tick2!.at)
      const b = latest(event, tick3!.at)
      result(Boolean(a && b), `${event}: delivered on every tick`)
      if (!a || !b) continue
      baseline[event] = b.data.version
      const stable = a.data.version === b.data.version
      if (ENVIRONMENT_SENSITIVE.has(event)) console.log(`  info  ${event}: idle version ${stable ? 'stable' : 'moved (real activity)'}`)
      else result(stable, `${event}: version stable while idle`, stable ? String(b.data.version) : `${a.data.version} -> ${b.data.version}`)
    }

    console.log('\nWrite -> push')
    // Roles
    let roleId = ''
    const roleKey = `sse_probe_${stamp}`
    const roleTotal = latest('admin-roles', Date.now())!.data.stats.total
    const role = await expectPush('admin-roles', baseline['admin-roles'], async () => {
      const created = await call('POST', '/api/v1/admin/roles', { name: `SSE Probe ${stamp}`, key: roleKey, permissions: ['reports.read'] })
      roleId = created.json?.data?.id
      assert.equal(created.status, 201, JSON.stringify(created.json))
    })
    cleanup.push(() => call('POST', `/api/v1/admin/roles/${roleId}/actions`, { action: 'delete', confirmKey: roleKey }))
    result(Boolean(role.frame) && role.frame!.data.stats.total === roleTotal + 1, 'admin-roles: create pushes a new version with total +1', `latency ${role.latency} ms`)

    // Tenants
    let tenantId = ''
    const tenantName = `SSE Probe Tenant ${stamp}`
    const tenantTotal = latest('admin-tenants', Date.now())!.data.stats.total
    const tenant = await expectPush('admin-tenants', latest('admin-tenants', Date.now())!.data.version, async () => {
      const created = await call('POST', '/api/v1/admin/tenants', { name: tenantName })
      tenantId = created.json?.data?.id
      assert.equal(created.status, 201, JSON.stringify(created.json))
    })
    cleanup.push(() => call('POST', `/api/v1/admin/tenants/${tenantId}/actions`, { action: 'delete', confirmName: tenantName }))
    result(Boolean(tenant.frame) && tenant.frame!.data.stats.total === tenantTotal + 1, 'admin-tenants: create pushes a new version with total +1', `latency ${tenant.latency} ms`)

    // Governance
    let policyId = ''
    let policyKey = ''
    const policyTotal = latest('admin-governance', Date.now())!.data.stats.policies
    const policy = await expectPush('admin-governance', latest('admin-governance', Date.now())!.data.version, async () => {
      const created = await call('POST', '/api/v1/admin/governance/policies', { name: `SSE Probe Policy ${stamp}`, category: 'operations', enforcementLevel: 'advisory' })
      policyId = created.json?.data?.id
      policyKey = created.json?.data?.key
      assert.equal(created.status, 201, JSON.stringify(created.json))
    })
    cleanup.push(() => call('DELETE', `/api/v1/admin/governance/policies/${policyId}`, { confirmKey: policyKey }))
    result(Boolean(policy.frame) && policy.frame!.data.stats.policies === policyTotal + 1, 'admin-governance: create pushes a new version with policies +1', `latency ${policy.latency} ms`)

    // Billing — a disposable user with a manual Starter plan
    let userId = ''
    const email = `qguard-console-sse-${stamp}@example.com`
    const billingBefore = latest('admin-billing', Date.now())!.data.stats
    const billingCount = billingBefore.subscriptions
    const billing = await expectPush('admin-billing', latest('admin-billing', Date.now())!.data.version, async () => {
      const created = await call('POST', '/api/v1/admin/users', { email, password: `Probe!${stamp}xyz`, role: 'user', plan: 'starter' })
      userId = created.json?.data?.userId
      assert.equal(created.status, 201, JSON.stringify(created.json))
    })
    cleanup.unshift(() => call('DELETE', `/api/v1/admin/users/${userId}`, { confirmEmail: email }))
    result(Boolean(billing.frame) && billing.frame!.data.stats.subscriptions === billingCount + 1, 'admin-billing: a new plan pushes a new version with subscriptions +1', `latency ${billing.latency} ms`)
    result(Boolean(billing.frame) && billing.frame!.data.stats.mrrCents === billingBefore.mrrCents, 'admin-billing: a manual plan does not move MRR')

    // History + security follow administrator actions
    const history = await nextFrame('admin-history', tick3!.at, (frame) => frame.data.stats.last7d >= latest('admin-history', tick3!.at)!.data.stats.last7d + 4, 15_000)
    result(Boolean(history), 'admin-history: the four actions above raised "Admin actions · 7d"')
    const security = await nextFrame('admin-security', tick3!.at, (frame) => frame.data.version !== baseline['admin-security'], 15_000)
    result(Boolean(security), 'admin-security: administrator activity pushes a new version')
  } finally {
    for (const undo of cleanup) {
      const outcome: any = await undo().catch((error) => ({ status: 0, json: String(error) }))
      if (outcome?.status !== 200) {
        failures += 1
        console.log(`  FAIL  cleanup answered ${outcome?.status}: ${JSON.stringify(outcome?.json)}`)
      }
    }
    controller.abort()
    await pump
    await client.auth.signOut({ scope: 'local' }).catch(() => undefined)
  }
  console.log(`\nConsole SSE probe: ${failures ? `FAIL (${failures})` : 'PASS'}`)
  process.exit(failures ? 1 : 0)
}

void main().catch((error) => {
  console.error('Console SSE probe: FAIL', error)
  process.exit(1)
})
