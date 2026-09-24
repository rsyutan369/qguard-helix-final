/**
 * Owner Admin > Users — SSE probe.
 *
 *   npx tsx tools/admin-users-sse-probe.ts
 *
 * Opens /api/v1/admin/stream as the owner, records the `admin-users` frames,
 * creates then deletes a DISPOSABLE account through the API, and asserts the
 * frame `version` changes after each write (the client refetches its table
 * only on a version change). Also asserts the unchanged ticks keep the same
 * version (no refresh storm).
 */
import 'dotenv/config'
import assert from 'node:assert/strict'
import { createClient } from '@supabase/supabase-js'
import { ADMIN_OWNER_EMAIL } from '@/lib/admin-access'

const BASE = process.env.ADMIN_CHECK_BASE || 'http://localhost:3000'
const URL_ = process.env.VITE_SUPABASE_URL || ''
const SERVICE = process.env.SUPABASE_SERVICE_ROLE_KEY || ''
const ANON = process.env.VITE_SUPABASE_ANON_KEY || ''

type Frame = { event: string; data: any; at: number }

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
  const response = await fetch(`${BASE}/api/v1/admin/stream?token=${encodeURIComponent(token)}`, { signal: controller.signal })
  assert.equal(response.status, 200)
  assert.match(String(response.headers.get('content-type')), /text\/event-stream/)
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
  const usersFrames = () => frames.filter((frame) => frame.event === 'admin-users')
  const waitForUsersFrame = async (after: number, timeoutMs = 25_000) => {
    const deadline = Date.now() + timeoutMs
    while (Date.now() < deadline) {
      const frame = usersFrames().find((candidate) => candidate.at > after)
      if (frame) return frame
      await wait(250)
    }
    throw new Error('no admin-users frame within timeout')
  }
  const call = (method: string, path: string, body?: unknown) => fetch(`${BASE}${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  }).then(async (res) => ({ status: res.status, json: await res.json().catch(() => null) }))

  try {
    const first = await waitForUsersFrame(0)
    console.log(`first admin-users frame: version=${first.data.version} total=${first.data.stats.totalUsers} sessions=${first.data.stats.liveSessions}`)
    const second = await waitForUsersFrame(first.at)
    console.log(`next tick (no writes):  version=${second.data.version}`)
    assert.equal(second.data.version, first.data.version, 'version must be stable while nothing changes')
    assert.ok(frames.some((frame) => frame.event === 'admin-connected'), 'admin-connected frame')
    assert.ok(frames.some((frame) => frame.event === 'admin-stats'), 'admin-stats frame')

    const email = `qguard-sse-probe-${Date.now()}@example.com`
    const created = await call('POST', '/api/v1/admin/users', { email, password: `Probe!${Date.now()}xyz`, role: 'user', plan: 'none' })
    assert.equal(created.status, 201, JSON.stringify(created.json))
    const userId = created.json.data.userId
    const writeAt = Date.now()
    try {
      const afterCreate = await waitForUsersFrame(writeAt)
      console.log(`after create:           version=${afterCreate.data.version} total=${afterCreate.data.stats.totalUsers} (latency ${afterCreate.at - writeAt} ms)`)
      assert.notEqual(afterCreate.data.version, first.data.version, 'version must change after a create')
      assert.equal(afterCreate.data.stats.totalUsers, first.data.stats.totalUsers + 1)
    } finally {
      const deleted = await call('DELETE', `/api/v1/admin/users/${userId}`, { confirmEmail: email })
      assert.equal(deleted.status, 200, JSON.stringify(deleted.json))
    }
    const deleteAt = Date.now()
    const afterDelete = await waitForUsersFrame(deleteAt)
    console.log(`after delete:           version=${afterDelete.data.version} total=${afterDelete.data.stats.totalUsers}`)
    assert.equal(afterDelete.data.stats.totalUsers, first.data.stats.totalUsers)
    // Real sign-ins/refreshes by other users also (correctly) change the version,
    // so a restored version is reported, not asserted.
    console.log(`version restored to pre-probe value: ${afterDelete.data.version === first.data.version}`)
    console.log('\nSSE probe: PASS')
  } finally {
    controller.abort()
    await pump
    await client.auth.signOut({ scope: 'local' }).catch(() => undefined)
  }
}

void main().catch((error) => {
  console.error('SSE probe: FAIL', error)
  process.exit(1)
})
