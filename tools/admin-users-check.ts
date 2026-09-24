/**
 * Owner Admin > Users — accuracy + wiring check.
 *
 *   npx tsx tools/admin-users-check.ts             pure model assertions (offline)
 *   npx tsx tools/admin-users-check.ts --live      + live API vs. an independent read of Supabase
 *   npx tsx tools/admin-users-check.ts --live --mutate
 *                                                  + every Users action end-to-end against a
 *                                                    DISPOSABLE account it creates and deletes
 *                                                    (never touches real users)
 *
 * Live mode needs the dev server (ADMIN_CHECK_BASE, default http://localhost:3000),
 * VITE_SUPABASE_URL, VITE_SUPABASE_ANON_KEY and SUPABASE_SERVICE_ROLE_KEY.
 */
import 'dotenv/config'
import assert from 'node:assert/strict'
import { createClient, type SupabaseClient } from '@supabase/supabase-js'
import {
  buildUserDirectory,
  directoryToCsv,
  filterDirectoryUsers,
  queryUserDirectory,
  type AuthDirectoryRow,
  type DirectoryInput,
} from '@/lib/admin/user-directory'
import { entitlementFromRecords } from '@/lib/subscription-access'
import { ADMIN_OWNER_EMAIL } from '@/lib/admin-access'

let passed = 0
let failed = 0
async function check(name: string, fn: () => unknown | Promise<unknown>) {
  try {
    await fn()
    passed += 1
    console.log(`  PASS  ${name}`)
  } catch (error) {
    failed += 1
    console.log(`  FAIL  ${name}\n        ${error instanceof Error ? error.message : String(error)}`)
  }
}

// ---------------------------------------------------------------------------
// Offline: the model
// ---------------------------------------------------------------------------

const NOW = Date.parse('2026-09-23T12:00:00Z')
const iso = (msAgo: number) => new Date(NOW - msAgo).toISOString()
const HOUR = 3_600_000
const DAY = 24 * HOUR

function authRow(id: string, email: string, patch: Partial<AuthDirectoryRow> = {}): AuthDirectoryRow {
  return {
    user_id: id,
    email,
    created_at: iso(10 * DAY),
    last_sign_in_at: iso(2 * DAY),
    email_confirmed_at: iso(10 * DAY),
    invited_at: null,
    banned_until: null,
    providers: ['email'],
    app_role: null,
    session_count: 1,
    aal2_session_count: 0,
    last_session_activity_at: iso(2 * DAY),
    last_session_ip: '203.0.113.7',
    last_session_user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0 Safari/537.36',
    mfa_verified_factors: 0,
    mfa_factor_types: [],
    ...patch,
  }
}

const IDS = {
  owner: 'a1000000-0000-4000-8000-000000000001',
  paid: 'b2000000-0000-4000-8000-000000000002',
  comp: 'c3000000-0000-4000-8000-000000000003',
  none: 'd4000000-0000-4000-8000-000000000004',
  banned: 'e5000000-0000-4000-8000-000000000005',
  driftSuspended: 'f6000000-0000-4000-8000-000000000006',
  unverified: '17000000-0000-4000-8000-000000000007',
  mfa: '28000000-0000-4000-8000-000000000008',
  orphan: '39000000-0000-4000-8000-000000000009',
}

function fixture(): DirectoryInput {
  return {
    now: NOW,
    authSource: 'rpc',
    auth: [
      authRow(IDS.owner, ADMIN_OWNER_EMAIL, { session_count: 3, last_session_activity_at: iso(10 * 60_000) }),
      authRow(IDS.paid, 'paid@corp.test', { session_count: 2 }),
      authRow(IDS.comp, 'comp@corp.test', { last_sign_in_at: iso(45 * DAY), last_session_activity_at: iso(45 * DAY) }),
      authRow(IDS.none, 'none@corp.test', { last_sign_in_at: null, last_session_activity_at: null, session_count: 0, last_session_ip: null, last_session_user_agent: null }),
      authRow(IDS.banned, 'banned@corp.test', { banned_until: new Date(NOW + 1000 * DAY).toISOString(), session_count: 0 }),
      authRow(IDS.driftSuspended, 'drift@corp.test'),
      authRow(IDS.unverified, 'unverified@corp.test', { email_confirmed_at: null, last_sign_in_at: null, last_session_activity_at: null, session_count: 0 }),
      authRow(IDS.mfa, 'mfa@corp.test', { mfa_verified_factors: 1, mfa_factor_types: ['totp'], aal2_session_count: 1, last_session_user_agent: 'node' }),
    ],
    profiles: [
      { id: IDS.owner, email: ADMIN_OWNER_EMAIL, role: null, tier: 'free', account_status: 'active' },
      { id: IDS.paid, email: 'paid@corp.test', full_name: 'Paid Person', role: 'security_admin', tier: 'pro', account_status: 'active', tenant_id: 'tenant-1' },
      { id: IDS.comp, email: 'comp@corp.test', role: null, tier: 'basic', account_status: 'active' },
      { id: IDS.none, email: 'none@corp.test', role: null, tier: 'pro', account_status: 'active' },
      { id: IDS.banned, email: 'banned@corp.test', role: null, tier: 'free', account_status: 'active' },
      { id: IDS.driftSuspended, email: 'drift@corp.test', role: null, tier: 'free', account_status: 'suspended' },
      { id: IDS.unverified, email: 'unverified@corp.test', role: null, tier: 'free', account_status: 'active' },
      { id: IDS.mfa, email: 'mfa@corp.test', role: 'user', tier: 'free', account_status: 'active', mfa_required: true },
      { id: IDS.orphan, email: 'orphan@corp.test', role: null, tier: 'free', account_status: 'active' },
    ],
    subscriptions: [
      { id: 's1', user_id: IDS.paid, plan: 'Pro', status: 'active', provider: 'paypal', current_period_end: iso(-20 * DAY) },
      { id: 's2', user_id: IDS.comp, plan: 'Basic', status: 'active', provider: 'manual_test' },
      { id: 's3', user_id: IDS.banned, plan: 'Elite', status: 'cancelled', provider: null },
    ],
    organizations: [{ id: 'tenant-1', name: 'Acme Corp', slug: 'acme', status: 'active' }],
    memberships: [{ organization_id: 'tenant-1', user_id: IDS.paid, role: 'security_admin', status: 'active' }],
  }
}

async function offline() {
  console.log('\nModel (offline)')
  const directory = buildUserDirectory(fixture())
  const byId = new Map(directory.users.map((user) => [user.id, user]))
  const u = (key: keyof typeof IDS) => {
    const user = byId.get(IDS[key])
    assert.ok(user, `user ${key} missing`)
    return user
  }

  await check('owner: role Owner, Elite access via bypass, never billed', () => {
    const owner = u('owner')
    assert.equal(owner.role, 'owner')
    assert.equal(owner.isOwner, true)
    assert.equal(owner.access.tier, 'elite')
    assert.equal(owner.access.isActive, true)
    assert.equal(owner.access.accessClass, 'owner')
    assert.equal(owner.access.tierDrift, null, 'owner profiles.tier must not count as drift')
    assert.equal(owner.activity, 'active_now')
  })
  await check('sessions come from Supabase Auth, not user_sessions', () => {
    assert.equal(u('owner').sessions.count, 3)
    assert.equal(u('paid').sessions.count, 2)
    assert.equal(directory.stats.liveSessions, 3 + 2 + 1 + 0 + 0 + 1 + 0 + 1)
  })
  await check('provider-billed plan: Pro, active, provider class, tenant resolved', () => {
    const paid = u('paid')
    assert.equal(paid.access.tier, 'pro')
    assert.equal(paid.access.accessClass, 'provider')
    assert.equal(paid.access.providerManaged, true)
    assert.equal(paid.tenantName, 'Acme Corp')
    assert.equal(paid.tenantRole, 'security_admin')
    assert.equal(paid.isAdministrator, true)
  })
  await check('manual_test seed is Complimentary (grants access, never MRR)', () => {
    const comp = u('comp')
    assert.equal(comp.access.accessClass, 'complimentary')
    assert.equal(comp.access.isActive, true)
    assert.equal(comp.activity, 'dormant')
  })
  await check('profiles.tier alone grants nothing and is flagged as drift', () => {
    const none = u('none')
    assert.equal(none.access.isActive, false)
    assert.equal(none.access.source, 'none')
    assert.match(String(none.access.tierDrift), /grants nothing/)
    assert.equal(none.activity, 'never')
  })
  await check('auth ban on an "active" profile reads Suspended + drift', () => {
    const banned = u('banned')
    assert.equal(banned.status, 'suspended')
    assert.match(String(banned.statusDrift), /banned/)
    assert.equal(banned.access.isActive, false, 'cancelled subscription grants nothing')
  })
  await check('profile "suspended" without an auth ban is drift (sign-in not blocked)', () => {
    assert.equal(u('driftSuspended').status, 'suspended')
    assert.match(String(u('driftSuspended').statusDrift), /still allows sign-in/)
  })
  await check('unconfirmed email reads Unverified, not Active', () => {
    assert.equal(u('unverified').status, 'pending_verification')
  })
  await check('MFA = verified factor enrollment; policy flag is separate', () => {
    assert.equal(u('mfa').mfa.state, 'enrolled')
    assert.equal(u('paid').mfa.state, 'not_enrolled')
    assert.equal(directory.stats.mfa.enrolled, 1)
    assert.equal(directory.stats.mfa.required, 1)
    assert.equal(u('mfa').sessions.lastDevice, 'API / script client')
  })
  await check('orphan profile is listed and fails the parity check', () => {
    assert.match(String(u('orphan').statusDrift), /no Supabase Auth account/)
    const parity = directory.integrity.find((c) => c.id === 'auth-profile-parity')
    assert.equal(parity?.ok, false)
  })
  await check('partitions: status, access, activity each sum to total', () => {
    for (const id of ['status-partition', 'access-partition', 'activity-partition']) {
      const c = directory.integrity.find((row) => row.id === id)
      assert.ok(c?.ok, `${id}: ${c?.detail}`)
    }
    assert.equal(directory.stats.totalUsers, 9)
  })
  await check('role filter "user" matches NULL-role profiles (old .eq bug)', () => {
    const users = filterDirectoryUsers(directory.users, { role: 'user' })
    assert.ok(users.length >= 6, `got ${users.length}`)
    assert.ok(users.every((user) => user.role === 'user'))
  })
  await check('plan / status / activity / mfa filters', () => {
    assert.deepEqual(filterDirectoryUsers(directory.users, { plan: 'no_access' }).map((x) => x.id).sort(), [IDS.none, IDS.banned, IDS.driftSuspended, IDS.unverified, IDS.mfa, IDS.orphan].sort())
    assert.deepEqual(filterDirectoryUsers(directory.users, { plan: 'complimentary' }).map((x) => x.id), [IDS.comp])
    assert.deepEqual(filterDirectoryUsers(directory.users, { status: 'drift' }).map((x) => x.id).sort(), [IDS.banned, IDS.driftSuspended, IDS.orphan].sort())
    assert.equal(filterDirectoryUsers(directory.users, { activity: 'active_now' }).length, 1)
    assert.equal(filterDirectoryUsers(directory.users, { mfa: 'enrolled' }).length, 1)
  })
  await check('search by display id, email, tenant', () => {
    const paid = u('paid')
    assert.deepEqual(filterDirectoryUsers(directory.users, { search: paid.displayId.toLowerCase() }).map((x) => x.id), [IDS.paid])
    assert.deepEqual(filterDirectoryUsers(directory.users, { search: 'acme' }).map((x) => x.id), [IDS.paid])
  })
  await check('pagination totals are the FILTERED count', () => {
    const page = queryUserDirectory(directory, { plan: 'no_access', limit: 2, page: 2 })
    assert.equal(page.pagination.total, 6)
    assert.equal(page.pagination.totalPages, 3)
    assert.equal(page.users.length, 2)
  })
  await check('admin-API fallback: sessions Unknown (null), never 0', () => {
    const input = fixture()
    input.authSource = 'admin_api'
    input.auth = input.auth.map((row) => ({ ...row, session_count: null, last_session_activity_at: null }))
    const fallback = buildUserDirectory(input)
    assert.equal(fallback.stats.liveSessions, null)
    assert.ok(fallback.users.every((user) => user.sessions.count === null))
    assert.ok(fallback.sources.notes.some((note) => /RPC is not installed/.test(note)))
  })
  await check('auth unreadable: MFA Unknown, not "not enrolled"', () => {
    const input = fixture()
    input.authSource = 'unavailable'
    input.auth = []
    const blind = buildUserDirectory(input)
    assert.equal(blind.stats.mfa.enrolled, null)
    assert.ok(blind.users.every((user) => user.mfa.state === 'unknown'))
  })
  await check('version: stable across rebuilds, changes when a record changes', () => {
    assert.equal(buildUserDirectory(fixture()).version, directory.version)
    const changed = fixture()
    changed.auth[1] = { ...changed.auth[1], session_count: 5 }
    assert.notEqual(buildUserDirectory(changed).version, directory.version)
    // The clock alone never changes the version.
    assert.equal(buildUserDirectory({ ...fixture(), now: NOW + 5 * HOUR }).version, directory.version)
  })
  await check('CSV: BOM, header, formula injection neutralised', () => {
    const input = fixture()
    input.profiles[1] = { ...input.profiles[1], full_name: '=HYPERLINK("http://x")' }
    const csv = directoryToCsv(buildUserDirectory(input).users)
    assert.ok(csv.startsWith('﻿User ID,'))
    assert.ok(csv.includes(`"'=HYPERLINK(""http://x"")"`), 'formula must be prefixed with a quote')
  })
  await check('entitlement rule: one function for gateway and console', () => {
    assert.deepEqual(entitlementFromRecords({ isOwner: false, subscription: { plan: 'Pro', status: 'past_due' } }).isActive, false)
    assert.deepEqual(entitlementFromRecords({ isOwner: false, subscription: null, profileTier: 'elite' }).isActive, false)
    assert.deepEqual(entitlementFromRecords({ isOwner: true, subscription: null }).tier, 'elite')
  })
}

// ---------------------------------------------------------------------------
// Live
// ---------------------------------------------------------------------------

type Session = { token: string; refresh: string; userId: string; client: SupabaseClient }

async function live(mutate: boolean) {
  console.log('\nLive API vs. Supabase')
  const BASE = process.env.ADMIN_CHECK_BASE || 'http://localhost:3000'
  const URL_ = process.env.VITE_SUPABASE_URL || ''
  const SERVICE = process.env.SUPABASE_SERVICE_ROLE_KEY || ''
  const ANON = process.env.VITE_SUPABASE_ANON_KEY || ''
  if (!URL_ || !SERVICE || !ANON) throw new Error('Missing VITE_SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY / VITE_SUPABASE_ANON_KEY')
  const admin = createClient(URL_, SERVICE, { auth: { persistSession: false, autoRefreshToken: false } })
  const anonClient = () => createClient(URL_, ANON, { auth: { persistSession: false, autoRefreshToken: false } })

  async function magicSession(email: string): Promise<Session> {
    const { data: link, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email })
    if (error) throw new Error(`generateLink(${email}): ${error.message}`)
    const client = anonClient()
    const { data, error: otpError } = await client.auth.verifyOtp({ token_hash: (link as any).properties.hashed_token, type: 'magiclink' })
    if (otpError || !data.session) throw new Error(`verifyOtp(${email}): ${otpError?.message}`)
    return { token: data.session.access_token, refresh: data.session.refresh_token, userId: data.user!.id, client }
  }
  async function passwordSession(email: string, password: string): Promise<Session> {
    const client = anonClient()
    const { data, error } = await client.auth.signInWithPassword({ email, password })
    if (error || !data.session) throw new Error(`signIn(${email}): ${error?.message}`)
    return { token: data.session.access_token, refresh: data.session.refresh_token, userId: data.user.id, client }
  }
  const call = async (method: string, path: string, token: string, body?: unknown) => {
    const response = await fetch(`${BASE}${path}`, {
      method,
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
    const text = await response.text()
    let json: any = null
    try { json = JSON.parse(text) } catch { json = text }
    return { status: response.status, json, headers: response.headers }
  }

  const owner = await magicSession(ADMIN_OWNER_EMAIL)
  const startedAt = new Date(Date.now() - 2000).toISOString()
  try {
    const list = await call('GET', '/api/v1/admin/users?limit=100', owner.token)
    const data = list.json?.data
    await check('GET /users: 200 with reconciled integrity checks', () => {
      assert.equal(list.status, 200, JSON.stringify(list.json))
      assert.equal(data.sources.auth, 'rpc')
      const failing = data.integrity.filter((c: any) => !c.ok && c.id !== 'status-drift')
      assert.equal(failing.length, 0, JSON.stringify(failing))
    })

    // Independent read — NOT through the model.
    const { data: rpcRows, error: rpcError } = await admin.rpc('admin_user_auth_directory')
    const { count: profileCount } = await admin.from('profiles').select('id', { count: 'exact', head: true })
    await check('Total users = Supabase Auth accounts = profiles', () => {
      assert.ok(!rpcError, rpcError?.message)
      assert.equal(data.stats.totalUsers, rpcRows.length)
      assert.equal(data.stats.totalUsers, profileCount)
    })
    await check('per-user sessions / last IP / MFA equal Supabase Auth', () => {
      for (const row of rpcRows as AuthDirectoryRow[]) {
        const user = data.users.find((candidate: any) => candidate.id === row.user_id)
        assert.ok(user, `missing ${row.email}`)
        assert.equal(user.sessions.count, row.session_count, `${row.email} sessions`)
        assert.equal(user.sessions.lastIp, row.last_session_ip, `${row.email} ip`)
        assert.equal(user.mfa.enrolledFactors, row.mfa_verified_factors, `${row.email} mfa`)
      }
      assert.equal(data.stats.liveSessions, (rpcRows as AuthDirectoryRow[]).reduce((sum, row) => sum + row.session_count!, 0))
    })
    const { data: subs } = await admin.from('billing_subscriptions').select('user_id,plan,status')
    await check('plan access equals billing_subscriptions (gateway rule)', () => {
      for (const user of data.users) {
        const sub = (subs || []).find((row: any) => row.user_id === user.id)
        const expected = entitlementFromRecords({ isOwner: user.email.toLowerCase() === ADMIN_OWNER_EMAIL, subscription: sub || null })
        assert.equal(user.access.isActive, expected.isActive, `${user.email} access`)
        if (expected.isActive) assert.equal(user.access.tier, expected.tier, `${user.email} tier`)
      }
    })
    await check('owner row: role Owner, Elite, protected', () => {
      const ownerRow = data.users.find((user: any) => user.isOwner)
      assert.ok(ownerRow)
      assert.equal(ownerRow.roleLabel, 'Owner')
      assert.equal(ownerRow.access.tierLabel, 'Owner · Elite')
    })
    const roleUser = await call('GET', '/api/v1/admin/users?role=user&limit=100', owner.token)
    await check('role=user returns NULL-role accounts (was 0 rows)', () => {
      assert.equal(roleUser.status, 200)
      assert.equal(roleUser.json.data.pagination.total, data.users.filter((user: any) => user.role === 'user').length)
      assert.ok(roleUser.json.data.pagination.total > 0)
    })
    const overview = await call('GET', '/api/v1/admin/stats', owner.token)
    await check('Overview KPIs read the same directory (one Total Users)', () => {
      assert.equal(overview.status, 200)
      assert.equal(overview.json.data.kpis.totalUsers, data.stats.totalUsers)
      assert.equal(overview.json.data.kpis.activeSessions, data.stats.liveSessions)
    })
    const security = await call('GET', '/api/v1/admin/security', owner.token)
    await check('Security tab: administrators, their sessions and MFA coverage read the same directory', () => {
      assert.equal(security.status, 200)
      const summary = security.json.data.summary
      assert.equal(summary.administrators, data.stats.administrators)
      const expectedCoverage = Math.round((data.stats.mfa.enrolled / Math.max(1, data.stats.totalUsers)) * 100)
      assert.equal(summary.mfaCoveragePercent, expectedCoverage)
      for (const admin of security.json.data.administrators) {
        const user = data.users.find((candidate: any) => candidate.id === admin.id)
        assert.ok(user, `administrator ${admin.email} missing from Users`)
        assert.equal(admin.sessions, user.sessions.count, admin.email)
        assert.equal(admin.mfa, user.mfa.state, admin.email)
      }
    })
    const csv = await fetch(`${BASE}/api/v1/admin/users/export?format=csv`, { headers: { Authorization: `Bearer ${owner.token}` } })
    // Read bytes: Response.text() strips a UTF-8 BOM by spec.
    const csvBytes = Buffer.from(await csv.arrayBuffer())
    const csvText = csvBytes.subarray(3).toString('utf8')
    await check('CSV export: every user, BOM + header, attachment', () => {
      assert.equal(csv.status, 200)
      assert.match(String(csv.headers.get('content-disposition')), /attachment; filename="qguard-users-/)
      assert.deepEqual([...csvBytes.subarray(0, 3)], [0xef, 0xbb, 0xbf], 'UTF-8 BOM')
      assert.ok(csvText.startsWith('User ID,'))
      assert.equal(csvText.trim().split(/\r\n/).length, data.stats.totalUsers + 1)
    })
    const noAuth = await fetch(`${BASE}/api/v1/admin/users`)
    await check('no token -> 401', () => assert.equal(noAuth.status, 401))

    if (!mutate) return

    console.log('\nLive actions (disposable account)')
    const email = `qguard-admin-e2e-${Date.now()}@example.com`
    const password = `E2e!${Math.random().toString(36).slice(2)}${Date.now()}`
    const created = await call('POST', '/api/v1/admin/users', owner.token, { email, password, name: 'E2E Disposable', role: 'user', plan: 'starter' })
    const testId: string = created.json?.data?.userId
    await check('POST /users: 201, Starter granted', () => {
      assert.equal(created.status, 201, JSON.stringify(created.json))
      assert.equal(created.json.data.plan, 'Starter')
    })
    if (!testId) return
    try {
      const weak = await call('POST', '/api/v1/admin/users', owner.token, { email: `weak-${email}`, password: 'short' })
      await check('POST /users: weak password -> 400', () => assert.equal(weak.status, 400))

      const user1 = await passwordSession(email, password)
      const forbidden = await call('GET', '/api/v1/admin/users', user1.token)
      await check('non-owner token -> 403', () => assert.equal(forbidden.status, 403))

      const role = await call('PATCH', `/api/v1/admin/users/${testId}`, owner.token, { role: 'security_analyst' })
      const badRole = await call('PATCH', `/api/v1/admin/users/${testId}`, owner.token, { role: 'super_admin' })
      const { data: authAfterRole } = await admin.auth.admin.getUserById(testId)
      await check('PATCH role: catalogue role saved + synced to auth; reserved role refused', () => {
        assert.equal(role.status, 200, JSON.stringify(role.json))
        assert.equal(authAfterRole.user?.app_metadata?.role, 'security_analyst')
        assert.equal(badRole.status, 400)
      })

      const plan = await call('POST', `/api/v1/admin/users/${testId}/subscription`, owner.token, { action: 'activate', plan: 'Pro', interval: 'annual' })
      const { data: subRow } = await admin.from('billing_subscriptions').select('plan,status,billing_cycle,amount_cents').eq('user_id', testId).single()
      await check('Manage plan: Pro annual active, re-priced', () => {
        assert.equal(plan.status, 200, JSON.stringify(plan.json))
        assert.equal(subRow?.plan, 'Pro')
        assert.equal(subRow?.status, 'active')
        assert.equal(subRow?.billing_cycle, 'annual')
      })
      const past = await call('POST', `/api/v1/admin/users/${testId}/subscription`, owner.token, { action: 'activate', plan: 'Pro', expiresAt: '2020-01-01T00:00:00Z' })
      await check('Manage plan: past period end refused', () => assert.equal(past.status, 400))

      // Sign out everywhere: the old token must die IMMEDIATELY, refresh too.
      const beforeLogout = await call('GET', '/api/v1/profile', user1.token)
      const logout = await call('POST', `/api/v1/admin/users/${testId}/actions`, owner.token, { action: 'force_logout', reason: 'e2e' })
      const afterLogout = await call('GET', '/api/v1/profile', user1.token)
      const refresh = await anonClient().auth.refreshSession({ refresh_token: user1.refresh })
      const { data: sessionsAfter } = await admin.rpc('admin_user_auth_sessions', { p_user_id: testId })
      await check('Sign out everywhere: sessions ended, old token 401, refresh refused', () => {
        assert.equal(beforeLogout.status, 200, `baseline profile call ${beforeLogout.status}`)
        assert.equal(logout.status, 200, JSON.stringify(logout.json))
        assert.ok(logout.json.data.sessionsEnded >= 1, `ended ${logout.json.data.sessionsEnded}`)
        assert.equal((sessionsAfter || []).length, 0)
        assert.equal(afterLogout.status, 401, `after logout ${afterLogout.status}`)
        assert.ok(refresh.error, 'refresh token must be revoked')
      })

      await new Promise((resolve) => setTimeout(resolve, 1100)) // new token iat > revocation second
      const user2 = await passwordSession(email, password)
      const suspend = await call('POST', `/api/v1/admin/users/${testId}/actions`, owner.token, { action: 'suspend', reason: 'e2e' })
      const afterSuspend = await call('GET', '/api/v1/profile', user2.token)
      const signInSuspended = await anonClient().auth.signInWithPassword({ email, password })
      const { data: bannedAuth } = await admin.auth.admin.getUserById(testId)
      const listSuspended = await call('GET', `/api/v1/admin/users?search=${encodeURIComponent(email)}`, owner.token)
      await check('Suspend: banned in auth, sessions ended, token 401, sign-in refused, status Suspended w/o drift', () => {
        assert.equal(suspend.status, 200, JSON.stringify(suspend.json))
        assert.ok(bannedAuth.user?.banned_until && Date.parse(bannedAuth.user.banned_until) > Date.now())
        assert.equal(afterSuspend.status, 401)
        assert.ok(signInSuspended.error, 'banned user must not sign in')
        const row = listSuspended.json.data.users[0]
        assert.equal(row.status, 'suspended')
        assert.equal(row.statusDrift, null)
      })
      const ownerSuspend = await call('POST', `/api/v1/admin/users/${owner.userId}/actions`, owner.token, { action: 'suspend' })
      await check('Owner cannot be suspended', () => assert.equal(ownerSuspend.status, 400))

      const restore = await call('POST', `/api/v1/admin/users/${testId}/actions`, owner.token, { action: 'restore' })
      await new Promise((resolve) => setTimeout(resolve, 1100))
      const signInRestored = await anonClient().auth.signInWithPassword({ email, password })
      await check('Restore: sign-in works again', () => {
        assert.equal(restore.status, 200, JSON.stringify(restore.json))
        assert.ok(!signInRestored.error, signInRestored.error?.message)
      })

      const link = await call('POST', `/api/v1/admin/users/${testId}/actions`, owner.token, { action: 'reset_password', delivery: 'link' })
      await check('Reset password (link): one-time recovery link returned', () => {
        assert.equal(link.status, 200, JSON.stringify(link.json))
        assert.match(String(link.json.data.recoveryLink), /^https:\/\/.+type=recovery/)
        assert.match(String(link.json.data.recoveryLink), /redirect_to=.*reset-password/)
      })
      const mail = await call('POST', `/api/v1/admin/users/${testId}/actions`, owner.token, { action: 'reset_password', delivery: 'email' })
      await check('Reset password (email): sent, or a clear provider error (never a silent success)', () => {
        if (mail.status === 200) assert.equal(mail.json.data.sentTo, email)
        else assert.ok([429, 502].includes(mail.status) && mail.json?.error?.message, JSON.stringify(mail.json))
      })
      console.log(`        reset email result: ${mail.status} ${mail.status === 200 ? 'sent' : mail.json?.error?.message}`)

      const mfaOn = await call('POST', `/api/v1/admin/users/${testId}/actions`, owner.token, { action: 'mfa_require' })
      const mfaRow = await call('GET', `/api/v1/admin/users?search=${encodeURIComponent(email)}`, owner.token)
      await check('Require MFA: state = required but not enrolled', () => {
        assert.equal(mfaOn.status, 200)
        assert.equal(mfaRow.json.data.users[0].mfa.state, 'required_not_enrolled')
      })
      const verify = await call('POST', `/api/v1/admin/users/${testId}/actions`, owner.token, { action: 'verify_email' })
      await check('Verify email on a confirmed account -> 409', () => assert.equal(verify.status, 409))

      const detail = await call('GET', `/api/v1/admin/users/${testId}`, owner.token)
      await check('Detail: live sessions + admin trail for this user', () => {
        assert.equal(detail.status, 200)
        assert.ok(Array.isArray(detail.json.data.sessions))
        assert.ok(detail.json.data.adminTrail.length >= 5, `trail ${detail.json.data.adminTrail.length}`)
      })
      const { data: audits } = await admin.from('admin_audit_events').select('action,details').eq('entity_id', testId).gte('created_at', startedAt)
      await check('Audit: every action recorded; no recovery link ever stored', () => {
        const actions = new Set((audits || []).map((row: any) => row.action))
        for (const action of ['admin.user.created', 'admin.user.updated', 'admin.user.force_logout', 'admin.user.suspend', 'admin.user.restore', 'admin.user.reset_password', 'admin.user.mfa_require']) {
          assert.ok(actions.has(action), `missing ${action}`)
        }
        assert.ok(!JSON.stringify(audits).includes('type=recovery'), 'recovery link leaked into audit')
      })
    } finally {
      const noConfirm = await call('DELETE', `/api/v1/admin/users/${testId}`, owner.token, {})
      const del = await call('DELETE', `/api/v1/admin/users/${testId}`, owner.token, { confirmEmail: email })
      const { data: gone } = await admin.auth.admin.getUserById(testId)
      const { count: profileLeft } = await admin.from('profiles').select('id', { count: 'exact', head: true }).eq('id', testId)
      const { count: subLeft } = await admin.from('billing_subscriptions').select('id', { count: 'exact', head: true }).eq('user_id', testId)
      await check('Delete: needs typed confirmation; removes auth, profile, subscription', () => {
        assert.equal(noConfirm.status, 400)
        assert.equal(del.status, 200, JSON.stringify(del.json))
        assert.ok(!gone?.user, 'auth user still exists')
        assert.equal(profileLeft, 0)
        assert.equal(subLeft, 0)
      })
      const ownerDelete = await call('DELETE', `/api/v1/admin/users/${owner.userId}`, owner.token, { confirmEmail: ADMIN_OWNER_EMAIL })
      await check('Owner cannot be deleted', () => assert.equal(ownerDelete.status, 400))
    }
  } finally {
    // Leave no extra owner session behind.
    await owner.client.auth.signOut({ scope: 'local' }).catch(() => undefined)
  }
}

async function main() {
  const args = new Set(process.argv.slice(2))
  await offline()
  if (args.has('--live')) await live(args.has('--mutate'))
  console.log(`\n${passed} passed, ${failed} failed`)
  process.exit(failed ? 1 : 0)
}

void main().catch((error) => {
  console.error(error)
  process.exit(1)
})
