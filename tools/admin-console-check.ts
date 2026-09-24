/**
 * Owner Admin > Roles, Tenants, Plans & Billing, Security, Governance, History —
 * accuracy + wiring check.
 *
 *   npx tsx tools/admin-console-check.ts                   pure model assertions (offline)
 *   npx tsx tools/admin-console-check.ts --live            + API vs. an independent read of Supabase
 *   npx tsx tools/admin-console-check.ts --live --mutate   + every action on DISPOSABLE records it
 *                                                            creates and removes (never real ones)
 *
 * Live mode needs the dev server (ADMIN_CHECK_BASE, default http://localhost:3000),
 * VITE_SUPABASE_URL, VITE_SUPABASE_ANON_KEY and SUPABASE_SERVICE_ROLE_KEY.
 */
import 'dotenv/config'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createClient, type SupabaseClient } from '@supabase/supabase-js'
import { buildUserDirectory, type AuthDirectoryRow, type DirectoryInput } from '@/lib/admin/user-directory'
import { buildRoleCatalog, normalizePermissions } from '@/lib/admin/role-catalog'
import { buildTenantDirectory } from '@/lib/admin/tenant-directory'
import { buildBillingConsole } from '@/lib/admin/billing-console'
import { buildSecurityPosture } from '@/lib/admin/security-posture'
import { buildGovernanceModel } from '@/lib/admin/governance'
import { adminActionCategory, normalizeAdminAuditRow } from '@/lib/admin/admin-history'
import { canonicalJson, modelVersion } from '@/lib/admin/model-utils'
import { ADMIN_OWNER_EMAIL } from '@/lib/admin-access'
import { normalizeRole, ROLE_CAPABILITIES, ROLE_LABELS } from '@/api-server/copilot-knowledge'

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
// Offline
// ---------------------------------------------------------------------------

const NOW = Date.parse('2026-09-23T12:00:00Z')
const DAY = 24 * 3_600_000
const iso = (msAgo: number) => new Date(NOW - msAgo).toISOString()

function auth(id: string, email: string, patch: Partial<AuthDirectoryRow> = {}): AuthDirectoryRow {
  return {
    user_id: id, email, created_at: iso(10 * DAY), last_sign_in_at: iso(DAY), email_confirmed_at: iso(10 * DAY), invited_at: null, banned_until: null,
    providers: ['email'], app_role: null, session_count: 1, aal2_session_count: 0, last_session_activity_at: iso(DAY), last_session_ip: '203.0.113.9',
    last_session_user_agent: 'Mozilla/5.0 Chrome/140', mfa_verified_factors: 0, mfa_factor_types: [], ...patch,
  }
}

const ID = { owner: 'a1000000-0000-4000-8000-000000000001', analyst: 'b2000000-0000-4000-8000-000000000002', member: 'c3000000-0000-4000-8000-000000000003', paying: 'd4000000-0000-4000-8000-000000000004' }

function directoryFixture() {
  const input: DirectoryInput = {
    now: NOW,
    authSource: 'rpc',
    auth: [
      auth(ID.owner, ADMIN_OWNER_EMAIL, { session_count: 14 }),
      auth(ID.analyst, 'analyst@corp.test', { mfa_verified_factors: 1, mfa_factor_types: ['totp'] }),
      auth(ID.member, 'member@corp.test', { last_sign_in_at: iso(60 * DAY), last_session_activity_at: iso(60 * DAY), session_count: 2 }),
      auth(ID.paying, 'paying@corp.test'),
    ],
    profiles: [
      { id: ID.owner, email: ADMIN_OWNER_EMAIL, role: null, tier: 'free', account_status: 'active' },
      { id: ID.analyst, email: 'analyst@corp.test', role: 'security_analyst', tier: 'pro', account_status: 'active', tenant_id: 'org-1' },
      { id: ID.member, email: 'member@corp.test', role: null, tier: 'basic', account_status: 'active', tenant_id: 'org-1' },
      { id: ID.paying, email: 'paying@corp.test', role: 'mystery_role', tier: 'pro', account_status: 'active' },
    ],
    subscriptions: [
      { id: 's-comp', user_id: ID.member, plan: 'Basic', status: 'active', provider: 'manual_test' },
      { id: 's-paid', user_id: ID.paying, plan: 'Pro', status: 'active', provider: 'paypal', current_period_end: iso(-10 * DAY), cancel_at_period_end: false },
    ],
    organizations: [{ id: 'org-1', name: 'Acme', slug: 'acme', status: 'active' }],
    memberships: [{ organization_id: 'org-1', user_id: ID.analyst, role: 'security_analyst', status: 'active' }],
  }
  return buildUserDirectory(input)
}

const sophiaFor = (key: string, isOwner: boolean) => {
  const role = normalizeRole(key === 'user' ? null : key, isOwner)
  return { role, label: ROLE_LABELS[role], capabilities: { ...ROLE_CAPABILITIES[role] } }
}

async function offline() {
  console.log('\nModels (offline)')
  const directory = directoryFixture()

  const roles = buildRoleCatalog({
    rows: [
      { id: 'r1', role_key: 'security_analyst', name: 'Security Analyst', description: '', role_type: 'custom', status: 'active', tenant_id: null, permission_scope: 'Security', permissions: ['security.read', 'alerts.manage', 'reports.generate'], metadata: {}, created_at: null, updated_at: null },
      { id: 'r2', role_key: 'readonly_auditor', name: 'Auditor', description: '', role_type: 'custom', status: 'inactive', tenant_id: null, permission_scope: 'Read Only', permissions: ['*.read'], metadata: {}, created_at: null, updated_at: null },
    ],
    definitions: [{ role_key: 'super_admin', name: 'Super Admin', description: '', role_type: 'system', permission_scope: 'All', permissions: ['*'] }],
    holders: directory.users.map((user) => ({ id: user.id, email: user.email, name: user.name, role: user.role, isOwner: user.isOwner })),
    tenants: [{ id: 'org-1', name: 'Acme' }],
    sophiaFor,
    now: NOW,
  })
  const role = (key: string) => roles.roles.find((candidate) => candidate.key === key)!
  await check('roles: permission count is the TRUE pattern count (was 64/128/256)', () => {
    assert.equal(role('security_analyst').permissionSummary, '3 permission patterns')
    assert.equal(role('super_admin').permissionSummary, 'All permissions (*)')
  })
  await check('roles: holders come from the directory; owner and NULL-role users counted', () => {
    assert.equal(role('owner').holders, 1)
    assert.equal(role('user').holders, 1)
    assert.equal(role('security_analyst').holders, 1)
    assert.equal(roles.stats.usersCovered, directory.users.length)
  })
  await check('roles: real effect = Sophia mapping (analyst read-only, auditor audit)', () => {
    assert.equal(role('security_analyst').sophia.role, 'security_analyst')
    assert.equal(role('security_analyst').sophia.capabilities.operate, false)
    assert.equal(role('readonly_auditor').sophia.role, 'auditor')
    assert.equal(role('owner').sophia.role, 'owner')
    assert.equal(role('user').sophia.role, 'security_analyst', 'no role = read-only Security Analyst')
    assert.equal(role('user').sophia.capabilities.operate, false)
  })
  await check('roles: a held role missing from the catalogue is flagged, not hidden', () => {
    assert.equal(role('mystery_role').type, 'discovered')
    assert.equal(roles.integrity.find((c) => c.id === 'no-discovered')?.ok, false)
  })
  await check('roles: reserved roles are never assignable; inactive roles are not either', () => {
    assert.equal(role('owner').assignable, false)
    assert.equal(role('super_admin').assignable, false)
    assert.equal(role('readonly_auditor').assignable, false)
    assert.equal(role('user').assignable, true)
  })
  await check('roles: permission pattern validation', () => {
    assert.deepEqual(normalizePermissions('security.read, audit.* bad pattern!').invalid, ['pattern!'])
    assert.deepEqual(normalizePermissions(['Security.Read', 'security.read']).permissions, ['security.read'])
  })

  const tenants = buildTenantDirectory({
    organizations: [
      { id: 'org-1', name: 'Acme', slug: 'acme', owner_user_id: ID.analyst, status: 'active', plan: 'pro', quota_users: 1, quota_storage_gb: 10, metadata: {}, created_at: null, updated_at: null },
      { id: 'org-2', name: 'Empty Co', slug: 'empty', owner_user_id: null, status: 'suspended', plan: null, quota_users: null, quota_storage_gb: null, metadata: { domain: 'empty.test' }, created_at: null, updated_at: null },
    ],
    memberships: [{ organization_id: 'org-1', user_id: ID.analyst, role: 'security_analyst', status: 'active' }],
    users: directory.users,
    unassignedUsers: directory.stats.noTenant,
    sessionsMeasured: true,
    now: NOW,
  })
  const acme = tenants.tenants.find((tenant) => tenant.id === 'org-1')!
  const empty = tenants.tenants.find((tenant) => tenant.id === 'org-2')!
  await check('tenants: members from the directory, over-quota detected', () => {
    assert.equal(acme.members, 2)
    assert.equal(acme.overQuota, true)
    assert.equal(tenants.stats.overQuota, 1)
  })
  await check('tenants: no invented domain / region (was <slug>.qguard.app, us-east-1)', () => {
    assert.equal(acme.domain, null)
    assert.equal(acme.region, null)
    assert.equal(empty.domain, 'empty.test')
  })
  await check('tenants: membership rows vs profiles drift is counted', () => {
    assert.equal(acme.membershipDrift, 1, 'member@corp.test has tenant_id but no membership row')
  })
  await check('tenants: members + unassigned partition all users', () => {
    assert.ok(tenants.integrity.find((c) => c.id === 'members-partition')?.ok)
  })

  const billing = buildBillingConsole({
    subscriptions: [
      { id: 's-comp', user_id: ID.member, plan: 'Basic', status: 'active', provider: 'manual_test', billing_cycle: 'monthly', auto_renew: true, cancel_at_period_end: false, renewal_date: null, current_period_end: iso(-300 * DAY), cancelled_at: null, created_at: iso(10 * DAY), updated_at: iso(DAY) },
      { id: 's-paid', user_id: ID.paying, plan: 'Pro', status: 'active', provider: 'paypal', billing_cycle: 'monthly', auto_renew: true, cancel_at_period_end: false, renewal_date: null, current_period_end: iso(-10 * DAY), cancelled_at: null, created_at: iso(10 * DAY), updated_at: iso(DAY) },
    ],
    invoices: [{ id: 'i1', user_id: ID.paying, invoice_id: 'inv-1', payment_date: iso(5 * DAY), amount_paid_cents: 3000, currency: 'USD', payment_method_summary: null, subscription_plan: 'Pro', status: 'paid', created_at: iso(5 * DAY) }],
    paymentMethods: [],
    users: directory.users,
    tenants: [{ id: 'org-1', name: 'Acme' }],
    now: NOW,
  })
  await check('billing: MRR counts only provider-billed rows (QA seed = $0)', () => {
    assert.equal(billing.stats.mrrCents, 3000)
    assert.equal(billing.rows.find((row) => row.id === 's-comp')!.mrrCents, 0)
  })
  await check('billing: complimentary rows are never "upcoming invoices" (next renewal = paid row)', () => {
    assert.equal(billing.stats.nextProviderRenewal?.subscriptionId, 's-paid')
    assert.equal(billing.rows.find((row) => row.id === 's-comp')!.renewal, 'manual')
  })
  await check('billing: collected YTD from paid invoices; integrity partitions hold', () => {
    assert.equal(billing.stats.collectedYtdCents, 3000)
    assert.ok(billing.integrity.every((c) => c.ok), JSON.stringify(billing.integrity.filter((c) => !c.ok)))
  })

  const security = buildSecurityPosture({
    window: '24h',
    directory,
    events: [
      { id: 'e1', source: 'platform', event_type: 'authorized_crypto_scan_completed', severity: 'warning', message: 'Scan completed for https://x', user_id: null, created_at: iso(3_600_000) },
      { id: 'e2', source: 'account', event_type: 'login', severity: 'success', message: 'ok', user_id: ID.member, created_at: iso(2 * 3_600_000) },
      { id: 'e3', source: 'platform', event_type: 'old', severity: 'critical', message: 'x', user_id: null, created_at: iso(3 * DAY) },
    ],
    vulnerabilities: [
      { id: 'v1', title: 'RSA-1024', severity: 'critical', status: 'open', source: 'scan', created_at: iso(DAY), asset_id: 'as-1', asset_name: 'api.corp.test' },
      { id: 'v2', title: 'fixed', severity: 'critical', status: 'resolved', source: 'scan', created_at: iso(DAY) },
    ],
    adminAudit: [
      { id: 'a1', action: 'admin.access_denied', created_at: iso(DAY) },
      { id: 'a2', action: 'revenue.access_denied', created_at: iso(DAY) },
      { id: 'a3', action: 'admin.stream.connected', created_at: iso(DAY) },
    ],
    infrastructure: [{ key: 'collector_agents', label: 'Collectors', rows: [] }, { key: 'sensor_nodes', label: 'Sensors', rows: null }],
    now: NOW,
  })
  const control = (id: string) => security.controls.find((row) => row.id === id)!
  await check('security: event types are real (no "Brute Force … SSH, RDP, VPN" narratives)', () => {
    assert.deepEqual(security.eventTypes.map((row) => row.type).sort(), ['authorized_crypto_scan_completed', 'login'])
    assert.equal(security.summary.eventsTotal, 2, 'the 3-day-old event is outside 24h')
    assert.equal(security.summary.attentionEvents, 0, 'a warning is not a critical threat')
  })
  await check('security: privileged-MFA control fails and names the owner', () => {
    assert.equal(control('privileged-mfa').status, 'fail')
    assert.deepEqual(control('privileged-mfa').affected.map((row) => row.label), [ADMIN_OWNER_EMAIL])
  })
  await check('security: session sprawl + dormant sessions + open critical vuln measured', () => {
    assert.equal(control('session-sprawl').status, 'warn')
    assert.equal(control('stale-sessions').status, 'warn')
    assert.equal(control('critical-vulnerabilities').affected.length, 1, 'resolved finding excluded')
    assert.equal(control('critical-vulnerabilities').affected[0].label, 'RSA-1024 — api.corp.test', 'names the affected asset')
  })
  await check('security: blocked attempts include Revenue Intelligence; views are not activity', () => {
    assert.equal(security.summary.blockedAdminAttempts, 2)
    assert.ok(security.adminActivity.every((row) => row.action !== 'admin.stream.connected'))
  })
  await check('security: missing table = unavailable, empty table = not configured (never 0/5 GB)', () => {
    assert.equal(security.infrastructure.find((row) => row.key === 'sensor_nodes')!.state, 'unavailable')
    assert.equal(security.infrastructure.find((row) => row.key === 'collector_agents')!.state, 'not_configured')
  })
  await check('security: the version ignores the sliding clock', () => {
    const later = buildSecurityPosture({ window: '24h', directory, events: [], vulnerabilities: [], adminAudit: [], infrastructure: [], now: NOW })
    const laterStill = buildSecurityPosture({ window: '24h', directory, events: [], vulnerabilities: [], adminAudit: [], infrastructure: [], now: NOW + 60_000 })
    assert.equal(later.version, laterStill.version)
  })

  const sha3 = (value: unknown) => createHash('sha3-256').update(canonicalJson(value)).digest('hex')
  const snapshot = { a: 1, b: { c: [1, 2] } }
  const governance = buildGovernanceModel({
    policies: [
      { id: 'p1', policy_key: 'privileged-mfa-required', name: 'Privileged MFA', category: 'access', status: 'enabled', enforcement_level: 'enforce', description: '', config: {}, updated_by: null, created_at: null, updated_at: null },
      { id: 'p2', policy_key: 'owner-only-admin-dashboard', name: 'Owner only', category: 'access', status: 'enabled', enforcement_level: 'enforce', description: '', config: {}, updated_by: null, created_at: null, updated_at: null },
      { id: 'p3', policy_key: 'data-classification', name: 'Classify data', category: 'data', status: 'enabled', enforcement_level: 'enforce', description: '', config: {}, updated_by: null, created_at: null, updated_at: null },
    ],
    evidence: [
      { id: 'ev-ok', title: 'ok', framework: null, evidence_type: null, status: null, generated_by: null, metadata: { snapshot, hash: { algorithm: 'SHA3-256', value: sha3(snapshot) } }, created_at: iso(DAY) },
      { id: 'ev-bad', title: 'tampered', framework: null, evidence_type: null, status: null, generated_by: null, metadata: { snapshot: { ...snapshot, a: 2 }, hash: { algorithm: 'SHA3-256', value: sha3(snapshot) } }, created_at: iso(DAY) },
    ],
    controls: security.controls,
    deniedAttempts30d: 2,
    audit: { count: 10, oldestAt: iso(5 * DAY) },
    emailById: new Map(),
    verifyHash: (value, expected) => sha3(value) === expected,
    now: NOW,
  })
  const policy = (key: string) => governance.policies.find((row) => row.key === key)!
  await check('governance: "enforce" MFA policy is NOT MET when admins lack MFA', () => {
    assert.equal(policy('privileged-mfa-required').verification.state, 'not_met')
  })
  await check('governance: unverifiable policy is Attested, never "Compliant"', () => {
    assert.equal(policy('data-classification').verification.state, 'attested')
    assert.equal(policy('owner-only-admin-dashboard').verification.state, 'enforced_by_platform')
  })
  await check('governance: evidence fingerprint verifies; tampering is detected', () => {
    assert.equal(governance.evidence.find((row) => row.id === 'ev-ok')!.intact, true)
    assert.equal(governance.evidence.find((row) => row.id === 'ev-bad')!.intact, false)
    assert.equal(governance.integrity.find((c) => c.id === 'evidence-intact')?.ok, false)
  })
  await check('canonical JSON: key order never changes the fingerprint', () => {
    assert.equal(sha3({ b: 1, a: [1, { d: 2, c: 3 }] }), sha3({ a: [1, { c: 3, d: 2 }], b: 1 }))
    assert.equal(modelVersion({ x: 1, generatedAt: 'a' }), modelVersion({ x: 1, generatedAt: 'b' }))
  })

  await check('history: categories (admin + revenue actions), no default to "security"', () => {
    assert.equal(adminActionCategory('revenue.stream.connected'), 'views')
    assert.equal(adminActionCategory('revenue.customer.viewed'), 'views')
    assert.equal(adminActionCategory('revenue.access_denied'), 'security')
    assert.equal(adminActionCategory('revenue.export'), 'exports')
    assert.equal(adminActionCategory('admin.user.suspend'), 'users')
    assert.equal(adminActionCategory('admin.something.new'), 'other')
  })
  await check('history: result + target come from the audit row', () => {
    const entry = normalizeAdminAuditRow({ id: 'x', action: 'admin.user.suspend', actor_email: 'o@x', details: { targetEmail: 't@x', targetName: 'T', status: 'completed_with_warnings', reason: 'r' }, created_at: iso(DAY) })
    assert.equal(entry.result, 'warning')
    assert.equal(entry.target, 'T (t@x)')
    assert.match(String(entry.detail), /reason: r/)
    assert.equal(normalizeAdminAuditRow({ action: 'admin.access_denied', details: {} }).result, 'blocked')
    assert.equal(entry.actionLabel, 'User Suspended', 'history reads in the past tense')
    assert.equal(normalizeAdminAuditRow({ action: 'admin.user.created', details: {} }).actionLabel, 'User Created')
  })
}

// ---------------------------------------------------------------------------
// Live
// ---------------------------------------------------------------------------

async function live(mutate: boolean) {
  console.log('\nLive API vs. Supabase')
  const BASE = process.env.ADMIN_CHECK_BASE || 'http://localhost:3000'
  const URL_ = process.env.VITE_SUPABASE_URL || ''
  const SERVICE = process.env.SUPABASE_SERVICE_ROLE_KEY || ''
  const ANON = process.env.VITE_SUPABASE_ANON_KEY || ''
  if (!URL_ || !SERVICE || !ANON) throw new Error('Missing VITE_SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY / VITE_SUPABASE_ANON_KEY')
  const db = createClient(URL_, SERVICE, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data: link, error: linkError } = await db.auth.admin.generateLink({ type: 'magiclink', email: ADMIN_OWNER_EMAIL })
  if (linkError) throw linkError
  const ownerClient: SupabaseClient = createClient(URL_, ANON, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data: session, error: otpError } = await ownerClient.auth.verifyOtp({ token_hash: (link as any).properties.hashed_token, type: 'magiclink' })
  if (otpError || !session.session) throw otpError || new Error('no owner session')
  const token = session.session.access_token
  const call = async (method: string, path: string, body?: unknown) => {
    const response = await fetch(`${BASE}${path}`, { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
    const text = await response.text()
    let json: any = null
    try { json = JSON.parse(text) } catch { json = text }
    return { status: response.status, json, headers: response.headers }
  }

  try {
    const roles = await call('GET', '/api/v1/admin/roles?limit=100')
    const { data: roleRows } = await db.from('admin_roles').select('role_key,permissions')
    await check('roles: every catalogue row listed with its TRUE permission count', () => {
      assert.equal(roles.status, 200, JSON.stringify(roles.json))
      for (const row of roleRows || []) {
        const role = roles.json.data.roles.find((candidate: any) => candidate.key === row.role_key)
        assert.ok(role, `missing ${row.role_key}`)
        const expected = (row.permissions || []).includes('*') ? 'All permissions (*)' : `${(row.permissions || []).length} permission pattern${(row.permissions || []).length === 1 ? '' : 's'}`
        assert.equal(role.permissionSummary, expected, row.role_key)
      }
    })
    const users = await call('GET', '/api/v1/admin/users?limit=100')
    await check('roles: holders equal the Users directory, per role', () => {
      const byRole = new Map<string, number>()
      for (const user of users.json.data.users) byRole.set(user.role, (byRole.get(user.role) || 0) + 1)
      for (const role of roles.json.data.roles) assert.equal(role.holders, byRole.get(role.key) || 0, role.key)
    })

    const tenants = await call('GET', '/api/v1/admin/tenants?limit=100')
    const { count: orgCount } = await db.from('organizations').select('id', { count: 'exact', head: true })
    await check('tenants: count equals organizations; members + unassigned = users', () => {
      assert.equal(tenants.status, 200)
      assert.equal(tenants.json.data.stats.total, orgCount)
      assert.equal(tenants.json.data.stats.unassignedUsers, users.json.data.stats.noTenant)
      assert.ok(tenants.json.data.integrity.find((c: any) => c.id === 'members-partition').ok)
    })

    const billing = await call('GET', '/api/v1/admin/billing?limit=100')
    const { data: subs } = await db.from('billing_subscriptions').select('id,provider,status,plan')
    await check('billing: every subscription listed; MRR only from provider-billed rows', () => {
      assert.equal(billing.status, 200)
      assert.equal(billing.json.data.stats.subscriptions, (subs || []).length)
      const billed = (subs || []).filter((row: any) => ['paypal', 'google_play', 'stripe', 'apple'].includes(String(row.provider)) && ['active', 'trial', 'pending_renewal'].includes(String(row.status)))
      if (!billed.length) assert.equal(billing.json.data.stats.mrrCents, 0)
      assert.ok(billing.json.data.integrity.every((c: any) => c.ok), JSON.stringify(billing.json.data.integrity))
    })
    const revenue = await call('GET', '/api/v1/revenue/snapshot')
    await check('billing: Admin MRR == Revenue Intelligence MRR', () => {
      assert.equal(revenue.status, 200, JSON.stringify(revenue.json).slice(0, 200))
      assert.equal(typeof revenue.json.data.kpis.mrrCents, 'number')
      assert.equal(billing.json.data.stats.mrrCents, revenue.json.data.kpis.mrrCents)
    })

    const security = await call('GET', '/api/v1/admin/security?window=30d')
    const { count: vulnOpen } = await db.from('vulnerabilities').select('id', { count: 'exact', head: true }).eq('status', 'open')
    await check('security: open vulnerabilities and admins equal the tables / directory', () => {
      assert.equal(security.status, 200)
      const open = security.json.data.summary.openVulnerabilities
      assert.equal(open.critical + open.high + open.warning + open.info, vulnOpen)
      assert.equal(security.json.data.summary.administrators, users.json.data.stats.administrators)
      const payload = JSON.stringify(security.json.data)
      assert.ok(!/Brute Force Login|Malicious IP|Exfiltration|SOC 2 Type II|PCI DSS|ISO 27001/.test(payload), 'fabricated threat/compliance text present')
    })

    const governance = await call('GET', '/api/v1/admin/governance')
    const { count: policyCount } = await db.from('admin_governance_policies').select('id', { count: 'exact', head: true })
    await check('governance: every policy has a verification state from evidence', () => {
      assert.equal(governance.status, 200)
      assert.equal(governance.json.data.stats.policies, policyCount)
      const mfa = governance.json.data.policies.find((p: any) => p.key === 'privileged-mfa-required')
      if (mfa && users.json.data.stats.mfa.enrolled === 0) assert.equal(mfa.verification.state, 'not_met')
    })

    const history = await call('GET', '/api/v1/admin/history?limit=100')
    await check('history: only audit rows (no "Subscription active"/"Role active" state rows)', () => {
      assert.equal(history.status, 200)
      assert.ok(history.json.data.entries.every((entry: any) => entry.source === 'admin' && entry.action))
      assert.ok(history.json.data.entries.every((entry: any) => entry.category !== 'views'), 'views hidden by default')
    })
    const views = await call('GET', '/api/v1/admin/history?category=views&limit=5')
    await check('history: views category returns only console views', () => {
      assert.ok(views.json.data.entries.length > 0)
      assert.ok(views.json.data.entries.every((entry: any) => entry.category === 'views'))
    })
    const csv = await fetch(`${BASE}/api/v1/admin/history/export?category=users`, { headers: { Authorization: `Bearer ${token}` } })
    const bytes = Buffer.from(await csv.arrayBuffer())
    await check('history: CSV export with BOM', () => {
      assert.equal(csv.status, 200)
      assert.deepEqual([...bytes.subarray(0, 3)], [0xef, 0xbb, 0xbf])
      assert.ok(bytes.subarray(3).toString('utf8').startsWith('When (UTC),'))
    })

    if (!mutate) return
    console.log('\nLive actions (disposable records)')
    const stamp = Date.now()

    // --- Roles
    const created = await call('POST', '/api/v1/admin/roles', { name: `E2E Role ${stamp}`, permissions: ['reports.read', 'audit.*'] })
    const roleId = created.json?.data?.id
    const dupe = await call('POST', '/api/v1/admin/roles', { name: `E2E Role ${stamp}` })
    const reserved = await call('POST', '/api/v1/admin/roles', { name: 'Super Admin' })
    const badPerm = await call('POST', '/api/v1/admin/roles', { name: `E2E Bad ${stamp}`, permissions: ['nope!'] })
    await check('roles: create; duplicate 409; reserved key 409; invalid pattern 400', () => {
      assert.equal(created.status, 201, JSON.stringify(created.json))
      assert.equal(dupe.status, 409)
      assert.equal(reserved.status, 409)
      assert.equal(badPerm.status, 400)
    })
    if (roleId) {
      const edited = await call('PATCH', `/api/v1/admin/roles/${roleId}`, { name: `E2E Role ${stamp}`, permissions: ['reports.read'] })
      const noop = await call('PATCH', `/api/v1/admin/roles/${roleId}`, { name: `E2E Role ${stamp}`, permissions: ['reports.read'] })
      const { data: stored } = await db.from('admin_roles').select('permission_count,permissions').eq('id', roleId).single()
      const deactivated = await call('POST', `/api/v1/admin/roles/${roleId}/actions`, { action: 'deactivate' })
      const noConfirm = await call('POST', `/api/v1/admin/roles/${roleId}/actions`, { action: 'delete' })
      const deleted = await call('POST', `/api/v1/admin/roles/${roleId}/actions`, { action: 'delete', confirmKey: created.json.data.key })
      const systemEdit = await call('PATCH', `/api/v1/admin/roles/${(roles.json.data.roles.find((r: any) => r.key === 'security_admin') || {}).id || '00000000-0000-4000-8000-000000000000'}`, { name: 'x' })
      await check('roles: edit writes the true count; deactivate; typed-key delete; system role protected', () => {
        assert.equal(edited.status, 200)
        assert.deepEqual(Object.keys(edited.json.data.changes), ['permissions'], 'unchanged name must not be audited as a change')
        assert.equal(noop.status, 400)
        assert.equal(stored?.permission_count, 1)
        assert.equal(deactivated.status, 200)
        assert.equal(noConfirm.status, 400)
        assert.equal(deleted.status, 200, JSON.stringify(deleted.json))
        assert.ok([400, 404].includes(systemEdit.status))
      })
    }

    // --- Tenants + quota enforcement + member suspension
    const email = `qguard-console-e2e-${stamp}@example.com`
    const password = `E2e!${Math.random().toString(36).slice(2)}${stamp}`
    const tenant = await call('POST', '/api/v1/admin/tenants', { name: `E2E Tenant ${stamp}`, quotaUsers: 1, domain: 'e2e.example.com' })
    const tenantId = tenant.json?.data?.id
    let overUserId: string | null = null
    const user = tenantId ? await call('POST', '/api/v1/admin/users', { email, password, role: 'user', plan: 'starter', tenantId }) : { status: 0, json: null }
    const userId = user.json?.data?.userId
    try {
      await check('tenants: create; user created into it', () => {
        assert.equal(tenant.status, 201, JSON.stringify(tenant.json))
        assert.equal(user.status, 201, JSON.stringify(user.json))
      })
      const over = await call('POST', '/api/v1/admin/users', { email: `over-${email}`, password, role: 'user', plan: 'none', tenantId })
      if (over.json?.data?.userId) overUserId = over.json.data.userId
      const lower = await call('PATCH', `/api/v1/admin/tenants/${tenantId}`, { quotaUsers: 0 })
      const cleared = await call('PATCH', `/api/v1/admin/tenants/${tenantId}`, { quotaStorageGb: null })
      const noop = await call('PATCH', `/api/v1/admin/tenants/${tenantId}`, { name: `E2E Tenant ${stamp}`, quotaUsers: '1', domain: 'e2e.example.com' })
      const { data: stored } = await db.from('organizations').select('quota_storage_gb').eq('id', tenantId).single()
      await check('tenants: user quota ENFORCED (409); cannot clear/zero a quota; unchanged edit is a no-op', () => {
        assert.equal(over.status, 409, JSON.stringify(over.json))
        assert.equal(lower.status, 400)
        assert.equal(cleared.status, 400)
        assert.equal(cleared.json.error.code, 'QUOTA_REQUIRED')
        assert.equal(noop.status, 400, JSON.stringify(noop.json))
        assert.equal(noop.json.error.code, 'NO_CHANGES')
        assert.ok(Number(stored?.quota_storage_gb) > 0, 'unset storage quota took the schema default')
      })
      const suspend = await call('POST', `/api/v1/admin/tenants/${tenantId}/actions`, { action: 'suspend', applyToMembers: true, reason: 'e2e' })
      const { data: bannedAuth } = await db.auth.admin.getUserById(userId)
      const signIn = await createClient(URL_, ANON, { auth: { persistSession: false } }).auth.signInWithPassword({ email, password })
      await check('tenants: suspend with members blocks the member account for real', () => {
        assert.equal(suspend.status, 200, JSON.stringify(suspend.json))
        assert.equal(suspend.json.data.membersAffected, 1)
        assert.ok(bannedAuth.user?.banned_until && Date.parse(bannedAuth.user.banned_until) > Date.now())
        assert.ok(signIn.error, 'suspended member must not sign in')
      })
      const restore = await call('POST', `/api/v1/admin/tenants/${tenantId}/actions`, { action: 'restore', applyToMembers: true })
      await new Promise((resolve) => setTimeout(resolve, 1100))
      const signInAgain = await createClient(URL_, ANON, { auth: { persistSession: false } }).auth.signInWithPassword({ email, password })
      await check('tenants: restore brings back exactly the members it suspended', () => {
        assert.equal(restore.status, 200)
        assert.equal(restore.json.data.membersAffected, 1)
        assert.ok(!signInAgain.error, signInAgain.error?.message)
      })
      const deleteWithMembers = await call('POST', `/api/v1/admin/tenants/${tenantId}/actions`, { action: 'delete', confirmName: `E2E Tenant ${stamp}` })
      await check('tenants: delete refused while members remain', () => assert.equal(deleteWithMembers.status, 409))

      // --- Billing on the disposable user's manual Starter subscription
      const b1 = await call('GET', `/api/v1/admin/billing?search=${encodeURIComponent(email)}`)
      const row = b1.json.data.subscriptions[0]
      const notify = await call('POST', `/api/v1/admin/subscriptions/${row.id}/actions`, { action: 'notify' })
      const { count: notes } = await db.from('billing_notifications').select('id', { count: 'exact', head: true }).eq('user_id', userId).eq('title', 'Subscription reminder')
      const extend = await call('POST', `/api/v1/admin/subscriptions/${row.id}/actions`, { action: 'extend', days: 10 })
      const upgrade = await call('POST', `/api/v1/admin/subscriptions/${row.id}/actions`, { action: 'upgrade', plan: 'Elite' })
      const cancel = await call('POST', `/api/v1/admin/subscriptions/${row.id}/actions`, { action: 'cancel' })
      const noConfirmDelete = await call('POST', `/api/v1/admin/subscriptions/${row.id}/actions`, { action: 'delete' })
      const deleteSub = await call('POST', `/api/v1/admin/subscriptions/${row.id}/actions`, { action: 'delete', confirmEmail: email })
      await check('billing: manual row, not MRR; notify DELIVERS; extend; old upgrade path refused; cancel; typed delete', () => {
        assert.equal(row.revenueClass, 'manual')
        assert.equal(row.mrrCents, 0)
        assert.equal(notify.status, 200, JSON.stringify(notify.json))
        assert.equal(notes, 1)
        assert.equal(extend.status, 200, JSON.stringify(extend.json))
        assert.equal(upgrade.status, 400)
        assert.equal(cancel.status, 200, JSON.stringify(cancel.json))
        assert.equal(noConfirmDelete.status, 400)
        assert.equal(deleteSub.status, 200, JSON.stringify(deleteSub.json))
      })
    } finally {
      if (userId) await call('DELETE', `/api/v1/admin/users/${userId}`, { confirmEmail: email })
      if (overUserId) await call('DELETE', `/api/v1/admin/users/${overUserId}`, { confirmEmail: `over-${email}` })
      if (tenantId) {
        const tenantDelete = await call('POST', `/api/v1/admin/tenants/${tenantId}/actions`, { action: 'delete', confirmName: `E2E Tenant ${stamp}` })
        await check('tenants: typed-name delete once empty', () => assert.equal(tenantDelete.status, 200, JSON.stringify(tenantDelete.json)))
      }
    }

    // --- Governance
    const policy = await call('POST', '/api/v1/admin/governance/policies', { name: `E2E Policy ${stamp}`, category: 'data', enforcementLevel: 'advisory' })
    const policyId = policy.json?.data?.id
    const badLevel = await call('POST', '/api/v1/admin/governance/policies', { name: `E2E Bad ${stamp}`, enforcementLevel: 'always' })
    const disable = policyId ? await call('PATCH', `/api/v1/admin/governance/policies/${policyId}`, { status: 'disabled' }) : null
    const builtin = (governance.json.data.policies.find((p: any) => p.builtin) || {}).id
    const builtinDelete = builtin ? await call('DELETE', `/api/v1/admin/governance/policies/${builtin}`, { confirmKey: 'x' }) : null
    const policyDelete = policyId ? await call('DELETE', `/api/v1/admin/governance/policies/${policyId}`, { confirmKey: policy.json.data.key }) : null
    await check('governance: create (attested); invalid level 400; disable; built-in protected; typed delete', () => {
      assert.equal(policy.status, 201, JSON.stringify(policy.json))
      assert.equal(badLevel.status, 400)
      assert.equal(disable?.status, 200)
      if (builtinDelete) assert.equal(builtinDelete.status, 400)
      assert.equal(policyDelete?.status, 200)
    })
    const evidence = await call('POST', '/api/v1/admin/governance/evidence', { title: `E2E evidence ${stamp}` })
    const evidenceId = evidence.json?.data?.id
    try {
      const pkg = evidenceId ? await call('GET', `/api/v1/admin/governance/evidence/${evidenceId}`) : null
      await check('governance: evidence generated server-side; SHA3-256 recomputes and matches', async () => {
        assert.equal(evidence.status, 201, JSON.stringify(evidence.json))
        assert.equal(pkg?.status, 200)
        assert.equal(pkg!.json.verification.intact, true)
        assert.equal(pkg!.json.hash.value, createHash('sha3-256').update(canonicalJson(pkg!.json.snapshot)).digest('hex'))
        const fresh = await call('GET', '/api/v1/admin/users?limit=1')
        assert.equal(pkg!.json.snapshot.users.stats.totalUsers, fresh.json.data.stats.totalUsers)
      })
    } finally {
      if (evidenceId) await db.from('admin_compliance_evidence').delete().eq('id', evidenceId)
    }

    const audit = await call('GET', `/api/v1/admin/history?search=${encodeURIComponent('role')}&category=roles&limit=50`)
    await check('history: the role actions just performed are in the trail', () => {
      const actions = new Set(audit.json.data.entries.map((entry: any) => entry.action))
      for (const action of ['admin.role.created', 'admin.role.updated', 'admin.role.deactivate', 'admin.role.deleted']) assert.ok(actions.has(action), `missing ${action}`)
    })
  } finally {
    await ownerClient.auth.signOut({ scope: 'local' }).catch(() => undefined)
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
