import { Router, Request, Response, NextFunction } from 'express'
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import type { SupabaseClient, User } from '@supabase/supabase-js'
import { createAuthClient, getServerUser, getServiceClient } from '@/lib/supabase-server'
import { createSubscription, reviseSubscription, cancelSubscription, resolveOrigin, isPaypalConfigured } from './paypal'

type AuthedRequest = Request & {
  user?: User
  token?: string
  authClient?: SupabaseClient
}

type PlanName = 'Starter' | 'Basic' | 'Pro' | 'Elite'
type BillingCycle = 'monthly' | 'annual'
type SubscriptionAction =
  | 'upgrade'
  | 'downgrade'
  | 'renew'
  | 'cancel'
  | 'reactivate'
  | 'switch-cycle'
  | 'enable-auto-renew'
  | 'disable-auto-renew'

const router = Router()

const PLAN_CATALOG: Record<PlanName, {
  name: PlanName
  monthlyCents: number
  annualCents: number
  teamMembers: number
  storageBytes: number
  scanQuota: number
  deepScanQuota: number
  apiQuota: number
  webhookQuota: number
  vaultCapacityBytes: number
  qrngQuota: number
  activeJobs: number
  retentionDays: number
  features: string[]
  advancedModules: string[]
}> = {
  Starter: {
    name: 'Starter',
    monthlyCents: 300,
    annualCents: 3600,
    teamMembers: 3,
    storageBytes: 5 * 1024 * 1024 * 1024,
    scanQuota: 25,
    deepScanQuota: 2,
    apiQuota: 5000,
    webhookQuota: 0,
    vaultCapacityBytes: 5 * 1024 * 1024 * 1024,
    qrngQuota: 0,
    activeJobs: 1,
    retentionDays: 30,
    features: ['Desktop Quantum Vault and Quantum Messaging access', 'End-to-end encrypted chat, voice and video calls', 'On-device, zero-knowledge file and folder encryption'],
    advancedModules: ['Quantum Vault (strictly on-device)', 'Quantum Messaging (E2E, multi-device trust)', 'ML-KEM-1024 and ML-DSA post-quantum protection'],
  },
  Basic: {
    name: 'Basic',
    monthlyCents: 800,
    annualCents: 6000,
    teamMembers: 5,
    storageBytes: 10 * 1024 * 1024 * 1024,
    scanQuota: 25,
    deepScanQuota: 5,
    apiQuota: 15000,
    webhookQuota: 0,
    vaultCapacityBytes: 10 * 1024 * 1024 * 1024,
    qrngQuota: 0,
    activeJobs: 2,
    retentionDays: 60,
    features: ['Quantum Readiness & Assessment Engine', 'Risk Analysis and Migration Planner', 'AI Migration Advisor and AI Executive Advisor'],
    advancedModules: ['Quantum Readiness & Assessment Engine', 'Risk Analysis and Migration Planner', 'Enterprise-grade readiness and assessment reports'],
  },
  Pro: {
    name: 'Pro',
    monthlyCents: 3000,
    annualCents: 24000,
    teamMembers: 15,
    storageBytes: 100 * 1024 * 1024 * 1024,
    scanQuota: 500,
    deepScanQuota: 50,
    apiQuota: 100000,
    webhookQuota: 5000,
    vaultCapacityBytes: 100 * 1024 * 1024 * 1024,
    qrngQuota: 50000,
    activeJobs: 10,
    retentionDays: 180,
    features: ['Everything in Starter', 'Runtime crypto telemetry and migration planning', 'NIST PQC and CNSA 2.0 evidence reports'],
    advancedModules: ['Quantum QRNG and key generation', 'OTP, PKI, tokenization, and API encryption monitoring', 'Migration Planner and Hybrid Crypto Lab'],
  },
  Elite: {
    name: 'Elite',
    monthlyCents: 19900,
    annualCents: 180000,
    teamMembers: 250,
    storageBytes: 1024 * 1024 * 1024 * 1024,
    scanQuota: 5000,
    deepScanQuota: 750,
    apiQuota: 2500000,
    webhookQuota: 100000,
    vaultCapacityBytes: 1024 * 1024 * 1024 * 1024,
    qrngQuota: 2500000,
    activeJobs: 250,
    retentionDays: 730,
    features: ['Everything in Pro', 'Enterprise QKMS governance and migration operations', 'Custom compliance mapping and audit evidence'],
    advancedModules: ['Full QKMS overview, inventory, governance, and readiness', 'PQC orchestration, live migration ops, rollback, and sandboxing', 'HNDL defense workflows and multi-cloud telemetry grid'],
  },
}

function jsonError(res: Response, status: number, code: string, message: string) {
  return res.status(status).json({ error: { code, message } })
}

function extractToken(req: Request): string | null {
  const authHeader = req.headers.authorization
  if (authHeader?.startsWith('Bearer ')) return authHeader.slice(7)
  const queryToken = req.query.token
  return typeof queryToken === 'string' && queryToken ? queryToken : null
}

function getClientIp(req: Request): string | null {
  const forwarded = req.headers['x-forwarded-for']
  const raw = Array.isArray(forwarded) ? forwarded[0] : forwarded
  const candidate = raw?.split(',')[0]?.trim() || req.ip || req.socket.remoteAddress || null
  return candidate?.replace('::ffff:', '') || null
}

function getUserAgent(req: Request): string {
  return String(req.headers['user-agent'] || 'Unknown device').slice(0, 500)
}

async function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const token = extractToken(req)
  if (!token) return jsonError(res, 401, 'UNAUTHORIZED', 'Authentication required')

  const client = createAuthClient(token)
  if (!client) return jsonError(res, 500, 'CONFIG_ERROR', 'Supabase is not configured')

  const user = await getServerUser(token)
  if (!user) return jsonError(res, 401, 'UNAUTHORIZED', 'Invalid or expired token')

  req.user = user
  req.token = token
  req.authClient = client
  return next()
}

function isMissingTable(error: any) {
  const code = String(error?.code || '')
  const message = String(error?.message || '')
  return code === '42P01' || code === 'PGRST205' || message.includes('Could not find the table') || message.includes('does not exist')
}

function toNumber(value: unknown, fallback = 0) {
  const numberValue = Number(value)
  return Number.isFinite(numberValue) ? numberValue : fallback
}

function toIso(value: unknown): string | null {
  if (!value) return null
  const date = new Date(String(value))
  return Number.isNaN(date.getTime()) ? null : date.toISOString()
}

function normalizePlan(value: unknown): PlanName {
  const text = String(value || '').toLowerCase()
  if (text.includes('elite') || text.includes('enterprise')) return 'Elite'
  if (text.includes('pro') || text.includes('professional')) return 'Pro'
  if (text.includes('basic')) return 'Basic'
  return 'Starter'
}

function normalizeCycle(value: unknown): BillingCycle {
  return String(value || '').toLowerCase().includes('annual') ? 'annual' : 'monthly'
}

function periodStart(subscription: any) {
  const current = toIso(subscription?.current_period_start)
  if (current) return current
  const now = new Date()
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)).toISOString()
}

function nextMonthlyRenewal() {
  const date = new Date()
  date.setUTCMonth(date.getUTCMonth() + 1)
  return date.toISOString()
}

function cents(value: unknown) {
  return Math.max(0, Math.round(toNumber(value, 0)))
}

function priceIdFor(plan: PlanName, cycle: BillingCycle) {
  if (plan === 'Starter') return null
  const key = `STRIPE_PRICE_${plan.toUpperCase()}_${cycle.toUpperCase()}`
  return process.env[key] || null
}

function providerStatus() {
  const stripeConfigured = Boolean(process.env.STRIPE_SECRET_KEY)
  return {
    stripeConfigured,
    checkoutConfigured: stripeConfigured && Boolean(
      process.env.STRIPE_PRICE_PRO_MONTHLY ||
      process.env.STRIPE_PRICE_PRO_ANNUAL ||
      process.env.STRIPE_PRICE_ELITE_MONTHLY ||
      process.env.STRIPE_PRICE_ELITE_ANNUAL,
    ),
    webhookConfigured: Boolean(process.env.STRIPE_WEBHOOK_SECRET),
    publishableKeyConfigured: Boolean(process.env.VITE_STRIPE_PUBLISHABLE_KEY || process.env.STRIPE_PUBLISHABLE_KEY),
  }
}

async function stripePost(path: string, params: Record<string, string>) {
  const secret = process.env.STRIPE_SECRET_KEY
  if (!secret) throw new Error('Stripe is not configured')

  const body = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) body.append(key, value)
  }

  const response = await fetch(`https://api.stripe.com/v1/${path}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${secret}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  })

  const json = await response.json().catch(() => ({}))
  if (!response.ok) {
    throw new Error(json?.error?.message || `Stripe request failed with HTTP ${response.status}`)
  }
  return json
}

function appUrl(req: Request) {
  const configured = process.env.APP_ORIGIN || process.env.VITE_APP_ORIGIN || process.env.PUBLIC_APP_ORIGIN
  if (configured) return configured.replace(/\/$/, '')
  const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http'
  const host = req.headers['x-forwarded-host'] || req.headers.host || 'localhost:3000'
  return `${protocol}://${host}`.replace(/\/$/, '')
}

async function createStripeCheckout(req: Request, user: User, subscription: any, plan: PlanName, cycle: BillingCycle) {
  const priceId = priceIdFor(plan, cycle)
  if (!priceId) throw new Error(`Stripe price is not configured for ${plan} ${cycle}`)

  const customerId = subscription?.provider_customer_id || subscription?.stripe_customer_id || ''
  const baseUrl = appUrl(req)
  const params: Record<string, string> = {
    mode: 'subscription',
    'payment_method_types[0]': 'card',
    'line_items[0][price]': priceId,
    'line_items[0][quantity]': '1',
    success_url: `${baseUrl}/dashboard/settings?tab=billing&billing=success`,
    cancel_url: `${baseUrl}/dashboard/settings?tab=billing&billing=cancelled`,
    client_reference_id: user.id,
    'metadata[userId]': user.id,
    'metadata[plan]': plan,
    'metadata[billingCycle]': cycle,
  }
  if (customerId) params.customer = customerId
  else if (user.email) params.customer_email = user.email

  return stripePost('checkout/sessions', params)
}

async function createStripeSetup(req: Request, user: User, subscription: any) {
  const customerId = subscription?.provider_customer_id || subscription?.stripe_customer_id || ''
  const baseUrl = appUrl(req)
  const params: Record<string, string> = {
    mode: 'setup',
    'payment_method_types[0]': 'card',
    success_url: `${baseUrl}/dashboard/settings?tab=billing&payment_method=success`,
    cancel_url: `${baseUrl}/dashboard/settings?tab=billing&payment_method=cancelled`,
    client_reference_id: user.id,
    'metadata[userId]': user.id,
    'metadata[purpose]': 'payment_method_setup',
  }
  if (customerId) params.customer = customerId
  else if (user.email) params.customer_email = user.email

  return stripePost('checkout/sessions', params)
}

async function safeRows(client: SupabaseClient, table: string, build: (query: any) => any) {
  try {
    const query = build(client.from(table))
    const { data, error } = await query
    if (error) {
      if (isMissingTable(error)) return { rows: [], available: false }
      console.warn(`[billing] ${table} query failed:`, error.message)
      return { rows: [], available: true }
    }
    return { rows: data || [], available: true }
  } catch (err) {
    console.warn(`[billing] ${table} query failed:`, err)
    return { rows: [], available: false }
  }
}

async function safeCount(client: SupabaseClient, table: string, build: (query: any) => any) {
  try {
    const query = build(client.from(table).select('id', { count: 'exact', head: true }))
    const { count, error } = await query
    if (error) {
      if (isMissingTable(error)) return { count: 0, available: false }
      console.warn(`[billing] ${table} count failed:`, error.message)
      return { count: 0, available: true }
    }
    return { count: count || 0, available: true }
  } catch (err) {
    console.warn(`[billing] ${table} count failed:`, err)
    return { count: 0, available: false }
  }
}

async function ensureSubscription(client: SupabaseClient, user: User) {
  const { data: profile } = await client
    .from('profiles')
    .select('id, email, tier, role, created_at, metadata')
    .eq('id', user.id)
    .maybeSingle()

  const plan = normalizePlan(profile?.tier)
  const accountCreatedAt = toIso(profile?.created_at || user.created_at) || new Date().toISOString()

  const { data, error } = await client
    .from('billing_subscriptions')
    .select('*')
    .eq('user_id', user.id)
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle()

  if (error && isMissingTable(error)) {
    const missing = new Error('Billing database schema is not installed')
    ;(missing as any).code = 'BILLING_SCHEMA_NOT_READY'
    throw missing
  }
  if (error) throw error
  if (data) return { subscription: data, profile }

  const now = new Date().toISOString()
  const subscriptionId = `qgsub_${randomBytes(10).toString('hex')}`
  const defaults = {
    user_id: user.id,
    subscription_id: subscriptionId,
    plan,
    status: 'active',
    billing_cycle: 'monthly',
    auto_renew: plan !== 'Starter',
    renewal_date: plan === 'Starter' ? null : nextMonthlyRenewal(),
    account_created_at: accountCreatedAt,
    provider: null,
    metadata: { source: 'qguard_account_bootstrap', profileTier: profile?.tier || null },
  }

  const result = await client
    .from('billing_subscriptions')
    .insert(defaults)
    .select('*')
    .single()

  if (result.error && isMissingTable(result.error)) {
    const missing = new Error('Billing database schema is not installed')
    ;(missing as any).code = 'BILLING_SCHEMA_NOT_READY'
    throw missing
  }
  if (result.error || !result.data) throw result.error || new Error('Failed to initialize billing subscription')
  return { subscription: result.data, profile }
}

async function ensureNotificationSettings(client: SupabaseClient, userId: string) {
  const { data, error } = await client
    .from('billing_notification_settings')
    .select('*')
    .eq('user_id', userId)
    .maybeSingle()

  if (error && isMissingTable(error)) throw error
  if (error) throw error
  if (data) return data

  const result = await client
    .from('billing_notification_settings')
    .insert({
      user_id: userId,
      email_notifications: true,
      in_app_alerts: true,
      webhook_notifications: false,
    })
    .select('*')
    .single()

  if (result.error || !result.data) throw result.error || new Error('Failed to initialize billing notifications')
  return result.data
}

function normalizeSubscription(row: any, user: User) {
  const plan = normalizePlan(row?.plan)
  const cycle = normalizeCycle(row?.billing_cycle)
  const catalog = PLAN_CATALOG[plan]
  return {
    id: row?.id || null,
    subscriptionId: row?.subscription_id || null,
    provider: row?.provider || null,
    providerCustomerId: row?.provider_customer_id || null,
    providerSubscriptionId: row?.provider_subscription_id || null,
    currentPlan: plan,
    status: row?.status || 'active',
    billingCycle: cycle,
    renewalDate: toIso(row?.renewal_date || row?.current_period_end),
    trialExpirationDate: toIso(row?.trial_expires_at),
    accountCreationDate: toIso(row?.account_created_at || user.created_at),
    autoRenew: Boolean(row?.auto_renew),
    cancelAtPeriodEnd: Boolean(row?.cancel_at_period_end),
    currentPeriodStart: toIso(row?.current_period_start),
    currentPeriodEnd: toIso(row?.current_period_end || row?.renewal_date),
    monthlyCents: catalog.monthlyCents,
    annualCents: catalog.annualCents,
    updatedAt: toIso(row?.updated_at),
  }
}

function normalizePaymentMethod(row: any) {
  return {
    id: row.id,
    provider: row.provider || 'tokenized',
    brand: row.brand || 'Card',
    last4: row.last4 || '',
    expMonth: row.exp_month || null,
    expYear: row.exp_year || null,
    isDefault: Boolean(row.is_default),
    billingName: row.billing_name || null,
    billingAddress: row.billing_address || {},
    country: row.country || null,
    taxRegion: row.tax_region || null,
    lastUsedAt: toIso(row.last_used_at),
    updatedAt: toIso(row.updated_at),
  }
}

function normalizeInvoice(row: any) {
  return {
    id: row.id,
    invoiceId: row.invoice_id || row.provider_invoice_id || row.id,
    transactionId: row.transaction_id || null,
    paymentDate: toIso(row.payment_date || row.paid_at || row.created_at),
    amountPaidCents: cents(row.amount_paid_cents),
    taxCents: cents(row.tax_cents),
    currency: row.currency || 'USD',
    paymentMethod: row.payment_method_summary || 'Tokenized payment method',
    subscriptionPlan: normalizePlan(row.subscription_plan || row.plan),
    status: row.status || 'pending',
    hostedInvoiceUrl: row.hosted_invoice_url || null,
    receiptUrl: row.receipt_url || null,
    createdAt: toIso(row.created_at),
  }
}

function normalizeNotificationSettings(row: any) {
  return {
    emailNotifications: row?.email_notifications ?? true,
    inAppAlerts: row?.in_app_alerts ?? true,
    webhookNotifications: row?.webhook_notifications ?? false,
    webhookUrl: row?.webhook_url || '',
    updatedAt: toIso(row?.updated_at),
  }
}

function normalizeEventNotification(row: any) {
  return {
    id: row.id,
    type: row.type || 'billing',
    severity: row.severity || 'info',
    title: row.title || 'Billing notification',
    message: row.message || '',
    readAt: toIso(row.read_at),
    createdAt: toIso(row.created_at),
  }
}

function usagePercent(used: number, limit: number) {
  if (!limit || limit < 0) return 0
  return Math.min(100, Math.round((used / limit) * 100))
}

function sumMetric(events: any[], metricKey: string) {
  return events
    .filter((event) => event.metric_key === metricKey)
    .reduce((total, event) => total + toNumber(event.quantity, 0), 0)
}

function byDay(events: any[]) {
  const map = new Map<string, Record<string, number | string>>()
  for (const event of events) {
    const day = String(event.created_at || '').slice(0, 10)
    if (!day) continue
    const existing = map.get(day) || { date: day }
    existing[event.metric_key] = toNumber(existing[event.metric_key], 0) + toNumber(event.quantity, 0)
    map.set(day, existing)
  }
  return Array.from(map.values()).sort((a, b) => String(a.date).localeCompare(String(b.date))).slice(-30)
}

async function buildUsage(client: SupabaseClient, userId: string, subscription: any) {
  const plan = normalizePlan(subscription?.plan)
  const limits = PLAN_CATALOG[plan]
  const start = periodStart(subscription)
  const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()

  const [
    usageEvents,
    scanSessions,
    deepScanSessions,
    activeJobs,
    vaultRows,
    vaultFileCount,
    generatedKeys,
    qrngKeys,
    activeSessions,
    runtimeEvents,
    runtime24h,
  ] = await Promise.all([
    safeRows(client, 'billing_usage_events', (q) => q.select('metric_key, quantity, source, created_at').eq('user_id', userId).gte('created_at', start).order('created_at', { ascending: true }).limit(10000)),
    safeCount(client, 'pqc_scan_sessions', (q) => q.eq('user_id', userId).gte('created_at', start)),
    safeRows(client, 'pqc_scan_sessions', (q) => q.select('id, metadata, target_scope, created_at').eq('user_id', userId).gte('created_at', start).limit(1000)),
    safeCount(client, 'scanner_agents', (q) => q.eq('user_id', userId).eq('status', 'active')),
    safeRows(client, 'vault_files', (q) => q.select('id, original_size, encrypted_size, size, file_size, metadata, uploaded_at, created_at').eq('user_id', userId).or('is_deleted.is.null,is_deleted.eq.false').limit(5000)),
    safeCount(client, 'vault_files', (q) => q.eq('user_id', userId).or('is_deleted.is.null,is_deleted.eq.false')),
    safeCount(client, 'generated_keys', (q) => q.eq('user_id', userId).gte('created_at', start)),
    safeCount(client, 'generated_keys', (q) => q.eq('user_id', userId).gte('created_at', start).ilike('entropy_source', '%QRNG%')),
    safeCount(client, 'user_sessions', (q) => q.eq('user_id', userId).is('revoked_at', null)),
    safeCount(client, 'runtime_crypto_events', (q) => q.eq('user_id', userId)),
    safeCount(client, 'runtime_crypto_events', (q) => q.eq('user_id', userId).gte('observed_at', since24h)),
  ])

  const usageRows = usageEvents.rows
  const deepScansUsed = deepScanSessions.rows.filter((row: any) => {
    const text = JSON.stringify(row.metadata || {}).toLowerCase() + ' ' + String(row.target_scope || '').toLowerCase()
    return text.includes('deep')
  }).length + sumMetric(usageRows, 'deep_scans')
  const vaultStorageUsed = vaultRows.rows.reduce((total: number, row: any) => {
    const metadataSize = toNumber(row.metadata?.size || row.metadata?.bytes || row.metadata?.originalSize, 0)
    return total + toNumber(row.encrypted_size ?? row.original_size ?? row.size ?? row.file_size, metadataSize)
  }, 0)

  const metrics = [
    {
      key: 'api_requests',
      label: 'API Requests Used',
      group: 'API Usage',
      used: sumMetric(usageRows, 'api_requests'),
      limit: limits.apiQuota,
      remaining: Math.max(0, limits.apiQuota - sumMetric(usageRows, 'api_requests')),
      status: 'metered',
    },
    {
      key: 'webhooks',
      label: 'Webhook Usage',
      group: 'API Usage',
      used: sumMetric(usageRows, 'webhook_deliveries'),
      limit: limits.webhookQuota,
      remaining: Math.max(0, limits.webhookQuota - sumMetric(usageRows, 'webhook_deliveries')),
      status: 'metered',
    },
    {
      key: 'scans',
      label: 'Quantum Vulnerability Scans',
      group: 'Scanner Usage',
      used: scanSessions.count + sumMetric(usageRows, 'scanner_runs'),
      limit: limits.scanQuota,
      remaining: Math.max(0, limits.scanQuota - scanSessions.count - sumMetric(usageRows, 'scanner_runs')),
      status: scanSessions.available ? 'live' : 'schema-not-installed',
    },
    {
      key: 'deep_scans',
      label: 'Deep Scan Usage',
      group: 'Scanner Usage',
      used: deepScansUsed,
      limit: limits.deepScanQuota,
      remaining: Math.max(0, limits.deepScanQuota - deepScansUsed),
      status: deepScanSessions.available ? 'live' : 'schema-not-installed',
    },
    {
      key: 'active_jobs',
      label: 'Active Monitoring Jobs',
      group: 'Scanner Usage',
      used: activeJobs.count,
      limit: limits.activeJobs,
      remaining: Math.max(0, limits.activeJobs - activeJobs.count),
      status: activeJobs.available ? 'live' : 'schema-not-installed',
    },
    {
      key: 'vault_storage',
      label: 'Quantum Vault Storage',
      group: 'Storage Usage',
      used: vaultStorageUsed,
      limit: limits.vaultCapacityBytes,
      remaining: Math.max(0, limits.vaultCapacityBytes - vaultStorageUsed),
      status: vaultRows.available ? 'live' : 'schema-not-installed',
      unit: 'bytes',
    },
    {
      key: 'encrypted_files',
      label: 'Encrypted Files Count',
      group: 'Storage Usage',
      used: vaultFileCount.count,
      limit: 0,
      remaining: 0,
      status: vaultFileCount.available ? 'live' : 'schema-not-installed',
    },
    {
      key: 'retention',
      label: 'Retention Consumption',
      group: 'Storage Usage',
      used: limits.retentionDays,
      limit: limits.retentionDays,
      remaining: 0,
      status: 'policy',
      unit: 'days',
    },
    {
      key: 'generated_keys',
      label: 'Generated Keys Count',
      group: 'QRNG Usage',
      used: generatedKeys.count,
      limit: limits.qrngQuota,
      remaining: Math.max(0, limits.qrngQuota - generatedKeys.count),
      status: generatedKeys.available ? 'live' : 'schema-not-installed',
    },
    {
      key: 'entropy_requests',
      label: 'Entropy Requests',
      group: 'QRNG Usage',
      used: sumMetric(usageRows, 'entropy_requests') + qrngKeys.count,
      limit: limits.qrngQuota,
      remaining: Math.max(0, limits.qrngQuota - sumMetric(usageRows, 'entropy_requests') - qrngKeys.count),
      status: generatedKeys.available ? 'live' : 'schema-not-installed',
    },
    {
      key: 'active_sessions',
      label: 'Active Sessions',
      group: 'QRNG Usage',
      used: activeSessions.count,
      limit: limits.teamMembers,
      remaining: Math.max(0, limits.teamMembers - activeSessions.count),
      status: activeSessions.available ? 'live' : 'schema-not-installed',
    },
  ]

  return {
    plan,
    periodStart: start,
    periodEnd: toIso(subscription?.current_period_end || subscription?.renewal_date),
    rateLimitStatus: metrics.find((metric) => metric.key === 'api_requests')?.used >= limits.apiQuota ? 'limit-reached' : 'within-limit',
    telemetry: {
      usageEvents: usageRows.length,
      runtimeEvents: runtimeEvents.count,
      runtimeEvents24h: runtime24h.count,
      lastSyncAt: new Date().toISOString(),
      tableAvailability: {
        billingUsageEvents: usageEvents.available,
        scans: scanSessions.available,
        vaultFiles: vaultRows.available,
        generatedKeys: generatedKeys.available,
        runtimeCryptoEvents: runtimeEvents.available,
      },
    },
    metrics: metrics.map((metric) => ({ ...metric, percent: usagePercent(metric.used, metric.limit) })),
    trends: byDay(usageRows),
  }
}

function derivedAlerts(subscription: any, usage: any) {
  const alerts: any[] = []
  const renewalDate = toIso(subscription?.renewal_date || subscription?.current_period_end)
  const trialDate = toIso(subscription?.trial_expires_at)
  const now = Date.now()

  if (renewalDate) {
    const days = Math.ceil((new Date(renewalDate).getTime() - now) / (24 * 60 * 60 * 1000))
    if (days >= 0 && days <= 14) {
      alerts.push({
        id: 'derived-renewal',
        type: 'upcoming-renewal',
        severity: days <= 3 ? 'warning' : 'info',
        title: 'Upcoming renewal',
        message: `Current subscription renews in ${days} day${days === 1 ? '' : 's'}.`,
        createdAt: new Date().toISOString(),
      })
    }
  }

  if (trialDate) {
    const days = Math.ceil((new Date(trialDate).getTime() - now) / (24 * 60 * 60 * 1000))
    if (days >= 0 && days <= 7) {
      alerts.push({
        id: 'derived-trial',
        type: 'trial-ending',
        severity: 'warning',
        title: 'Trial ending soon',
        message: `Trial access expires in ${days} day${days === 1 ? '' : 's'}.`,
        createdAt: new Date().toISOString(),
      })
    }
  }

  for (const metric of usage.metrics || []) {
    if (metric.limit > 0 && metric.percent >= 85) {
      alerts.push({
        id: `derived-usage-${metric.key}`,
        type: 'usage-limit',
        severity: metric.percent >= 100 ? 'critical' : 'warning',
        title: `${metric.label} usage warning`,
        message: `${metric.percent}% of the ${metric.label.toLowerCase()} quota has been consumed.`,
        createdAt: new Date().toISOString(),
      })
    }
  }

  if (subscription?.status === 'cancelled' || subscription?.status === 'expired') {
    alerts.push({
      id: 'derived-subscription-state',
      type: 'subscription-expiration',
      severity: 'critical',
      title: 'Subscription requires attention',
      message: `Subscription status is ${subscription.status}. Reactivate or renew to keep paid modules available.`,
      createdAt: new Date().toISOString(),
    })
  }

  return alerts
}

async function recordBillingAudit(
  client: SupabaseClient,
  userId: string,
  req: Request,
  action: string,
  message: string,
  metadata: Record<string, unknown> = {},
) {
  const payload = {
    user_id: userId,
    action,
    message,
    ip_address: getClientIp(req),
    user_agent: getUserAgent(req),
    metadata,
  }
  try {
    await client.from('billing_audit_events').insert(payload)
  } catch {
    // Audit logging must not block billing operations.
  }
  try {
    await client.from('user_security_events').insert({
      user_id: userId,
      event_type: `billing.${action}`,
      severity: 'info',
      message,
      ip_address: payload.ip_address,
      user_agent: payload.user_agent,
      metadata,
    })
  } catch {
    // Security event mirroring is best-effort.
  }
}

async function fetchBillingBundle(client: SupabaseClient, user: User) {
  const { subscription, profile } = await ensureSubscription(client, user)
  const [settings, paymentMethods, invoices, notifications, usage] = await Promise.all([
    ensureNotificationSettings(client, user.id),
    safeRows(client, 'billing_payment_methods', (q) => q.select('*').eq('user_id', user.id).is('removed_at', null).order('is_default', { ascending: false }).order('updated_at', { ascending: false }).limit(20)),
    safeRows(client, 'billing_invoices', (q) => q.select('*').eq('user_id', user.id).order('created_at', { ascending: false }).limit(100)),
    safeRows(client, 'billing_notifications', (q) => q.select('*').eq('user_id', user.id).order('created_at', { ascending: false }).limit(30)),
    buildUsage(client, user.id, subscription),
  ])

  const normalizedSubscription = normalizeSubscription(subscription, user)

  return {
    subscription: normalizedSubscription,
    planCatalog: Object.values(PLAN_CATALOG),
    profile: {
      role: profile?.role || user.user_metadata?.role || user.app_metadata?.role || '',
      email: profile?.email || user.email || '',
    },
    paymentMethods: paymentMethods.rows.map(normalizePaymentMethod),
    invoices: invoices.rows.map(normalizeInvoice),
    notificationSettings: normalizeNotificationSettings(settings),
    notifications: [
      ...derivedAlerts(subscription, usage),
      ...notifications.rows.map(normalizeEventNotification),
    ].slice(0, 30),
    usage,
    providerStatus: providerStatus(),
    permissions: {
      canManageBilling: canManageBilling(user, profile),
      canViewInvoices: true,
    },
    telemetry: {
      live: true,
      lastSyncAt: new Date().toISOString(),
      source: 'supabase-authenticated-billing-api',
    },
  }
}

function canManageBilling(user: User, profile: any) {
  const roleText = [
    user.app_metadata?.role,
    user.user_metadata?.role,
    profile?.role,
  ].filter(Boolean).join(' ').toLowerCase()
  return !/(viewer|read[-_\s]?only|auditor)/.test(roleText)
}

function cleanWebhookUrl(value: unknown) {
  if (value === null || value === undefined || value === '') return null
  if (typeof value !== 'string' || value.length > 500) return undefined
  try {
    const url = new URL(value)
    if (!['https:', 'http:'].includes(url.protocol)) return undefined
    return url.toString()
  } catch {
    return undefined
  }
}

function escapePdf(value: unknown) {
  return String(value ?? '').replace(/[\\()]/g, '\\$&').replace(/\r?\n/g, ' ')
}

function buildInvoicePdf(invoice: any, kind: 'invoice' | 'receipt') {
  const lines = [
    `QGuard Helix ${kind === 'invoice' ? 'Invoice' : 'Receipt'}`,
    `Invoice ID: ${invoice.invoice_id || invoice.provider_invoice_id || invoice.id}`,
    `Transaction ID: ${invoice.transaction_id || 'Not recorded'}`,
    `Status: ${invoice.status || 'pending'}`,
    `Plan: ${normalizePlan(invoice.subscription_plan || invoice.plan)}`,
    `Payment Date: ${toIso(invoice.payment_date || invoice.paid_at || invoice.created_at) || 'Not recorded'}`,
    `Amount Paid: ${((cents(invoice.amount_paid_cents) + cents(invoice.tax_cents)) / 100).toFixed(2)} ${(invoice.currency || 'USD').toUpperCase()}`,
    `Tax: ${(cents(invoice.tax_cents) / 100).toFixed(2)} ${(invoice.currency || 'USD').toUpperCase()}`,
    `Payment Method: ${invoice.payment_method_summary || 'Tokenized payment method'}`,
    '',
    'Generated from authenticated tenant billing records. Full card numbers are never stored or displayed by QGuard Helix.',
  ]
  const text = lines.map((line, index) => `BT /F1 11 Tf 54 ${742 - index * 22} Td (${escapePdf(line)}) Tj ET`).join('\n')
  const stream = `${text}\n`
  const objects = [
    '1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj',
    '2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj',
    '3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj',
    '4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj',
    `5 0 obj << /Length ${Buffer.byteLength(stream)} >> stream\n${stream}endstream endobj`,
  ]
  let pdf = '%PDF-1.4\n'
  const offsets = [0]
  for (const object of objects) {
    offsets.push(Buffer.byteLength(pdf))
    pdf += `${object}\n`
  }
  const xrefOffset = Buffer.byteLength(pdf)
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`
  for (let index = 1; index <= objects.length; index += 1) {
    pdf += `${String(offsets[index]).padStart(10, '0')} 00000 n \n`
  }
  pdf += `trailer << /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`
  return Buffer.from(pdf)
}

async function fetchOwnedInvoice(client: SupabaseClient, userId: string, invoiceId: string) {
  const attempts = [
    { column: 'invoice_id', value: invoiceId },
    { column: 'provider_invoice_id', value: invoiceId },
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(invoiceId)
      ? { column: 'id', value: invoiceId }
      : null,
  ].filter(Boolean) as { column: string; value: string }[]

  for (const attempt of attempts) {
    const { data, error } = await client
      .from('billing_invoices')
      .select('*')
      .eq('user_id', userId)
      .eq(attempt.column, attempt.value)
      .limit(1)
      .maybeSingle()
    if (error && isMissingTable(error)) {
      const missing = new Error('Billing invoice schema is not installed')
      ;(missing as any).code = 'BILLING_SCHEMA_NOT_READY'
      throw missing
    }
    if (error) throw error
    if (data) return data
  }

  return null
}

function verifyStripeSignature(req: Request) {
  const secret = process.env.STRIPE_WEBHOOK_SECRET
  if (!secret) return false
  const header = req.headers['stripe-signature']
  if (typeof header !== 'string') return false
  const parts = Object.fromEntries(header.split(',').map((item) => {
    const [key, value] = item.split('=')
    return [key, value]
  }))
  const timestamp = parts.t
  const signature = parts.v1
  const rawBody = (req as any).rawBody as Buffer | undefined
  if (!timestamp || !signature || !rawBody) return false
  const expected = createHmac('sha256', secret).update(`${timestamp}.${rawBody.toString('utf8')}`).digest('hex')
  const expectedBuffer = Buffer.from(expected, 'hex')
  const signatureBuffer = Buffer.from(signature, 'hex')
  return expectedBuffer.length === signatureBuffer.length && timingSafeEqual(expectedBuffer, signatureBuffer)
}

async function handleStripeEvent(event: any, req: Request, res: Response) {
  if (!verifyStripeSignature(req)) return jsonError(res, 400, 'INVALID_SIGNATURE', 'Invalid Stripe webhook signature')
  const db = getServiceClient()
  if (!db) return jsonError(res, 500, 'CONFIG_ERROR', 'Supabase service client is not configured')

  const object = event?.data?.object || {}
  const metadata = object.metadata || {}
  const userId = metadata.userId || object.client_reference_id
  if (!userId) return res.status(202).json({ data: { received: true, ignored: true } })

  if (event.type === 'checkout.session.completed') {
    const plan = normalizePlan(metadata.plan)
    const billingCycle = normalizeCycle(metadata.billingCycle)
    await db.from('billing_subscriptions').upsert({
      user_id: userId,
      subscription_id: object.subscription || `stripe_${object.id}`,
      provider: 'stripe',
      provider_customer_id: object.customer || null,
      provider_subscription_id: object.subscription || null,
      plan,
      status: 'active',
      billing_cycle: billingCycle,
      auto_renew: true,
      renewal_date: null,
      metadata: { stripeCheckoutSessionId: object.id },
      updated_at: new Date().toISOString(),
    }, { onConflict: 'user_id' })
    await db.from('profiles').update({ tier: plan.toLowerCase(), updated_at: new Date().toISOString() }).eq('id', userId)
  }

  if (event.type === 'invoice.payment_succeeded' || event.type === 'invoice.payment_failed') {
    await db.from('billing_invoices').upsert({
      user_id: userId,
      invoice_id: object.number || object.id,
      provider_invoice_id: object.id,
      transaction_id: object.payment_intent || object.charge || null,
      amount_paid_cents: cents(object.amount_paid),
      tax_cents: cents(object.tax),
      currency: String(object.currency || 'usd').toUpperCase(),
      status: event.type === 'invoice.payment_succeeded' ? 'paid' : 'failed',
      payment_method_summary: object.payment_settings?.payment_method_types?.join(', ') || 'Stripe card',
      subscription_plan: normalizePlan(metadata.plan),
      hosted_invoice_url: object.hosted_invoice_url || null,
      receipt_url: object.receipt_url || null,
      payment_date: object.status_transitions?.paid_at ? new Date(object.status_transitions.paid_at * 1000).toISOString() : new Date().toISOString(),
      metadata: { stripeEventId: event.id },
    }, { onConflict: 'provider_invoice_id' })
  }

  if (event.type === 'customer.subscription.updated' || event.type === 'customer.subscription.deleted') {
    const status = event.type === 'customer.subscription.deleted' ? 'cancelled' : object.status
    await db.from('billing_subscriptions').update({
      status,
      auto_renew: !object.cancel_at_period_end,
      cancel_at_period_end: Boolean(object.cancel_at_period_end),
      current_period_start: object.current_period_start ? new Date(object.current_period_start * 1000).toISOString() : null,
      current_period_end: object.current_period_end ? new Date(object.current_period_end * 1000).toISOString() : null,
      renewal_date: object.current_period_end ? new Date(object.current_period_end * 1000).toISOString() : null,
      provider_subscription_id: object.id,
      updated_at: new Date().toISOString(),
    }).eq('user_id', userId)
  }

  if (event.type === 'payment_method.attached') {
    const card = object.card || {}
    await db.from('billing_payment_methods').upsert({
      user_id: userId,
      provider: 'stripe',
      provider_payment_method_id: object.id,
      brand: card.brand || 'Card',
      last4: card.last4 || '',
      exp_month: card.exp_month || null,
      exp_year: card.exp_year || null,
      country: card.country || null,
      is_default: false,
      metadata: { stripeEventId: event.id },
      updated_at: new Date().toISOString(),
    }, { onConflict: 'provider_payment_method_id' })
  }

  try {
    await db.from('billing_audit_events').insert({
      user_id: userId,
      action: `stripe.${event.type}`,
      message: `Stripe billing event processed: ${event.type}`,
      ip_address: getClientIp(req),
      user_agent: getUserAgent(req),
      metadata: { eventId: event.id },
    })
  } catch {
    // Webhook acknowledgement should not fail because an audit sink is unavailable.
  }

  return res.json({ data: { received: true } })
}

router.post('/webhooks/stripe', async (req, res) => {
  try {
    return await handleStripeEvent(req.body, req, res)
  } catch (err) {
    console.error('Stripe webhook error:', err)
    return jsonError(res, 500, 'WEBHOOK_ERROR', 'Failed to process Stripe webhook')
  }
})

router.get('/stream', async (req: Request, res: Response) => {
  const token = extractToken(req)
  if (!token) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
    })
    res.write(`event: error\ndata: ${JSON.stringify({ error: 'Unauthorized' })}\n\n`)
    res.end()
    return
  }

  const client = createAuthClient(token)
  const user = await getServerUser(token)
  if (!client || !user) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
    })
    res.write(`event: error\ndata: ${JSON.stringify({ error: 'Invalid token' })}\n\n`)
    res.end()
    return
  }

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  })
  res.write(`event: connected\ndata: ${JSON.stringify({ connectedAt: new Date().toISOString() })}\n\n`)

  const sendSnapshot = async () => {
    try {
      const bundle = await fetchBillingBundle(client, user)
      res.write(`event: billing-sync\ndata: ${JSON.stringify(bundle)}\n\n`)
    } catch (err) {
      res.write(`event: heartbeat\ndata: ${JSON.stringify({ timestamp: new Date().toISOString(), degraded: true })}\n\n`)
    }
  }

  const heartbeat = setInterval(() => {
    res.write(`event: heartbeat\ndata: ${JSON.stringify({ timestamp: new Date().toISOString() })}\n\n`)
  }, 15000)
  const poll = setInterval(() => sendSnapshot().catch(() => undefined), 10000)
  sendSnapshot()

  req.on('close', () => {
    clearInterval(heartbeat)
    clearInterval(poll)
  })
})

router.use(requireAuth)

router.get('/', async (req: AuthedRequest, res: Response) => {
  try {
    const data = await fetchBillingBundle(req.authClient!, req.user!)
    return res.json({ data })
  } catch (err: any) {
    if (err?.code === 'BILLING_SCHEMA_NOT_READY' || isMissingTable(err)) {
      return jsonError(res, 503, 'BILLING_SCHEMA_NOT_READY', 'Billing database schema is not installed. Run supabase/billing-subscription-schema.sql.')
    }
    console.error('Billing fetch error:', err)
    return jsonError(res, 500, 'BILLING_ERROR', 'Failed to load billing settings')
  }
})

router.post('/subscription/actions', async (req: AuthedRequest, res: Response) => {
  const action = String(req.body?.action || '') as SubscriptionAction
  const targetPlan = normalizePlan(req.body?.plan)
  const targetCycle = normalizeCycle(req.body?.billingCycle)
  const validActions: SubscriptionAction[] = ['upgrade', 'downgrade', 'renew', 'cancel', 'reactivate', 'switch-cycle', 'enable-auto-renew', 'disable-auto-renew']
  if (!validActions.includes(action)) return jsonError(res, 400, 'INVALID_ACTION', 'Unsupported billing action')

  try {
    const client = req.authClient!
    const user = req.user!
    const { subscription, profile } = await ensureSubscription(client, user)
    if (!canManageBilling(user, profile)) return jsonError(res, 403, 'FORBIDDEN', 'Billing management requires account administrator permissions')

    // Any plan-changing action creates a PayPal subscription and redirects the
    // user to approve it. The PayPal webhook is the single source of activation
    // (it upserts billing_subscriptions + profiles.tier and cancels the prior
    // subscription), so we do not mutate the plan here.
    const paymentActions: SubscriptionAction[] = ['upgrade', 'downgrade', 'renew', 'switch-cycle', 'reactivate']
    if (paymentActions.includes(action)) {
      if (!isPaypalConfigured()) {
        return jsonError(res, 503, 'PAYMENT_PROVIDER_NOT_CONFIGURED', 'PayPal is not configured')
      }
      const origin = resolveOrigin(req)
      if (!origin) {
        return jsonError(res, 503, 'APP_ORIGIN_NOT_CONFIGURED', 'Set APP_ORIGIN to the public site URL so PayPal return URLs can be built safely.')
      }
      const desiredPlan = req.body?.plan ? normalizePlan(req.body.plan) : normalizePlan(subscription?.plan)
      const desiredCycle = req.body?.billingCycle ? normalizeCycle(req.body.billingCycle) : normalizeCycle(subscription?.billing_cycle)
      const paypalCycle = desiredCycle === 'annual' ? 'yearly' : 'monthly'
      const returnUrl = `${origin}/dashboard/settings?tab=billing&billing=success`
      const cancelUrl = `${origin}/dashboard/settings?tab=billing&billing=cancelled`
      // Change an existing PayPal subscription in place (prorated, same id) when
      // one is live; otherwise create a fresh subscription.
      const existingPaypalSub = subscription?.provider === 'paypal'
        && ['active', 'past_due', 'suspended', 'pending_renewal'].includes(String(subscription?.status || '').toLowerCase())
        && subscription?.provider_subscription_id
        ? String(subscription.provider_subscription_id)
        : null
      try {
        if (existingPaypalSub) {
          const revised = await reviseSubscription({
            providerSubscriptionId: existingPaypalSub,
            tier: desiredPlan,
            cycle: paypalCycle,
            returnUrl,
            cancelUrl,
          })
          await recordBillingAudit(client, user.id, req, action, `PayPal subscription revised to ${desiredPlan} ${desiredCycle}`, {
            plan: desiredPlan,
            billingCycle: desiredCycle,
            providerSubscriptionId: existingPaypalSub,
          })
          if (revised.approvalUrl) {
            return res.json({ data: { action, status: 'checkout_required', redirectUrl: revised.approvalUrl } })
          }
          // Applied without re-approval; BILLING.SUBSCRIPTION.UPDATED will sync our record.
          return res.json({ data: { action, status: 'updated' } })
        }

        const result = await createSubscription({
          userId: user.id,
          email: user.email,
          tier: desiredPlan,
          cycle: paypalCycle,
          returnUrl,
          cancelUrl,
        })
        await recordBillingAudit(client, user.id, req, action, `PayPal subscription checkout created for ${desiredPlan} ${desiredCycle}`, {
          plan: desiredPlan,
          billingCycle: desiredCycle,
          providerSubscriptionId: result.subscriptionId,
        })
        return res.json({ data: { action, status: 'checkout_required', redirectUrl: result.approvalUrl } })
      } catch (err: any) {
        const code = err?.code === 'PLAN_NOT_CONFIGURED' ? 'PLAN_NOT_CONFIGURED' : 'PAYMENT_PROVIDER_NOT_CONFIGURED'
        return jsonError(res, 503, code, err instanceof Error ? err.message : 'Payment provider is not configured')
      }
    }

    const updates: Record<string, unknown> = { updated_at: new Date().toISOString() }
    if (action === 'cancel') {
      // Cancel the live PayPal subscription first, then record the state change.
      if (subscription?.provider === 'paypal' && subscription?.provider_subscription_id) {
        try {
          await cancelSubscription(subscription.provider_subscription_id, 'Customer cancelled from billing settings')
        } catch (err) {
          console.warn('[billing] PayPal cancellation failed:', err)
        }
      }
      updates.status = 'cancelled'
      updates.auto_renew = false
      updates.cancel_at_period_end = true
      updates.cancelled_at = new Date().toISOString()
    }
    if (action === 'reactivate' || action === 'renew') {
      updates.status = 'active'
      updates.auto_renew = true
      updates.cancel_at_period_end = false
      updates.cancelled_at = null
      updates.renewal_date = subscription?.renewal_date || nextMonthlyRenewal()
    }
    if (action === 'enable-auto-renew') updates.auto_renew = true
    if (action === 'disable-auto-renew') updates.auto_renew = false
    if (action === 'switch-cycle') {
      updates.billing_cycle = targetCycle
      updates.renewal_date = targetCycle === 'annual'
        ? new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
        : nextMonthlyRenewal()
    }
    if (action === 'downgrade') {
      updates.plan = targetPlan
      updates.billing_cycle = targetCycle
      updates.auto_renew = targetPlan !== 'Starter'
      updates.renewal_date = targetPlan === 'Starter' ? null : nextMonthlyRenewal()
      await client.from('profiles').update({ tier: targetPlan.toLowerCase(), updated_at: new Date().toISOString() }).eq('id', user.id)
    }

    const { data, error } = await client
      .from('billing_subscriptions')
      .update(updates)
      .eq('id', subscription.id)
      .eq('user_id', user.id)
      .select('*')
      .single()

    if (error || !data) return jsonError(res, 500, 'BILLING_UPDATE_FAILED', 'Failed to update subscription state')
    await recordBillingAudit(client, user.id, req, action, `Subscription action completed: ${action}`, { plan: targetPlan, billingCycle: targetCycle })
    return res.json({ data: { action, status: 'completed', subscription: normalizeSubscription(data, user) } })
  } catch (err) {
    console.error('Billing action error:', err)
    return jsonError(res, 500, 'BILLING_ACTION_FAILED', 'Failed to process billing action')
  }
})

router.post('/payment-methods/setup-session', async (req: AuthedRequest, res: Response) => {
  try {
    const { subscription, profile } = await ensureSubscription(req.authClient!, req.user!)
    if (!canManageBilling(req.user!, profile)) return jsonError(res, 403, 'FORBIDDEN', 'Billing management requires account administrator permissions')
    const setup = await createStripeSetup(req, req.user!, subscription)
    await recordBillingAudit(req.authClient!, req.user!.id, req, 'payment_method.setup', 'Payment method setup session created', { checkoutSessionId: setup.id })
    return res.json({ data: { status: 'setup_required', redirectUrl: setup.url } })
  } catch (err) {
    return jsonError(res, 503, 'PAYMENT_PROVIDER_NOT_CONFIGURED', err instanceof Error ? err.message : 'Payment provider is not configured')
  }
})

router.patch('/payment-methods/:id', async (req: AuthedRequest, res: Response) => {
  const paymentMethodId = req.params.id
  try {
    const { profile } = await ensureSubscription(req.authClient!, req.user!)
    if (!canManageBilling(req.user!, profile)) return jsonError(res, 403, 'FORBIDDEN', 'Billing management requires account administrator permissions')

    const updates: Record<string, unknown> = { updated_at: new Date().toISOString() }
    if (req.body?.billingName !== undefined) updates.billing_name = String(req.body.billingName || '').slice(0, 200) || null
    if (req.body?.country !== undefined) updates.country = String(req.body.country || '').slice(0, 80) || null
    if (req.body?.taxRegion !== undefined) updates.tax_region = String(req.body.taxRegion || '').slice(0, 120) || null
    if (req.body?.billingAddress !== undefined && typeof req.body.billingAddress === 'object') updates.billing_address = req.body.billingAddress
    if (Number.isFinite(Number(req.body?.expMonth))) updates.exp_month = Math.max(1, Math.min(12, Math.round(Number(req.body.expMonth))))
    if (Number.isFinite(Number(req.body?.expYear))) updates.exp_year = Math.max(new Date().getUTCFullYear(), Math.round(Number(req.body.expYear)))

    if (req.body?.isDefault === true) {
      await req.authClient!.from('billing_payment_methods').update({ is_default: false }).eq('user_id', req.user!.id)
      updates.is_default = true
    }

    const { data, error } = await req.authClient!
      .from('billing_payment_methods')
      .update(updates)
      .eq('id', paymentMethodId)
      .eq('user_id', req.user!.id)
      .is('removed_at', null)
      .select('*')
      .single()

    if (error || !data) return jsonError(res, 404, 'PAYMENT_METHOD_NOT_FOUND', 'Payment method not found')
    await recordBillingAudit(req.authClient!, req.user!.id, req, 'payment_method.updated', 'Payment method metadata updated', { paymentMethodId })
    return res.json({ data: { paymentMethod: normalizePaymentMethod(data) } })
  } catch (err) {
    console.error('Payment method update error:', err)
    return jsonError(res, 500, 'PAYMENT_METHOD_UPDATE_FAILED', 'Failed to update payment method')
  }
})

router.delete('/payment-methods/:id', async (req: AuthedRequest, res: Response) => {
  const paymentMethodId = req.params.id
  try {
    const { profile } = await ensureSubscription(req.authClient!, req.user!)
    if (!canManageBilling(req.user!, profile)) return jsonError(res, 403, 'FORBIDDEN', 'Billing management requires account administrator permissions')

    const { error } = await req.authClient!
      .from('billing_payment_methods')
      .update({ removed_at: new Date().toISOString(), is_default: false, updated_at: new Date().toISOString() })
      .eq('id', paymentMethodId)
      .eq('user_id', req.user!.id)

    if (error) return jsonError(res, 404, 'PAYMENT_METHOD_NOT_FOUND', 'Payment method not found')
    await recordBillingAudit(req.authClient!, req.user!.id, req, 'payment_method.removed', 'Payment method removed', { paymentMethodId })
    return res.json({ data: { removed: true, id: paymentMethodId } })
  } catch (err) {
    return jsonError(res, 500, 'PAYMENT_METHOD_REMOVE_FAILED', 'Failed to remove payment method')
  }
})

router.put('/notifications', async (req: AuthedRequest, res: Response) => {
  try {
    const webhookUrl = cleanWebhookUrl(req.body?.webhookUrl)
    if (webhookUrl === undefined) return jsonError(res, 400, 'INVALID_WEBHOOK_URL', 'Webhook URL must be a valid HTTP or HTTPS URL')

    const updates = {
      user_id: req.user!.id,
      email_notifications: Boolean(req.body?.emailNotifications),
      in_app_alerts: Boolean(req.body?.inAppAlerts),
      webhook_notifications: Boolean(req.body?.webhookNotifications),
      webhook_url: webhookUrl,
      updated_at: new Date().toISOString(),
    }

    const { data, error } = await req.authClient!
      .from('billing_notification_settings')
      .upsert(updates, { onConflict: 'user_id' })
      .select('*')
      .single()

    if (error || !data) return jsonError(res, 500, 'NOTIFICATION_UPDATE_FAILED', 'Failed to update billing notifications')
    await recordBillingAudit(req.authClient!, req.user!.id, req, 'notifications.updated', 'Billing notification settings updated')
    return res.json({ data: { notificationSettings: normalizeNotificationSettings(data) } })
  } catch (err) {
    return jsonError(res, 500, 'NOTIFICATION_UPDATE_FAILED', 'Failed to update billing notifications')
  }
})

router.get('/invoices/:id/:kind(invoice|receipt).pdf', async (req: AuthedRequest, res: Response) => {
  try {
    const invoice = await fetchOwnedInvoice(req.authClient!, req.user!.id, req.params.id)
    if (!invoice) return jsonError(res, 404, 'INVOICE_NOT_FOUND', 'Invoice not found')
    const kind = req.params.kind as 'invoice' | 'receipt'
    const buffer = buildInvoicePdf(invoice, kind)
    const fileName = `qguard-${kind}-${invoice.invoice_id || invoice.id}.pdf`.replace(/[^a-zA-Z0-9_.-]/g, '-')
    res.setHeader('Content-Type', 'application/pdf')
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`)
    return res.send(buffer)
  } catch (err) {
    return jsonError(res, 500, 'INVOICE_DOWNLOAD_FAILED', 'Failed to download invoice document')
  }
})

export default router
