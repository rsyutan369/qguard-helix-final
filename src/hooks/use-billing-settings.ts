import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useAuth } from '@/contexts/auth-context'
import { supabase } from '@/lib/supabase'
import { openTicketedEventSource } from '@/lib/stream-ticket'

export type BillingPlan = 'Starter' | 'Basic' | 'Pro' | 'Elite'
export type BillingCycle = 'monthly' | 'annual'
export type BillingStatus = 'active' | 'trial' | 'expired' | 'suspended' | 'pending_renewal' | 'cancelled' | 'past_due' | 'incomplete'
export type BillingAction = 'upgrade' | 'downgrade' | 'renew' | 'cancel' | 'reactivate' | 'switch-cycle' | 'enable-auto-renew' | 'disable-auto-renew'

export interface BillingPlanDefinition {
  name: BillingPlan
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
}

export interface BillingSubscription {
  id: string | null
  subscriptionId: string | null
  provider: string | null
  providerCustomerId: string | null
  providerSubscriptionId: string | null
  currentPlan: BillingPlan
  status: BillingStatus
  billingCycle: BillingCycle
  renewalDate: string | null
  trialExpirationDate: string | null
  accountCreationDate: string | null
  autoRenew: boolean
  cancelAtPeriodEnd: boolean
  currentPeriodStart: string | null
  currentPeriodEnd: string | null
  monthlyCents: number
  annualCents: number
  updatedAt: string | null
}

export interface BillingPaymentMethod {
  id: string
  provider: string
  brand: string
  last4: string
  expMonth: number | null
  expYear: number | null
  isDefault: boolean
  billingName: string | null
  billingAddress: Record<string, unknown>
  country: string | null
  taxRegion: string | null
  lastUsedAt: string | null
  updatedAt: string | null
}

export interface BillingInvoice {
  id: string
  invoiceId: string
  transactionId: string | null
  paymentDate: string | null
  amountPaidCents: number
  taxCents: number
  currency: string
  paymentMethod: string
  subscriptionPlan: BillingPlan
  status: 'paid' | 'failed' | 'pending' | 'refunded'
  hostedInvoiceUrl: string | null
  receiptUrl: string | null
  createdAt: string | null
}

export interface BillingUsageMetric {
  key: string
  label: string
  group: string
  used: number
  limit: number
  remaining: number
  percent: number
  status: string
  unit?: string
}

export interface BillingNotification {
  id: string
  type: string
  severity: 'info' | 'success' | 'warning' | 'critical'
  title: string
  message: string
  readAt?: string | null
  createdAt: string | null
}

export interface BillingNotificationSettings {
  emailNotifications: boolean
  inAppAlerts: boolean
  webhookNotifications: boolean
  webhookUrl: string
  updatedAt: string | null
}

export interface BillingBundle {
  subscription: BillingSubscription
  planCatalog: BillingPlanDefinition[]
  profile: {
    role: string
    email: string
  }
  paymentMethods: BillingPaymentMethod[]
  invoices: BillingInvoice[]
  notificationSettings: BillingNotificationSettings
  notifications: BillingNotification[]
  usage: {
    plan: BillingPlan
    periodStart: string
    periodEnd: string | null
    rateLimitStatus: string
    telemetry: {
      usageEvents: number
      runtimeEvents: number
      runtimeEvents24h: number
      lastSyncAt: string
      tableAvailability: Record<string, boolean>
    }
    metrics: BillingUsageMetric[]
    trends: Record<string, string | number>[]
  }
  providerStatus: {
    stripeConfigured: boolean
    checkoutConfigured: boolean
    webhookConfigured: boolean
    publishableKeyConfigured: boolean
  }
  permissions: {
    canManageBilling: boolean
    canViewInvoices: boolean
  }
  telemetry: {
    live: boolean
    lastSyncAt: string
    source: string
  }
}

function parseApiError(json: any, fallback: string) {
  return json?.error?.message || json?.message || fallback
}

function parseApiCode(json: any) {
  return json?.error?.code || json?.code || null
}

function wait(ms: number) {
  return new Promise((resolve) => window.setTimeout(resolve, ms))
}

function mergeBilling(previous: BillingBundle | null, incoming: BillingBundle | null | undefined) {
  if (!incoming) return previous
  if (!previous) return incoming
  return {
    ...previous,
    ...incoming,
    subscription: { ...previous.subscription, ...incoming.subscription },
    usage: { ...previous.usage, ...incoming.usage },
    providerStatus: { ...previous.providerStatus, ...incoming.providerStatus },
    permissions: { ...previous.permissions, ...incoming.permissions },
    telemetry: { ...previous.telemetry, ...incoming.telemetry },
  }
}

export function useBillingSettings() {
  const { session, user } = useAuth()
  const token = session?.access_token
  const [billing, setBilling] = useState<BillingBundle | null>(null)
  const [loading, setLoading] = useState(Boolean(user))
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [schemaReady, setSchemaReady] = useState(true)
  const [sseConnected, setSseConnected] = useState(false)
  const eventSourceRef = useRef<EventSource | null>(null)
  const savingRef = useRef(false)

  useEffect(() => {
    setBilling(null)
    setLoading(Boolean(user))
    setError(null)
    setSchemaReady(true)
    setSseConnected(false)
  }, [user?.id])

  const headers = useMemo(() => {
    const next: Record<string, string> = { 'Content-Type': 'application/json' }
    if (token) next.Authorization = `Bearer ${token}`
    return next
  }, [token])

  const request = useCallback(async <T,>(path: string, init: RequestInit = {}): Promise<T> => {
    let lastError: Error | null = null

    for (let attempt = 0; attempt < 5; attempt += 1) {
      const response = await fetch(path, {
        ...init,
        headers: {
          ...headers,
          ...(init.headers || {}),
        },
      })
      const contentType = response.headers.get('content-type') || ''
      const json = contentType.includes('application/json') ? await response.json().catch(() => ({})) : {}
      const apiCode = parseApiCode(json)

      if (response.ok) return json.data as T

      if (apiCode === 'BILLING_SCHEMA_NOT_READY') setSchemaReady(false)
      lastError = new Error(parseApiError(json, `Request failed with HTTP ${response.status}`))

      if (response.status === 503 && apiCode !== 'PAYMENT_PROVIDER_NOT_CONFIGURED') {
        await wait(350 + attempt * 150)
        continue
      }
      throw lastError
    }

    throw lastError || new Error('Request failed')
  }, [headers])

  const refresh = useCallback(async () => {
    if (!token) {
      setLoading(false)
      return
    }

    setLoading((current) => current || !billing)
    try {
      const data = await request<BillingBundle>('/api/v1/billing')
      setBilling((previous) => mergeBilling(previous, data))
      setSchemaReady(true)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load billing settings')
    } finally {
      setLoading(false)
    }
  }, [billing, request, token])

  useEffect(() => {
    refresh()
  }, [refresh])

  useEffect(() => {
    if (!token || !user) return

    const refreshBilling = () => refresh()
    const channels = [
      supabase
        .channel(`billing-subscription-${user.id}`)
        .on('postgres_changes', { event: '*', schema: 'public', table: 'billing_subscriptions', filter: `user_id=eq.${user.id}` }, refreshBilling)
        .subscribe(),
      supabase
        .channel(`billing-payment-methods-${user.id}`)
        .on('postgres_changes', { event: '*', schema: 'public', table: 'billing_payment_methods', filter: `user_id=eq.${user.id}` }, refreshBilling)
        .subscribe(),
      supabase
        .channel(`billing-invoices-${user.id}`)
        .on('postgres_changes', { event: '*', schema: 'public', table: 'billing_invoices', filter: `user_id=eq.${user.id}` }, refreshBilling)
        .subscribe(),
      supabase
        .channel(`billing-usage-${user.id}`)
        .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'billing_usage_events', filter: `user_id=eq.${user.id}` }, refreshBilling)
        .subscribe(),
      supabase
        .channel(`billing-notifications-${user.id}`)
        .on('postgres_changes', { event: '*', schema: 'public', table: 'billing_notifications', filter: `user_id=eq.${user.id}` }, refreshBilling)
        .subscribe(),
    ]

    return () => {
      for (const channel of channels) supabase.removeChannel(channel)
    }
  }, [refresh, token, user])

  useEffect(() => {
    if (!token || !billing?.subscription?.id) return

    let retryTimer: number | null = null
    let disposed = false
    const connect = () => {
      // A single-use ticket per connection: the JWT never enters the URL.
      void openTicketedEventSource('billing', token).then((eventSource) => {
      if (disposed) { eventSource.close(); return }
      eventSourceRef.current = eventSource
      eventSource.addEventListener('connected', () => setSseConnected(true))
      eventSource.addEventListener('heartbeat', () => setSseConnected(true))
      eventSource.addEventListener('billing-sync', (event) => {
        try {
          const payload = JSON.parse(event.data) as BillingBundle
          setBilling((previous) => mergeBilling(previous, payload))
          setSseConnected(true)
        } catch {
          // Ignore malformed stream payloads; the next poll will reconcile.
        }
      })
      eventSource.onerror = () => {
        setSseConnected(false)
        eventSource.close()
        retryTimer = window.setTimeout(connect, 15000)
      }
      }).catch(() => {
        if (disposed) return
        setSseConnected(false)
        retryTimer = window.setTimeout(connect, 15000)
      })
    }

    connect()
    return () => {
      disposed = true
      if (retryTimer) window.clearTimeout(retryTimer)
      eventSourceRef.current?.close()
      eventSourceRef.current = null
      setSseConnected(false)
    }
  }, [billing?.subscription?.id, token])

  const withSaving = useCallback(async <T,>(operation: () => Promise<T>) => {
    if (savingRef.current) throw new Error('Another billing update is already in progress.')
    savingRef.current = true
    setSaving(true)
    setError(null)
    try {
      return await operation()
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Billing operation failed'
      setError(message)
      throw err
    } finally {
      savingRef.current = false
      setSaving(false)
    }
  }, [])

  const runSubscriptionAction = useCallback((
    action: BillingAction,
    payload: { plan?: BillingPlan; billingCycle?: BillingCycle } = {},
  ) => withSaving(async () => {
    const data = await request<{ action: BillingAction; status: string; redirectUrl?: string; subscription?: BillingSubscription }>('/api/v1/billing/subscription/actions', {
      method: 'POST',
      body: JSON.stringify({ action, ...payload }),
    })
    if (data.subscription) {
      setBilling((previous) => previous ? { ...previous, subscription: data.subscription! } : previous)
    }
    await refresh()
    return data
  }), [refresh, request, withSaving])

  const createPaymentMethodSession = useCallback(() => withSaving(async () => {
    return request<{ status: string; redirectUrl?: string }>('/api/v1/billing/payment-methods/setup-session', { method: 'POST' })
  }), [request, withSaving])

  const updatePaymentMethod = useCallback((id: string, updates: Partial<BillingPaymentMethod>) => withSaving(async () => {
    const data = await request<{ paymentMethod: BillingPaymentMethod }>(`/api/v1/billing/payment-methods/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    })
    setBilling((previous) => previous ? {
      ...previous,
      paymentMethods: previous.paymentMethods.map((method) => method.id === data.paymentMethod.id ? data.paymentMethod : updates.isDefault ? { ...method, isDefault: false } : method),
    } : previous)
    await refresh()
    return data.paymentMethod
  }), [refresh, request, withSaving])

  const removePaymentMethod = useCallback((id: string) => withSaving(async () => {
    await request<{ removed: boolean; id: string }>(`/api/v1/billing/payment-methods/${id}`, { method: 'DELETE' })
    setBilling((previous) => previous ? {
      ...previous,
      paymentMethods: previous.paymentMethods.filter((method) => method.id !== id),
    } : previous)
  }), [request, withSaving])

  const updateNotifications = useCallback((updates: BillingNotificationSettings) => withSaving(async () => {
    const data = await request<{ notificationSettings: BillingNotificationSettings }>('/api/v1/billing/notifications', {
      method: 'PUT',
      body: JSON.stringify(updates),
    })
    setBilling((previous) => previous ? { ...previous, notificationSettings: data.notificationSettings } : previous)
    return data.notificationSettings
  }), [request, withSaving])

  const downloadInvoice = useCallback(async (invoiceId: string, kind: 'invoice' | 'receipt') => {
    if (!token) throw new Error('Authentication required')
    const response = await fetch(`/api/v1/billing/invoices/${encodeURIComponent(invoiceId)}/${kind}.pdf`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    if (!response.ok) {
      const json = await response.json().catch(() => ({}))
      throw new Error(parseApiError(json, `Failed to download ${kind}`))
    }
    const blob = await response.blob()
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `qguard-${kind}-${invoiceId}.pdf`
    anchor.click()
    URL.revokeObjectURL(url)
  }, [token])

  return {
    user,
    billing,
    loading,
    saving,
    error,
    schemaReady,
    sseConnected,
    refresh,
    runSubscriptionAction,
    createPaymentMethodSession,
    updatePaymentMethod,
    removePaymentMethod,
    updateNotifications,
    downloadInvoice,
  }
}
