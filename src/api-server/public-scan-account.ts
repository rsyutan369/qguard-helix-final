import { createAuthClient, getWorkspaceServiceClient } from '@/lib/supabase-server'
import { isPublicScanUsage, type PublicScanUsage } from '@/lib/public-scan-usage'

type Operation = 'usage' | 'reserve' | 'complete' | 'release'
type QuotaStatus = 'ok' | 'exhausted' | 'active' | 'expired'

export interface PublicScanAccount {
  id: string
  quota: (operation: Operation, scanId?: string) => Promise<{ status: QuotaStatus; usage: PublicScanUsage }>
}

export async function authenticatePublicScan(token: string): Promise<PublicScanAccount | null> {
  const auth = createAuthClient(token)
  if (!auth) throw new Error('Public Scan authentication is unavailable')
  const { data: { user }, error } = await auth.auth.getUser(token)
  if (error && (!error.status || error.status === 429 || error.status >= 500)) {
    throw new Error('Public Scan authentication is unavailable')
  }
  if (error || !user || user.role !== 'authenticated' || user.is_anonymous ||
    !(user.email_confirmed_at || user.phone_confirmed_at)) return null

  const db = getWorkspaceServiceClient(token)
  if (!db) throw new Error('Public Scan quota is unavailable')
  return {
    id: user.id,
    async quota(operation, scanId) {
      const { data, error: quotaError } = await db.rpc('manage_public_scan_quota', {
        p_account_id: user.id,
        p_operation: operation,
        p_scan_id: scanId ?? null,
      }).abortSignal(AbortSignal.timeout(8_000))
      const status = data?.status
      if (quotaError || !isPublicScanUsage(data) ||
        !['ok', 'exhausted', 'active', 'expired'].includes(status)) {
        throw new Error('Public Scan quota is unavailable')
      }
      const { limit, remaining, resetAt, inProgress } = data
      return { status, usage: { limit, remaining, resetAt, inProgress } }
    },
  }
}
