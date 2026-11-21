export interface PublicScanUsage {
  limit: number
  remaining: number
  resetAt: string
  inProgress: boolean
}

export function isPublicScanUsage(value: unknown): value is PublicScanUsage {
  if (!value || typeof value !== 'object') return false
  const data = value as PublicScanUsage
  return data.limit === 3 && Number.isInteger(data.remaining) &&
    data.remaining >= 0 && data.remaining <= data.limit &&
    typeof data.resetAt === 'string' && Number.isFinite(Date.parse(data.resetAt)) &&
    typeof data.inProgress === 'boolean'
}
