import type { ReactNode } from 'react'
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Clock3,
  Crown,
  HelpCircle,
  KeyRound,
  MailQuestion,
  PauseCircle,
  ShieldCheck,
  ShieldOff,
  UserRound,
} from 'lucide-react'
import type { AdminUser } from '@/hooks/use-admin-dashboard'
import { Chip, formatDate, timeAgo, type Tone } from '../_shared/primitives'

const ICON = 'h-3.5 w-3.5 shrink-0'

export const STATUS_META: Record<AdminUser['status'], { label: string; tone: Tone; icon: ReactNode; description: string }> = {
  active: { label: 'Active', tone: 'ok', icon: <CheckCircle2 className={ICON} />, description: 'Can sign in' },
  pending_verification: { label: 'Unverified email', tone: 'info', icon: <MailQuestion className={ICON} />, description: 'Has not confirmed their email address' },
  suspended: { label: 'Suspended', tone: 'warn', icon: <PauseCircle className={ICON} />, description: 'Sign-in blocked until restored' },
  disabled: { label: 'Disabled', tone: 'bad', icon: <Ban className={ICON} />, description: 'Sign-in blocked until restored' },
}

export const ACTIVITY_META: Record<AdminUser['activity'], { label: string; tone: Tone }> = {
  active_now: { label: 'Active in last hour', tone: 'ok' },
  active_30d: { label: 'Active ≤ 30 days', tone: 'info' },
  dormant: { label: 'Dormant > 30 days', tone: 'warn' },
  never: { label: 'Never signed in', tone: 'neutral' },
}

export function StatusBadge({ user }: { user: AdminUser }) {
  const meta = STATUS_META[user.status]
  return (
    <div className="flex flex-col items-start gap-1.5">
      <Chip tone={meta.tone} icon={meta.icon} title={meta.description}>{meta.label}</Chip>
      {user.statusDrift && (
        <Chip tone="warn" icon={<AlertTriangle className={ICON} />} title={user.statusDrift}>Drift</Chip>
      )}
    </div>
  )
}

export function RoleBadge({ user }: { user: AdminUser }) {
  const tone: Tone = user.isOwner || user.isAdministrator ? 'violet' : 'info'
  return (
    <Chip tone={tone} icon={user.isOwner ? <Crown className={ICON} /> : <UserRound className={ICON} />} title={`Role source: ${user.roleSource.replace(/_/g, ' ')}`}>
      {user.roleLabel}
    </Chip>
  )
}

export function accessClassLabel(user: AdminUser): { label: string; tone: Tone } | null {
  switch (user.access.accessClass) {
    case 'owner': return { label: 'Owner bypass', tone: 'violet' }
    case 'provider': return { label: user.access.providerLabel ? `Billed · ${user.access.providerLabel}` : 'Provider billed', tone: 'ok' }
    case 'complimentary': return { label: 'Complimentary', tone: 'neutral' }
    case 'manual': return { label: 'Manual · not billed', tone: 'neutral' }
    default: return null
  }
}

export function PlanBadge({ user, compact = false }: { user: AdminUser; compact?: boolean }) {
  const { access } = user
  const billing = accessClassLabel(user)
  const tone: Tone = access.isActive ? (user.isOwner ? 'violet' : 'ok') : access.source === 'subscription' ? 'warn' : 'neutral'
  const statusText = user.isOwner
    ? 'Full access'
    : access.source === 'none'
      ? 'No subscription'
      : `${String(access.status || 'unknown').replace(/_/g, ' ')}${access.isActive ? '' : ' · no access'}`
  return (
    <div className="flex flex-col items-start gap-1.5">
      <Chip tone={tone} icon={<KeyRound className={ICON} />} title={access.accessClassReason}>{access.tierLabel}</Chip>
      {!compact && <span className="text-xs capitalize qgu-soft">{statusText}</span>}
      {!compact && billing && access.source !== 'none' && !user.isOwner && (
        <span className="text-[11px] qgu-muted" title={access.accessClassReason}>
          {billing.label}
          {access.periodEnd ? ` · ${access.cancelAtPeriodEnd ? 'ends' : access.isActive ? 'renews' : 'ended'} ${formatDate(access.periodEnd)}` : ''}
        </span>
      )}
    </div>
  )
}

export function MfaBadge({ user }: { user: AdminUser }) {
  const { mfa } = user
  if (mfa.state === 'enrolled') {
    const types = mfa.factorTypes.length ? mfa.factorTypes.join(', ').toUpperCase() : `${mfa.enrolledFactors} factor${mfa.enrolledFactors === 1 ? '' : 's'}`
    return <Chip tone="ok" icon={<ShieldCheck className={ICON} />} title="Verified MFA factor(s) enrolled in Supabase Auth">Enrolled · {types}</Chip>
  }
  if (mfa.state === 'required_not_enrolled') {
    return <Chip tone="warn" icon={<AlertTriangle className={ICON} />} title="Policy requires MFA, but no verified factor is enrolled">Required · not enrolled</Chip>
  }
  if (mfa.state === 'not_enrolled') {
    return <Chip tone="neutral" icon={<ShieldOff className={ICON} />} title="No verified MFA factor in Supabase Auth">Not enrolled</Chip>
  }
  return <Chip tone="neutral" icon={<HelpCircle className={ICON} />} title="MFA factors could not be read from Supabase Auth">Unknown</Chip>
}

export function ActivityCell({ user, now }: { user: AdminUser; now: number }) {
  const meta = ACTIVITY_META[user.activity]
  return (
    <div className="flex flex-col items-start gap-1">
      <span className="font-semibold qgu-strong qgu-num" title={user.lastActivityAt ? new Date(user.lastActivityAt).toString() : 'No sign-in recorded'}>
        {user.lastActivityAt ? timeAgo(user.lastActivityAt, now) : 'Never'}
      </span>
      <Chip tone={meta.tone} icon={<Clock3 className={ICON} />}>{meta.label}</Chip>
      {(user.sessions.lastDevice || user.sessions.lastIp) && (
        <span className="max-w-[210px] truncate text-[11px] qgu-muted" title={user.sessions.lastUserAgent || undefined}>
          {[user.sessions.lastDevice, user.sessions.lastIp].filter(Boolean).join(' · ')}
        </span>
      )}
    </div>
  )
}
