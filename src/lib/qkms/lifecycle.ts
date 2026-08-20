/**
 * The one lifecycle and rotation state machine.
 *
 * Before this module the lifecycle existed twice: the backend published
 * `rotationStatus` from `rotationStatusFor()`, and the Lifecycle page derived
 * its own ten-state `lifecycleState()` in the browser. The same key could
 * therefore read "Healthy" on the Rotation page and "Pending Rotation" on the
 * Lifecycle page in the same second.
 *
 * ── The honesty rule ────────────────────────────────────────────────────────
 * The predecessor's fall-through was `return 'Healthy'`. A key discovered by a
 * scanner has no rotation policy, no last-rotated timestamp and often no
 * expiry — so the estate's least-governed keys were the ones reported healthiest.
 * Here, absence of evidence returns `unknown` / `never-rotated`, and the
 * denominators for rotation health exclude keys whose state is not determinable
 * rather than counting them as passes.
 */

import type { LifecycleState, RotationState } from './types'

export const ONE_DAY_MS = 24 * 60 * 60 * 1000

/** Default rotation interval when neither the key nor a policy declares one. */
export const DEFAULT_ROTATION_INTERVAL_DAYS = 365
/** How far ahead "expiring soon" reaches. Matches the platform's cert window. */
export const EXPIRY_WARNING_DAYS = 45
/** Rotation is "due" this far before the computed next-rotation date. */
export const ROTATION_DUE_WINDOW_DAYS = 30
/** A key older than this with no rotation is reported as long-lived. */
export const LONG_LIVED_DAYS = 730
/**
 * Age past which never having rotated is itself the finding.
 *
 * Below this a key simply has not reached its first rotation, and reporting it
 * as "never rotated" would bury the keys that genuinely are neglected.
 */
export const NEVER_ROTATED_AFTER_DAYS = 180

export function dateMs(value: unknown): number | null {
  if (!value) return null
  const ms = new Date(String(value)).getTime()
  return Number.isFinite(ms) ? ms : null
}

export function daysBetween(from: number, to: number): number {
  return Math.round((to - from) / ONE_DAY_MS)
}

export interface LifecycleInput {
  /** Raw status text from whichever source owns the key record. */
  status: string
  createdAt: string | null
  activatedAt: string | null
  lastUsedAt: string | null
  lastRotatedAt: string | null
  expiresAt: string | null
  decommissionedAt: string | null
  /** Policy or key-declared rotation interval, in days. */
  rotationIntervalDays: number | null
  /** An open rotation work order exists for this key. */
  rotationInProgress: boolean
  /** The most recent terminal rotation work order failed. */
  rotationFailed: boolean
  /** The key's algorithm is broken today — rotation is not optional. */
  deprecated: boolean
  /** Runtime events attributable to the key; `null` = never measured. */
  runtimeUsage: number | null
  /** Rotation is meaningless for this key class (e.g. a published hash). */
  rotationApplicable: boolean
  now: number
}

export interface LifecycleVerdict {
  lifecycle: LifecycleState
  lifecycleReason: string
  rotation: RotationState
  rotationReason: string
  nextRotationDueAt: string | null
  ageDays: number | null
  daysToExpiry: number | null
}

const REVOKED = /\brevok|compromis|disabl(ed)?\b/i
const DESTROYED = /\bdestroy|purged|deleted\b/i
const RETIRED = /\bretired|decommission|archiv|superseded\b/i
const SUSPENDED = /\bsuspend|inactive|paused|quarantin|on.hold\b/i
const PENDING = /\bpending|provision|awaiting|staged\b/i
const ROTATED = /\brotated\b/i

/**
 * Resolve both states together.
 *
 * They are resolved in one pass because they constrain each other: a revoked
 * key has no meaningful rotation state, and an overdue rotation is itself a
 * lifecycle state the funnel has to show.
 */
export function resolveLifecycle(input: LifecycleInput): LifecycleVerdict {
  const { now } = input
  const status = String(input.status || '').toLowerCase()

  const createdMs = dateMs(input.createdAt)
  const expiryMs = dateMs(input.expiresAt)
  const rotatedMs = dateMs(input.lastRotatedAt)
  const usedMs = dateMs(input.lastUsedAt)

  const ageDays = createdMs === null ? null : Math.max(0, daysBetween(createdMs, now))
  const daysToExpiry = expiryMs === null ? null : daysBetween(now, expiryMs)

  /* ---- Next rotation due ----------------------------------------- */
  const interval = input.rotationIntervalDays && input.rotationIntervalDays > 0
    ? input.rotationIntervalDays
    : DEFAULT_ROTATION_INTERVAL_DAYS
  // Anchored on the last rotation when there was one, otherwise on creation.
  // With neither, no due date can be computed and we say so rather than
  // inventing one from "now".
  const anchor = rotatedMs ?? createdMs
  const nextRotationMs = anchor === null ? null : anchor + interval * ONE_DAY_MS
  const nextRotationDueAt = nextRotationMs === null ? null : new Date(nextRotationMs).toISOString()
  const daysToRotation = nextRotationMs === null ? null : daysBetween(now, nextRotationMs)

  /* ---- Rotation state -------------------------------------------- */
  let rotation: RotationState
  let rotationReason: string

  if (!input.rotationApplicable) {
    rotation = 'not-applicable'
    rotationReason = 'This key class has no rotation obligation; custody and integrity evidence apply instead.'
  } else if (REVOKED.test(status) || DESTROYED.test(status)) {
    rotation = 'not-applicable'
    rotationReason = 'The key is revoked or destroyed, so no rotation is outstanding against it.'
  } else if (input.rotationInProgress) {
    rotation = 'in-progress'
    rotationReason = 'A rotation work order is open and has not yet been validated.'
  } else if (input.rotationFailed) {
    rotation = 'failed'
    rotationReason = 'The most recent rotation work order terminated in failure and needs retry or rollback.'
  } else if (input.deprecated) {
    rotation = 'overdue'
    rotationReason = 'The algorithm is broken against classical attack, so replacement is overdue regardless of schedule.'
  } else if (expiryMs !== null && expiryMs < now) {
    rotation = 'overdue'
    rotationReason = `The key expired ${Math.abs(daysToExpiry ?? 0)} day(s) ago and is past its replacement date.`
  } else if (daysToRotation !== null && daysToRotation < 0) {
    rotation = 'overdue'
    rotationReason = `Rotation was due ${Math.abs(daysToRotation)} day(s) ago against a ${interval}-day interval.`
  } else if (expiryMs !== null && daysToExpiry !== null && daysToExpiry <= EXPIRY_WARNING_DAYS) {
    rotation = 'due'
    rotationReason = `The key expires in ${daysToExpiry} day(s), inside the ${EXPIRY_WARNING_DAYS}-day replacement window.`
  } else if (daysToRotation !== null && daysToRotation <= ROTATION_DUE_WINDOW_DAYS) {
    rotation = 'due'
    rotationReason = `Rotation falls due in ${daysToRotation} day(s) against a ${interval}-day interval.`
  } else if (rotatedMs === null && createdMs === null && expiryMs === null) {
    // Nothing to be healthy about: the source carried no lifecycle metadata.
    rotation = 'unknown'
    rotationReason = 'No creation, rotation or expiry evidence was observed, so no rotation state can be determined. Bring the key under QKMS governance to establish one.'
  } else if (rotatedMs === null && ageDays !== null && ageDays >= NEVER_ROTATED_AFTER_DAYS) {
    /*
     * `never-rotated` is reserved for keys where the absence of a rotation is
     * itself the finding. A key created last week has no rotation because none
     * has fallen due — reporting that as "never rotated" fills the Lifecycle
     * page's attention list with keys that need no action, which is how a real
     * signal gets buried.
     */
    rotation = 'never-rotated'
    rotationReason = `The key has never been rotated in the ${ageDays} day(s) since it was created.`
  } else if (rotatedMs === null) {
    rotation = 'healthy'
    rotationReason = ageDays === null
      ? 'No rotation is outstanding against this key.'
      : `Created ${ageDays} day(s) ago and not yet rotated; the first rotation falls due in ${daysToRotation ?? interval} day(s).`
  } else {
    rotation = 'healthy'
    rotationReason = daysToRotation === null
      ? 'The key was rotated and no rotation is currently outstanding.'
      : `Last rotated ${Math.max(0, daysBetween(rotatedMs, now))} day(s) ago; next rotation in ${daysToRotation} day(s).`
  }

  /* ---- Lifecycle state -------------------------------------------- */
  let lifecycle: LifecycleState
  let lifecycleReason: string

  if (input.decommissionedAt || DESTROYED.test(status)) {
    lifecycle = 'decommissioned'
    lifecycleReason = 'The key record is decommissioned; its material is recorded as destroyed.'
  } else if (RETIRED.test(status)) {
    lifecycle = 'retired'
    lifecycleReason = 'The key is retired and superseded; it should no longer protect new data.'
  } else if (REVOKED.test(status)) {
    lifecycle = 'revoked'
    lifecycleReason = 'The key is revoked and must not be trusted for any operation.'
  } else if (expiryMs !== null && expiryMs < now) {
    lifecycle = 'expired'
    lifecycleReason = `The key expired ${Math.abs(daysToExpiry ?? 0)} day(s) ago.`
  } else if (SUSPENDED.test(status)) {
    lifecycle = 'suspended'
    lifecycleReason = 'The key is suspended; usage is withheld pending a governance decision.'
  } else if (rotation === 'overdue') {
    lifecycle = 'rotation-overdue'
    lifecycleReason = rotationReason
  } else if (rotation === 'due' || rotation === 'in-progress') {
    lifecycle = 'rotation-due'
    lifecycleReason = rotationReason
  } else if (ROTATED.test(status) || (rotatedMs !== null && rotatedMs > now - 30 * ONE_DAY_MS)) {
    lifecycle = 'rotated'
    lifecycleReason = 'The key was rotated recently and the new version is in service.'
  } else if (PENDING.test(status)) {
    lifecycle = 'pending-activation'
    lifecycleReason = 'The key exists but has not been activated for use.'
  } else if (input.runtimeUsage !== null && input.runtimeUsage > 0) {
    lifecycle = 'in-use'
    lifecycleReason = `${input.runtimeUsage} runtime operation(s) were attributed to this key, so it is actively in use.`
  } else if (usedMs !== null) {
    lifecycle = 'in-use'
    lifecycleReason = `The key was last used ${Math.max(0, daysBetween(usedMs, now))} day(s) ago.`
  } else if (/\bactive|enabled|in.service|ok\b/.test(status)) {
    lifecycle = 'active'
    lifecycleReason = 'The key record is marked active by the system that owns it.'
  } else if (createdMs !== null || rotatedMs !== null || expiryMs !== null) {
    lifecycle = 'active'
    lifecycleReason = 'Lifecycle dates are recorded and no terminal state applies, so the key is treated as active.'
  } else {
    // Discovered by a scan, with nothing else known about it.
    lifecycle = 'discovered'
    lifecycleReason = 'The key was discovered by scan or telemetry but carries no lifecycle metadata. Classify and assign it to bring it under governance.'
  }

  return { lifecycle, lifecycleReason, rotation, rotationReason, nextRotationDueAt, ageDays, daysToExpiry }
}

/** Rotation states that count toward a health denominator at all. */
export const ROTATION_GOVERNED: RotationState[] = ['healthy', 'due', 'overdue', 'in-progress', 'failed', 'never-rotated', 'blocked']

/** Lifecycle states meaning the key still protects something. */
export const LIFECYCLE_LIVE: LifecycleState[] = ['active', 'in-use', 'rotation-due', 'rotation-overdue', 'rotated', 'pending-activation', 'discovered']

/** Lifecycle states meaning the key is out of service. */
export const LIFECYCLE_TERMINAL: LifecycleState[] = ['revoked', 'retired', 'decommissioned', 'expired']

export function ageBucketOf(ageDays: number | null): string {
  if (ageDays === null) return 'Age unknown'
  if (ageDays <= 30) return '0–30 days'
  if (ageDays <= 90) return '31–90 days'
  if (ageDays <= 180) return '91–180 days'
  if (ageDays <= 365) return '181–365 days'
  if (ageDays <= LONG_LIVED_DAYS) return '1–2 years'
  return 'Over 2 years'
}

export function expiryBucketOf(daysToExpiry: number | null): string {
  if (daysToExpiry === null) return 'No expiry recorded'
  if (daysToExpiry < 0) return 'Expired'
  if (daysToExpiry <= 7) return 'Within 7 days'
  if (daysToExpiry <= 30) return 'Within 30 days'
  if (daysToExpiry <= 90) return 'Within 90 days'
  if (daysToExpiry <= 365) return 'Within 1 year'
  return 'Over 1 year'
}
