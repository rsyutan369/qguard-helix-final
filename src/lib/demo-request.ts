/**
 * Request Demo — the contract shared by the landing-page modal
 * (src/pages/Landing.tsx) and POST /api/v1/demo-request
 * (src/api-server/demo-request.ts).
 *
 * Both sides run the same validator, so the browser and the server can never
 * disagree about what a valid request is, and the server never trusts the
 * browser's check.
 */

import { SITE } from './site-identity'

/** Where submissions are delivered. DEMO_REQUEST_TO overrides it server-side. */
export const DEMO_REQUEST_INBOX = SITE.salesEmail

export const DEMO_STAGES = [
  { value: 'researching', label: 'Just researching / Educating self' },
  { value: 'planning', label: 'Actively mapping cryptographic footprint' },
  { value: 'piloting', label: 'Piloting Post-Quantum Algorithms (ML-KEM / ML-DSA)' },
  { value: 'deployed', label: 'Fully migrated or in active production transition' },
] as const

export type DemoStage = (typeof DEMO_STAGES)[number]['value']

export const DEMO_FIELD_LIMITS = {
  name: 120,
  email: 254,
  organization: 160,
  message: 4000,
} as const

export interface DemoRequestInput {
  name: string
  email: string
  organization: string
  stage: DemoStage
  whitepaper: boolean
  message: string
}

export type DemoRequestField = keyof DemoRequestInput

export type DemoRequestValidation =
  | { ok: true; value: DemoRequestInput }
  | { ok: false; field: DemoRequestField; message: string }

/**
 * Deliberately narrower than RFC 5322: no quotes, comments, angle brackets,
 * spaces or group syntax. The address becomes the email's Reply-To, and every
 * mail-library address-parser defect so far has needed one of those to reach.
 */
export const DEMO_EMAIL_PATTERN = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,63}$/

/** One line of text: control characters (CR/LF included) become spaces. */
function singleLine(raw: unknown): string {
  return typeof raw === 'string'
    ? raw.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim()
    : ''
}

/** Free text: line breaks kept, every other control character dropped. */
function multiLine(raw: unknown): string {
  return typeof raw === 'string'
    ? raw.replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, '').trim()
    : ''
}

export function demoStageLabel(stage: DemoStage): string {
  return DEMO_STAGES.find((entry) => entry.value === stage)?.label ?? stage
}

export function validateDemoRequest(raw: unknown): DemoRequestValidation {
  const body = raw && typeof raw === 'object' && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {}

  const name = singleLine(body.name)
  if (!name) return { ok: false, field: 'name', message: 'Enter your name.' }
  if (name.length > DEMO_FIELD_LIMITS.name) {
    return { ok: false, field: 'name', message: `Name must be at most ${DEMO_FIELD_LIMITS.name} characters.` }
  }

  const email = singleLine(body.email)
  if (!email || email.length > DEMO_FIELD_LIMITS.email || !DEMO_EMAIL_PATTERN.test(email)) {
    return { ok: false, field: 'email', message: 'Enter a valid work email address, like name@organization.com.' }
  }

  const organization = singleLine(body.organization)
  if (!organization) return { ok: false, field: 'organization', message: 'Enter your organization.' }
  if (organization.length > DEMO_FIELD_LIMITS.organization) {
    return {
      ok: false,
      field: 'organization',
      message: `Organization must be at most ${DEMO_FIELD_LIMITS.organization} characters.`,
    }
  }

  const stage = DEMO_STAGES.find((entry) => entry.value === body.stage)?.value
  if (!stage) return { ok: false, field: 'stage', message: 'Choose your PQC migration status.' }

  const message = multiLine(body.message)
  if (message.length > DEMO_FIELD_LIMITS.message) {
    return { ok: false, field: 'message', message: `Message must be at most ${DEMO_FIELD_LIMITS.message} characters.` }
  }

  return {
    ok: true,
    value: { name, email, organization, stage, whitepaper: body.whitepaper === true, message },
  }
}
