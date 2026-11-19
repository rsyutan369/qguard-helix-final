/**
 * Publisher identity and policy constants for the public legal surfaces.
 *
 * Single source of truth for every fact that appears in more than one legal
 * document: who the provider is, how to reach them, which law governs, how long
 * the refund window is, and what a subscription costs. The Terms, Privacy
 * Policy, Refund Policy and Contact pages all read from here, so the three
 * documents cannot drift apart or contradict the pricing section.
 *
 * Prices are NOT restated here — they are imported from
 * src/lib/billing/plan-pricing.ts so a price change reaches the legal copy in
 * the same edit that reaches PayPal and the landing page.
 */

import { PLAN_PRICING, PLAN_TIERS, type PlanTier } from './billing/plan-pricing'

export const SITE = {
  /** Trading name presented to customers and shown by PayPal at checkout. */
  providerName: 'Qguard Helix',
  productName: 'Qguard Helix',
  domain: 'qguardhelix.com',
  origin: 'https://qguardhelix.com',
  supportEmail: 'support@qguardhelix.com',
  privacyEmail: 'support@qguardhelix.com',
  /** Inbox that receives Request Demo submissions (POST /api/v1/demo-request). */
  salesEmail: 'info@qguardhelix.com',
  /** Operating location — governs the jurisdiction clauses below. */
  city: 'Imus',
  province: 'Cavite',
  country: 'Philippines',
  jurisdiction: 'the Republic of the Philippines',
  courts: 'the courts of Imus, Cavite, Philippines',
  /**
   * Date the current documents took effect. Bump this (and say what changed in
   * the change log section) whenever the substance of a policy changes — not
   * for typo fixes.
   */
  effectiveDate: '2026-09-15',
  /** Support response target published on the Contact page. */
  supportResponseTarget: '2 business days',
} as const

/**
 * Refund terms (owner decision 2026-11-12, Qguard_Wiki/GooglePlay_Billing §1):
 * QGuard offers NO promotional money-back guarantee. That never overrides
 * refund rights under consumer law or an app store's own refund policy, and
 * billing errors are always corrected. Renewal charges are not refundable, but
 * a subscriber can cancel any time before a renewal date to stop it.
 */
export const REFUND_POLICY = {
  moneyBackGuarantee: false,
  renewalsRefundable: false,
  cancellationTakesEffect: 'end of the paid period',
  /** Business days from an approved request to PayPal issuing the refund. */
  processingDays: 10,
} as const

export const LEGAL_PAGES = [
  { path: '/terms', label: 'Terms of Service' },
  { path: '/privacy', label: 'Privacy Policy' },
  { path: '/refund', label: 'Refund Policy' },
  { path: '/contact', label: 'Contact' },
] as const

/** Formatted date for document headers, e.g. "15 September 2026". */
export function formatLegalDate(iso: string = SITE.effectiveDate): string {
  const date = new Date(`${iso}T00:00:00Z`)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' })
}

/** "$1 per month or $12 per year" — used in the refund and terms copy. */
export function planPriceSentence(tier: PlanTier): string {
  const pricing = PLAN_PRICING[tier]
  return `$${pricing.monthly} per month or $${pricing.yearlyPerMonth * 12} per year`
}

/** Every tier with both charge amounts, for the pricing table in the Terms. */
export function planPriceRows(): Array<{ tier: PlanTier; monthly: string; yearly: string }> {
  return PLAN_TIERS.map((tier) => ({
    tier,
    monthly: `$${PLAN_PRICING[tier].monthly}`,
    yearly: `$${PLAN_PRICING[tier].yearlyPerMonth * 12}`,
  }))
}
