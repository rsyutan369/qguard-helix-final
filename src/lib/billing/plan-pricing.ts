/**
 * Single source of truth for subscription list pricing (USD).
 *
 * Consumed by:
 *   - src/api-server/paypal.ts        (PayPal subscription creation / revision)
 *   - src/api-server/play-billing.ts  (Play Billing invoice amounts)
 *   - src/api-server/revenue.ts       (MRR contribution)
 *   - tools/paypal-setup.ts           (one-time plan provisioning)
 *   - tools/paypal-update-pricing.ts  (repricing existing PayPal plans)
 *
 * `yearlyPerMonth` is the discounted monthly-equivalent rate; a yearly plan is
 * billed ONCE per year at `yearlyPerMonth x 12`.
 *
 * Landing copy (src/pages/Landing.tsx PRICING_PLANS) and the billing catalog
 * (src/api-server/billing.ts, cents) must match these figures.
 */

export type PlanTier = 'Starter' | 'Basic' | 'Pro' | 'Elite'
export type PlanCycle = 'monthly' | 'yearly'

export const PLAN_TIERS: PlanTier[] = ['Starter', 'Basic', 'Pro', 'Elite']

export const PLAN_PRICING: Record<PlanTier, { monthly: number; yearlyPerMonth: number }> = {
  Starter: { monthly: 1, yearlyPerMonth: 1 },
  Basic: { monthly: 8, yearlyPerMonth: 5 },
  Pro: { monthly: 30, yearlyPerMonth: 20 },
  Elite: { monthly: 199, yearlyPerMonth: 150 },
}

/** Amount actually charged per billing cycle (yearly = the full annual charge). */
export function planChargeAmount(tier: PlanTier, cycle: PlanCycle): number {
  const pricing = PLAN_PRICING[tier]
  return cycle === 'yearly' ? pricing.yearlyPerMonth * 12 : pricing.monthly
}

/** Amount charged per cycle, in cents (integer). */
export function planChargeCents(tier: PlanTier, cycle: PlanCycle): number {
  return Math.round(planChargeAmount(tier, cycle) * 100)
}
