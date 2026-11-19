/**
 * QGuard entitlement catalog — what each paid tier grants, as explicit keys.
 *
 * Runtime-agnostic (Edge Function, Express, Node checks, React clients).
 * The tiers form a strict ladder (owner decision 2026-11-12): every tier
 * includes everything below it, an account holds ONE subscription, and a plan
 * change replaces it in place. There is no free tier and no trial: without an
 * access-granting subscription an account holds no entitlement at all.
 *
 * The SAME catalog is seeded into public.subscription_entitlement_catalog
 * (supabase/google-play-billing-v2.sql), from which the database computes
 * public.user_entitlements; tools/billing-edge-check.ts asserts the SQL seed
 * and this file agree key-for-key, and that every `routes` prefix resolves to
 * `minTier` in src/lib/subscription-access.ts, so web gating, the database and
 * the billing API answer "what does this plan grant" identically.
 *
 * Per Qguard_Wiki/GooglePlay_Billing §3.5 ("Maintain the Current Entitlement
 * and Access per tier") the tier of each web module follows the CURRENT route
 * gating, not a new mapping.
 */

export type EntitlementTier = "Starter" | "Basic" | "Pro" | "Elite";

export interface EntitlementDefinition {
  key: string;
  minTier: EntitlementTier;
  label: string;
  /** Dashboard route prefixes this entitlement opens on the web platform. */
  routes?: string[];
}

export const ENTITLEMENT_TIERS: EntitlementTier[] = ["Starter", "Basic", "Pro", "Elite"];

export const ENTITLEMENT_CATALOG: EntitlementDefinition[] = [
  // Starter — QGuard Messaging (desktop + mobile).
  { key: "quantum_messaging", minTier: "Starter", label: "Quantum Messaging" },
  { key: "secure_chat", minTier: "Starter", label: "End-to-end encrypted Secure Chat" },
  { key: "encrypted_voice_calls", minTier: "Starter", label: "Encrypted voice calls" },
  { key: "encrypted_video_calls", minTier: "Starter", label: "Encrypted video calls" },
  { key: "disappearing_messages", minTier: "Starter", label: "Disappearing messages" },
  { key: "multi_device_trust", minTier: "Starter", label: "Multi-device trust" },
  { key: "call_verification", minTier: "Starter", label: "One-tap call verification" },
  { key: "quantum_vault_local", minTier: "Starter", label: "On-device Quantum Vault (local only)" },
  { key: "hidden_vault", minTier: "Starter", label: "Hidden Vault" },
  { key: "offgrid_mesh_xfer", minTier: "Starter", label: "OffGrid Mesh and XFER" },
  // Basic — Quantum Readiness and Assessment.
  { key: "qrae", minTier: "Basic", label: "Quantum Readiness & Assessment Engine", routes: ["/dashboard/quantum-readiness"] },
  { key: "risk_analysis", minTier: "Basic", label: "Risk Analysis", routes: ["/dashboard/harvest-now"] },
  { key: "migration_planner", minTier: "Basic", label: "Migration Planner", routes: ["/dashboard/migration-planner"] },
  { key: "migration_sandbox", minTier: "Basic", label: "Migration Sandbox", routes: ["/dashboard/migration-sandbox"] },
  { key: "ai_migration_advisor", minTier: "Basic", label: "AI Migration Advisor", routes: ["/dashboard/sophia"] },
  { key: "ai_executive_advisor", minTier: "Basic", label: "AI Executive Advisor", routes: ["/dashboard/sophia"] },
  { key: "assessment_reports", minTier: "Basic", label: "Quantum Readiness & Assessment Reports", routes: ["/dashboard/quantum-certification"] },
  { key: "crypto_asset_discovery", minTier: "Basic", label: "Cryptographic asset discovery", routes: ["/dashboard/scanner", "/dashboard/assets"] },
  { key: "cbom_explorer", minTier: "Basic", label: "Assets & CBOM Explorer", routes: ["/dashboard/cbom"] },
  { key: "hndl_center", minTier: "Basic", label: "Harvest Now, Decrypt Later Center", routes: ["/dashboard/harvest-now"] },
  // Pro — Operational PQC readiness.
  { key: "migration_timeline", minTier: "Pro", label: "Migration Timeline", routes: ["/dashboard/migration-timeline"] },
  { key: "pqc_auth", minTier: "Pro", label: "PQC-Auth Identity Migration Engine", routes: ["/dashboard/pqauth"] },
  { key: "pqc_orchestration", minTier: "Pro", label: "PQC Orchestration", routes: ["/dashboard/pqc-orchestration"] },
  { key: "live_migration", minTier: "Pro", label: "Live Migration Operations", routes: ["/dashboard/live-migration"] },
  { key: "rollback_operations", minTier: "Pro", label: "Rollback operations", routes: ["/dashboard/live-migration"] },
  { key: "runtime_crypto_intelligence", minTier: "Pro", label: "Runtime & Cryptographic Intelligence", routes: ["/dashboard/runtime-crypto-intel"] },
  { key: "supply_chain_readiness", minTier: "Pro", label: "Supply Chain Readiness Center", routes: ["/dashboard/vendor-pqc-readiness", "/dashboard/ecosystem-dependency-map"] },
  { key: "trust_chain_analysis", minTier: "Pro", label: "Trust Chain Analysis", routes: ["/dashboard/trust-chain-analyzer"] },
  { key: "crypto_agility", minTier: "Pro", label: "Crypto Agility Engine", routes: ["/dashboard/crypto-agility"] },
  { key: "email_support", minTier: "Pro", label: "Email support" },
  // Elite — Enterprise crypto agility.
  { key: "enterprise_crypto_governance", minTier: "Elite", label: "Enterprise cryptographic estate governance", routes: ["/dashboard/quantum-governance"] },
  { key: "qkms", minTier: "Elite", label: "QKMS overview, inventory, governance & readiness", routes: ["/dashboard/qkms"] },
  { key: "compliance_control_mapping", minTier: "Elite", label: "SOC 2, PCI DSS 4.0.1, NIST & custom control mapping", routes: ["/dashboard/compliance", "/dashboard/regulatory-mapping"] },
];

export function tierRankOf(tier: unknown): number {
  const text = String(tier ?? "").trim().toLowerCase();
  const index = ENTITLEMENT_TIERS.findIndex((entry) => entry.toLowerCase() === text);
  return index + 1; // 0 = no tier
}

/** Entitlement keys a tier grants (the ladder: a tier includes every lower tier). */
export function entitlementsForTier(tier: unknown): string[] {
  const rank = tierRankOf(tier);
  if (!rank) return [];
  return ENTITLEMENT_CATALOG.filter((entry) => tierRankOf(entry.minTier) <= rank).map((entry) => entry.key);
}

/** Keys a tier grants that the tier below it does not (for plan cards). */
export function entitlementsAddedBy(tier: EntitlementTier): EntitlementDefinition[] {
  return ENTITLEMENT_CATALOG.filter((entry) => entry.minTier === tier);
}
