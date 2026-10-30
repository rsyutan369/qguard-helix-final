/**
 * Identity discovery → table rows (pure).
 *
 * `probeIdentityInfrastructure` returns structured records, and the identity
 * tables in supabase/pqauth-identity-schema.sql were built to hold them — but
 * nothing ever connected the two, so every identity table stayed empty and the
 * PQAuth pages fell back to guessing from crypto-row text. This module is that
 * connection, kept free of I/O so `tools/pqauth-identity-check.ts` can prove
 * the mapping offline.
 *
 * What is written, and why only this:
 *   • every probe that ran — including misses, which are proof of absence;
 *   • one provider per issuer (upserted on `user_id, issuer`);
 *   • the provider's public JWKS keys (upserted on `provider_id, key_id`);
 *   • a `declared` TRUSTS edge from the probed asset to the provider, only
 *     when the document served by the asset names an issuer on ANOTHER host —
 *     the asset is publishing that it delegates authentication there.
 *
 * Metadata only: never token contents, never private key material. A JWKS
 * publishes public keys by design, and only public parameters are stored.
 */

import type { IdentityProbeReport } from '../scanner/identity/identity-probe'

export interface IdentityPersistContext {
  userId: string
  assetId: string
  /** The host that was probed (the asset's authorized target). */
  assetHost: string
  /** Groups every probe of one discovery run (stored in `scan_session_id`). */
  runId: string
  observedAt: string
}

export interface IdentityProviderWrite {
  row: Record<string, unknown>
  keys: Array<Record<string, unknown>>
  /** Write a declared TRUSTS edge from the probed asset to this provider. */
  declaredTrust: Record<string, unknown> | null
}

export interface IdentityWriteSet {
  probes: Array<Record<string, unknown>>
  providers: IdentityProviderWrite[]
}

const clip = (value: string | null | undefined, max: number) => (value ? String(value).slice(0, max) : null)

export function identityReportToRows(report: IdentityProbeReport, ctx: IdentityPersistContext): IdentityWriteSet {
  const probes = report.probes.map((probe) => ({
    user_id: ctx.userId,
    asset_id: ctx.assetId,
    scan_session_id: ctx.runId,
    probe_url: clip(probe.url, 2048),
    method: clip(probe.method, 40),
    http_status: probe.httpStatus,
    outcome: probe.outcome,
    detail: clip(probe.detail, 500),
    observed_at: probe.observedAt || ctx.observedAt,
  }))

  const assetHost = ctx.assetHost.toLowerCase()
  const providers: IdentityProviderWrite[] = report.providers.map((provider) => {
    const sameHost = provider.host.toLowerCase() === assetHost
    const row: Record<string, unknown> = {
      user_id: ctx.userId,
      issuer: clip(provider.issuer, 2048),
      protocol: provider.protocol,
      display_name: clip(provider.displayName, 255),
      vendor: clip(provider.vendor, 120),
      host: clip(provider.host, 255),
      signing_algorithms_supported: provider.signingAlgorithmsSupported,
      key_encryption_algorithms_supported: provider.keyEncryptionAlgorithmsSupported,
      content_encryption_algorithms_supported: provider.contentEncryptionAlgorithmsSupported,
      grant_types_supported: provider.grantTypesSupported,
      response_types_supported: provider.responseTypesSupported,
      scopes_supported: provider.scopesSupported,
      jwks_uri: provider.jwksUri,
      endpoints: provider.endpoints.map((e) => ({ kind: e.kind, url: e.url, insecureTransport: e.insecureTransport })),
      quantum_class: provider.quantumClass,
      source_url: provider.evidence.sourceUrl,
      discovery_method: clip(provider.evidence.method, 40),
      http_status: provider.evidence.httpStatus,
      last_seen_at: ctx.observedAt,
      updated_at: ctx.observedAt,
    }
    // The provider IS this asset only when it is served from the asset's own
    // host. An external IdP the asset delegates to keeps its own asset link
    // (or none) — overwriting it would claim the relying app hosts the IdP.
    if (sameHost) row.asset_id = ctx.assetId

    const keys = provider.signingKeys.map((key) => ({
      user_id: ctx.userId,
      key_id: clip(key.keyId, 255),
      key_type: clip(key.keyType, 16),
      algorithm: clip(key.algorithm, 64),
      key_use: key.use,
      key_size: key.keySize,
      curve: clip(key.curve, 32),
      quantum_class: key.classification.quantumClass,
      crypto_purpose: key.classification.purpose,
      pqc_target: clip(key.classification.pqcTarget, 120),
      standard: clip(key.classification.standard, 40),
      rationale: key.classification.rationale,
      source_url: key.evidence.sourceUrl,
      last_seen_at: ctx.observedAt,
      updated_at: ctx.observedAt,
    }))

    const declaredTrust = sameHost
      ? null
      : {
          user_id: ctx.userId,
          source_asset_id: ctx.assetId,
          relationship_type: 'TRUSTS',
          protocol: provider.protocol,
          confidence: 'declared',
          evidence: `The ${provider.evidence.method} document served by ${assetHost} names issuer ${provider.issuer}.`,
          source_url: provider.evidence.sourceUrl,
          last_seen_at: ctx.observedAt,
        }

    return { row, keys, declaredTrust }
  })

  return { probes, providers }
}
