/**
 * Quantum Migration Dependency Engine™.
 *
 * Every finding sits on a dependency chain (Customer → CDN/Provider → Browser →
 * NIST → CA/B Forum → Certificate Authority → TLS Library). Migration cannot
 * proceed until the upstream blocker completes. This module derives the
 * migration-dependency status and builds the ordered chain with the blocking
 * node identified.
 */

import { PROVIDER_BY_ID } from './provider-catalog'
import type {
  CustomerActionability,
  DependencyChain,
  DependencyNode,
  MigrationDependencyStatus,
  ProviderAttribution,
  ResponsibilityDomain,
} from './types'

/** Derive the migration-dependency status from ownership + attribution. */
export function deriveMigrationDependencyStatus(
  domain: ResponsibilityDomain,
  attribution: ProviderAttribution,
  customerActionable: CustomerActionability,
): MigrationDependencyStatus {
  if (domain === 'customer') {
    return customerActionable === 'no' ? 'blocked' : 'ready'
  }

  const profile = attribution.providerId ? PROVIDER_BY_ID.get(attribution.providerId) : undefined

  if (domain === 'provider') {
    return profile?.migrationDependencyStatus ?? 'waiting_provider'
  }

  // Ecosystem — status follows the participant category.
  switch (attribution.category) {
    case 'browser':
      return 'waiting_browser'
    case 'hardware':
      return 'waiting_hardware'
    case 'standards_body':
    case 'certificate_authority':
      return 'waiting_standards'
    case 'crypto_library':
    case 'runtime':
    case 'operating_system':
      // A shipping library/runtime is adoptable by the customer → ready.
      return attribution.pqRoadmapStatus === 'shipping' ? 'ready' : 'waiting_vendor'
    default:
      return profile?.migrationDependencyStatus ?? 'waiting_vendor'
  }
}

export function migrationDependencyLabel(status: MigrationDependencyStatus): string {
  switch (status) {
    case 'ready':
      return 'Ready'
    case 'blocked':
      return 'Blocked'
    case 'waiting_provider':
      return 'Waiting on Provider'
    case 'waiting_browser':
      return 'Waiting on Browser'
    case 'waiting_vendor':
      return 'Waiting on Vendor'
    case 'waiting_hardware':
      return 'Waiting on Hardware'
    case 'waiting_standards':
      return 'Waiting on Standards'
    default:
      return 'Unknown'
  }
}

const NIST_NODE: DependencyNode = {
  id: 'nist',
  label: 'NIST PQC Standards',
  role: 'standards',
  status: 'complete',
  blocking: false,
  note: 'FIPS 203 (ML-KEM), 204 (ML-DSA) and 205 (SLH-DSA) are finalized.',
}

/** Build the ordered dependency chain and identify the blocking node. */
export function buildDependencyChain(
  status: MigrationDependencyStatus,
  attribution: ProviderAttribution,
  domain: ResponsibilityDomain,
  isTransport: boolean,
): DependencyChain {
  const providerName = attribution.attributed ? attribution.providerName : 'Provider'
  const nodes: DependencyNode[] = []

  const customer: DependencyNode = {
    id: 'customer',
    label: 'Customer Organization',
    role: 'customer',
    status: domain === 'customer' ? 'in_progress' : 'pending',
    blocking: domain === 'customer' && status !== 'ready',
    note:
      domain === 'customer'
        ? 'The organization owns this asset and can execute the migration.'
        : 'The organization can prepare, but a downstream dependency currently gates completion.',
  }
  nodes.push(customer)

  switch (status) {
    case 'ready': {
      if (domain === 'customer') {
        nodes.push({
          id: 'tls-library',
          label: isTransport ? 'TLS Library (customer-deployed)' : 'Crypto Library (customer-deployed)',
          role: 'tls_library',
          status: 'complete',
          blocking: false,
          note: 'A quantum-safe library (e.g. OpenSSL 3.5+) is available for the customer to deploy.',
        })
      } else {
        nodes.push({
          id: attribution.providerId ?? 'provider',
          label: providerName,
          role: 'provider',
          status: 'complete',
          blocking: false,
          note: `${providerName} post-quantum support is available for adoption.`,
        })
      }
      break
    }
    case 'waiting_provider': {
      nodes.push({
        id: attribution.providerId ?? 'provider',
        label: providerName,
        role: 'provider',
        status: 'blocked',
        blocking: true,
        note: `${providerName} manages this cryptographic surface; completion depends on the provider roadmap.`,
      })
      break
    }
    case 'waiting_browser': {
      nodes.push({
        id: attribution.providerId ?? 'browser',
        label: attribution.attributed ? providerName : 'Browser Vendors',
        role: 'browser',
        status: 'blocked',
        blocking: true,
        note: 'End-to-end post-quantum support depends on browser adoption.',
      })
      break
    }
    case 'waiting_hardware': {
      nodes.push({
        id: attribution.providerId ?? 'hardware',
        label: attribution.attributed ? providerName : 'Hardware / Firmware Vendor',
        role: 'hardware',
        status: 'blocked',
        blocking: true,
        note: 'PQC availability depends on device firmware and often a hardware refresh cycle.',
      })
      break
    }
    case 'waiting_standards': {
      nodes.push(
        {
          id: 'certificate-authority',
          label: attribution.category === 'certificate_authority' && attribution.attributed ? providerName : 'Certificate Authority',
          role: 'ca',
          status: 'blocked',
          blocking: false,
          note: 'Public CA post-quantum certificate issuance is gated on standards.',
        },
        {
          id: 'cab-forum',
          label: 'CA/Browser Forum',
          role: 'standards',
          status: 'in_progress',
          blocking: true,
          note: 'PQ certificate profiles are being defined by the CA/Browser Forum.',
        },
      )
      break
    }
    case 'waiting_vendor': {
      nodes.push({
        id: attribution.providerId ?? 'vendor',
        label: attribution.attributed ? providerName : 'Vendor',
        role: 'provider',
        status: 'blocked',
        blocking: true,
        note: `Completion depends on ${providerName}'s post-quantum roadmap.`,
      })
      break
    }
    case 'blocked':
    default: {
      nodes.push({
        id: 'blocker',
        label: attribution.attributed ? providerName : 'Upstream Dependency',
        role: domain === 'ecosystem' ? 'standards' : 'provider',
        status: 'blocked',
        blocking: true,
        note: 'An upstream dependency currently blocks this migration.',
      })
      break
    }
  }

  nodes.push(NIST_NODE)

  const blockingNode = nodes.find((n) => n.blocking) ?? null
  const blockedBy = blockingNode && blockingNode.role !== 'customer' ? blockingNode.label : blockingNode?.role === 'customer' ? null : null

  const summary =
    status === 'ready'
      ? 'No upstream blocker — the customer can execute this migration now.'
      : `Migration is gated on ${blockingNode?.label ?? 'an upstream dependency'} (${migrationDependencyLabel(status)}).`

  return {
    nodes,
    criticalPath: nodes.map((n) => n.id),
    blockedBy,
    migrationDependencyStatus: status,
    summary,
  }
}
