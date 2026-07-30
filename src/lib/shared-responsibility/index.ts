/**
 * Shared Responsibility Quantum Migration Intelligence Engine™.
 *
 * Pure, isomorphic ownership-intelligence core. Callers adapt real tenant rows
 * into `OwnershipFindingInput[]` and receive the normalized
 * `SharedResponsibilityIntelligence` aggregate — consumed identically by the
 * scanner, dashboards, Sophia, reporting, certification and the migration
 * planner.
 */

export * from './types'
export { PROVIDER_CATALOG, PROVIDER_BY_ID, CUSTOMER_PROFILE } from './provider-catalog'
export { attributeProvider } from './provider-attribution'
export { classifyEdgeVsOrigin, isTransportFinding } from './tls-intelligence'
export { buildDependencyChain, deriveMigrationDependencyStatus, migrationDependencyLabel } from './dependency-graph'
export { classifyFinding, quickOwnershipTag } from './classify'
export type { OwnershipTag } from './classify'
export { buildSharedResponsibility, canonicalAssetLabel, assetDisplayLabel } from './rollup'
export type { BuildOptions } from './rollup'
