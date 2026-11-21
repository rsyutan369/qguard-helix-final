export interface MigrationAssetOption {
  id: string
  name: string
  type: string | null
  environment: string | null
  owner: string | null
}

export interface MigrationAssetRelationship {
  id: string
  assetId: string
  assetName: string
  type: string | null
  direction: 'outgoing' | 'incoming'
  recordedAt: string | null
}

export interface MigrationAssetJob {
  id: string
  name: string
  type: string
  status: string
  target: string | null
  startedAt: string | null
  completedAt: string | null
  updatedAt: string | null
}

export interface MigrationAssetScope extends MigrationAssetOption {
  ownerSource: string | null
  businessService: string | null
  inventoryStatus: string | null
  scanStatus: string | null
  lastScannedAt: string | null
  lastScannedSource: 'evidence' | 'scan-record' | null
  relationships: {
    state: 'available' | 'unavailable' | 'no-record'
    total: number | null
    rows: MigrationAssetRelationship[]
  }
  jobs: {
    state: 'available' | 'unavailable' | 'no-record'
    total: number | null
    rows: MigrationAssetJob[]
  }
}

export interface MigrationIntelligenceCoverage {
  source: 'scanner' | 'partial-scanner' | 'readiness-fallback'
  /** Size of the scanner window before this module's classification limit. */
  scannerFindings: number | null
  readiness: 'assessment' | 'estimate'
  providerConnectorsAvailable: boolean
}
