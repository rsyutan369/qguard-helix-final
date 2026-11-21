'use client'

import AuditVault from './AuditVault'
import { useGovernanceAccount } from '@/hooks/use-governance'

export default function AuditVaultPage() {
  const { accountId } = useGovernanceAccount()
  return <AuditVault key={accountId} />
}
