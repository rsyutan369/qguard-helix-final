'use client'

import ComplianceCommandCenter from './ComplianceCommandCenter'
import { useGovernanceAccount } from '@/hooks/use-governance'

export default function CompliancePage() {
  const { accountId } = useGovernanceAccount()
  return <ComplianceCommandCenter key={accountId} />
}
