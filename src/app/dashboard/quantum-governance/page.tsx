'use client'

import QuantumGovernanceCenter from './QuantumGovernanceCenter'
import { useGovernanceAccount } from '@/hooks/use-governance'

export default function QuantumGovernancePage() {
  const { accountId } = useGovernanceAccount()
  return <QuantumGovernanceCenter key={accountId} />
}
