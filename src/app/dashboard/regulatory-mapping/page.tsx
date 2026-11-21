'use client'

import RegulatoryMapping from './RegulatoryMapping'
import { useGovernanceAccount } from '@/hooks/use-governance'

export default function RegulatoryMappingPage() {
  const { accountId } = useGovernanceAccount()
  return <RegulatoryMapping key={accountId} />
}
