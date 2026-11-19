'use client'

import MigrationPlanner from './MigrationPlanner'
import { useAuth } from '@/contexts/auth-context'

export default function MigrationPlannerPage() {
  const { user } = useAuth()
  return <MigrationPlanner key={user?.id} />
}
