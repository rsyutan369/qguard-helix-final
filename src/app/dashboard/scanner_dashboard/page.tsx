'use client'

import { Navigate, useSearchParams } from 'react-router-dom'
import ScannerDashboard from './ScannerDashboard'

/**
 * Old Scanner tabs that now live on the Agents Collector page, and the section
 * each one lands on there.
 */
const MOVED_TABS: Record<string, string> = {
  agents: '/dashboard/agents',
  'agent-collector': '/dashboard/agents',
  'agent-collector-scanners': '/dashboard/agents',
  collector: '/dashboard/agents',
  settings: '/dashboard/agents?view=settings',
}

export default function ScannerDashboardPage() {
  const [searchParams] = useSearchParams()
  // Bookmarks and links into the retired tabs land on the new page.
  const moved = MOVED_TABS[(searchParams.get('tab') || '').trim().toLowerCase()]
  if (moved) return <Navigate to={moved} replace />
  return <ScannerDashboard />
}
