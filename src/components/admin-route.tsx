import type { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { ShieldAlert } from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'
import { isOwnerEmail } from '@/lib/admin-access'

export function AdminRoute({ children }: { children: ReactNode }) {
  const location = useLocation()
  const { user, loading } = useAuth()

  if (loading) {
    return (
      <div className="grid min-h-[60vh] place-items-center px-6">
        <div className="q-card px-6 py-4 text-xs font-black uppercase tracking-[0.18em] text-[var(--qg-amber)]">
          Verifying owner session
        </div>
      </div>
    )
  }

  if (!user) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />
  }

  if (!isOwnerEmail(user.email)) {
    return (
      <div className="grid min-h-[70vh] place-items-center px-6">
        <div className="q-card max-w-xl p-8 text-center">
          <div className="mx-auto mb-5 flex h-12 w-12 items-center justify-center rounded-lg border border-red-400/30 bg-red-500/10 text-red-300">
            <ShieldAlert className="h-6 w-6" />
          </div>
          <h1 className="mb-3 text-2xl font-black text-[var(--qg-text-primary)]">Owner Access Required</h1>
          <p className="text-sm leading-6 text-[var(--qg-text-secondary)]">
            This administrator dashboard is restricted to the QGuardHelix application owner.
            Your session remains active for tenant dashboard features, but platform controls are blocked.
          </p>
        </div>
      </div>
    )
  }

  return <>{children}</>
}
