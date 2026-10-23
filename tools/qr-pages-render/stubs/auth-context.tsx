import type { ReactNode } from 'react'

// Render-smoke stand-in: a signed-in tenant, no network.
const VALUE = {
  user: { id: '00000000-0000-4000-8000-000000000001', email: 'render-check@example.com' },
  session: { access_token: 'render-check-token' },
  loading: false,
  signIn: async () => undefined,
  signOut: async () => undefined,
}
export function AuthProvider({ children }: { children: ReactNode }) {
  return <>{children}</>
}
export function useAuth() {
  return VALUE as never
}
