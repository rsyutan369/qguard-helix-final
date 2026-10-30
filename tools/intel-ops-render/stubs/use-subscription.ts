export function useSubscription() {
  return { tier: 'pro', loading: false, isActive: true, refresh: async () => undefined } as never
}
