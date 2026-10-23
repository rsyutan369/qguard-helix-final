export function useSubscription() {
  return { tier: 'pro', loading: false, refresh: async () => undefined } as never
}
