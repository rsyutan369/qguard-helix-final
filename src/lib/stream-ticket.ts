/**
 * Open an SSE stream WITHOUT putting the Supabase access token in the URL.
 *
 * The token is sent once, in the Authorization header, to mint a 60-second,
 * single-use ticket bound to this one stream (src/api-server/runtime/
 * stream-tickets.ts); only that opaque ticket appears in the EventSource URL.
 *
 * A ticket is single use, so the browser's own EventSource auto-reconnect
 * (which reuses the URL) cannot work: callers close the source on error and
 * call this again for a fresh ticket.
 */
export type StreamName = 'admin' | 'revenue' | 'profile' | 'billing'

export class StreamTicketError extends Error {
  constructor(message: string, public status: number) {
    super(message)
  }
}

export async function openTicketedEventSource(stream: StreamName, accessToken: string): Promise<EventSource> {
  const response = await fetch('/api/v1/stream-tickets', {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ stream }),
    cache: 'no-store',
  })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok || typeof payload?.data?.ticket !== 'string') {
    throw new StreamTicketError(payload?.error?.message || `Stream ticket refused (HTTP ${response.status})`, response.status)
  }
  return new EventSource(`${payload.data.path}?ticket=${encodeURIComponent(payload.data.ticket)}`)
}
