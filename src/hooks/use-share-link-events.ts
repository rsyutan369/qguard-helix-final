import { useState, useEffect, useCallback } from 'react'
import { useAuth } from '@/contexts/auth-context'
import { openAuthenticatedEventStream } from '@/lib/authenticated-event-stream'

/**
 * Real-time security events for vault share links.
 * Listens via Server-Sent Events (SSE).
 */

export interface ShareLinkSecurityEvent {
  type: 'failed_attempt' | 'link_destroyed'
  linkId: string
  fileName: string
  attemptsUsed: number
  remainingAttempts: number
  ip: string
  timestamp: string
}

export function useShareLinkEvents() {
  const { session } = useAuth()
  const [events, setEvents] = useState<ShareLinkSecurityEvent[]>([])

  useEffect(() => {
    if (!session?.access_token) return

    const token = session.access_token
    let closeStream: (() => void) | undefined
    let retry: ReturnType<typeof setTimeout> | undefined

    const handleSecurityEvent = (payload: string) => {
      try {
        const data = JSON.parse(payload) as ShareLinkSecurityEvent
        setEvents((prev) => [data, ...prev])
      } catch (err) {
        console.error('Failed to parse share security event:', err)
      }
    }

    const connect = (attempt = 0) => {
      closeStream = openAuthenticatedEventStream('/api/v1/vault/share/events', token, {
        onOpen: () => { attempt = 0 },
        onEvent: (name, data) => {
          if (name === 'security_alert' || name === 'failed_attempt' || name === 'link_destroyed') {
            handleSecurityEvent(data)
          }
        },
        onError: () => {
          retry = setTimeout(() => connect(attempt + 1), Math.min(60_000, 5_000 * 2 ** Math.min(attempt, 4)))
        },
      })
    }
    connect()

    return () => {
      closeStream?.()
      clearTimeout(retry)
    }
  }, [session?.access_token])

  const dismissEvent = useCallback((index: number) => {
    setEvents((prev) => prev.filter((_, i) => i !== index))
  }, [])

  const dismissAll = useCallback(() => {
    setEvents([])
  }, [])

  return {
    events,
    dismissEvent,
    dismissAll,
  }
}
