/**
 * A Server-Sent Events reader that authenticates with the Authorization header.
 *
 * The browser's `EventSource` cannot set request headers, so every stream that
 * used it carried the Supabase access token in the URL (`?token=…`). A token in
 * a URL is written to browser history, reverse-proxy logs and server access
 * logs, and survives there long after the session it belongs to. This reads the
 * same `text/event-stream` body with `fetch()` instead, so the token travels
 * where the rest of the API expects it.
 *
 * Behavioural contract, matched to what callers relied on from `EventSource`:
 *  • `onEvent(name, data)` is called once per named frame with the raw `data:`
 *    payload (multi-line data joined with "\n"). Comment frames — heartbeats —
 *    are dropped.
 *  • `onError` is called at most once, when the stream fails OR ends. There is
 *    no built-in reconnect: the caller owns its retry and fallback policy.
 *  • The returned function closes the stream. After it runs, neither callback
 *    fires again.
 */
export interface AuthenticatedEventStreamHandlers {
  onEvent: (name: string, data: string) => void
  /** The stream failed to open, broke, or the server ended it. */
  onError: (error: Error) => void
  /** The response arrived with a 2xx status and a readable body. */
  onOpen?: () => void
}

export function openAuthenticatedEventStream(
  url: string,
  token: string,
  handlers: AuthenticatedEventStreamHandlers,
): () => void {
  const controller = new AbortController()
  let closed = false

  const dispatch = (frame: string) => {
    let name = 'message'
    const lines: string[] = []
    for (const line of frame.split('\n')) {
      if (line.startsWith('event:')) name = line.slice(6).trim()
      else if (line.startsWith('data:')) lines.push(line.slice(5).replace(/^ /, ''))
    }
    if (lines.length && !closed) handlers.onEvent(name, lines.join('\n'))
  }

  void (async () => {
    try {
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' },
        signal: controller.signal,
        cache: 'no-store',
      })
      if (!response.ok || !response.body) throw new Error(`Stream responded ${response.status}`)
      if (!closed) handlers.onOpen?.()
      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      for (;;) {
        const { value, done } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, '\n')
        let boundary = buffer.indexOf('\n\n')
        while (boundary !== -1) {
          dispatch(buffer.slice(0, boundary))
          buffer = buffer.slice(boundary + 2)
          boundary = buffer.indexOf('\n\n')
        }
      }
      throw new Error('Stream ended')
    } catch (error) {
      if (closed || controller.signal.aborted) return
      closed = true
      handlers.onError(error instanceof Error ? error : new Error('Stream failed'))
    }
  })()

  return () => {
    closed = true
    controller.abort()
  }
}
