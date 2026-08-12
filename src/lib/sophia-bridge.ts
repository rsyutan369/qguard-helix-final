/**
 * Sophia bridge — lets any dashboard surface hand a question to the Sophia AI
 * Security Copilot™ dock that DashboardLayout already mounts globally.
 *
 * A browser CustomEvent is used deliberately: the dock owns its own streaming
 * state and tenant context, so pages must not hold a reference to it or
 * duplicate the copilot client. Pages ask; the dock answers with the
 * authenticated tenant's live data.
 */

export const ASK_SOPHIA_EVENT = 'qguard:ask-sophia'

export interface AskSophiaDetail {
  question: string
  /** Optional page context appended to the question for grounding. */
  context?: string
}

/** Opens the Sophia dock and submits `question` against the caller's tenant. */
export function askSophia(question: string, context?: string): void {
  if (typeof window === 'undefined') return
  const trimmed = question.trim()
  if (!trimmed) return
  window.dispatchEvent(new CustomEvent<AskSophiaDetail>(ASK_SOPHIA_EVENT, { detail: { question: trimmed, context } }))
}
