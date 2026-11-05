/**
 * Which conversation is on screen in Secure Chat, and requests from outside
 * Secure Chat to open one (the new-message alert's "Open").
 *
 * The alert must not ring for the chat you are reading; Secure Chat publishes
 * the open conversation here. And "Open" can be pressed while Secure Chat is
 * not mounted (another page, or behind its lock), so the request is kept until
 * Secure Chat takes it — the same pattern as vault-nav.ts.
 */

let focusedConversationId: string | null = null;

export function setFocusedConversation(conversationId: string | null): void {
  focusedConversationId = conversationId;
}

/** The conversation being read right now: open in Secure Chat and the app visible. */
export function isConversationOnScreen(conversationId: string): boolean {
  return focusedConversationId === conversationId && document.visibilityState === "visible" && document.hasFocus();
}

const OPEN_EVENT = "qguard:open-conversation";
let pendingOpen: string | null = null;

export function requestOpenConversation(conversationId: string): void {
  pendingOpen = conversationId;
  window.dispatchEvent(new CustomEvent<string>(OPEN_EVENT, { detail: conversationId }));
}

export function takeRequestedConversation(): string | null {
  const id = pendingOpen;
  pendingOpen = null;
  return id;
}

export function onOpenConversationRequest(listener: (conversationId: string) => void): () => void {
  const handler = () => {
    const id = takeRequestedConversation();
    if (id) listener(id);
  };
  window.addEventListener(OPEN_EVENT, handler);
  return () => window.removeEventListener(OPEN_EVENT, handler);
}
