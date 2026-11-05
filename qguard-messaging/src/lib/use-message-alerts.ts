import { useCallback, useEffect, useRef, useState } from "react";
import { isConversationOnScreen } from "@/lib/chat-focus";
import { useOptionalChatPreferences } from "@/lib/chat-preferences-context";
import { playMessageSound } from "@/lib/message-sounds";
import type { ConversationSummary } from "@/lib/types";

type AlertSource = Pick<ConversationSummary, "id" | "title" | "unread_count" | "hidden_at" | "deleted_at" | "conversation_type" | "member_user_ids">;

/**
 * Conversations whose unread count went up since `previous`, and by how much.
 * Hidden and deleted chats never alert (an alert would reveal a hidden chat).
 * The first call (previous = null) only records the counts. Exported for tests.
 */
export function newMessagesSince(previous: Map<string, number> | null, conversations: AlertSource[]): Array<{ conversationId: string; added: number }> {
  if (!previous) return [];
  const out: Array<{ conversationId: string; added: number }> = [];
  for (const conversation of conversations) {
    if (conversation.hidden_at || conversation.deleted_at) continue;
    const before = previous.get(conversation.id) ?? 0;
    if (conversation.unread_count > before) out.push({ conversationId: conversation.id, added: conversation.unread_count - before });
  }
  return out;
}

export interface MessageAlert {
  conversationId: string;
  title: string;
  count: number;
  peerUserId: string | null;
  isGroup: boolean;
  at: number;
}

const ALERT_LIFETIME_MS = 10_000;

/**
 * In-app "new encrypted message" alerts and sounds, driven by the unread counts
 * the dashboard data already keeps live (realtime on message envelopes), so no
 * message is decrypted for it and nothing extra is fetched.
 *
 * A chat that is open on screen, muted, set to no alerts, hidden or deleted
 * makes no alert; muted or "No sound" makes no sound. Alerts only exist while
 * the app is running: there is no push service, so a closed app cannot alert.
 */
export function useMessageAlerts(conversations: AlertSource[], myUserId: string | null): {
  alerts: MessageAlert[];
  dismiss: (conversationId: string) => void;
} {
  const prefs = useOptionalChatPreferences();
  const previous = useRef<Map<string, number> | null>(null);
  const [alerts, setAlerts] = useState<MessageAlert[]>([]);

  useEffect(() => {
    const arrived = newMessagesSince(previous.current, conversations);
    previous.current = new Map(conversations.map((conversation) => [conversation.id, conversation.unread_count]));
    if (arrived.length === 0) return;

    let sound: ReturnType<NonNullable<typeof prefs>["effectiveFor"]>["sound"] | null = null;
    const fresh: MessageAlert[] = [];
    for (const { conversationId, added } of arrived) {
      if (isConversationOnScreen(conversationId)) continue;
      const effective = prefs?.effectiveFor(conversationId) ?? { alert: true, sound: "chime" as const, muted: false, ring: true };
      if (effective.sound !== "none" && sound === null) sound = effective.sound;
      if (!effective.alert) continue;
      const conversation = conversations.find((item) => item.id === conversationId)!;
      const isGroup = conversation.conversation_type !== "direct";
      fresh.push({
        conversationId,
        title: conversation.title,
        count: added,
        peerUserId: isGroup ? null : conversation.member_user_ids.find((id) => id !== myUserId) ?? null,
        isGroup,
        at: Date.now(),
      });
    }
    if (sound) playMessageSound(sound);
    if (fresh.length === 0) return;
    setAlerts((current) => {
      const merged = new Map(current.map((alert) => [alert.conversationId, alert]));
      for (const alert of fresh) {
        const existing = merged.get(alert.conversationId);
        merged.set(alert.conversationId, existing ? { ...alert, count: existing.count + alert.count } : alert);
      }
      // Newest first, at most three on screen.
      return [...merged.values()].sort((a, b) => b.at - a.at).slice(0, 3);
    });
  }, [conversations, myUserId, prefs]);

  // Each alert leaves on its own after a few seconds.
  useEffect(() => {
    if (alerts.length === 0) return undefined;
    const oldest = Math.min(...alerts.map((alert) => alert.at));
    const timer = window.setTimeout(() => {
      setAlerts((current) => current.filter((alert) => Date.now() - alert.at < ALERT_LIFETIME_MS - 50));
    }, Math.max(200, oldest + ALERT_LIFETIME_MS - Date.now()));
    return () => window.clearTimeout(timer);
  }, [alerts]);

  const dismiss = useCallback((conversationId: string) => {
    setAlerts((current) => current.filter((alert) => alert.conversationId !== conversationId));
  }, []);

  return { alerts, dismiss };
}
