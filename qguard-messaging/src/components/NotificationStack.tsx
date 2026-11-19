import type { ReactNode } from "react";
import IncomingShareNotice from "@/components/IncomingShareNotice";
import MessageAlerts from "@/components/MessageAlerts";
import { useOptionalChatPreferences } from "@/lib/chat-preferences-context";
import { muteUntil } from "@/lib/chat-preferences";
import { useMessageAlerts, type MessageAlert } from "@/lib/use-message-alerts";
import type { PendingShareNotice } from "@/lib/vault-share";
import type { ConversationSummary } from "@/lib/types";

/**
 * The app's in-app notifications, stacked in one place (top right on desktop,
 * under the header on a phone): local transfers, Vault shares, and new messages.
 * Rendered inside ChatPreferencesProvider so mutes and alert settings apply.
 */
export default function NotificationStack({
  userId,
  conversations,
  chatUnlocked,
  showShares,
  showMessages,
  pendingShares,
  transferNotice,
  onRespondShare,
  onViewShares,
  onOpenConversation,
}: {
  userId: string;
  conversations: ConversationSummary[];
  /** Secure Chat is unlocked, so a chat's name may be shown. */
  chatUnlocked: boolean;
  showShares: boolean;
  showMessages: boolean;
  pendingShares: PendingShareNotice[];
  transferNotice?: ReactNode;
  onRespondShare: (shareId: string, accept: boolean) => Promise<void>;
  onViewShares: () => void;
  onOpenConversation: (alert: MessageAlert) => void;
}) {
  const prefs = useOptionalChatPreferences();
  const { alerts, dismiss } = useMessageAlerts(conversations, userId);
  const visibleAlerts = showMessages ? alerts : [];

  if (!transferNotice && !showShares && visibleAlerts.length === 0) return null;
  return (
    <div className="fixed inset-x-3 top-[calc(env(safe-area-inset-top,0px)+104px)] z-[60] flex flex-col gap-2 sm:inset-x-auto sm:right-5 sm:top-[76px] sm:w-[390px]">
      {transferNotice}
      {showShares && <IncomingShareNotice userId={userId} pending={pendingShares} onRespond={onRespondShare} onView={onViewShares} />}
      <MessageAlerts
        alerts={visibleAlerts}
        revealNames={chatUnlocked}
        onOpen={(alert) => {
          dismiss(alert.conversationId);
          onOpenConversation(alert);
        }}
        onMute={(alert) => {
          dismiss(alert.conversationId);
          void prefs?.updateChat(alert.conversationId, alert.peerUserId, { mutedUntil: muteUntil(8 * 60 * 60_000, Date.now()) }).catch(() => undefined);
        }}
        onDismiss={dismiss}
      />
    </div>
  );
}
