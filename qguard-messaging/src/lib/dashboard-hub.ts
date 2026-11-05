// The dashboard's protected-area cards — Secure Chat, Calls, Quantum Vault,
// Contacts — shared by the phone dashboard (MobileDashboard) and the desktop
// one (DashboardPage), so both offer the same areas, counts and lock rule.
// Opening a card goes through App's `openProtectedArea`, which locks the area
// first: every tap asks for the PIN, password or pattern. Calls and Contacts
// sit behind the Secure Chat lock (who you talk to is conversation metadata).

import { Contact, MessageSquareLock, Phone, Vault, type LucideIcon } from "lucide-react";
import type { ConversationSummary } from "@/lib/types";

export type HubArea = "chat" | "calls" | "vault" | "contacts";

export interface HubEntry {
  route: HubArea;
  icon: LucideIcon;
  title: string;
  caption: string;
  /** The workspace whose lock guards this area. */
  unlocks: "Secure Chat" | "Quantum Vault";
  /** A count to show on the card (0 shows none). */
  badge: number;
  /** What the count is, for screen readers. */
  badgeLabel: "unread" | "missed" | "shared files waiting";
}

/** Unread encrypted messages across visible conversations (the Chats badge). */
export function unreadMessageCount(conversations: Pick<ConversationSummary, "hidden_at" | "deleted_at" | "unread_count">[]): number {
  return conversations
    .filter((conversation) => !conversation.hidden_at && !conversation.deleted_at)
    .reduce((sum, conversation) => sum + conversation.unread_count, 0);
}

export function dashboardHub(unread: number, missedCalls: number, sharedFilesWaiting = 0): HubEntry[] {
  return [
    { route: "chat", icon: MessageSquareLock, title: "Secure Chat", caption: "End-to-end encrypted", unlocks: "Secure Chat", badge: unread, badgeLabel: "unread" },
    {
      route: "calls",
      icon: Phone,
      title: "Calls",
      caption: missedCalls > 0 ? `${missedCalls} missed · voice & video` : "Voice & video",
      unlocks: "Secure Chat",
      badge: missedCalls,
      badgeLabel: "missed",
    },
    {
      route: "vault",
      icon: Vault,
      title: "Quantum Vault",
      caption: sharedFilesWaiting > 0 ? `${sharedFilesWaiting} shared file${sharedFilesWaiting === 1 ? "" : "s"} waiting` : "Your private storage",
      unlocks: "Quantum Vault",
      badge: sharedFilesWaiting,
      badgeLabel: "shared files waiting",
    },
    { route: "contacts", icon: Contact, title: "Contacts", caption: "Manage your network", unlocks: "Secure Chat", badge: 0, badgeLabel: "unread" },
  ];
}

/** The card's accessible name: what it is, its count, and which lock guards it. */
export function hubCardLabel(entry: HubEntry): string {
  const count = entry.badge > 0 ? ` ${entry.badge} ${entry.badgeLabel}.` : "";
  return `${entry.title}: ${entry.caption}.${count} Protected by your ${entry.unlocks} lock.`;
}
