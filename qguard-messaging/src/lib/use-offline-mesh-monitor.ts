import { useCallback, useState } from "react";
import { useOfflineFeed, type MeshNotice } from "@/lib/offline";
import { safeInvoke } from "@/lib/tauri";

export type MeshMessageRef = Pick<MeshNotice, "id" | "sender">;

/**
 * Unread incoming Mesh messages, refreshed on every native `offline:changed`
 * event (real time) with a polling fallback. Opening or dismissing a notice
 * marks it read in the sealed native ledger, so it does not return after a
 * restart; the local hide keeps the screen responsive while that lands.
 */
export function useOfflineMeshMonitor({ accountId, enabled }: { accountId: string | undefined; enabled: boolean }) {
  const scoped = enabled ? accountId : undefined;
  const read = useCallback(
    () => safeInvoke<MeshNotice[]>("offline_mesh_monitor", { expectedAccount: scoped }),
    [scoped],
  );
  const { value, refresh } = useOfflineFeed(read, 15_000, Boolean(scoped));
  const [hidden, setHidden] = useState<{ accountId: string; keys: ReadonlySet<string> } | null>(null);
  const hiddenKeys = hidden && hidden.accountId === accountId ? hidden.keys : undefined;

  const markRead = useCallback(async (messages: MeshMessageRef[]) => {
    if (!accountId || !enabled || messages.length === 0) return;
    setHidden((previous) => {
      const keys = new Set(previous?.accountId === accountId ? previous.keys : []);
      for (const message of messages) keys.add(`${message.sender}:${message.id}`);
      return { accountId, keys };
    });
    await safeInvoke("offline_mesh_mark_read", {
      messages: messages.map(({ id, sender }) => ({ id, sender })),
      expectedAccount: accountId,
    }).catch(() => undefined);
    refresh();
  }, [accountId, enabled, refresh]);

  const notices = enabled && value
    ? value.filter((notice) => !hiddenKeys?.has(`${notice.sender}:${notice.id}`))
    : [];
  return { notices, markRead };
}
