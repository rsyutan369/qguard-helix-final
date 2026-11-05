import { useCallback, useEffect, useRef, useState } from "react";
import { supabase } from "@/lib/supabase";
import { listPendingShareNotices, respondToShare, type PendingShareNotice } from "@/lib/vault-share";

/**
 * Files other people shared with this account that still wait for Accept /
 * Decline — the source of the app-wide "someone sent you a file" notice and of
 * the Quantum Vault badges.
 *
 * Live: `qv_share_recipients` is in the supabase_realtime publication
 * (migration 049) and its RLS shows a recipient only their own rows, so a new
 * share, or one revoked by its sender, re-loads the list at once. Realtime is
 * the fast path, not the only one: the list is also re-read every minute, when
 * the window regains focus and when the device comes back online.
 */
export function useIncomingShares(userId: string | null): {
  pending: PendingShareNotice[];
  respond: (shareId: string, accept: boolean) => Promise<void>;
  refresh: () => Promise<void>;
} {
  const [pending, setPending] = useState<PendingShareNotice[]>([]);
  const inFlight = useRef(false);

  const refresh = useCallback(async () => {
    if (!userId || inFlight.current) return;
    inFlight.current = true;
    try {
      setPending(await listPendingShareNotices(userId));
    } catch {
      // Keep the last known list: a dropped connection must not hide a
      // waiting file or flash the badge to zero.
    } finally {
      inFlight.current = false;
    }
  }, [userId]);

  useEffect(() => {
    setPending([]);
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!userId) return undefined;
    const channel = supabase
      .channel(`qv-share-inbox-${userId}`)
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "qv_share_recipients", filter: `recipient_user_id=eq.${userId}` },
        () => void refresh(),
      )
      .subscribe();
    const interval = window.setInterval(() => void refresh(), 60_000);
    const onWake = () => void refresh();
    window.addEventListener("focus", onWake);
    window.addEventListener("online", onWake);
    return () => {
      void supabase.removeChannel(channel);
      window.clearInterval(interval);
      window.removeEventListener("focus", onWake);
      window.removeEventListener("online", onWake);
    };
  }, [userId, refresh]);

  const respond = useCallback(
    async (shareId: string, accept: boolean) => {
      await respondToShare(shareId, accept);
      // Drop it right away; the realtime UPDATE and the re-read confirm it.
      setPending((current) => current.filter((notice) => notice.shareId !== shareId));
      void refresh();
    },
    [refresh],
  );

  return { pending, respond, refresh };
}
