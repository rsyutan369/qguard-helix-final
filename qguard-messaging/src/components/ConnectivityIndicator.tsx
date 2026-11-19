import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, Archive, Cloud, LockKeyhole, Network, Radio } from "lucide-react";
import { nearbyStatus } from "@/lib/nearby";
import { useOfflineFeed } from "@/lib/offline";
import type { RelayAvailability } from "@/lib/relay-health";
import { isAndroidRuntime, isTauriRuntime, safeInvoke } from "@/lib/tauri";

interface LocalConnectivity {
  activeAuthenticatedPeers: number;
  pendingMessages: number;
  discoveryRunning: boolean;
}

function useLocalConnectivity(accountId: string) {
  const read = useCallback(() => safeInvoke<LocalConnectivity>("offline_connectivity", { expectedAccount: accountId }), [accountId]);
  const { value: local } = useOfflineFeed(read, 5_000, isTauriRuntime());
  const [nearbyPeers, setNearbyPeers] = useState(0);

  useEffect(() => {
    if (!isAndroidRuntime()) return;
    let disposed = false;
    const refreshNearby = async () => {
      const next = await nearbyStatus();
      if (!disposed) setNearbyPeers(next.running ? next.peers : 0);
    };
    void refreshNearby();
    const nearbyTimer = setInterval(() => void refreshNearby(), 5_000);
    return () => {
      disposed = true;
      clearInterval(nearbyTimer);
    };
  }, []);

  return { local, nearbyPeers };
}

export function ConnectivityIndicator({ accountId, relay, outboxCount, vaultUnlocked, showAlways = false }: {
  accountId: string; relay: RelayAvailability; outboxCount: number; vaultUnlocked: boolean;
  /** Settings screens always show the strip; elsewhere it appears only while Mesh/XFER is in use. */
  showAlways?: boolean;
}) {
  const { local, nearbyPeers } = useLocalConnectivity(accountId);
  const localAuthorized = local !== null;
  const [automaticError, setAutomaticError] = useState<string | null>(null);
  useEffect(() => {
    if (!localAuthorized || relay === "unknown" || !isTauriRuntime()) return;
    let disposed = false;
    setAutomaticError(null);
    void safeInvoke("offline_relay_state", { unavailable: relay === "unavailable", expectedAccount: accountId }).then(
      () => { if (!disposed) setAutomaticError(null); },
      (error: unknown) => { if (!disposed) setAutomaticError(error instanceof Error ? error.message : String(error)); },
    );
    return () => { disposed = true; };
  }, [accountId, localAuthorized, relay]);
  const pending = outboxCount + (local?.pendingMessages ?? 0);
  const authenticated = local?.activeAuthenticatedPeers ?? 0;
  const authenticatedLabel = `${authenticated} authenticated local ${authenticated === 1 ? "peer" : "peers"}`;
  const chip = "inline-flex items-center gap-1.5 rounded-md border border-line bg-canvas px-2 py-1 text-xs font-bold text-ink-800";

  const showAutomaticError = automaticError !== null && localAuthorized && relay !== "unknown";
  // A reachable relay is the normal state and needs no banner. The strip only
  // appears when there is something to report; this component stays mounted
  // either way because the effect above drives automatic local recovery.
  // Outside Settings the relay/vault chips stay hidden unless the offline
  // Mesh/XFER transport is actually in use (peers, discovery or Nearby).
  const offgridInUse = authenticated > 0 || local?.discoveryRunning === true || nearbyPeers > 0;
  if (!showAlways && !offgridInUse) return null;
  const hasContent = relay === "unavailable" || authenticated > 0 || local?.discoveryRunning === true
    || nearbyPeers > 0 || pending > 0 || vaultUnlocked || showAutomaticError;
  if (!hasContent) return null;

  return <div aria-label="Connectivity and local services" role="status" className="flex flex-wrap gap-1.5 border-b border-line bg-white/75 px-3 py-2 sm:px-5">
    {relay === "unavailable" && <span className={chip}><Cloud size={14} aria-hidden /> RELAY UNAVAILABLE</span>}
    {authenticated > 0 ? <span className={chip}>
      <Network size={14} aria-hidden /> OFFGRID MESH <span className="font-normal">· {authenticatedLabel}</span>
    </span> : local?.discoveryRunning ? <span className={chip}><Radio size={14} aria-hidden /> LOCAL DISCOVERY</span> : null}
    {nearbyPeers > 0 && <span className={chip}><Radio size={14} aria-hidden /> ANDROID NEARBY · {nearbyPeers}</span>}
    {pending > 0 && <span className={chip} title="Messages waiting in the encrypted device queues"><Archive size={14} aria-hidden /> STORE &amp; FORWARD · {pending}</span>}
    {vaultUnlocked && <span className={chip} title="Quantum Vault is unlocked on this device"><LockKeyhole size={14} aria-hidden /> LOCAL VAULT</span>}
    {showAutomaticError && <span className={chip} title={automaticError ?? undefined}><AlertTriangle size={14} aria-hidden /> Check offline settings</span>}
  </div>;
}
