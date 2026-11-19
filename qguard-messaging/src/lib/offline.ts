import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { safeInvoke } from "@/lib/tauri";
import type { Page } from "@/lib/types";

export type OfflinePageId = Extract<Page, "mesh" | "xfer" | "transfer-history" | "offline-settings">;
export type OfflineMode = Extract<OfflinePageId, "mesh" | "xfer">;

export type OfflinePairingDecision = "allow" | "reject" | "confirm" | "cancel";

export interface OfflinePairing {
  id: string;
  peer: string;
  label: string | null;
  platform: string | null;
  capabilities: OfflineMode[];
  requested: OfflineMode[];
  direction: "incoming" | "outgoing";
  status: "requesting" | "awaitingApproval" | "verifying" | "awaitingConfirmation" | "establishing"
    | "trusted" | "rejected" | "cancelled" | "failed" | "expired";
  code: string | null;
  error: string | null;
}

export interface OfflinePeer {
  fingerprint: string;
  label: string | null;
  address: string | null;
  lastSeen: number | null;
  authenticatedAt: number | null;
  trusted: boolean;
  discovery?: ("ble" | "lan" | "manual")[];
  bleMesh?: boolean;
  /** Bluetooth signal strength in dBm while the device is in radio range. */
  rssi?: number | null;
  platform?: string | null;
  pairedAt?: number | null;
  capabilities?: OfflineMode[];
  connected?: boolean;
  blocked?: boolean;
  disconnected?: boolean;
  /** Display name the paired user shared after both confirmed the code. */
  owner?: string | null;
  /** The persistent channel the Rust core holds to this peer, if any. */
  link?: OfflineLink | null;
  /** SHA3-256 digest of this device's profile picture: sent over the
   *  authenticated channel by a trusted peer, or shared before pairing by a
   *  nearby device whose owner turned that on. `offline_avatar` returns it. */
  avatar?: string | null;
  /** A direct Wi-Fi link to this peer, while one is set up or in use. */
  wifiLink?: OfflineWifiLink | null;
}

/** The direct Wi-Fi link XFER sets up when two devices share only Bluetooth. */
export interface OfflineWifiLink {
  state: "requested" | "starting" | "hosting" | "joinPrompt" | "joining" | "manual" | "connected" | "failed" | "declined";
  role: "host" | "join";
  /** Only when this user must join by hand. */
  network?: string;
  passphrase?: string;
  error?: string;
  /** This platform joins by itself once the user agrees. */
  automaticJoin: boolean;
}

/** A persistent Mesh channel, exactly as the native channel registry reports it. */
export interface OfflineLink {
  state: "connected" | "connecting" | "reconnecting";
  transport: "bluetooth" | "lan" | null;
  /** Unix seconds when the current channel opened. */
  since: number | null;
  /** First 16 hex digits of the session binding: identical on both devices. */
  session: string | null;
  rttMs: number | null;
  attempts: number;
}

/** One connection diagnostics entry recorded by the transport and session layers. */
export interface OfflineLinkEvent {
  id: number;
  atMs: number;
  kind: string;
  peer?: string;
  session?: string;
  transport?: "bluetooth" | "lan";
  detail?: string;
}

/** The connection line for a peer, from its channel and discovery state only. */
export function offlineLinkState(peer: OfflinePeer | undefined): { label: string; detail: string | null; tone: "connected" | "pending" | "idle" | "blocked" } {
  if (!peer) return { label: "Not in range", detail: null, tone: "idle" };
  if (peer.blocked) return { label: "Blocked", detail: null, tone: "blocked" };
  if (peer.disconnected) return { label: "Disconnected", detail: "you disconnected this device", tone: "idle" };
  const link = peer.link;
  if (link?.state === "connected") {
    const via = link.transport === "bluetooth" ? "Bluetooth" : "local network";
    return { label: "Connected", detail: link.rttMs != null ? `${via} · ${link.rttMs} ms` : via, tone: "connected" };
  }
  if (link?.state === "reconnecting") return { label: "Reconnecting", detail: link.attempts > 0 ? `attempt ${link.attempts + 1}` : null, tone: "pending" };
  if (link?.state === "connecting") return { label: "Connecting", detail: null, tone: "pending" };
  if (peer.lastSeen != null) return { label: "In range", detail: peer.discovery?.includes("ble") ? "Bluetooth" : "local network", tone: "idle" };
  return { label: "Not in range", detail: null, tone: "idle" };
}

/**
 * Whether a trusted peer may be used for a workflow. Mutual pairings carry
 * the capabilities both users approved; fingerprints pinned before scoped
 * pairing (no `pairedAt`) keep their original access.
 */
export function peerAllows(peer: OfflinePeer, mode: OfflineMode): boolean {
  if (!peer.trusted || peer.blocked) return false;
  return peer.pairedAt == null || (peer.capabilities ?? []).includes(mode);
}

export function offlinePeerName(peer: Pick<OfflinePeer, "owner" | "label" | "fingerprint"> | undefined, fallback: string): string {
  return peer?.owner || peer?.label || fallback;
}

export interface SmartConnectStatus {
  bluetoothAvailable: boolean;
  bluetoothPermissionGranted: boolean;
  bluetoothRunning: boolean;
  bluetoothScanning: boolean;
  bluetoothAdvertising: boolean;
  bluetoothError: string | null;
  hotspotAvailable: boolean;
  hotspotActive: boolean;
  hotspotStarting?: boolean;
  hotspotError?: string | null;
}

export interface OfflineStatus {
  running: boolean;
  lanDiscoveryRunning: boolean;
  autoStart: boolean;
  fingerprint: string;
  port: number | null;
  peers: OfflinePeer[];
  networkError: string | null;
  platform: string;
  smartConnect?: SmartConnectStatus;
  localOwner?: string | null;
  /** Whether this device can open Mesh and XFER for this account without internet. */
  offlineAccess?: OfflineAccess;
  /** Keep Mesh running while Qguard is locked or in the background. */
  background?: boolean;
  /** Carry sealed Mesh messages for trusted devices (multi-hop). */
  relay?: boolean;
  /** Sealed messages this device is carrying for others right now. */
  relayCarrying?: number;
  /** SHA3-256 digest of this account picture as shared with trusted devices. */
  localAvatar?: string | null;
  /** Show this account's picture to nearby devices before pairing (opt-in). */
  sharePictureNearby?: boolean;
}

export interface OfflineAccess {
  enrolled: boolean;
  /** Unix seconds; renewed on every online sign-in. */
  offlineUntil: number | null;
  /** Desktop: the account password signs in offline. */
  passwordSignIn: boolean;
}

export interface MeshMessage {
  id: string;
  sender: string;
  recipients: string[];
  body: string;
  group: string | null;
  emergency: boolean;
  createdAt: number;
  expiresAt: number;
  direction: "incoming" | "outgoing";
  status: "pending" | "delivered" | "expired";
  deliveredTo: string[];
  receivedAt?: number | null;
  readAt?: number | null;
  /** Recipients a sealed copy was handed to relays for (multi-hop Mesh). */
  relayedTo?: string[];
}

/** Wording for an outgoing message that is still waiting for receipts. */
export function meshPendingLabel(message: Pick<MeshMessage, "relayedTo">): string {
  return message.relayedTo?.length ? "Relayed, awaiting delivery" : "Queued for delivery";
}

/** An unread incoming Mesh message for the in-app notice. */
export interface MeshNotice {
  id: string;
  sender: string;
  senderName: string | null;
  preview: string;
  group: string | null;
  emergency: boolean;
  receivedAt: number;
}

/** The suite every Mesh message travels under (session v1, LAN and BLE). */
export const MESH_SUITE = {
  keyEstablishment: "ML-KEM-768 + X25519",
  signatures: "ML-DSA-65 + Ed25519",
  encryption: "AES-256-GCM",
  integrity: "SHA3-256",
} as const;

export type TransferStatus = "awaitingConsent" | "queued" | "active" | "paused" | "stopped" | "interrupted" | "verified" | "rejected" | "cancelled" | "expired" | "failed";

export type TransferFailure = "connectionLost" | "peerUnavailable" | "storageFull" | "fileWrite" | "encryption" | "integrity" | "timeout" | "interrupted";

export interface OfflineTransferIdentity {
  displayName?: string | null;
  deviceName?: string | null;
  avatarUrl?: string | null;
}

export interface OfflineTransferSecurity {
  phase: "initializing" | "keyEstablishment" | "payloadEncryption" | "secureTransfer" | "integrityVerification" | "verified" | "error";
  mode: string | null;
  keyEstablishment: string | null;
  signatures: string | null;
  encryption: string | null;
  integrity: string | null;
}

export interface OfflineTransfer {
  id: string;
  direction: "incoming" | "outgoing";
  sender: string;
  recipient: string;
  files: {
    name: string; size: number; destination?: string | null; verifiedBytes?: number; payloadComplete?: boolean; verified?: boolean;
    canOpenFile?: boolean; canOpenFolder?: boolean;
    /** SHA3-256 digest from the authenticated manifest, lowercase hex. */
    digest?: string;
  }[];
  status: TransferStatus;
  verifiedBytes: number;
  totalBytes: number;
  createdAt: number;
  expiresAt: number;
  localCopyRetained: boolean;
  bytesPerSecond: number | null;
  error: string | null;
  errorKind?: TransferFailure | null;
  /** Sender only: the receiver's answer to an offer sent over Bluetooth. */
  channelOffer?: "awaiting" | "accepted" | "declined" | "complete" | "integrityFailed" | null;
  security?: OfflineTransferSecurity | null;
  folderName?: string | null;
  verifiedFiles?: number;
  currentFile?: number | null;
  revision?: number;
  startedAtMs?: number | null;
  completedAtMs?: number | null;
  elapsedMs?: number | null;
  updatedAt?: number | null;
  averageBytesPerSecond?: number | null;
  throughput?: { atMs: number; bytesPerSecond: number }[];
  controlSyncPending?: boolean;
  localHold?: "pause" | "stop" | null;
  remoteHold?: "pause" | "stop" | null;
  /** First 64 bits of the authenticated session binding; identical on both devices. */
  sessionId?: string | null;
}

interface DashboardSnapshot {
  status: OfflineStatus;
  messages: MeshMessage[] | null;
  transfers: OfflineTransfer[] | null;
}

/** A reported Bluetooth signal reading, e.g. "strong signal, -58 dBm". */
export function offlineSignalLabel(rssi: number | null | undefined): string | null {
  if (rssi == null || !Number.isFinite(rssi)) return null;
  const quality = rssi >= -60 ? "strong" : rssi >= -75 ? "good" : rssi >= -88 ? "weak" : "very weak";
  return `${quality} signal, ${Math.round(rssi)} dBm`;
}

export function offlineError(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  return "The local service could not complete this action. Try again.";
}

export function formatOfflineTime(timestamp: number): string {
  return new Date(timestamp * 1000).toLocaleString();
}

export function formatOfflineBytes(bytes: number): string {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let amount = bytes;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: unit > 0 ? 1 : 0 }).format(amount)} ${units[unit]}`;
}

const OFFLINE_CHANGED_EVENT = "offline:changed";
const READ_TIMEOUT_MS = 12_000;
// Failures that mean this view may no longer show the account's records.
const AUTHORIZATION_LOST = /OFFLINE_PRINCIPAL|account|authoriz|trust error|no longer|session has ended|sign in|unlock/i;

// The Rust event carries no account data. Each event asks the view to re-read
// its authorized snapshot through IPC, with polling as a missed-event fallback.
export function useOfflineFeed<T>(read: () => Promise<T>, pollMs: number, enabled = true) {
  const [result, setResult] = useState<{ read: typeof read; value: T | null; error: string | null } | null>(null);
  const refreshRef = useRef(() => {});
  const refresh = useCallback(() => refreshRef.current(), []);

  useEffect(() => {
    if (!enabled) return;
    let disposed = false;
    let fetching = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let deadline: ReturnType<typeof setTimeout> | undefined;
    let queued = false;
    let unlisten: (() => void) | undefined;

    function schedule() {
      if (disposed || timer !== undefined) return;
      if (fetching) {
        queued = true;
        return;
      }
      timer = setTimeout(() => {
        timer = undefined;
        void load();
      }, 180);
    }

    async function load() {
      fetching = true;
      // IPC cannot be cancelled by the webview, so a slow read stays in flight
      // (no stacked native reads). A slow or failed read keeps the last good
      // snapshot on screen and only adds a notice. Dropping it used to unmount
      // the whole workspace, which threw an open conversation or a running
      // transfer back to the discovery radar whenever one read was slow (the
      // transfer engine holds the store while it writes a chunk).
      const keep = (error: string) => setResult((current) => ({
        read,
        value: current?.read === read ? current.value : null,
        error,
      }));
      deadline = setTimeout(() => {
        if (!disposed) keep("Local status is taking longer to update. Waiting for Qguard.");
      }, READ_TIMEOUT_MS);
      try {
        const value = await read();
        if (!disposed) setResult({ read, value, error: null });
      } catch (failure) {
        const message = offlineError(failure);
        // Lost authorization must take the records off screen at once. Only a
        // transient failure keeps the last good snapshot.
        if (disposed) return;
        if (AUTHORIZATION_LOST.test(message)) setResult({ read, value: null, error: message });
        else keep(message);
      } finally {
        clearTimeout(deadline);
        fetching = false;
        if (queued) {
          queued = false;
          schedule();
        }
      }
    }

    const resume = () => {
      if (!document.hidden) schedule();
    };
    refreshRef.current = schedule;
    void listen(OFFLINE_CHANGED_EVENT, schedule).then((unsubscribe) => {
      if (disposed) unsubscribe();
      else {
        unlisten = unsubscribe;
        // Reconcile a change that arrived before the listener was installed.
        schedule();
      }
    }).catch(() => {
      // The periodic read also recovers state if the native event bridge disconnects.
    });
    document.addEventListener("visibilitychange", resume);
    window.addEventListener("focus", resume);
    void load();
    const interval = setInterval(schedule, pollMs);
    return () => {
      disposed = true;
      document.removeEventListener("visibilitychange", resume);
      window.removeEventListener("focus", resume);
      unlisten?.();
      clearTimeout(timer);
      clearTimeout(deadline);
      clearInterval(interval);
      refreshRef.current = () => {};
    };
  }, [enabled, pollMs, read]);

  const current = enabled && result?.read === read ? result : null;
  return { value: current?.value ?? null, error: current?.error ?? null, refresh };
}

export function useOfflineSnapshot(page: OfflinePageId, accountId: string) {
  const read = useCallback(() => safeInvoke<DashboardSnapshot>(
    "offline_dashboard_snapshot", { page, expectedAccount: accountId },
  ), [accountId, page]);
  const { value, error, refresh } = useOfflineFeed(read, 15_000);

  useEffect(() => {
    if (!value) return;
    const expiry = Math.min(
      ...(value.messages ?? []).filter(({ status }) => status === "pending").map(({ expiresAt }) => expiresAt),
      ...(value.transfers ?? []).filter(({ status, localCopyRetained }) => (
        localCopyRetained || status === "awaitingConsent" || status === "queued" || status === "active" || status === "paused" || status === "stopped" || status === "interrupted"
      )).map(({ expiresAt }) => expiresAt),
    );
    if (!Number.isFinite(expiry)) return;
    const timer = setTimeout(refresh, Math.max(250, expiry * 1000 - Date.now()));
    return () => clearTimeout(timer);
  }, [refresh, value]);

  return {
    status: value?.status ?? null,
    messages: value?.messages ?? null,
    transfers: value?.transfers ?? null,
    error,
    refresh,
  };
}
