import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import {
  ArrowDownToLine, ArrowLeft, ArrowLeftRight, Bluetooth, ChevronDown, ChevronRight, FolderPlus, History,
  ExternalLink, FileUp, FolderOpen, Inbox, LockKeyhole, MonitorSmartphone, Network, Pause, Play, Plus, Radio, Reply, RotateCcw, ShieldCheck, SlidersHorizontal, Square, Wifi, X,
} from "lucide-react";
import { QueueHeading, RadarConsole, TransferBar, TransferFileIcon } from "@/components/offline/OfflineDashboard";
import { XferTransferDashboard } from "@/components/offline/XferTransferDashboard";
import { MeshConversation } from "@/components/offline/MeshConversation";
import { LinkDiagnostics } from "@/components/offline/LinkDiagnostics";
import { PeerPicture } from "@/components/offline/PeerPicture";
import { WifiLinkCard } from "@/components/offline/WifiLinkCard";
import { OfflineAccountContext } from "@/lib/offline-avatars";
import { offlinePairingPlatform } from "@/components/offline/OfflinePairingDialog";
import { safeInvoke } from "@/lib/tauri";
import { ask } from "@/lib/tauri-dialog";
import { withNativeDialog } from "@/lib/native-dialog-guard";
import type { RelayAvailability } from "@/lib/relay-health";
import {
  formatOfflineBytes, formatOfflineTime, MESH_SUITE, meshPendingLabel, offlineError, offlineLinkState, offlinePeerName, peerAllows, useOfflineSnapshot,
  type MeshMessage, type OfflineMode, type OfflinePageId, type OfflinePeer, type OfflineStatus, type OfflineTransfer, type OfflineTransferIdentity,
} from "@/lib/offline";
import type { Page } from "@/lib/types";
import "@/components/offline/offline-guided-flow.css";

const button = "focus-ring inline-flex min-h-12 items-center justify-center gap-2 rounded-lg border border-line bg-white px-4 py-2 text-sm font-semibold text-ink-700 transition-colors hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50";
const primary = "focus-ring inline-flex min-h-12 items-center justify-center gap-2 rounded-lg bg-violet-700 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-violet-800 disabled:cursor-not-allowed disabled:opacity-50";
const field = "focus-ring min-h-12 w-full rounded-lg border border-line bg-white px-3 py-2 text-sm text-ink-950";
const muted = "text-sm leading-relaxed text-ink-600";

const sections = {
  mesh: { label: "Mesh", icon: Network, title: "Nearby messaging", note: "Send or queue messages for trusted nearby devices." },
  xfer: { label: "XFER", icon: ArrowLeftRight, title: "Local file transfer", note: "Offer files to a trusted device. The recipient reviews each offer before receiving any file data." },
  "transfer-history": { label: "History", icon: History, title: "Transfer history", note: "Review transfer receipts, find verified files, or recover an interrupted transfer." },
  "offline-settings": { label: "Offline settings", icon: SlidersHorizontal, title: "Nearby access & trust", note: "Manage offline discovery and the devices you trust for Mesh and XFER." },
};

const transferLabels: Record<OfflineTransfer["status"], string> = {
  awaitingConsent: "Awaiting consent",
  queued: "Queued",
  active: "Transferring",
  paused: "Paused",
  stopped: "Stopped",
  interrupted: "Interrupted",
  verified: "Integrity verified",
  rejected: "Declined",
  cancelled: "Cancelled",
  expired: "Expired",
  failed: "Failed",
};

type RunAction = (task: () => Promise<unknown>, result?: string, pending?: string) => Promise<boolean>;
type DiscoveryAction = () => void;
interface PickedSources {
  token: string;
  names: string[];
  totalBytes?: number | null;
}

function Panel({ title, children, dashboard = false, id }: {
  title: string; children: ReactNode; dashboard?: boolean; id?: string;
}) {
  return <section id={id} tabIndex={id ? -1 : undefined}
    className={`${dashboard ? "offline-surface" : "shell-card p-4 sm:p-5"} min-w-0 space-y-4 focus-ring`}>
    <h3 className="text-base font-bold text-ink-950">{title}</h3>
    {children}
  </section>;
}

function FingerprintText({ value }: { value: string }) {
  return <code className="block select-all break-all rounded-md bg-canvas px-3 py-2 font-mono text-xs leading-relaxed text-ink-800">{value}</code>;
}

const capabilityNames: Record<OfflineMode, string> = { mesh: "Mesh messaging", xfer: "XFER file transfer" };

function DeviceLabel({ peer }: { peer: OfflinePeer }) {
  return <span className="min-w-0">
    <span className="block break-words text-sm font-bold text-ink-950">{offlinePeerName(peer, "Nearby device")}</span>
    {peer.owner && peer.label && <span className="block break-words text-xs text-ink-600">{peer.label}</span>}
    <span className="block break-words text-xs text-ink-600">
      {peer.authenticatedAt
        ? `Last authenticated ${formatOfflineTime(peer.authenticatedAt)}`
        : peer.trusted ? "Fingerprint pinned · awaiting authentication" : "Discovered · verification required"}
    </span>
    {peer.bleMesh && <span className="block text-xs text-ink-600">Bluetooth messaging advertised</span>}
  </span>;
}

function HotspotCredentials({ run, busy }: { run: RunAction; busy: boolean }) {
  const [details, setDetails] = useState<{ ssid: string; password: string } | null>(null);
  useEffect(() => {
    const hideWhenBackgrounded = () => { if (document.hidden) setDetails(null); };
    document.addEventListener("visibilitychange", hideWhenBackgrounded);
    return () => document.removeEventListener("visibilitychange", hideWhenBackgrounded);
  }, []);

  function toggle() {
    if (details) {
      setDetails(null);
      return;
    }
    void run(async () => {
      const credentials = await safeInvoke<{ ssid: string; password: string } | null>("offline_hotspot_details");
      if (!credentials) throw new Error("Hotspot details are unavailable. Refresh the local status and try again.");
      if (!document.hidden) setDetails(credentials);
    });
  }

  return <div className="space-y-2">
    <button type="button" className={button} disabled={busy} aria-expanded={Boolean(details)} onClick={toggle}>
      {details ? "Hide hotspot details" : "Show hotspot details"}
    </button>
    {details && <dl className="grid gap-2 rounded-lg bg-canvas p-3 text-sm text-ink-800 sm:grid-cols-2">
      <div className="min-w-0"><dt className="font-semibold">Wi-Fi network</dt><dd className="select-all break-all font-mono">{details.ssid}</dd></div>
      <div className="min-w-0"><dt className="font-semibold">Wi-Fi password</dt><dd className="select-all break-all font-mono">{details.password}</dd></div>
    </dl>}
  </div>;
}

function SmartConnectPanel({ status, run, busy }: {
  status: OfflineStatus; run: RunAction; busy: boolean;
}) {
  const smart = status.smartConnect;
  if (!smart) return null;

  const nearby = status.peers.filter((peer) => peer.lastSeen !== null && peer.discovery?.includes("ble")).length;
  const needsBluetoothPermission = status.platform === "android" && !smart.bluetoothPermissionGranted;
  const bluetoothState = !status.running ? "Start local discovery to check Bluetooth"
    : !smart.bluetoothAvailable ? "Bluetooth discovery unavailable"
    : needsBluetoothPermission ? "Bluetooth permission required"
    : smart.bluetoothScanning ? `Bluetooth scanning · ${nearby} nearby ${nearby === 1 ? "device" : "devices"}`
    : smart.bluetoothAdvertising ? "Bluetooth advertising is active"
    : "Bluetooth discovery stopped";
  const requestPermission = status.running && smart.bluetoothAvailable && needsBluetoothPermission;
  const retryBluetooth = status.running && smart.bluetoothAvailable && !needsBluetoothPermission && !smart.bluetoothScanning;

  return <Panel title="Helix Smart Connect">
    <dl className="grid gap-3 sm:grid-cols-3">
      <div className="min-w-0 space-y-1 rounded-lg border border-line p-3">
        <dt className="flex items-center gap-2 text-sm font-bold text-ink-950"><Bluetooth className="shrink-0 text-violet-600" size={18} aria-hidden /> Find nearby devices</dt>
        <dd aria-live="polite" aria-atomic="true" className={muted}>{bluetoothState}</dd>
      </div>
      <div className="min-w-0 space-y-1 rounded-lg border border-line p-3">
        <dt className="flex items-center gap-2 text-sm font-bold text-ink-950"><Wifi className="shrink-0 text-violet-600" size={18} aria-hidden /> Find a local link</dt>
        <dd aria-live="polite" aria-atomic="true" className={muted}>{smart.hotspotStarting ? "Waiting for system hotspot…" : smart.hotspotActive ? "Temporary hotspot active" : status.running ? "Listening for local connections" : "Local listener stopped"}</dd>
      </div>
      <div className="min-w-0 space-y-1 rounded-lg border border-line p-3">
        <dt className="flex items-center gap-2 text-sm font-bold text-ink-950"><ShieldCheck className="shrink-0 text-violet-600" size={18} aria-hidden /> Authenticate with QHCE</dt>
        <dd className={muted}>Compare fingerprints before pinning. Qguard authenticates the peer when opening a session.</dd>
      </div>
    </dl>
    <p className={muted}>For file transfers, connect both devices to a shared Wi-Fi network or hotspot. The local link works without internet while your verified account session is valid.</p>
    {smart.bluetoothError && <p className="break-words text-sm text-ink-800">{smart.bluetoothError}</p>}
    {(requestPermission || retryBluetooth) && <div className="flex flex-wrap gap-2">
      {requestPermission && <button type="button" className={button} disabled={busy} onClick={() => void run(() => withNativeDialog(() => safeInvoke("offline_bluetooth_permissions")), undefined, "Requesting Nearby devices permission…")}>Allow Nearby devices</button>}
      {retryBluetooth && <button type="button" className={button} disabled={busy} onClick={() => void run(() => safeInvoke("offline_bluetooth_restart"), undefined, "Starting Bluetooth discovery…")}>Retry Bluetooth discovery</button>}
    </div>}
    {smart.hotspotError && <p className="break-words text-sm text-ink-800">{smart.hotspotError}</p>}
    {status.running && smart.hotspotAvailable && <div className="space-y-3 rounded-lg border border-line p-3">
      <p className={muted}>{smart.hotspotStarting ? "Complete the system permission prompt if it is shown. The hotspot becomes available after the operating system confirms it."
        : smart.hotspotActive
        ? "On the other device, use system Wi-Fi settings to join this hotspot. Internet access is optional."
        : "Create a temporary hotspot when the devices do not share a local Wi-Fi network."}</p>
      <button type="button" className={button} disabled={busy || smart.hotspotStarting} onClick={() => void run(
        () => smart.hotspotActive
          ? safeInvoke("offline_hotspot_stop")
          : withNativeDialog(() => safeInvoke("offline_hotspot_start")),
        undefined,
        smart.hotspotActive ? "Stopping the hotspot…" : "Starting the hotspot…",
      )}>{smart.hotspotStarting ? "Waiting for hotspot" : smart.hotspotActive ? "Stop temporary hotspot" : "Create temporary hotspot"}</button>
      {smart.hotspotActive && <HotspotCredentials key={status.fingerprint} run={run} busy={busy} />}
    </div>}
  </Panel>;
}

/** Background Mesh and multi-hop relaying: both are the user's choice. */
function MeshReachSettings({ status, run, busy }: { status: OfflineStatus; run: RunAction; busy: boolean }) {
  if (status.background === undefined || status.relay === undefined) return null;
  const android = status.platform === "android";
  const carrying = status.relayCarrying ?? 0;
  const row = "flex min-h-12 items-start gap-3 rounded-lg border border-line p-3 text-sm text-ink-800";
  return <section aria-label="Mesh reach" className="space-y-2">
    <label className={row}>
      <input className="mt-1 h-4 w-4 shrink-0 accent-violet-700" type="checkbox" checked={status.background} disabled={busy}
        onChange={(event) => {
          const enabled = event.target.checked;
          void run(() => safeInvoke("offline_set_background", { enabled }),
            enabled ? "Mesh will keep running in the background." : "Background Mesh turned off.");
        }} />
      <span className="min-w-0">
        <span className="block font-semibold">Keep Mesh running in the background</span>
        <span className="block text-xs text-ink-600">
          {android
            ? "Messages keep arriving after Qguard locks or leaves the screen. Android shows a \"Qguard Mesh is active\" notice while this is on, and it uses more battery. Alerts never show message text; reading or pairing still needs your unlock."
            : "On this computer Mesh already runs while the Qguard window is minimized. This setting applies to your Android devices."}
        </span>
      </span>
    </label>
    <label className={row}>
      <input className="mt-1 h-4 w-4 shrink-0 accent-violet-700" type="checkbox" checked={status.relay} disabled={busy}
        onChange={(event) => {
          const enabled = event.target.checked;
          void run(() => safeInvoke("offline_set_relay", { enabled }),
            enabled ? "This device will relay sealed messages." : "Relaying turned off. Carried messages were removed.");
        }} />
      <span className="min-w-0">
        <span className="block font-semibold">Relay messages for trusted devices</span>
        <span className="block text-xs text-ink-600">
          Passes sealed messages along (up to 4 devices) so they reach people out of direct range. This device cannot read
          them or see who they are from or for.{status.relay && status.running ? ` Carrying ${carrying} right now.` : ""}
        </span>
      </span>
    </label>
  </section>;
}

/**
 * Opt-in: show this account's picture on nearby devices' radar before
 * pairing. Off by default, because any nearby Qguard device can then ask for
 * it. Paired devices always see the picture over their encrypted link.
 */
function NearbyPictureSetting({ status, run, busy, accountId }: { status: OfflineStatus; run: RunAction; busy: boolean; accountId: string }) {
  if (status.sharePictureNearby === undefined) return null;
  return <label className="flex min-h-12 items-start gap-3 rounded-lg border border-line p-3 text-sm text-ink-800">
    <input className="mt-1 h-4 w-4 shrink-0 accent-violet-700" type="checkbox" checked={status.sharePictureNearby} disabled={busy}
      onChange={(event) => {
        const enabled = event.target.checked;
        void run(() => safeInvoke("offline_set_share_picture", { enabled, expectedAccount: accountId }),
          enabled ? "Nearby devices can now show your picture before pairing." : "Your picture is shown only to paired devices.");
      }} />
    <span className="min-w-0">
      <span className="block font-semibold">Show my picture to nearby devices</span>
      <span className="block text-xs text-ink-600">
        Helps people recognize this device on their radar before pairing. Any nearby Qguard device can see the picture
        while this is on{status.localAvatar ? "" : " (add a profile picture first)"}. Paired devices always see it over the encrypted link.
        Bluetooth discovery restarts briefly when you change this.
      </span>
    </span>
  </label>;
}

/** Whether, and until when, this device opens Mesh and XFER without internet. */
function OfflineAccessPanel({ status, run, busy, accountId }: {
  status: OfflineStatus; run: RunAction; busy: boolean; accountId: string;
}) {
  const access = status.offlineAccess;
  if (!access) return null;
  const android = status.platform === "android";
  const until = access.offlineUntil
    ? new Date(access.offlineUntil * 1000).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" })
    : null;
  const how = android
    ? "Unlock Qguard with your PIN, pattern or fingerprint to open Mesh and XFER without internet."
    : access.passwordSignIn
      ? "Your account password signs in to Mesh and XFER without internet."
      : "Sign in once online with your email and password to allow offline sign-in on this computer.";
  const turnOff = () => void run(async () => {
    const confirmed = await ask(
      "This device will need an internet connection to sign in again before Mesh and XFER open. Trusted devices and transfer history stay.",
      { title: "Turn off offline sign-in", okLabel: "Turn off", cancelLabel: "Cancel" },
    );
    if (!confirmed) return false;
    await safeInvoke("offline_forget_device", { expectedAccount: accountId });
    return true;
  }, "Offline sign-in turned off for this device.");
  return <section aria-label="Offline sign-in" className="space-y-2 rounded-lg border border-line p-3">
    <h4 className="flex items-center gap-2 text-sm font-bold text-ink-950"><ShieldCheck size={16} aria-hidden /> Offline sign-in</h4>
    {access.enrolled ? <>
      <p className="text-sm text-ink-700">On for this device{until ? ` until ${until}` : ""}. Each online sign-in renews it for 30 days.</p>
      <p className={muted}>{how}</p>
      <button type="button" className={button} disabled={busy} onClick={turnOff}>Turn off offline sign-in</button>
    </> : <p className={muted}>Not set up yet. Sign in once while online; this device then opens Mesh and XFER without internet for 30 days.</p>}
  </section>;
}

function PairingSettings({ status, run, busy, relay, accountId, onNavigate }: {
  status: OfflineStatus; run: RunAction; busy: boolean; relay: RelayAvailability; accountId: string; onNavigate: (page: Page) => void;
}) {
  const peers = status.peers.filter(({ trusted, blocked }) => trusted || blocked);
  const currentPlatform = offlinePairingPlatform(status.platform).name;

  async function manage(peer: OfflinePeer, action: "disconnect" | "block" | "unblock" | "revoke") {
    const messages = {
      disconnect: ["Disconnect device", "Pause local communication until you explicitly reconnect this device."],
      revoke: ["Revoke trust", "This device must pair again before exchanging local messages or files."],
      block: ["Block device", "This device will lose trust and cannot send another pairing request while blocked."],
      unblock: ["Unblock device", "This device may request pairing again."],
    };
    const [title, message] = messages[action];
    await run(async () => {
      if (!(await ask(message, { title, okLabel: title, cancelLabel: "Cancel" }))) return false;
      const expectedAccount = accountId;
      if (action === "revoke") await safeInvoke("offline_revoke", { fingerprint: peer.fingerprint, expectedAccount });
      else await safeInvoke(`offline_${action}_peer`, { peer: peer.fingerprint, expectedAccount });
      return true;
    }, { disconnect: "Device disconnected.", revoke: "Device trust revoked.", block: "Device blocked.", unblock: "Device unblocked." }[action]);
  }

  return <div className="grid min-w-0 items-start gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
    <Panel title="This device">
      <FingerprintText value={status.fingerprint} />
      <dl className="grid gap-2 text-sm text-ink-700">
        <div className="flex flex-wrap justify-between gap-x-4"><dt>Platform</dt><dd className="font-semibold">{currentPlatform}</dd></div>
        <div className="flex flex-wrap justify-between gap-x-4"><dt>Local listener</dt><dd className="font-semibold">{status.port === null ? "Stopped" : `Port ${status.port}`}</dd></div>
      </dl>
      <label className="flex min-h-12 items-center gap-3 rounded-lg border border-line p-3 text-sm font-semibold text-ink-800">
        <input className="h-4 w-4 shrink-0 accent-violet-700" type="checkbox" checked={status.autoStart} disabled={busy} onChange={(event) => {
          const enabled = event.target.checked;
          void run(async () => {
            await safeInvoke("offline_set_auto", { enabled });
            if (enabled && relay === "unavailable") await safeInvoke("offline_relay_state", { unavailable: true, expectedAccount: accountId });
          }, enabled ? "Automatic local discovery enabled." : "Automatic local discovery disabled.");
        }} />
        Start local discovery when the Qguard relay cannot be reached
      </label>
      <MeshReachSettings {...{ status, run, busy }} />
      <NearbyPictureSetting {...{ status, run, busy, accountId }} />
      <p className={muted}>To add a device, open Mesh or XFER on both devices and start local discovery. Both people must compare and confirm the pairing code.</p>
      <div className="flex flex-wrap gap-2">
        <button type="button" className={button} onClick={() => onNavigate("mesh")}>Open Mesh</button>
        <button type="button" className={button} onClick={() => onNavigate("xfer")}>Open XFER</button>
      </div>
      <OfflineAccessPanel {...{ status, run, busy, accountId }} />
    </Panel>
    <Panel title="Trusted devices">
      {peers.length === 0 && <p className={muted}>Paired and blocked devices will appear here.</p>}
      {peers.map((peer) => {
        const platform = offlinePairingPlatform(peer.platform);
        const mode: OfflineMode = peerAllows(peer, "mesh") ? "mesh" : "xfer";
        const missing = peer.pairedAt != null && !peer.blocked
          ? (["mesh", "xfer"] as const).filter((capability) => !peerAllows(peer, capability))
          : [];
        const state = peer.blocked ? "Blocked" : peer.connected ? "Connected" : peer.disconnected ? "Disconnected" : peer.lastSeen != null ? "Discovered" : "Offline";
        return <article key={peer.fingerprint} className="space-y-3 rounded-lg border border-line p-3">
          <div className="flex flex-wrap items-center gap-3">
            <span className="offline-device-icon" aria-hidden>
              <PeerPicture fingerprint={peer.trusted ? peer.fingerprint : undefined} digest={peer.avatar} fallback={<platform.icon size={19} />} />
            </span>
            <div className="min-w-0 flex-1">
              <strong className="block break-words text-sm text-ink-950">{offlinePeerName(peer, "Nearby Qguard device")}</strong>
              <p className={muted}>{peer.owner && peer.label ? `${peer.label} · ` : ""}{platform.name} · {peer.blocked ? "Blocked" : peer.pairedAt ? "Mutually paired" : "Trusted fingerprint"}</p>
              {!peer.blocked && <p className="mt-1 flex flex-wrap gap-1.5" aria-label="Approved capabilities">
                {(["mesh", "xfer"] as const).filter((capability) => peerAllows(peer, capability)).map((capability) =>
                  <span key={capability} className="offline-state-chip" data-tone="cyan">{capabilityNames[capability]}</span>)}
              </p>}
            </div>
            <span className="offline-state-chip" data-tone={peer.connected ? "green" : "neutral"}>{state}</span>
          </div>
          <details className="group">
            <summary className="focus-ring flex min-h-12 cursor-pointer items-center gap-2 rounded-md text-sm font-semibold text-ink-800"><ChevronDown size={15} aria-hidden className="-rotate-90 group-open:rotate-0" /> View device details</summary>
            <div className="space-y-2">
              <FingerprintText value={peer.fingerprint} />
              <dl className="grid gap-2 text-sm text-ink-700">
                {peer.owner && <div><dt className="inline font-semibold">Owner</dt> <dd className="inline">{peer.owner}</dd></div>}
                {peer.label && <div><dt className="inline font-semibold">Device name</dt> <dd className="inline">{peer.label}</dd></div>}
                <div><dt className="inline font-semibold">First paired</dt> <dd className="inline">{peer.pairedAt != null ? formatOfflineTime(peer.pairedAt) : "Unavailable"}</dd></div>
                <div><dt className="inline font-semibold">Last connected</dt> <dd className="inline">{peer.authenticatedAt != null ? formatOfflineTime(peer.authenticatedAt) : "Unavailable"}</dd></div>
                <div><dt className="inline font-semibold">Approved capabilities</dt> <dd className="inline">{(["mesh", "xfer"] as const).filter((capability) => peerAllows(peer, capability)).map((capability) => capabilityNames[capability]).join(" · ") || "None"}</dd></div>
                <div><dt className="inline font-semibold">Identity keys</dt> <dd className="inline">Ed25519 + ML-DSA-65 (fingerprint: SHA3-256)</dd></div>
              </dl>
            </div>
          </details>
          <div className="flex flex-wrap gap-2">
            {peer.blocked ? <button type="button" className={button} disabled={busy} onClick={() => void manage(peer, "unblock")}>Unblock device</button> : <>
              <button type="button" className={button} disabled={busy || !status.running} onClick={() => void run(
                () => safeInvoke("offline_probe_peer", { peer: peer.fingerprint, mode, expectedAccount: accountId }),
                "Authenticated the local link.", "Checking the secure connection…",
              )}>Connect</button>
              {missing.map((capability) => <button key={capability} type="button" className={button} disabled={busy || !status.running} onClick={() => void run(
                () => safeInvoke("offline_pairing_start", { peer: peer.fingerprint, mode: capability, both: false, expectedAccount: accountId }),
                undefined, "Sending the connection request…",
              )}><Plus size={16} aria-hidden /> Add {capability === "mesh" ? "Mesh" : "XFER"} access</button>)}
              <button type="button" className={button} disabled={busy || peer.disconnected} onClick={() => void manage(peer, "disconnect")}>Disconnect</button>
              <button type="button" className={button} disabled={busy} onClick={() => void manage(peer, "revoke")}>Revoke trust</button>
              <button type="button" className={button} disabled={busy} onClick={() => void manage(peer, "block")}>Block device</button>
            </>}
          </div>
        </article>;
      })}
    </Panel>
  </div>;
}

function MeshComposer({ status, recipients, onToggleRecipient, run, busy, onNavigate, onQueued }: {
  status: OfflineStatus; recipients: string[]; onToggleRecipient: (id: string) => void;
  run: RunAction; busy: boolean; onNavigate: (page: Page) => void; onQueued: (id: string) => void;
}) {
  const [body, setBody] = useState("");
  const [group, setGroup] = useState("");
  const [emergency, setEmergency] = useState(false);
  const [ttlSeconds, setTtl] = useState(3600);
  const peers = status.peers.filter((peer) => peerAllows(peer, "mesh") && !peer.disconnected);
  const selected = recipients.filter((fingerprint) => peers.some((peer) => peer.fingerprint === fingerprint));

  async function sendMessage(event: FormEvent) {
    event.preventDefault();
    const sent = await run(async () => {
      const id = await safeInvoke<string>("offline_mesh_send", {
        recipients: selected,
        body: body.trim(),
        group: selected.length > 1 ? group.trim() : null,
        emergency,
        ttlSeconds,
      });
      if (typeof id === "string") onQueued(id);
    });
    if (sent) setBody("");
  }

  const recipientFields = (
        <fieldset className="space-y-2">
          <legend className="text-sm font-semibold text-ink-800">Trusted recipients</legend>
          <div className="max-h-56 space-y-2 overflow-y-auto p-1">
            {peers.map((peer) => <label key={peer.fingerprint} className="flex min-h-12 items-center gap-3 rounded-lg border border-line px-3 py-2">
              <input type="checkbox" className="h-4 w-4 shrink-0 accent-violet-700" checked={selected.includes(peer.fingerprint)} onChange={() => onToggleRecipient(peer.fingerprint)} />
              <DeviceLabel peer={peer} />
            </label>)}
          </div>
        </fieldset>
  );
  const options = <>
    <label className="block space-y-1 text-sm font-semibold text-ink-800">
      Queue expiry
      <select className={field} value={ttlSeconds} onChange={(event) => setTtl(Number(event.target.value))}>
        <option value={900}>15 minutes</option><option value={3600}>1 hour</option><option value={86400}>24 hours</option>
      </select>
    </label>
    <label className="flex min-h-12 items-center gap-3 text-sm font-semibold text-ink-800">
      <input type="checkbox" className="h-4 w-4 accent-violet-700" checked={emergency} onChange={(event) => setEmergency(event.target.checked)} />
      Mark as emergency
    </label>
  </>;

  return <Panel id="offline-compose" title="Send a nearby message" dashboard>
      {peers.length ? <form className="space-y-3" onSubmit={sendMessage}>
        <details className="space-y-2 rounded-lg border border-line p-2">
          <summary className="focus-ring flex min-h-12 cursor-pointer items-center px-2 text-sm font-semibold">Recipients ({selected.length})</summary>
          {recipientFields}
        </details>
        {selected.length > 1 && <label className="block space-y-1 text-sm font-semibold text-ink-800">
          Group label
          <input className={field} value={group} maxLength={64} required onChange={(event) => setGroup(event.target.value)} />
        </label>}
        <label className="block space-y-1 text-sm font-semibold text-ink-800">
          Message
          <textarea className={`${field} resize-y`} rows={3} value={body} onChange={(event) => setBody(event.target.value)} maxLength={2048} required />
        </label>
        <details className="rounded-lg border border-line px-2">
          <summary className="focus-ring flex min-h-12 cursor-pointer items-center text-sm font-semibold">Message options</summary>{options}
        </details>
        <button type="submit" className={primary} disabled={busy || selected.length === 0 || !body.trim() || (selected.length > 1 && !group.trim())}>
          Queue message
        </button>
      </form> : <>
        <p className={muted}>Pair with a nearby device and allow Mesh messaging to send it a message.</p>
        <button type="button" className={button} onClick={() => onNavigate("offline-settings")}>Manage device trust</button>
      </>}
    </Panel>;
}

function MeshActivity({ status, messages, run, busy, onOpen }: {
  status: OfflineStatus; messages: MeshMessage[] | null; run: RunAction; busy: boolean; onOpen?: (message: MeshMessage) => void;
}) {
  const labels = new Map(status.peers.map((peer) => [peer.fingerprint, peer.owner || peer.label]));
  const displayPeer = (fingerprint: string) => labels.get(fingerprint) || fingerprint;
  const pending = messages?.filter((message) => message.status === "pending").length;
  return <Panel id="offline-activity" title="Local message activity" dashboard>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className={muted}>{pending === undefined ? "Reading local queue…" : `${pending} pending · ${messages?.filter((message) => message.status === "delivered").length} delivered · ${messages?.filter((message) => message.status === "expired").length} expired`}</p>
        <button className={button} type="button" disabled={busy || !status.running || !pending} onClick={() => void run(() => safeInvoke("offline_mesh_retry"))}>Retry queued</button>
      </div>
      {messages?.length === 0 && <p className={muted}>Incoming messages, outgoing queue entries, and delivery receipts will appear here.</p>}
      {messages?.map((message) => <article key={`${message.direction}:${message.sender}:${message.id}`} className="min-w-0 space-y-2 rounded-lg border border-line p-3">
        <div className="flex flex-wrap justify-between gap-x-3 gap-y-1 text-xs font-semibold text-ink-600">
          <span className="flex items-center gap-2">{message.direction === "incoming" ? "Received" : message.status === "delivered" ? "Delivered" : message.status === "pending" ? (message.relayedTo?.length ? "Relayed" : "Pending") : "Expired"}
            {message.direction === "incoming" && message.readAt == null && <span className="offline-state-chip" data-tone="cyan">Unread</span>}</span>
          <time dateTime={new Date(message.createdAt * 1000).toISOString()}>{formatOfflineTime(message.createdAt)}</time>
        </div>
        {message.emergency && <p className="text-sm font-bold text-ink-950">Emergency message</p>}
        <p className="break-all text-xs font-semibold text-ink-700">
          {message.direction === "incoming" ? `From ${displayPeer(message.sender)}` : `To ${message.recipients.map(displayPeer).join(", ")}`}
          {message.group ? ` · ${message.group}` : ""}
        </p>
        <p className="whitespace-pre-wrap break-words text-sm text-ink-950">{message.body}</p>
        {message.direction === "outgoing" && <p className="text-xs text-ink-600">{message.deliveredTo.length}/{message.recipients.length} acknowledged</p>}
        {onOpen && <button type="button" className={button} onClick={() => onOpen(message)}>View message</button>}
      </article>)}
    </Panel>;
}

/** The authenticated session suite every Mesh message travels under. */
function MeshSecurity() {
  return <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-xs text-emerald-900" aria-label="Message encryption">
    <p className="flex items-center gap-1.5 font-bold"><ShieldCheck size={14} aria-hidden /> Quantum-encrypted end to end</p>
    <dl className="mt-1.5 grid gap-0.5">
      <div className="flex flex-wrap gap-x-1.5"><dt>Key exchange</dt><dd className="font-semibold">{MESH_SUITE.keyEstablishment}</dd></div>
      <div className="flex flex-wrap gap-x-1.5"><dt>Device signatures</dt><dd className="font-semibold">{MESH_SUITE.signatures}</dd></div>
      <div className="flex flex-wrap gap-x-1.5"><dt>Message encryption</dt><dd className="font-semibold">{MESH_SUITE.encryption}</dd></div>
    </dl>
    <p className="mt-1.5">Stored on this device in the account's sealed message ledger.</p>
  </div>;
}

function toggleRecipient(set: (update: (current: string[]) => string[]) => void, fingerprint: string) {
  set((current) => current.includes(fingerprint) ? current.filter((id) => id !== fingerprint) : [...current, fingerprint]);
}

function TransferComposer({ status, busy, run, onNavigate, recipient, onQueued, autoPick = false }: {
  status: OfflineStatus; busy: boolean; run: RunAction; onNavigate: (page: Page) => void;
  recipient: string; onQueued: (id: string) => void;
  /** Open the file picker on arrival ("Send more files" in the same session). */
  autoPick?: boolean;
}) {
  const [sources, setSources] = useState<PickedSources[]>([]);
  const picked = useRef(false);
  useEffect(() => {
    if (!autoPick || picked.current) return;
    picked.current = true;
    chooseSources(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- once per arrival
  }, [autoPick]);
  const trusted = status.peers.filter((peer) => peerAllows(peer, "xfer") && !peer.disconnected);
  const androidDocuments = status.platform === "android";
  const supportsFolders = status.platform !== "ios";
  const selectedPeer = trusted.find((peer) => peer.fingerprint === recipient);
  const queue = Boolean(selectedPeer && (!status.running || !selectedPeer.address));
  const selectedBytes = sources.every((source) => typeof source.totalBytes === "number")
    ? sources.reduce((total, source) => total + (source.totalBytes ?? 0), 0)
    : null;

  function chooseSources(folder: boolean) {
    void run(async () => {
      const picked = await withNativeDialog(() => safeInvoke<PickedSources | null>("offline_xfer_pick_sources", { folder }));
      if (picked) setSources((previous) => [...previous, picked]);
    });
  }

  async function sendOffer(event: FormEvent) {
    event.preventDefault();
    if (!selectedPeer || sources.length === 0) return;
    if (await run(async () => {
      const id = await safeInvoke<string>("offline_xfer_offer", { recipient, selectionTokens: sources.map((source) => source.token) });
      if (typeof id === "string") onQueued(id);
    }, undefined, "Preparing the selected files…")) setSources([]);
  }

  return <Panel title="Send files" dashboard>
    {trusted.length ? <form className="space-y-3" onSubmit={sendOffer}>
      {queue && <p id="xfer-route-hint" className={muted}>A local connection to this device is unavailable or has no reported address. Qguard will keep the selected files in the encrypted queue.</p>}
      <div className="flex flex-wrap gap-2">
        <button type="button" className={button} onClick={() => chooseSources(false)} disabled={busy}><Plus size={16} aria-hidden /> Add files</button>
        {supportsFolders && <button type="button" className={button} onClick={() => chooseSources(true)} disabled={busy}><FolderPlus size={16} aria-hidden /> Add folder</button>}
      </div>
      {androidDocuments && <p className={muted}>Choose photos, videos, or documents through the Android file picker. Queued files are kept in encrypted local storage.</p>}
      {sources.length > 0 && <div className="rounded-lg border border-line p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-sm font-semibold text-ink-800">Selected items{selectedBytes === null ? "" : ` · ${formatOfflineBytes(selectedBytes)}`}</p>
          <button type="button" className={button} disabled={busy} onClick={() => setSources([])}>Clear selection</button>
        </div>
        <ul className="mt-2 max-h-40 space-y-1 overflow-y-auto text-sm text-ink-700">
          {sources.flatMap(({ token, names }) => names.map((name, index) => <li key={`${token}-${index}`} className="break-all">{name}</li>))}
        </ul>
      </div>}
      <button type="submit" className={primary} disabled={busy || !selectedPeer || !sources.length}>{queue ? "Queue transfer" : "Offer selected files"}</button>
    </form> : <>
      <p className={muted}>Pair with the recipient and allow XFER file transfer before offering files.</p>
      <button type="button" className={button} onClick={() => onNavigate("offline-settings")}>Manage device trust</button>
    </>}
  </Panel>;
}

function transferState(transfer: OfflineTransfer) {
  if (transfer.status === "active" && transfer.totalBytes > 0 && transfer.verifiedBytes >= transfer.totalBytes) {
    return "Awaiting final verification";
  }
  return transfer.status === "verified" && transfer.direction === "outgoing" ? "Recipient verified" : transferLabels[transfer.status];
}

function TransferControls({ transfer, running, busy, run, accountId }: {
  transfer: OfflineTransfer; running: boolean; busy: boolean; run: RunAction; accountId?: string;
}) {
  const { id, status, direction } = transfer;
  const active = status === "active";
  const resumable = status === "interrupted" || status === "queued" || status === "paused" || status === "stopped";
  const waitingForPeer = Boolean(transfer.remoteHold && !transfer.localHold);
  if (!active && !resumable && !(status === "awaitingConsent" && direction === "outgoing")) return null;

  return <div className="flex flex-wrap gap-2">
    {active && <button className={button} type="button" disabled={busy} onClick={() => void run(() => safeInvoke("offline_xfer_pause", { id }))}>
      <Pause size={16} aria-hidden /> Pause
    </button>}
    {resumable && <button className={button} type="button" disabled={busy || !running || waitingForPeer} onClick={() => void run(() => safeInvoke("offline_xfer_resume", { id }))}>
      <Play size={16} aria-hidden /> {status === "queued" && direction === "outgoing" ? "Retry offer" : "Resume"}
    </button>}
    {active && accountId && <button className={button} type="button" disabled={busy} onClick={() => void run(async () => {
      if (!(await withNativeDialog(() => ask("Stop the transfer and keep the verified checkpoint? You can resume it before the transfer expires.", {
        title: "Stop transfer", okLabel: "Stop transfer", cancelLabel: "Keep transferring",
      })))) return false;
      await safeInvoke("offline_xfer_stop", { id, expectedAccount: accountId });
      return true;
    }, "Transfer stopped. Its checkpoint is available to resume.")}><Square size={16} aria-hidden /> Stop</button>}
    <button className={button} type="button" disabled={busy} onClick={() => void run(async () => {
      const accepted = await withNativeDialog(() => ask("Cancel this transfer and discard its incomplete data?", {
        title: "Cancel transfer", okLabel: "Cancel transfer", cancelLabel: "Keep transfer",
      }));
      if (!accepted) return false;
      await safeInvoke("offline_xfer_cancel", { id });
      return true;
    }, "Transfer cancelled.")}><X size={16} aria-hidden /> Cancel</button>
  </div>;
}

const endedOutgoing = new Set<OfflineTransfer["status"]>(["failed", "rejected", "cancelled", "expired"]);

/**
 * Recovery for a transfer that cannot resume. The sender erased its encrypted
 * copy when the transfer ended, so sending again starts a fresh, consented
 * offer to the same verified device with files the user selects again.
 */
function TransferRecovery({ transfer, onSendAgain }: {
  transfer: OfflineTransfer; onSendAgain?: (peer: string) => void;
}) {
  if (transfer.direction === "outgoing" && endedOutgoing.has(transfer.status) && onSendAgain) {
    return <button type="button" className={button} onClick={() => onSendAgain(transfer.recipient)}>
      <RotateCcw size={16} aria-hidden /> Send again
    </button>;
  }
  if (transfer.direction === "incoming" && transfer.status === "failed") {
    return <p className={muted}>Qguard deleted the unverified data. Ask the sender to send the files again.</p>;
  }
  return null;
}

function OpenTransferredFile({ transfer, file, accountId, platform, busy, run }: {
  transfer: OfflineTransfer; file: number; accountId: string; platform: string; busy: boolean; run: RunAction;
}) {
  const saved = transfer.files[file];
  if (transfer.direction !== "incoming" || transfer.status !== "verified" || !saved?.destination) return null;
  const open = (target: "file" | "folder") => void run(() => withNativeDialog(() => safeInvoke("offline_xfer_open", {
    id: transfer.id, file, target, expectedAccount: accountId,
  })), undefined, target === "file" ? "Checking the saved file…" : "Opening the save location…");
  return <>
    {saved.canOpenFile && <button type="button" className={button} disabled={busy} onClick={() => open("file")}><ExternalLink size={16} aria-hidden /> Open file</button>}
    {saved.canOpenFolder && <button type="button" className={button} disabled={busy} onClick={() => open("folder")}><FolderOpen size={16} aria-hidden /> {platform === "android" ? "Open Downloads" : "Open folder"}</button>}
  </>;
}

function TransferFileActions({ transfer, file, run, busy, vaultUnlocked, onNavigate, children }: {
  transfer: OfflineTransfer; file: number; run: RunAction; busy: boolean; vaultUnlocked: boolean;
  onNavigate: (page: Page) => void; children?: ReactNode;
}) {
  if (transfer.direction !== "incoming" || transfer.status !== "verified") return null;
  return <div className="flex flex-wrap gap-2 empty:hidden">
    {children}
    {transfer.localCopyRetained && <>
      <button className={button} type="button" disabled={busy} onClick={() => void run(async () => Boolean(await withNativeDialog(() => safeInvoke<string | null>(
        "offline_xfer_export", { id: transfer.id, file },
      ))), "Verified file saved.", "Saving verified file…")}><ArrowDownToLine size={16} aria-hidden /> Save file</button>
      {vaultUnlocked ? <button className={button} type="button" disabled={busy} onClick={() => void run(() => safeInvoke("offline_xfer_import_vault", { id: transfer.id, file }), "Verified file imported into Quantum Vault.", "Importing verified file…")}>
        <LockKeyhole size={16} aria-hidden /> Import into Vault
      </button> : <button className={button} type="button" onClick={() => onNavigate("vault")}><LockKeyhole size={16} aria-hidden /> Unlock Quantum Vault</button>}
    </>}
  </div>;
}

function TransferConsentActions({ transfer, run, busy, vaultUnlocked }: {
  transfer: OfflineTransfer; run: RunAction; busy: boolean; vaultUnlocked: boolean;
}) {
  if (transfer.direction !== "incoming" || transfer.status !== "awaitingConsent") return null;
  const { id } = transfer;
  return <div className="space-y-3">
    <p className={muted}>After you accept, Qguard receives files into protected local storage and verifies their integrity. {vaultUnlocked ? "Choose Quantum Vault for automatic import after verification." : "Unlock Quantum Vault to import verified files."}</p>
    {vaultUnlocked && <p className={muted}>Quantum Vault uses your existing backup setting for imported files.</p>}
    <div className="flex flex-wrap gap-2">
      <button className={primary} type="button" disabled={busy} onClick={() => void run(() => safeInvoke("offline_xfer_respond", { id, accept: true }), "Transfer accepted.")}>Accept files</button>
      {vaultUnlocked && <button className={button} type="button" disabled={busy} onClick={() => void run(() => safeInvoke("offline_xfer_respond", { id, accept: true, intoVault: true }), "Transfer accepted for Quantum Vault.")}>
        <LockKeyhole size={16} aria-hidden /> Accept into Quantum Vault
      </button>}
      <button className={button} type="button" disabled={busy} onClick={() => void run(() => safeInvoke("offline_xfer_respond", { id, accept: false }), "Transfer declined.")}>Decline</button>
    </div>
  </div>;
}

function TransferRecord({ transfer, status, run, busy, vaultUnlocked, onNavigate, onMonitor, inMonitor, onSendAgain }: {
  transfer: OfflineTransfer; status: OfflineStatus; run: RunAction; busy: boolean; vaultUnlocked: boolean;
  onNavigate: (page: Page) => void; onMonitor?: () => void; inMonitor: boolean; onSendAgain?: (peer: string) => void;
}) {
  const { id, verifiedBytes, totalBytes, files } = transfer;
  const incoming = transfer.direction === "incoming";
  const peerId = incoming ? transfer.sender : transfer.recipient;
  const peerLabel = offlinePeerName(status.peers.find((peer) => peer.fingerprint === peerId), peerId);
  const active = transfer.status === "active";
  const verified = transfer.status === "verified";
  const awaitingConsent = transfer.status === "awaitingConsent";
  const speed = active && verifiedBytes < totalBytes ? transfer.bytesPerSecond : null;
  const fileLabel = files.length === 1 ? files[0].name : `${files.length} files`;

  return <article id={`offline-transfer-${id}`} tabIndex={-1} className="offline-queue-record focus-ring space-y-3 rounded-xl border border-line p-3 sm:p-4" data-selected={inMonitor}>
    <div className="flex flex-wrap justify-between gap-2">
      <div className="flex min-w-0 items-center gap-2.5">
        <span className="offline-device-icon"><TransferFileIcon name={files[0]?.name} /></span>
        <div className="min-w-0">
          <h4 className="break-words text-sm font-bold text-ink-950">{fileLabel}</h4>
          <p className="mt-0.5 break-all text-xs text-ink-600">{incoming ? "From" : "To"} {peerLabel}</p>
        </div>
      </div>
      <span className="offline-state-chip" data-tone={verified ? "green" : active ? "cyan" : "neutral"}>{transferState(transfer)}</span>
    </div>
    {(active || transfer.status === "interrupted" || transfer.status === "paused" || transfer.status === "stopped" || verified) && <div>
      <TransferBar transfer={transfer} />
      <p className="mt-2 text-xs tabular-nums text-ink-600">
        {formatOfflineBytes(verifiedBytes)} of {formatOfflineBytes(totalBytes)} verified
        {speed ? ` · ${formatOfflineBytes(speed)}/s` : ""}
      </p>
    </div>}
    <details open={awaitingConsent ? true : undefined} className="group text-sm text-ink-700">
      <summary className="focus-ring flex min-h-12 cursor-pointer items-center gap-2 rounded-md font-semibold"><ChevronDown size={15} aria-hidden className="-rotate-90 group-open:rotate-0" /> {formatOfflineBytes(totalBytes)} · File details</summary>
      <p className="mb-2 text-xs text-ink-600">{formatOfflineTime(transfer.createdAt)}</p>
      <ul className="space-y-2">
        {files.map((file, index) => <li key={`${id}-${index}`} className="space-y-2 rounded-md bg-canvas p-2">
          <p className="break-all">{file.name} · {formatOfflineBytes(file.size)}</p>
          {file.destination && <p className="break-all text-xs text-ink-600">Saved to {file.destination}</p>}
          <TransferFileActions {...{ transfer, run, busy, vaultUnlocked, onNavigate }} file={index} />
        </li>)}
      </ul>
    </details>
    {incoming && verified && !transfer.localCopyRetained && <p className={muted}>The receipt is retained. The protected local file copy has expired.</p>}
    {transfer.error && <p className="break-words text-sm text-ink-700">{transfer.error}</p>}
    {transfer.localCopyRetained && <p className={muted}>Quantum Vault uses your existing backup setting for imported files.</p>}
    <TransferConsentActions {...{ transfer, run, busy, vaultUnlocked }} />
    <div className="flex flex-wrap gap-2 empty:hidden">
      {!inMonitor && <TransferControls {...{ transfer, busy, run }} running={status.running} />}
      {!inMonitor && <TransferRecovery {...{ transfer, onSendAgain }} />}
      {onMonitor && <button type="button" className={button} onClick={onMonitor}>{inMonitor ? "Go to monitor" : "View in monitor"}</button>}
    </div>
  </article>;
}

function TransferActivity({ page, status, transfers, busy, run, vaultUnlocked, onNavigate, onMonitor, focusedId, compact, onSendAgain }: {
  page: OfflinePageId; status: OfflineStatus; transfers: OfflineTransfer[] | null; busy: boolean; run: RunAction;
  vaultUnlocked: boolean; onNavigate: (page: Page) => void; onMonitor?: (id: string) => void; focusedId?: string; compact?: boolean;
  onSendAgain?: (peer: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("");
  const history = page === "transfer-history";
  const filtered = transfers?.filter((transfer) => (!filter || transfer.status === filter)
    && (!query.trim() || transfer.files.some((file) => file.name.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase()))));
  const records = filtered;

  const entries = <>
    {history ? <div className="grid gap-3 sm:grid-cols-2">
      <label className="block space-y-1 text-sm font-semibold text-ink-800">Search by filename
        <input className={field} type="search" value={query} onChange={(event) => setQuery(event.target.value)} />
      </label>
      <label className="block space-y-1 text-sm font-semibold text-ink-800">Transfer state
        <select className={field} value={filter} onChange={(event) => setFilter(event.target.value)}>
          <option value="">All states</option>
          {Object.entries(transferLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
      </label>
    </div> : <>
      <div className="flex flex-wrap gap-2" role="group" aria-label="Filter transfer queue">
        {[["", "All"], ["active", "Active"], ["verified", "Verified"]].map(([value, label]) =>
          <button key={value} type="button" className={`${button} offline-queue-filter`} aria-pressed={filter === value} onClick={() => setFilter(value)}>{label}</button>,
        )}
      </div>
      {!status.running && <p className={muted}>Start local discovery to receive file offers.</p>}
    </>}
    {transfers === null && <p role="status" className={muted}>Reading local transfer records…</p>}
    {records?.length === 0 && <p className={muted}>{transfers?.length ? "No transfers match this view." : "No transfer records yet."}</p>}
    {compact && onMonitor ? <div className="offline-mobile-list">{records?.map((transfer) =>
      <button type="button" key={transfer.id} className="offline-mobile-row focus-ring" onClick={() => onMonitor(transfer.id)}>
        <span className="offline-device-icon"><TransferFileIcon name={transfer.files[0]?.name} /></span>
        <span><strong>{transfer.files.length === 1 ? transfer.files[0].name : `${transfer.files.length} files`}</strong>
          <small>{transferState(transfer)} · {formatOfflineBytes(transfer.totalBytes)}</small></span>
        <ChevronRight size={16} aria-hidden />
      </button>)}</div> : records?.map((transfer) => <TransferRecord key={transfer.id} {...{ transfer, status, busy, run, vaultUnlocked, onNavigate, onSendAgain }}
        inMonitor={transfer.id === focusedId} onMonitor={onMonitor ? () => onMonitor(transfer.id) : undefined} />)}
  </>;

  return history ? <Panel title="Local transfer records">{entries}</Panel>
    : <section className="offline-surface space-y-3" aria-labelledby="offline-queue-title">
      <QueueHeading active={transfers?.filter(({ status }) => status === "active").length}
        verified={transfers?.filter(({ status }) => status === "verified").length} />
      {entries}
    </section>;
}

/**
 * The live session with one XFER device: the link state the native channel
 * registry reports, and a manual Disconnect. The session otherwise stays up
 * across transfers until the user disconnects, trust is withdrawn, local
 * networking stops, or the link is lost (then it is redialed).
 */
function XferSessionBar({ peerId, peer, accountId, busy, run, onDisconnected }: {
  peerId: string; peer: OfflinePeer | undefined; accountId: string; busy: boolean; run: RunAction; onDisconnected: () => void;
}) {
  const link = offlineLinkState(peer);
  const canDisconnect = Boolean(peer?.trusted && !peer.disconnected);
  const disconnect = () => void run(async () => {
    if (!(await ask("Nothing is exchanged with this device until you reconnect it from Nearby devices. Its trust and your transfer history stay.", {
      title: "Disconnect device", okLabel: "Disconnect", cancelLabel: "Cancel",
    }))) return false;
    await safeInvoke("offline_disconnect_peer", { peer: peerId, expectedAccount: accountId });
    onDisconnected();
    return true;
  }, "Device disconnected.");
  return <div className="offline-session-bar">
    <p role="status" className="offline-receive-link" data-tone={link.tone}>
      <span aria-hidden /> {link.label}{link.detail ? ` · ${link.detail}` : ""}
    </p>
    {canDisconnect && <button type="button" className="offline-session-disconnect focus-ring" disabled={busy} onClick={disconnect}>Disconnect</button>}
  </div>;
}

const ENDED_TRANSFER = new Set<OfflineTransfer["status"]>(["verified", "rejected", "cancelled", "expired", "failed"]);

/**
 * The transfer a waiting receiver should open: an offer from this device that
 * still needs consent, or any transfer from it that started after waiting
 * began (`seen` holds the ids that existed then). Null while nothing arrived.
 */
export function xferArrival(transfers: OfflineTransfer[] | null, peer: string, seen: ReadonlySet<string>): OfflineTransfer | null {
  const fromPeer = transfers?.filter(({ direction, sender }) => direction === "incoming" && sender === peer) ?? [];
  return fromPeer.find(({ status }) => status === "awaitingConsent")
    ?? fromPeer.find(({ id, status }) => !seen.has(id) && !ENDED_TRANSFER.has(status))
    ?? fromPeer.find(({ id }) => !seen.has(id))
    ?? null;
}

/**
 * Shown on the receiving device once a trusted XFER connection exists. It keeps
 * the device on this screen (instead of the radar) and opens the offer as soon
 * as the native core records it, so the user can review and accept it.
 */
function XferReceiveWaiting({ peerId, peer, status, transfers, busy, onArrival, onSendInstead, onStop, onToggleDiscovery, session }: {
  peerId: string; peer: OfflinePeer | undefined; status: OfflineStatus; transfers: OfflineTransfer[] | null; busy: boolean;
  onArrival: (id: string) => void; onSendInstead: () => void; onStop: () => void; onToggleDiscovery: DiscoveryAction;
  /** The session bar (link state and Disconnect). */
  session: ReactNode;
}) {
  const name = offlinePeerName(peer, `Device ${peerId.slice(0, 8)}`);
  const usable = Boolean(peer && peerAllows(peer, "xfer") && !peer.disconnected);
  const PeerIcon = offlinePairingPlatform(peer?.platform).icon;
  // Transfers already recorded when waiting began are history, not arrivals.
  // Until the first snapshot arrives, nothing is known to be old.
  const [seen, setSeen] = useState<ReadonlySet<string> | null>(() => transfers ? new Set(transfers.map(({ id }) => id)) : null);
  useEffect(() => {
    if (!seen && transfers) setSeen(new Set(transfers.map(({ id }) => id)));
  }, [seen, transfers]);
  const arrival = useMemo(() => seen ? xferArrival(transfers, peerId, seen) : null, [peerId, seen, transfers]);
  const arrivalId = arrival?.id;
  useEffect(() => {
    if (arrivalId) onArrival(arrivalId);
  }, [arrivalId, onArrival]);

  return <section className="offline-mobile-surface offline-mobile-card offline-mobile-center offline-receive-waiting" aria-label={`Waiting for files from ${name}`}>
    <div className="offline-receive-emblem" data-live={(usable && status.running) || undefined}>
      <Inbox size={30} aria-hidden />
    </div>
    <div className="space-y-1">
      <h3 className="break-words text-lg font-bold text-ink-950">Ready to receive</h3>
      <p className="offline-receive-peer">
        <span className="offline-receive-picture" aria-hidden>
          <PeerPicture fingerprint={peer?.trusted ? peerId : undefined} digest={peer?.avatar} fallback={<PeerIcon size={16} />} />
        </span>
        <strong className="break-all">{name}</strong>
      </p>
      {session}
    </div>
    {!usable ? <p className={muted}>{peer?.disconnected
      ? "You disconnected this device. Reconnect it from Nearby devices before it can send you files."
      : "This device isn't trusted for XFER. Connect it from the radar first."}</p>
      : !status.running ? <>
        <p className={muted}>Local networking is stopped, so {name} can't reach this device. Start discovery to keep receiving.</p>
        <button type="button" className={primary} disabled={busy} onClick={onToggleDiscovery}>Start local discovery</button>
      </>
      : <p className={muted}>Waiting for {name} to choose files. Keep Qguard open on both devices. The offer opens here, and nothing is saved until you accept it.</p>}
    <div className="offline-mobile-actions">
      {usable && <button type="button" className={button} disabled={busy} onClick={onSendInstead}><FileUp size={16} aria-hidden /> Send files instead</button>}
      <button type="button" className={button} disabled={busy} onClick={onStop}>Stop waiting</button>
    </div>
  </section>;
}

type DiscoveryScreen = "discovery" | "devices";
type OfflineScreen =
  | { kind: DiscoveryScreen | "activity" }
  | { kind: "connect" | "compose"; peer: string; from: DiscoveryScreen; route?: "lan" | "ble"; pick?: boolean }
  /** XFER receiver: connected, waiting for the other device to offer files. */
  | { kind: "receive"; peer: string; from: DiscoveryScreen }
  | { kind: "conversation"; peer: string; from: DiscoveryScreen | "activity" }
  | { kind: "record"; id: string; from: "activity" | "discovery"; sender?: string };

interface XferNavigation {
  initialTransferId?: string;
  onTransferFocus?: (id: string | null) => void;
  onCloseTransfer?: () => void;
  localIdentity?: OfflineTransferIdentity;
  /** XFER after pairing: send files now, or wait for the other device's files. */
  initialIntent?: "send" | "receive";
  /** A Mesh message a notice asked to open. */
  initialMessage?: { id: string; sender: string };
  /** Marks incoming Mesh messages read once they are on screen. */
  onMeshRead?: (messages: { id: string; sender: string }[]) => unknown;
}

function GuidedOfflineWorkspace({ mode, accountId, status, messages, transfers, busy, run, vaultUnlocked, onNavigate, onToggleDiscovery, relay, initialPeer, initialTransferId, onTransferFocus, onCloseTransfer, localIdentity, initialMessage, onMeshRead, initialIntent }: {
  mode: OfflineMode; accountId: string; status: OfflineStatus; messages: MeshMessage[] | null;
  transfers: OfflineTransfer[] | null; busy: boolean; run: RunAction; vaultUnlocked: boolean;
  onNavigate: (page: Page) => void; onToggleDiscovery: DiscoveryAction; relay: RelayAvailability; initialPeer?: string;
} & XferNavigation) {
  const android = status.platform === "android";
  const paired = initialPeer && status.peers.some((candidate) => candidate.fingerprint === initialPeer && peerAllows(candidate, mode));
  const [scope, setScope] = useState<"mode" | "both">("mode");
  const [screen, setScreen] = useState<OfflineScreen>(() => {
    if (mode === "xfer" && initialTransferId) return { kind: "record", id: initialTransferId, from: "activity" };
    if (mode === "mesh" && initialMessage) return { kind: "record", id: initialMessage.id, from: "activity", sender: initialMessage.sender };
    if (paired && initialPeer) return mode === "mesh"
      ? { kind: "conversation", peer: initialPeer, from: "discovery" }
      : initialIntent === "receive"
        ? { kind: "receive", peer: initialPeer, from: "discovery" }
        : { kind: "compose", peer: initialPeer, from: "discovery" };
    return { kind: "discovery" };
  });
  const [recipients, setRecipients] = useState<string[]>(() => paired && initialPeer ? [initialPeer] : []);
  const heading = useRef<HTMLHeadingElement>(null);
  const xfer = mode === "xfer";
  const focusedTransfer = xfer && screen.kind === "record" ? screen.id : null;
  useEffect(() => { onTransferFocus?.(focusedTransfer); }, [focusedTransfer, onTransferFocus]);
  useEffect(() => () => onTransferFocus?.(null), [onTransferFocus]);
  const peer = "peer" in screen ? status.peers.find(({ fingerprint }) => fingerprint === screen.peer) : undefined;
  const transfer = xfer && screen.kind === "record" ? transfers?.find(({ id }) => id === screen.id) : undefined;
  const message = !xfer && screen.kind === "record" ? messages?.find((entry) => entry.id === screen.id && (
    screen.sender ? entry.direction === "incoming" && entry.sender === screen.sender : entry.direction === "outgoing"
  )) : undefined;
  const complete = transfer?.status === "verified" || (message?.direction === "outgoing" && message.status === "delivered");
  // An incoming message on screen has been read.
  const unreadId = message?.direction === "incoming" && message.readAt == null ? message.id : null;
  const unreadSender = unreadId ? message?.sender ?? null : null;
  useEffect(() => {
    if (unreadId && unreadSender) void onMeshRead?.([{ id: unreadId, sender: unreadSender }]);
  }, [onMeshRead, unreadId, unreadSender]);
  function reply(sender: string) {
    const known = status.peers.find(({ fingerprint }) => fingerprint === sender);
    if (known && peerAllows(known, "mesh") && !known.disconnected) {
      setRecipients([sender]);
      setScreen({ kind: "conversation", peer: sender, from: "discovery" });
    } else {
      setScreen({ kind: "connect", peer: sender, from: "discovery" });
    }
  }
  const title = screen.kind === "discovery" ? (xfer ? "Qguard XFER" : "Qguard Mesh")
    : screen.kind === "devices" ? "Nearby devices"
    : screen.kind === "connect" ? "Connect to device"
    : screen.kind === "compose" ? (xfer ? "Send files" : "Message several devices")
    : screen.kind === "conversation" ? "Conversation"
    : screen.kind === "receive" ? "Waiting for files"
    : screen.kind === "activity" ? (xfer ? "Transfers" : "Message activity")
    : xfer ? (complete ? "Transfer complete" : transfer?.status === "awaitingConsent" && transfer.direction === "incoming" ? "Incoming file offer" : "Transfer progress")
    : message?.direction === "incoming" ? "Message received" : complete ? "Message delivered" : "Message delivery";
  useEffect(() => {
    if (screen.kind !== "discovery") {
      heading.current?.focus({ preventScroll: true });
      heading.current?.scrollIntoView({ block: "nearest" });
    }
  }, [screen.kind, title]);

  function selectPeer(id: string, from: DiscoveryScreen) {
    const known = status.peers.find(({ fingerprint }) => fingerprint === id);
    if (!xfer && known && peerAllows(known, "mesh") && !known.disconnected && !known.blocked) {
      setScreen({ kind: "conversation", peer: id, from });
      return;
    }
    setScreen({ kind: "connect", peer: id, from });
  }

  function goBack() {
    if (focusedTransfer && focusedTransfer === initialTransferId && onCloseTransfer) {
      onCloseTransfer();
      return;
    }
    if (screen.kind === "compose" && !xfer && peer && peerAllows(peer, "mesh")) setScreen({ kind: "conversation", peer: screen.peer, from: screen.from });
    else if (screen.kind === "compose") setScreen({ kind: "connect", peer: screen.peer, from: screen.from });
    else if ("from" in screen) setScreen({ kind: screen.from });
    else setScreen({ kind: "discovery" });
  }

  function prepare(route?: "lan" | "ble") {
    if (screen.kind !== "connect") return;
    setRecipients([screen.peer]);
    setScreen({ ...screen, kind: "compose", route });
  }

  async function connectPeer() {
    if (!peer || peer.blocked || !status.running) return;
    if (!peerAllows(peer, mode)) {
      // A new pairing, or adding this feature to an existing pairing. Both
      // users approve and compare a fresh code for the requested scope.
      await run(() => safeInvoke("offline_pairing_start", {
        peer: peer.fingerprint, mode, both: !peer.trusted && scope === "both", expectedAccount: accountId,
      }), undefined, "Preparing the connection request…");
      return;
    }
    if (!xfer) {
      setScreen({ kind: "conversation", peer: peer.fingerprint, from: screen.kind === "connect" ? screen.from : "discovery" });
      return;
    }
    await run(async () => {
      const route = await safeInvoke<"lan" | "ble">("offline_probe_peer", { peer: peer.fingerprint, mode, expectedAccount: accountId });
      prepare(route);
    }, undefined, "Verifying the secure connection…");
  }

  const showRecord = (id: string) => setScreen({ kind: "record", id, from: "discovery" });
  const labelPeer = (id: string) => offlinePeerName(status.peers.find(({ fingerprint }) => fingerprint === id), id);
  const sendAgain = (target: string, pick = false) => {
    const known = status.peers.find(({ fingerprint }) => fingerprint === target);
    if (known && peerAllows(known, "xfer") && !known.disconnected) {
      setRecipients([target]);
      setScreen({ kind: "compose", peer: target, from: "discovery", pick });
    } else {
      setScreen({ kind: "connect", peer: target, from: "discovery" });
    }
  };
  // Direct Wi-Fi links (XFER over Bluetooth-only pairs) show on every screen:
  // the join prompt must be visible wherever the user is.
  const linkCards = xfer && status.peers.some((candidate) => candidate.wifiLink)
    ? <div className="space-y-3">{status.peers.filter((candidate) => candidate.wifiLink).map((candidate) =>
      <WifiLinkCard key={candidate.fingerprint} peer={candidate} {...{ accountId, busy, run }} />)}</div>
    : null;
  const waitFor = (target: string) => setScreen({ kind: "receive", peer: target, from: "discovery" });
  const openArrival = useCallback((id: string) => setScreen({ kind: "record", id, from: "discovery" }), []);
  const smart = status.smartConnect;
  const needsPermission = android && status.running && smart?.bluetoothAvailable && !smart.bluetoothPermissionGranted;
  const canRetry = status.running && smart?.bluetoothAvailable && smart.bluetoothPermissionGranted && !smart.bluetoothScanning;
  const visiblePeers = status.peers.filter(({ trusted, lastSeen, blocked }) => !blocked && (trusted || lastSeen !== null));
  const PeerIcon = offlinePairingPlatform(peer?.platform).icon;
  const incomingOffers = transfers?.filter(({ direction, status }) => direction === "incoming" && status === "awaitingConsent").length ?? 0;

  if (transfer) {
    const firstSavedFile = transfer.files.findIndex((file) => file.canOpenFile || file.canOpenFolder);
    // One connection session can carry several transfers: after a verified
    // transfer the sender picks more files for the same device, and the
    // receiver goes back to waiting, without pairing or radar scanning again.
    const nextAction = transfer.status !== "verified" ? undefined
      : transfer.direction === "outgoing"
        ? { kind: "send" as const, onSelect: () => sendAgain(transfer.recipient, true) }
        : { kind: "receive" as const, onSelect: () => waitFor(transfer.sender) };
    return <div className="offline-guided-flow" data-desktop={!android && status.platform !== "ios"}
      data-transfer-monitor="true" data-screen={complete ? "complete" : "record"}>
      {linkCards}
      <XferTransferDashboard {...{ transfer, status, localIdentity, nextAction }} onBack={goBack} onDone={goBack}
        actions={<>
          <TransferControls {...{ transfer, busy, run, accountId }} running={status.running} />
          <TransferRecovery transfer={transfer} onSendAgain={sendAgain} />
        </>}
        details={<>
          <TransferConsentActions {...{ transfer, run, busy, vaultUnlocked }} />
          {transfer.direction === "incoming" && transfer.status === "verified" && !transfer.localCopyRetained
            && <p className={muted}>The receipt is retained. The protected local file copy has expired.</p>}
          {transfer.localCopyRetained && <p className={muted}>Quantum Vault uses your existing backup setting for imported files.</p>}
        </>}
        completionActions={firstSavedFile >= 0 && <OpenTransferredFile {...{ transfer, accountId, busy, run }} file={firstSavedFile} platform={status.platform} />}
        fileActions={(_, index) => <TransferFileActions {...{ transfer, run, busy, vaultUnlocked, onNavigate }} file={index}>
          {index !== firstSavedFile && <OpenTransferredFile {...{ transfer, accountId, busy, run }} file={index} platform={status.platform} />}
        </TransferFileActions>} />
    </div>;
  }

  return <div className="offline-guided-flow" data-desktop={!android && status.platform !== "ios"} data-screen={complete ? "complete" : screen.kind}>
    {linkCards}
    {/* The shell already names the page (Qguard Mesh / Qguard XFER), so the
        radar screen opens directly on the Discovery radar, whose header holds
        the Offline settings control. Deeper screens keep Back and a title. */}
    {screen.kind !== "discovery" && screen.kind !== "conversation" && <header className="offline-mobile-header">
      <button type="button" aria-label="Back" className={`${button} !px-3`} disabled={busy} onClick={goBack}><ArrowLeft size={20} aria-hidden /></button>
      <div><h2 ref={heading} tabIndex={-1} className="text-lg font-bold text-ink-950">{title}</h2>
        <p className={muted}>{xfer ? "Qguard XFER" : "Qguard Mesh"}</p></div>
      <button type="button" aria-label="Offline settings" className={`${button} !px-3`} disabled={busy} onClick={() => onNavigate("offline-settings")}><SlidersHorizontal size={19} aria-hidden /></button>
    </header>}
    {screen.kind === "discovery" && <>
      <RadarConsole {...{ mode, status, busy, onToggleDiscovery }} selected={[]}
        activeTransfers={transfers?.filter(({ status: state }) => state === "active").length ?? 0}
        onSelect={(id) => selectPeer(id, "discovery")} onOpenDevices={() => setScreen({ kind: "devices" })} onOpenSettings={() => onNavigate("offline-settings")} />
      {needsPermission && <p className={muted}>Bluetooth permission required</p>}
      <div className="offline-mobile-actions">
        {needsPermission && <button type="button" className={button} disabled={busy} onClick={() => void run(() => withNativeDialog(() => safeInvoke("offline_bluetooth_permissions")))}><Bluetooth size={16} aria-hidden /> Allow Nearby devices</button>}
        {canRetry && <button type="button" className={button} disabled={busy} onClick={() => void run(() => safeInvoke("offline_bluetooth_restart"))}>Retry Bluetooth discovery</button>}
        <button type="button" className={button} onClick={() => setScreen({ kind: "activity" })}><History size={16} aria-hidden /> {xfer ? "Transfers" : "Message activity"}
          {incomingOffers > 0 && <span className="offline-state-chip" data-tone="cyan">{incomingOffers} incoming</span>}
        </button>
      </div>
    </>}
    {screen.kind === "devices" && <section className="offline-mobile-surface offline-mobile-card" aria-label="Nearby and saved devices">
      <div className="offline-mobile-list">
        {visiblePeers.map((device) => {
          const platform = offlinePairingPlatform(device.platform);
          const connection = device.disconnected ? "Disconnected" : device.connected ? "Connected" : device.lastSeen === null ? "Saved device" : "Discovered";
          const access = !device.trusted ? "Approval required"
            : peerAllows(device, mode) ? "Trusted" : `Trusted · ${xfer ? "XFER" : "Mesh"} not approved`;
          return <button className="offline-mobile-row focus-ring" key={device.fingerprint} type="button" onClick={() => selectPeer(device.fingerprint, "devices")}>
            <span className="offline-device-icon" aria-hidden>
              <PeerPicture fingerprint={device.fingerprint} digest={device.avatar} fallback={<platform.icon size={19} />} />
            </span>
            <span><strong>{offlinePeerName(device, `Device ${device.fingerprint.slice(0, 8)}`)}</strong>
              <small>{device.owner && device.label ? `${device.label} · ` : ""}{platform.name} · {connection} · {access}</small></span>
            <ChevronRight size={16} aria-hidden />
          </button>;
        })}
      </div>
      {!visiblePeers.length && <p className={muted}>Start discovery on both devices to find a nearby peer.</p>}
    </section>}
    {screen.kind === "connect" && <section className="offline-mobile-surface offline-mobile-card space-y-4" aria-label="Peer connection">
      {peer && !peer.blocked ? (() => {
        const allowed = peerAllows(peer, mode);
        const upgrade = peer.trusted && !allowed;
        const feature = capabilityNames[mode];
        return <>
          <div className="offline-mobile-center space-y-2">
            <div className="offline-mobile-emblem"><PeerIcon size={28} aria-hidden /></div>
            <h3 className="break-all text-lg font-bold text-ink-950">{offlinePeerName(peer, `Device ${peer.fingerprint.slice(0, 8)}`)}</h3>
            <p className={muted}>{peer.owner && peer.label ? `${peer.label} · ` : ""}{offlinePairingPlatform(peer.platform).name}</p>
            <p className={muted}>{allowed ? "Connect to authenticate the current local link."
              : upgrade ? `This device is trusted, but ${feature} was not approved. Send a request to add it. Both users compare a new verification code.`
              : "Send a connection request. Both devices must approve and confirm the same verification code."}</p>
          </div>
          {!peer.trusted && <fieldset className="offline-scope" disabled={busy}>
            <legend>Connection type</legend>
            <label>
              <input type="radio" name="offline-scope" checked={scope === "mode"} onChange={() => setScope("mode")} />
              <span><strong>{feature} only</strong><small>The other device can {xfer ? "offer you files" : "exchange nearby messages"} after both users approve.</small></span>
            </label>
            <label>
              <input type="radio" name="offline-scope" checked={scope === "both"} onChange={() => setScope("both")} />
              <span><strong>Mesh messaging and XFER</strong><small>One approval covers nearby messages and file offers. Every file still needs your consent.</small></span>
            </label>
          </fieldset>}
          {xfer && <p className={muted}>File transfers use a reachable local Wi-Fi, Ethernet, or hotspot connection.</p>}
          <div className="offline-mobile-actions">
            <button type="button" className={primary} disabled={busy || !status.running} onClick={() => void connectPeer()}>
              {allowed ? "Connect" : upgrade ? `Add ${xfer ? "XFER" : "Mesh"} access` : "Connect Device"}
            </button>
            {allowed && !peer.disconnected && <button type="button" className={button} disabled={busy} onClick={() => prepare()}>Continue without connection</button>}
            {xfer && allowed && !peer.disconnected && <button type="button" className={button} disabled={busy}
              onClick={() => setScreen({ kind: "receive", peer: peer.fingerprint, from: screen.kind === "connect" ? screen.from : "discovery" })}>
              <Inbox size={16} aria-hidden /> Wait for files
            </button>}
          </div>
        </>;
      })() : <p className={muted}>This device is no longer visible. Return to discovery to find it again.</p>}
    </section>}
    {screen.kind === "compose" && <>
      <div className="offline-mobile-route"><MonitorSmartphone size={18} aria-hidden /><div><strong className="break-all">{labelPeer(screen.peer)}</strong>
        <p className={muted}>{screen.route ? `Peer authenticated over ${screen.route === "ble" ? "Bluetooth" : "the local network"}` : peer && peerAllows(peer, mode) && !peer.disconnected ? "Trusted device. Qguard authenticates the connection when sending." : "Ready to prepare an item for the local queue"}</p>
        {xfer && <XferSessionBar peerId={screen.peer} {...{ peer, accountId, busy, run }} onDisconnected={() => setScreen({ kind: "discovery" })} />}
      </div></div>
      {xfer ? <TransferComposer {...{ status, busy, run, onNavigate }} recipient={screen.peer} onQueued={showRecord} autoPick={screen.pick} />
        : <MeshComposer {...{ status, recipients, run, busy, onNavigate }} onToggleRecipient={(id) => toggleRecipient(setRecipients, id)} onQueued={showRecord} />}
    </>}
    {screen.kind === "receive" && <XferReceiveWaiting peerId={screen.peer} {...{ peer, status, transfers, busy, onToggleDiscovery }}
      session={<XferSessionBar peerId={screen.peer} {...{ peer, accountId, busy, run }} onDisconnected={() => setScreen({ kind: "discovery" })} />}
      onArrival={openArrival}
      onSendInstead={() => { setRecipients([screen.peer]); setScreen({ kind: "compose", peer: screen.peer, from: screen.from }); }}
      onStop={goBack} />}
    {screen.kind === "conversation" && <MeshConversation peerId={screen.peer} peer={peer} messages={messages} running={status.running}
      onBack={goBack} onMeshRead={onMeshRead}
      onOpenMessage={(entry) => setScreen({ kind: "record", id: entry.id, from: "activity", sender: entry.direction === "incoming" ? entry.sender : undefined })}
      onGroupMessage={() => { setRecipients([screen.peer]); setScreen({ kind: "compose", peer: screen.peer, from: screen.from === "activity" ? "discovery" : screen.from }); }} />}
    {screen.kind === "activity" && (xfer ? <TransferActivity page="xfer" compact {...{ status, transfers, busy, run, vaultUnlocked, onNavigate }}
      onSendAgain={sendAgain} onMonitor={(id) => setScreen({ kind: "record", id, from: "activity" })} />
      : <MeshActivity {...{ status, messages, run, busy }} onOpen={(entry) => {
        const other = entry.direction === "incoming" ? entry.sender : entry.recipients.length === 1 ? entry.recipients[0] : null;
        if (other) setScreen({ kind: "conversation", peer: other, from: "activity" });
        else setScreen({ kind: "record", id: entry.id, from: "activity" });
      }} />)}
    {screen.kind === "activity" && xfer && !android && <div className="offline-mobile-actions">
      <button type="button" className={button} onClick={() => onNavigate("transfer-history")}>View transfer history</button>
      {relay === "available" && <button type="button" className={button} onClick={() => onNavigate("chat")}>Share online in Secure Chat</button>}
    </div>}
    {screen.kind === "record" && <>
      {complete && <div className="offline-mobile-surface offline-mobile-card offline-mobile-center space-y-2">
        <div className="offline-mobile-emblem" data-tone="success"><ShieldCheck size={32} aria-hidden /></div>
        <p className="font-bold text-ink-950">{xfer ? "File integrity verified" : "Delivery receipt confirmed"}</p>
      </div>}
      {message && <section className="offline-mobile-surface offline-mobile-card space-y-3" aria-label="Message receipt">
        {message.emergency && <p className="text-sm font-bold text-rose-700">Emergency message</p>}
        <p className="font-semibold text-ink-950">{message.direction === "incoming" ? `From ${labelPeer(message.sender)}` : `To ${message.recipients.map(labelPeer).join(", ")}`}{message.group ? ` · ${message.group}` : ""}</p>
        <p className="whitespace-pre-wrap break-words text-sm text-ink-950">{message.body}</p>
        {message.direction === "outgoing" && <p role="status" className={muted}>{message.status === "pending" ? meshPendingLabel(message) : message.status === "expired" ? "Delivery expired" : "Delivered"} · {message.deliveredTo.length}/{message.recipients.length} acknowledged</p>}
        <MeshSecurity />
        {message.status === "pending" && <button type="button" className={button} disabled={busy || !status.running} onClick={() => void run(() => safeInvoke("offline_mesh_retry"))}>Retry queued</button>}
        {message.direction === "incoming" && <button type="button" className={primary} onClick={() => reply(message.sender)}>
          <Reply size={16} aria-hidden /> Reply
        </button>}
      </section>}
      {!transfer && !message && <p role="status" className={muted}>Waiting for the local record…</p>}
      {complete && <div className="offline-mobile-actions"><button type="button" className={primary} onClick={() => setScreen({ kind: "discovery" })}>{xfer ? "Share again" : "New message"}</button></div>}
    </>}
  </div>;
}

export default function OfflinePage({ page, accountId, onNavigate, vaultUnlocked, relay = "unknown", initialPeer, ...xferNavigation }: {
  page: OfflinePageId; accountId: string; onNavigate: (page: Page) => void; vaultUnlocked: boolean; relay?: RelayAvailability; initialPeer?: string;
} & XferNavigation) {
  const { status, messages, transfers, error, refresh } = useOfflineSnapshot(page, accountId);
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const principalRequired = error?.includes("OFFLINE_PRINCIPAL_UNVERIFIED:") ?? false;
  const dashboard = page === "xfer" || page === "mesh";
  const section = sections[page];
  const Icon = section.icon;
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const run: RunAction = async (task, result, pending) => {
    if (busyRef.current) return false;
    busyRef.current = true;
    setBusy(true);
    setActionError(null);
    setNotice(null);
    setPendingAction(pending ?? null);
    try {
      const outcome = await task();
      refresh();
      if (outcome !== false && result) setNotice(result);
      return outcome !== false;
    } catch (actionFailure) {
      setActionError(offlineError(actionFailure));
      refresh();
      return false;
    } finally {
      busyRef.current = false;
      setBusy(false);
      setPendingAction(null);
    }
  };
  const toggleDiscovery = () => void run(
    () => safeInvoke(status?.running ? "offline_stop" : "offline_start"),
    undefined,
    status?.running ? "Stopping local discovery…" : "Starting local discovery…",
  );

  return <OfflineAccountContext.Provider value={accountId}><div className="offline-dashboard mx-auto max-w-7xl min-w-0 space-y-4 pb-3">
    {!dashboard && <nav aria-label="Offline workspaces" className="offline-nav">
      {Object.entries(sections).map(([id, item]) => <button type="button" className={id === page ? primary : button} key={id} aria-current={id === page ? "page" : undefined} onClick={() => onNavigate(id as OfflinePageId)}>
        <item.icon size={16} aria-hidden /> {item.label}
      </button>)}
    </nav>}
    {(!dashboard || !status) && <header className="shell-card flex flex-wrap items-center justify-between gap-4 p-4 sm:p-5">
      <div className="flex min-w-0 items-start gap-3">
        <span className="rounded-lg border border-line bg-canvas p-3 text-violet-600"><Icon size={20} aria-hidden /></span>
        <div>
          <h2 className="text-lg font-bold text-ink-950">{section.title}</h2>
          <p className={muted}>{section.note}</p>
          {status && <p className="mt-2 flex items-center gap-2 text-xs font-semibold text-ink-700">
            <Radio size={15} aria-hidden /> {status.running ? "Local networking is running" : "Local networking is stopped"}
          </p>}
        </div>
      </div>
      {status && <button type="button" className={status.running ? button : primary} disabled={busy} onClick={toggleDiscovery}>
        {status.running ? "Stop discovery" : "Start local discovery"}
      </button>}
    </header>}
    {(actionError || error || status?.networkError) && <div role="alert" className="shell-card flex flex-wrap items-center justify-between gap-2 p-4 text-sm text-ink-800">
      <p className="min-w-0 break-words">{actionError ?? (principalRequired ? "Connect to Qguard to verify this account session for offline use." : error ?? status?.networkError)}</p>
      {principalRequired
        ? <button type="button" className={primary} disabled={busy} onClick={() => void run(() => safeInvoke("offline_verify_principal"), "Local account session verified.", "Verifying account…")}>Verify local account</button>
        : error && <button type="button" className={button} onClick={refresh}>Refresh local status</button>}
    </div>}
    {notice && <p role="status" className="shell-card flex items-center gap-2 p-3 text-sm font-semibold text-ink-800"><ShieldCheck size={17} aria-hidden /> {notice}</p>}
    {pendingAction && <p role="status" className="shell-card p-3 text-sm font-semibold text-ink-800">{pendingAction}</p>}
    {!status && !error && <p role="status" className={muted}>Reading local networking state…</p>}
    {status && dashboard && <GuidedOfflineWorkspace key={page} mode={page} {...{ accountId, status, messages, transfers, busy, run, vaultUnlocked, onNavigate, relay, initialPeer }}
      {...xferNavigation} onToggleDiscovery={toggleDiscovery} />}
    {status?.smartConnect && page === "offline-settings" && <SmartConnectPanel {...{ status, run, busy }} />}
    {status && page === "offline-settings" && <PairingSettings {...{ status, busy, run, relay, accountId, onNavigate }} />}
    {status && page === "offline-settings" && <LinkDiagnostics accountId={accountId} peers={status.peers} />}
    {status && page === "transfer-history" && <TransferActivity {...{ page, status, transfers, busy, run, vaultUnlocked, onNavigate }} />}
  </div></OfflineAccountContext.Provider>;
}
