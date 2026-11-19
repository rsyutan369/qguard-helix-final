import { useState, type CSSProperties } from "react";
import {
  ArrowUpFromLine, Bluetooth, Check, CirclePause, File,
  FileText, FolderArchive, Image, List, LockKeyhole, MonitorSmartphone, Network, Play,
  Radar, ScanLine, ShieldCheck, SlidersHorizontal,
} from "lucide-react";
import { formatOfflineBytes, offlineLinkState, offlineSignalLabel, type OfflinePeer, type OfflineStatus, type OfflineTransfer } from "@/lib/offline";
import { offlinePairingPlatform } from "./OfflinePairingDialog";
import { PeerPicture } from "./PeerPicture";
import "./offline-dashboard.css";

const radarSlots = [[66, 19], [21, 51], [66, 77], [79, 51], [34, 19], [34, 77]];
const radarTicks = Array.from({ length: 48 }, (_, index) => index);

function peerName(peer: OfflinePeer) {
  return peer.label || `Nearby device ${peer.fingerprint.slice(0, 8)}`;
}

function discoveryLabel(peer: OfflinePeer) {
  const bluetooth = peer.discovery?.includes("ble");
  const wifi = peer.discovery?.includes("lan");
  const signal = bluetooth ? offlineSignalLabel(peer.rssi) : null;
  if (bluetooth && wifi) return signal ? `Bluetooth (${signal}) + local network` : "Bluetooth + local network";
  if (bluetooth) return signal ? `Bluetooth · ${signal}` : "Bluetooth";
  if (wifi) return "Local network";
  return "Local discovery";
}

export function RadarConsole({ mode, status, selected, busy, onSelect, onToggleDiscovery, onOpenSettings, onOpenDevices, activeTransfers = 0 }: {
  mode: "mesh" | "xfer";
  /** Transfers the engine is moving right now (sending or receiving). */
  activeTransfers?: number;
  status: OfflineStatus;
  selected: readonly string[];
  busy: boolean;
  onSelect: (fingerprint: string) => void;
  onToggleDiscovery: () => void;
  onOpenSettings: () => void;
  onOpenDevices?: () => void;
}) {
  const [motionPaused, setMotionPaused] = useState(false);
  const bluetoothScanning = status.running && status.smartConnect?.bluetoothScanning === true;
  const bluetoothAdvertising = status.running && status.smartConnect?.bluetoothAdvertising === true;
  const lanListening = status.running && status.lanDiscoveryRunning;
  const sweep = bluetoothScanning || lanListening;
  const nearby = sweep ? status.peers.filter((peer) => !peer.blocked && peer.lastSeen !== null && (
    (bluetoothScanning && peer.discovery?.includes("ble")) || (lanListening && peer.discovery?.includes("lan"))
  )) : [];
  const nearbyIds = new Set(nearby.map((peer) => peer.fingerprint));
  const saved = status.peers.filter((peer) => peer.trusted && !peer.blocked && !nearbyIds.has(peer.fingerprint));
  const displayed = [...nearby, ...saved];
  // Devices with an open, authenticated channel, as the core reports them.
  // Once a session exists the console shows it instead of "scanning": the
  // radios keep listening for other devices, but this device is connected.
  const connected = status.peers.filter((peer) => !peer.blocked && peer.link?.state === "connected");
  const reconnecting = status.peers.filter((peer) => !peer.blocked && peer.link && peer.link.state !== "connected");
  const inSession = connected.length > 0 || activeTransfers > 0;
  const discoveryState = activeTransfers > 0 ? `Transfer in progress${connected.length ? ` · ${connected.length} connected` : ""}`
    : connected.length > 0 ? `Connected to ${connected.length === 1 ? peerName(connected[0]) : `${connected.length} devices`}`
    : reconnecting.length > 0 ? `${reconnecting[0].link?.state === "connecting" ? "Connecting to" : "Reconnecting to"} ${peerName(reconnecting[0])}`
    : bluetoothScanning ? "Bluetooth scanning"
    : lanListening ? "LAN discovery listening"
    : bluetoothAdvertising ? "Bluetooth advertising"
    : status.running ? "Local listener active" : "Discovery stopped";
  const MapIcon = mode === "mesh" ? Network : Radar;
  const HeadingIcon = mode === "mesh" ? Network : ArrowUpFromLine;
  const desktop = ["windows", "macos", "linux"].includes(status.platform);

  function choosePeer(peer: OfflinePeer) {
    if (peer.trusted || onOpenDevices) onSelect(peer.fingerprint);
    else onOpenSettings();
  }

  return <section className="offline-radar-console offline-surface" aria-labelledby="offline-radar-title">
    <header className="offline-console-heading">
      <span className="offline-feature-icon"><HeadingIcon size={23} aria-hidden /></span>
      <div className="min-w-0">
        <h2 id="offline-radar-title">{onOpenDevices ? "Discovery radar" : mode === "xfer" ? "Qguard XFER" : "Qguard Mesh"}</h2>
        {!onOpenDevices && <p>{mode === "xfer" ? "Secure file transfer over a local link" : "Secure messaging for trusted nearby devices"}</p>}
      </div>
      <span className="offline-state-chip" data-tone={inSession ? "green" : sweep ? "cyan" : "neutral"} role="status">
        <span className="offline-state-dot" aria-hidden /> {discoveryState}
      </span>
      {onOpenDevices && <button className="offline-icon-button offline-console-settings focus-ring" type="button"
        aria-label="Offline settings" title="Offline settings" disabled={busy} onClick={onOpenSettings}>
        <SlidersHorizontal size={18} aria-hidden />
      </button>}
    </header>

    <div className="offline-radar-layout">
      <div className="offline-radar-pane" data-desktop={desktop}>
        <div className="offline-radar" data-sweeping={sweep && !inSession && !motionPaused}>
          <div className="offline-radar-field" aria-hidden />
          <svg className="offline-radar-grid" viewBox="0 0 320 320" aria-hidden="true">
            <g fill="none" stroke="currentColor">
              {[35, 59, 83, 108, 134].map((radius) => <circle key={radius} cx="160" cy="160" r={radius} />)}
              <path d="M26 160h268M160 26v268M65 65l190 190M65 255L255 65" opacity=".48" />
              {radarTicks.map((tick) => <line key={tick} x1="160" x2="160" y1="15" y2={tick % 4 === 0 ? "24" : "20"}
                opacity={tick % 4 === 0 ? ".9" : ".48"} transform={`rotate(${tick * 7.5} 160 160)`} />)}
            </g>
          </svg>
          <div className="offline-radar-beam" aria-hidden />
          <span className="offline-radar-core" aria-hidden><ShieldCheck size={30} /></span>
          {nearby.slice(0, radarSlots.length).map((peer, index) => {
            const [x, y] = radarSlots[index];
            const selectedPeer = selected.includes(peer.fingerprint);
            const PlatformIcon = offlinePairingPlatform(peer.platform).icon;
            return <button key={peer.fingerprint} className="offline-radar-marker focus-ring"
              style={{ "--radar-x": `${x}%`, "--radar-y": `${y}%` } as CSSProperties}
              aria-label={peer.trusted ? `Select ${peerName(peer)} on radar` : `Review ${peerName(peer)} on radar`}
              title={desktop ? peerName(peer) : undefined}
              aria-pressed={peer.trusted ? selectedPeer : undefined} onClick={() => choosePeer(peer)} type="button">
              <span className="offline-marker-icon">
                <PeerPicture fingerprint={peer.fingerprint} digest={peer.avatar} fallback={<PlatformIcon size={18} aria-hidden />} />
              </span>
              <span className="offline-marker-name" aria-hidden>{peerName(peer)}</span>
            </button>;
          })}
        </div>
        <div className="offline-radar-caption">
          <span><MapIcon size={14} aria-hidden /> Schematic device map{nearby.length > radarSlots.length ? ` · ${radarSlots.length} of ${nearby.length}` : ""}</span>
          {sweep && !inSession && <button type="button" className="offline-motion-toggle focus-ring" aria-label="Pause radar animation"
            aria-pressed={motionPaused} title={motionPaused ? "Resume radar animation" : "Pause radar animation"}
            onClick={() => setMotionPaused((paused) => !paused)}>
            {motionPaused ? <Play size={16} aria-hidden /> : <CirclePause size={17} aria-hidden />}
          </button>}
        </div>
      </div>
      <div className="offline-device-pane">
        {connected.length > 0 && <ul className="offline-device-list" aria-label="Connected devices">
          {connected.map((peer) => {
            const link = offlineLinkState(peer);
            return <li key={`link:${peer.fingerprint}`}>
              <button type="button" className="offline-device-row focus-ring" data-connected="true" onClick={() => onSelect(peer.fingerprint)}>
                <span className="offline-device-icon">
                  <PeerPicture fingerprint={peer.fingerprint} digest={peer.avatar} fallback={<MonitorSmartphone size={18} aria-hidden />} />
                </span>
                <span className="offline-device-copy">
                  <strong>{peerName(peer)}</strong>
                  <small>{link.label}{link.detail ? ` · ${link.detail}` : ""}</small>
                </span>
                <span className="offline-state-dot offline-device-indicator" data-tone="green" aria-hidden />
              </button>
            </li>;
          })}
        </ul>}
        {onOpenDevices ? <p className="text-xs font-semibold text-ink-600">{nearby.length} discovered · {saved.length} saved</p> : <div className="offline-panel-heading">
          <div className="min-w-0"><h3>Nearby devices</h3><p>{nearby.length} discovered · {saved.length} saved</p></div>
          <button className="offline-icon-button focus-ring" type="button" aria-label="Manage device trust" title="Manage device trust" onClick={onOpenSettings}>
            <LockKeyhole size={17} aria-hidden />
          </button>
        </div>}
        {onOpenDevices ? <button type="button" className="offline-scan-button focus-ring" onClick={onOpenDevices}>Nearby devices</button>
          : displayed.length > 0 ? <ul className="offline-device-list" aria-label="Nearby and saved devices">
          {displayed.map((peer) => {
            const TransportIcon = peer.discovery?.includes("ble") ? Bluetooth : Network;
            return <li key={peer.fingerprint}>
              <button type="button" className="offline-device-row focus-ring"
                aria-pressed={peer.trusted ? selected.includes(peer.fingerprint) : undefined}
                onClick={() => choosePeer(peer)}>
                <span className="offline-device-icon">
                  <PeerPicture fingerprint={peer.fingerprint} digest={peer.avatar} fallback={<MonitorSmartphone size={18} aria-hidden />} />
                </span>
                <span className="offline-device-copy">
                  <strong>{peerName(peer)}</strong>
                  <small>{peer.link ? offlineLinkState(peer).label : nearbyIds.has(peer.fingerprint) ? discoveryLabel(peer) : "Saved device"} · {peer.trusted ? "Pinned" : "Review fingerprint"}</small>
                </span>
                {selected.includes(peer.fingerprint)
                  ? <Check size={17} className="offline-device-indicator" aria-hidden />
                  : nearbyIds.has(peer.fingerprint) && <TransportIcon size={16} className="offline-device-indicator" aria-hidden />}
              </button>
            </li>;
          })}
        </ul> : <p className="offline-device-empty">{sweep
          ? "Waiting for nearby devices. Start discovery on the other device too."
          : status.running ? "Check connection options to enable nearby discovery." : "Start local discovery to find nearby devices."}</p>}
        <button type="button" className="offline-scan-button focus-ring" disabled={busy} onClick={onToggleDiscovery}>
          <ScanLine size={18} aria-hidden /> {status.running ? sweep ? "Stop discovery" : "Stop local networking" : "Start local discovery"}
        </button>
      </div>
    </div>
  </section>;
}

export function transferPercent(transfer: OfflineTransfer) {
  if (transfer.status === "verified") return 100;
  if (transfer.totalBytes <= 0) return 0;
  return Math.min(99, Math.max(0, 100 * transfer.verifiedBytes / transfer.totalBytes));
}

function progressText(transfer: OfflineTransfer) {
  return `${formatOfflineBytes(transfer.verifiedBytes)} of ${formatOfflineBytes(transfer.totalBytes)} verified`;
}

export function TransferBar({ transfer }: { transfer: OfflineTransfer }) {
  const percent = transferPercent(transfer);
  return <div className="offline-progress-track" role="progressbar" aria-label="Verified transfer bytes"
    aria-valuenow={Math.floor(percent)} aria-valuetext={progressText(transfer)} data-complete={transfer.status === "verified"}>
    <span style={{ transform: `scaleX(${percent / 100})` }} />
  </div>;
}

export function TransferFileIcon({ name, size = 20 }: { name?: string; size?: number }) {
  const extension = name?.split(".").pop()?.toLowerCase();
  const Icon = extension && /^(png|webp|jpg|jpeg|gif|heic|avif)$/.test(extension) ? Image
    : extension && /^(zip|7z|tar|gz|rar)$/.test(extension) ? FolderArchive
      : extension && /^(pdf|docx?|txt|md|xlsx?|pptx?)$/.test(extension) ? FileText : File;
  return <Icon size={size} aria-hidden />;
}

export function QueueHeading({ active, verified }: { active?: number; verified?: number }) {
  return <div className="offline-panel-heading">
    <div className="offline-queue-title"><List size={19} aria-hidden /><h3 id="offline-queue-title">Transfer queue</h3></div>
    {active !== undefined && verified !== undefined && <p>{active} active · {verified} verified</p>}
  </div>;
}
