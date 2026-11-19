import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import {
  ArrowLeft, ChevronDown, ChevronRight, ChevronsRight, Clock3, FilePlus, Fingerprint, Folder, Gauge, Inbox,
  MoreVertical, ShieldCheck, ShieldQuestionMark, TriangleAlert, Zap,
} from "lucide-react";
import {
  formatOfflineBytes, formatOfflineTime, offlinePeerName, type OfflineStatus, type OfflineTransfer,
} from "@/lib/offline";
import { TransferFileIcon } from "./OfflineDashboard";
import { offlinePairingPlatform } from "./OfflinePairingDialog";
import { useOfflineAvatar } from "@/lib/offline-avatars";
import "./xfer-transfer-dashboard.css";

export interface XferLocalIdentity {
  displayName?: string | null;
  deviceName?: string | null;
  avatarUrl?: string | null;
}

interface XferTransferDashboardProps {
  transfer: OfflineTransfer;
  status: OfflineStatus;
  localIdentity?: XferLocalIdentity;
  actions?: ReactNode;
  details?: ReactNode;
  fileActions?: (file: OfflineTransfer["files"][number], index: number) => ReactNode;
  completionActions?: ReactNode;
  /** After a verified transfer: keep the session going (send or receive more). */
  nextAction?: { kind: "send" | "receive"; onSelect: () => void };
  onBack: () => void;
  onDone?: () => void;
}

const labels: Record<OfflineTransfer["status"], string> = {
  awaitingConsent: "Awaiting consent",
  queued: "Waiting for a connection",
  active: "Transferring",
  paused: "Paused",
  stopped: "Stopped",
  interrupted: "Connection interrupted",
  verified: "Integrity verified",
  rejected: "Offer declined",
  cancelled: "Cancelled",
  expired: "Transfer expired",
  failed: "Transfer failed",
};

const failureLabels: Record<NonNullable<OfflineTransfer["errorKind"]>, string> = {
  connectionLost: "Connection lost",
  peerUnavailable: "Receiver unavailable",
  storageFull: "Insufficient storage",
  fileWrite: "File write failed",
  encryption: "Encryption failed",
  integrity: "Integrity verification failed",
  timeout: "Transfer timed out",
  interrupted: "Transfer interrupted",
};

const securityPhases = {
  initializing: ["Encryption initializing", "Waiting for the authenticated transfer session."],
  keyEstablishment: ["Quantum key establishment", "Authenticating both devices and establishing hybrid session keys."],
  payloadEncryption: ["Payload encryption", "Session keys are established. File data is sealed before it leaves this device."],
  secureTransfer: ["Secure transfer active", "Every frame is encrypted and authenticated with a fresh per-frame key."],
  integrityVerification: ["Integrity verification", "Checking every received byte against the SHA3-256 manifest digests."],
  verified: ["Transfer security verified", "The receiver confirmed every file against its SHA3-256 digest."],
  error: ["Transfer security error", "The transfer engine could not establish or verify protection. No file was marked complete."],
} as const;

const SAMPLE_WINDOW = 90;

function formatDuration(milliseconds: number) {
  const seconds = Math.max(0, Math.floor(milliseconds / 1_000));
  return [Math.floor(seconds / 3_600), Math.floor(seconds / 60) % 60, seconds % 60]
    .map((value) => String(value).padStart(2, "0")).join(":");
}

function formatRate(rate?: number | null) {
  return typeof rate === "number" && Number.isFinite(rate) && rate >= 0 ? `${formatOfflineBytes(rate)}/s` : "Unavailable";
}

/** Group a hex session prefix for reading aloud: 7F3A 91D4 C2B0 11EE. */
export function formatSessionId(value?: string | null) {
  return value ? value.toUpperCase().match(/.{1,4}/g)?.join(" ") ?? value : null;
}

function shortDigest(digest: string) {
  return digest.length > 24 ? `${digest.slice(0, 12)}…${digest.slice(-8)}` : digest;
}

function initials(name: string) {
  const words = name.trim().split(/\s+/u).filter(Boolean);
  const letters = words.length > 1 ? `${[...words[0]][0]}${[...words.at(-1)!][0]}` : [...(words[0] ?? "")].slice(0, 2).join("");
  return letters.toLocaleUpperCase() || "?";
}

function Participant({ role, fingerprint, status, localIdentity }: {
  role: "Sender" | "Receiver"; fingerprint: string; status: OfflineStatus; localIdentity?: XferLocalIdentity;
}) {
  const [failedAvatar, setFailedAvatar] = useState<string | null>(null);
  const local = fingerprint === status.fingerprint;
  const peer = local ? undefined : status.peers.find((candidate) => candidate.fingerprint === fingerprint);
  const trustedPeer = peer?.trusted ? peer : undefined;
  const platform = offlinePairingPlatform(local ? status.platform : trustedPeer?.pairedAt ? trustedPeer.platform : null);
  const Icon = platform.icon;
  const owner = local ? localIdentity?.displayName || status.localOwner : trustedPeer?.owner;
  const deviceLabel = local ? localIdentity?.deviceName || "This device" : trustedPeer?.label;
  const name = owner || (local ? "You" : offlinePeerName(trustedPeer, `Device ${fingerprint.slice(0, 8)}`));
  const device = owner ? deviceLabel || platform.name : local ? "This device" : `ID ${fingerprint.slice(0, 8).toUpperCase()}`;
  // The peer's picture arrives over its authenticated channel and is stored
  // under its fingerprint; this device's falls back to the synced thumbnail
  // when the online profile picture is unavailable (offline mode).
  const synced = useOfflineAvatar(local ? null : trustedPeer?.fingerprint, local ? status.localAvatar : trustedPeer?.avatar);
  const avatar = local ? localIdentity?.avatarUrl || synced : synced;
  const trusted = local || Boolean(trustedPeer);

  return <div className="xfer-live-participant" data-local={local}>
    <span className="xfer-live-role">{role}{local ? " · You" : ""}</span>
    <span className="xfer-live-avatar" data-initials={Boolean(owner) && !(avatar && avatar !== failedAvatar)}>
      {avatar && avatar !== failedAvatar
        ? <img src={avatar} alt="" referrerPolicy="no-referrer" onError={() => setFailedAvatar(avatar)} />
        : owner ? <span aria-hidden>{initials(owner)}</span> : <Icon size={25} aria-hidden />}
      {trusted && <span className="xfer-live-peer-shield"><ShieldCheck size={13} aria-hidden /></span>}
    </span>
    <strong>{name}</strong>
    <span>{device}</span>
    <span className="xfer-live-platform"><Icon size={13} aria-hidden /> {platform.name}</span>
    <span className="xfer-live-badge" data-tone={trusted ? "trusted" : "unknown"}>
      {trusted ? <ShieldCheck size={12} aria-hidden /> : <ShieldQuestionMark size={12} aria-hidden />}
      {local ? "This device" : trusted ? "Verified device" : "Not paired"}
    </span>
  </div>;
}

interface ChartPoint { x: number; y: number; at: number; rate: number }

/**
 * Throughput from the transfer engine's own measurements. Stalls are measured
 * zero samples. A pause or interruption ends sampling, so a long gap between
 * samples is drawn as a dashed break rather than an invented slope.
 */
function Throughput({ transfer }: { transfer: OfflineTransfer }) {
  const fillId = useId();
  const samples = (transfer.throughput ?? [])
    .filter(({ atMs, bytesPerSecond }) => Number.isFinite(atMs) && Number.isFinite(bytesPerSecond) && bytesPerSecond >= 0)
    .slice(-SAMPLE_WINDOW);
  const first = samples[0];
  const last = samples.at(-1);
  const peak = Math.max(0, ...samples.map(({ bytesPerSecond }) => bytesPerSecond));
  const top = Math.max(1, peak);
  const span = first && last ? last.atMs - first.atMs : 0;
  const intervals = samples.slice(1).map((sample, index) => sample.atMs - samples[index].atMs).sort((a, b) => a - b);
  const typical = intervals[Math.floor(intervals.length / 2)] ?? 1_000;
  const gapMs = Math.max(4_000, typical * 3);
  const segments: ChartPoint[][] = [];
  const gaps: [ChartPoint, ChartPoint][] = [];
  if (span > 0) {
    let previous: ChartPoint | undefined;
    for (const { atMs, bytesPerSecond } of samples) {
      const point = { x: 3 + 314 * (atMs - first!.atMs) / span, y: 65 - 58 * bytesPerSecond / top, at: atMs, rate: bytesPerSecond };
      if (!previous || point.at - previous.at > gapMs) {
        if (previous) gaps.push([previous, point]);
        segments.push([]);
      }
      segments.at(-1)!.push(point);
      previous = point;
    }
  }
  const drawn = segments.filter((segment) => segment.length > 1);
  const line = (segment: ChartPoint[]) => segment.map(({ x, y }, index) => `${index === 0 ? "M" : "L"}${x.toFixed(2)},${y.toFixed(2)}`).join(" ");
  const stalls = samples.filter(({ bytesPerSecond }) => bytesPerSecond === 0).length;
  const tip = drawn.at(-1)?.at(-1);
  const scope = transfer.status === "active" ? "Measured on this device" : "Recorded on this device";

  return <figure className="xfer-live-throughput">
    <figcaption><span><Zap size={15} aria-hidden /> Throughput</span><small>{scope}</small></figcaption>
    {drawn.length > 0 ? <>
      <svg viewBox="0 0 320 72" preserveAspectRatio="none" role="img"
        aria-label={`Measured throughput over ${formatDuration(span)}: latest ${formatRate(last?.bytesPerSecond)}, peak ${formatRate(peak)}${stalls ? `, ${stalls} stalled ${stalls === 1 ? "sample" : "samples"}` : ""}${gaps.length ? `, ${gaps.length} ${gaps.length === 1 ? "pause or interruption" : "pauses or interruptions"}` : ""}.`}>
        <defs><linearGradient id={fillId} x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor="currentColor" stopOpacity=".28" />
          <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
        </linearGradient></defs>
        <path className="xfer-live-chart-grid" d="M3 9h314 M3 28h314 M3 46h314 M3 65h314" />
        {drawn.map((segment) => <path key={`fill-${segment[0].at}`} d={`${line(segment)} L${segment.at(-1)!.x},65 L${segment[0].x},65 Z`} fill={`url(#${fillId})`} />)}
        {gaps.map(([from, to]) => <path key={`gap-${from.at}`} className="xfer-live-chart-gap" d={`M${from.x},65 L${to.x},65`} />)}
        {drawn.map((segment) => <path key={`line-${segment[0].at}`} className="xfer-live-chart-line" d={line(segment)} />)}
        {drawn.flat().filter(({ rate }) => rate === 0).map(({ x, at }) => <circle key={`stall-${at}`} className="xfer-live-chart-stall" cx={x} cy={65} r="2.2" />)}
        {tip && <circle cx={tip.x} cy={tip.y} r="2.8" fill="currentColor" />}
      </svg>
      <p className="xfer-live-chart-caption">
        <span>{formatDuration(span)} window</span>
        <span>Peak {formatRate(peak)}</span>
      </p>
      {(stalls > 0 || gaps.length > 0) && <p className="xfer-live-chart-legend">
        {stalls > 0 && <span><i className="xfer-live-legend-stall" aria-hidden /> Stalled (0 B/s measured)</span>}
        {gaps.length > 0 && <span><i className="xfer-live-legend-gap" aria-hidden /> Paused or interrupted</span>}
      </p>}
    </> : <p className="xfer-live-empty-chart">{last ? `Latest measurement ${formatRate(last.bytesPerSecond)}. The graph appears after the next measurement.` : "No recent throughput measurements. Measurements start when file data moves."}</p>}
  </figure>;
}

function Security({ transfer, done }: { transfer: OfflineTransfer; done: boolean }) {
  const titleId = useId();
  const security = transfer.security;
  const phase = security?.phase;
  const phaseText = phase ? securityPhases[phase] : undefined;
  const proof = phase === "secureTransfer" || phase === "integrityVerification" || phase === "verified" || phase === "payloadEncryption";
  const algorithms = proof ? [
    ["Key establishment", security?.keyEstablishment], ["Device authentication", security?.signatures],
    ["Payload encryption", security?.encryption], ["File integrity", security?.integrity],
  ].filter((entry): entry is [string, string] => Boolean(entry[1])) : [];
  const session = formatSessionId(transfer.sessionId);
  const fileCount = transfer.files.length;
  const SecurityIcon = phase === "error" ? TriangleAlert : proof ? ShieldCheck : ShieldQuestionMark;

  return <section className="xfer-live-security" aria-labelledby={titleId} data-proof={proof} data-error={phase === "error"}>
    <span className="xfer-live-security-icon"><SecurityIcon size={23} aria-hidden /></span>
    <div className="xfer-live-security-body">
      <h3 id={titleId}>{proof && security?.mode ? `${security.mode} post-quantum protection` : "Transfer security"}</h3>
      <strong>{phaseText?.[0] ?? "Session security unavailable"}</strong>
      <p>{phaseText?.[1] ?? "The transfer engine has not reported the cryptographic configuration for this record."}</p>
      {algorithms.length > 0 && <dl className="xfer-live-algorithms">
        {algorithms.map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{value}</dd></div>)}
      </dl>}
      {(proof || done) && session && <div className="xfer-live-session">
        <span><Fingerprint size={14} aria-hidden /> Session ID</span>
        <code aria-label={`Session ID ${session.split("").join(" ")}`}>{session}</code>
        <small>Both devices show the same ID for the same authenticated session.</small>
      </div>}
      {done && <p className="xfer-live-integrity"><ShieldCheck size={14} aria-hidden /> SHA3-256 verified · {fileCount} of {fileCount} {fileCount === 1 ? "file" : "files"}</p>}
    </div>
  </section>;
}

export function XferTransferDashboard({ transfer, status, localIdentity, actions, details, fileActions, completionActions, nextAction, onBack, onDone }: XferTransferDashboardProps) {
  const heading = useId();
  const gradient = useId();
  const titleRef = useRef<HTMLHeadingElement>(null);
  const fileDetails = useRef<HTMLDetailsElement>(null);
  const more = useRef<HTMLDetailsElement>(null);
  const done = transfer.status === "verified";
  const active = transfer.status === "active";
  const verifying = active && (transfer.security?.phase === "integrityVerification"
    || (transfer.totalBytes > 0 && transfer.verifiedBytes >= transfer.totalBytes));
  const percent = done ? 100 : transfer.totalBytes > 0 ? Math.min(99, Math.max(0, Math.floor(100 * transfer.verifiedBytes / transfer.totalBytes))) : 0;
  const failure = transfer.errorKind && (transfer.status === "interrupted" || transfer.status === "failed")
    ? failureLabels[transfer.errorKind]
    : undefined;
  const stalled = active && !verifying && transfer.bytesPerSecond === 0;
  const outgoingConsent = transfer.status === "awaitingConsent" && transfer.direction === "outgoing";
  const state = verifying ? "Awaiting final verification"
    : stalled ? "Stalled · waiting for data"
    : outgoingConsent ? "Waiting for the receiver"
    // Offered over Bluetooth because no local network reached the receiver.
    : transfer.direction === "outgoing" && transfer.status === "queued" && transfer.channelOffer === "awaiting" ? "Offer delivered · waiting for the receiver to accept"
    : transfer.direction === "outgoing" && transfer.status === "queued" && transfer.channelOffer === "accepted" ? "Accepted · connecting over a direct Wi-Fi link"
    : failure ?? labels[transfer.status];
  const title = done ? "Successfully transferred" : transfer.status === "failed" ? "Transfer needs attention" : "File Transfer";
  const remaining = Math.max(0, transfer.totalBytes - transfer.verifiedBytes);
  const speed = active && !verifying ? transfer.bytesPerSecond : null;
  const eta = speed && speed > 0 && remaining > 0 ? formatDuration(Math.ceil(remaining / speed) * 1_000) : stalled ? "Waiting for data" : "Unavailable";
  const verifiedBytes = formatOfflineBytes(transfer.verifiedBytes);
  const totalBytes = formatOfflineBytes(transfer.totalBytes);
  const folder = transfer.folderName;
  const file = transfer.files[0];
  const fileName = folder || (transfer.files.length === 1 ? file?.name : `${transfer.files.length} files`) || "Transfer manifest";
  const current = active && !verifying && typeof transfer.currentFile === "number" ? transfer.files[transfer.currentFile] : undefined;
  const verifiedFiles = transfer.verifiedFiles ?? (done ? transfer.files.length : null);
  const showError = Boolean(transfer.error);
  const peerFingerprint = transfer.direction === "incoming" ? transfer.sender : transfer.recipient;
  const peer = status.peers.find(({ fingerprint }) => fingerprint === peerFingerprint);
  const peerName = offlinePeerName(peer?.trusted ? peer : undefined, `Device ${peerFingerprint.slice(0, 8)}`);
  const localName = localIdentity?.displayName || status.localOwner || "You";
  const security = transfer.security;

  useEffect(() => {
    titleRef.current?.focus({ preventScroll: true });
    titleRef.current?.scrollIntoView?.({ block: "nearest" });
  }, [transfer.id]);

  function showDetails() {
    if (more.current) more.current.open = false;
    if (!fileDetails.current) return;
    fileDetails.current.open = true;
    const summary = fileDetails.current.querySelector("summary");
    summary?.scrollIntoView?.({ block: "nearest" });
    summary?.focus();
  }

  return <section className="xfer-live" aria-labelledby={heading} data-state={transfer.status} data-active={active && !verifying && !stalled} data-stalled={stalled}>
    <div className="xfer-live-particles" aria-hidden />
    {/* The app shell already names the page (Qguard XFER), so the dashboard
        carries one compact row: back, the transfer state title, and options. */}
    <header className="xfer-live-header">
      <button type="button" className="xfer-live-icon-button" onClick={onBack} aria-label="Back to transfers"><ArrowLeft size={20} aria-hidden /></button>
      <h2 id={heading} ref={titleRef} tabIndex={-1} className="xfer-live-title">{title}</h2>
      <details className="xfer-live-more" ref={more}>
        <summary className="xfer-live-icon-button" aria-label="Transfer options"><MoreVertical size={20} aria-hidden /></summary>
        <div className="xfer-live-more-panel"><button type="button" onClick={showDetails}>View transfer details</button></div>
      </details>
    </header>

    <div className="xfer-live-grid">
      <div className="xfer-live-main">
        <div className="xfer-live-route">
          <Participant role="Sender" fingerprint={transfer.sender} {...{ status, localIdentity }} />
          <span className="xfer-live-direction" aria-hidden><ChevronsRight size={28} /><ChevronRight size={21} /></span>
          <Participant role="Receiver" fingerprint={transfer.recipient} {...{ status, localIdentity }} />
        </div>
        <div className="xfer-live-dial-stage">
          <div className="xfer-live-field" aria-hidden />
          <div className="xfer-live-dial" role="progressbar" aria-label="Verified transfer progress" aria-valuemin={0} aria-valuemax={100}
            aria-valuenow={percent} aria-valuetext={`${verifiedBytes} of ${totalBytes} verified. ${state}.`}>
            <svg className="xfer-live-orbit" viewBox="0 0 224 224" aria-hidden="true">
              <defs><linearGradient id={gradient} x1="15%" y1="0%" x2="85%" y2="100%">
                <stop offset="0%" stopColor="var(--xfer-ring-end)" />
                <stop offset="57%" stopColor="var(--xfer-ring-middle)" />
                <stop offset="100%" stopColor="var(--xfer-ring-start)" />
              </linearGradient></defs>
              <circle className="xfer-live-orbit-outer" cx="112" cy="112" r="105" />
              <circle className="xfer-live-orbit-inner" cx="112" cy="112" r="82" />
              <circle className="xfer-live-orbit-track" cx="112" cy="112" r="93" />
              <circle className="xfer-live-orbit-fill" cx="112" cy="112" r="93" pathLength="100"
                stroke={`url(#${gradient})`} strokeDasharray="100 100" strokeDashoffset={100 - percent}
                transform="rotate(-90 112 112)" opacity={percent > 0 ? 1 : 0} />
              <circle className="xfer-live-orbit-comet" cx="112" cy="19" r="4" transform={`rotate(${percent * 3.6} 112 112)`} opacity={percent > 0 && !done ? 1 : 0} />
            </svg>
            <div className="xfer-live-dial-label" aria-hidden="true">
              <span className="xfer-live-file-icon">{done ? <ShieldCheck size={29} /> : folder ? <Folder size={28} /> : <TransferFileIcon name={file?.name} size={28} />}</span>
              <strong>{percent}%</strong><span>{state}</span>
            </div>
          </div>
        </div>
        <div className="xfer-live-file-summary">
          <h3>{fileName}</h3>
          <p><strong>{verifiedBytes}</strong> / {totalBytes} verified</p>
          {transfer.files.length > 1 && <p>{verifiedFiles === null ? `${transfer.files.length} files` : `${verifiedFiles} of ${transfer.files.length} files verified`}</p>}
          {current && <p>Current file <strong>{current.name}</strong></p>}
        </div>
      </div>

      <div className="xfer-live-telemetry">
        {done ? <div className="xfer-live-completion" role="status">
          <p className="xfer-live-completion-title"><ShieldCheck size={18} aria-hidden /> Successfully transferred and verified</p>
          <dl className="xfer-live-receipt">
            <div><dt>Files</dt><dd>{fileName}</dd></div>
            <div><dt>Total size</dt><dd>{totalBytes}</dd></div>
            <div><dt>Sender</dt><dd>{transfer.direction === "outgoing" ? localName : peerName}</dd></div>
            <div><dt>Receiver</dt><dd>{transfer.direction === "incoming" ? localName : peerName}</dd></div>
            <div><dt>Duration</dt><dd>{transfer.elapsedMs != null ? formatDuration(transfer.elapsedMs) : "Unavailable"}</dd></div>
            <div><dt>Integrity</dt><dd>SHA3-256 · {transfer.files.length} of {transfer.files.length} verified</dd></div>
            {security?.keyEstablishment && <div><dt>Encryption</dt><dd>{security.keyEstablishment} · {security.encryption}</dd></div>}
            {transfer.completedAtMs != null && <div><dt>Completed</dt><dd><time dateTime={new Date(transfer.completedAtMs).toISOString()}>{formatOfflineTime(transfer.completedAtMs / 1_000)}</time></dd></div>}
          </dl>
          <div className="xfer-live-completion-actions">
            {nextAction && <button type="button" className="xfer-live-next" onClick={nextAction.onSelect}>
              {nextAction.kind === "send" ? <><FilePlus size={17} aria-hidden /> Send more files</> : <><Inbox size={17} aria-hidden /> Wait for more files</>}
            </button>}
            {completionActions}
            <button type="button" onClick={showDetails}>View transfer details</button>
            {onDone && <button type="button" className="xfer-live-done" onClick={onDone}>Done</button>}
          </div>
        </div> : <section className="xfer-live-metrics" aria-label="Transfer metrics">
          <dl>
            <div data-tone={stalled ? "warn" : undefined}><dt><Zap size={16} aria-hidden /> Current speed</dt><dd>{stalled ? "Stalled" : formatRate(speed)}</dd></div>
            <div><dt><Clock3 size={16} aria-hidden /> Estimated time remaining</dt><dd>{eta}</dd></div>
            <div><dt><Gauge size={16} aria-hidden /> Average speed</dt><dd>{formatRate(transfer.averageBytesPerSecond)}</dd></div>
            <div><dt><Clock3 size={16} aria-hidden /> Elapsed time</dt><dd>{transfer.elapsedMs != null ? formatDuration(transfer.elapsedMs) : "Unavailable"}</dd></div>
            <div><dt>Verified bytes</dt><dd>{verifiedBytes}</dd></div>
            <div><dt>Remaining bytes</dt><dd>{formatOfflineBytes(remaining)}</dd></div>
          </dl>
        </section>}
        {!done && <Throughput transfer={transfer} />}
        {transfer.controlSyncPending && <p className="xfer-live-status-note" role="status">Waiting for the other device to confirm the change.</p>}
        {transfer.remoteHold && <p className="xfer-live-status-note" role="status">The other device {transfer.remoteHold === "pause" ? "paused" : "stopped"} this transfer.</p>}
        {showError && <p className="xfer-live-error" role="status"><TriangleAlert size={18} aria-hidden /> <span>{failure && <strong>{failure}. </strong>}{transfer.error}</span></p>}
        {actions && <div className="xfer-live-actions">{actions}</div>}
        {details && <div className="xfer-live-inline-details">{details}</div>}
        <Security {...{ transfer, done }} />
      </div>
    </div>

    <details className="xfer-live-manifest" ref={fileDetails}>
      <summary><Folder size={17} aria-hidden /> <span>Transfer details</span><small>{transfer.files.length} {transfer.files.length === 1 ? "file" : "files"}</small><ChevronDown size={16} aria-hidden /></summary>
      <div className="xfer-live-manifest-body">
        <dl className="xfer-live-manifest-meta">
          <div><dt>Transfer ID</dt><dd><code>{transfer.id}</code></dd></div>
          {transfer.sessionId && <div><dt>Session ID</dt><dd><code>{formatSessionId(transfer.sessionId)}</code></dd></div>}
          <div><dt>Direction</dt><dd>{transfer.direction === "incoming" ? `From ${peerName}` : `To ${peerName}`}</dd></div>
        </dl>
        <ul>{transfer.files.map((entry, index) => <li key={`${entry.name}:${index}`}>
          <div className="xfer-live-manifest-file"><TransferFileIcon name={entry.name} size={17} /><span><strong>{entry.name}</strong>
            <small>{formatOfflineBytes(entry.size)}{entry.verifiedBytes != null && !entry.verified && !done ? ` · ${formatOfflineBytes(entry.verifiedBytes)} received` : ""}
              {entry.verified || done ? " · Integrity verified" : ""}</small>
            {entry.digest && <small className="xfer-live-digest" title={entry.digest}>SHA3-256 <code>{shortDigest(entry.digest)}</code></small>}</span></div>
          {entry.destination && <p className="xfer-live-file-location">Saved to {entry.destination}</p>}
          {fileActions?.(entry, index)}
        </li>)}</ul>
      </div>
    </details>
    <span className="sr-only" role="status">{state}</span>
  </section>;
}
