import { useCallback, useMemo, useState } from "react";
import { Activity, Copy } from "lucide-react";
import { useOfflineFeed, type OfflineLinkEvent, type OfflinePeer } from "@/lib/offline";
import { safeInvoke } from "@/lib/tauri";

/** Plain-language names for the events the Rust core records. */
const EVENT_LABELS: Record<string, string> = {
  dial_started: "Connecting",
  dial_failed: "Connection attempt failed",
  session_authenticated: "Device authenticated",
  channel_open: "Channel open",
  channel_closed: "Channel closed",
  channel_duplicate_closed: "Duplicate link closed",
  channel_unconfirmed: "Channel not confirmed",
  heartbeat_missed: "Heartbeat missed",
  message_queued: "Message queued",
  message_sent: "Message sent",
  message_resent: "Message resent",
  message_acknowledged: "Delivery receipt",
  message_received: "Message received",
  message_duplicate: "Repeated message ignored",
  message_rejected: "Message rejected",
  receipt_rejected: "Receipt rejected",
  message_alert_raised: "Message notification",
  pairing_requested: "Pairing requested",
  pairing_request_received: "Pairing request received",
  pairing_code_ready: "Verification code ready",
  pairing_trusted: "Device trusted",
  pairing_failed: "Pairing failed",
  transfer_offer_received: "File offer received",
  transfer_session_started: "Transfer session started",
  transfer_session_ended: "Transfer session ended",
  transfer_session_interrupted: "Transfer interrupted",
  transfer_nudge_received: "Transfer retry requested by peer",
  transfer_verified: "Transfer verified",
  transfer_failed: "Transfer failed",
};

const FAILURES = new Set(["dial_failed", "heartbeat_missed", "message_rejected", "receipt_rejected", "pairing_failed", "transfer_session_interrupted", "transfer_failed", "channel_unconfirmed"]);
const SUCCESSES = new Set(["session_authenticated", "channel_open", "message_acknowledged", "message_received", "pairing_trusted", "transfer_verified"]);

function clock(atMs: number): string {
  const date = new Date(atMs);
  return `${date.toLocaleTimeString(undefined, { hour12: false })}.${String(date.getMilliseconds()).padStart(3, "0")}`;
}

/**
 * Connection diagnostics, read from the core's bounded in-memory event log.
 * Two devices' logs line up by the session id (the same on both ends of one
 * authenticated session) and by the message and transfer ids in the details.
 */
export function LinkDiagnostics({ accountId, peers }: { accountId: string; peers: OfflinePeer[] }) {
  const read = useCallback(() => safeInvoke<OfflineLinkEvent[]>("offline_link_events", { expectedAccount: accountId }), [accountId]);
  const { value, error } = useOfflineFeed(read, 4_000);
  const [copied, setCopied] = useState(false);
  const names = useMemo(() => new Map(peers.map((peer) => [peer.fingerprint.slice(0, 8), peer.owner || peer.label || null])), [peers]);
  const events = useMemo(() => [...(value ?? [])].reverse(), [value]);

  async function copy() {
    const text = (value ?? []).map((event) => [
      new Date(event.atMs).toISOString(), `#${event.id}`, event.kind,
      event.transport ?? "", event.session ? `session=${event.session}` : "", event.peer ? `peer=${event.peer}` : "", event.detail ?? "",
    ].filter(Boolean).join(" ")).join("\n");
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  }

  return <section className="shell-card space-y-3 p-4 sm:p-5" aria-labelledby="link-diagnostics-title">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <h3 id="link-diagnostics-title" className="flex items-center gap-2 text-base font-bold text-ink-950"><Activity size={18} aria-hidden /> Connection diagnostics</h3>
        <p className="text-sm leading-relaxed text-ink-600">What the Bluetooth and local network links on this device actually did, newest first. Compare the session id with the other device's log. No message text, file names or keys are recorded.</p>
      </div>
      <button type="button" className="focus-ring inline-flex min-h-12 items-center gap-2 rounded-lg border border-line bg-white px-4 py-2 text-sm font-semibold text-ink-700 hover:bg-canvas disabled:opacity-50"
        disabled={!value?.length} onClick={() => void copy()}>
        <Copy size={16} aria-hidden /> {copied ? "Copied" : "Copy log"}
      </button>
    </div>
    {error && <p role="alert" className="text-sm text-ink-700">{error}</p>}
    {value && value.length === 0 && <p className="text-sm text-ink-600">No connection activity yet in this session. Start local discovery on both devices.</p>}
    {events.length > 0 && <ol className="max-h-[26rem] space-y-1.5 overflow-y-auto pr-1" aria-label="Connection events">
      {events.slice(0, 150).map((event) => {
        const tone = FAILURES.has(event.kind) ? "text-rose-700" : SUCCESSES.has(event.kind) ? "text-emerald-700" : "text-ink-800";
        const who = event.peer ? names.get(event.peer) ?? `device ${event.peer}` : null;
        return <li key={event.id} className="rounded-lg border border-line px-3 py-2 text-xs">
          <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
            <time className="font-mono text-ink-500" dateTime={new Date(event.atMs).toISOString()}>{clock(event.atMs)}</time>
            <strong className={tone}>{EVENT_LABELS[event.kind] ?? event.kind}</strong>
            {who && <span className="text-ink-700">{who}</span>}
            {event.transport && <span className="text-ink-500">{event.transport === "bluetooth" ? "Bluetooth" : "Local network"}</span>}
            {event.session && <span className="font-mono text-ink-500">session {event.session}</span>}
          </div>
          {event.detail && <p className="mt-0.5 break-words text-ink-600">{event.detail}</p>}
        </li>;
      })}
    </ol>}
  </section>;
}
