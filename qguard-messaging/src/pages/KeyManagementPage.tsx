import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Database,
  KeyRound,
  Loader2,
  Radio,
  RefreshCcw,
  ShieldCheck,
  UploadCloud,
} from "lucide-react";
import { useMemo, useState } from "react";
import { bytesToBytea } from "@/lib/encoding";
import { recordCryptoTelemetry } from "@/lib/crypto-telemetry";
import { useIsAdmin } from "@/lib/admin";
import type { QGuardLiveEvent, QGuardLiveStatus } from "@/lib/live-sse";
import { syncCurrentMessagingDevice } from "@/lib/messaging-bootstrap";
import type { PublicIdentityBundle } from "@/lib/messaging-bootstrap";
import { supabase } from "@/lib/supabase";
import { safeInvoke } from "@/lib/tauri";
import type { KeyInventory, SecurityEvent, TelemetryEvent, TrustedDevice } from "@/lib/types";

interface KeyManagementPageProps {
  userId: string;
  devices: TrustedDevice[];
  keyInventory: KeyInventory;
  telemetry: TelemetryEvent[];
  securityEvents: SecurityEvent[];
  liveEvents: QGuardLiveEvent[];
  liveStatus: QGuardLiveStatus;
  onRefresh: () => void | Promise<void>;
}

interface PublicSignedPrekey {
  prekey_id: string;
  device_id: string;
  x25519_public: number[];
  mlkem_public: number[];
  signature: Record<string, unknown>;
  fingerprint: string;
  created_at: string;
  expires_at: string;
}

type KeyAction = "publish" | "rotate" | "refresh";
type OperationStatus = "running" | "success" | "error";

interface KeyOperationLog {
  id: string;
  stage: string;
  detail: string;
  status: OperationStatus;
}

const REQUEST_TIMEOUT_MS = 45_000;
const KEY_LIVE_TABLES = new Set([
  "messaging_devices",
  "messaging_signed_prekeys",
  "messaging_one_time_prekeys",
  "messaging_crypto_telemetry",
  "messaging_security_events",
]);

function describeError(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  return "Key management action failed.";
}

function deviceTime(device: TrustedDevice): number {
  const parsed = new Date(device.last_seen_at).getTime();
  return Number.isFinite(parsed) ? parsed : 0;
}

function relativeTime(value: string | null | undefined): string {
  if (!value) return "No events yet";
  const time = new Date(value).getTime();
  if (!Number.isFinite(time)) return "Unknown";
  const seconds = Math.max(0, Math.floor((Date.now() - time) / 1000));
  if (seconds < 10) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function latestIso(values: Array<string | null | undefined>): string | null {
  const latest = values
    .map((value) => new Date(value ?? "").getTime())
    .filter(Number.isFinite)
    .sort((a, b) => b - a)[0];
  return latest ? new Date(latest).toISOString() : null;
}

function cleanLabel(value: string): string {
  return value.replace(/_/g, " ");
}

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "No active signed prekey";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "Unknown";
  return date.toLocaleString();
}

function liveTone(state: QGuardLiveStatus["state"]): string {
  if (state === "live") return "bg-emerald-50 text-emerald-600";
  if (state === "connecting") return "bg-amber-50 text-amber-600";
  if (state === "fallback") return "bg-cyan-50 text-cyan-700";
  return "bg-rose-50 text-rose-600";
}

function statusTone(value: string): string {
  if (/failed|critical|revoked|missing|no active|blocked|error/i.test(value)) return "text-rose-500";
  if (/pending|warning|replenish|low|fallback|connecting/i.test(value)) return "text-amber-600";
  return "text-emerald-600";
}

function telemetryTone(event: TelemetryEvent): string {
  if (/failed|error|critical/i.test(`${event.stage} ${event.detail}`)) return "bg-rose-50 text-rose-600";
  if (event.progress < 100) return "bg-amber-50 text-amber-600";
  return "bg-emerald-50 text-emerald-600";
}

function isTrustedDevice(device: TrustedDevice): boolean {
  return device.trust_state === "ThisDevice" || device.trust_state === "Trusted";
}

function hasSendablePrekeys(device: TrustedDevice): boolean {
  return Boolean(
    isTrustedDevice(device)
    && device.identity_signature
    && device.x25519_identity_public.length > 0
    && device.mlkem_identity_public.length > 0
    && device.ed25519_identity_public.length > 0
    && device.mldsa_identity_public.length > 0
    && device.signed_prekey
    && device.signed_prekey.x25519_public.length > 0
    && device.signed_prekey.mlkem_public.length > 0
    && device.signed_prekey.signature.ed25519.length > 0
    && device.signed_prekey.signature.ml_dsa_65.length > 0
  );
}

function isKeyTelemetry(event: TelemetryEvent): boolean {
  return /key|prekey|identity|device|bundle|rotation/i.test(`${event.stage} ${event.detail}`);
}

function isKeyLiveEvent(event: QGuardLiveEvent): boolean {
  return KEY_LIVE_TABLES.has(event.table);
}

async function withTimeout<T>(
  task: PromiseLike<T>,
  label: string,
  timeoutMs = REQUEST_TIMEOUT_MS,
): Promise<T> {
  let timeoutId: number | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timeoutId = window.setTimeout(() => {
      reject(new Error(`${label} timed out. The operation was stopped so the app can stay responsive.`));
    }, timeoutMs);
  });

  try {
    return await Promise.race([Promise.resolve(task), timeout]);
  } finally {
    if (timeoutId !== undefined) window.clearTimeout(timeoutId);
  }
}

export default function KeyManagementPage({
  userId,
  devices,
  keyInventory,
  telemetry,
  securityEvents,
  liveEvents,
  liveStatus,
  onRefresh,
}: KeyManagementPageProps) {
  const isAdmin = useIsAdmin();
  const [busy, setBusy] = useState<KeyAction | null>(null);
  const [actionStatus, setActionStatus] = useState<string | null>(null);
  const [operationLogs, setOperationLogs] = useState<KeyOperationLog[]>([]);

  const ownDevices = useMemo(() => {
    return devices
      .filter((device) => device.user_id === userId)
      .sort((a, b) => deviceTime(b) - deviceTime(a));
  }, [devices, userId]);
  const latestThisDevice = useMemo(() => {
    return ownDevices.filter((device) => device.trust_state === "ThisDevice")[0] ?? null;
  }, [ownDevices]);
  const activeOwnDevices = useMemo(() => ownDevices.filter((device) => device.trust_state !== "Revoked"), [ownDevices]);
  const trustedOwnDevices = useMemo(() => activeOwnDevices.filter(isTrustedDevice), [activeOwnDevices]);
  const sendableDevices = useMemo(() => activeOwnDevices.filter(hasSendablePrekeys), [activeOwnDevices]);
  const displayDevices = ownDevices.slice(0, 8);
  const hiddenDeviceCount = Math.max(0, ownDevices.length - displayDevices.length);
  const duplicateCurrentDeviceCount = ownDevices.filter((device) => device.trust_state === "ThisDevice").length;
  const signedPrekeyTarget = Math.max(1, activeOwnDevices.length);
  const signedPrekeyLabel = `${keyInventory.active_signed_prekeys}/${signedPrekeyTarget}`;
  const prekeyTarget = Math.max(8, activeOwnDevices.length * 8);
  const oneTimePrekeyLabel = `${keyInventory.available_one_time_prekeys}/${prekeyTarget}`;
  const signedPrekeysReady = keyInventory.active_signed_prekeys >= signedPrekeyTarget;
  const oneTimePrekeysReady = keyInventory.available_one_time_prekeys >= prekeyTarget;
  const nextRotation = formatTimestamp(keyInventory.next_signed_prekey_expiry);
  const latestKeyEvent = securityEvents.find((event) => /key|prekey|identity|device/i.test(event.event_type));
  const keyTelemetry = telemetry.filter(isKeyTelemetry).slice(0, 5);
  const keyLiveEvents = liveEvents.filter(isKeyLiveEvent).slice(0, 5);
  const latestBackendAt = latestIso([
    liveStatus.lastEventAt,
    latestKeyEvent?.created_at,
    keyTelemetry[0]?.created_at,
    ...activeOwnDevices.map((device) => device.last_seen_at),
  ]);
  const latestLogStatus = operationLogs[0]?.status ?? "success";
  const materialReadiness = sendableDevices.length > 0 && signedPrekeysReady && oneTimePrekeysReady
    ? "Ready"
    : "Needs Sync";

  function pushLog(stage: string, detail: string, status: OperationStatus = "running") {
    setOperationLogs((current) => [
      {
        id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
        stage,
        detail,
        status,
      },
      ...current,
    ].slice(0, 12));
  }

  async function recordKeyTelemetry(
    stage: string,
    detail: string,
    progress: number,
    status: "started" | "progress" | "verified" | "failed" | "complete",
    deviceId?: string | null,
  ) {
    await recordCryptoTelemetry({
      userId,
      deviceId: deviceId ?? latestThisDevice?.device_id ?? null,
      scope: "key",
      stage,
      detail,
      progress,
      status,
      metadata: {
        module: "key_management",
        live_state: liveStatus.state,
      },
    });
  }

  async function runKeyAction(action: KeyAction, label: string, callback: () => Promise<string>) {
    if (busy) return;
    setBusy(action);
    setActionStatus(null);
    pushLog(label, "Started", "running");
    await recordKeyTelemetry(label, "Started", 5, "started");
    try {
      const message = await callback();
      setActionStatus(message);
      pushLog(label, message, "success");
      await recordKeyTelemetry(label, message, 100, "complete");
    } catch (error) {
      const message = describeError(error);
      setActionStatus(message);
      pushLog(label, message, "error");
      await recordKeyTelemetry(label, message, 100, "failed");
    } finally {
      setBusy(null);
    }
  }

  async function prepareRegisteredDevice(): Promise<PublicIdentityBundle> {
    pushLog("Secure storage", "Loading device-bound public identity and PQC prekeys", "running");
    const bundle = await withTimeout(
      syncCurrentMessagingDevice(supabase, userId),
      "Publish device key bundle",
      REQUEST_TIMEOUT_MS,
    );
    if (!bundle) {
      throw new Error("QGuard desktop key service is required to publish device-bound keys.");
    }
    pushLog("Device registry", "Identity, signed prekey, and one-time prekeys synchronized", "success");
    await recordKeyTelemetry("Device key sync", "Public identity bundle and prekeys synchronized", 100, "verified", bundle.device_id);
    return bundle;
  }

  function publishPublicBundle() {
    void runKeyAction("publish", "Publish public bundle", async () => {
      const bundle = await prepareRegisteredDevice();
      pushLog("Inventory refresh", "Refreshing key inventory", "running");
      await Promise.resolve(onRefresh());
      return `Public identity bundle and prekeys published for ${bundle.fingerprint.slice(0, 24)}`;
    });
  }

  function rotateAndPublishPrekey() {
    void runKeyAction("rotate", "Rotate signed prekey", async () => {
      const bundle = await prepareRegisteredDevice();
      pushLog("Key generation", "Generating ML-KEM-1024 + X25519 signed prekey locally", "running");
      const prekey = await withTimeout(
        safeInvoke<PublicSignedPrekey>("keys_rotate_prekeys", { userId }),
        "Rotate signed prekey",
        REQUEST_TIMEOUT_MS,
      );

      // Publish the NEW prekey first, deactivate old ones after. The reverse
      // order stranded the device keyless (unreachable for messages/calls)
      // whenever the publish step failed between the two writes.
      pushLog("Relay publish", "Publishing active signed prekey", "running");
      const publishResult = await withTimeout(
        supabase.from("messaging_signed_prekeys").upsert({
          id: prekey.prekey_id,
          user_id: bundle.user_id,
          device_id: prekey.device_id,
          x25519_public: bytesToBytea(prekey.x25519_public),
          mlkem_public: bytesToBytea(prekey.mlkem_public),
          signature: prekey.signature,
          fingerprint: prekey.fingerprint,
          is_active: true,
          expires_at: prekey.expires_at,
          created_at: prekey.created_at,
        }, { onConflict: "id" }),
        "Publish signed prekey",
        20_000,
      );
      if (publishResult.error) throw publishResult.error;

      const deactivateResult = await withTimeout(
        supabase
          .from("messaging_signed_prekeys")
          .update({ is_active: false })
          .eq("user_id", bundle.user_id)
          .eq("device_id", prekey.device_id)
          .eq("is_active", true)
          .neq("id", prekey.prekey_id),
        "Deactivate previous signed prekeys",
        20_000,
      );
      if (deactivateResult.error) throw deactivateResult.error;

      pushLog("Inventory refresh", "Refreshing key inventory", "running");
      await Promise.resolve(onRefresh());
      await recordKeyTelemetry("Signed prekey rotation", `Published ${prekey.fingerprint.slice(0, 24)}`, 100, "verified", prekey.device_id);
      return `Signed prekey rotated and published: ${prekey.fingerprint.slice(0, 24)}`;
    });
  }

  function refreshInventory() {
    void runKeyAction("refresh", "Refresh key inventory", async () => {
      await withTimeout(Promise.resolve(onRefresh()), "Refresh key inventory", 20_000);
      return "Key inventory refreshed from live backend state.";
    });
  }

  return (
    <div className="grid gap-4">
      <div className="grid gap-4 lg:grid-cols-4">
        <section className="shell-card p-4">
          <KeyRound className="text-violet-600" size={24} />
          <div className="mt-3 text-sm font-bold text-ink-950">Hybrid Identity</div>
          <div className={`mt-1 text-sm font-semibold ${statusTone(materialReadiness)}`}>
            {sendableDevices.length}/{Math.max(1, activeOwnDevices.length)} sendable devices
          </div>
          <div className="mt-1 text-xs text-ink-500">{trustedOwnDevices.length} trusted device records</div>
        </section>
        <section className="shell-card p-4">
          <RefreshCcw className="text-violet-600" size={24} />
          <div className="mt-3 text-sm font-bold text-ink-950">Prekey Rotation</div>
          <div className={`mt-1 text-sm font-semibold ${signedPrekeysReady ? "text-emerald-600" : "text-amber-600"}`}>
            {signedPrekeyLabel} signed prekeys active
          </div>
          <div className="mt-1 truncate text-xs text-ink-500">Next expiry: {nextRotation}</div>
        </section>
        <section className="shell-card p-4">
          <ShieldCheck className="text-violet-600" size={24} />
          <div className="mt-3 text-sm font-bold text-ink-950">One-Time Prekeys</div>
          <div className={`mt-1 text-sm font-semibold ${oneTimePrekeysReady ? "text-emerald-600" : "text-amber-600"}`}>
            {oneTimePrekeyLabel} ready
          </div>
          <div className="mt-1 text-xs text-ink-500">{keyInventory.rotation_events} key lifecycle events</div>
        </section>
        <section className="shell-card p-4">
          <Radio className={liveStatus.state === "live" ? "text-emerald-600" : "text-amber-600"} size={24} />
          <div className="mt-3 text-sm font-bold text-ink-950">Realtime Stream</div>
          <div className={`mt-1 text-sm font-semibold ${statusTone(liveStatus.state)}`}>{liveStatus.state}</div>
          <div className="mt-1 truncate text-xs text-ink-500">{relativeTime(latestBackendAt)}</div>
        </section>
      </div>

      {isAdmin && (
      <section className="shell-card p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-ink-950">Realtime Key Telemetry</h2>
            <div className="mt-1 text-xs text-ink-600">Backend key state refreshed {relativeTime(latestBackendAt)}</div>
          </div>
          <span className={`status-pill ${liveTone(liveStatus.state)}`}>
            <Radio size={13} />
            {liveStatus.state}
          </span>
        </div>

        <div className="mt-4 grid gap-4 border-y border-line py-3 md:grid-cols-4">
          <div>
            <div className="text-[11px] font-bold uppercase text-ink-400">Live Detail</div>
            <div className="mt-1 truncate text-sm font-semibold text-ink-950">{liveStatus.detail}</div>
          </div>
          <div>
            <div className="text-[11px] font-bold uppercase text-ink-400">Last Event</div>
            <div className="mt-1 text-sm font-semibold text-ink-950">{relativeTime(liveStatus.lastEventAt)}</div>
          </div>
          <div>
            <div className="text-[11px] font-bold uppercase text-ink-400">Key Telemetry</div>
            <div className="mt-1 text-sm font-semibold text-ink-950">{keyTelemetry.length} recent records</div>
          </div>
          <div>
            <div className="text-[11px] font-bold uppercase text-ink-400">Key Material</div>
            <div className={`mt-1 text-sm font-semibold ${statusTone(materialReadiness)}`}>{materialReadiness}</div>
          </div>
        </div>

        <div className="mt-4 grid gap-6 lg:grid-cols-2">
          <div className="min-w-0">
            <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase text-ink-400">
              <Database size={14} />
              Backend Key Events
            </div>
            {keyLiveEvents.length === 0 && (
              <div className="rounded-lg border border-line bg-canvas p-3 text-xs text-ink-600">Live stream connected. No key registry changes received yet.</div>
            )}
            <div className="space-y-2">
              {keyLiveEvents.map((event) => (
                <div key={event.id} className="flex items-center gap-3 border-t border-line pt-2 first:border-t-0 first:pt-0">
                  <span className="h-2 w-2 shrink-0 rounded-full bg-emerald-500" />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-xs font-semibold text-ink-950">{event.detail}</div>
                    <div className="text-[11px] text-ink-400">{event.table} - {event.event.toLowerCase()} - {relativeTime(event.at)}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="min-w-0">
            <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase text-ink-400">
              <Activity size={14} />
              Crypto Telemetry
            </div>
            {keyTelemetry.length === 0 && (
              <div className="rounded-lg border border-line bg-canvas p-3 text-xs text-ink-600">No key-specific telemetry yet.</div>
            )}
            <div className="space-y-2">
              {keyTelemetry.map((event) => (
                <div key={event.id} className="flex items-center gap-3 border-t border-line pt-2 first:border-t-0 first:pt-0">
                  <span className={`status-pill shrink-0 ${telemetryTone(event)}`}>{Math.max(0, Math.min(100, event.progress))}%</span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-xs font-semibold text-ink-950">{cleanLabel(event.stage)}</div>
                    <div className="truncate text-[11px] text-ink-500">{event.detail}</div>
                  </div>
                  <div className="shrink-0 text-[11px] text-ink-400">{relativeTime(event.created_at)}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>
      )}

      <section className="shell-card overflow-hidden" aria-busy={Boolean(busy)}>
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line p-4">
          <div>
            <h2 className="text-sm font-bold text-ink-950">Device Key Material</h2>
            <div className="mt-1 flex flex-wrap gap-2 text-xs">
              <span className="status-pill bg-emerald-50 text-emerald-600">
                <CheckCircle2 size={13} />
                Client-side keys
              </span>
              <span className={`status-pill ${busy ? "bg-amber-50 text-amber-600" : "bg-violet-50 text-violet-600"}`}>
                <Clock3 size={13} />
                {busy ? "Operation running" : "Ready"}
              </span>
              <span className={`status-pill ${materialReadiness === "Ready" ? "bg-emerald-50 text-emerald-600" : "bg-amber-50 text-amber-600"}`}>
                <ShieldCheck size={13} />
                {materialReadiness}
              </span>
              {duplicateCurrentDeviceCount > 1 && (
                <span className="status-pill bg-amber-50 text-amber-700">
                  <AlertTriangle size={13} />
                  {duplicateCurrentDeviceCount} current markers
                </span>
              )}
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <button onClick={refreshInventory} disabled={Boolean(busy)} className="flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-sm font-semibold text-ink-700 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50">
              {busy === "refresh" ? <Loader2 className="animate-spin" size={16} /> : <RefreshCcw size={16} />}
              {busy === "refresh" ? "Refreshing" : "Refresh"}
            </button>
            {isAdmin && (
              <button onClick={publishPublicBundle} disabled={Boolean(busy)} className="flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-sm font-semibold text-ink-700 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50">
                {busy === "publish" ? <Loader2 className="animate-spin" size={16} /> : <UploadCloud size={16} />}
                {busy === "publish" ? "Publishing" : "Publish Public Bundle"}
              </button>
            )}
            <button onClick={rotateAndPublishPrekey} disabled={Boolean(busy)} className="flex items-center gap-2 rounded-lg bg-violet-600 px-3 py-2 text-sm font-semibold text-white hover:bg-violet-700 disabled:cursor-not-allowed disabled:opacity-50">
              {busy === "rotate" ? <Loader2 className="animate-spin" size={16} /> : <RefreshCcw size={16} />}
              {busy === "rotate" ? "Rotating" : "Rotate Prekeys"}
            </button>
          </div>
        </div>
        {actionStatus && (
          <div className={`border-b border-line px-4 py-2 text-xs font-semibold ${latestLogStatus === "error" ? "bg-rose-50 text-rose-600" : "bg-cyan-50 text-cyan-700"}`}>
            {actionStatus}
          </div>
        )}

        <div className="overflow-x-auto">
          <div className="min-w-[900px]">
            <div className="grid grid-cols-[180px_1fr_160px_1fr] border-b border-line bg-canvas px-4 py-3 text-xs font-bold uppercase tracking-wide text-ink-400">
              <span>Object</span>
              <span>Source</span>
              <span>Status</span>
              <span>Detail</span>
            </div>

            {ownDevices.length === 0 && (
              <div className="p-6 text-sm text-ink-600">No key bundles are registered for this user.</div>
            )}

            {displayDevices.map((device) => {
              const sendable = hasSendablePrekeys(device);
              return (
                <div key={device.device_id} className="grid grid-cols-[180px_1fr_160px_1fr] border-b border-line px-4 py-3 text-sm">
                  <span className="font-semibold text-ink-950">Hybrid Identity</span>
                  <span className="truncate font-mono text-xs text-violet-600">{device.fingerprint}</span>
                  <span className={statusTone(sendable ? "ready" : device.trust_state)}>{sendable ? "Sendable" : device.trust_state}</span>
                  <span className="truncate text-ink-600">
                    {device.pqc_status} - {relativeTime(device.last_seen_at)} - {device.signed_prekey ? "active signed prekey" : "missing signed prekey"}
                  </span>
                </div>
              );
            })}

            {hiddenDeviceCount > 0 && (
              <div className="border-b border-line bg-amber-50/70 px-4 py-3 text-xs font-semibold text-amber-700">
                {hiddenDeviceCount} older registered identity {hiddenDeviceCount === 1 ? "row is" : "rows are"} hidden from this panel.
              </div>
            )}

            <div className="grid grid-cols-[180px_1fr_160px_1fr] border-b border-line px-4 py-3 text-sm">
              <span className="font-semibold text-ink-950">Private Decryption Key</span>
              <span className="truncate font-mono text-xs text-violet-600">OS keychain / secure storage</span>
              <span className="text-emerald-600">local only</span>
              <span className="truncate text-ink-600">Private keys remain device-bound</span>
            </div>

            <div className="grid grid-cols-[180px_1fr_160px_1fr] border-b border-line px-4 py-3 text-sm">
              <span className="font-semibold text-ink-950">Signed Prekeys</span>
              <span className="font-mono text-xs text-violet-600">messaging_signed_prekeys</span>
              <span className={signedPrekeysReady ? "text-emerald-600" : "text-amber-600"}>{signedPrekeyLabel} active</span>
              <span className="text-ink-600">{nextRotation}</span>
            </div>

            <div className="grid grid-cols-[180px_1fr_160px_1fr] border-b border-line px-4 py-3 text-sm">
              <span className="font-semibold text-ink-950">One-Time Prekeys</span>
              <span className="font-mono text-xs text-violet-600">messaging_one_time_prekeys</span>
              <span className={oneTimePrekeysReady ? "text-emerald-600" : "text-amber-600"}>{oneTimePrekeyLabel} available</span>
              <span className="text-ink-600">Ready pool target is 8 prekeys per active device.</span>
            </div>

            <div className="grid grid-cols-[180px_1fr_160px_1fr] border-b border-line px-4 py-3 text-sm">
              <span className="font-semibold text-ink-950">Latest Key Event</span>
              <span className="truncate font-mono text-xs text-violet-600">{latestKeyEvent?.event_hash ?? "No event hash"}</span>
              <span className={latestKeyEvent?.severity === "critical" ? "text-rose-500" : "text-emerald-600"}>
                {latestKeyEvent?.severity ?? "none"}
              </span>
              <span className="truncate text-ink-600">{latestKeyEvent?.event_type ?? "No key rotation event has been recorded"}</span>
            </div>
          </div>
        </div>

        <div className="bg-ink-950 px-4 py-3 font-mono text-xs text-emerald-200">
          {operationLogs.length === 0 ? (
            <div className="text-emerald-200/70">qguard:key-management idle</div>
          ) : (
            operationLogs.map((entry) => (
              <div key={entry.id} className={entry.status === "error" ? "text-rose-300" : entry.status === "success" ? "text-cyan-200" : "text-emerald-200"}>
                [{entry.status}] {entry.stage}: {entry.detail}
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  );
}
