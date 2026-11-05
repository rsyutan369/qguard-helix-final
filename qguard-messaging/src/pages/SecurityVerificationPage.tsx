import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Copy,
  Database,
  Fingerprint,
  Loader2,
  MonitorSmartphone,
  QrCode,
  Radio,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { securityEventDetails } from "@/lib/account-key";
import { recordCryptoTelemetry } from "@/lib/crypto-telemetry";
import { useIsAdmin } from "@/lib/admin";
import type { QGuardLiveEvent, QGuardLiveStatus } from "@/lib/live-sse";
import { supabase } from "@/lib/supabase";
import { safeInvoke } from "@/lib/tauri";
import type { SecurityEvent, TelemetryEvent, TrustedDevice } from "@/lib/types";
import { coreSha3Hex } from "@/lib/core-crypto";

interface SafetyNumberResult {
  display?: string;
  safety_number?: string;
  qr_payload: string;
  verified?: boolean;
}

type StoredVerificationPayload = SafetyNumberResult & {
  user_id: string;
  device_id: string;
  fingerprint: string;
  created_at: string;
};

interface PersistentVerificationRow {
  user_id: string;
  device_id: string | null;
  fingerprint: string;
  display: string | null;
  safety_number: string | null;
  qr_payload: string;
  verified: boolean | null;
  signed_at: string | null;
  updated_at: string | null;
}

interface SecurityVerificationPageProps {
  userId: string;
  devices: TrustedDevice[];
  telemetry: TelemetryEvent[];
  securityEvents: SecurityEvent[];
  liveEvents: QGuardLiveEvent[];
  liveStatus: QGuardLiveStatus;
  onRefresh: () => void | Promise<void>;
}

type BusyAction = "verify" | "copy" | "refresh";
type StatusState = {
  tone: "success" | "warning" | "error" | "info";
  message: string;
} | null;

const VERIFICATION_LIVE_TABLES = new Set([
  "messaging_devices",
  "messaging_device_verification_payloads",
  "messaging_device_link_requests",
  "messaging_security_events",
  "messaging_crypto_telemetry",
]);

const statusAlertTone = {
  success: "border-emerald-200 bg-emerald-50 text-emerald-700",
  warning: "border-amber-200 bg-amber-50 text-amber-700",
  error: "border-rose-200 bg-rose-50 text-rose-600",
  info: "border-cyan-200 bg-cyan-50 text-cyan-700",
};

const VERIFICATION_STORAGE_PREFIX = "qguard:security-verification:v1";
const VERIFICATION_FINGERPRINT_STORAGE_PREFIX = "qguard:security-verification-fingerprint:v1";

function describeDataError(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  const candidate = error as { message?: string; details?: string; hint?: string; code?: string };
  return [candidate.message, candidate.details, candidate.hint, candidate.code].filter(Boolean).join(" ") || "Security verification failed.";
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

function liveTone(state: QGuardLiveStatus["state"]): string {
  if (state === "live") return "bg-emerald-50 text-emerald-600";
  if (state === "connecting") return "bg-amber-50 text-amber-600";
  if (state === "fallback") return "bg-cyan-50 text-cyan-700";
  return "bg-rose-50 text-rose-600";
}

function textTone(value: string): string {
  if (/failed|critical|revoked|missing|unverified|error|required/i.test(value)) return "text-rose-500";
  if (/pending|warning|fallback|connecting|partial|desktop/i.test(value)) return "text-amber-600";
  return "text-emerald-600";
}

function telemetryTone(event: TelemetryEvent): string {
  if (/failed|error|critical/i.test(`${event.stage} ${event.detail}`)) return "bg-rose-50 text-rose-600";
  if (event.progress < 100) return "bg-amber-50 text-amber-600";
  return "bg-emerald-50 text-emerald-600";
}

function securityEventTone(event: SecurityEvent): string {
  if (event.severity === "critical") return "bg-rose-50 text-rose-600";
  if (event.severity === "warning") return "bg-amber-50 text-amber-700";
  return "bg-emerald-50 text-emerald-600";
}

function isTrustedDevice(device: TrustedDevice): boolean {
  return device.trust_state === "ThisDevice" || device.trust_state === "Trusted";
}

function hasVerifiableMaterial(device: TrustedDevice): boolean {
  return Boolean(
    isTrustedDevice(device)
    && device.fingerprint
    && device.identity_signature
    && device.ed25519_identity_public.length > 0
    && device.mldsa_identity_public.length > 0
  );
}

function isVerificationTelemetry(event: TelemetryEvent): boolean {
  return /verification|safety|fingerprint|qr|device_link|device_sync|device_approved|trust/i.test(`${event.stage} ${event.detail}`);
}

function isVerificationSecurityEvent(event: SecurityEvent): boolean {
  return /verification|safety|fingerprint|qr|device_link|device_approved|device_sync/i.test(event.event_type);
}

function isVerificationLiveEvent(event: QGuardLiveEvent): boolean {
  if (!VERIFICATION_LIVE_TABLES.has(event.table)) return false;
  if (event.table === "messaging_crypto_telemetry" || event.table === "messaging_security_events") {
    return /verification|safety|fingerprint|qr|device_link|device_sync|device_approved|trust/i.test(event.detail);
  }
  return true;
}

function formatSuite(device: TrustedDevice): string {
  const pqKem = String(device.suite.pq_kem ?? "ML-KEM-1024");
  const classical = String(device.suite.classical_kex ?? "X25519");
  return `${pqKem} + ${classical}`;
}


function verificationStorageKey(userId: string, deviceId: string): string {
  return `${VERIFICATION_STORAGE_PREFIX}:${userId}:${deviceId}`;
}

function verificationFingerprintStorageKey(userId: string, fingerprint: string): string {
  return `${VERIFICATION_FINGERPRINT_STORAGE_PREFIX}:${userId}:${encodeURIComponent(fingerprint)}`;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function normalizeStoredVerification(value: unknown): SafetyNumberResult | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  const qrPayload = stringValue(record.qr_payload) ?? stringValue(record.qrPayload);
  if (!qrPayload) return null;
  return {
    display: stringValue(record.display),
    safety_number: stringValue(record.safety_number) ?? stringValue(record.safetyNumber),
    qr_payload: qrPayload,
    verified: record.verified === false ? false : true,
  };
}

function readStoredVerification(userId: string, deviceId: string, fingerprint: string): SafetyNumberResult | null {
  if (typeof window === "undefined") return null;
  const candidateKeys = [
    verificationFingerprintStorageKey(userId, fingerprint),
    verificationStorageKey(userId, deviceId),
  ];
  try {
    for (const key of candidateKeys) {
      const raw = window.localStorage.getItem(key);
      if (!raw) continue;
      const parsed = JSON.parse(raw) as Partial<StoredVerificationPayload>;
      if (parsed.user_id !== userId) continue;
      const fingerprintMatches = parsed.fingerprint ? parsed.fingerprint === fingerprint : false;
      const deviceMatches = parsed.device_id === deviceId;
      if (!fingerprintMatches && !deviceMatches) continue;
      const verification = normalizeStoredVerification(parsed);
      if (verification) return verification;
    }
  } catch {
    return null;
  }
  return null;
}

function writeStoredVerification(userId: string, device: TrustedDevice, verification: SafetyNumberResult): void {
  if (typeof window === "undefined") return;
  try {
    const payload: StoredVerificationPayload = {
      ...verification,
      user_id: userId,
      device_id: device.device_id,
      fingerprint: device.fingerprint,
      created_at: new Date().toISOString(),
    };
    const encoded = JSON.stringify(payload);
    window.localStorage.setItem(verificationFingerprintStorageKey(userId, device.fingerprint), encoded);
    window.localStorage.setItem(verificationStorageKey(userId, device.device_id), encoded);
  } catch {
    // Local storage is a convenience cache; backend security events remain authoritative.
  }
}

function isMissingVerificationStore(error: unknown): boolean {
  if (!error || typeof error === "string" || error instanceof Error) return false;
  const dataError = error as { code?: string; message?: string; details?: string; hint?: string };
  const raw = [dataError.code, dataError.message, dataError.details, dataError.hint].filter(Boolean).join(" ");
  return /PGRST205|could not find|does not exist|schema cache|relation/i.test(raw);
}

function verificationFromSecurityEvents(userId: string, device: TrustedDevice, events: SecurityEvent[]): SafetyNumberResult | null {
  for (const event of events) {
    if (event.event_type !== "safety_number_generated") continue;
    const details = event.encrypted_details ?? null;
    if (details && String(details.user_id ?? userId) !== userId) continue;
    const eventDeviceId = event.device_id ? String(event.device_id) : null;
    const detailDeviceId = details?.device_id ? String(details.device_id) : null;
    const detailFingerprint = details?.fingerprint ? String(details.fingerprint) : null;
    const deviceMatches = eventDeviceId === device.device_id || detailDeviceId === device.device_id;
    const fingerprintMatches = Boolean(
      detailFingerprint
      && (detailFingerprint === device.fingerprint || device.fingerprint.startsWith(detailFingerprint)),
    );
    if (!deviceMatches && !fingerprintMatches) continue;
    const verification = normalizeStoredVerification(details);
    if (verification) return verification;
  }
  return null;
}

async function readPersistentVerification(userId: string, device: TrustedDevice): Promise<SafetyNumberResult | null> {
  const { data, error } = await supabase
    .from("messaging_device_verification_payloads")
    .select("user_id,device_id,fingerprint,display,safety_number,qr_payload,verified,signed_at,updated_at")
    .eq("user_id", userId)
    .eq("fingerprint", device.fingerprint)
    .maybeSingle();

  if (error) {
    if (isMissingVerificationStore(error)) return null;
    throw error;
  }

  return normalizeStoredVerification(data as PersistentVerificationRow | null);
}

async function writePersistentVerification(userId: string, device: TrustedDevice, verification: SafetyNumberResult): Promise<boolean> {
  const now = new Date().toISOString();
  const { error } = await supabase
    .from("messaging_device_verification_payloads")
    .upsert({
      user_id: userId,
      device_id: device.device_id,
      fingerprint: device.fingerprint,
      display: verification.display ?? verification.safety_number ?? null,
      safety_number: verification.safety_number ?? verification.display ?? null,
      qr_payload: verification.qr_payload,
      verified: verification.verified !== false,
      suite: device.suite,
      signed_at: now,
      updated_at: now,
    }, { onConflict: "user_id,fingerprint" });

  if (error) {
    if (isMissingVerificationStore(error)) return false;
    throw error;
  }

  return true;
}

export default function SecurityVerificationPage({
  userId,
  devices,
  telemetry,
  securityEvents,
  liveEvents,
  liveStatus,
  onRefresh,
}: SecurityVerificationPageProps) {
  const isAdmin = useIsAdmin();
  const ownDevices = useMemo(() => {
    return devices
      .filter((device) => device.user_id === userId)
      .sort((a, b) => new Date(b.last_seen_at).getTime() - new Date(a.last_seen_at).getTime());
  }, [devices, userId]);
  const activeDevices = useMemo(() => ownDevices.filter((device) => device.trust_state !== "Revoked"), [ownDevices]);
  const trustedDevices = useMemo(() => activeDevices.filter(isTrustedDevice), [activeDevices]);
  const verifiableDevices = useMemo(() => activeDevices.filter(hasVerifiableMaterial), [activeDevices]);
  const thisDevice = useMemo(() => ownDevices.find((device) => device.trust_state === "ThisDevice") ?? trustedDevices[0] ?? null, [ownDevices, trustedDevices]);
  const [selectedDeviceId, setSelectedDeviceId] = useState(verifiableDevices[0]?.device_id ?? trustedDevices[0]?.device_id ?? "");
  const [verification, setVerification] = useState<SafetyNumberResult | null>(null);
  const [busy, setBusy] = useState<BusyAction | null>(null);
  const [status, setStatus] = useState<StatusState>(null);

  const selectedDevice = useMemo(() => {
    return ownDevices.find((device) => device.device_id === selectedDeviceId)
      ?? verifiableDevices[0]
      ?? trustedDevices[0]
      ?? activeDevices[0]
      ?? null;
  }, [activeDevices, ownDevices, selectedDeviceId, trustedDevices, verifiableDevices]);
  const verificationTelemetry = useMemo(() => telemetry.filter(isVerificationTelemetry).slice(0, 5), [telemetry]);
  const verificationSecurityEvents = useMemo(() => securityEvents.filter(isVerificationSecurityEvent).slice(0, 5), [securityEvents]);
  const verificationLiveEvents = useMemo(() => liveEvents.filter(isVerificationLiveEvent).slice(0, 5), [liveEvents]);
  const latestBackendAt = latestIso([
    liveStatus.lastEventAt,
    verificationTelemetry[0]?.created_at,
    verificationSecurityEvents[0]?.created_at,
    ...activeDevices.map((device) => device.last_seen_at),
  ]);
  const selectedDeviceVerifiable = selectedDevice ? hasVerifiableMaterial(selectedDevice) : false;
  const safetyDisplay = verification?.display ?? verification?.safety_number ?? "Generate a safety number from a trusted device fingerprint.";
  const payloadReady = Boolean(verification?.qr_payload);
  const verificationState = verification
    ? verification.verified === false ? "Unverified" : "Signed"
    : selectedDeviceVerifiable ? "Ready" : "Desktop Required";

  useEffect(() => {
    setSelectedDeviceId((current) => {
      if (ownDevices.some((device) => device.device_id === current)) return current;
      return verifiableDevices[0]?.device_id ?? trustedDevices[0]?.device_id ?? activeDevices[0]?.device_id ?? "";
    });
    if (ownDevices.length === 0) setVerification(null);
  }, [activeDevices, ownDevices, trustedDevices, verifiableDevices]);

  useEffect(() => {
    if (!selectedDeviceId) {
      setVerification(null);
      return;
    }
    if (!selectedDevice) {
      setVerification(null);
      return;
    }

    let active = true;
    const cachedVerification = verificationFromSecurityEvents(userId, selectedDevice, securityEvents)
      ?? readStoredVerification(userId, selectedDevice.device_id, selectedDevice.fingerprint);
    setVerification(cachedVerification);

    void readPersistentVerification(userId, selectedDevice)
      .then((persistentVerification) => {
        if (!active || !persistentVerification) return;
        setVerification(persistentVerification);
        writeStoredVerification(userId, selectedDevice, persistentVerification);
      })
      .catch((error) => {
        if (!active) return;
        setStatus({ tone: "warning", message: `Verification state is using local cache while backend payload sync catches up: ${describeDataError(error)}` });
      });

    return () => {
      active = false;
    };
  }, [liveStatus.lastEventAt, securityEvents, selectedDevice, selectedDeviceId, userId]);

  async function logVerificationEvent(
    eventType: string,
    severity: SecurityEvent["severity"],
    deviceId: string | null,
    metadata: Record<string, string | number | boolean | null>,
  ) {
    try {
      const createdAt = new Date().toISOString();
      const eventHash = await coreSha3Hex(JSON.stringify({ eventType, severity, deviceId, metadata, createdAt }));
      await supabase.from("messaging_security_events").insert({
        user_id: userId,
        device_id: deviceId,
        event_type: eventType,
        severity,
        encrypted_details: await securityEventDetails(eventHash, { user_id: userId, device_id: deviceId, ...metadata }),
        event_hash: eventHash,
      });
    } catch {
      // Verification audit rows should not block local safety-number checks.
    }
  }

  async function recordVerificationTelemetry(
    deviceId: string | null,
    stage: string,
    detail: string,
    progress: number,
    statusValue: "started" | "progress" | "verified" | "failed" | "complete",
  ) {
    await recordCryptoTelemetry({
      userId,
      deviceId,
      scope: "verification",
      stage,
      detail,
      progress,
      status: statusValue,
      metadata: {
        module: "security_verification",
        live_state: liveStatus.state,
      },
    });
  }

  async function verify(device: TrustedDevice | null = selectedDevice) {
    if (!device) {
      setStatus({ tone: "warning", message: "No trusted device is available for safety-number verification." });
      return;
    }
    setStatus({ tone: "info", message: "Generating signed safety number from the local desktop key service..." });
    setBusy("verify");
    try {
      await recordVerificationTelemetry(device.device_id, "safety_number_started", "Desktop verifier requested", 10, "started");
      const result = await safeInvoke<SafetyNumberResult>("security_verify_fingerprint", {
        remoteFingerprint: device.fingerprint,
      });
      const verifiedResult = { ...result, verified: result.verified ?? true };
      setVerification(verifiedResult);
      writeStoredVerification(userId, device, verifiedResult);
      const persisted = await writePersistentVerification(userId, device, verifiedResult);
      const verified = verifiedResult.verified !== false;
      await logVerificationEvent("safety_number_generated", verified ? "info" : "warning", device.device_id, {
        device_label: device.label,
        fingerprint: device.fingerprint,
        display: verifiedResult.display ?? verifiedResult.safety_number ?? null,
        safety_number: verifiedResult.safety_number ?? verifiedResult.display ?? null,
        qr_payload: verifiedResult.qr_payload,
        persistent_payload: persisted,
        verified,
      });
      await recordVerificationTelemetry(
        device.device_id,
        verified ? "safety_number_verified" : "safety_number_unverified",
        verified
          ? persisted
            ? "Signed safety number persisted for this device fingerprint"
            : "Signed safety number generated; backend persistence table is pending migration"
          : "Safety-number verifier returned an unverified result",
        100,
        verified ? "verified" : "failed",
      );
      setStatus({
        tone: verified ? "success" : "warning",
        message: verified
          ? persisted
            ? "Safety number is permanently signed for this device fingerprint and logged to the live stream."
            : "Safety number generated locally. Apply the persistent verification migration to sync it across sessions."
          : "Safety number generated, but verifier marked it untrusted.",
      });
      await Promise.resolve(onRefresh());
    } catch (error) {
      const message = describeDataError(error);
      setStatus({ tone: "error", message });
      await recordVerificationTelemetry(device.device_id, "safety_number_failed", message, 100, "failed");
    } finally {
      setBusy(null);
    }
  }

  async function copyPayload() {
    if (!verification) return;
    setBusy("copy");
    try {
      await navigator.clipboard.writeText(`${verification.display ?? verification.safety_number}\n${verification.qr_payload}`);
      await logVerificationEvent("verification_payload_copied", "info", selectedDevice?.device_id ?? null, {
        device_label: selectedDevice?.label ?? "unknown",
        payload_ready: true,
      });
      await recordVerificationTelemetry(selectedDevice?.device_id ?? null, "verification_payload_copied", "Safety number and QR payload copied locally", 100, "complete");
      setStatus({ tone: "success", message: "Verification payload copied locally." });
      await Promise.resolve(onRefresh());
    } catch (error) {
      const message = describeDataError(error);
      setStatus({ tone: "error", message });
      await recordVerificationTelemetry(selectedDevice?.device_id ?? null, "verification_payload_copy_failed", message, 100, "failed");
    } finally {
      setBusy(null);
    }
  }

  function refreshVerificationState() {
    void (async () => {
      setBusy("refresh");
      try {
        await Promise.resolve(onRefresh());
        await recordVerificationTelemetry(thisDevice?.device_id ?? null, "verification_state_refreshed", "Verification state refreshed from backend", 100, "complete");
        setStatus({ tone: "success", message: "Verification state refreshed from live backend data." });
      } catch (error) {
        setStatus({ tone: "error", message: describeDataError(error) });
      } finally {
        setBusy(null);
      }
    })();
  }

  return (
    // grid-cols-[minmax(0,1fr)] keeps the wide device matrix scrolling inside
    // its card instead of inflating the page past a phone viewport.
    <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
      <div className="grid gap-4 lg:grid-cols-4">
        <section className="shell-card p-4">
          <ShieldCheck className="text-emerald-600" size={24} />
          <div className="mt-3 text-sm font-bold text-ink-950">Safety Status</div>
          <div className={`mt-1 text-sm font-semibold ${textTone(verificationState)}`}>{verificationState}</div>
          <div className="mt-1 text-xs text-ink-500">{payloadReady ? "Persistent signed payload ready" : "Awaiting signed payload"}</div>
        </section>
        <section className="shell-card p-4">
          <MonitorSmartphone className="text-cyan-600" size={24} />
          <div className="mt-3 text-sm font-bold text-ink-950">Trusted Devices</div>
          <div className="mt-1 text-sm font-semibold text-emerald-600">{trustedDevices.length}/{Math.max(1, activeDevices.length)} trusted</div>
          <div className="mt-1 text-xs text-ink-500">{verifiableDevices.length} have signed identity material</div>
        </section>
        <section className="shell-card p-4">
          <Fingerprint className="text-violet-600" size={24} />
          <div className="mt-3 text-sm font-bold text-ink-950">Selected Identity</div>
          <div className={`mt-1 text-sm font-semibold ${textTone(selectedDeviceVerifiable ? "ready" : "missing")}`}>
            {selectedDevice ? selectedDevice.trust_state : "No device"}
          </div>
          <div className="mt-1 break-all text-xs text-ink-500">{selectedDevice?.fingerprint ?? "No fingerprint"}</div>
        </section>
        <section className="shell-card p-4">
          <Radio className={liveStatus.state === "live" ? "text-emerald-600" : "text-amber-600"} size={24} />
          <div className="mt-3 text-sm font-bold text-ink-950">Realtime Stream</div>
          <div className={`mt-1 text-sm font-semibold ${textTone(liveStatus.state)}`}>{liveStatus.state}</div>
          <div className="mt-1 truncate text-xs text-ink-500">{relativeTime(latestBackendAt)}</div>
        </section>
      </div>

      {/* Base grid-cols-[minmax(0,1fr)] caps the single mobile column at
          container width; without it the auto track inflates to the max-content
          width of the text-xl monospace safety box and pushes the panel off a
          phone screen. The xl two-column layout overrides it on desktop. */}
      <div className="grid grid-cols-[minmax(0,1fr)] gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
        <section className="shell-card p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <ShieldCheck className="text-emerald-600" size={26} />
              <div>
                <h2 className="text-sm font-bold text-ink-950">Safety Number</h2>
                <div className="text-sm text-ink-600">Compare the generated value with a trusted device before approving key changes.</div>
              </div>
            </div>
            <button onClick={refreshVerificationState} disabled={Boolean(busy)} className="flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-sm font-semibold text-ink-700 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50">
              {busy === "refresh" ? <Loader2 className="animate-spin" size={16} /> : <Clock3 size={16} />}
              Refresh
            </button>
          </div>

          <label className="mt-5 block text-xs font-bold uppercase tracking-wide text-ink-400" htmlFor="device-fingerprint">
            Device fingerprint
          </label>
          <select
            id="device-fingerprint"
            value={selectedDevice?.device_id ?? ""}
            onChange={(event) => {
              setSelectedDeviceId(event.target.value);
              setVerification(null);
              setStatus(null);
            }}
            className="mt-2 w-full rounded-lg border border-line bg-white px-3 py-2 text-sm text-ink-950 outline-none focus:border-violet-300"
          >
            {ownDevices.length === 0 && <option value="">No devices available</option>}
            {ownDevices.map((device) => (
              <option key={device.device_id} value={device.device_id}>{device.label} - {device.trust_state}</option>
            ))}
          </select>

          <div className="mt-5 break-words rounded-lg border border-line bg-canvas p-5 font-mono text-xl font-bold leading-relaxed text-ink-950">
            {safetyDisplay}
          </div>
          {selectedDevice && (
            <div className="mt-3 grid gap-2 md:grid-cols-3">
              <div className="rounded-lg border border-line bg-canvas px-3 py-2">
                <div className="text-[11px] font-bold uppercase text-ink-400">Fingerprint</div>
                <div className="mt-1 break-all font-mono text-xs text-ink-700">{selectedDevice.fingerprint}</div>
              </div>
              <div className="rounded-lg border border-line bg-canvas px-3 py-2">
                <div className="text-[11px] font-bold uppercase text-ink-400">Suite</div>
                <div className="mt-1 truncate text-xs font-semibold text-ink-700">{formatSuite(selectedDevice)}</div>
              </div>
              <div className="rounded-lg border border-line bg-canvas px-3 py-2">
                <div className="text-[11px] font-bold uppercase text-ink-400">Last Seen</div>
                <div className="mt-1 text-xs font-semibold text-ink-700">{relativeTime(selectedDevice.last_seen_at)}</div>
              </div>
            </div>
          )}

          {status && (
            <div className={`mt-3 rounded-lg border px-3 py-2 text-sm font-semibold ${statusAlertTone[status.tone]}`}>
              {status.message}
            </div>
          )}

          <div className="mt-4 flex flex-wrap gap-2">
            <button disabled={!selectedDevice || Boolean(busy)} onClick={() => verify()} className="flex items-center gap-2 rounded-lg bg-violet-600 px-4 py-2 text-sm font-bold text-white hover:bg-violet-700 disabled:cursor-not-allowed disabled:opacity-50">
              {busy === "verify" ? <Loader2 className="animate-spin" size={16} /> : <ShieldCheck size={16} />}
              {busy === "verify" ? "Verifying" : payloadReady ? "Re-verify" : "Verify"}
            </button>
            <button disabled={!verification || Boolean(busy)} onClick={copyPayload} className="flex items-center gap-2 rounded-lg border border-line px-4 py-2 text-sm font-bold text-ink-700 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50">
              {busy === "copy" ? <Loader2 className="animate-spin" size={16} /> : <Copy size={16} />}
              {busy === "copy" ? "Copying" : "Copy"}
            </button>
          </div>
        </section>

        <section className="shell-card p-5">
          <QrCode className="text-violet-600" size={30} />
          <h2 className="mt-3 text-sm font-bold text-ink-950">QR Verification Payload</h2>
          <div className="mt-1 text-xs text-ink-600">{payloadReady ? "Signed payload restored from backend/device cache." : "Generate a signed safety number for new trusted devices."}</div>
          <div className="mt-4 min-h-72 rounded-lg border border-line bg-white p-4 shadow-tight">
            {verification ? (
              <div className="break-all font-mono text-xs leading-relaxed text-ink-700">{verification.qr_payload}</div>
            ) : (
              <div className="flex h-60 items-center justify-center text-center text-sm text-ink-600">
                Select a new trusted device and generate a signed verification payload.
              </div>
            )}
          </div>
        </section>
      </div>

      {isAdmin && (
      <section className="shell-card p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-ink-950">Realtime Verification Telemetry</h2>
            <div className="mt-1 text-xs text-ink-600">Backend verification state refreshed {relativeTime(latestBackendAt)}</div>
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
            <div className="text-[11px] font-bold uppercase text-ink-400">Telemetry Rows</div>
            <div className="mt-1 text-sm font-semibold text-ink-950">{verificationTelemetry.length} recent records</div>
          </div>
          <div>
            <div className="text-[11px] font-bold uppercase text-ink-400">Audit Events</div>
            <div className="mt-1 text-sm font-semibold text-ink-950">{verificationSecurityEvents.length} verification events</div>
          </div>
        </div>

        <div className="mt-4 grid gap-6 xl:grid-cols-3">
          <div className="min-w-0">
            <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase text-ink-400">
              <Database size={14} />
              Backend Events
            </div>
            {verificationLiveEvents.length === 0 && (
              <div className="rounded-lg border border-line bg-canvas p-3 text-xs text-ink-600">Live stream connected. No verification backend changes received yet.</div>
            )}
            <div className="space-y-2">
              {verificationLiveEvents.map((event) => (
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
            {verificationTelemetry.length === 0 && (
              <div className="rounded-lg border border-line bg-canvas p-3 text-xs text-ink-600">No verification telemetry yet.</div>
            )}
            <div className="space-y-2">
              {verificationTelemetry.map((event) => (
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

          <div className="min-w-0">
            <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase text-ink-400">
              <CheckCircle2 size={14} />
              Security Audit
            </div>
            {verificationSecurityEvents.length === 0 && (
              <div className="rounded-lg border border-line bg-canvas p-3 text-xs text-ink-600">No verification audit events yet.</div>
            )}
            <div className="space-y-2">
              {verificationSecurityEvents.map((event) => (
                <div key={event.id} className="flex items-center gap-3 border-t border-line pt-2 first:border-t-0 first:pt-0">
                  <span className={`status-pill shrink-0 ${securityEventTone(event)}`}>{event.severity}</span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-xs font-semibold text-ink-950">{cleanLabel(event.event_type)}</div>
                    <div className="truncate font-mono text-[11px] text-ink-400">{event.event_hash}</div>
                  </div>
                  <div className="shrink-0 text-[11px] text-ink-400">{relativeTime(event.created_at)}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>
      )}

      <section className="shell-card overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line p-4">
          <div>
            <h2 className="text-sm font-bold text-ink-950">Verification Device Matrix</h2>
            <div className="mt-1 text-xs text-ink-600">User-scoped devices eligible for safety-number comparison and QR trust checks.</div>
          </div>
          {verifiableDevices.length < activeDevices.length && (
            <span className="status-pill bg-amber-50 text-amber-700">
              <AlertTriangle size={13} />
              {activeDevices.length - verifiableDevices.length} need signed identity material
            </span>
          )}
        </div>
        <div className="overflow-x-auto">
          {/* Below lg each row reflows to a stacked card (device label as the
              title, fingerprint/status/suite beneath) so phone widths never
              clip the matrix; at lg+ it is the column table. */}
          <div className="lg:min-w-[840px]">
            <div className="hidden border-b border-line bg-canvas px-4 py-3 text-xs font-bold uppercase tracking-wide text-ink-400 lg:grid lg:grid-cols-[180px_1fr_140px_180px]">
              <span>Device</span>
              <span>Fingerprint</span>
              <span>Status</span>
              <span>Suite</span>
            </div>
            {ownDevices.length === 0 && (
              <div className="p-6 text-sm text-ink-600">No trusted device records are available for this user.</div>
            )}
            {ownDevices.slice(0, 8).map((device) => {
              const verifiable = hasVerifiableMaterial(device);
              return (
                <div key={device.device_id} className="flex flex-col gap-1.5 border-b border-line px-4 py-3 text-sm lg:grid lg:grid-cols-[180px_1fr_140px_180px] lg:gap-0">
                  <span className="font-semibold text-ink-950 lg:truncate">{device.label}</span>
                  <span className="break-all font-mono text-xs text-violet-600 lg:truncate">{device.fingerprint}</span>
                  <span className={textTone(verifiable ? "ready" : device.trust_state)}>{verifiable ? "Verifiable" : device.trust_state}</span>
                  <span className="text-ink-600 lg:truncate">{formatSuite(device)}</span>
                </div>
              );
            })}
          </div>
        </div>
      </section>
    </div>
  );
}
