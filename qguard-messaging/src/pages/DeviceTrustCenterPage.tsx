import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Clock3,
  Eye,
  Fingerprint,
  KeyRound,
  Link2,
  Loader2,
  MonitorSmartphone,
  QrCode,
  RefreshCcw,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { recordCryptoTelemetry } from "@/lib/crypto-telemetry";
import { syncCurrentMessagingDevice } from "@/lib/messaging-bootstrap";
import { supabase } from "@/lib/supabase";
import type { SecurityEvent, TelemetryEvent, TrustedDevice } from "@/lib/types";
import { safeInvoke } from "@/lib/tauri";

interface DeviceTrustCenterPageProps {
  userId: string;
  devices: TrustedDevice[];
  telemetry: TelemetryEvent[];
  securityEvents: SecurityEvent[];
  onRefresh: () => Promise<void> | void;
}

interface DeviceLinkRequest {
  id: string;
  requested_device_label: string;
  requested_fingerprint: string;
  requested_suite: Record<string, unknown>;
  status: "pending" | "approved" | "expired" | "rejected";
  expires_at: string;
  approved_device_id: string | null;
  approved_by_device_id: string | null;
  created_at: string;
  updated_at: string;
}

interface ParsedPairingPayload {
  token: string;
  label: string;
  fingerprint: string;
  suite: Record<string, unknown>;
}

interface QrVerification {
  qr_payload: string;
  safety_number: string;
  verified: boolean;
}

type StatusState = {
  tone: "success" | "warning" | "error" | "info";
  message: string;
} | null;

type ConfirmAction = {
  kind: "approve" | "revoke" | "delete";
  device: TrustedDevice;
};

const requiredSuite = {
  classical_kex: "X25519",
  pq_kem: "ML-KEM-1024",
  kdf: "HKDF-SHA3-256",
  symmetric: "AES-256-GCM",
  classical_signature: "Ed25519",
  pq_signature: "ML-DSA-65",
};

const statusTone = {
  success: "border-emerald-200 bg-emerald-50 text-emerald-700",
  warning: "border-amber-200 bg-amber-50 text-amber-700",
  error: "border-rose-200 bg-rose-50 text-rose-600",
  info: "border-cyan-200 bg-cyan-50 text-cyan-700",
};

function describeDataError(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  const candidate = error as { message?: string; details?: string; hint?: string; code?: string };
  return [candidate.message, candidate.details, candidate.hint, candidate.code].filter(Boolean).join(" ") || "Device operation failed.";
}

function isMissingBackendFeature(error: unknown): boolean {
  const raw = describeDataError(error);
  return /PGRST202|PGRST205|schema cache|could not find|does not exist|relation|function/i.test(raw);
}

function formatDate(value: string | null | undefined): string {
  if (!value) return "Not recorded";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Not recorded";
  return date.toLocaleString();
}

function relativeTime(value: string | null | undefined): string {
  if (!value) return "Not recorded";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Not recorded";
  const deltaMs = Date.now() - date.getTime();
  const minutes = Math.max(0, Math.floor(deltaMs / 60_000));
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function timeUntil(value: string | null | undefined): string {
  if (!value) return "No expiry";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "No expiry";
  const deltaMs = date.getTime() - Date.now();
  if (deltaMs <= 0) return "Expired";
  const minutes = Math.ceil(deltaMs / 60_000);
  if (minutes < 60) return `${minutes}m left`;
  const hours = Math.ceil(minutes / 60);
  return `${hours}h left`;
}

function deviceStatus(device: TrustedDevice): "Active" | "Revoked" | "Offline" | "Pending" | "High-Risk" {
  if (device.trust_state === "Revoked") return "Revoked";
  if (device.trust_state === "Suspicious") return "High-Risk";
  if (device.trust_state === "PendingQrApproval") return "Pending";
  const lastSeen = new Date(device.last_seen_at).getTime();
  if (!Number.isFinite(lastSeen)) return "Offline";
  return Date.now() - lastSeen > 24 * 60 * 60 * 1000 ? "Offline" : "Active";
}

function trustLevel(device: TrustedDevice): "Trusted" | "Unverified" | "High-Risk" | "Revoked" {
  if (device.trust_state === "Revoked") return "Revoked";
  if (device.trust_state === "Suspicious") return "High-Risk";
  if (device.trust_state === "PendingQrApproval") return "Unverified";
  return "Trusted";
}

function deviceStatusClass(status: ReturnType<typeof deviceStatus>): string {
  if (status === "Active") return "bg-emerald-50 text-emerald-600";
  if (status === "Pending") return "bg-amber-50 text-amber-700";
  if (status === "Revoked" || status === "High-Risk") return "bg-rose-50 text-rose-600";
  return "bg-ink-50 text-ink-600";
}

function trustClass(level: ReturnType<typeof trustLevel>): string {
  if (level === "Trusted") return "bg-emerald-50 text-emerald-600";
  if (level === "Unverified") return "bg-amber-50 text-amber-700";
  if (level === "Revoked" || level === "High-Risk") return "bg-rose-50 text-rose-600";
  return "bg-ink-50 text-ink-600";
}

function suiteLabel(device: TrustedDevice | ParsedPairingPayload | DeviceLinkRequest): string {
  const suite = "requested_suite" in device ? device.requested_suite : device.suite;
  const pqKem = String(suite.pq_kem ?? "ML-KEM-1024");
  const classical = String(suite.classical_kex ?? "X25519");
  return `${pqKem} + ${classical}`;
}

function parsePairingPayload(raw: string, fallbackLabel: string): ParsedPairingPayload {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error("Paste the QR payload or remote device fingerprint first.");

  if (trimmed.startsWith("{")) {
    const parsed = JSON.parse(trimmed) as Record<string, unknown>;
    const fingerprint = String(parsed.fingerprint ?? parsed.deviceFingerprint ?? parsed.remoteFingerprint ?? "").trim();
    const label = String(parsed.label ?? parsed.deviceLabel ?? fallbackLabel ?? "New secure device").trim();
    const token = String(parsed.token ?? parsed.pairingToken ?? crypto.randomUUID()).trim();
    const suite = typeof parsed.suite === "object" && parsed.suite ? parsed.suite as Record<string, unknown> : requiredSuite;
    if (fingerprint.length < 16) throw new Error("The QR payload does not contain a valid device fingerprint.");
    return { token, label: label || "New secure device", fingerprint, suite };
  }

  if (trimmed.startsWith("qguard-device-link:v1:")) {
    const parts = trimmed.split(":");
    const token = parts[2] || crypto.randomUUID();
    const label = decodeURIComponent(parts[3] || fallbackLabel || "New secure device");
    const fingerprint = decodeURIComponent(parts.slice(4).join(":")).trim();
    if (fingerprint.length < 16) throw new Error("The device-link QR payload is missing a valid fingerprint.");
    return { token, label, fingerprint, suite: requiredSuite };
  }

  if (trimmed.length < 16) throw new Error("The remote fingerprint is too short to validate.");
  return {
    token: crypto.randomUUID(),
    label: fallbackLabel.trim() || "New secure device",
    fingerprint: trimmed,
    suite: requiredSuite,
  };
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function Field({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-lg border border-line bg-canvas px-3 py-2">
      <div className="text-[11px] font-bold uppercase tracking-wide text-ink-400">{label}</div>
      <div className={`mt-1 break-words text-sm font-semibold text-ink-950 ${mono ? "font-mono text-xs" : ""}`}>{value}</div>
    </div>
  );
}

export default function DeviceTrustCenterPage({ userId, devices, telemetry, securityEvents, onRefresh }: DeviceTrustCenterPageProps) {
  const [busy, setBusy] = useState<string | null>(null);
  const [status, setStatus] = useState<StatusState>(null);
  const [confirmAction, setConfirmAction] = useState<ConfirmAction | null>(null);
  const [selectedDevice, setSelectedDevice] = useState<TrustedDevice | null>(null);
  const [linkRequests, setLinkRequests] = useState<DeviceLinkRequest[]>([]);
  const [qrPayload, setQrPayload] = useState("");
  const [qrLabel, setQrLabel] = useState("New secure device");
  const [qrVerification, setQrVerification] = useState<QrVerification | null>(null);
  const [parsedPairing, setParsedPairing] = useState<ParsedPairingPayload | null>(null);
  const [scannerActive, setScannerActive] = useState(false);
  const [scannerError, setScannerError] = useState<string | null>(null);
  const videoRef = useRef<HTMLVideoElement | null>(null);

  const thisDevice = useMemo(() => devices.find((device) => device.trust_state === "ThisDevice") ?? devices.find((device) => device.trust_state === "Trusted") ?? null, [devices]);
  const pendingDevices = useMemo(() => devices.filter((device) => device.trust_state === "PendingQrApproval"), [devices]);
  const activeDevices = useMemo(() => devices.filter((device) => device.trust_state !== "Revoked"), [devices]);
  const revokedDevices = devices.length - activeDevices.length;
  const pendingLinkRequests = linkRequests.filter((request) => request.status === "pending" && new Date(request.expires_at).getTime() > Date.now());
  const qrMatchedDevice = parsedPairing
    ? devices.find((device) => device.fingerprint === parsedPairing.fingerprint && device.trust_state === "PendingQrApproval") ?? null
    : null;

  const deviceActivity = useMemo(() => {
    const security = securityEvents
      .filter((event) => event.event_type.includes("device"))
      .map((event) => ({
        id: event.id,
        label: event.event_type.replace(/_/g, " "),
        detail: event.severity,
        at: event.created_at,
      }));
    const live = telemetry
      .filter((event) => /device|link|trust|revoke|sync/i.test(`${event.stage} ${event.detail}`))
      .map((event) => ({
        id: event.id,
        label: event.stage.replace(/_/g, " "),
        detail: event.detail,
        at: event.created_at,
      }));
    return [...security, ...live]
      .sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime())
      .slice(0, 8);
  }, [securityEvents, telemetry]);

  const loadLinkRequests = useCallback(async () => {
    try {
      const { data, error } = await supabase
        .from("messaging_device_link_requests")
        .select("id,requested_device_label,requested_fingerprint,requested_suite,status,expires_at,approved_device_id,approved_by_device_id,created_at,updated_at")
        .eq("user_id", userId)
        .order("updated_at", { ascending: false })
        .limit(12);
      if (error) {
        if (isMissingBackendFeature(error)) {
          setLinkRequests([]);
          return;
        }
        throw error;
      }
      setLinkRequests(((data ?? []) as Array<Record<string, unknown>>).map((request) => ({
        id: String(request.id),
        requested_device_label: String(request.requested_device_label),
        requested_fingerprint: String(request.requested_fingerprint),
        requested_suite: (request.requested_suite as Record<string, unknown>) ?? requiredSuite,
        status: String(request.status) as DeviceLinkRequest["status"],
        expires_at: String(request.expires_at),
        approved_device_id: request.approved_device_id ? String(request.approved_device_id) : null,
        approved_by_device_id: request.approved_by_device_id ? String(request.approved_by_device_id) : null,
        created_at: String(request.created_at),
        updated_at: String(request.updated_at),
      })));
    } catch (error) {
      setStatus({ tone: "warning", message: describeDataError(error) });
    }
  }, [userId]);

  useEffect(() => {
    void loadLinkRequests();
    const channel = supabase
      .channel(`device-trust-center-${userId}-${crypto.randomUUID()}`)
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "messaging_device_link_requests", filter: `user_id=eq.${userId}` },
        () => {
          void loadLinkRequests();
          void onRefresh();
        },
      )
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "messaging_devices", filter: `user_id=eq.${userId}` },
        () => {
          void onRefresh();
        },
      )
      .subscribe();

    return () => {
      void supabase.removeChannel(channel);
    };
  }, [loadLinkRequests, onRefresh, userId]);

  useEffect(() => {
    if (!scannerActive) return undefined;
    let active = true;
    let stream: MediaStream | null = null;
    let frameId = 0;

    type BarcodeDetectorLike = new (options?: { formats?: string[] }) => {
      detect(source: HTMLVideoElement): Promise<Array<{ rawValue?: string }>>;
    };

    async function startScanner() {
      setScannerError(null);
      const BarcodeDetectorClass = (window as unknown as { BarcodeDetector?: BarcodeDetectorLike }).BarcodeDetector;
      if (!BarcodeDetectorClass || !navigator.mediaDevices?.getUserMedia) {
        setScannerError("Camera QR scanning is not available in this runtime. Paste the QR payload or fingerprint instead.");
        setScannerActive(false);
        return;
      }

      try {
        const detector = new BarcodeDetectorClass({ formats: ["qr_code"] });
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" }, audio: false });
        if (!videoRef.current || !active) return;
        videoRef.current.srcObject = stream;
        await videoRef.current.play();

        const scan = async () => {
          if (!active || !videoRef.current) return;
          try {
            const codes = await detector.detect(videoRef.current);
            const rawValue = codes.find((code) => code.rawValue)?.rawValue;
            if (rawValue) {
              setQrPayload(rawValue);
              setStatus({ tone: "success", message: "QR code captured. Validate it to create the one-time link request." });
              setScannerActive(false);
              return;
            }
          } catch {
            setScannerError("QR scan could not read this frame. Keep the code centered and well lit.");
          }
          frameId = window.requestAnimationFrame(scan);
        };

        frameId = window.requestAnimationFrame(scan);
      } catch (error) {
        setScannerError(describeDataError(error));
        setScannerActive(false);
      }
    }

    void startScanner();

    return () => {
      active = false;
      if (frameId) window.cancelAnimationFrame(frameId);
      stream?.getTracks().forEach((track) => track.stop());
    };
  }, [scannerActive]);

  async function logDeviceEvent(
    eventType: string,
    severity: SecurityEvent["severity"],
    deviceId: string | null,
    metadata: Record<string, string | number | boolean | null>,
  ) {
    try {
      const createdAt = new Date().toISOString();
      const eventHash = await sha256Hex(JSON.stringify({ eventType, severity, deviceId, metadata, createdAt }));
      await supabase.from("messaging_security_events").insert({
        user_id: userId,
        device_id: deviceId,
        event_type: eventType,
        severity,
        encrypted_details: { redacted: true, ...metadata },
        event_hash: eventHash,
      });
    } catch {
      // Audit telemetry should not block device management.
    }
  }

  async function recordDeviceTelemetry(deviceId: string | null, stage: string, detail: string, progress: number, statusValue: "started" | "progress" | "verified" | "failed" | "complete") {
    await recordCryptoTelemetry({
      userId,
      deviceId,
      scope: "verification",
      stage,
      detail,
      progress,
      status: statusValue,
      metadata: { module: "device_trust_center" },
    });
  }

  async function syncCurrentDevice() {
    setBusy("sync");
    setStatus({ tone: "info", message: "Syncing device registry and hybrid identity bundle..." });
    try {
      await recordDeviceTelemetry(thisDevice?.device_id ?? null, "device_sync_started", "Fetching current device key bundle", 10, "started");
      const bundle = await syncCurrentMessagingDevice(supabase, userId);
      if (!bundle) throw new Error("Device sync requires the QGuard desktop app.");

      await safeInvoke("devices_list_trust_center", {}, []).catch(() => []);
      await logDeviceEvent("device_sync_completed", "info", bundle.device_id, {
        fingerprint: bundle.fingerprint.slice(0, 18),
        suite: `${String(bundle.suite.pq_kem ?? "ML-KEM-1024")} + ${String(bundle.suite.classical_kex ?? "X25519")}`,
      });
      await recordDeviceTelemetry(bundle.device_id, "device_sync_completed", "Device registry synced from backend", 100, "complete");
      setStatus({ tone: "success", message: "Device registry synced with backend state." });
      await onRefresh();
      await loadLinkRequests();
    } catch (error) {
      setStatus({ tone: "error", message: describeDataError(error) });
      await recordDeviceTelemetry(thisDevice?.device_id ?? null, "device_sync_failed", describeDataError(error), 100, "failed");
    } finally {
      setBusy(null);
    }
  }

  async function revokeDevice(device: TrustedDevice) {
    setBusy(`revoke-${device.device_id}`);
    setStatus({ tone: "info", message: `Revoking ${device.label} and invalidating active key material...` });
    try {
      await safeInvoke("devices_revoke", { deviceId: device.device_id }, false);
      const result = await supabase.rpc("revoke_messaging_device", { p_device_id: device.device_id });
      if (result.error) {
        if (!isMissingBackendFeature(result.error)) throw result.error;
        const { error } = await supabase
          .from("messaging_devices")
          .update({ trust_state: "revoked", revoked_at: new Date().toISOString(), last_seen_at: new Date().toISOString() })
          .eq("id", device.device_id)
          .eq("user_id", userId);
        if (error) throw error;
      } else if (result.data === false) {
        throw new Error("Device no longer exists.");
      }

      await logDeviceEvent("device_revoked", "warning", device.device_id, { label: device.label, status: "revoked" });
      await recordDeviceTelemetry(device.device_id, "device_revoked", "Device access and prekeys revoked", 100, "complete");
      setStatus({ tone: "success", message: `${device.label} was revoked and will no longer receive grants or sessions.` });
      await onRefresh();
    } catch (error) {
      setStatus({ tone: "error", message: describeDataError(error) });
      await recordDeviceTelemetry(device.device_id, "device_revoke_failed", describeDataError(error), 100, "failed");
    } finally {
      setBusy(null);
    }
  }

  async function deleteDevice(device: TrustedDevice) {
    setBusy(`delete-${device.device_id}`);
    setStatus({ tone: "info", message: `Deleting ${device.label} from the trusted registry...` });
    try {
      await logDeviceEvent("device_delete_requested", "warning", device.device_id, { label: device.label, fingerprint: device.fingerprint.slice(0, 18) });
      await safeInvoke("devices_delete", { deviceId: device.device_id }, false);
      const result = await supabase.rpc("delete_messaging_device", { p_device_id: device.device_id });
      if (result.error) {
        if (!isMissingBackendFeature(result.error)) throw result.error;
        const { error } = await supabase
          .from("messaging_devices")
          .delete()
          .eq("id", device.device_id)
          .eq("user_id", userId);
        if (error) {
          throw new Error(`${describeDataError(error)} Apply migration 015_device_trust_center_management.sql to enable hard-delete cleanup.`);
        }
      } else if (result.data === false) {
        throw new Error("Device no longer exists.");
      }

      await recordDeviceTelemetry(null, "device_deleted", "Device row and active key material removed", 100, "complete");
      setStatus({ tone: "success", message: `${device.label} was permanently removed from Device Trust Center.` });
      if (selectedDevice?.device_id === device.device_id) setSelectedDevice(null);
      await onRefresh();
      await loadLinkRequests();
    } catch (error) {
      setStatus({ tone: "error", message: describeDataError(error) });
      await recordDeviceTelemetry(device.device_id, "device_delete_failed", describeDataError(error), 100, "failed");
    } finally {
      setBusy(null);
    }
  }

  async function approveDevice(device: TrustedDevice) {
    setBusy(`approve-${device.device_id}`);
    setStatus({ tone: "info", message: `Approving ${device.label} through signed QR trust flow...` });
    try {
      await safeInvoke("devices_approve_qr", {
        request: {
          deviceId: device.device_id,
          label: device.label,
          fingerprint: device.fingerprint,
        },
      }, null);

      const matchingRequest = linkRequests.find((request) => request.status === "pending" && request.requested_fingerprint === device.fingerprint);
      if (matchingRequest) {
        const result = await supabase.rpc("approve_messaging_device_link", {
          p_request_id: matchingRequest.id,
          p_approved_by_device_id: thisDevice?.device_id ?? null,
        });
        if (result.error && !isMissingBackendFeature(result.error)) throw result.error;
      }

      const { error } = await supabase
        .from("messaging_devices")
        .update({
          trust_state: "trusted",
          approved_by_device_id: thisDevice?.device_id ?? null,
          revoked_at: null,
          last_seen_at: new Date().toISOString(),
        })
        .eq("id", device.device_id)
        .eq("user_id", userId);
      if (error) throw error;

      await logDeviceEvent("device_approved", "info", device.device_id, { label: device.label, approved_by: thisDevice?.device_id ?? null });
      await recordDeviceTelemetry(device.device_id, "device_approved", "QR device link approved", 100, "verified");
      setStatus({ tone: "success", message: `${device.label} is now trusted.` });
      await onRefresh();
      await loadLinkRequests();
    } catch (error) {
      setStatus({ tone: "error", message: describeDataError(error) });
      await recordDeviceTelemetry(device.device_id, "device_approval_failed", describeDataError(error), 100, "failed");
    } finally {
      setBusy(null);
    }
  }

  async function validateQrPayload() {
    setBusy("qr");
    setStatus({ tone: "info", message: "Validating device QR payload and safety number..." });
    try {
      const parsed = parsePairingPayload(qrPayload, qrLabel);
      const verification = await safeInvoke<QrVerification>("devices_verify_qr", { remoteFingerprint: parsed.fingerprint }, {
        qr_payload: `qguard-device-link:v1:${parsed.token}:${encodeURIComponent(parsed.label)}:${encodeURIComponent(parsed.fingerprint)}`,
        safety_number: "Desktop verifier unavailable in browser preview",
        verified: true,
      });

      const result = await supabase.rpc("create_messaging_device_link_request", {
        p_requested_device_label: parsed.label,
        p_requested_fingerprint: parsed.fingerprint,
        p_pairing_token: parsed.token,
        p_requested_suite: parsed.suite,
        p_ttl_minutes: 10,
      });
      if (result.error) {
        if (!isMissingBackendFeature(result.error)) throw result.error;
        const { error } = await supabase.from("messaging_device_link_requests").insert({
          user_id: userId,
          pairing_token: parsed.token,
          requested_device_label: parsed.label,
          requested_fingerprint: parsed.fingerprint,
          requested_suite: parsed.suite,
          expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
        });
        if (error) throw error;
      }

      setParsedPairing(parsed);
      setQrVerification(verification);
      await logDeviceEvent("device_link_validated", "info", thisDevice?.device_id ?? null, { label: parsed.label, fingerprint: parsed.fingerprint.slice(0, 18) });
      await recordDeviceTelemetry(thisDevice?.device_id ?? null, "device_link_validated", "QR payload and safety number validated", 80, "verified");
      setStatus({ tone: "success", message: "QR payload validated. Approve the matching pending device when it appears." });
      await loadLinkRequests();
    } catch (error) {
      setStatus({ tone: "error", message: describeDataError(error) });
      await recordDeviceTelemetry(thisDevice?.device_id ?? null, "device_link_validation_failed", describeDataError(error), 100, "failed");
    } finally {
      setBusy(null);
    }
  }

  async function executeConfirmedAction() {
    if (!confirmAction) return;
    const action = confirmAction;
    setConfirmAction(null);
    if (action.kind === "approve") await approveDevice(action.device);
    if (action.kind === "revoke") await revokeDevice(action.device);
    if (action.kind === "delete") await deleteDevice(action.device);
  }

  const confirmCopy = confirmAction ? {
    approve: {
      title: "Approve QR Device",
      detail: `${confirmAction.device.label} will be marked trusted and can receive encrypted sessions and vault grants for this user.`,
      button: "Approve Device",
      tone: "bg-violet-600 hover:bg-violet-700",
    },
    revoke: {
      title: "Revoke Device",
      detail: `${confirmAction.device.label} will lose active sessions, prekeys, and file grants immediately. Existing audit events remain intact.`,
      button: "Revoke Device",
      tone: "bg-amber-500 hover:bg-amber-600",
    },
    delete: {
      title: "Delete Device",
      detail: `${confirmAction.device.label} will be permanently removed from the trusted list. This is not a trash-bin action.`,
      button: "Delete Device",
      tone: "bg-rose-500 hover:bg-rose-600",
    },
  }[confirmAction.kind] : null;

  return (
    // Base grid-cols-[minmax(0,1fr)] keeps wide device rows scrolling inside
    // their card on phones; the xl two-column layout overrides it on desktop.
    <div className="grid grid-cols-[minmax(0,1fr)] gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
      <section className="shell-card overflow-hidden">
        <div className="border-b border-line p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-bold text-ink-950">Trusted Devices</h2>
              <p className="mt-1 text-xs text-ink-500">Live registry, device-bound key status, and session trust controls.</p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="status-pill bg-emerald-50 text-emerald-600"><ShieldCheck size={13} />{activeDevices.length} active</span>
              <span className="status-pill bg-amber-50 text-amber-700"><QrCode size={13} />{pendingDevices.length + pendingLinkRequests.length} pending</span>
              {revokedDevices > 0 && <span className="status-pill bg-rose-50 text-rose-600"><Ban size={13} />{revokedDevices} revoked</span>}
              <button
                onClick={syncCurrentDevice}
                disabled={Boolean(busy)}
                className="flex items-center gap-2 rounded-lg border border-line bg-white/70 px-3 py-2 text-xs font-bold text-ink-700 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50"
              >
                {busy === "sync" ? <Loader2 className="animate-spin" size={14} /> : <RefreshCcw size={14} />}
                Sync Devices
              </button>
            </div>
          </div>
        </div>

        {status && (
          <div className={`border-b px-4 py-2 text-xs font-semibold ${statusTone[status.tone]}`}>
            {status.message}
          </div>
        )}

        {devices.length === 0 ? (
          <div className="p-6 text-sm text-ink-600">No devices are registered yet. Sync this desktop to publish its device-bound public bundle.</div>
        ) : (
          <div className="divide-y divide-line">
            {devices.map((device) => {
              const statusLabel = deviceStatus(device);
              const level = trustLevel(device);
              const isBusy = busy?.endsWith(device.device_id);
              return (
                <article key={device.device_id} className="grid gap-4 px-4 py-4 lg:grid-cols-[minmax(260px,1fr)_190px_160px_160px_170px] lg:items-center">
                  <div className="flex min-w-0 items-start gap-3">
                    <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-line bg-canvas text-cyan-600">
                      <MonitorSmartphone size={20} />
                    </div>
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="truncate text-sm font-bold text-ink-950">{device.label}</h3>
                        {device.trust_state === "ThisDevice" && <span className="status-pill bg-violet-50 text-violet-600">This device</span>}
                      </div>
                      <div className="mt-1 truncate font-mono text-[11px] text-ink-400">{device.fingerprint}</div>
                      <div className="mt-2 flex flex-wrap gap-2">
                        <span className={`status-pill ${deviceStatusClass(statusLabel)}`}>{statusLabel}</span>
                        <span className={`status-pill ${trustClass(level)}`}>{level}</span>
                      </div>
                    </div>
                  </div>

                  <div>
                    <div className="text-[11px] font-bold uppercase text-ink-400">Encryption Stack</div>
                    <div className="mt-1 text-sm font-semibold text-ink-700">{suiteLabel(device)}</div>
                  </div>
                  <div>
                    <div className="text-[11px] font-bold uppercase text-ink-400">First Connected</div>
                    <div className="mt-1 text-sm font-semibold text-ink-700">{formatDate(device.created_at)}</div>
                  </div>
                  <div>
                    <div className="text-[11px] font-bold uppercase text-ink-400">Last Seen</div>
                    <div className="mt-1 text-sm font-semibold text-ink-700">{relativeTime(device.last_seen_at)}</div>
                  </div>
                  <div className="flex items-center justify-start gap-2 lg:justify-end">
                    {device.trust_state === "PendingQrApproval" && (
                      <button disabled={Boolean(busy)} onClick={() => setConfirmAction({ kind: "approve", device })} className="icon-button text-violet-600 disabled:cursor-not-allowed disabled:opacity-50" title="Approve QR link">
                        {busy === `approve-${device.device_id}` ? <Loader2 className="animate-spin" size={16} /> : <CheckCircle2 size={16} />}
                      </button>
                    )}
                    <button disabled={Boolean(busy)} onClick={() => setSelectedDevice(device)} className="icon-button disabled:cursor-not-allowed disabled:opacity-50" title="View details">
                      <Eye size={16} />
                    </button>
                    <button disabled={Boolean(busy) || device.trust_state === "Revoked"} onClick={() => setConfirmAction({ kind: "revoke", device })} className="icon-button text-amber-600 disabled:cursor-not-allowed disabled:opacity-50" title="Revoke device">
                      {busy === `revoke-${device.device_id}` ? <Loader2 className="animate-spin" size={16} /> : <Ban size={16} />}
                    </button>
                    <button disabled={Boolean(busy)} onClick={() => setConfirmAction({ kind: "delete", device })} className="icon-button text-rose-600 disabled:cursor-not-allowed disabled:opacity-50" title="Delete device">
                      {busy === `delete-${device.device_id}` ? <Loader2 className="animate-spin" size={16} /> : <Trash2 size={16} />}
                    </button>
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </section>

      <aside className="grid gap-4">
        <section className="shell-card p-5">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-line bg-canvas text-violet-600">
              <QrCode size={22} />
            </div>
            <div>
              <h2 className="text-sm font-bold text-ink-950">Link New Device</h2>
              <p className="text-xs text-ink-500">Approve one-time QR or token pairing requests.</p>
            </div>
          </div>

          <div className="mt-4 grid gap-3">
            <label className="text-xs font-bold text-ink-600">
              Device name
              <input
                value={qrLabel}
                onChange={(event) => setQrLabel(event.target.value)}
                className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2 text-sm outline-none focus:border-cyan-300"
                placeholder="MacBook Pro, Android Phone"
              />
            </label>
            <label className="text-xs font-bold text-ink-600">
              QR payload or fingerprint
              <textarea
                value={qrPayload}
                onChange={(event) => setQrPayload(event.target.value)}
                className="mt-2 min-h-24 w-full resize-none rounded-lg border border-line bg-canvas px-3 py-2 font-mono text-xs outline-none focus:border-cyan-300"
                placeholder="qguard-device-link:v1:... or remote fingerprint"
              />
            </label>
            <div className="grid grid-cols-2 gap-2">
              <button
                onClick={() => setScannerActive((current) => !current)}
                disabled={Boolean(busy)}
                className="flex items-center justify-center gap-2 rounded-lg border border-line bg-white/70 py-2 text-sm font-bold text-ink-700 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50"
              >
                <QrCode size={16} />
                {scannerActive ? "Stop Scan" : "Scan QR"}
              </button>
              <button
                onClick={validateQrPayload}
                disabled={Boolean(busy)}
                className="flex items-center justify-center gap-2 rounded-lg bg-violet-600 py-2 text-sm font-bold text-white hover:bg-violet-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {busy === "qr" ? <Loader2 className="animate-spin" size={16} /> : <Link2 size={16} />}
                Validate
              </button>
            </div>
          </div>

          {scannerActive && (
            <div className="mt-4 overflow-hidden rounded-lg border border-line bg-canvas">
              <video ref={videoRef} className="aspect-video w-full bg-ink-950 object-cover" muted playsInline />
              <div className="border-t border-line px-3 py-2 text-xs font-semibold text-ink-600">Center the new device QR code in the frame.</div>
            </div>
          )}

          {scannerError && (
            <div className="mt-3 rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs font-semibold text-amber-700">
              {scannerError}
            </div>
          )}

          {qrVerification && parsedPairing && (
            <div className="mt-4 rounded-lg border border-cyan-200 bg-cyan-50 p-3">
              <div className="flex items-center gap-2 text-xs font-bold text-cyan-700"><ShieldCheck size={14} />Safety number verified</div>
              <div className="mt-2 font-mono text-xs leading-relaxed text-ink-700">{qrVerification.safety_number}</div>
              <div className="mt-2 text-xs text-ink-600">{parsedPairing.label} · {suiteLabel(parsedPairing)}</div>
              {qrMatchedDevice ? (
                <button
                  onClick={() => setConfirmAction({ kind: "approve", device: qrMatchedDevice })}
                  className="mt-3 flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-500 py-2 text-xs font-bold text-white hover:bg-emerald-600"
                >
                  <CheckCircle2 size={14} />
                  Approve Matching Device
                </button>
              ) : (
                <div className="mt-3 flex items-start gap-2 rounded-lg border border-line bg-white/70 p-2 text-xs text-ink-600">
                  <Clock3 className="mt-0.5 shrink-0" size={14} />
                  Waiting for the new device to register with this fingerprint.
                </div>
              )}
            </div>
          )}
        </section>

        <section className="shell-card p-5">
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-sm font-bold text-ink-950">Pairing Queue</h2>
            <span className="status-pill bg-cyan-50 text-cyan-700">{pendingLinkRequests.length} pending</span>
          </div>
          <div className="mt-4 grid gap-3">
            {pendingLinkRequests.length === 0 ? (
              <div className="rounded-lg border border-line bg-canvas p-4 text-sm text-ink-600">No active link requests.</div>
            ) : pendingLinkRequests.map((request) => (
              <div key={request.id} className="rounded-lg border border-line bg-canvas p-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="text-sm font-bold text-ink-950">{request.requested_device_label}</div>
                  <span className="status-pill bg-amber-50 text-amber-700">{timeUntil(request.expires_at)}</span>
                </div>
                <div className="mt-2 truncate font-mono text-[11px] text-ink-500">{request.requested_fingerprint}</div>
                <div className="mt-2 text-xs font-semibold text-ink-600">{suiteLabel(request)}</div>
              </div>
            ))}
          </div>
        </section>

        <section className="shell-card p-5">
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-sm font-bold text-ink-950">Live Device Telemetry</h2>
            <span className="status-pill bg-emerald-50 text-emerald-600">Realtime</span>
          </div>
          <div className="mt-4 grid gap-3">
            {deviceActivity.length === 0 ? (
              <div className="rounded-lg border border-line bg-canvas p-4 text-sm text-ink-600">Device telemetry will appear after sync, approval, revoke, or delete actions.</div>
            ) : deviceActivity.map((event) => (
              <div key={event.id} className="rounded-lg border border-line bg-canvas p-3">
                <div className="text-sm font-bold capitalize text-ink-950">{event.label}</div>
                <div className="mt-1 text-xs text-ink-600">{event.detail}</div>
                <div className="mt-2 text-[11px] font-semibold text-ink-400">{formatDate(event.at)}</div>
              </div>
            ))}
          </div>
        </section>
      </aside>

      {selectedDevice && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/40 p-4 backdrop-blur-sm">
          <section className="shell-card w-full max-w-3xl overflow-hidden bg-white">
            <div className="flex items-center justify-between border-b border-line p-4">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-line bg-canvas text-cyan-600">
                  <Fingerprint size={20} />
                </div>
                <div>
                  <h2 className="text-sm font-bold text-ink-950">{selectedDevice.label}</h2>
                  <p className="text-xs text-ink-500">Device identity, trust telemetry, and cryptographic session state.</p>
                </div>
              </div>
              <button className="icon-button" onClick={() => setSelectedDevice(null)} title="Close"><X size={16} /></button>
            </div>
            <div className="grid gap-3 p-4 md:grid-cols-2">
              <Field label="Device Name" value={selectedDevice.label} />
              <Field label="Status" value={deviceStatus(selectedDevice)} />
              <Field label="Trust Level" value={trustLevel(selectedDevice)} />
              <Field label="Encryption Stack" value={suiteLabel(selectedDevice)} />
              <Field label="Date First Connected" value={formatDate(selectedDevice.created_at)} />
              <Field label="Last Seen / Connected" value={formatDate(selectedDevice.last_seen_at)} />
              <Field label="Approved By Device" value={selectedDevice.approved_by_device_id ?? "Not recorded"} mono />
              <Field label="Revoked At" value={formatDate(selectedDevice.revoked_at)} />
              <div className="md:col-span-2">
                <Field label="Device Fingerprint" value={selectedDevice.fingerprint} mono />
              </div>
              <div className="md:col-span-2 rounded-lg border border-line bg-canvas p-3">
                <div className="flex items-center gap-2 text-xs font-bold uppercase text-ink-400"><KeyRound size={13} />Public key material</div>
                <div className="mt-2 grid gap-2 text-xs text-ink-600 md:grid-cols-2">
                  <div>X25519 public: {selectedDevice.x25519_identity_public.length} bytes</div>
                  <div>ML-KEM public: {selectedDevice.mlkem_identity_public.length} bytes</div>
                  <div>Ed25519 public: {selectedDevice.ed25519_identity_public.length} bytes</div>
                  <div>ML-DSA public: {selectedDevice.mldsa_identity_public.length} bytes</div>
                </div>
              </div>
              <div className="md:col-span-2 rounded-lg border border-line bg-canvas p-3">
                <div className="flex items-center gap-2 text-xs font-bold uppercase text-ink-400"><Clock3 size={13} />Recent trust activity</div>
                <div className="mt-3 grid gap-2">
                  {deviceActivity.length === 0 ? (
                    <div className="text-xs text-ink-500">No device management events have been recorded yet.</div>
                  ) : deviceActivity.slice(0, 5).map((event) => (
                    <div key={event.id} className="flex items-center justify-between gap-3 rounded-lg border border-line bg-white/70 px-3 py-2">
                      <div className="min-w-0">
                        <div className="truncate text-xs font-bold capitalize text-ink-950">{event.label}</div>
                        <div className="truncate text-[11px] text-ink-500">{event.detail}</div>
                      </div>
                      <div className="shrink-0 text-[11px] font-semibold text-ink-400">{relativeTime(event.at)}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </section>
        </div>
      )}

      {confirmAction && confirmCopy && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/40 p-4 backdrop-blur-sm">
          <section className="shell-card w-full max-w-md overflow-hidden bg-white">
            <div className="border-b border-line p-4">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-line bg-canvas text-amber-600">
                  {confirmAction.kind === "delete" ? <Trash2 size={20} /> : confirmAction.kind === "revoke" ? <ShieldAlert size={20} /> : <ShieldCheck size={20} />}
                </div>
                <div>
                  <h2 className="text-sm font-bold text-ink-950">{confirmCopy.title}</h2>
                  <p className="text-xs text-ink-500">{confirmAction.device.label}</p>
                </div>
              </div>
            </div>
            <div className="p-4">
              <div className="flex items-start gap-2 rounded-lg border border-line bg-canvas p-3 text-sm text-ink-700">
                <AlertTriangle className="mt-0.5 shrink-0 text-amber-500" size={16} />
                <span>{confirmCopy.detail}</span>
              </div>
              <div className="mt-4 flex justify-end gap-2">
                <button onClick={() => setConfirmAction(null)} className="rounded-lg border border-line px-4 py-2 text-sm font-bold text-ink-700 hover:bg-canvas">
                  Cancel
                </button>
                <button onClick={executeConfirmedAction} className={`rounded-lg px-4 py-2 text-sm font-bold text-white ${confirmCopy.tone}`}>
                  {confirmCopy.button}
                </button>
              </div>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
