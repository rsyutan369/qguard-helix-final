import {
  Activity,
  Clock3,
  Database,
  KeyRound,
  LockKeyhole,
  MessageSquarePlus,
  MonitorSmartphone,
  Radio,
  ShieldAlert,
  ShieldCheck,
  Users,
} from "lucide-react";
import { isAdminEmail } from "@/lib/admin";
import type { CSSProperties } from "react";
import MetricCard from "@/components/MetricCard";
import type { QGuardLiveEvent, QGuardLiveStatus } from "@/lib/live-sse";
import type { DashboardData, TelemetryEvent, TrustedDevice } from "@/lib/types";

interface DashboardPageProps {
  data: DashboardData;
  liveEvents: QGuardLiveEvent[];
  liveStatus: QGuardLiveStatus;
  onNavigate: (page: string) => void;
}

function scoreColor(score: number): string {
  if (score >= 90) return "#10b981";
  if (score >= 70) return "#f59e0b";
  return "#f43f5e";
}

function statusTone(value: string): string {
  if (/failed|critical|no devices|needs device|not ready|missing|below|awaiting/i.test(value)) return "text-rose-600";
  if (/review|warning|partial|needs verification|replenish/i.test(value)) return "text-amber-600";
  return "text-emerald-600";
}

function liveTone(state: QGuardLiveStatus["state"]): string {
  if (state === "live") return "bg-emerald-50 text-emerald-600";
  if (state === "connecting") return "bg-amber-50 text-amber-600";
  if (state === "fallback") return "bg-cyan-50 text-cyan-700";
  return "bg-rose-50 text-rose-600";
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

function isTrustedDevice(device: TrustedDevice): boolean {
  return device.trust_state === "ThisDevice" || device.trust_state === "Trusted";
}

function isRecentDevice(device: TrustedDevice): boolean {
  const lastSeen = new Date(device.last_seen_at).getTime();
  return Number.isFinite(lastSeen) && Date.now() - lastSeen <= 24 * 60 * 60 * 1000;
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

function telemetryTone(event: TelemetryEvent): string {
  if (/failed|error|critical/i.test(`${event.stage} ${event.detail}`)) return "bg-rose-50 text-rose-600";
  if (event.progress < 100) return "bg-amber-50 text-amber-600";
  return "bg-emerald-50 text-emerald-600";
}

export default function DashboardPage({ data, liveEvents, liveStatus, onNavigate }: DashboardPageProps) {
  const { snapshot, devices, conversations, modules, report, keyInventory, telemetry, securityEvents } = data;
  const isAdmin = isAdminEmail(data.profile?.email);
  const myDevices = devices.filter((device) => device.user_id === data.profile?.id);
  const activeMyDevices = myDevices.filter((device) => device.trust_state !== "Revoked");
  const trustedDevices = activeMyDevices.filter(isTrustedDevice);
  const sendableDevices = activeMyDevices.filter(hasSendablePrekeys);
  const recentDevices = activeMyDevices.filter(isRecentDevice);
  const quickActions = modules.filter((module) => module.route !== "dashboard").slice(0, 4);
  const recentConversations = conversations.filter((conversation) => !conversation.archived_at && !conversation.hidden_at).slice(0, 5);
  const latestTelemetry = telemetry[0] ?? null;
  const latestSecurityEvent = securityEvents[0] ?? null;
  const latestBackendAt = latestIso([
    liveStatus.lastEventAt,
    latestTelemetry?.created_at,
    latestSecurityEvent?.created_at,
    ...activeMyDevices.map((device) => device.last_seen_at),
    ...conversations.map((conversation) => conversation.updated_at),
  ]);
  const prekeyTarget = Math.max(8, activeMyDevices.length * 8);
  const oneTimePrekeyLabel = `${keyInventory.available_one_time_prekeys}/${prekeyTarget}`;
  const scoreRingStyle = {
    "--score-color": scoreColor(snapshot.quantum_safe_score),
    background: `conic-gradient(var(--score-color) ${snapshot.quantum_safe_score * 3.6}deg, rgba(148, 163, 184, 0.28) 0deg)`,
  } as CSSProperties;
  const scoreCaption = snapshot.quantum_safe_score === 100
    ? "100% Quantum Security Protection"
    : snapshot.quantum_safe_score >= 90
      ? "Excellent Protection"
      : "Review Warnings";
  const securityRows = [
    ["End-to-End Encryption", snapshot.e2ee_status],
    ["Quantum Protection", snapshot.pqc_status],
    ["Forward Secrecy", report.forward_secrecy],
    ["Signed Prekeys", `${keyInventory.active_signed_prekeys}/${Math.max(1, activeMyDevices.length)} active`],
    ["One-Time Prekeys", oneTimePrekeyLabel],
    ["Device Security", activeMyDevices.length > 0 ? `${trustedDevices.length}/${activeMyDevices.length} trusted` : "No Devices"],
  ];

  return (
    <div className="grid gap-4">
      <div className="grid grid-cols-4 gap-4">
        <MetricCard
          icon={ShieldCheck}
          label="E2EE Status"
          value={snapshot.e2ee_status}
          caption={sendableDevices.length > 0 ? `${sendableDevices.length} sendable PQC device${sendableDevices.length === 1 ? "" : "s"}` : "Sync device keys and prekeys"}
          tone="emerald"
        />
        <MetricCard icon={KeyRound} label="Quantum Security" value={snapshot.pqc_status} caption={report.pqc_algorithm} tone="violet" />
        <MetricCard
          icon={Users}
          label="Active Devices"
          value={String(activeMyDevices.length)}
          caption={`${trustedDevices.length} trusted - ${recentDevices.length} recent heartbeat${recentDevices.length === 1 ? "" : "s"}`}
          tone="cyan"
        />
        <MetricCard icon={LockKeyhole} label="Vault Usage" value={snapshot.vault_storage} caption={`${data.vaultFiles.length} encrypted vault objects`} tone="emerald" />
      </div>

      {isAdmin && (
      <section className="shell-card p-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-ink-950">Realtime Data Fabric</h2>
            <div className="mt-1 text-xs text-ink-600">Backend state refreshed {relativeTime(latestBackendAt)}</div>
          </div>
          <span className={`status-pill ${liveTone(liveStatus.state)}`}>
            <Radio size={13} />
            {liveStatus.state}
          </span>
        </div>

        <div className="mt-4 grid grid-cols-4 gap-4 border-y border-line py-3">
          <div>
            <div className="text-[11px] font-bold uppercase text-ink-400">Live Stream</div>
            <div className="mt-1 truncate text-sm font-semibold text-ink-950">{liveStatus.detail}</div>
          </div>
          <div>
            <div className="text-[11px] font-bold uppercase text-ink-400">Last Event</div>
            <div className="mt-1 text-sm font-semibold text-ink-950">{relativeTime(liveStatus.lastEventAt)}</div>
          </div>
          <div>
            <div className="text-[11px] font-bold uppercase text-ink-400">Telemetry Rows</div>
            <div className="mt-1 text-sm font-semibold text-ink-950">{telemetry.length} live records</div>
          </div>
          <div>
            <div className="text-[11px] font-bold uppercase text-ink-400">Prekey Pool</div>
            <div className={`mt-1 text-sm font-semibold ${keyInventory.available_one_time_prekeys >= prekeyTarget ? "text-emerald-600" : "text-amber-600"}`}>{oneTimePrekeyLabel} ready</div>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-2 gap-6">
          <div className="min-w-0">
            <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase text-ink-400">
              <Database size={14} />
              Backend Events
            </div>
            {liveEvents.length === 0 && <div className="rounded-lg border border-line bg-canvas p-3 text-xs text-ink-600">Live stream connected. No backend changes received yet.</div>}
            <div className="space-y-2">
              {liveEvents.slice(0, 3).map((event) => (
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
            {telemetry.length === 0 && <div className="rounded-lg border border-line bg-canvas p-3 text-xs text-ink-600">No crypto telemetry yet.</div>}
            <div className="space-y-2">
              {telemetry.slice(0, 3).map((event) => (
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

      <div className="grid grid-cols-[1.2fr_1fr_0.85fr] gap-4">
        <section className="shell-card p-4">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-sm font-bold text-ink-950">Recent Conversations</h2>
            <button type="button" onClick={() => onNavigate("chat")} className="text-xs font-semibold text-violet-600">View All</button>
          </div>
          <div className="divide-y divide-line">
            {recentConversations.length === 0 && (
              <div className="py-8 text-center text-sm text-ink-600">No encrypted conversations are available for this user.</div>
            )}
            {recentConversations.map((conversation) => (
              <div key={conversation.id} className="flex items-center gap-3 py-3">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-violet-500 text-sm font-bold text-white">
                  {conversation.conversation_type.slice(0, 2).toUpperCase()}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex min-w-0 items-center gap-2 text-sm font-semibold text-ink-950">
                    <span className="truncate">{conversation.title}</span>
                    <LockKeyhole size={12} className="shrink-0 text-emerald-500" />
                  </div>
                  <div className="truncate text-xs text-ink-600">{conversation.last_activity}</div>
                </div>
                <div className="shrink-0 text-right">
                  <div className="text-[11px] text-ink-400">{relativeTime(conversation.updated_at)}</div>
                  {conversation.unread_count > 0 && <div className="mt-1 inline-flex h-5 min-w-5 items-center justify-center rounded-full bg-violet-500 px-1 text-[11px] font-bold text-white">{conversation.unread_count}</div>}
                </div>
              </div>
            ))}
          </div>
          <button type="button" onClick={() => onNavigate("chat")} className="mt-4 flex w-full items-center justify-center gap-2 rounded-lg border border-violet-100 py-2 text-sm font-semibold text-violet-600 hover:bg-violet-50">
            <MessageSquarePlus size={16} />
            New Secure Chat
          </button>
        </section>

        <section className="shell-card p-5">
          <div className="mb-5 flex items-center justify-between">
            <h2 className="text-sm font-bold text-ink-950">Security Overview</h2>
            <button type="button" onClick={() => onNavigate("quantum")} className="text-xs font-semibold text-violet-600">View Details</button>
          </div>
          <div className="mx-auto flex h-44 w-44 items-center justify-center rounded-full p-2" style={scoreRingStyle}>
            <div className="flex h-full w-full items-center justify-center rounded-full bg-white text-emerald-600">
              <ShieldCheck size={48} />
            </div>
          </div>
          <div className="mt-4 text-center">
            <div className={`text-xl font-bold ${statusTone(scoreCaption)}`}>Security Score: {snapshot.quantum_safe_score}%</div>
            <div className="text-sm text-ink-600">{scoreCaption}</div>
          </div>
          <div className="mt-5 space-y-2 text-sm">
            {securityRows.map(([item, value]) => (
              <div key={item} className="flex items-center justify-between gap-3">
                <span className="flex min-w-0 items-center gap-2 text-ink-600"><ShieldCheck size={14} className="shrink-0 text-emerald-500" /><span className="truncate">{item}</span></span>
                <span className={`truncate text-right text-xs font-semibold ${statusTone(value)}`}>{value}</span>
              </div>
            ))}
          </div>
          {report.warnings.length > 0 && (
            <div className="mt-4 space-y-2 border-t border-line pt-3">
              {report.warnings.slice(0, 3).map((warning) => (
                <div key={warning} className="flex gap-2 text-xs text-amber-600">
                  <ShieldAlert size={14} className="mt-0.5 shrink-0" />
                  <span>{warning}</span>
                </div>
              ))}
            </div>
          )}
        </section>

        <div className="grid gap-4">
          <section className="shell-card p-4">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-sm font-bold text-ink-950">My Devices</h2>
              <button type="button" onClick={() => onNavigate("devices")} className="text-xs font-semibold text-violet-600">Manage</button>
            </div>
            <div className="space-y-3">
              {myDevices.length === 0 && (
                <div className="py-5 text-sm text-ink-600">No trusted devices registered for this user.</div>
              )}
              {activeMyDevices.slice(0, 3).map((device) => {
                const sendable = hasSendablePrekeys(device);
                return (
                  <div key={device.device_id} className="flex items-center gap-3">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-canvas text-ink-600">
                      <MonitorSmartphone size={18} />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-semibold text-ink-950">{device.label}</div>
                      <div className="truncate text-xs text-ink-400">{device.pqc_status} - {relativeTime(device.last_seen_at)}</div>
                    </div>
                    <span className={`status-pill ${sendable ? "bg-emerald-50 text-emerald-600" : "bg-amber-50 text-amber-600"}`}>
                      {device.trust_state === "ThisDevice" ? "This Device" : sendable ? "Ready" : "Sync"}
                    </span>
                  </div>
                );
              })}
            </div>
          </section>

          <section className="shell-card p-4">
            <div className="mb-3 flex items-center gap-2">
              <Clock3 size={16} className="text-violet-600" />
              <h2 className="text-sm font-bold text-ink-950">Operational Readiness</h2>
            </div>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between gap-3">
                <span className="text-ink-600">Audit Events</span>
                <span className="font-semibold text-ink-950">{securityEvents.length}</span>
              </div>
              <div className="flex justify-between gap-3">
                <span className="text-ink-600">Key Rotations</span>
                <span className="font-semibold text-ink-950">{keyInventory.rotation_events}</span>
              </div>
              <div className="flex justify-between gap-3">
                <span className="text-ink-600">Last Security Event</span>
                <span className="font-semibold text-ink-950">{relativeTime(latestSecurityEvent?.created_at)}</span>
              </div>
            </div>
          </section>

          <section className="shell-card p-4">
            <h2 className="mb-3 text-sm font-bold text-ink-950">Quick Actions</h2>
            {quickActions.length === 0 && (
              <div className="rounded-lg border border-amber-100 bg-amber-50 p-3 text-xs font-semibold text-amber-700">
                No enabled actions are available for this account.
              </div>
            )}
            {quickActions.map((module) => (
              <button key={module.module_id} type="button" onClick={() => onNavigate(module.route)} className="flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left text-sm font-semibold text-ink-700 hover:bg-canvas">
                <MessageSquarePlus size={17} className="text-violet-600" />
                <span className="flex-1">{module.label}</span>
              </button>
            ))}
          </section>
        </div>
      </div>
    </div>
  );
}
