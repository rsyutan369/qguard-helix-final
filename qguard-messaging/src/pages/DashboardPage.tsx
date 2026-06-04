import {
  KeyRound,
  LockKeyhole,
  MessageSquarePlus,
  MonitorSmartphone,
  ShieldCheck,
  Users,
} from "lucide-react";
import type { CSSProperties } from "react";
import MetricCard from "@/components/MetricCard";
import type { DashboardData } from "@/lib/types";

interface DashboardPageProps {
  data: DashboardData;
  onNavigate: (page: string) => void;
}

function scoreColor(score: number): string {
  if (score >= 90) return "#10b981";
  if (score >= 70) return "#f59e0b";
  return "#f43f5e";
}

function statusTone(value: string): string {
  if (/failed|critical|no devices|needs device|not ready/i.test(value)) return "text-rose-600";
  if (/review|warning|awaiting|partial|needs verification|replenish/i.test(value)) return "text-amber-600";
  return "text-emerald-600";
}

export default function DashboardPage({ data, onNavigate }: DashboardPageProps) {
  const { snapshot, devices, conversations, modules, report } = data;
  const myDevices = devices.filter((device) => device.user_id === data.profile?.id);
  const activeMyDevices = myDevices.filter((device) => device.trust_state !== "Revoked");
  const quickActions = modules.filter((module) => module.route !== "dashboard").slice(0, 4);
  const securityRows = [
    ["End-to-End Encryption", snapshot.e2ee_status],
    ["Quantum Protection", snapshot.pqc_status],
    ["Forward Secrecy", report.forward_secrecy],
    ["HNDL Protection", snapshot.hndl_status],
    ["Device Security", myDevices.length > 0 ? `${snapshot.device_count}/${myDevices.length} trusted` : "No Devices"],
  ];
  const scoreRingStyle = {
    "--score-color": scoreColor(snapshot.quantum_safe_score),
    background: `conic-gradient(var(--score-color) ${snapshot.quantum_safe_score * 3.6}deg, rgba(148, 163, 184, 0.28) 0deg)`,
  } as CSSProperties;
  const scoreCaption = snapshot.quantum_safe_score === 100
    ? "100% Quantum Security Protection"
    : snapshot.quantum_safe_score >= 90
      ? "Excellent Protection"
      : "Review Warnings";

  return (
    <div className="grid gap-4">
      <div className="grid grid-cols-4 gap-4">
        <MetricCard icon={ShieldCheck} label="E2EE Status" value={snapshot.e2ee_status} caption={activeMyDevices.length > 0 ? "End-to-end encryption active" : "Register a device to enable"} tone="emerald" />
        <MetricCard icon={KeyRound} label="Quantum Security" value={snapshot.pqc_status} caption={report.pqc_algorithm} tone="violet" />
        <MetricCard icon={Users} label="Active Sessions" value={String(snapshot.active_sessions)} caption={`${snapshot.device_count} trusted device records`} tone="cyan" />
        <MetricCard icon={LockKeyhole} label="Vault Usage" value={snapshot.vault_storage} caption={`${data.vaultFiles.length} encrypted vault objects`} tone="emerald" />
      </div>

      <div className="grid grid-cols-[1.2fr_1fr_0.85fr] gap-4">
        <section className="shell-card p-4">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-sm font-bold text-ink-950">Recent Conversations</h2>
            <button onClick={() => onNavigate("chat")} className="text-xs font-semibold text-violet-600">View All</button>
          </div>
          <div className="divide-y divide-line">
            {conversations.length === 0 && (
              <div className="py-8 text-center text-sm text-ink-600">No encrypted conversations are available for this user.</div>
            )}
            {conversations.map((conversation) => (
              <div key={conversation.id} className="flex items-center gap-3 py-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-violet-500 text-sm font-bold text-white">
                  {conversation.conversation_type.slice(0, 2).toUpperCase()}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 text-sm font-semibold text-ink-950">
                    {conversation.title}
                    <LockKeyhole size={12} className="text-emerald-500" />
                  </div>
                  <div className="truncate text-xs text-ink-600">{conversation.last_activity}</div>
                </div>
                <div className="text-right">
                  <div className="text-[11px] text-ink-400">{new Date(conversation.updated_at).toLocaleString()}</div>
                  {conversation.unread_count > 0 && <div className="mt-1 inline-flex h-5 min-w-5 items-center justify-center rounded-full bg-violet-500 px-1 text-[11px] font-bold text-white">{conversation.unread_count}</div>}
                </div>
              </div>
            ))}
          </div>
          <button onClick={() => onNavigate("chat")} className="mt-4 flex w-full items-center justify-center gap-2 rounded-lg border border-violet-100 py-2 text-sm font-semibold text-violet-600 hover:bg-violet-50">
            <MessageSquarePlus size={16} />
            New Secure Chat
          </button>
        </section>

        <section className="shell-card p-5">
          <div className="mb-5 flex items-center justify-between">
            <h2 className="text-sm font-bold text-ink-950">Security Overview</h2>
            <button onClick={() => onNavigate("quantum")} className="text-xs font-semibold text-violet-600">View Details</button>
          </div>
          <div className="mx-auto flex h-44 w-44 items-center justify-center rounded-full p-2" style={scoreRingStyle}>
            <div className="flex h-full w-full items-center justify-center rounded-full bg-white text-emerald-600">
              <ShieldCheck size={48} />
            </div>
          </div>
          <div className="mt-4 text-center">
            <div className="text-xl font-bold text-emerald-600">Security Score: {snapshot.quantum_safe_score}%</div>
            <div className="text-sm text-ink-600">{scoreCaption}</div>
          </div>
          <div className="mt-5 space-y-2 text-sm">
            {securityRows.map(([item, value]) => (
              <div key={item} className="flex items-center justify-between gap-3">
                <span className="flex items-center gap-2 text-ink-600"><ShieldCheck size={14} className="text-emerald-500" />{item}</span>
                <span className={`truncate text-right text-xs font-semibold ${statusTone(value)}`}>{value}</span>
              </div>
            ))}
          </div>
        </section>

        <div className="grid gap-4">
          <section className="shell-card p-4">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-sm font-bold text-ink-950">My Devices</h2>
              <button onClick={() => onNavigate("devices")} className="text-xs font-semibold text-violet-600">Manage</button>
            </div>
            <div className="space-y-3">
              {myDevices.length === 0 && (
                <div className="py-5 text-sm text-ink-600">No trusted devices registered for this user.</div>
              )}
              {activeMyDevices.slice(0, 3).map((device) => (
                <div key={device.device_id} className="flex items-center gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-canvas text-ink-600">
                    <MonitorSmartphone size={18} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-semibold text-ink-950">{device.label}</div>
                    <div className="truncate text-xs text-ink-400">{device.pqc_status}</div>
                  </div>
                  <span className="status-pill bg-emerald-50 text-emerald-600">{device.trust_state === "ThisDevice" ? "This Device" : "Active"}</span>
                </div>
              ))}
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
              <button key={module.module_id} onClick={() => onNavigate(module.route)} className="flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left text-sm font-semibold text-ink-700 hover:bg-canvas">
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
