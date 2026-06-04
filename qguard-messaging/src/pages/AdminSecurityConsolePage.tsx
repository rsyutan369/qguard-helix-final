import { Building2, ShieldCheck, Users } from "lucide-react";
import type { OrgMemberSummary, TrustedDevice } from "@/lib/types";

interface AdminSecurityConsolePageProps {
  orgMembers: OrgMemberSummary[];
  devices: TrustedDevice[];
}

export default function AdminSecurityConsolePage({ orgMembers, devices }: AdminSecurityConsolePageProps) {
  const trustedDevices = devices.filter((device) => device.trust_state === "Trusted" || device.trust_state === "ThisDevice").length;

  return (
    <div className="grid gap-4">
      <div className="grid grid-cols-3 gap-4">
        <section className="shell-card p-4">
          <Building2 className="text-violet-600" size={24} />
          <div className="mt-3 text-sm font-bold text-ink-950">Organizations</div>
          <div className="mt-1 text-2xl font-bold text-violet-600">{new Set(orgMembers.map((member) => member.org_id)).size}</div>
        </section>
        <section className="shell-card p-4">
          <Users className="text-violet-600" size={24} />
          <div className="mt-3 text-sm font-bold text-ink-950">Membership Rows</div>
          <div className="mt-1 text-2xl font-bold text-violet-600">{orgMembers.length}</div>
        </section>
        <section className="shell-card p-4">
          <ShieldCheck className="text-violet-600" size={24} />
          <div className="mt-3 text-sm font-bold text-ink-950">Trusted Devices</div>
          <div className="mt-1 text-2xl font-bold text-violet-600">{trustedDevices}</div>
        </section>
      </div>

      <section className="shell-card overflow-hidden">
        <div className="border-b border-line p-4">
          <h2 className="text-sm font-bold text-ink-950">Organization Security Posture</h2>
        </div>
        {orgMembers.length === 0 && (
          <div className="p-6 text-center text-sm text-ink-600">No organization memberships are available for this user.</div>
        )}
        {orgMembers.map((member) => (
          <div key={`${member.org_id}-${member.user_id}`} className="grid grid-cols-[1fr_160px_220px_120px] items-center border-b border-line px-4 py-4 text-sm">
            <span className="truncate font-bold text-ink-950">{member.org_id}</span>
            <span className="text-ink-600">{member.role}</span>
            <span className="text-ink-600">{new Date(member.created_at).toLocaleString()}</span>
            <span className="status-pill bg-emerald-50 text-emerald-600"><ShieldCheck size={13} />Protected</span>
          </div>
        ))}
      </section>
    </div>
  );
}
