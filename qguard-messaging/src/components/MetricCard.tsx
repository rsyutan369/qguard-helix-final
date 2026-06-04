import type { LucideIcon } from "lucide-react";
import { AlertTriangle, CheckCircle2 } from "lucide-react";

interface MetricCardProps {
  icon: LucideIcon;
  label: string;
  value: string;
  caption: string;
  tone: "violet" | "cyan" | "emerald";
}

const tones = {
  violet: "bg-violet-50 text-violet-600",
  cyan: "bg-cyan-50 text-cyan-600",
  emerald: "bg-emerald-50 text-emerald-600",
};

export default function MetricCard({ icon: Icon, label, value, caption, tone }: MetricCardProps) {
  const needsAttention = /needs|awaiting|not ready|failed|warning/i.test(value);
  return (
    <section className="shell-card p-4">
      <div className="flex items-start justify-between">
        <div className={`flex h-12 w-12 items-center justify-center rounded-full ${tones[tone]}`}>
          <Icon size={23} />
        </div>
        {needsAttention ? <AlertTriangle className="text-amber-500" size={17} /> : <CheckCircle2 className="text-emerald-500" size={17} />}
      </div>
      <div className="mt-3 text-xs font-semibold text-ink-600">{label}</div>
      <div className={`mt-1 text-xl font-bold ${tone === "emerald" ? "text-emerald-600" : tone === "cyan" ? "text-cyan-600" : "text-violet-600"}`}>
        {value}
      </div>
      <div className="mt-2 text-xs leading-5 text-ink-600">{caption}</div>
    </section>
  );
}
