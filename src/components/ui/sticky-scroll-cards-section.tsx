import {
  Activity,
  Cpu,
  FileCheck,
  Fingerprint,
  Hourglass,
  Sparkles,
  Target,
  Workflow,
  type LucideIcon,
} from "lucide-react";

type Capability = {
  num: string;
  title: string;
  icon: LucideIcon;
  desc: string;
};

export const capabilities: Capability[] = [
  {
    num: "01",
    title: "Quantum-Native Platform",
    icon: Cpu,
    desc: "Built from the ground up for the quantum era - architected specifically to address emerging quantum threats, cryptographic modernization, and long-term crypto agility across modern enterprise environments.",
  },
  {
    num: "02",
    title: "Runtime Cryptographic Visibility and Telemetry",
    icon: Activity,
    desc: "Live cryptographic telemetry and intelligence engine that continuously monitors, analyzes, and maps how cryptography is actively being used across applications, APIs, endpoints, cloud workloads, containers, VPNs, databases, messaging systems, CI/CD pipelines, Kubernetes clusters, identities, certificates, and enterprise infrastructure in real time.",
  },
  {
    num: "03",
    title: "Complete Crypto Visibility",
    icon: Target,
    desc: "Deliver complete visibility into cryptographic assets, dependencies, trust relationships, and encryption usage across the entire enterprise ecosystem.",
  },
  {
    num: "04",
    title: "Intelligent Risk Prioritization",
    icon: Sparkles,
    desc: "AI-powered Q-Score analytics engine intelligently prioritizes cryptographic and quantum risks based on operational impact, exploitability, business criticality, and migration urgency.",
  },
  {
    num: "05",
    title: "End-to-End Migration Orchestration",
    icon: Workflow,
    desc: "Enterprise-grade orchestration engine designed to automate and manage the complete post-quantum migration lifecycle from discovery to full operational deployment.",
  },
  {
    num: "06",
    title: "Crypto-Agility by Design",
    icon: Fingerprint,
    desc: "Built with a flexible, policy-driven architecture that enables organizations to rapidly adapt to evolving cryptographic standards, emerging quantum threats, and future regulatory requirements.",
  },
  {
    num: "07",
    title: "Compliance & Governance Built-In",
    icon: FileCheck,
    desc: "Integrated governance, audit, and compliance framework designed to support regulatory alignment, cryptographic accountability, and enterprise security governance initiatives.",
  },
  {
    num: "08",
    title: "Ready for the Next Transition",
    icon: Hourglass,
    desc: "Post-quantum migration will not be the last cryptographic transition. The platform is built so algorithms, libraries, certificates and policies can be changed again as NIST, the IETF and vendors move.",
  },
];

export function CoreCapabilities() {
  return (
    <section
      className="relative overflow-hidden border-b border-slate-200 bg-[#f8fafc] bg-[radial-gradient(#e2e8f0_1.5px,transparent_1.5px)] bg-[size:24px_24px] px-6 py-24"
      id="core-capabilities-section"
    >
      <div className="relative z-10 mx-auto max-w-7xl">
        <div className="mb-16 space-y-3 text-center">
          <div className="inline-block select-none border-2 border-[#090d16] bg-white px-4 py-1.5 font-mono text-[9px] font-black uppercase tracking-widest text-[#090d16]">
            SYSTEM CAPABILITIES
          </div>
          <h2 className="mt-2 font-sans text-2xl font-black uppercase tracking-tight text-[#090d16] sm:text-3xl">
            CORE PLATFORM CAPABILITIES
          </h2>
          <p className="mx-auto max-w-2xl select-none font-mono text-xs leading-relaxed tracking-wide text-slate-500 sm:text-sm">
            The fundamental capabilities of the QGuard Helix platform engineered to discover, manage, and secure cryptographic vulnerabilities at scale.
          </p>
        </div>

        <div className="grid grid-cols-1 items-stretch gap-6 md:grid-cols-2 lg:grid-cols-4">
          {capabilities.map((cap) => {
            const IconComp = cap.icon;

            return (
              <div
                key={cap.num}
                className="relative flex min-h-[23.5rem] flex-col border-2 border-[#090d16] bg-white p-6 shadow-[5px_5px_0px_#090d16] transition-transform duration-200 hover:-translate-x-0.5 hover:-translate-y-0.5"
                id={`core-cap-${cap.num}`}
              >
                <div className="mb-6 flex h-12 w-12 shrink-0 items-center justify-center border-2 border-[#090d16] bg-white shadow-[2px_2px_0px_#090d16]">
                  <IconComp className="h-5 w-5 text-[#090d16]" />
                </div>

                <h3 className="mb-3 text-left font-sans text-xs font-black uppercase leading-tight tracking-wider text-[#090d16] md:text-[13px]">
                  {cap.title}
                </h3>

                <p className="mb-6 text-left text-[11px] font-semibold leading-relaxed text-slate-600">
                  {cap.desc}
                </p>

                <span className="mt-auto self-end select-none text-right font-mono text-[9px] font-extrabold tracking-wider text-slate-400">
                  // CAPABILITY_{cap.num}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}

export function StickyFeatureSection() {
  return <CoreCapabilities />;
}
