import { useState } from "react";
import { Chars } from "@/pages/landing-chars";
import { useNavigate } from "react-router-dom";
import {
  Activity,
  ArrowRight,
  Database,
  Eye,
  GitBranch,
  Layers,
  Network,
  RotateCcw,
  ShieldCheck,
} from "lucide-react";

const ADVANCE_FEATURES = [
  {
    value: "hndl",
    label: "Harvest-Now Defense",
    title: "Intelligent Quantum Risk Analysis",
    description:
      "Go beyond cryptographic discovery with intelligent quantum risk analysis. Qguard Helix calculates Harvest Now, Decrypt Later exposure by evaluating data lifetime, cryptographic strength, business value, threat actor interest, retention policies, and trust dependencies. The result is a prioritized quantum-risk view that identifies which assets require immediate action before encrypted data harvested today becomes readable in the future.",
    image: "/helix-features/hndl.png",
    alt: "HNDL protection command center with encrypted traffic risk maps",
    status: "HNDL exposure mapped",
    highlights: ["Exposure scoring", "Critical asset ranking", "Defense actions"],
    icon: ShieldCheck,
  },
  {
    value: "runtime-visibility",
    label: "Runtime Visibility",
    title: "Live Crypto Observability",
    description:
      "Continuously monitor cryptographic activity across certificates, TLS sessions, key usage, applications, workloads, APIs, and trust relationships in real time. Qguard Helix streams operational telemetry into a unified view, enabling security teams to detect cryptographic exposure, policy violations, certificate anomalies, weak algorithms, and quantum-readiness gaps before they impact business operations.",
    image: "/helix-features/runtime-visibility.png",
    alt: "Runtime visibility dashboard showing live cryptographic telemetry",
    status: "Runtime telemetry live",
    highlights: ["TLS behavior", "Key-use signals", "Service posture"],
    icon: Eye,
  },
  {
    value: "trust-fabric",
    label: "Trust Fabric",
    title: "Verified Trust Graph",
    description:
      "Discover and visualize the trust relationships that power your organization. Qguard Helix continuously maps identities, certificates, trust anchors, applications, services, devices, vendors, and policy evidence to reveal ownership, dependencies, trust paths, and potential single points of failure before they impact operations or migration initiatives.",
    image: "/helix-features/trust-fabric.png",
    alt: "Trust fabric graph connecting identities devices APIs and certificates",
    status: "Trust graph verified",
    highlights: ["Identity mesh", "Policy evidence", "Certificate controls"],
    icon: Network,
  },
  {
    value: "crypto-agility",
    label: "Crypto Agility",
    title: "Policy-Driven Upgrades",
    description:
      "Post-quantum migration is not the last cryptographic transition. Qguard Helix helps organizations build long-term cryptographic agility by enforcing algorithm-independent security policies, simplifying certificate rotation, accelerating key management workflows, and enabling future migrations without repeating costly transformation efforts.",
    image: "/helix-features/crypto-agility.png",
    alt: "Crypto agility control plane with modular algorithms and upgrade paths",
    status: "Agility controls ready",
    highlights: ["Algorithm swaps", "Cert rotation", "Hybrid rollout"],
    icon: GitBranch,
  },
  {
    value: "migration",
    label: "Migration",
    title: "PQC Migration Command",
    description:
      "Coordinate phased migration waves, readiness telemetry, dependency validation, trust-state assurance, rollback planning, and executive risk posture from a single operational control plane. Qguard Helix enables organizations to modernize cryptography, validate trust relationships, and accelerate post-quantum readiness while maintaining operational continuity.",
    image: "/helix-features/migration.png",
    alt: "Post-quantum migration control center with legacy to PQC transition lanes",
    status: "Migration wave active",
    highlights: ["Wave planning", "Dependency checks", "Readiness proof"],
    icon: Activity,
  },
  {
    value: "sandbox-migration",
    label: "Sandbox Migration",
    title: "Safe Migration Rehearsal",
    description:
      "Test applications, certificates, APIs, workloads, trust relationships, and cryptographic dependencies in isolated PQC-ready replicas before production deployment. Qguard Helix simulates migration outcomes, validates trust paths, identifies hidden dependencies, and verifies rollback strategies to reduce risk and accelerate quantum-safe transformation.",
    image: "/helix-features/sandbox-migration.png",
    alt: "Sandbox migration lab with isolated production-like crypto test environments",
    status: "Sandbox isolated",
    highlights: ["Replica testing", "Compatibility proof", "Release confidence"],
    icon: Layers,
  },
  {
    value: "rollback-snapshot",
    label: "Rollback & Snapshot",
    title: "Recovery-First Migration",
    description:
      "Preserve immutable snapshots, versioned cryptographic policies, trust-state baselines, dependency maps, and restore checkpoints so migration teams can validate changes, compare outcomes, and recover cleanly when needed. Qguard Helix ensures every post-quantum migration is backed by verifiable recovery paths, operational resilience, and continuous trust assurance.",
    image: "/helix-features/rollback-snapshot.png",
    alt: "Rollback and snapshot control center with recovery timelines",
    status: "Restore point sealed",
    highlights: ["Immutable snapshots", "Policy versions", "Fast restore"],
    icon: RotateCcw,
  },
  {
    value: "quantum-vault",
    label: "Quantum Vault",
    title: "Zero-Knowledge Protection",
    description:
      "Protect sensitive files, secrets, and cryptographic key material with PQC-aware vaulting, sealed storage, isolated cryptographic envelopes, and zero-knowledge access controls. Qguard Helix combines secure storage, cryptographic governance, key lifecycle protection, and quantum-ready security architectures to safeguard critical assets against current threats and future cryptographic disruption.",
    image: "/helix-features/quantum-vault.png",
    alt: "Quantum vault with encrypted file capsules and post-quantum key protection",
    status: "Zero-knowledge vault",
    highlights: ["PQC envelopes", "Key isolation", "Encrypted storage"],
    icon: Database,
  },
];

/**
 * Homepage "Advance Features" section. Styled by src/pages/landing.css (the
 * .lp-* classes), so it must render inside the homepage root.
 */
export const Hero195 = () => {
  const navigate = useNavigate();
  const [activeValue, setActiveValue] = useState(ADVANCE_FEATURES[0].value);
  const activeIndex = Math.max(0, ADVANCE_FEATURES.findIndex((feature) => feature.value === activeValue));
  const feature = ADVANCE_FEATURES[activeIndex];

  return (
    <section id="command-center" className="lp-section">
      <div className="lp-wrap">
        <div className="lp-head lp-head--split">
          <div>
            <p className="lp-eyebrow">Next-Gen PQC Infrastructure</p>
            <h2 className="lp-h2" data-letters="scroll" aria-label="Qguard Helix - Advance Features">
              <Chars text="Qguard Helix - Advance Features" />
            </h2>
            <p className="lp-lede">
              A unified advanced-features dashboard for HNDL defense, runtime visibility, trust fabric, crypto
              agility, migration execution, sandbox rehearsal, rollback snapshots, and Quantum Vault protection.
            </p>
          </div>
          <button type="button" onClick={() => navigate("/auth")} className="lp-btn lp-btn--secondary">
            Launch Advance Features
            <ArrowRight aria-hidden="true" />
          </button>
        </div>

        <div className="lp-tabs" role="tablist" aria-label="Advance features">
          {ADVANCE_FEATURES.map((item) => {
            const Icon = item.icon;

            return (
              <button
                key={item.value}
                type="button"
                role="tab"
                aria-selected={item.value === feature.value}
                aria-controls="advance-feature-panel"
                onClick={() => setActiveValue(item.value)}
              >
                <Icon className="lp-icon" aria-hidden="true" />
                {item.label}
              </button>
            );
          })}
        </div>

        <div key={feature.value} id="advance-feature-panel" role="tabpanel" className="lp-feature lp-card">
          <div className="lp-feature__media">
            <img src={feature.image} alt={feature.alt} />
          </div>

          <div className="lp-feature__copy">
            <div className="lp-feature__meta">
              <span className="lp-label">{feature.label}</span>
              <span className="lp-label">Feature {String(activeIndex + 1).padStart(2, "0")}</span>
            </div>
            <h3>{feature.title}</h3>
            <p>{feature.description}</p>

            <ul className="lp-feature__highlights">
              <li className="lp-tag">{feature.status}</li>
              {feature.highlights.map((highlight) => (
                <li key={highlight} className="lp-tag">
                  {highlight}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
};
