import React from "react";
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import {
  Activity,
  Database,
  Eye,
  GitBranch,
  Layers,
  Network,
  RotateCcw,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { BorderBeam } from "./border-beam";
import { Button } from "./button";
import { Card } from "./card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./tabs";
import { TracingBeam } from "./tracing-beam";

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

export const Hero195 = () => {
  const navigate = useNavigate();

  return (
    <section id="command-center" className="relative overflow-hidden bg-transparent py-24 scroll-mt-24">
      <div className="absolute left-1/2 top-0 h-full w-full -translate-x-1/2 overflow-hidden pointer-events-none">
        <div className="absolute left-[-10%] top-[-10%] h-[40%] w-[40%] rounded-full bg-gold/5 blur-[120px]" />
        <div className="absolute bottom-[-10%] right-[-10%] h-[40%] w-[40%] rounded-full bg-gold/5 blur-[120px]" />
      </div>

      <TracingBeam className="px-6">
        <div className="mx-auto max-w-6xl">
          <div className="mb-16 text-center">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
            >
              <span className="mb-6 inline-block rounded-full border border-gold/30 bg-gold/10 px-4 py-1.5 font-mono text-xs font-bold uppercase tracking-[0.2em] text-gold">
                Next-Gen PQC Infrastructure
              </span>
              <h2 className="mb-6 text-4xl font-black uppercase tracking-tight text-white md:text-6xl">
                Qguard Helix - <span className="gold-glow text-gold">Advance Features</span>
              </h2>
              <p className="mx-auto max-w-2xl text-lg leading-relaxed text-muted-foreground">
                A unified advanced-features dashboard for HNDL defense, runtime visibility, trust fabric, crypto
                agility, migration execution, sandbox rehearsal, rollback snapshots, and Quantum Vault protection.
              </p>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              whileInView={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.2, duration: 0.5 }}
              className="mt-10 flex justify-center gap-4"
            >
              <Button
                onClick={() => navigate("/auth")}
                size="lg"
                className="bg-gold px-8 font-bold uppercase tracking-widest text-black transition-all hover:bg-white"
              >
                Launch Advance Features <Zap className="ml-2 h-4 w-4" />
              </Button>
            </motion.div>
          </div>

          <motion.div
            initial={{ opacity: 0, y: 40 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3, duration: 0.7 }}
            className="relative"
          >
            <Tabs defaultValue={ADVANCE_FEATURES[0].value} className="w-full">
              <div className="mb-12 flex justify-center">
                <TabsList className="flex h-auto flex-wrap justify-center rounded-xl border border-white/10 bg-white/5 p-1">
                  {ADVANCE_FEATURES.map((feature) => {
                    const Icon = feature.icon;

                    return (
                      <TabsTrigger
                        key={feature.value}
                        value={feature.value}
                        className="rounded-lg px-4 py-3 text-[10px] font-bold uppercase tracking-wide transition-all data-[state=active]:bg-gold data-[state=active]:text-black sm:text-xs lg:px-5"
                      >
                        <Icon className="mr-2 h-4 w-4" />
                        {feature.label}
                      </TabsTrigger>
                    );
                  })}
                </TabsList>
              </div>

              {ADVANCE_FEATURES.map((feature, index) => {
                const Icon = feature.icon;

                return (
                  <TabsContent
                    key={feature.value}
                    value={feature.value}
                    className="mt-0 outline-none focus-visible:ring-0"
                  >
                    <Card className="group relative overflow-hidden border-gold/20 bg-cyber-navy/40 backdrop-blur-xl">
                      <BorderBeam size={300} duration={8} delay={2} />
                      <div className="grid items-stretch gap-4 p-4 md:p-6 lg:grid-cols-[1.45fr_0.9fr]">
                        <div className="relative min-h-[20rem] overflow-hidden rounded-2xl border border-white/10 bg-black/40 md:min-h-[24rem] lg:h-full lg:min-h-[32rem]">
                          <img
                            src={feature.image}
                            alt={feature.alt}
                            className="h-full w-full object-cover object-center opacity-90 transition-opacity duration-500 group-hover:opacity-100"
                          />
                          <div className="absolute inset-0 bg-gradient-to-t from-black/65 via-black/10 to-transparent pointer-events-none" />
                          <div className="absolute right-4 top-4 md:right-6 md:top-6">
                            <div className="flex items-center gap-2 rounded-full border border-gold/30 bg-black/60 px-4 py-2 shadow-[0_0_20px_rgba(212,175,55,0.2)] backdrop-blur-md">
                              <Icon className="h-3 w-3 text-gold" />
                              <span className="text-[10px] font-bold uppercase tracking-widest text-gold">
                                {feature.status}
                              </span>
                            </div>
                          </div>
                        </div>

                        <div className="flex h-full min-h-full flex-col justify-between rounded-2xl border border-white/10 bg-black/35 p-5 text-left md:p-6">
                          <div>
                            <div className="mb-5 flex items-center justify-between gap-4">
                              <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border border-gold/30 bg-gold/10 text-gold">
                                <Icon className="h-5 w-5" />
                              </div>
                              <span className="font-mono text-[10px] font-bold uppercase tracking-[0.2em] text-white/35">
                                // Feature {String(index + 1).padStart(2, "0")}
                              </span>
                            </div>
                            <p className="mb-2 font-mono text-[10px] font-bold uppercase tracking-[0.22em] text-gold">
                              {feature.label}
                            </p>
                            <h3 className="mb-3 text-2xl font-black uppercase tracking-tight text-white md:text-3xl">
                              {feature.title}
                            </h3>
                            <p className="text-sm leading-7 text-white/62">{feature.description}</p>
                          </div>

                          <div className="mt-6 grid gap-2 sm:grid-cols-3 lg:grid-cols-1 xl:grid-cols-3">
                            {feature.highlights.map((highlight) => (
                              <span
                                key={highlight}
                                className="rounded-lg border border-gold/20 bg-gold/10 px-3 py-2 text-center font-mono text-[10px] font-bold uppercase tracking-wide text-gold"
                              >
                                {highlight}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                    </Card>
                  </TabsContent>
                );
              })}
            </Tabs>
          </motion.div>
        </div>
      </TracingBeam>
    </section>
  );
};
