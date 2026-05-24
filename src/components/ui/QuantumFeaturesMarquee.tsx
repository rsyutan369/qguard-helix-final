import { useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { Lock, Radio, Shield, Terminal, Workflow, Zap } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Marquee } from "@/components/ui/marquee";

const roadmapQuestions: Record<string, string> = {
  "Where is cryptography used?": "Cryptography is used across TLS/HTTPS, VPNs, APIs, databases, identity systems, cloud storage, email, messaging, code signing, certificates, payment systems, backups, firmware signing, and service-to-service communication.",
  "Which applications use vulnerable crypto?": "Applications using quantum-vulnerable public-key cryptography such as RSA, classical Diffie-Hellman, ECDH, ECDSA, or DSA may require migration planning to NIST-approved post-quantum algorithms.",
  "Where are keys exchanged?": "Keys are commonly exchanged during TLS handshakes, VPN tunnel establishment, API authentication, database connections, SSH sessions, messaging sessions, device onboarding, and cloud service integrations.",
  "What certificates are weak?": "Weak certificates include expired certificates, certificates using deprecated hash algorithms such as SHA-1, insufficient key sizes, misconfigured trust chains, unmanaged internal CAs, and certificates dependent on quantum-vulnerable RSA or ECDSA for long-term security.",
  "Which services still use RSA/ECC?": "Common locations include web servers, load balancers, VPN gateways, SSH servers, API gateways, database connectors, IAM platforms, certificate authorities, code-signing systems, firmware-signing systems, and third-party SaaS integrations.",
  "Where do deprecated TLS versions exist?": "Deprecated TLS versions commonly appear on legacy web applications, internal portals, old appliances, unmanaged APIs, embedded systems, VPN concentrators, printers, IoT devices, and forgotten staging or test environments.",
  "Where does shadow crypto exist?": "Shadow crypto exists in undocumented certificates, hardcoded keys, unmanaged crypto libraries, developer-created encryption routines, legacy microservices, old containers, internal scripts, vendor SDKs, firmware, and embedded components.",
  "Which applications secretly downgrade encryption?": "Applications may downgrade encryption through legacy fallback modes, weak cipher negotiation, outdated SDKs, proxy or load-balancer termination, compatibility settings, or middleware that forces older TLS versions or weaker cipher suites.",
  "Which vendors embed weak cryptography?": "Weak vendor cryptography may appear in closed-source appliances, outdated SDKs, firmware, IoT devices, identity connectors, VPN clients, endpoint agents, monitoring tools, legacy drivers, and third-party cryptographic libraries.",
  "Where does Harvest Now, Decrypt Later exposure occur?": "Harvest Now, Decrypt Later exposure occurs where long-lived sensitive data is transmitted or stored using quantum-vulnerable public-key cryptography, especially financial records, health data, identity data, government data, legal archives, backups, source code, intellectual property, and encrypted network captures.",
  "Can we migrate to ML-KEM without downtime?": "Potentially yes, but it depends on the protocol, vendor support, and deployment architecture. A phased hybrid approach can allow classical and post-quantum key establishment to operate during transition, reducing migration risk while maintaining compatibility.",
  "Are my encryption keys vulnerable to Shor's algorithm?": "Public-key systems based on RSA, finite-field Diffie-Hellman, ECDH, ECDSA, and DSA are considered quantum-vulnerable because a cryptographically relevant quantum computer could break their underlying mathematical assumptions using Shor's algorithm.",
  "Where are my legacy RSA and ECC keys located?": "Legacy RSA and ECC keys may be located in TLS certificates, web servers, load balancers, VPN gateways, SSH keys, database connectors, cloud KMS/IAM systems, certificate authorities, code-signing systems, firmware-signing pipelines, and application secrets stores.",
  "How does Harvest Now Decrypt Later affect us?": "Adversaries may capture encrypted traffic or archived encrypted data today and store it until a cryptographically relevant quantum computer becomes available, creating risk for data that must remain confidential for many years.",
  "Which cipher suites should we deprecate?": "Organizations should phase out deprecated TLS versions, weak cipher suites, static RSA key exchange, weak Diffie-Hellman groups, SHA-1-based signatures, and configurations that rely only on quantum-vulnerable public-key exchange for long-lived sensitive data. AES-GCM itself is not deprecated by NIST, but it does not solve quantum-vulnerable key establishment by itself.",
  "What systems have the highest crypto-urgency?": "Highest-priority systems are those protecting long-lived sensitive data or trust anchors, including identity platforms, PKI and certificate authorities, VPN gateways, financial systems, healthcare records, government archives, code-signing infrastructure, firmware-signing systems, and critical backups.",
  "Can we automate TLS certificate rotations?": "Yes. TLS certificate lifecycle management can be automated using ACME-compatible workflows and certificate management platforms. Post-quantum or hybrid certificate deployment depends on vendor, browser, CA, and protocol support, so it should be tested before production rollout.",
  "How do I maintain hybrid cryptographic pipelines?": "Use crypto-agility: maintain a cryptographic inventory, abstract algorithm choices from application logic, centralize policy control, track dependencies, support configurable algorithms, and plan phased migration to NIST-standardized PQC where supported.",
  "Is there a standard ML-DSA parameter set?": "Yes. NIST FIPS 204 standardizes ML-DSA parameter sets including ML-DSA-44, ML-DSA-65, and ML-DSA-87. ML-DSA-65 is a reasonable enterprise-grade default, while ML-DSA-87 may be selected for higher-security use cases.",
  "Are our VPN tunnels secure against post-quantum intercepts?": "Traditional VPNs using RSA, Diffie-Hellman, ECDH, or ECDSA are not fully post-quantum secure. Organizations should evaluate vendor-supported hybrid or PQC-capable VPN options and test interoperability, performance, and compliance before production migration.",
  "What encryption standards does CNSA 2.0 require?": "NSA CNSA 2.0 defines a transition toward quantum-resistant algorithms for national security systems, including ML-KEM for key establishment and ML-DSA or SLH-DSA for signatures. Exact requirements depend on system type, use case, and implementation timeline.",
  "How do we audit third-party vendor cryptography?": "Audit vendors by requesting cryptographic inventories, certificates, SBOM/CBOM details, TLS configurations, algorithm lists, key-management practices, PQC migration roadmaps, FIPS validation status where required, and evidence of support for NIST-standardized PQC algorithms.",
};

const marqueeRows = [
  [
    "Can we migrate to ML-KEM without downtime?",
    "Are my encryption keys vulnerable to Shor's algorithm?",
    "Where are my legacy RSA and ECC keys located?",
    "How does Harvest Now Decrypt Later affect us?",
  ],
  [
    "Which cipher suites should we deprecate?",
    "What systems have the highest crypto-urgency?",
    "Can we automate TLS certificate rotations?",
    "How do I maintain hybrid cryptographic pipelines?",
  ],
  [
    "Is there a standard ML-DSA parameter set?",
    "Are our VPN tunnels secure against post-quantum intercepts?",
    "What encryption standards does CNSA 2.0 require?",
    "How do we audit third-party vendor cryptography?",
  ],
];

const features = [
  {
    title: "WE SIMPLIFY MIGRATION",
    description: "No complex jargon - just clear, actionable intelligence to transition your infrastructure to post-quantum standards.",
    icon: Shield,
  },
  {
    title: "FOCUS ON RESILIENCE",
    description: "Every strategy is designed to minimize risk, eliminate vulnerabilities, and ensure cryptographic agility.",
    icon: Zap,
  },
  {
    title: "PROVEN FRAMEWORKS",
    description: "With deep expertise in NIST guidelines and NSA directives, we bring proven frameworks to your enterprise.",
    icon: Workflow,
  },
  {
    title: "END-TO-END SECURITY",
    description: "From initial discovery to full hybrid deployment, we provide ongoing telemetry and monitoring.",
    icon: Lock,
  },
];

export function QuantumFeaturesMarquee() {
  const [selectedQuestion, setSelectedQuestion] = useState<string | null>(
    "Can we migrate to ML-KEM without downtime?",
  );

  const handleQuestionClick = (question: string) => {
    setSelectedQuestion((previous) => (previous === question ? null : question));
  };

  return (
    <section
      className="relative overflow-hidden border-b border-slate-900 bg-[#050b14] bg-[radial-gradient(#1e293b_1.2px,transparent_1.2px)] bg-[size:32px_32px] px-6 py-24"
      id="mitigation-roadblocks-section"
    >
      <div className="relative z-10 mx-auto max-w-7xl">
        <div className="mx-auto mb-16 max-w-4xl space-y-3 text-center">
          <div className="inline-block select-none border border-cyan-800 bg-cyan-950/30 px-4 py-1 font-mono text-[9px] font-black uppercase tracking-widest text-cyan-400">
            MITIGATION ROAD BLOCKS
          </div>

          <h2 className="mt-3 font-sans text-2xl font-black uppercase leading-tight tracking-tight text-white sm:text-3xl md:text-4xl">
            REMOVING THE ROADBLOCKS TO{" "}
            <span className="bg-gradient-to-r from-amber-300 via-yellow-400 to-amber-200 bg-clip-text font-black text-transparent drop-shadow-sm">
              POST-QUANTUM READINESS
            </span>
          </h2>

          <p className="mx-auto mt-4 max-w-3xl font-mono text-xs leading-relaxed tracking-wide text-slate-400 sm:text-sm">
            It's easy to get lost in a sea of cryptographic protocols, compliance mandates, and theoretical threats. We filter out the noise, focus on what truly matters, and give you the actionable clarity needed to secure your assets against quantum adversaries.
          </p>
        </div>

        <div className="relative mx-auto max-w-5xl select-none overflow-hidden py-4">
          <div className="pointer-events-none absolute bottom-0 left-0 top-0 z-20 w-24 bg-gradient-to-r from-[#050b14] via-[#050b14]/70 to-transparent" />
          <div className="pointer-events-none absolute bottom-0 right-0 top-0 z-20 w-24 bg-gradient-to-l from-[#050b14] via-[#050b14]/70 to-transparent" />

          <div className="flex flex-col space-y-3.5">
            {marqueeRows.map((row, rowIndex) => {
              const isPaused = row.includes(selectedQuestion || "");

              return (
                <Marquee
                  key={rowIndex}
                  duration={rowIndex === 0 ? "55s" : rowIndex === 1 ? "60s" : "50s"}
                  gap="0.75rem"
                  repeat={3}
                  reverse={rowIndex === 1}
                  pause={isPaused}
                  pauseOnHover
                >
                  {row.map((question) => {
                    const isSelected = selectedQuestion === question;

                    return (
                      <Badge
                        key={question}
                        role="button"
                        tabIndex={0}
                        onClick={() => handleQuestionClick(question)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            handleQuestionClick(question);
                          }
                        }}
                        className={`h-auto cursor-pointer rounded-full border px-4 py-2 font-mono text-[10px] font-bold transition-all whitespace-nowrap md:text-xs ${
                          isSelected
                            ? "scale-105 border-yellow-400/80 bg-yellow-400/10 text-yellow-300 shadow-[0_0_12px_rgba(250,204,21,0.15)]"
                            : rowIndex === 1
                              ? "border-slate-800 bg-slate-900/50 text-[#94a3b8] hover:border-slate-700 hover:bg-slate-900"
                              : "border-slate-800 bg-slate-900/50 text-slate-300 hover:border-slate-700 hover:bg-slate-900"
                        }`}
                        variant="outline"
                      >
                        {question}
                      </Badge>
                    );
                  })}
                </Marquee>
              );
            })}
          </div>
        </div>

        <AnimatePresence mode="wait">
          {selectedQuestion ? (
            <motion.div
              key={selectedQuestion}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.25 }}
              className="relative mx-auto mb-16 mt-8 max-w-4xl rounded-none border-2 border-slate-800 bg-slate-950/90 p-5 text-left font-mono text-xs text-[#f8fafc] shadow-2xl"
              id="roadblock-qa-console"
            >
              <div className="absolute right-4 top-3 flex select-none items-center space-x-2 font-mono text-[9px] font-bold text-[#00c5eb]">
                <Radio className="h-3.5 w-3.5 animate-pulse text-yellow-400" />
                <span>HELIX DECRYPTION LABS // CAROUSEL_PAUSED</span>
              </div>

              <div className="mb-3 flex select-none items-center space-x-2 border-b border-slate-900 pb-3 font-mono text-[10px] font-bold text-slate-400">
                <Terminal className="h-4 w-4 text-[#00c5eb]" />
                <span>LOGID_SEC_AUDIT // RESOLUTION: READY</span>
              </div>

              <div className="space-y-3.5 pt-4 sm:pt-0">
                <div>
                  <span className="mr-2 font-black text-yellow-400">&gt; QUESTION:</span>
                  <span className="select-text text-sm font-extrabold text-white">{selectedQuestion}</span>
                </div>

                <div className="border-l-2 border-[#00c5eb] py-1 pl-4 leading-relaxed text-slate-300">
                  <span className="mb-1 block text-[10px] font-extrabold uppercase tracking-widest text-[#00c5eb]">
                    System Solution Response
                  </span>
                  <p className="select-text text-[13px] font-medium text-slate-200">
                    {roadmapQuestions[selectedQuestion]}
                  </p>
                </div>
              </div>
            </motion.div>
          ) : (
            <motion.div
              key="standby"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.25 }}
              className="relative mx-auto mb-16 mt-8 max-w-4xl rounded-none border-2 border-slate-800 bg-slate-950/90 p-6 text-center font-mono text-xs text-[#f8fafc] shadow-2xl"
              id="roadblock-qa-console-standby"
            >
              <div className="absolute right-4 top-3 flex select-none items-center space-x-2 text-[9px] font-bold text-slate-500">
                <Radio className="h-3.5 w-3.5 animate-pulse text-green-500" />
                <span>HELIX DECRYPTION LABS // COGNITIVE_ACTIVE</span>
              </div>

              <div className="mb-3 flex select-none items-center space-x-2 border-b border-slate-900 pb-3 text-[10px] font-bold text-slate-500">
                <Terminal className="h-4 w-4 text-green-500" />
                <span>LOGID_SEC_AUDIT // RESOLUTION: MONITORING</span>
              </div>

              <div className="flex flex-col items-center justify-center space-y-2 py-6">
                <span className="block animate-pulse text-sm font-bold uppercase tracking-widest text-amber-400">
                  &gt;&gt; MONITOR ACTIVE &lt;&lt;
                </span>
                <p className="mx-auto max-w-md text-[12px] font-semibold text-slate-400">
                  Click any of the moving cryptographic conundrum queries above to freeze its carousel and decrypt the post-quantum resolution details.
                </p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        <div className="mx-auto my-16 max-w-6xl border-t border-dashed border-slate-900" />

        <div className="grid grid-cols-1 items-stretch gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {features.map((item, idx) => {
            const Icon = item.icon;

            return (
              <div
                key={item.title}
                className="group relative flex flex-col overflow-hidden border border-slate-800 bg-slate-950/40 p-6 text-left backdrop-blur-md transition-all duration-300 hover:border-[#1e293b] hover:shadow-[0_0_20px_rgba(14,165,233,0.05)]"
                id={`roadblock-card-${idx}`}
              >
                <div className="absolute inset-x-0 top-0 h-[1.5px] bg-[#00c5eb] opacity-0 transition-opacity duration-300 group-hover:opacity-100" />

                <div className="mb-6 flex h-12 w-12 shrink-0 items-center justify-center rounded-full border border-amber-500/30 bg-amber-500/5 text-amber-400 shadow-inner transition-all duration-300 group-hover:scale-105 group-hover:bg-amber-500/10">
                  <Icon className="h-5 w-5" />
                </div>

                <h3 className="mb-2 select-none font-sans text-xs font-black uppercase tracking-widest text-white">
                  {item.title}
                </h3>

                <p className="mb-2 text-[11px] font-semibold leading-relaxed text-slate-400">
                  {item.description}
                </p>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
