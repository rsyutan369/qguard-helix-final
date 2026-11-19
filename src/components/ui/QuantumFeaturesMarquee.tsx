import { useState, type CSSProperties } from "react";
import { Lock, Shield, Workflow, Zap } from "lucide-react";

import { Chars } from "@/pages/landing-chars";

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
  "What encryption standards does CNSA 2.0 require?": "NSA CNSA 2.0 applies to national security systems and specifies the highest parameter sets only: ML-KEM-1024 for key establishment, ML-DSA-87 for signatures, AES-256 for symmetric encryption, and SHA-384 or SHA-512 for hashing. LMS and XMSS (NIST SP 800-208) are specified for software and firmware signing. SLH-DSA is a NIST standard but is not part of CNSA 2.0. Adoption timelines vary by system type.",
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
    title: "We Simplify Migration",
    description: "No complex jargon - just clear, actionable intelligence to transition your infrastructure to post-quantum standards.",
    icon: Shield,
  },
  {
    title: "Focus on Resilience",
    description: "Every strategy is designed to reduce cryptographic exposure, sequence remediation by risk, and leave you able to change algorithms again.",
    icon: Zap,
  },
  {
    title: "Published Frameworks",
    description: "Use NIST FIPS 203, 204 and 205 for algorithm selection, final NIST IR 8547 for transition planning and NCCoE guidance for discovery and interoperability testing.",
    icon: Workflow,
  },
  {
    title: "End-to-End Security",
    description: "From initial discovery to full hybrid deployment, we provide ongoing telemetry and monitoring.",
    icon: Lock,
  },
];

const ROW_DURATIONS = ["55s", "60s", "50s"];
/** Each row is rendered this many times so the loop never shows a gap. */
const ROW_COPIES = [0, 1, 2];

/**
 * Homepage section. Styled by src/pages/landing.css (the .lp-* classes), so it
 * must render inside the homepage root.
 */
export function QuantumFeaturesMarquee() {
  const [selectedQuestion, setSelectedQuestion] = useState<string | null>(null);

  const handleQuestionClick = (question: string) => {
    setSelectedQuestion((previous) => (previous === question ? null : question));
  };

  return (
    <section className="lp-section lp-band" id="mitigation-roadblocks-section">
      <div className="lp-wrap">
        <div className="lp-head">
          <p className="lp-eyebrow">Mitigation Road Blocks</p>
          <h2 className="lp-h2" data-letters="scroll" aria-label="Removing the Roadblocks to Post-Quantum Readiness">
            <Chars text="Removing the Roadblocks to Post-Quantum Readiness" />
          </h2>
          <p className="lp-lede">
            It's easy to get lost in a sea of cryptographic protocols, compliance mandates, and theoretical threats. We filter out the noise, focus on what truly matters, and give you the actionable clarity needed to secure your assets against quantum adversaries.
          </p>
        </div>

        <div className="lp-qa__rows">
          {marqueeRows.map((row, rowIndex) => (
            <div
              key={row[0]}
              className="lp-qa__row"
              data-reverse={rowIndex === 1 ? "" : undefined}
              data-paused={selectedQuestion !== null && row.includes(selectedQuestion) ? "" : undefined}
              style={{ "--lp-qa-duration": ROW_DURATIONS[rowIndex] } as CSSProperties}
            >
              {ROW_COPIES.map((copy) => (
                <div key={copy} className="lp-qa__track" aria-hidden={copy > 0 ? true : undefined}>
                  {row.map((question) => (
                    <button
                      key={question}
                      type="button"
                      tabIndex={copy > 0 ? -1 : undefined}
                      aria-pressed={selectedQuestion === question}
                      aria-controls="roadblock-qa-console"
                      onClick={() => handleQuestionClick(question)}
                      className="lp-qa__q"
                    >
                      {question}
                    </button>
                  ))}
                </div>
              ))}
            </div>
          ))}
        </div>

        <div className="lp-qa__console lp-dark" id="roadblock-qa-console" aria-live="polite">
          <div className="lp-console__bar">
            <span>LOGID_SEC_AUDIT // RESOLUTION: {selectedQuestion ? "READY" : "MONITORING"}</span>
            <span>HELIX DECRYPTION LABS // {selectedQuestion ? "CAROUSEL_PAUSED" : "COGNITIVE_ACTIVE"}</span>
          </div>

          {selectedQuestion ? (
            <div key={selectedQuestion} className="lp-qa__body">
              <span className="lp-label">Question</span>
              <h3>{selectedQuestion}</h3>
              <span className="lp-label">System Solution Response</span>
              <p>{roadmapQuestions[selectedQuestion]}</p>
            </div>
          ) : (
            <div key="standby" className="lp-qa__body">
              <span className="lp-label">Monitor Active</span>
              <p>
                Click any of the moving cryptographic conundrum queries above to freeze its carousel and decrypt the post-quantum resolution details.
              </p>
            </div>
          )}
        </div>

        <div className="lp-points">
          {features.map((item, idx) => {
            const Icon = item.icon;

            return (
              <div key={item.title} id={`roadblock-card-${idx}`}>
                <Icon className="lp-icon" aria-hidden="true" />
                <h3>{item.title}</h3>
                <p>{item.description}</p>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
