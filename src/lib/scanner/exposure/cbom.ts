/**
 * CBOM Discovery Engine™ (§11, Spec-2 §23, §25).
 *
 * Turns the findings every content engine produced into a Cryptographic Bill of
 * Materials: one row per (algorithm, role, location) cryptographic component,
 * with the evidence that proves it and the dependency edges that connect it to
 * the package, container, workload and cloud service it lives in.
 *
 * THE COMPONENT / FINDING DISTINCTION, which this platform has been bitten by
 * before: a FINDING is something wrong; a COMPONENT is something present. Twenty
 * call sites of RSA-2048 in one file are twenty findings and ONE component. A
 * "No Certificate Pinning" finding is a finding and NOT a component at all — it
 * names a missing control, not a cryptographic primitive. Mixing the two
 * inflates the CBOM headline and both sides of the quantum-vulnerable ratio.
 *
 * §11 also says: "Do not falsely claim complete CycloneDX compatibility unless
 * implemented and validated." The export below is CycloneDX-SHAPED — it uses
 * the 1.6 cryptographic-asset vocabulary and validates against nothing. It says
 * so, in the document itself.
 */

import type {
  CbomComponent,
  CryptoRole,
  ExposureFinding,
  FindingConfidence,
  QuantumStatus,
} from './types';
import { stableHash } from './types';
import { canonicalAlgorithmName, describeAlgorithm } from './algorithms';
import { postQuantumReadiness } from './exposure-truth';

/* ─────────────────────────────────────────────── component qualification ── */

/**
 * Is this finding about a cryptographic COMPONENT, or about a control?
 *
 * A component must name a primitive the algorithm catalogue recognises. That
 * single test excludes "No Certificate Pinning", "Container runs as root" and
 * "Debug mode enabled" — all real findings, none of them cryptography.
 */
export function isCryptographicComponent(finding: ExposureFinding): boolean {
  if (!finding.algorithm && !finding.canonicalAlgorithm) return false;
  const entry = describeAlgorithm(finding.canonicalAlgorithm ?? finding.algorithm);
  if (!entry) return false;
  // A protocol on its own is a component only when it carries a concrete
  // primitive; "TLS is configured" is a fact about transport, not an algorithm
  // inventory row.
  if (entry.family === 'protocol' && finding.layer !== 'edge' && finding.layer !== 'certificate') return false;
  return true;
}

/* ─────────────────────────────────────────────────────────── construction ── */

const CONFIDENCE_RANK: Record<FindingConfidence, number> = { high: 3, medium: 2, low: 1, unknown: 0 };

const QUANTUM_RANK: Record<QuantumStatus, number> = {
  vulnerable: 5,
  hybrid: 4,
  pqc: 3,
  resistant: 2,
  unknown: 1,
  'not-applicable': 0,
};

/**
 * The component identity.
 *
 * (canonical algorithm, role, location) — deliberately NOT including the
 * engine or the rule, because the same component discovered by the source
 * engine and by the dependency engine is ONE component with two evidence
 * sources, which is exactly what §39 asks for.
 */
function componentKey(finding: ExposureFinding): string {
  const algorithm = canonicalAlgorithmName(finding.canonicalAlgorithm ?? finding.algorithm);
  const location = finding.evidence[0]?.file ?? finding.evidence[0]?.reference ?? finding.layer;
  return `${algorithm}|${finding.role ?? 'unknown'}|${location}`;
}

export function buildCbom(findings: ExposureFinding[]): CbomComponent[] {
  const byKey = new Map<string, CbomComponent>();

  for (const finding of findings) {
    if (!isCryptographicComponent(finding)) continue;

    const key = componentKey(finding);
    const algorithm = canonicalAlgorithmName(finding.canonicalAlgorithm ?? finding.algorithm);
    const evidence = finding.evidence[0];
    const existing = byKey.get(key);

    if (existing) {
      // Merge: take the strongest confidence, the most specific quantum verdict
      // and the union of evidence.
      if (CONFIDENCE_RANK[finding.confidence] > CONFIDENCE_RANK[existing.confidence]) {
        existing.confidence = finding.confidence;
        existing.detection = finding.detection;
      }
      if (QUANTUM_RANK[finding.quantumStatus] > QUANTUM_RANK[existing.quantumStatus]) {
        existing.quantumStatus = finding.quantumStatus;
      }
      existing.keySize = existing.keySize ?? finding.keySize ?? null;
      existing.library = existing.library ?? finding.library;
      existing.package = existing.package ?? finding.component;
      existing.version = existing.version ?? finding.version;
      existing.protocol = existing.protocol ?? finding.protocol;
      existing.cipherMode = existing.cipherMode ?? finding.mode_;
      for (const item of finding.evidence) {
        const duplicate = existing.evidence.some(
          (candidate) => candidate.file === item.file && candidate.line === item.line && candidate.ruleId === item.ruleId,
        );
        if (!duplicate) existing.evidence.push(item);
      }
      continue;
    }

    byKey.set(key, {
      id: `cbom-${stableHash(key)}`,
      package: finding.component,
      library: finding.library,
      version: finding.version,
      language: typeof evidence?.attributes?.language === 'string' ? evidence.attributes.language : undefined,
      file: evidence?.file,
      line: evidence?.line,
      algorithm: finding.algorithm ?? algorithm,
      canonicalAlgorithm: algorithm,
      keySize: finding.keySize ?? null,
      cipherMode: finding.mode_,
      protocol: finding.protocol,
      usage: (finding.role ?? 'unknown') as CryptoRole,
      provider: evidence?.provider,
      confidence: finding.confidence,
      detection: finding.detection,
      quantumStatus: finding.quantumStatus,
      layer: finding.layer,
      evidence: [...finding.evidence],
    });
  }

  /* ── dependency edges (Spec-2 §25) ──────────────────────────────────── */
  const components = [...byKey.values()];
  const byLayer = new Map<string, CbomComponent[]>();
  for (const component of components) {
    const list = byLayer.get(component.layer) ?? [];
    list.push(component);
    byLayer.set(component.layer, list);
  }

  /* A source component that names the same algorithm as a dependency component
     depends on it: `src/auth.ts uses RSA` → `jsonwebtoken brings RSA`. Only
     that relationship is asserted, because it is the only one the evidence
     actually supports. */
  for (const source of byLayer.get('source') ?? []) {
    const suppliers = (byLayer.get('dependency') ?? []).filter(
      (candidate) => candidate.canonicalAlgorithm === source.canonicalAlgorithm,
    );
    if (suppliers.length) source.dependsOn = suppliers.map((supplier) => supplier.id);
  }

  /* A container component supplying the same algorithm is what the dependency
     ultimately links against. */
  for (const dependency of byLayer.get('dependency') ?? []) {
    const containers = (byLayer.get('container') ?? []).filter(
      (candidate) => candidate.canonicalAlgorithm === dependency.canonicalAlgorithm,
    );
    if (containers.length) dependency.dependsOn = containers.map((container) => container.id);
  }

  return components.sort((a, b) => {
    const rank = QUANTUM_RANK[b.quantumStatus] - QUANTUM_RANK[a.quantumStatus];
    if (rank !== 0) return rank;
    return a.canonicalAlgorithm.localeCompare(b.canonicalAlgorithm);
  });
}

/* ───────────────────────────────────────────────────────────────── export ── */

/** Machine-readable CBOM in the platform's own JSON shape. */
export function cbomToJson(components: CbomComponent[], meta: { scanId: string; target: string; generatedAt: string }): string {
  return JSON.stringify(
    {
      schema: 'qguard-helix.cbom/1',
      scanId: meta.scanId,
      target: meta.target,
      generatedAt: meta.generatedAt,
      componentCount: components.length,
      components,
    },
    null,
    2,
  );
}

/** Flat CSV, one row per component. */
export function cbomToCsv(components: CbomComponent[]): string {
  const escape = (value: unknown) => `"${String(value ?? '').replace(/"/g, '""')}"`;
  const header = [
    'Component ID', 'Algorithm', 'Canonical Algorithm', 'Key Size', 'Mode', 'Protocol',
    'Usage', 'Library', 'Package', 'Version', 'Language', 'File', 'Line',
    'Layer', 'Provider', 'Detection', 'Confidence', 'Quantum Status', 'Evidence',
  ];
  const rows = components.map((component) =>
    [
      component.id,
      component.algorithm,
      component.canonicalAlgorithm,
      component.keySize ?? '',
      component.cipherMode ?? '',
      component.protocol ?? '',
      component.usage,
      component.library ?? '',
      component.package ?? '',
      component.version ?? '',
      component.language ?? '',
      component.file ?? '',
      component.line ?? '',
      component.layer,
      component.provider ?? '',
      component.detection,
      component.confidence,
      component.quantumStatus,
      component.evidence[0]?.summary ?? '',
    ]
      .map(escape)
      .join(','),
  );
  return [header.join(','), ...rows].join('\n');
}

/**
 * CycloneDX-SHAPED export.
 *
 * Uses the CycloneDX 1.6 `cryptographic-asset` component type and the
 * `cryptoProperties` vocabulary. It is NOT validated against the CycloneDX
 * schema by this platform, and the document says so in its own metadata — which
 * is the difference between interoperability and a claim of it.
 */
export function cbomToCycloneDx(
  components: CbomComponent[],
  meta: { scanId: string; target: string; generatedAt: string },
): string {
  const primitiveOf = (component: CbomComponent): string => {
    const entry = describeAlgorithm(component.canonicalAlgorithm);
    if (!entry) return 'unknown';
    switch (entry.family) {
      case 'rsa':
      case 'ecc':
      case 'dsa':
      case 'falcon':
      case 'ml-dsa':
      case 'slh-dsa':
        return 'signature';
      case 'ml-kem':
      case 'dh':
        return 'kem';
      case 'aes':
      case 'chacha':
      case 'legacy-symmetric':
        return 'block-cipher';
      case 'sha2':
      case 'sha3':
      case 'legacy-hash':
        return 'hash';
      case 'mac':
        return 'mac';
      case 'kdf':
      case 'password-hash':
        return 'key-derive';
      default:
        return 'other';
    }
  };

  const document = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
      timestamp: meta.generatedAt,
      tools: [{ vendor: 'QGuard Helix', name: 'Exposure Assessment Engine', version: '1.0.0' }],
      component: { type: 'application', name: meta.target, 'bom-ref': meta.scanId },
      properties: [
        {
          name: 'qguard:compatibility-notice',
          value:
            'This document uses the CycloneDX 1.6 cryptographic-asset vocabulary. It has NOT been validated against the CycloneDX JSON schema by QGuard Helix, and full CycloneDX compatibility is not claimed.',
        },
        { name: 'qguard:scan-id', value: meta.scanId },
      ],
    },
    components: components.map((component) => ({
      type: 'cryptographic-asset',
      'bom-ref': component.id,
      name: component.canonicalAlgorithm,
      version: component.version,
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: primitiveOf(component),
          parameterSetIdentifier: component.keySize ? String(component.keySize) : undefined,
          mode: component.cipherMode,
          cryptoFunctions: [component.usage],
          classicalSecurityLevel: component.keySize ?? undefined,
          nistQuantumSecurityLevel:
            component.quantumStatus === 'pqc' || component.quantumStatus === 'hybrid' ? 3 : 0,
        },
        oid: undefined,
      },
      evidence: {
        occurrences: component.evidence
          .filter((item) => item.file)
          .map((item) => ({ location: item.file, line: item.line })),
      },
      properties: [
        { name: 'qguard:quantum-status', value: component.quantumStatus },
        { name: 'qguard:detection-method', value: component.detection },
        { name: 'qguard:confidence', value: component.confidence },
        { name: 'qguard:layer', value: component.layer },
        ...(component.library ? [{ name: 'qguard:library', value: component.library }] : []),
        ...(component.provider ? [{ name: 'qguard:provider', value: component.provider }] : []),
      ],
    })),
    dependencies: components
      .filter((component) => component.dependsOn?.length)
      .map((component) => ({ ref: component.id, dependsOn: component.dependsOn })),
  };

  return JSON.stringify(document, null, 2);
}

/* ───────────────────────────────────────────────────────────── statistics ── */

export interface CbomSummary {
  total: number;
  vulnerable: number;
  hybrid: number;
  pqc: number;
  resistant: number;
  unknown: number;
  notApplicable: number;
  /**
   * Post-quantum readiness across the QUANTUM-RELEVANT components only.
   *
   * Null when no quantum-relevant component was observed — which is the honest
   * answer for a repository with no asymmetric cryptography, and is emphatically
   * not 100%.
   */
  readiness: number | null;
  /**
   * Components whose primitive is broken by CLASSICAL cryptanalysis — MD5,
   * SHA-1, RC4, DES, Blowfish and friends.
   *
   * These live in the `resistant` bucket, because `resistant` is a statement
   * about Shor's algorithm and nothing else. That is a correct quantum verdict
   * and a dangerous headline on its own: a reader sees "Resistant 230" in cyan
   * and concludes 230 components are fine. This count is what lets every panel
   * qualify that cell instead of implying an all-clear the evidence contradicts.
   */
  classicallyWeak: number;
  byAlgorithm: Array<{
    algorithm: string;
    count: number;
    /**
     * The status MOST of this algorithm's components carry — not the status of
     * whichever component happened to be enumerated first, which is what this
     * used to publish. One ML-KEM component sitting in an X25519+ML-KEM hybrid
     * made all 90 ML-KEM components read `hybrid`, directly beneath a cell
     * reporting 23 hybrid components in total.
     */
    quantumStatus: QuantumStatus;
    /** Every status present in the group, largest first. Length > 1 = mixed. */
    mix: Array<{ status: QuantumStatus; count: number }>;
    /** Components in this group broken by classical cryptanalysis. */
    classicallyWeak: number;
  }>;
  byUsage: Array<{ usage: CryptoRole; count: number }>;
  byLayer: Array<{ layer: string; count: number }>;
}

export function summariseCbom(components: CbomComponent[]): CbomSummary {
  const counts = { vulnerable: 0, hybrid: 0, pqc: 0, resistant: 0, unknown: 0, notApplicable: 0 };
  const byAlgorithm = new Map<string, { count: number; classicallyWeak: number; statuses: Map<QuantumStatus, number> }>();
  const byUsage = new Map<CryptoRole, number>();
  const byLayer = new Map<string, number>();
  let classicallyWeak = 0;

  for (const component of components) {
    switch (component.quantumStatus) {
      case 'vulnerable': counts.vulnerable += 1; break;
      case 'hybrid': counts.hybrid += 1; break;
      case 'pqc': counts.pqc += 1; break;
      case 'resistant': counts.resistant += 1; break;
      case 'not-applicable': counts.notApplicable += 1; break;
      default: counts.unknown += 1; break;
    }

    /* The knowledge base already knows MD5 and RC4 are broken; nothing read the
       flag, so the verdict never reached a panel. */
    const weak = describeAlgorithm(component.canonicalAlgorithm)?.classicallyWeak === true;
    if (weak) classicallyWeak += 1;

    let algorithmEntry = byAlgorithm.get(component.canonicalAlgorithm);
    if (!algorithmEntry) {
      algorithmEntry = { count: 0, classicallyWeak: 0, statuses: new Map() };
      byAlgorithm.set(component.canonicalAlgorithm, algorithmEntry);
    }
    algorithmEntry.count += 1;
    if (weak) algorithmEntry.classicallyWeak += 1;
    algorithmEntry.statuses.set(
      component.quantumStatus,
      (algorithmEntry.statuses.get(component.quantumStatus) ?? 0) + 1,
    );

    byUsage.set(component.usage, (byUsage.get(component.usage) ?? 0) + 1);
    byLayer.set(component.layer, (byLayer.get(component.layer) ?? 0) + 1);
  }

  /* The denominator is the quantum-relevant population: vulnerable + hybrid +
     pqc. Symmetric and hash components are excluded on both sides, because
     including them lets an estate full of AES-256 report high readiness while
     every one of its signatures is RSA — the exact error §16 forbids.

     The formula lives in `postQuantumReadiness` so this panel and the
     reconciler behind every other panel cannot publish different percentages
     for one scan, which they did: 31% here against 48% from the reconciler. */
  const readiness = postQuantumReadiness(counts);

  return {
    total: components.length,
    ...counts,
    readiness,
    classicallyWeak,
    byAlgorithm: [...byAlgorithm.entries()]
      .map(([algorithm, entry]) => {
        /* Dominant status, with the WORSE verdict winning a tie. A group split
           evenly between vulnerable and pqc is reported vulnerable: understating
           exposure on a coin-flip is the one failure mode worth ruling out. */
        const mix = [...entry.statuses.entries()]
          .map(([status, count]) => ({ status, count }))
          .sort((a, b) => b.count - a.count || QUANTUM_RANK[b.status] - QUANTUM_RANK[a.status]);
        return {
          algorithm,
          count: entry.count,
          quantumStatus: mix[0]?.status ?? 'unknown',
          mix,
          classicallyWeak: entry.classicallyWeak,
        };
      })
      .sort((a, b) => b.count - a.count),
    byUsage: [...byUsage.entries()].map(([usage, count]) => ({ usage, count })).sort((a, b) => b.count - a.count),
    byLayer: [...byLayer.entries()].map(([layer, count]) => ({ layer, count })).sort((a, b) => b.count - a.count),
  };
}
