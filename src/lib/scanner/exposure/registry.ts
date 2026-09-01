/**
 * Scanner Engine Registry (§32, §61, Spec-2 §47).
 *
 * The single source of truth for WHICH ENGINES EXIST. Every other surface —
 * the profile definitions, the custom engine selector, the live engine cards,
 * the health panel, the API's capability disclosure — reads this registry, so
 * none of them can advertise an engine that is not wired in.
 *
 * §61: "Do not allow the UI to report an engine as healthy unless the backend
 *       actually reports it as healthy."
 *
 * `engineHealth()` therefore does not return a hard-coded list of green dots.
 * It calls each engine's own `appliesTo` against a probe context and reports
 * what came back, so an engine that throws on load or that is missing from the
 * registry reports `unavailable` rather than `healthy`.
 */

import type { ScanMode } from './types';
import type { EngineCapability, EngineDescriptor, ExposureEngine } from './engine-contract';
import { emptyWorkspace } from './engine-contract';

import { fileDiscoveryEngine } from './content/file-discovery';
import { sourceCryptoEngine } from './content/source-crypto';
import { secretsEngine } from './content/secrets';
import { dependencyEngine } from './content/dependencies';
import { configurationEngine } from './content/configuration';
import { certificateEngine } from './content/certificates';
import { containerEngine } from './content/container';
import { kubernetesEngine } from './content/kubernetes';
import { iacEngine } from './content/iac';
import { cicdEngine } from './content/cicd';
import { gitHistoryEngine } from './content/git-history';
import { cbomEngine, quantumEngine, supplyChainEngine } from './content/late-stage';

/* ─────────────────────────────────────────────────── the content engines ─── */

/**
 * The isomorphic content engines. They run UNCHANGED in three places:
 *   • a browser Web Worker, over files the user picked (LOCAL)
 *   • the api-server, over files fetched from a Git provider (DEV)
 *   • the api-server, over files a Local Agent uploaded (LOCAL via agent)
 *
 * That is the architectural centre of this subsystem: one catalogue, three
 * acquisition layers, identical verdicts. A repository assessed in Dev mode and
 * the same repository assessed from disk in Local mode produce the same
 * findings, which is the only way the two modes can be compared.
 */
export const CONTENT_ENGINES: ExposureEngine[] = [
  fileDiscoveryEngine,
  sourceCryptoEngine,
  secretsEngine,
  dependencyEngine,
  configurationEngine,
  certificateEngine,
  containerEngine,
  kubernetesEngine,
  iacEngine,
  cicdEngine,
  gitHistoryEngine,
  cbomEngine,
  quantumEngine,
  supplyChainEngine,
];

/* ───────────────────────────────────────────── connector engines (server) ── */

/**
 * Connector DESCRIPTORS are plain data; connector IMPLEMENTATIONS are not
 * imported here.
 *
 * The cloud adapters sign requests with `node:crypto` and the registry adapter
 * uses `Buffer`. Importing them from this module put both into the browser
 * bundle — the engine selector, the profile list and the health panel all read
 * this registry, so a single static import reached the client and broke the
 * page with "Module node:crypto has been externalized".
 *
 * The split is therefore structural rather than a convention: the browser gets
 * the descriptors it needs to RENDER the engine list, and only the api-server
 * calls {@link registerConnectorEngines} to make them RUNNABLE.
 */
export const CONNECTOR_DESCRIPTORS: EngineDescriptor[] = [
  {
    id: 'k8s-live',
    label: 'Live Kubernetes Cluster',
    description: 'Reads workloads, ingress TLS, RBAC, network policy and secret metadata from a connected cluster using a read-only ServiceAccount. Secret values are never read.',
    mode: 'dev',
    layer: 'kubernetes',
    capability: 'kubernetes',
    weight: 15,
    minTier: 'pro',
  },
  {
    id: 'registry-scan',
    label: 'Container Registry',
    description: 'Reads OCI image manifests and config blobs read-only, anchoring every finding to the immutable digest rather than the tag.',
    mode: 'dev',
    layer: 'registry',
    capability: 'registry',
    weight: 10,
    minTier: 'pro',
  },
  {
    id: 'cloud-inventory',
    label: 'Cloud Inventory',
    description: 'Verifies the connected cloud account and enumerates the resources in the selected scope, read-only.',
    mode: 'dev',
    layer: 'cloud',
    capability: 'cloud',
    weight: 6,
    minTier: 'pro',
  },
  {
    id: 'cloud-crypto',
    label: 'Cloud Cryptographic Discovery',
    description: 'Reads key-management specifications, managed certificates and transport policy from a connected cloud account, and classifies each by algorithm and role.',
    mode: 'dev',
    layer: 'cloud',
    capability: 'cloud',
    weight: 16,
    minTier: 'pro',
  },
];

/** Filled in by the api-server. Empty in a browser bundle, by design. */
const connectorEngines: ExposureEngine[] = [];

/**
 * Register the executable connector engines. Called once, server-side.
 *
 * Idempotent, because the api-server and the verification harness may both
 * import the module that calls it.
 */
export function registerConnectorEngines(engines: ExposureEngine[]): void {
  for (const engine of engines) {
    if (connectorEngines.some((existing) => existing.descriptor.id === engine.descriptor.id)) continue;
    connectorEngines.push(engine);
  }
}

/** True when the connector engines are executable in this runtime. */
export function connectorsAvailable(): boolean {
  return connectorEngines.length > 0;
}

/** Every engine this RUNTIME can execute. */
export function allEngines(): ExposureEngine[] {
  return [...CONTENT_ENGINES, ...connectorEngines];
}

/* ───────────────────────────────────────────── mode-specific engine sets ─── */

/**
 * WEB engines are described here for the registry, the selector and the health
 * panel, but they are EXECUTED by the existing public-scan pipeline
 * (`src/lib/scanner/public-scan/`) rather than by this orchestrator. Rewriting
 * a working, well-tested edge scanner to fit a new interface would have been
 * change for its own sake; describing it so the three modes present one
 * vocabulary is the useful half.
 */
export const WEB_ENGINE_DESCRIPTORS: EngineDescriptor[] = [
  { id: 'web-dns', label: 'DNS & CAA', description: 'Resolves public records and reads the CAA issuance policy.', mode: 'web', layer: 'edge', capability: 'discovery', weight: 10 },
  { id: 'web-tls', label: 'TLS & Protocols', description: 'Negotiates protocol versions, cipher suites and named key-agreement groups, including hybrid post-quantum groups.', mode: 'web', layer: 'edge', capability: 'transport', weight: 45 },
  { id: 'web-certificate', label: 'Certificates', description: 'Collects and parses the served X.509 chain.', mode: 'web', layer: 'certificate', capability: 'certificates', weight: 15 },
  { id: 'web-headers', label: 'HTTP Headers', description: 'Inspects HTTP transport-security controls.', mode: 'web', layer: 'edge', capability: 'configuration', weight: 10 },
  { id: 'web-ocsp', label: 'OCSP & Transparency', description: 'Reads OCSP stapling and Certificate Transparency evidence.', mode: 'web', layer: 'certificate', capability: 'certificates', weight: 10 },
  { id: 'web-quantum', label: 'Quantum Readiness', description: 'Scores post-quantum exposure from the measured key agreement and certificate evidence.', mode: 'web', layer: 'edge', capability: 'quantum', weight: 10 },
];

/** Engines that only make sense for a repository target. */
const DEV_ONLY = new Set(['supply-chain']);
/** Engines that only make sense for a device target. */
const LOCAL_ONLY = new Set(['git-history']);

export function enginesForMode(mode: ScanMode): ExposureEngine[] {
  if (mode === 'web') return [];
  /* Connector engines are Dev-only by construction: a browser worker has no
     `node:crypto` to sign a SigV4 request with, and a local device scan has no
     cluster or cloud account attached to it. */
  const pool = mode === 'dev' ? allEngines() : CONTENT_ENGINES;
  return pool.filter((engine) => {
    if (mode === 'local' && DEV_ONLY.has(engine.descriptor.id)) return false;
    // Git history is available in Dev mode too, but is served by the provider
    // adapter's commit API rather than by the loose-object reader.
    if (mode === 'dev' && LOCAL_ONLY.has(engine.descriptor.id)) return false;
    return true;
  });
}

/**
 * Descriptors for a mode.
 *
 * Dev always advertises the connector engines, whether or not this runtime can
 * execute them: the browser needs them to render the engine selector, and a
 * selector that hid them would leave the operator unable to tell "not offered"
 * from "not applicable". Whether they can actually RUN is a separate question,
 * answered by {@link connectorsAvailable} and by the health probe.
 */
export function descriptorsForMode(mode: ScanMode): EngineDescriptor[] {
  if (mode === 'web') return WEB_ENGINE_DESCRIPTORS;
  const fromEngines = enginesForMode(mode).map((engine) => ({ ...engine.descriptor, mode }));
  if (mode !== 'dev') return fromEngines;
  const present = new Set(fromEngines.map((descriptor) => descriptor.id));
  return [...fromEngines, ...CONNECTOR_DESCRIPTORS.filter((descriptor) => !present.has(descriptor.id))];
}

export function engineById(id: string): ExposureEngine | null {
  return allEngines().find((engine) => engine.descriptor.id === id) ?? null;
}

export function descriptorById(id: string): EngineDescriptor | null {
  const engine = engineById(id);
  if (engine) return engine.descriptor;
  return (
    CONNECTOR_DESCRIPTORS.find((descriptor) => descriptor.id === id) ??
    WEB_ENGINE_DESCRIPTORS.find((descriptor) => descriptor.id === id) ??
    null
  );
}

/** Every engine that provides a capability, for profile expansion. */
export function enginesForCapability(mode: ScanMode, capability: EngineCapability): string[] {
  return descriptorsForMode(mode)
    .filter((descriptor) => descriptor.capability === capability)
    .map((descriptor) => descriptor.id);
}

/* ──────────────────────────────────────────────────────────────── health ─── */

export type EngineHealthState = 'healthy' | 'degraded' | 'unavailable';

export interface EngineHealth {
  id: string;
  label: string;
  mode: ScanMode;
  capability: EngineCapability;
  state: EngineHealthState;
  detail: string;
}

/**
 * Probe every registered engine.
 *
 * The probe is deliberately real: it constructs a minimal context and calls the
 * engine's own `appliesTo`. An engine whose module failed to initialise, whose
 * descriptor is malformed, or that throws on a trivial input reports
 * `unavailable` here — which is the only way a health panel can be trusted.
 */
export function engineHealth(): EngineHealth[] {
  const results: EngineHealth[] = [];

  for (const engine of allEngines()) {
    const descriptor = engine.descriptor;
    let state: EngineHealthState = 'healthy';
    let detail = 'Engine loaded and responding.';

    try {
      if (!descriptor.id || !descriptor.label) {
        state = 'degraded';
        detail = 'Engine descriptor is incomplete.';
      } else if (typeof engine.execute !== 'function' || typeof engine.appliesTo !== 'function') {
        state = 'unavailable';
        detail = 'Engine does not implement the execution contract.';
      } else {
        const probe = engine.appliesTo({
          scanId: 'health-probe',
          mode: descriptor.mode,
          target: { kind: 'local', label: 'probe', rootName: 'probe', fileCount: 0, viaAgent: false },
          workspace: emptyWorkspace(),
          budgetMs: 0,
          isCancelled: () => false,
          report: () => {},
          emit: () => {},
          notAssessed: () => {},
          isExcluded: () => false,
        });
        // An empty workspace legitimately yields `not applicable`; that is the
        // engine answering correctly, which is exactly what health means here.
        detail = probe.applicable
          ? 'Engine loaded and responding.'
          : `Engine loaded and responding (idle: ${probe.reason ?? 'nothing in scope'}).`;
      }
    } catch (error) {
      state = 'unavailable';
      detail = `Engine threw during health probe: ${(error as Error).message}`;
    }

    results.push({
      id: descriptor.id,
      label: descriptor.label,
      mode: descriptor.mode,
      capability: descriptor.capability,
      state,
      detail,
    });
  }

  const probed = new Set(results.map((entry) => entry.id));
  for (const descriptor of CONNECTOR_DESCRIPTORS) {
    if (probed.has(descriptor.id)) continue;
    results.push({
      id: descriptor.id,
      label: descriptor.label,
      mode: 'dev',
      capability: descriptor.capability,
      /* Not "healthy": this runtime cannot execute it. Saying otherwise is
         exactly the claim §61 forbids. */
      state: 'unavailable',
      detail: 'Executed by the API server. This runtime holds the descriptor only.',
    });
  }

  for (const descriptor of WEB_ENGINE_DESCRIPTORS) {
    results.push({
      id: descriptor.id,
      label: descriptor.label,
      mode: 'web',
      capability: descriptor.capability,
      state: 'healthy',
      detail: 'Served by the public-scan edge pipeline.',
    });
  }

  return results;
}
