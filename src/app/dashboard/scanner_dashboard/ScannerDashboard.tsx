/**
 * Dashboard Scanner — /dashboard/scanner
 *
 * The authenticated enterprise edition of the Public Quantum Exposure
 * Assessment. It renders in the same design language as /public-scan — the same
 * Quantum Visualization Engine™ hero, the same glass panels, gauge, rings,
 * meters and reveal motion — while running the platform's real scanner against
 * the tenant's authorized estate.
 *
 * Composition:
 *   _types.ts      shared domain vocabulary (mirrors the SSE payloads)
 *   _intel.ts      pure derivations: real evidence → assessment model
 *   _qve-bridge.ts real scan events → visualization events
 *   _hero.tsx      the QVE hero, mounted with the estate-discovery node ring
 *   _sections.tsx  the result panels
 *
 * DATA CONTRACT: every number on this page traces to a measurement the scanner
 * made — the SSE summary, per-target results, the Scanner_2 enterprise pass,
 * module execution state, or the tenant-wide Scanner Intelligence snapshot that
 * also feeds Assets, CBOM, Exposure and Quantum Readiness. Nothing is
 * placeholder, and anything unmeasured renders as Unknown rather than zero.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useSearchParams, Link } from 'react-router-dom';
import { useSubscription } from '@/hooks/use-subscription';
import { tierMeets } from '@/lib/subscription-access';
import { isOwnerEmail } from '@/lib/admin-access';
import {
  AlertTriangle, Calendar, CheckCircle2, ChevronRight, Copy, Database, Download, Eraser, Eye,
  FileJson, FileSpreadsheet, Globe, History, Layers, Loader2, Lock, MinusCircle, Network, Plus,
  RefreshCw, RotateCcw, Search, Server, ShieldAlert, Sparkles, Target, Terminal,
  Trash2, Wifi, XCircle,
} from 'lucide-react';
import { useAuth } from '@/contexts/auth-context';
import {
  parseAssetInput,
  deduplicateAssets,
  type ValidatedAsset
} from '@/lib/scanner/asset-validator';
import { useScannerIntelligence } from '@/lib/scanner/use-scanner-intelligence';
import { mandatoryPqcStackMetadata } from '@/lib/crypto/mandatory-pqc-stack';
import AgentCollectorConsole from '@/components/agent-collector/AgentCollectorConsole';
import AgentSettingsConsole from '@/components/agent-collector/AgentSettingsConsole';
import {
  ACCENT,
  CountUp,
  Meter,
  Modal,
  Panel,
  QuantumField,
  Reveal,
  SectionLabel,
  StatusPill,
  scoreColor,
} from '@/components/quantum-scan/ui';
import { ScannerHero } from './_hero';
import { ExposureModeTabs, ExposureViewTabs, type ExposureView } from '@/components/exposure/ExposureModeTabs';
import { ExposureHistoryPanel } from '@/components/exposure/ExposureHistoryPanel';
import { useExposureAccess } from '@/hooks/use-exposure-access';
import { LocalAssessmentPanel } from '@/components/exposure/LocalAssessmentPanel';
import { DevAssessmentPanel } from '@/components/exposure/DevAssessmentPanel';
import type { ExposureAssessment, ScanMode } from '@/lib/scanner/exposure/types';
import { buildAssessment, SCANNER_NODE_BLUEPRINTS, SCANNER_NODE_MODULES } from './_intel';
import {
  clearScannerSession,
  loadScannerSession,
  restoreStatus,
  saveScannerSession,
} from './_session';
import {
  ScannerAttackSurface,
  ScannerCoverage,
  ScannerCryptoIntelligence,
  ScannerEmptyState,
  ScannerEncryptionScore,
  ScannerExecutiveSummary,
  ScannerFindingsTable,
  ScannerFootprint,
  ScannerModuleFlow,
  ScannerQuantumTimeline,
  ScannerRecommendations,
  ScannerScopePanel,
  ScannerSophiaInsight,
} from './_sections';
import type {
  DefensiveFinding,
  EnterpriseScanner2,
  HistoryEntry,
  HistoryTimeframe,
  LogEntry,
  ModuleLedger,
  ModuleState,
  ScanResultRecord,
  ScanStatus,
  ScanSummary,
  ScheduledScan,
  TabId,
} from './_types';

const scannerTabFromParam = (value: string | null): TabId | null => {
  if (!value) return null;

  const normalized = value.trim().toLowerCase();
  if (normalized === 'agent-collector-scanners' || normalized === 'agent-collector' || normalized === 'collector') {
    return 'agents';
  }

  if (['setup', 'overview', 'findings', 'logs', 'history', 'agents', 'settings'].includes(normalized)) {
    return normalized as TabId;
  }

  return null;
};

type AgentPolicy = {
  enabled?: boolean;
  intervalSeconds?: number;
  interval_seconds?: number;
  allowedTargets?: string[];
  allowed_targets?: string[];
  allowedPaths?: string[];
  allowed_paths?: string[];
  scanTypes?: string[];
  scan_types?: string[];
  alertThreshold?: string;
  alert_threshold?: string;
};

type CollectorAgent = {
  id: string;
  user_id: string;
  name: string;
  status: 'active' | 'online' | 'offline' | 'pending' | 'degraded' | 'unhealthy' | 'revoked' | 'updating' | string;
  hostname?: string | null;
  platform?: string | null;
  version?: string | null;
  capabilities?: Record<string, unknown>;
  policy?: AgentPolicy;
  last_seen_at?: string | null;
  revoked_at?: string | null;
  metadata?: Record<string, any>;
  created_at?: string;
  updated_at?: string;
};

type ScannerEvidenceRow = {
  id: string;
  agent_id?: string | null;
  evidence_type?: string | null;
  asset_name?: string | null;
  observed_algorithm?: string | null;
  host?: string | null;
  file_path?: string | null;
  observed_at?: string | null;
  created_at?: string | null;
};

type ScannerAlertRow = {
  id: string;
  agent_id?: string | null;
  severity?: string | null;
  category?: string | null;
  title?: string | null;
  message?: string | null;
  status?: string | null;
  created_at?: string | null;
};

type ConnectorAccount = {
  id: string;
  provider: string;
  display_name?: string | null;
  status?: string | null;
  scopes?: string[];
  capabilities?: Record<string, unknown>;
  policy?: AgentPolicy;
  last_sync_at?: string | null;
  metadata?: Record<string, any>;
  created_at?: string;
  updated_at?: string;
};

type PatchOption = {
  id: string;
  label: string;
  actionType: string;
  requiresConnector: boolean;
  requiredScopes: string[];
  summary: string;
  validation: string;
  mandatoryQuantumStack?: Record<string, any>;
  executionContract?: Record<string, any>;
};

type PatchOptionGroup = {
  assetClass: string;
  options: PatchOption[];
};

type OperatorAction = {
  id: string;
  migration_id?: string | null;
  connector_account_id?: string | null;
  action_type?: string | null;
  asset_class?: string | null;
  status?: string | null;
  approval_mode?: string | null;
  patch_plan?: Record<string, any>;
  evidence?: Record<string, any>;
  validation?: Record<string, any>;
  metadata?: Record<string, any>;
  requested_at?: string | null;
  approved_at?: string | null;
  applied_at?: string | null;
  validated_at?: string | null;
  created_at?: string;
  updated_at?: string;
};

type AgentFormState = {
  name: string;
  environment: string;
  enabled: boolean;
  allowedTargets: string;
  allowedPaths: string;
  intervalSeconds: string;
  scanTypes: string[];
  alertThreshold: string;
};

type ConnectorFormState = {
  provider: string;
  displayName: string;
  scopes: string;
  allowedTargets: string;
  allowedPaths: string;
  sdkPatchEnabled: boolean;
  credentialMode: string;
  region: string;
  subscriptionId: string;
  projectId: string;
};

type OperatorPatchFormState = {
  assetClass: string;
  optionId: string;
  connectorId: string;
  target: string;
  migrationJobId: string;
  dryRun: boolean;
  payloadJson: string;
};

type OneTimeAgentToken = {
  agentId: string;
  token: string;
  createdAt: string;
  mode: 'created' | 'rotated';
} | null;

const AGENT_SCAN_TYPE_OPTIONS = [
  { id: 'tls', label: 'TLS', detail: 'Protocol, ciphers, KEX' },
  { id: 'certificates', label: 'Certificates', detail: 'X.509 and chain state' },
  { id: 'pki', label: 'PKI', detail: 'Trust stores and issuers' },
  { id: 'ssh', label: 'SSH', detail: 'Host and authorized keys' },
  { id: 'packages', label: 'Packages', detail: 'Manifests and versions' },
  { id: 'configs', label: 'Configs', detail: 'Crypto policy files' },
  { id: 'libraries', label: 'Libraries', detail: 'OpenSSL, OQS, JVM, .NET' },
  { id: 'vpn', label: 'VPN', detail: 'IPSec, OpenVPN, WireGuard' },
  { id: 'kubernetes', label: 'Kubernetes', detail: 'Ingress and cert-manager' },
  { id: 'service_mesh', label: 'Mesh', detail: 'mTLS and workload policy' },
  { id: 'api_gateway', label: 'Gateway', detail: 'API gateway TLS policy' },
  { id: 'load_balancer', label: 'Load Balancer', detail: 'Edge and LB profiles' },
  { id: 'hsm', label: 'HSM/KMS', detail: 'PKCS#11, KMS, vault bindings' },
  { id: 'cloud', label: 'Cloud', detail: 'AWS, Azure, GCP, OCI, Alibaba' },
  { id: 'cloud_kms', label: 'Cloud KMS', detail: 'Key vault and KMS policies' },
  { id: 'cloud_hsm', label: 'Cloud HSM', detail: 'HSM and private CA bindings' },
  { id: 'cloud_database', label: 'Cloud DB', detail: 'Managed database crypto' },
  { id: 'cloud_storage', label: 'Cloud Storage', detail: 'Bucket/blob encryption' },
  { id: 'cloud_load_balancer', label: 'Cloud LB', detail: 'Cloud load balancer TLS' },
  { id: 'web_application', label: 'Web Apps', detail: 'Websites and portals' },
  { id: 'public_tls', label: 'Public TLS', detail: 'Internet-facing endpoints' },
  { id: 'api', label: 'APIs', detail: 'API crypto and signing' },
  { id: 'cdn', label: 'CDN', detail: 'Edge TLS and cert policy' },
  { id: 'saas', label: 'SaaS', detail: 'SaaS trust and API policy' },
  { id: 'database', label: 'Databases', detail: 'DB TLS, certs, keys' },
  { id: 'network_device', label: 'Network Devices', detail: 'Firewalls, routers, VPNs' },
  { id: 'containers', label: 'Containers', detail: 'Images and runtime crypto' },
  { id: 'runtime', label: 'Runtime', detail: 'Handshake and drift events' },
];

const ALL_AGENT_SCAN_TYPE_IDS = AGENT_SCAN_TYPE_OPTIONS.map((item) => item.id);
const DEFAULT_AGENT_SCAN_TYPES: string[] = [];
const QUANTUM_VULNERABILITY_PATTERN = /\b(quantum[-\s]?vulnerable|hndl|non[-\s]?compliant|weak|legacy|rsa|ecdsa|ecc|ecdh|dsa|diffie|dh\b|ssh-rsa|tls[-\s]?1\.[012]|ssl[-\s]?v[23]|sha[-\s]?1|md5|3des|des|rc4|p-?256|p-?384|secp|x25519|curve25519)\b/i;
const DETECTED_SCOPE_RULES = [
  { ids: ['tls'], pattern: /\b(tls|ssl|cipher|ciphersuite|handshake|key exchange|kex|x25519|ecdh|rsa key exchange|openssl|nginx|apache|iis|envoy|haproxy|traefik)\b/i },
  { ids: ['certificates', 'pki'], pattern: /\b(certificate|cert\b|x\.?509|issuer|chain|csr|pki|trust store|ca\b|private ca|ml-dsa|mldsa|ed25519)\b/i },
  { ids: ['ssh'], pattern: /\b(ssh|ssh-rsa|ssh-dss|authorized_keys|host key|hostkey|sshd|rsa-sha2)\b/i },
  { ids: ['packages'], pattern: /\b(package|dependency|manifest|package-lock|requirements|pom\.xml|gradle|nuget|composer|gemfile|sbom)\b/i },
  { ids: ['libraries'], pattern: /\b(openssl|bouncycastle|wolfssl|libsodium|java crypto|\.net crypto|liboqs|oqs|oqs-provider|provider|crypto library)\b/i },
  { ids: ['configs'], pattern: /\b(config|configuration|policy|openssl\.cnf|ssl_conf|nginx\.conf|httpd\.conf|web\.config|envoy\.yaml|haproxy\.cfg|crypto policy)\b/i },
  { ids: ['vpn'], pattern: /\b(vpn|ipsec|ikev2|openvpn|wireguard|ssl vpn|strongswan|racoon)\b/i },
  { ids: ['kubernetes'], pattern: /\b(kubernetes|k8s|ingress|cert-manager|gateway api|clusterissuer|issuer|namespace|helm|kubectl|openshift)\b/i },
  { ids: ['service_mesh'], pattern: /\b(service mesh|mtls|istio|linkerd|consul|envoy sidecar|workload policy)\b/i },
  { ids: ['api_gateway', 'api'], pattern: /\b(api gateway|gateway|kong|apigee|reverse proxy|jwt|api signing|mTLS|webhook signature)\b/i },
  { ids: ['load_balancer'], pattern: /\b(load balancer|alb|nlb|application gateway|front door|https lb|f5|citrix|big-ip)\b/i },
  { ids: ['hsm', 'cloud_kms', 'cloud_hsm'], pattern: /\b(hsm|kms|key vault|cloudhsm|pkcs#?11|luna|nshield|vault binding)\b/i },
  { ids: ['cloud'], pattern: /\b(aws|azure|gcp|google cloud|oracle cloud|oci|alibaba|aliyun|cloud)\b/i },
  { ids: ['cloud_database', 'database'], pattern: /\b(database|db tls|rds|aurora|cloud sql|azure sql|cosmos|spanner|postgres|mysql|mariadb|mongodb|oracle db|sql server)\b/i },
  { ids: ['cloud_storage'], pattern: /\b(storage|bucket|blob|object store|s3|gcs|azure storage|kms encryption)\b/i },
  { ids: ['cloud_load_balancer'], pattern: /\b(cloud load balancer|cloud lb|elb|alb|nlb|front door|cloudfront|https lb)\b/i },
  { ids: ['web_application', 'public_tls'], pattern: /\b(web app|website|portal|e-commerce|public tls|public endpoint|https endpoint|internet-facing|domain)\b/i },
  { ids: ['cdn'], pattern: /\b(cdn|cloudflare|akamai|fastly|cloudfront|edge tls|edge certificate)\b/i },
  { ids: ['saas'], pattern: /\b(saas|okta|entra|auth0|saml|oidc|federation|custom domain|tenant api)\b/i },
  { ids: ['network_device'], pattern: /\b(network device|firewall|router|switch|appliance|vpn concentrator|f5|citrix)\b/i },
  { ids: ['containers'], pattern: /\b(container|docker|image|registry|pod|sidecar|runtime image)\b/i },
  { ids: ['runtime'], pattern: /\b(runtime|telemetry|drift|handshake event|key rotation|unauthorized crypto|crypto event)\b/i },
];
const REMEDIATION_WORKFLOW_STAGES = ['DISCOVER', 'ANALYZE', 'APPROVE', 'PATCH', 'VALIDATE', 'MONITOR', 'REPORT'];
const MANDATORY_QUANTUM_STACK = mandatoryPqcStackMetadata();
const MANDATORY_QUANTUM_STACK_GROUPS = [
  { title: 'Libraries', items: MANDATORY_QUANTUM_STACK.requiredLibraries },
  { title: 'Key Exchange', items: [MANDATORY_QUANTUM_STACK.keyExchange.primary, MANDATORY_QUANTUM_STACK.keyExchange.hybrid] },
  { title: 'Signatures', items: [MANDATORY_QUANTUM_STACK.signatures.primary, MANDATORY_QUANTUM_STACK.signatures.hybrid] },
  { title: 'Data Protection', items: [MANDATORY_QUANTUM_STACK.encryption.symmetric, MANDATORY_QUANTUM_STACK.kdf.primary, `${MANDATORY_QUANTUM_STACK.kdf.compatibilityFallback} (fallback)`, ...MANDATORY_QUANTUM_STACK.hashes] },
  { title: 'TLS Policy', items: [MANDATORY_QUANTUM_STACK.tls.minProtocol, `${MANDATORY_QUANTUM_STACK.tls.preferredGroup} preferred`, 'Hybrid TLS enabled', 'Classical fallback: policy-controlled'] },
  { title: 'High Security Profile', items: [MANDATORY_QUANTUM_STACK.highSecurityProfile.keyExchange, ...MANDATORY_QUANTUM_STACK.highSecurityProfile.signatures] },
];
const REMEDIATION_READINESS_GROUPS = [
  {
    title: 'Discover',
    items: ['TLS, certificates, PKI, keys, trust fabric', 'SSH, VPN, gateways, load balancers, network devices', 'AWS, Azure, GCP, OCI, Alibaba, Kubernetes, containers', 'Web apps, APIs, CDNs, SaaS, public TLS endpoints'],
  },
  {
    title: 'Assess',
    items: ['Quantum-vulnerable algorithms and weak cipher suites', 'NIST readiness and FIPS posture', 'Migration feasibility and dependency chains', 'Potential blast radius across local, cloud, web, and SaaS assets'],
  },
  {
    title: 'Patch',
    items: ['TLS 1.3 and X25519 + ML-KEM-768 hybrid key exchange', 'ML-DSA-65 and Ed25519 + ML-DSA-65 hybrid certificates', 'SSH Ed25519, weak cipher removal, key rotation', 'OQS Provider/liboqs, VPN, KMS/HSM, database, CDN, API gateway, ingress policy'],
  },
  {
    title: 'Verify',
    items: ['Before and after state with functional testing', 'TLS, certificate, dependency, rollback, and compliance validation', 'Automatic rollback on failed guarded local patches', 'Runtime crypto intelligence, PQC adoption, trust fabric, and drift monitoring'],
  },
];
const REMEDIATION_CONTROL_SUMMARY = [
  ['Approval gate', 'RBAC + tenant admin'],
  ['Snapshots', 'Config, cert, key metadata, TLS policy'],
  ['Rollback', 'Automatic after failed validation'],
  ['Telemetry', 'SSE heartbeat every 30-60s'],
];
const SUPPORTED_ENVIRONMENT_GROUPS = [
  {
    title: 'Local / On-Prem',
    items: ['Workstations', 'Servers', 'VMs', 'Databases', 'Internal apps', 'PKI, certificates, keys', 'TLS configs', 'Network devices'],
  },
  {
    title: 'Cloud',
    items: ['AWS', 'Azure', 'GCP', 'Oracle Cloud', 'Alibaba Cloud', 'Cloud databases/storage', 'KMS and HSM', 'Cloud load balancers'],
  },
  {
    title: 'Kubernetes / Containers',
    items: ['Clusters', 'Ingress', 'Gateway API', 'cert-manager', 'Service mesh', 'Containers', 'Registries', 'Workload crypto config'],
  },
  {
    title: 'Web / Edge / SaaS',
    items: ['Websites', 'Web apps', 'APIs', 'API gateways', 'Reverse proxies', 'CDNs', 'Customer portals', 'SaaS apps'],
  },
];
const LOCAL_COLLECTOR_CLARIFICATIONS = [
  ['Installed where?', 'A Local Collector is a tenant-owned agent installed on an endpoint, server, VM, container, sidecar, or controlled jump host.'],
  ['Local only?', 'No. It monitors local OS/resources when authorized, but can also scan allowed network targets and submit evidence for external assets.'],
  ['Cloud APIs?', 'Yes, when the customer explicitly authorizes provider API access. Remote mutation uses scoped Cloud Connectors or operator patch actions.'],
  ['External assets?', 'Yes. Public TLS endpoints, APIs, web apps, SaaS trust metadata, and cloud resources can be discovered through allowlisted targets/connectors.'],
  ['Remote remediation?', 'Yes. Collectors can trigger workflows; Cloud/Web/SaaS/Kubernetes changes require least-privilege scopes, approval, snapshots, validation, and audit logs.'],
];
const CONNECTOR_PROVIDER_OPTIONS = ['kubernetes', 'aws', 'azure', 'gcp', 'oracle-cloud', 'alibaba-cloud', 'cloudflare', 'akamai', 'fastly', 'pki', 'database', 'network-device', 'saas', 'okta', 'entra-id', 'auth0', 'custom'];

function orderedKnownScanTypes(scanTypes: Iterable<string>) {
  const selected = new Set(scanTypes);
  return ALL_AGENT_SCAN_TYPE_IDS.filter((id) => selected.has(id));
}

function detectedScopeIdsFromText(text: string) {
  const selected = new Set<string>();
  DETECTED_SCOPE_RULES.forEach((rule) => {
    if (rule.pattern.test(text)) {
      rule.ids.forEach((id) => selected.add(id));
    }
  });

  if (selected.size === 0) {
    if (/\b(rsa|ecdsa|dsa|signature|signing)\b/i.test(text)) {
      selected.add('certificates');
      selected.add('pki');
    }
    if (/\b(ecdh|x25519|curve25519|diffie|dh\b|key exchange|kex|kem|tls|ssl)\b/i.test(text)) {
      selected.add('tls');
    }
    if (/\b(sha[-\s]?1|md5|3des|des|rc4|cipher|kdf|hash)\b/i.test(text)) {
      selected.add('configs');
      selected.add('libraries');
    }
  }

  return selected;
}

function detectedMitigationScanTypesFromData(
  findingsInput: DefensiveFinding[],
  evidenceInput: ScannerEvidenceRow[],
  alertsInput: ScannerAlertRow[],
) {
  const selected = new Set<string>();

  findingsInput.forEach((finding) => {
    if (finding.threatLevel === 'SAFE') return;
    const text = [
      finding.algorithm,
      finding.category,
      finding.location,
      finding.status,
      finding.description,
      finding.recommendation,
      finding.pqcReplacement,
      finding.evidence,
      finding.detectionMethod,
      finding.source,
    ].filter(Boolean).join(' ');

    if (!finding.pqcReplacement && !QUANTUM_VULNERABILITY_PATTERN.test(text)) return;
    detectedScopeIdsFromText(text).forEach((id) => selected.add(id));
  });

  evidenceInput.forEach((evidence) => {
    const text = [
      evidence.evidence_type,
      evidence.asset_name,
      evidence.observed_algorithm,
      evidence.host,
      evidence.file_path,
    ].filter(Boolean).join(' ');

    if (!QUANTUM_VULNERABILITY_PATTERN.test(text)) return;
    detectedScopeIdsFromText(text).forEach((id) => selected.add(id));
  });

  alertsInput.forEach((alert) => {
    const status = String(alert.status || 'open').toLowerCase();
    if (['resolved', 'closed', 'suppressed'].includes(status)) return;
    const text = [
      alert.severity,
      alert.category,
      alert.title,
      alert.message,
    ].filter(Boolean).join(' ');

    if (!QUANTUM_VULNERABILITY_PATTERN.test(text)) return;
    detectedScopeIdsFromText(text).forEach((id) => selected.add(id));
  });

  return orderedKnownScanTypes(selected);
}

/**
 * Severity palette, aligned to the shared design tokens so a severity chip on
 * this page is the same colour as the same severity anywhere else on the
 * platform. Returns Tailwind class fragments for the places that still compose
 * classes, plus the raw token for inline styles.
 */
function sevColor(s: string) {
  switch (s.toLowerCase()) {
    case 'critical': return { t: 'text-rose-300', b: 'bg-rose-500/10', br: 'border-rose-400/30', d: 'bg-rose-400', hex: ACCENT.rose };
    case 'high': return { t: 'text-amber-300', b: 'bg-amber-500/10', br: 'border-amber-400/30', d: 'bg-amber-400', hex: ACCENT.amber };
    case 'medium': return { t: 'text-yellow-300', b: 'bg-yellow-500/10', br: 'border-yellow-400/30', d: 'bg-yellow-400', hex: '#facc15' };
    case 'low': return { t: 'text-emerald-300', b: 'bg-emerald-500/10', br: 'border-emerald-400/30', d: 'bg-emerald-400', hex: ACCENT.emerald };
    case 'safe': return { t: 'text-emerald-300', b: 'bg-emerald-500/10', br: 'border-emerald-400/30', d: 'bg-emerald-400', hex: ACCENT.emerald };
    default: return { t: 'text-cyan-300', b: 'bg-cyan-500/10', br: 'border-cyan-400/30', d: 'bg-cyan-400', hex: ACCENT.cyan };
  }
}

function logColor(level: string) {
  switch (level) {
    case 'WARN': return 'text-amber-300';
    case 'ERROR': return 'text-rose-400';
    case 'SUCCESS': return 'text-emerald-300';
    default: return 'text-slate-400';
  }
}

function targetIcon(t: string) {
  const lower = t.toLowerCase();
  if (lower.includes('certificate') || lower.includes('tls') || lower.includes('ssh') || lower.includes('key')) return Lock;
  if (lower.includes('database')) return Database;
  if (lower.includes('protocol') || lower.includes('api') || lower.includes('url')) return Globe;
  if (lower.includes('library') || lower.includes('source')) return Layers;
  if (lower.includes('wireless')) return Wifi;
  return Server;
}

function statusToLevel(type: string, status?: string): LogEntry['level'] {
  if (type.includes('failed') || status === 'failed' || type === 'error') return 'ERROR';
  if (type.includes('complete') || status === 'completed') return 'SUCCESS';
  if (type.includes('warning') || type.includes('cancel')) return 'WARN';
  return 'INFO';
}

function formatMs(ms: number | null) {
  if (!ms) return 'N/A';
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function formatElapsed(startedAt: number | null, timestamp?: string) {
  if (!startedAt) return '00:00';
  const end = timestamp ? Date.parse(timestamp) : Date.now();
  const seconds = Math.max(0, Math.floor((end - startedAt) / 1000));
  const mm = String(Math.floor(seconds / 60)).padStart(2, '0');
  const ss = String(seconds % 60).padStart(2, '0');
  return `${mm}:${ss}`;
}

/** Module lifecycle status → the seven-state status vocabulary of `StatusPill`. */

function normalizeAgentPolicy(policy?: AgentPolicy) {
  return {
    enabled: policy?.enabled !== false,
    intervalSeconds: Math.max(30, Math.min(60, Number(policy?.intervalSeconds || policy?.interval_seconds || 60))),
    allowedTargets: policy?.allowedTargets || policy?.allowed_targets || [],
    allowedPaths: policy?.allowedPaths || policy?.allowed_paths || [],
    scanTypes: policy?.scanTypes || policy?.scan_types || DEFAULT_AGENT_SCAN_TYPES,
    alertThreshold: policy?.alertThreshold || policy?.alert_threshold || 'moderate',
  };
}

function isAgentOnline(agent: CollectorAgent) {
  if (agent.revoked_at || agent.status === 'revoked') return false;
  if (!agent.last_seen_at) return false;
  return Date.now() - Date.parse(agent.last_seen_at) < 10 * 60 * 1000;
}

function agentDisplayStatus(agent: CollectorAgent) {
  if (agent.revoked_at || agent.status === 'revoked') return 'Revoked';
  if (agent.status === 'updating') return 'Updating';
  if (agent.status === 'degraded' || agent.status === 'unhealthy') return 'Unhealthy';
  if (isAgentOnline(agent)) return 'Online';
  if (!agent.last_seen_at) return 'Pending setup';
  return 'Offline';
}

function agentStatusClass(status: string) {
  switch (status.toLowerCase()) {
    case 'online': return 'border-green-500/30 bg-green-500/10 text-green-400';
    case 'offline': return 'border-red-500/30 bg-red-500/10 text-red-400';
    case 'pending setup': return 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400';
    case 'unhealthy': return 'border-orange-500/30 bg-orange-500/10 text-orange-400';
    case 'revoked': return 'border-white/10 bg-white/[0.03] text-white/35';
    case 'updating': return 'border-cyan-500/30 bg-cyan-500/10 text-cyan-400';
    default: return 'border-gold/20 bg-gold/10 text-gold';
  }
}

function formatDateTime(value?: string | null) {
  if (!value) return 'Never';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Unknown';
  return date.toLocaleString();
}

function serializeLogs(logs: LogEntry[]) {
  return logs.map((entry) => `[${entry.elapsed || entry.timestamp}] [${entry.level}] ${entry.moduleName ? `[${entry.moduleName}] ` : ''}${entry.message}`).join('\n');
}

function safeText(value: unknown, fallback = '') {
  return typeof value === 'string' && value.trim() ? value : fallback;
}

function directDashboardThreatLevel(value: unknown): DefensiveFinding['threatLevel'] | null {
  const normalized = String(value || '').toUpperCase();
  if (normalized === 'CRITICAL' || normalized === 'HIGH' || normalized === 'MEDIUM' || normalized === 'LOW' || normalized === 'SAFE') {
    return normalized;
  }
  if (normalized === 'MODERATE') return 'MEDIUM';
  return null;
}

function inferDashboardThreatLevel(input: {
  algorithm: string;
  category?: string;
  status?: string;
  severity?: unknown;
  rawSeverity?: unknown;
}): DefensiveFinding['threatLevel'] {
  const direct = directDashboardThreatLevel(input.severity) || directDashboardThreatLevel(input.rawSeverity);
  if (direct) return direct;

  const algorithm = input.algorithm.toLowerCase();
  const category = String(input.category || '').toLowerCase();
  const status = String(input.status || '').toLowerCase();

  if (status.includes('pqc-ready') || algorithm.includes('aes-256') || algorithm.includes('ml-kem') || algorithm.includes('ml-dsa')) return 'SAFE';
  if (algorithm.includes('tlsv1.3') || algorithm.includes('tls 1.3') || algorithm.includes('tls-1.3')) return 'LOW';
  if (algorithm.includes('tlsv1.0') || algorithm === 'tlsv1' || algorithm.includes('tls 1.0') || algorithm.includes('tls-1.0')) return 'CRITICAL';
  if (algorithm.includes('tlsv1.1') || algorithm.includes('tls 1.1') || algorithm.includes('tls-1.1')) return 'CRITICAL';
  if (algorithm.includes('rsa-1024') || algorithm.includes('md5') || algorithm.includes('sha-1') || algorithm.includes('sha1')) return 'CRITICAL';
  if (algorithm.includes('expired certificate') || category.includes('expired')) return 'CRITICAL';

  if (algorithm.includes('wide crypto attack surface')) return 'HIGH';
  if (algorithm.includes('hndl risk')) return 'HIGH';
  if (algorithm.includes('ecdsa') || algorithm.includes('ecdhe') || algorithm.includes('ecdh') || algorithm.includes('x25519')) return 'HIGH';
  if (algorithm.includes('rsa-2048') || algorithm.includes('rsa 2048') || algorithm.includes('dhe') || algorithm.includes('diffie')) return 'HIGH';
  if (category.includes('certificate') && status.includes('quantum-vulnerable')) return 'HIGH';
  if (category.includes('key exchange') && status.includes('quantum-vulnerable')) return 'HIGH';

  if (algorithm.includes('tlsv1.2') || algorithm.includes('tls 1.2') || algorithm.includes('tls-1.2')) return 'MEDIUM';
  if (algorithm.includes('nist pqc deadline')) return 'MEDIUM';
  if (algorithm.includes('no hybrid crypto')) return 'MEDIUM';
  if (algorithm.includes('no certificate pinning')) return 'MEDIUM';
  if (algorithm.includes('regulatory compliance gap')) return 'LOW';
  if (status.includes('quantum-vulnerable') || status.includes('legacy') || status.includes('misconfigured')) return 'MEDIUM';

  return 'LOW';
}

function normalizeDashboardFinding(finding: Partial<DefensiveFinding> & Record<string, unknown>, index = 0): DefensiveFinding {
  const raw = (finding.raw && typeof finding.raw === 'object' ? finding.raw : {}) as Record<string, unknown>;
  const algorithm = safeText(finding.algorithm, safeText(raw.algorithm, 'Unknown algorithm'));
  const category = safeText(finding.category, safeText(raw.category, 'Stored Finding'));
  const location = safeText(finding.location, safeText(raw.location, 'Stored scanner result'));
  const status = safeText(finding.status, '');
  const threatLevel = inferDashboardThreatLevel({
    algorithm,
    category,
    status,
    severity: finding.threatLevel || finding.severity,
    rawSeverity: raw.threatLevel || raw.severity,
  });

  return {
    id: safeText(finding.id, safeText(raw.id, `finding-${index + 1}`)),
    algorithm,
    category,
    location,
    threatLevel,
    status: status || (threatLevel === 'SAFE' ? 'PQC-ready' : 'Quantum-vulnerable'),
    description: safeText(finding.description, safeText(raw.description, 'Persisted scanner finding')),
    recommendation: safeText(finding.recommendation, safeText(raw.recommendation, 'Review against NIST PQC migration policy')),
    pqcReplacement: typeof finding.pqcReplacement === 'string' ? finding.pqcReplacement : null,
    keySize: typeof finding.keySize === 'number' ? finding.keySize : null,
    evidence: safeText(finding.evidence, `${safeText(finding.detectionMethod, 'scanner')}: ${location}`),
    detectionMethod: safeText(finding.detectionMethod, safeText(raw.phase, 'persisted-scan-result')),
    source: safeText(finding.source, 'authorized-scanner-history'),
  };
}

function normalizeDashboardFindings(value: unknown): DefensiveFinding[] {
  if (!Array.isArray(value)) return [];
  return value.map((finding, index) => normalizeDashboardFinding(
    finding && typeof finding === 'object' ? finding as Partial<DefensiveFinding> & Record<string, unknown> : {},
    index
  ));
}

function dateInputFor(offsetDays = 1) {
  const date = new Date();
  date.setDate(date.getDate() + offsetDays);
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
}

function isHistoryEntryInLastDays(entry: HistoryEntry, days: number, offsetDays = 0) {
  const value = Date.parse(entry.startedAt || entry.completedAt || '');
  if (!Number.isFinite(value)) return false;
  const end = Date.now() - offsetDays * 86400000;
  const start = end - days * 86400000;
  return value >= start && value <= end;
}

function filterHistoryByTimeframe(entries: HistoryEntry[], timeframe: HistoryTimeframe) {
  if (timeframe === 'last7') return entries.filter((entry) => isHistoryEntryInLastDays(entry, 7));
  return entries;
}

function historyMetricSnapshot(entries: HistoryEntry[]) {
  const assetKeys = new Set<string>();
  const vulnerableAssetKeys = new Set<string>();
  let totalFindings = 0;
  let critical = 0;
  let vulnerableFindings = 0;
  let pqcReady = 0;
  let weightedRisk = 0;
  let riskWeight = 0;

  entries.forEach((entry) => {
    const summary = entry.summary;
    const entryAssets = entry.linkedAssetRecords?.length
      ? entry.linkedAssetRecords
      : [entry.target || entry.scanId].filter(Boolean);
    entryAssets.forEach((asset) => assetKeys.add(asset));
    if ((entry.vulnerableFindings || summary?.vulnerable || 0) > 0) {
      entryAssets.forEach((asset) => vulnerableAssetKeys.add(asset));
    }

    const findingsCount = summary?.totalFindings ?? entry.detectedComponents ?? entry.findings?.length ?? 0;
    totalFindings += findingsCount;
    critical += summary?.critical ?? normalizeDashboardFindings(entry.findings).filter((finding) => finding.threatLevel === 'CRITICAL').length;
    vulnerableFindings += summary?.vulnerable ?? entry.vulnerableFindings ?? 0;
    pqcReady += summary?.pqcReady ?? entry.pqcReadyFindings ?? 0;

    const risk = entry.riskScore ?? summary?.riskScore;
    if (typeof risk === 'number' && Number.isFinite(risk)) {
      const weight = Math.max(1, findingsCount);
      weightedRisk += risk * weight;
      riskWeight += weight;
    }
  });

  const riskScore = riskWeight > 0 ? Math.round(weightedRisk / riskWeight) : 0;
  const pqcReadiness = totalFindings > 0 ? Math.round((pqcReady / totalFindings) * 100) : 0;

  return {
    totalAssetsScanned: assetKeys.size || entries.reduce((sum, entry) => sum + Math.max(0, entry.summary?.targetsScanned ?? 0), 0),
    vulnerableAssets: vulnerableAssetKeys.size,
    riskScore,
    criticalFindings: critical,
    pqcReadiness,
    totalFindings,
    vulnerableFindings,
    pqcReady,
  };
}




function csvCell(value: unknown) {
  const text = String(value ?? '').replace(/\r?\n/g, ' ');
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function downloadTextFile(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}



export default function ScannerDashboard() {
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedTab = scannerTabFromParam(searchParams.get('tab'));
  const { session, user } = useAuth();

  // Agent access is BASIC, with the write-capable roles held back to PRO.
  //
  //   canUseAgents       BASIC+  reach the Agents tab, deploy and operate the
  //                              two READ-ONLY roles (Collector, Scanner).
  //   canUseWriteAgents  PRO+    Patcher and Migration Operator, the roles that
  //                              modify a host.
  //
  // Splitting the two is the whole point: a Basic tenant needs a real agent
  // fleet to feed the Quantum Readiness engine they already pay for, but must
  // never hold an agent that can change one of their endpoints. The server
  // enforces the same split per role in api-server/agent-entitlement.ts; this
  // is the UX layer.
  const subscription = useSubscription();
  const isOwner = isOwnerEmail(user?.email);
  const canUseAgents = isOwner || (subscription.isActive && tierMeets(subscription.tier, 'basic'));
  const canUseWriteAgents = isOwner || (subscription.isActive && tierMeets(subscription.tier, 'pro'));

  // Central Scanner Intelligence — the platform-wide, tenant-scoped snapshot
  // (shared-table truth + SSE + poll fallback) that also powers the Assets,
  // CBOM, Exposure and Quantum-Readiness views. Wiring the scanner headline to
  // this SAME source keeps every KPI card consistent across the platform and
  // makes previously scanned assets visible regardless of when they were
  // scanned (the local /scanner/history fetch alone was time-window fragile).
  const scannerIntel = useScannerIntelligence();

  // Floating notifications
  const [toast, setToast] = useState<string | null>(null);
  const showToast = useCallback((msg: string) => {
    setToast(msg);
  }, []);

  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(null), 3500);
    return () => clearTimeout(timer);
  }, [toast]);

  const [status, setStatus] = useState<ScanStatus>('idle');
  const [activeTab, setActiveTab] = useState<TabId>(() => requestedTab ?? 'setup');

  /* Three assessment modes (§3). Web is the existing authenticated estate
     scanner, unchanged. Local and Dev mount the Exposure Assessment Engine's
     own panels, with the authenticated extras — connector credentials and
     platform synchronisation — that the anonymous page cannot offer. */
  const [exposureMode, setExposureMode] = useState<ScanMode>(() => {
    const requested = searchParams.get('mode');
    return requested === 'local' || requested === 'dev' ? requested : 'web';
  });

  /* Assessment vs History, within Local and Dev.

     The two panels are BOTH mounted and toggled with `hidden` rather than
     swapped, because a Local assessment runs in a Web Worker owned by
     `LocalAssessmentPanel`'s hook: unmounting it to look at the history would
     kill a scan the operator is in the middle of. */
  const [exposureView, setExposureView] = useState<ExposureView>(() =>
    searchParams.get('view') === 'history' ? 'history' : 'assessment',
  );

  /* Lock badges on the tabs. Reaching /dashboard/scanner at all already needs
     BASIC, so Local is normally open here — but Dev needs PRO, and a Basic
     tenant must see that before they click rather than after. */
  const localAccess = useExposureAccess('local');
  const devAccess = useExposureAccess('dev');
  const lockedModes = useMemo(() => {
    const locked: Partial<Record<ScanMode, string>> = {};
    if (!localAccess.loading && !localAccess.allowed) locked.local = localAccess.message;
    if (!devAccess.loading && !devAccess.allowed) locked.dev = devAccess.message;
    return locked;
  }, [localAccess.loading, localAccess.allowed, localAccess.message, devAccess.loading, devAccess.allowed, devAccess.message]);
  useEffect(() => {
    if (requestedTab) {
      setActiveTab(requestedTab);
    }
  }, [requestedTab]);

  const handleTabSelect = useCallback((tab: TabId) => {
    setActiveTab(tab);

    const nextParams = new URLSearchParams(searchParams);
    if (tab === 'setup') {
      nextParams.delete('tab');
    } else {
      nextParams.set('tab', tab);
    }
    setSearchParams(nextParams, { replace: true });
  }, [searchParams, setSearchParams]);

  const handleModeSelect = useCallback((mode: ScanMode) => {
    setExposureMode(mode);
    const nextParams = new URLSearchParams(searchParams);
    if (mode === 'web') nextParams.delete('mode');
    else nextParams.set('mode', mode);
    /* Web has its own tab bar and no `view`; leaving the parameter behind would
       put the URL in a state the page does not render. */
    if (mode === 'web') nextParams.delete('view');
    setSearchParams(nextParams, { replace: true });
  }, [searchParams, setSearchParams]);

  const handleViewSelect = useCallback((view: ExposureView) => {
    setExposureView(view);
    const nextParams = new URLSearchParams(searchParams);
    if (view === 'assessment') nextParams.delete('view');
    else nextParams.set('view', view);
    setSearchParams(nextParams, { replace: true });
  }, [searchParams, setSearchParams]);

  /**
   * Persist a Local assessment into the tenant's inventory (§73).
   *
   * The browser produced it, so the server re-derives everything it writes —
   * this call only carries it across the boundary.
   */
  const syncLocalAssessment = useCallback(async (assessment: ExposureAssessment) => {
    const token = session?.access_token;
    if (!token) throw new Error('Sign in again to synchronise this assessment.');
    const response = await fetch('/api/v1/exposure/local/sync', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ assessment }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error?.message ?? 'The assessment could not be synchronised.');
    showToast(
      payload.data?.degraded
        ? payload.data.notice ?? 'The assessment was not persisted.'
        : `Synchronised: ${payload.data?.cryptoInventoryRows ?? 0} CBOM components and ${payload.data?.scanResultRows ?? 0} findings written to the inventory.`,
    );
  }, [session?.access_token]);

  const syncDevAssessment = useCallback(async (scanId: string) => {
    const token = session?.access_token;
    if (!token) throw new Error('Sign in again to synchronise this assessment.');
    const response = await fetch(`/api/v1/exposure/scans/${encodeURIComponent(scanId)}/sync`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error?.message ?? 'The assessment could not be synchronised.');
    showToast(
      payload.data?.degraded
        ? payload.data.notice ?? 'The assessment was not persisted.'
        : `Synchronised: ${payload.data?.cryptoInventoryRows ?? 0} CBOM components and ${payload.data?.scanResultRows ?? 0} findings written to the inventory.`,
    );
  }, [session?.access_token]);

  const [sevFilter, setSevFilter] = useState<string | null>(null);
  const [searchQ, setSearchQ] = useState('');
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [inputText, setInputText] = useState('');
  const [targets, setTargets] = useState<ValidatedAsset[]>([]);
  const [authorizationAccepted, setAuthorizationAccepted] = useState(false);
  const [progress, setProgress] = useState(0);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [findings, setFindings] = useState<DefensiveFinding[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [modules, setModules] = useState<ModuleState[]>([]);
  /** The scanner's own execution ledger for the current run, when one exists. */
  const [moduleLedger, setModuleLedger] = useState<ModuleLedger | null>(null);
  // Per-target results and the Scanner_2 enterprise pass arrive on the same
  // `scan-complete` frame the summary does. They carry the published risk
  // decomposition, scan confidence, HNDL analysis and migration
  // recommendations — the evidence the assessment panels are built from.
  const [scanResults, setScanResults] = useState<ScanResultRecord[]>([]);
  const [scanner2, setScanner2] = useState<EnterpriseScanner2 | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [selectedHistoryId, setSelectedHistoryId] = useState<string | null>(null);
  const [expandedHistoryFinding, setExpandedHistoryFinding] = useState<string | null>(null);
  const [historyFindingSearch, setHistoryFindingSearch] = useState('');
  const [historySeverityFilter, setHistorySeverityFilter] = useState<string | null>(null);
  const [historyTimeframe, setHistoryTimeframe] = useState<HistoryTimeframe>('all');
  const [scheduleOpen, setScheduleOpen] = useState(false);
  const [scheduleDate, setScheduleDate] = useState(dateInputFor(1));
  const [scheduleTime, setScheduleTime] = useState('02:00');
  const [scheduledScans, setScheduledScans] = useState<ScheduledScan[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  // Scan-history deletion: the entry pending a confirm, and the in-flight id.
  const [pendingDeleteEntry, setPendingDeleteEntry] = useState<HistoryEntry | null>(null);
  const [deletingScanId, setDeletingScanId] = useState<string | null>(null);
  const [terminalPaused, setTerminalPaused] = useState(false);
  const [terminalPinned, setTerminalPinned] = useState(false);
  const [copiedLogs, setCopiedLogs] = useState(false);
  const [scanStartedAt, setScanStartedAt] = useState<number | null>(null);
  const [agents, setAgents] = useState<CollectorAgent[]>([]);
  const [agentEvidence, setAgentEvidence] = useState<ScannerEvidenceRow[]>([]);
  const [agentAlerts, setAgentAlerts] = useState<ScannerAlertRow[]>([]);
  const [connectors, setConnectors] = useState<ConnectorAccount[]>([]);
  const [patchOptionGroups, setPatchOptionGroups] = useState<PatchOptionGroup[]>([]);
  const [operatorActions, setOperatorActions] = useState<OperatorAction[]>([]);
  const [agentsLoading, setAgentsLoading] = useState(false);
  const [agentsError, setAgentsError] = useState<string | null>(null);
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);
  const [oneTimeAgentToken, setOneTimeAgentToken] = useState<OneTimeAgentToken>(null);
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);
  const [isAgentSetupWorkflowOpen, setIsAgentSetupWorkflowOpen] = useState(false);
  const [isInstallationCommandsOpen, setIsInstallationCommandsOpen] = useState(false);
  const [isSecurityNotesOpen, setIsSecurityNotesOpen] = useState(false);
  const [isTroubleshootingOpen, setIsTroubleshootingOpen] = useState(false);
  const [settingsApplyMode, setSettingsApplyMode] = useState<'selected' | 'all'>('selected');
  const [settingsSaving, setSettingsSaving] = useState(false);
  const [agentSyncConnected, setAgentSyncConnected] = useState(false);
  const [agentSyncLastEventAt, setAgentSyncLastEventAt] = useState<string | null>(null);
  const [agentForm, setAgentForm] = useState<AgentFormState>({
    name: 'Production Collector Agent',
    environment: 'production',
    enabled: true,
    allowedTargets: 'https://api.customer.com\napi.customer.com:443\nssh://server.customer.com:22',
    allowedPaths: 'C:\\Apps\\CustomerApi\\config\nC:\\nginx\\conf\n/opt/customer-api/config\n/etc/nginx/sites-enabled',
    intervalSeconds: '60',
    scanTypes: DEFAULT_AGENT_SCAN_TYPES,
    alertThreshold: 'moderate',
  });
  const [connectorForm, setConnectorForm] = useState<ConnectorFormState>({
    provider: 'kubernetes',
    displayName: 'Production Kubernetes Connector',
    scopes: 'kubernetes:read\nkubernetes:patch:ingress\nkubernetes:patch:cert-manager\nkubernetes:patch:service-mesh\ncloud:read\ncloud:patch:load-balancer\ncloud:patch:kms\nweb:patch:tls\nsaas:patch:certificate',
    allowedTargets: 'https://api.customer.com\nnamespace/default/ingress/customer-api\narn:aws:elasticloadbalancing:region:acct:listener/app/app-lb/listener-id\n/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/app-gw',
    allowedPaths: '/etc/kubernetes/manifests\n/repos/customer-api\n/opt/customer-api/config',
    sdkPatchEnabled: false,
    credentialMode: 'provider-default-chain',
    region: 'us-east-1',
    subscriptionId: '',
    projectId: '',
  });
  const [operatorPatchForm, setOperatorPatchForm] = useState<OperatorPatchFormState>({
    assetClass: 'kubernetes',
    optionId: 'k8s-ingress-tls-profile',
    connectorId: '',
    target: 'https://api.customer.com',
    migrationJobId: '',
    dryRun: true,
    payloadJson: '{\n  "sslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06",\n  "certificateArn": "",\n  "kmsKeyId": "",\n  "caCertificateIdentifier": "",\n  "sslPolicyName": "",\n  "kmsKeyName": ""\n}',
  });
  const [operatorEvidenceJson, setOperatorEvidenceJson] = useState('[\n  {\n    "evidenceType": "tls-protocol",\n    "assetName": "api.customer.com",\n    "target": "https://api.customer.com",\n    "host": "api.customer.com",\n    "port": 443,\n    "protocol": "TLS",\n    "observedAlgorithm": "TLS-1.3",\n    "rawEvidence": { "operatorValidation": true, "hndlRisk": false }\n  }\n]');
  const detectedMitigationScanTypes = useMemo(() => {
    const findingSource = findings.length > 0
      ? findings
      : history.flatMap((entry) => normalizeDashboardFindings(entry.findings));
    return detectedMitigationScanTypesFromData(findingSource, agentEvidence, agentAlerts);
  }, [agentAlerts, agentEvidence, findings, history]);
  const detectedMitigationScanTypeKey = detectedMitigationScanTypes.join('|');
  const detectedAgentScanTypeOptions = useMemo(
    () => AGENT_SCAN_TYPE_OPTIONS.filter((item) => detectedMitigationScanTypes.includes(item.id)),
    [detectedMitigationScanTypeKey],
  );
  const abortRef = useRef<AbortController | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);
  /* Bumped by "New Scan" — the hero watches it and wipes the visualization
     engine, which owns state this component cannot reach into. */
  const [heroResetSignal, setHeroResetSignal] = useState(0);
  /** True once the persisted session has been restored (or found absent). */
  const sessionRestored = useRef(false);
  /** Scroll offset from the restored session, applied after the first paint. */
  const pendingScrollY = useRef<number | null>(null);

  useEffect(() => {
    setAgentForm((current) => {
      if (current.scanTypes.join('|') === detectedMitigationScanTypeKey) return current;
      return { ...current, scanTypes: detectedMitigationScanTypes };
    });
  }, [detectedMitigationScanTypeKey]);

  const isRunning = status === 'queued' || status === 'running' || status === 'analyzing';

  const authHeaders = useCallback(() => {
    if (!session?.access_token) return null;
    return { Authorization: `Bearer ${session.access_token}` };
  }, [session?.access_token]);

  const addLog = useCallback((entry: Omit<LogEntry, 'timestamp'> & { timestamp?: string }) => {
    setLogs((prev) => [
      ...prev.slice(-499),
      {
        timestamp: entry.timestamp || new Date().toISOString(),
        level: entry.level,
        message: entry.message,
        phase: entry.phase,
        severity: entry.severity,
        elapsed: entry.elapsed || formatElapsed(scanStartedAt, entry.timestamp),
        moduleName: entry.moduleName,
      },
    ]);
  }, [scanStartedAt]);

  const fetchHistory = useCallback(async () => {
    const headers = authHeaders();
    if (!headers) return;
    setHistoryLoading(true);
    try {
      const res = await fetch('/api/v1/scanner/history', { headers });
      const json = await res.json();
      if (!res.ok) throw new Error(json?.error?.message || 'Unable to load scan history');
      setHistory(json?.data?.history || []);
    } catch (err) {
      addLog({ level: 'ERROR', message: err instanceof Error ? err.message : 'History load failed' });
    } finally {
      setHistoryLoading(false);
    }
  }, [addLog, authHeaders]);

  // Permanently delete one scan (history entry) and every record it produced —
  // backend cascade + optimistic frontend removal + intelligence refresh.
  const deleteHistoryEntry = useCallback(async (scanId: string) => {
    const headers = authHeaders();
    if (!headers) {
      showToast('Your session expired — sign in again to delete scans.');
      return;
    }
    setDeletingScanId(scanId);
    try {
      const res = await fetch(`/api/v1/scanner/history/${encodeURIComponent(scanId)}`, {
        method: 'DELETE',
        headers,
      });
      const json = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(json?.error?.message || 'Failed to delete scan.');

      // Frontend removal — drop the entry and clear selection if it was active.
      setHistory((prev) => prev.filter((entry) => entry.scanId !== scanId));
      setSelectedHistoryId((prev) => (prev === scanId ? null : prev));
      setPendingDeleteEntry(null);

      const removed = (json?.data?.removed || {}) as Record<string, number>;
      const totalRemoved = Object.values(removed).reduce((sum, value) => sum + (typeof value === 'number' ? value : 0), 0);
      addLog({ level: 'INFO', message: `Deleted scan ${scanId} and ${totalRemoved} associated record(s) across the platform.` });
      showToast('Scan and all its data were permanently deleted.');

      // Recompute every intelligence-derived view (CBOM, assets, exposure map).
      void scannerIntel.refresh?.();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Delete failed';
      addLog({ level: 'ERROR', message });
      showToast(message);
    } finally {
      setDeletingScanId(null);
    }
  }, [addLog, authHeaders, scannerIntel, showToast]);

  // Merge the central Scanner Intelligence history into the local scan history so
  // every persisted scan session shows up in the History tab — even ones that
  // predate the local fetch or arrive via the intelligence SSE stream. Fresher
  // local/live entries always win (dedupe by scanId); never clobbers them.
  useEffect(() => {
    const intelHistory = scannerIntel.data?.history?.history;
    if (!Array.isArray(intelHistory) || intelHistory.length === 0) return;
    setHistory((prev) => {
      const seen = new Set(prev.map((entry) => entry.scanId));
      const additions = intelHistory.filter((entry: HistoryEntry) => entry?.scanId && !seen.has(entry.scanId));
      if (additions.length === 0) return prev;
      return [...prev, ...additions].sort(
        (a, b) => Date.parse(b.startedAt || b.completedAt || '') - Date.parse(a.startedAt || a.completedAt || ''),
      );
    });
    // Keyed on the snapshot timestamp to avoid array-identity churn on every poll.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scannerIntel.data?.generatedAt]);

  const fetchAgents = useCallback(async () => {
    const headers = authHeaders();
    if (!headers) return;
    setAgentsLoading(true);
    setAgentsError(null);
    try {
      const [agentsRes, evidenceRes, alertsRes, patchOptionsRes, operatorActionsRes] = await Promise.all([
        fetch('/api/v1/agent-scanner/agents', { headers }),
        fetch('/api/v1/agent-scanner/evidence', { headers }),
        fetch('/api/v1/agent-scanner/alerts', { headers }),
        fetch('/api/v1/agent-scanner/remediation/patch-options', { headers }),
        fetch('/api/v1/agent-scanner/remediation/operator-actions', { headers }),
      ]);
      const agentsJson = await agentsRes.json();
      const evidenceJson = await evidenceRes.json();
      const alertsJson = await alertsRes.json();
      const patchOptionsJson = await patchOptionsRes.json();
      const operatorActionsJson = await operatorActionsRes.json();
      if (!agentsRes.ok) throw new Error(agentsJson?.error?.message || 'Unable to load collector agents');
      if (!evidenceRes.ok) throw new Error(evidenceJson?.error?.message || 'Unable to load collector evidence');
      if (!alertsRes.ok) throw new Error(alertsJson?.error?.message || 'Unable to load collector alerts');
      if (!patchOptionsRes.ok) throw new Error(patchOptionsJson?.error?.message || 'Unable to load remediation patch options');
      if (!operatorActionsRes.ok) throw new Error(operatorActionsJson?.error?.message || 'Unable to load remediation operator actions');
      const nextAgents = agentsJson?.data?.agents || [];
      setAgents(nextAgents);
      setAgentEvidence(evidenceJson?.data?.evidence || []);
      setAgentAlerts(alertsJson?.data?.alerts || []);
      setPatchOptionGroups(patchOptionsJson?.data?.options || []);
      setConnectors(patchOptionsJson?.data?.connectors || []);
      setOperatorActions(operatorActionsJson?.data?.actions || []);
      setSelectedAgentId((current) => current || nextAgents[0]?.id || null);
      setOperatorPatchForm((current) => {
        const currentGroup = (patchOptionsJson?.data?.options || []).find((group: PatchOptionGroup) => group.assetClass === current.assetClass);
        const optionStillExists = currentGroup?.options?.some((option: PatchOption) => option.id === current.optionId);
        return {
          ...current,
          optionId: optionStillExists ? current.optionId : currentGroup?.options?.[0]?.id || current.optionId,
          connectorId: current.connectorId || patchOptionsJson?.data?.connectors?.[0]?.id || '',
        };
      });
    } catch (err) {
      setAgentsError(err instanceof Error ? err.message : 'Collector agents load failed');
    } finally {
      setAgentsLoading(false);
    }
  }, [authHeaders]);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  // Agent Collector data + live SSE now live entirely inside the self-contained
  // AgentCollectorConsole / AgentSettingsConsole (via the useAgentCollector
  // hook), so ScannerDashboard no longer loads collector state or opens a
  // second agent-scanner SSE connection — that would duplicate the stream.

  // A Basic user who deep-links ?tab=agents is bounced to the scanner tab once
  // the entitlement resolves (the tab is also hidden from the tab bar below).
  useEffect(() => {
    if (activeTab === 'agents' && !canUseAgents && !subscription.loading) {
      setActiveTab('setup');
    }
  }, [activeTab, canUseAgents, subscription.loading]);

  useEffect(() => {
    const scopedHistory = filterHistoryByTimeframe(history, historyTimeframe);
    if (scopedHistory.length === 0) {
      setSelectedHistoryId(null);
      return;
    }
    if (!selectedHistoryId || !scopedHistory.some((entry) => entry.scanId === selectedHistoryId)) {
      setSelectedHistoryId(scopedHistory[0].scanId);
    }
  }, [history, historyTimeframe, selectedHistoryId]);

  useEffect(() => {
    if (!user?.id || typeof window === 'undefined') return;
    try {
      const stored = window.localStorage.getItem(`qguard:scheduled-scans:${user.id}`);
      const parsed = stored ? JSON.parse(stored) : [];
      setScheduledScans(Array.isArray(parsed) ? parsed : []);
    } catch {
      setScheduledScans([]);
    }
  }, [user?.id]);

  useEffect(() => {
    if (!terminalPaused && terminalPinned) logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs.length, terminalPaused, terminalPinned]);

  /* ── Session restore ───────────────────────────────────────────────────────
     Runs once per signed-in user, before the first checkpoint can be written.
     Everything here came from the scanner; nothing is reconstructed. */
  useEffect(() => {
    if (!user?.id || sessionRestored.current) return;
    const snapshot = loadScannerSession(user.id);
    sessionRestored.current = true;
    if (!snapshot) return;

    setStatus(restoreStatus(snapshot));
    setProgress(snapshot.progress);
    setJobId(snapshot.jobId);
    setScanStartedAt(snapshot.scanStartedAt);
    setSummary(snapshot.summary);
    setFindings(snapshot.findings);
    setModules(snapshot.modules);
    setModuleLedger(snapshot.moduleLedger);
    setScanResults(snapshot.scanResults);
    setScanner2(snapshot.scanner2);
    setLogs(snapshot.logs);
    setError(snapshot.error);
    setTargets(snapshot.targets as ValidatedAsset[]);
    setAuthorizationAccepted(snapshot.authorizationAccepted);
    setInputText(snapshot.inputText);
    setSevFilter(snapshot.sevFilter);
    setSearchQ(snapshot.searchQ);
    setExpandedFinding(snapshot.expandedFinding);
    setHistoryTimeframe(snapshot.historyTimeframe);
    setSelectedHistoryId(snapshot.selectedHistoryId);
    setTerminalPaused(snapshot.terminalPaused);
    setTerminalPinned(snapshot.terminalPinned);
    // A deep-link (?tab=) is the user's more recent intent than the checkpoint.
    if (!requestedTab) setActiveTab(snapshot.activeTab);
    pendingScrollY.current = snapshot.scrollY;

    /* A run that was still streaming when the page was left kept running on
       the server; only the client stopped listening. Say so, and pull the
       authoritative record rather than inventing an outcome. */
    if (snapshot.wasStreaming) {
      setLogs((prev) => [
        ...prev,
        {
          timestamp: new Date().toISOString(),
          level: 'WARN',
          message:
            'Live telemetry stream was detached when this page was reloaded. The scan continues on the server — its completed record appears in History.',
        },
      ]);
      void fetchHistory();
    }
    // Restore is a one-shot bound to the signed-in user.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id]);

  /* Restore the scroll offset once the restored content has been laid out. */
  useEffect(() => {
    if (pendingScrollY.current === null) return;
    const target = pendingScrollY.current;
    pendingScrollY.current = null;
    if (target <= 0) return;
    const frame = window.requestAnimationFrame(() => window.scrollTo({ top: target }));
    return () => window.cancelAnimationFrame(frame);
  }, [status, findings.length]);

  /* ── Session checkpoint ────────────────────────────────────────────────────
     Written on every material change so leaving the page — by navigation, by
     reload, or by closing the laptop — never costs the assessment on screen. */
  useEffect(() => {
    if (!user?.id || !sessionRestored.current) return;
    const hasSomethingToKeep =
      status !== 'idle' ||
      findings.length > 0 ||
      modules.length > 0 ||
      targets.length > 0 ||
      logs.length > 0 ||
      Boolean(summary);
    if (!hasSomethingToKeep) return;

    saveScannerSession(user.id, {
      status,
      progress,
      jobId,
      scanStartedAt,
      summary,
      findings,
      modules,
      moduleLedger,
      scanResults,
      scanner2,
      logs,
      error,
      wasStreaming: isRunning,
      targets,
      authorizationAccepted,
      inputText,
      activeTab,
      sevFilter,
      searchQ,
      expandedFinding,
      historyTimeframe,
      selectedHistoryId,
      terminalPaused,
      terminalPinned,
      scrollY: typeof window === 'undefined' ? 0 : window.scrollY,
    });
  }, [
    user?.id,
    status,
    progress,
    jobId,
    scanStartedAt,
    summary,
    findings,
    modules,
    moduleLedger,
    scanResults,
    scanner2,
    logs,
    error,
    isRunning,
    targets,
    authorizationAccepted,
    inputText,
    activeTab,
    sevFilter,
    searchQ,
    expandedFinding,
    historyTimeframe,
    selectedHistoryId,
    terminalPaused,
    terminalPinned,
  ]);

  const handleParseInput = () => {
    const parsed = parseAssetInput(inputText);
    const valid = parsed.filter((item) => item.valid);
    const invalid = parsed.filter((item) => !item.valid);
    setTargets(deduplicateAssets([...targets, ...valid]));
    setInputText('');
    if (invalid.length) {
      addLog({ level: 'WARN', message: `${invalid.length} invalid target(s) were skipped during local validation` });
    }
  };

  const handleStart = useCallback(async () => {
    const headers = authHeaders();
    if (!headers || !user) {
      setError('Sign in before starting an authorized scan.');
      return;
    }
    if (!authorizationAccepted) {
      setError('Confirm authorization for every submitted target before scanning.');
      return;
    }
    if (isRunning || targets.length === 0) return;

    const startedAtMs = Date.now();
    setError(null);
    setSummary(null);
    setFindings([]);
    setLogs([]);
    setModules([]);
    setModuleLedger(null);
    setScanResults([]);
    setScanner2(null);
    setProgress(0);
    setJobId(null);
    setCopiedLogs(false);
    setTerminalPaused(false);
    setTerminalPinned(false);
    setScanStartedAt(startedAtMs);
    setStatus('queued');
    // The hero visualization sits above the tab strip and is visible from every
    // tab, so a run no longer needs to steal the user's current view.
    addLog({ level: 'INFO', message: 'Scan job created', elapsed: '00:00' });

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const params = new URLSearchParams({
        authorized: 'true',
        targets: JSON.stringify(targets.map((target) => target.normalized || target.raw)),
      });
      const response = await fetch(`/api/v1/scanner/stream?${params.toString()}`, {
        headers,
        signal: controller.signal,
      });

      if (!response.ok || !response.body) {
        const json = await response.json().catch(() => null);
        throw new Error(json?.error?.message || `Scanner request failed (${response.status})`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const chunks = buffer.split('\n\n');
        buffer = chunks.pop() || '';

        for (const chunk of chunks) {
          const line = chunk.split('\n').find((item) => item.startsWith('data: '));
          if (!line) continue;
          const event = JSON.parse(line.slice(6));
          if (event.jobId) setJobId(event.jobId);
          if (typeof event.progress === 'number') setProgress(Math.max(0, Math.min(100, event.progress)));
          if (event.status) setStatus(event.status);
          if (Array.isArray(event.moduleCatalog)) setModules(event.moduleCatalog);
          if (Array.isArray(event.modules) && event.type === 'module-catalog') setModules(event.modules);
          if (event.type === 'module-state' && event.module) {
            setModules((prev) => {
              const incoming = event.module as ModuleState;
              const exists = prev.some((module) => module.id === incoming.id);
              return exists
                ? prev.map((module) => module.id === incoming.id ? { ...module, ...incoming } : module)
                : [...prev, incoming];
            });
          }

          const message = event.message || event.label || event.moduleName || event.type || 'Scanner event';
          addLog({
            timestamp: event.timestamp,
            level: event.type === 'finding-detected'
              ? event.severity === 'CRITICAL' || event.severity === 'HIGH' ? 'WARN' : event.severity === 'SAFE' ? 'SUCCESS' : 'INFO'
              : statusToLevel(String(event.type || ''), event.status),
            message,
            phase: event.phase,
            severity: event.severity,
            moduleName: event.moduleName || event.module?.name,
            elapsed: formatElapsed(startedAtMs, event.timestamp),
          });

          if (event.finding) {
            setFindings((prev) => prev.some((finding) => finding.id === event.finding.id) ? prev : [...prev, event.finding]);
          }
          if (event.type === 'finding-detected' && event.summary) setSummary(event.summary);

          if (Array.isArray(event.results)) {
            const allFindings = event.results.flatMap((result: any) => result.findings || []);
            setFindings(allFindings);
            // The per-target records carry the published risk decomposition and
            // scan confidence the assessment panels read. Captured here rather
            // than re-derived so the page never computes a second opinion.
            setScanResults(event.results as ScanResultRecord[]);
          }
          if (event.enterpriseScanner2) setScanner2(event.enterpriseScanner2 as EnterpriseScanner2);

          if (event.summary) setSummary(event.summary);
          if (Array.isArray(event.moduleStates)) setModules(event.moduleStates);
          if (event.moduleLedger) setModuleLedger(event.moduleLedger as ModuleLedger);

          /* A run is terminal only when the SCANNER says so.
             The nested web scan emits its own per-target `scan-complete`, which
             this reader used to treat as the end of the job — flipping the page
             to "SCAN COMPLETE" while persistence, the Scanner_2 pass and every
             posture module were still running, so half the Discovery Workflow
             rendered as SKIPPED and a partial estate got graded. The backend now
             namespaces those frames, and this guard is the second lock: the
             authoritative frame is the one that carries the scan session id. */
          const isTerminalComplete =
            event.type === 'scan-complete' && event.status === 'completed' && Boolean(event.scanSessionId);
          if (isTerminalComplete) {
            setStatus('completed');
            setProgress(100);
            // Land on the full assessment — the enterprise equivalent of the
            // public scan's results stack.
            setActiveTab('setup');
            // Deliberately not awaited: awaiting a REST round-trip inside the
            // stream reader stalls consumption of frames the backend has
            // already written.
            void fetchHistory();
          }
          if (event.type === 'scan-failed') {
            setStatus('failed');
            setError(event.message || 'Scan failed');
            void fetchHistory();
          }
          if (event.type === 'scan-cancelled') {
            setStatus('cancelled');
            void fetchHistory();
          }
        }
      }
    } catch (err) {
      if ((err as Error).name === 'AbortError') {
        setStatus('cancelled');
        addLog({ level: 'WARN', message: 'Scan stream cancelled by user' });
      } else {
        const message = err instanceof Error ? err.message : 'Scan failed';
        setStatus('failed');
        setError(message);
        addLog({ level: 'ERROR', message });
      }
    } finally {
      abortRef.current = null;
    }
  }, [addLog, authHeaders, authorizationAccepted, fetchHistory, isRunning, targets, user]);

  const handleCancel = useCallback(async () => {
    abortRef.current?.abort();
    if (jobId && session?.access_token) {
      await fetch(`/api/v1/scanner/jobs/${jobId}/cancel`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${session.access_token}` },
      }).catch(() => undefined);
    }
    setStatus('cancelled');
  }, [jobId, session?.access_token]);

  /**
   * New Scan — a controlled application reset.
   *
   * Returns the scanner to its ready-to-scan state without a browser refresh:
   * every derived surface on the page reads from the state cleared here, so the
   * hero cards, Discovery Workflow rail, Executive Summary, findings, charts,
   * timeline, recommendations, telemetry and progress all reset together. The
   * visualization engine holds its own reducer state, which `heroResetSignal`
   * clears.
   *
   * Deliberately NON-DESTRUCTIVE to evidence: every scan is already persisted
   * server-side, so the assessment being cleared remains in History and in
   * CBOM / Assets / Exposure. This clears a view, not a record.
   */
  const handleNewScan = useCallback(() => {
    if (isRunning) {
      showToast('Stop the running scan before starting a new assessment.');
      return;
    }

    setSummary(null);
    setFindings([]);
    setModules([]);
    setModuleLedger(null);
    setScanResults([]);
    setScanner2(null);
    setLogs([]);
    setProgress(0);
    setJobId(null);
    setError(null);
    setScanStartedAt(null);
    setStatus('idle');

    // Queue + composer
    setTargets([]);
    setInputText('');
    setAuthorizationAccepted(false);

    // Review state — filters, expansions, selections, terminal
    setSevFilter(null);
    setSearchQ('');
    setExpandedFinding(null);
    setSelectedHistoryId(null);
    setExpandedHistoryFinding(null);
    setHistoryFindingSearch('');
    setHistorySeverityFilter(null);
    setTerminalPaused(false);
    setTerminalPinned(false);
    setCopiedLogs(false);

    // The visualization engine's own reducer.
    setHeroResetSignal((signal) => signal + 1);

    // The checkpoint must go too, or the next mount restores what was cleared.
    clearScannerSession(user?.id);

    setActiveTab('setup');
    const nextParams = new URLSearchParams(searchParams);
    nextParams.delete('tab');
    setSearchParams(nextParams, { replace: true });
    window.scrollTo({ top: 0, behavior: 'smooth' });

    showToast('Scanner reset. Previous results remain available in History.');
  }, [isRunning, searchParams, setSearchParams, showToast, user?.id]);

  const handleCopyLogs = useCallback(async () => {
    const text = serializeLogs(logs);
    try {
      await navigator.clipboard.writeText(text);
      setCopiedLogs(true);
      setTimeout(() => setCopiedLogs(false), 1500);
    } catch {
      addLog({ level: 'ERROR', message: 'Unable to copy logs to clipboard' });
    }
  }, [addLog, logs]);

  const handleDownloadReport = useCallback(() => {
    const payload = {
      generatedAt: new Date().toISOString(),
      status,
      progress,
      jobId,
      summary,
      modules,
      findings,
      logs,
      targets,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `qguard-scan-report-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }, [findings, jobId, logs, modules, progress, status, summary, targets]);

  const handleOpenSchedule = useCallback(() => {
    setScheduleDate((value) => value || dateInputFor(1));
    setScheduleTime((value) => value || '02:00');
    setScheduleOpen(true);
  }, []);

  const handleSaveSchedule = useCallback(() => {
    const scheduledAt = new Date(`${scheduleDate}T${scheduleTime || '00:00'}:00`);
    if (!scheduleDate || Number.isNaN(scheduledAt.getTime())) {
      showToast('Select a valid scan date.');
      return;
    }
    if (scheduledAt.getTime() <= Date.now()) {
      showToast('Select a future scan date and time.');
      return;
    }

    const scheduledTargets = targets.length > 0
      ? targets.map((target) => target.normalized || target.raw)
      : history[0]?.target
        ? [history[0].target]
        : [];

    if (scheduledTargets.length === 0) {
      showToast('Add an authorized target before scheduling.');
      return;
    }

    const nextSchedule: ScheduledScan = {
      id: `scheduled-${Date.now()}`,
      scheduledFor: scheduledAt.toISOString(),
      createdAt: new Date().toISOString(),
      status: 'scheduled',
      targets: scheduledTargets,
    };

    setScheduledScans((prev) => {
      const next = [nextSchedule, ...prev].slice(0, 20);
      if (user?.id && typeof window !== 'undefined') {
        window.localStorage.setItem(`qguard:scheduled-scans:${user.id}`, JSON.stringify(next));
      }
      return next;
    });
    setScheduleOpen(false);
    showToast(`Scan scheduled for ${scheduledAt.toLocaleString()}.`);
  }, [history, scheduleDate, scheduleTime, showToast, targets, user?.id]);

  const handleToggleTimeframe = useCallback(async () => {
    setActiveTab('history');
    setHistoryTimeframe((prev) => {
      const next = prev === 'all' ? 'last7' : 'all';
      showToast(next === 'all' ? 'Showing all recorded scans.' : 'Showing scans from the last 7 days.');
      return next;
    });
    await fetchHistory();
  }, [fetchHistory, showToast]);

  const handleExportScannerReport = useCallback(() => {
    const scopedHistory = filterHistoryByTimeframe(history, historyTimeframe);
    const generatedAt = new Date().toISOString();
    const latestHistory = scopedHistory[0] || history[0] || null;
    const exportSummary = summary || latestHistory?.summary || null;
    const liveFindings = normalizeDashboardFindings(findings);
    const persistedFindingRows = scopedHistory.flatMap((entry) =>
      normalizeDashboardFindings(entry.findings).map((finding) => ({
        scanId: entry.scanId,
        target: entry.target,
        startedAt: entry.startedAt,
        completedAt: entry.completedAt || '',
        finding,
      }))
    );
    const liveFindingRows = liveFindings.map((finding) => ({
      scanId: jobId || 'live-session',
      target: targets.map((target) => target.normalized || target.raw).join('; ') || latestHistory?.target || '',
      startedAt: scanStartedAt ? new Date(scanStartedAt).toISOString() : generatedAt,
      completedAt: status === 'completed' ? generatedAt : '',
      finding,
    }));
    const findingRows = liveFindingRows.length > 0 ? liveFindingRows : persistedFindingRows;

    if (!exportSummary && findingRows.length === 0 && scopedHistory.length === 0 && logs.length === 0) {
      showToast('No scanner data is available to export yet.');
      return;
    }

    const rows: unknown[][] = [
      ['QGuard Scanner Report'],
      ['Generated At', generatedAt],
      ['Timeframe', historyTimeframe === 'last7' ? 'Last 7 days' : 'All recorded scans'],
      [],
      ['SUMMARY'],
      ['Total Assets Scanned', 'Total Findings', 'Critical', 'High', 'Medium', 'Low', 'Safe', 'Vulnerable', 'PQC Ready', 'Risk Score', 'Q Score'],
      [
        exportSummary?.targetsScanned ?? '',
        exportSummary?.totalFindings ?? findingRows.length,
        exportSummary?.critical ?? '',
        exportSummary?.high ?? '',
        exportSummary?.medium ?? '',
        exportSummary?.low ?? '',
        exportSummary?.safe ?? '',
        exportSummary?.vulnerable ?? '',
        exportSummary?.pqcReady ?? '',
        exportSummary?.riskScore ?? '',
        exportSummary?.qScore ?? '',
      ],
      [],
      ['FINDINGS'],
      ['Scan ID', 'Target', 'Started At', 'Completed At', 'Algorithm', 'Category', 'Location', 'Threat Level', 'Status', 'Source', 'Evidence', 'Recommendation', 'PQC Replacement'],
      ...findingRows.map((row) => [
        row.scanId,
        row.target,
        row.startedAt,
        row.completedAt,
        row.finding.algorithm,
        row.finding.category,
        row.finding.location,
        row.finding.threatLevel,
        row.finding.status,
        row.finding.source,
        row.finding.evidence,
        row.finding.recommendation,
        row.finding.pqcReplacement || '',
      ]),
      [],
      ['SCAN HISTORY'],
      ['Scan ID', 'Target', 'Started At', 'Completed At', 'Status', 'Components', 'Vulnerable', 'PQC Ready', 'Risk Score', 'Q Score'],
      ...scopedHistory.map((entry) => [
        entry.scanId,
        entry.target,
        entry.startedAt,
        entry.completedAt || '',
        entry.status,
        entry.detectedComponents,
        entry.vulnerableFindings,
        entry.pqcReadyFindings,
        entry.riskScore ?? '',
        entry.qScore ?? '',
      ]),
      [],
      ['TELEMETRY'],
      ['Timestamp', 'Level', 'Module', 'Severity', 'Message'],
      ...logs.map((entry) => [
        entry.timestamp,
        entry.level,
        entry.moduleName || entry.phase || '',
        entry.severity || '',
        entry.message,
      ]),
    ];
    const csv = rows.map((row) => row.map(csvCell).join(',')).join('\n');
    const stamp = generatedAt.replace(/[:.]/g, '-');
    downloadTextFile(`qguard-scanner-report-${stamp}.csv`, csv, 'text/csv;charset=utf-8');
    showToast(`Exported ${findingRows.length} finding(s) and ${scopedHistory.length} scan record(s).`);
  }, [findings, history, historyTimeframe, jobId, logs, scanStartedAt, showToast, status, summary, targets]);

  const handleClearTerminal = useCallback(() => {
    if (isRunning) return;
    setLogs([]);
    setCopiedLogs(false);
  }, [isRunning]);

  const copyPlainText = useCallback(async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedCommand(key);
      setTimeout(() => setCopiedCommand(null), 1600);
    } catch {
      setAgentsError('Unable to copy to clipboard');
    }
  }, []);

  const agentPolicyFromForm = useCallback(() => ({
    enabled: agentForm.enabled,
    intervalSeconds: Math.max(30, Math.min(60, Number(agentForm.intervalSeconds || 60))),
    allowedTargets: agentForm.allowedTargets.split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean),
    allowedPaths: agentForm.allowedPaths.split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean),
    scanTypes: agentForm.scanTypes,
    alertThreshold: agentForm.alertThreshold,
  }), [agentForm]);

  const handleCreateAgent = useCallback(async () => {
    const headers = authHeaders();
    if (!headers) {
      setAgentsError('Sign in before creating a collector agent.');
      return;
    }
    setAgentsLoading(true);
    setAgentsError(null);
    try {
      const response = await fetch('/api/v1/agent-scanner/agents/enroll', {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: agentForm.name,
          environment: agentForm.environment,
          hostname: 'pending-customer-install',
          platform: 'customer-managed',
          version: '0.1.0',
          capabilities: Object.fromEntries(agentForm.scanTypes.map((scanType) => [scanType, true])),
          policy: agentPolicyFromForm(),
          metadata: { environment: agentForm.environment, source: 'dashboard-agent-collector-tab' },
        }),
      });
      const json = await response.json();
      if (!response.ok) throw new Error(json?.error?.message || 'Unable to create collector agent');
      const agentId = json?.data?.enrollment?.agentId;
      const token = json?.data?.enrollment?.agentToken;
      if (agentId && token) {
        setOneTimeAgentToken({ agentId, token, createdAt: new Date().toISOString(), mode: 'created' });
        setSelectedAgentId(agentId);
      }
      await fetchAgents();
    } catch (err) {
      setAgentsError(err instanceof Error ? err.message : 'Collector agent creation failed');
    } finally {
      setAgentsLoading(false);
    }
  }, [agentForm, agentPolicyFromForm, authHeaders, fetchAgents]);

  const connectorPolicyFromForm = useCallback(() => ({
    enabled: true,
    intervalSeconds: 60,
    allowedTargets: connectorForm.allowedTargets.split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean),
    allowedPaths: connectorForm.allowedPaths.split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean),
    scanTypes: agentForm.scanTypes,
    alertThreshold: 'moderate',
  }), [agentForm.scanTypes, connectorForm.allowedPaths, connectorForm.allowedTargets]);

  const handleCreateConnector = useCallback(async () => {
    const headers = authHeaders();
    if (!headers) {
      setAgentsError('Sign in before creating a connector.');
      return;
    }
    setAgentsLoading(true);
    setAgentsError(null);
    try {
      const scopes = connectorForm.scopes.split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean);
      const response = await fetch('/api/v1/agent-scanner/connectors', {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: connectorForm.provider,
          displayName: connectorForm.displayName,
          scopes,
          capabilities: {
            ...Object.fromEntries(scopes.map((scope) => [scope, true])),
            localCollectorRelationship: 'Collectors discover and validate local/external assets; remote mutation uses connector credentials and operator approval.',
            supportedEnvironments: SUPPORTED_ENVIRONMENT_GROUPS.map((group) => group.title),
            sdkPatchEnabled: connectorForm.sdkPatchEnabled,
            sdkPatchAdapters: ['aws-sdk', 'azure-sdk', 'gcp-sdk'],
          },
          policy: connectorPolicyFromForm(),
          metadata: {
            source: 'dashboard-operator-patch-workflow',
            connectorMode: 'operator-approved',
            sdkPatchEnabled: connectorForm.sdkPatchEnabled,
            credentialMode: connectorForm.credentialMode,
            region: connectorForm.region,
            awsRegion: connectorForm.region,
            subscriptionId: connectorForm.subscriptionId,
            projectId: connectorForm.projectId,
            supportedEnvironments: SUPPORTED_ENVIRONMENT_GROUPS.map((group) => group.title),
            credentialBoundary: 'least-privilege customer-authorized provider credentials',
          },
        }),
      });
      const json = await response.json();
      if (!response.ok) throw new Error(json?.error?.message || 'Unable to create connector');
      const connectorId = json?.data?.connector?.id || '';
      setOperatorPatchForm((current) => ({ ...current, connectorId: connectorId || current.connectorId }));
      await fetchAgents();
      showToast('Connector registered for operator-approved remediation.');
    } catch (err) {
      setAgentsError(err instanceof Error ? err.message : 'Connector creation failed');
    } finally {
      setAgentsLoading(false);
    }
  }, [authHeaders, connectorForm, connectorPolicyFromForm, fetchAgents, showToast]);

  const handleCreateOperatorAction = useCallback(async () => {
    const headers = authHeaders();
    if (!headers) {
      setAgentsError('Sign in before creating an operator patch action.');
      return;
    }
    setAgentsLoading(true);
    setAgentsError(null);
    try {
      let patchPayload: Record<string, unknown> = {};
      try {
        patchPayload = operatorPatchForm.payloadJson.trim() ? JSON.parse(operatorPatchForm.payloadJson) : {};
      } catch {
        throw new Error('Operator patch payload must be valid JSON.');
      }
      const response = await fetch('/api/v1/agent-scanner/remediation/operator-actions', {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          assetClass: operatorPatchForm.assetClass,
          optionId: operatorPatchForm.optionId,
          connectorId: operatorPatchForm.connectorId || undefined,
          target: operatorPatchForm.target,
          jobId: operatorPatchForm.migrationJobId || undefined,
          approvalMode: 'operator_approved',
          status: 'planned',
          dryRun: operatorPatchForm.dryRun,
          payload: {
            createdFrom: 'Agent Collector Scanners',
            tenant: user?.id,
            ...patchPayload,
          },
        }),
      });
      const json = await response.json();
      if (!response.ok) throw new Error(json?.error?.message || 'Unable to create operator patch action');
      await fetchAgents();
      const blocked = (json?.data?.missingScopes || []).length > 0;
      showToast(blocked ? 'Patch action created but blocked by missing connector scopes.' : 'Patch action created and queued for approval.');
    } catch (err) {
      setAgentsError(err instanceof Error ? err.message : 'Operator patch action failed');
    } finally {
      setAgentsLoading(false);
    }
  }, [authHeaders, fetchAgents, operatorPatchForm, showToast, user?.id]);

  const handleUpdateOperatorAction = useCallback(async (actionId: string, nextStatus: string, options: { execute?: boolean; dryRun?: boolean } = {}) => {
    const headers = authHeaders();
    if (!headers) return;
    setAgentsLoading(true);
    setAgentsError(null);
    try {
      const response = await fetch(`/api/v1/agent-scanner/remediation/operator-actions/${actionId}/status`, {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status: nextStatus,
          execute: options.execute === true,
          dryRun: options.dryRun ?? operatorPatchForm.dryRun,
          message: `Operator marked patch action as ${nextStatus}.`,
        }),
      });
      const json = await response.json();
      if (!response.ok) throw new Error(json?.error?.message || 'Unable to update operator action');
      await fetchAgents();
      const cloudResult = json?.data?.cloudSdkPatchResult;
      if (cloudResult?.status === 'blocked') {
        showToast(`Cloud SDK patch blocked: ${cloudResult.reason || 'review connector readiness'}`);
      } else if (cloudResult?.status === 'dry_run') {
        showToast('Cloud SDK dry run completed; no provider mutation was applied.');
      } else if (cloudResult?.executed) {
        showToast('Cloud SDK patch executed and evidence was recorded.');
      } else {
        showToast(`Patch action marked ${nextStatus}.`);
      }
    } catch (err) {
      setAgentsError(err instanceof Error ? err.message : 'Operator action update failed');
    } finally {
      setAgentsLoading(false);
    }
  }, [authHeaders, fetchAgents, operatorPatchForm.dryRun, showToast]);

  const handleValidateOperatorAction = useCallback(async (actionId: string) => {
    const headers = authHeaders();
    if (!headers) return;
    setAgentsLoading(true);
    setAgentsError(null);
    try {
      let evidence: unknown = [];
      try {
        evidence = JSON.parse(operatorEvidenceJson || '[]');
      } catch {
        throw new Error('Validation evidence must be valid JSON array data.');
      }
      const response = await fetch(`/api/v1/agent-scanner/remediation/operator-actions/${actionId}/status`, {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status: 'validated',
          message: 'Operator submitted post-patch validation evidence.',
          evidence,
        }),
      });
      const json = await response.json();
      if (!response.ok) throw new Error(json?.error?.message || 'Unable to validate operator action');
      await fetchAgents();
      showToast(json?.data?.validation?.passed ? 'Validation passed and remediation can close.' : 'Validation evidence was processed; risk remains under review.');
    } catch (err) {
      setAgentsError(err instanceof Error ? err.message : 'Operator validation failed');
    } finally {
      setAgentsLoading(false);
    }
  }, [authHeaders, fetchAgents, operatorEvidenceJson, showToast]);

  const handleRotateAgentToken = useCallback(async (agentId: string) => {
    const headers = authHeaders();
    if (!headers) return;
    setAgentsLoading(true);
    setAgentsError(null);
    try {
      const response = await fetch(`/api/v1/agent-scanner/agents/${agentId}/token/rotate`, {
        method: 'POST',
        headers,
      });
      const json = await response.json();
      if (!response.ok) throw new Error(json?.error?.message || 'Unable to rotate collector token');
      setOneTimeAgentToken({
        agentId,
        token: json?.data?.agentToken,
        createdAt: json?.data?.rotatedAt || new Date().toISOString(),
        mode: 'rotated',
      });
      await fetchAgents();
    } catch (err) {
      setAgentsError(err instanceof Error ? err.message : 'Token rotation failed');
    } finally {
      setAgentsLoading(false);
    }
  }, [authHeaders, fetchAgents]);

  const handleRevokeAgent = useCallback(async (agentId: string) => {
    const headers = authHeaders();
    if (!headers) return;
    setAgentsLoading(true);
    setAgentsError(null);
    try {
      const response = await fetch(`/api/v1/agent-scanner/agents/${agentId}/revoke`, { method: 'POST', headers });
      const json = await response.json();
      if (!response.ok) throw new Error(json?.error?.message || 'Unable to revoke collector agent');
      await fetchAgents();
    } catch (err) {
      setAgentsError(err instanceof Error ? err.message : 'Collector revoke failed');
    } finally {
      setAgentsLoading(false);
    }
  }, [authHeaders, fetchAgents]);

  const handleDeleteAgent = useCallback(async (agentId: string) => {
    const headers = authHeaders();
    if (!headers) return;
    setAgentsLoading(true);
    setAgentsError(null);
    try {
      const response = await fetch(`/api/v1/agent-scanner/agents/${agentId}`, { method: 'DELETE', headers });
      const json = await response.json();
      if (!response.ok) throw new Error(json?.error?.message || 'Unable to delete collector agent');
      setSelectedAgentId((current) => current === agentId ? null : current);
      await fetchAgents();
    } catch (err) {
      setAgentsError(err instanceof Error ? err.message : 'Collector delete failed');
    } finally {
      setAgentsLoading(false);
    }
  }, [authHeaders, fetchAgents]);

  const handleAssignCurrentScope = useCallback(async (agentId: string) => {
    const headers = authHeaders();
    if (!headers) return;
    setAgentsLoading(true);
    setAgentsError(null);
    try {
      const response = await fetch(`/api/v1/agent-scanner/agents/${agentId}/policy`, {
        method: 'PUT',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify(agentPolicyFromForm()),
      });
      const json = await response.json();
      if (!response.ok) throw new Error(json?.error?.message || 'Unable to assign scan scope');
      await fetchAgents();
    } catch (err) {
      setAgentsError(err instanceof Error ? err.message : 'Scan scope assignment failed');
    } finally {
      setAgentsLoading(false);
    }
  }, [agentPolicyFromForm, authHeaders, fetchAgents]);

  const handleRetryFailedModule = useCallback((module: ModuleState) => {
    addLog({ level: 'WARN', message: `Retry requested for ${module.name}; rerunning the authorized scan for the same target queue.`, moduleName: module.name });
    if (!isRunning) void handleStart();
  }, [addLog, handleStart, isRunning]);

  const handleOpenHistoryInFindings = useCallback((entry: HistoryEntry) => {
    const storedFindings = normalizeDashboardFindings(entry.findings);
    setFindings(storedFindings);
    setSummary(entry.summary || {
      targetsScanned: 1,
      totalFindings: storedFindings.length,
      critical: storedFindings.filter((finding) => finding.threatLevel === 'CRITICAL').length,
      high: storedFindings.filter((finding) => finding.threatLevel === 'HIGH').length,
      medium: storedFindings.filter((finding) => finding.threatLevel === 'MEDIUM').length,
      low: storedFindings.filter((finding) => finding.threatLevel === 'LOW').length,
      safe: storedFindings.filter((finding) => finding.threatLevel === 'SAFE').length,
      vulnerable: storedFindings.filter((finding) => finding.threatLevel !== 'SAFE').length,
      pqcReady: storedFindings.filter((finding) => finding.threatLevel === 'SAFE').length,
      riskScore: entry.riskScore ?? 0,
      qScore: entry.qScore ?? 0,
    });
    setModules(entry.moduleStates || []);
    // Restore the same evidence the live run captured so the assessment panels
    // describe the scan being reviewed rather than the last one that ran.
    setScanResults(entry.results ?? []);
    setScanner2(entry.enterpriseScanner2 ?? null);
    setLogs((entry.telemetry || []).slice(-500).map((event: any) => ({
      timestamp: event.timestamp || entry.startedAt,
      level: statusToLevel(String(event.type || ''), event.status),
      message: String(event.message || event.type || 'Stored scanner event'),
      phase: event.phase,
      severity: event.severity,
      moduleName: event.moduleName || event.module?.name,
      elapsed: formatElapsed(Date.parse(entry.startedAt), event.timestamp),
    })));
    setStatus(entry.status === 'completed' ? 'completed' : 'idle');
    setProgress(100);
    setExpandedFinding(null);
    setActiveTab('findings');
  }, []);

  const handleDownloadHistoryAudit = useCallback((entry: HistoryEntry) => {
    const auditFindings = normalizeDashboardFindings(entry.findings);
    const payload = {
      generatedAt: new Date().toISOString(),
      scanId: entry.scanId,
      target: entry.target,
      scanType: entry.scanType,
      startedAt: entry.startedAt,
      completedAt: entry.completedAt,
      status: entry.status,
      summary: entry.summary,
      findings: auditFindings,
      moduleStates: entry.moduleStates || [],
      telemetry: entry.telemetry || [],
      linkedCbomRecords: entry.linkedCbomRecords || [],
      linkedAssetRecords: entry.linkedAssetRecords || [],
      linkedExposureNodes: entry.linkedExposureNodes || [],
      enterpriseScanner2: entry.enterpriseScanner2 || null,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `qguard-audit-${entry.scanId}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }, []);

  const liveCounts = {
    assets: summary?.targetsScanned ?? 0,
    components: summary?.totalFindings ?? findings.length,
    critical: summary?.critical ?? findings.filter((finding) => finding.threatLevel === 'CRITICAL').length,
    high: summary?.high ?? findings.filter((finding) => finding.threatLevel === 'HIGH').length,
    medium: summary?.medium ?? findings.filter((finding) => finding.threatLevel === 'MEDIUM').length,
    low: summary?.low ?? findings.filter((finding) => finding.threatLevel === 'LOW').length,
    pqcReady: summary?.pqcReady ?? findings.filter((finding) => finding.threatLevel === 'SAFE').length,
    vulnerable: summary?.vulnerable ?? findings.filter((finding) => finding.threatLevel !== 'SAFE').length,
  };
  const showMitigationNextStep = status === 'completed' && liveCounts.vulnerable > 0;

  const displayedHistory = filterHistoryByTimeframe(history, historyTimeframe);
  const historyMetrics = historyMetricSnapshot(displayedHistory);

  /* ── The assessment's evidence set, chosen ONCE ────────────────────────────
     Everything on the results surface — hero counters, Executive Summary,
     Estate Footprint, the findings table — reads from these three bindings, so
     the page cannot describe a live run in one panel and the tenant estate in
     the next. `latestHistoryEntry` is hoisted here (rather than defined beside
     `buildAssessment` further down) precisely so the headline metrics and the
     assessment resolve the same scan. */
  /* ── Only a WEB scan can be this surface's scan-in-view ──────────────────
     `/scanner/history` returns every session this tenant owns, including the
     continuous-agent evidence batches written by `agent-scanner.ts`. Those are
     real evidence, but they carry no targets, no module ledger and no
     per-target results — so adopting one as the scan-in-view produced a page
     that contradicted itself: a graded Encryption Score above a Module
     Execution Flow with nothing in it, a Discovery Coverage of 0% and an
     Assessment Scope with no targets.

     Agent evidence has its own surface (the Agents tab) and still appears in
     History. Here the fallback walks to the newest scan that this page can
     actually describe; if the tenant has none, the assessment falls through to
     estate scope, which is exactly what estate scope is for. */
  const isWebScanEntry = useCallback((entry: HistoryEntry | null | undefined) => {
    if (!entry) return false;
    /* Sessions written before `scannerMode` existed default to the web scanner
       in buildHistoryPayload, so an absent mode is a web scan. */
    return !String(entry.scanType ?? '').startsWith('continuous-agent');
  }, []);

  const latestHistoryEntry =
    displayedHistory.find(isWebScanEntry)
    ?? history.find(isWebScanEntry)
    ?? null;
  const effectiveSummary = summary ?? latestHistoryEntry?.summary ?? null;
  const effectiveScanFindings = findings.length > 0
    ? findings
    : normalizeDashboardFindings(latestHistoryEntry?.findings);

  const currentScanReadiness = effectiveSummary?.totalFindings
    ? Math.round(((effectiveSummary.pqcReady ?? 0) / Math.max(1, effectiveSummary.totalFindings)) * 100)
    : 0;
  // Central-intelligence KPIs — computed from the shared cryptographic tables
  // (assets / inventory / exposures / results / vulnerabilities), never a
  // time-window subset. This is the authoritative headline for the tenant's
  // scanned estate and stays in lock-step with CBOM, Exposure and Readiness.
  const intelSummary = scannerIntel.data.summary;
  const intelHasData =
    intelSummary.totalAssets > 0 || intelSummary.totalFindings > 0 || intelSummary.totalComponents > 0;
  const intelMetrics = {
    totalAssetsScanned: intelSummary.totalAssets,
    vulnerableAssets: intelSummary.vulnerableAssets,
    riskScore: intelSummary.riskScore,
    criticalFindings: intelSummary.criticalFindings,
    pqcReadiness: intelSummary.pqcReadiness,
    totalFindings: intelSummary.totalFindings,
    vulnerableFindings: intelSummary.vulnerableComponents,
    pqcReady: intelSummary.pqcReadyComponents,
  };
  /* Scan scope when an assessment is in view, estate scope otherwise — the same
     rule `buildAssessment` applies, so the hero counters and the Estate
     Footprint panel can never be counting different populations. */
  const dashboardMetrics = effectiveSummary
    ? {
        totalAssetsScanned: effectiveSummary.targetsScanned,
        vulnerableAssets: effectiveSummary.vulnerable > 0 ? Math.max(1, effectiveSummary.targetsScanned) : 0,
        riskScore: effectiveSummary.riskScore,
        criticalFindings: effectiveSummary.critical,
        pqcReadiness: currentScanReadiness,
        totalFindings: effectiveSummary.totalFindings,
        vulnerableFindings: effectiveSummary.vulnerable,
        pqcReady: effectiveSummary.pqcReady,
      }
    : intelHasData
      ? intelMetrics
      : historyMetrics;
  const dashboardRiskLabel = dashboardMetrics.riskScore >= 80
    ? 'Critical Risk'
    : dashboardMetrics.riskScore >= 60
      ? 'High Risk'
      : dashboardMetrics.riskScore >= 40
        ? 'Medium Risk'
        : dashboardMetrics.riskScore > 0
          ? 'Low Risk'
          : 'No Scan Data';
  /* The findings the result panels read.
     When an assessment is in view these are THAT scan's findings — listing
     every finding ever recorded beside a per-scan total is what let the
     Cryptographic Findings table and the Executive Summary disagree by an order
     of magnitude. With no assessment in view the table falls back to the full
     recorded set, which is then what the totals describe too. */
  const dashboardFindings = effectiveSummary
    ? effectiveScanFindings
    : displayedHistory.flatMap((entry) => normalizeDashboardFindings(entry.findings));
  const dashboardSeverityCounts = {
    critical: dashboardFindings.filter((finding) => finding.threatLevel === 'CRITICAL').length,
    high: dashboardFindings.filter((finding) => finding.threatLevel === 'HIGH').length,
    medium: dashboardFindings.filter((finding) => finding.threatLevel === 'MEDIUM').length,
    low: dashboardFindings.filter((finding) => finding.threatLevel === 'LOW').length,
    safe: dashboardFindings.filter((finding) => finding.threatLevel === 'SAFE').length,
  };
  const dashboardSeverityTotal = Math.max(1, Object.values(dashboardSeverityCounts).reduce((sum, value) => sum + value, 0));
  const riskDistributionRows = [
    { label: 'Critical', count: dashboardSeverityCounts.critical, color: '#ef4444' },
    { label: 'High', count: dashboardSeverityCounts.high, color: '#f97316' },
    { label: 'Medium', count: dashboardSeverityCounts.medium, color: '#eab308' },
    { label: 'Low', count: dashboardSeverityCounts.low, color: '#22c55e' },
    { label: 'Secure', count: dashboardSeverityCounts.safe, color: '#06b6d4' },
  ];
  const threatRank: Record<DefensiveFinding['threatLevel'], number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, SAFE: 0 };
  const topVulnerableAlgorithmMap = new Map<string, { algo: string; assets: number; risk: DefensiveFinding['threatLevel'] }>();
  dashboardFindings
    .filter((finding) => finding.threatLevel !== 'SAFE')
    .forEach((finding) => {
      const current = topVulnerableAlgorithmMap.get(finding.algorithm) || { algo: finding.algorithm, assets: 0, risk: finding.threatLevel };
      current.assets += 1;
      if (threatRank[finding.threatLevel] > threatRank[current.risk]) current.risk = finding.threatLevel;
      topVulnerableAlgorithmMap.set(finding.algorithm, current);
    });
  const topVulnerableAlgorithmRows = Array.from(topVulnerableAlgorithmMap.values())
    .sort((a, b) => threatRank[b.risk] - threatRank[a.risk] || b.assets - a.assets)
    .slice(0, 8)
    .map((row) => ({
      ...row,
      color: row.risk === 'CRITICAL' ? 'text-red-400' : row.risk === 'HIGH' ? 'text-orange-400' : row.risk === 'MEDIUM' ? 'text-yellow-400' : 'text-green-400',
    }));
  const nextScheduledScan = scheduledScans
    .filter((scan) => Date.parse(scan.scheduledFor) > Date.now())
    .sort((a, b) => Date.parse(a.scheduledFor) - Date.parse(b.scheduledFor))[0] || null;
  const historyEmptyText = history.length === 0
    ? 'No scans recorded yet — run an authorized scan to build your audit-ready history.'
    : historyTimeframe === 'last7'
      ? 'No scans in the last 7 days. Switch to All Time to see earlier scans.'
      : 'No authorized scan history available.';

  const failedModules = modules.filter((module) => module.status === 'Failed');
  const selectedHistoryEntry = displayedHistory.find((entry) => entry.scanId === selectedHistoryId) || displayedHistory[0] || null;
  const selectedHistoryFindings = normalizeDashboardFindings(selectedHistoryEntry?.findings);
  const selectedHistorySummary = selectedHistoryEntry?.summary || null;
  const historyFindingQuery = historyFindingSearch.trim().toLowerCase();
  const filteredHistoryFindings = selectedHistoryFindings.filter((finding) => {
    const severityMatch = !historySeverityFilter || finding.threatLevel.toLowerCase() === historySeverityFilter;
    const queryMatch = !historyFindingQuery ||
      finding.algorithm.toLowerCase().includes(historyFindingQuery) ||
      finding.category.toLowerCase().includes(historyFindingQuery) ||
      finding.location.toLowerCase().includes(historyFindingQuery) ||
      finding.evidence.toLowerCase().includes(historyFindingQuery) ||
      finding.recommendation.toLowerCase().includes(historyFindingQuery);
    return severityMatch && queryMatch;
  });
  const selectedHistorySeverityCounts = {
    critical: selectedHistorySummary?.critical ?? selectedHistoryFindings.filter((finding) => finding.threatLevel === 'CRITICAL').length,
    high: selectedHistorySummary?.high ?? selectedHistoryFindings.filter((finding) => finding.threatLevel === 'HIGH').length,
    medium: selectedHistorySummary?.medium ?? selectedHistoryFindings.filter((finding) => finding.threatLevel === 'MEDIUM').length,
    low: selectedHistorySummary?.low ?? selectedHistoryFindings.filter((finding) => finding.threatLevel === 'LOW').length,
    safe: selectedHistorySummary?.safe ?? selectedHistoryFindings.filter((finding) => finding.threatLevel === 'SAFE').length,
  };
  const selectedAgent = agents.find((agent) => agent.id === selectedAgentId) || agents[0] || null;
  const tenantId = user?.id || 'tenant_id_here';
  const apiUrlPlaceholder = typeof window !== 'undefined' ? window.location.origin : 'https://api.yourdomain.com';
  const selectedAgentPolicy = normalizeAgentPolicy(selectedAgent?.policy);
  const selectedAgentEvidence = selectedAgent ? agentEvidence.filter((item) => item.agent_id === selectedAgent.id) : [];
  const selectedAgentAlerts = selectedAgent ? agentAlerts.filter((item) => item.agent_id === selectedAgent.id) : [];
  const selectedAgentLastScan = selectedAgentEvidence[0]?.observed_at || selectedAgentEvidence[0]?.created_at || null;
  const onlineAgents = agents.filter(isAgentOnline).length;
  const revokedAgents = agents.filter((agent) => agent.status === 'revoked' || agent.revoked_at).length;
  const unhealthyAgents = agents.filter((agent) => ['degraded', 'unhealthy'].includes(String(agent.status))).length;
  const selectedPatchGroup = patchOptionGroups.find((group) => group.assetClass === operatorPatchForm.assetClass) || patchOptionGroups[0] || { assetClass: 'network_protocol', options: [] };
  const selectedPatchOption = selectedPatchGroup.options.find((option) => option.id === operatorPatchForm.optionId) || selectedPatchGroup.options[0] || null;
  const selectedMandatoryStack = selectedPatchOption?.mandatoryQuantumStack || selectedPatchOption?.executionContract?.mandatoryQuantumStack || MANDATORY_QUANTUM_STACK;
  const selectedConnector = connectors.find((connector) => connector.id === operatorPatchForm.connectorId) || null;
  const connectorScopeSet = new Set((selectedConnector?.scopes || []).map((scope) => scope.toLowerCase()));
  const selectedMissingScopes = selectedPatchOption?.requiredScopes?.filter((scope) => !connectorScopeSet.has(scope.toLowerCase())) || [];
  const operatorActionStats = {
    total: operatorActions.length,
    blocked: operatorActions.filter((action) => ['blocked', 'rejected', 'scheduled'].includes(String(action.status))).length,
    active: operatorActions.filter((action) => ['planned', 'approved', 'applying', 'applied', 'validating'].includes(String(action.status))).length,
    validated: operatorActions.filter((action) => action.status === 'validated').length,
  };
  const openAgentAlerts = agentAlerts.filter((alert) => !['resolved', 'closed', 'suppressed'].includes(String(alert.status || 'open').toLowerCase()));
  const editableAgentPolicy = agentPolicyFromForm();
  const policyScopeCount = editableAgentPolicy.allowedTargets.length + editableAgentPolicy.allowedPaths.length;
  const manageableAgents = agents.filter((agent) => !agent.revoked_at && String(agent.status || '').toLowerCase() !== 'revoked');
  const selectedAgentIsManageable = Boolean(selectedAgent && !selectedAgent.revoked_at && String(selectedAgent.status || '').toLowerCase() !== 'revoked');
  const settingsTargetCount = settingsApplyMode === 'all' ? manageableAgents.length : selectedAgentIsManageable ? 1 : 0;
  const settingsCanSave = settingsTargetCount > 0
    && editableAgentPolicy.scanTypes.length > 0
    && (!editableAgentPolicy.enabled || policyScopeCount > 0);

  const handleLoadSelectedAgentPolicy = useCallback(() => {
    if (!selectedAgent) {
      setAgentsError('Select an agent before loading its policy.');
      return;
    }
    const policy = normalizeAgentPolicy(selectedAgent.policy);
    const matchingScanTypes = policy.scanTypes.filter((scanType) => detectedMitigationScanTypes.includes(scanType));
    setAgentForm((current) => ({
      ...current,
      name: selectedAgent.name || current.name,
      environment: selectedAgent.metadata?.environment || current.environment || 'production',
      enabled: policy.enabled,
      allowedTargets: policy.allowedTargets.join('\n'),
      allowedPaths: policy.allowedPaths.join('\n'),
      intervalSeconds: String(policy.intervalSeconds),
      scanTypes: matchingScanTypes.length > 0 ? matchingScanTypes : detectedMitigationScanTypes,
      alertThreshold: policy.alertThreshold,
    }));
    showToast('Selected agent policy loaded into settings.');
  }, [detectedMitigationScanTypeKey, selectedAgent, showToast]);

  const handleApplyScannerSettings = useCallback(async () => {
    const headers = authHeaders();
    if (!headers) return;
    const targetAgents = settingsApplyMode === 'all'
      ? agents.filter((agent) => !agent.revoked_at && String(agent.status || '').toLowerCase() !== 'revoked')
      : selectedAgent && !selectedAgent.revoked_at && String(selectedAgent.status || '').toLowerCase() !== 'revoked'
        ? [selectedAgent]
        : [];
    const policy = agentPolicyFromForm();

    if (targetAgents.length === 0) {
      setAgentsError('Select an active agent or switch to Apply to all active agents.');
      return;
    }
    if (policy.scanTypes.length === 0 || (policy.enabled && policy.allowedTargets.length + policy.allowedPaths.length === 0)) {
      setAgentsError('Add at least one scan type and one authorized target or path before applying policy.');
      return;
    }

    setSettingsSaving(true);
    setAgentsError(null);
    try {
      await Promise.all(targetAgents.map(async (agent) => {
        const response = await fetch(`/api/v1/agent-scanner/agents/${agent.id}/policy`, {
          method: 'PUT',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify(policy),
        });
        const json = await response.json();
        if (!response.ok) throw new Error(json?.error?.message || `Unable to apply policy to ${agent.name || agent.id}`);
      }));
      await fetchAgents();
      setAgentSyncLastEventAt(new Date().toISOString());
      showToast(`Scanner policy applied to ${targetAgents.length} agent${targetAgents.length === 1 ? '' : 's'}.`);
    } catch (err) {
      setAgentsError(err instanceof Error ? err.message : 'Scanner settings update failed');
    } finally {
      setSettingsSaving(false);
    }
  }, [agentPolicyFromForm, agents, authHeaders, fetchAgents, selectedAgent, settingsApplyMode, showToast]);

  const handleRefreshAgentSettings = useCallback(async () => {
    await fetchAgents();
    setAgentSyncLastEventAt(new Date().toISOString());
    showToast('Scanner settings synchronized.');
  }, [fetchAgents, showToast]);

  const handleAcknowledgeOpenAgentAlerts = useCallback(async () => {
    const headers = authHeaders();
    if (!headers) return;
    if (openAgentAlerts.length === 0) {
      showToast('No open scanner alerts to acknowledge.');
      return;
    }
    setSettingsSaving(true);
    setAgentsError(null);
    try {
      await Promise.all(openAgentAlerts.map(async (alert) => {
        const response = await fetch(`/api/v1/agent-scanner/alerts/${alert.id}/acknowledge`, {
          method: 'POST',
          headers,
        });
        const json = await response.json();
        if (!response.ok) throw new Error(json?.error?.message || 'Unable to acknowledge scanner alert');
      }));
      await fetchAgents();
      showToast(`Acknowledged ${openAgentAlerts.length} scanner alert${openAgentAlerts.length === 1 ? '' : 's'}.`);
    } catch (err) {
      setAgentsError(err instanceof Error ? err.message : 'Alert acknowledgement failed');
    } finally {
      setSettingsSaving(false);
    }
  }, [authHeaders, fetchAgents, openAgentAlerts, showToast]);

  // Findings tab reads from dashboardFindings (live scan results when scanning,
  // otherwise the persisted findings for previously scanned assets) so the tab
  // is never empty when the tenant has recorded scans.
  const filteredFindings = dashboardFindings.filter((finding) => {
    const severity = finding.threatLevel.toLowerCase();
    if (sevFilter && severity !== sevFilter) return false;
    if (!searchQ.trim()) return true;
    const q = searchQ.toLowerCase();
    return [finding.algorithm, finding.category, finding.location, finding.status, finding.evidence]
      .some((value) => String(value || '').toLowerCase().includes(q));
  });



  /* ── Enterprise assessment ───────────────────────────────────────────────
     One derivation, shared by every result panel, so the executive summary,
     the gauge, the surface list and the recommendations can never disagree.
     Falls back from live scan evidence to the tenant-wide Scanner Intelligence
     snapshot — the same snapshot Assets, CBOM, Exposure and Quantum Readiness
     read — which is what keeps this page tallying with the rest of the
     platform between runs. */
  const effectiveResults = scanResults.length > 0
    ? scanResults
    : (latestHistoryEntry?.results ?? []);
  const effectiveScanner2 = scanner2 ?? latestHistoryEntry?.enterpriseScanner2 ?? null;
  const effectiveModules = modules.length > 0 ? modules : (latestHistoryEntry?.moduleStates ?? []);

  const assessment = useMemo(
    () => buildAssessment({
      status,
      summary: effectiveSummary,
      findings: dashboardFindings,
      modules: effectiveModules,
      results: effectiveResults,
      scanner2: effectiveScanner2,
      targets: targets.map((target) => target.normalized || target.raw),
      completedAt: latestHistoryEntry?.completedAt ?? null,
      estate: {
        totalAssets: intelSummary.totalAssets,
        totalFindings: intelSummary.totalFindings,
        criticalFindings: intelSummary.criticalFindings,
        /* Real counts, from the same snapshot every other number here reads.
           Estate scope used to substitute a literal 0 for `high` and to treat
           every finding as vulnerable. */
        highFindings: scannerIntel.data.severityCounts.high,
        vulnerableAssets: intelSummary.vulnerableAssets,
        vulnerableComponents: intelSummary.vulnerableComponents,
        pqcReadiness: intelSummary.pqcReadiness,
        riskScore: intelSummary.riskScore,
      },
      linked: {
        cbom: latestHistoryEntry?.linkedCbomRecords?.length ?? 0,
        assets: latestHistoryEntry?.linkedAssetRecords?.length ?? 0,
        exposures: latestHistoryEntry?.linkedExposureNodes?.length ?? 0,
      },
      provenance: summary
        ? 'Live scan evidence'
        : latestHistoryEntry?.summary
          ? `Recorded scan · ${latestHistoryEntry.target}`
          : intelHasData
            ? 'Tenant Scanner Intelligence'
            : 'No evidence yet',
    }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [
      status,
      summary,
      effectiveSummary,
      dashboardFindings,
      effectiveModules,
      effectiveResults,
      effectiveScanner2,
      targets,
      latestHistoryEntry,
      intelSummary,
      scannerIntel.data.severityCounts.high,
      intelHasData,
    ],
  );

  const showResults = assessment.hasEvidence;

  /* ── Real risk trend, one point per recorded scan ─────────────────────── */
  const riskTrendPoints = useMemo(() => {
    const points = [...displayedHistory]
      .filter((entry) => typeof (entry.qScore ?? entry.summary?.qScore) === 'number')
      .sort((a, b) => Date.parse(a.startedAt) - Date.parse(b.startedAt))
      .slice(-14)
      .map((entry) => ({
        scanId: entry.scanId,
        at: entry.startedAt,
        score: Math.max(0, Math.min(100, Math.round((entry.qScore ?? entry.summary?.qScore) as number))),
      }));
    return points;
  }, [displayedHistory]);

  const parsedPreview = useMemo(
    () => (inputText.trim() ? parseAssetInput(inputText).slice(0, 6) : []),
    [inputText],
  );

  const TABS: Array<{ id: TabId; label: string; count?: number }> = [
    { id: 'setup', label: 'Assessment' },
    { id: 'overview', label: 'Live Dashboard' },
    { id: 'findings', label: 'Findings', count: dashboardFindings.length },
    { id: 'logs', label: 'Telemetry', count: logs.length },
    { id: 'history', label: 'History', count: history.length },
    { id: 'agents', label: 'Agent Collectors' },
    { id: 'settings', label: 'Settings' },
  ];

  return (
    <div className="relative min-h-full text-slate-200 antialiased">
      <QuantumField scoped />

      {/* overflow-x-clip is the backstop: the findings table and module rail
          scroll inside their own containers, and nothing may push the page
          sideways on a phone. */}
      <div className="relative z-10 mx-auto max-w-[92rem] overflow-x-clip px-3 pb-16 pt-4 sm:px-5 sm:pt-6">
        {/* ── Assessment mode: Web / Local / Dev (§3) ──────────────────── */}
        <div className="mb-5 flex flex-wrap items-center gap-3">
          <ExposureModeTabs value={exposureMode} onChange={handleModeSelect} locked={lockedModes} scope="dashboard-scanner" />
          {/* Assessment / History, for the two modes that record one. Web keeps
              its own full tab bar further down the page, History included. */}
          {exposureMode !== 'web' && (
            <ExposureViewTabs value={exposureView} onChange={handleViewSelect} scope={`dashboard-scanner-${exposureMode}`} />
          )}
        </div>

        {exposureMode === 'local' && (
          <div role="tabpanel" id="exposure-panel-local" aria-labelledby="exposure-tab-local">
            {/* Kept mounted, never swapped: the Local worker lives in this
                panel's hook and a running scan must survive a trip to History. */}
            <div id="exposure-view-panel-assessment" hidden={exposureView !== 'assessment'}>
              <LocalAssessmentPanel onSync={syncLocalAssessment} />
            </div>
            {exposureView === 'history' && (
              <div id="exposure-view-panel-history">
                <ExposureHistoryPanel
                  mode="local"
                  active
                  onStartAssessment={() => handleViewSelect('assessment')}
                />
              </div>
            )}
          </div>
        )}

        {exposureMode === 'dev' && (
          <div role="tabpanel" id="exposure-panel-dev" aria-labelledby="exposure-tab-dev">
            <div id="exposure-view-panel-assessment" hidden={exposureView !== 'assessment'}>
              <DevAssessmentPanel authenticated onSync={syncDevAssessment} />
            </div>
            {exposureView === 'history' && (
              <div id="exposure-view-panel-history">
                <ExposureHistoryPanel
                  mode="dev"
                  active
                  onStartAssessment={() => handleViewSelect('assessment')}
                />
              </div>
            )}
          </div>
        )}

        {exposureMode === 'web' && (
        <div role="tabpanel" id="exposure-panel-web" aria-labelledby="exposure-tab-web">
        <div>
          <ScannerHero
            status={status}
            progress={progress}
            modules={modules}
            findings={findings}
            summary={summary}
            error={error}
            targets={targets.map((target) => target.normalized || target.raw)}
            evidenceFindings={dashboardFindings}
            evidenceModules={effectiveModules}
            results={effectiveResults}
            scanner2={effectiveScanner2}
            counters={{
              components: dashboardMetrics.totalFindings,
              vulnerable: dashboardMetrics.vulnerableFindings,
              cbom: latestHistoryEntry?.linkedCbomRecords?.length ?? 0,
              assets: latestHistoryEntry?.linkedAssetRecords?.length ?? 0,
              exposures: latestHistoryEntry?.linkedExposureNodes?.length ?? 0,
            }}
            hasEvidence={assessment.hasEvidence}
            gradeLabel={assessment.executive.gradeable ? assessment.executive.gradeLabel : null}
            verdict={{
              score: assessment.executive.encryptionScore,
              postQuantumReadiness: assessment.executive.postQuantumReadiness,
              gradeable: assessment.executive.gradeable,
              /* One decomposition, one set of surface scores. The hero used to
                 derive its own from the finding list, which is how the cards
                 came to contradict the gauge they surround. */
              nodeScores: assessment.nodeScores,
              nodeScoreScopes: assessment.nodeScoreScopes,
            }}
            scoreComponents={assessment.scoreComponents}
            onStart={() => {
              if (targets.length === 0) {
                showToast('Add an authorized target to the scan queue first.');
                return;
              }
              if (!authorizationAccepted) {
                showToast('Confirm authorization for every submitted target before scanning.');
                return;
              }
              void handleStart();
            }}
            onCancel={() => {
              void handleCancel();
              showToast('Scan terminated by operator.');
            }}
            onNewScan={handleNewScan}
            resetSignal={heroResetSignal}
            canStart={targets.length > 0 && authorizationAccepted && Boolean(session?.access_token)}
            composerSlot={
              <TargetComposer
                inputText={inputText}
                onInputChange={setInputText}
                onAdd={handleParseInput}
                targets={targets}
                onRemoveTarget={(index) => setTargets(targets.filter((_, current) => current !== index))}
                onClearTargets={() => setTargets([])}
                authorizationAccepted={authorizationAccepted}
                onAuthorizationChange={setAuthorizationAccepted}
                preview={parsedPreview}
              />
            }
            railSlot={
              <>
                <ScanModuleRail
                  /* Reconciled, not live-only: after a reload the rail must
                     describe the scan the rest of the page is describing,
                     instead of resetting every surface to Waiting. */
                  modules={effectiveModules}
                  progress={isRunning ? progress : effectiveModules.length ? 100 : 0}
                  status={status === 'idle' && latestHistoryEntry
                    ? (latestHistoryEntry.status === 'completed' ? 'completed' : 'failed')
                    : status}
                  isRunning={isRunning}
                />

                <Panel className="overflow-hidden border-violet-400/15">
                  <div className="px-4 py-4">
                    <h3 className="text-[15px] font-black leading-tight text-white">Platform Synchronization</h3>
                    <p className="mt-2 text-[12px] leading-relaxed text-slate-400">
                      Every completed scan writes CBOM records, asset inventory and exposure nodes for this tenant —
                      the same evidence the rest of the platform reads.
                    </p>
                    <dl className="mt-3 space-y-1.5">
                      {[
                        { label: 'Assets', value: intelSummary.totalAssets, to: '/dashboard/assets' },
                        { label: 'Components', value: intelSummary.totalComponents ?? intelSummary.totalFindings, to: '/dashboard/cbom' },
                        { label: 'Critical findings', value: intelSummary.criticalFindings, to: '/dashboard/findings' },
                      ].map((row) => (
                        <div key={row.label} className="flex items-center justify-between gap-3 text-[12px]">
                          <dt className="text-slate-500">{row.label}</dt>
                          <dd>
                            <Link to={row.to} className="font-mono font-bold text-cyan-300 no-underline hover:underline">
                              {row.value}
                            </Link>
                          </dd>
                        </div>
                      ))}
                    </dl>
                    <Link
                      to="/dashboard/migration-planner?source=scanner"
                      className="mt-4 flex w-full items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-violet-500 to-cyan-400 px-4 py-2.5 text-[13px] font-black text-[#04060e] no-underline transition-opacity hover:opacity-90"
                    >
                      Plan the migration <ChevronRight className="h-4 w-4" />
                    </Link>
                  </div>
                </Panel>
              </>
            }
          />
        </div>

        {/* ── Status bar ──────────────────────────────────────────────── */}
        <AnimatePresence mode="wait">
          {(status === 'completed' || status === 'failed' || status === 'cancelled') && (
            <motion.div
              key={status}
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.35 }}
              className="mt-5"
            >
              <Panel className="flex flex-wrap items-center justify-between gap-3 px-5 py-3">
                <div className="flex min-w-0 items-center gap-2.5">
                  {status === 'completed' && failedModules.length === 0 ? (
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
                  ) : (
                    <ShieldAlert
                      className={`h-4 w-4 shrink-0 ${status === 'completed' ? 'text-amber-400' : 'text-rose-400'}`}
                    />
                  )}
                  <span className="text-[13.5px] font-bold text-white">
                    {status === 'completed'
                      ? failedModules.length > 0
                        ? 'Scan completed with module errors'
                        : 'Scan completed'
                      : status === 'cancelled'
                        ? 'Scan cancelled'
                        : 'Scan could not complete'}
                  </span>
                  <span className="truncate text-[12px] text-slate-500">
                    {status === 'completed'
                      ? `${assessment.target.label} · ${new Date().toUTCString().replace('GMT', 'UTC')}`
                      : error || 'The scan stream stopped before every module reported.'}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <ScannerExportBar
                    onCsv={handleExportScannerReport}
                    onJson={handleDownloadReport}
                    onPrint={() => window.print()}
                  />
                  <button
                    type="button"
                    onClick={() => {
                      setStatus('idle');
                      setProgress(0);
                      setError(null);
                    }}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-3 py-1.5 text-[11.5px] font-semibold text-slate-400 transition-colors hover:text-white"
                  >
                    <RotateCcw className="h-3.5 w-3.5" /> New scan
                  </button>
                </div>
              </Panel>
            </motion.div>
          )}
        </AnimatePresence>

        {error && (
          <div className="mt-4 flex items-start gap-3 rounded-xl border border-rose-400/25 bg-rose-500/[0.07] px-4 py-3">
            <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
            <p className="text-[12.5px] leading-relaxed text-rose-100/85">{error}</p>
          </div>
        )}

        {failedModules.length > 0 && (
          <div className="mt-4 flex items-start gap-3 rounded-xl border border-amber-400/20 bg-amber-400/[0.06] px-4 py-3">
            <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
            <p className="text-[12.5px] leading-relaxed text-amber-100/85">
              <strong className="font-bold">Partial coverage.</strong>{' '}
              {failedModules.map((module) => `${module.name}: ${module.error || 'failed'}`).join(' · ')}. Scores below
              are computed only from the modules that reported — unmeasured dimensions are excluded rather than scored
              as failures.
            </p>
          </div>
        )}

        {/* ── Tabs ─────────────────────────────────────────────────────── */}
        <div className="mt-5 overflow-x-auto">
          <div role="tablist" aria-label="Scanner views" className="flex min-w-max gap-1.5 border-b border-white/[0.07] pb-2">
            {TABS.filter((tab) => tab.id !== 'agents' || canUseAgents).map((tab) => {
              const active = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  role="tab"
                  id={`scanner-tab-${tab.id}`}
                  aria-selected={active}
                  aria-controls={`scanner-panel-${tab.id}`}
                  onClick={() => handleTabSelect(tab.id)}
                  className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg px-3.5 py-2 text-[12.5px] font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50 ${
                    active
                      ? 'bg-cyan-400/10 text-cyan-300 ring-1 ring-cyan-400/25'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {tab.label}
                  {typeof tab.count === 'number' && tab.count > 0 && (
                    <span className="rounded bg-white/[0.07] px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
                      {tab.count}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* ── Assessment ───────────────────────────────────────────────── */}
        {activeTab === 'setup' && (
          <div role="tabpanel" id="scanner-panel-setup" aria-labelledby="scanner-tab-setup">
            {showResults ? (
              <div className="mt-5 space-y-5">
                <Reveal>
                  <ScannerExecutiveSummary assessment={assessment} />
                </Reveal>

                <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[minmax(0,1.35fr)_minmax(0,0.85fr)_minmax(0,1fr)]">
                  <Reveal>
                    <ScannerEncryptionScore assessment={assessment} />
                  </Reveal>
                  <Reveal delay={0.05}>
                    <ScannerAttackSurface assessment={assessment} />
                  </Reveal>
                  <Reveal delay={0.1}>
                    <ScannerCryptoIntelligence assessment={assessment} />
                  </Reveal>
                </div>

                <Reveal>
                  <ScannerModuleFlow
                    modules={effectiveModules}
                    onRetry={handleRetryFailedModule}
                    canRetry={!isRunning}
                  />
                </Reveal>

                <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[minmax(0,1.75fr)_minmax(0,1fr)]">
                  <Reveal>
                    <ScannerFindingsTable findings={dashboardFindings} total={dashboardMetrics.totalFindings} />
                  </Reveal>
                  <Reveal delay={0.05}>
                    <ScannerQuantumTimeline assessment={assessment} />
                  </Reveal>
                </div>

                <Reveal>
                  <ScannerRecommendations assessment={assessment} />
                </Reveal>

                <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[minmax(0,1.65fr)_minmax(0,1fr)]">
                  <Reveal>
                    <ScannerFootprint assessment={assessment} />
                  </Reveal>
                  <Reveal delay={0.05}>
                    <ScannerCoverage assessment={assessment} />
                  </Reveal>
                </div>

                <Reveal>
                  <ScannerSophiaInsight assessment={assessment} />
                </Reveal>

                <Reveal>
                  <ScannerScopePanel assessment={assessment} />
                </Reveal>
              </div>
            ) : (
              <ScannerEmptyState scanning={isRunning} />
            )}
          </div>
        )}

        {/* ── Live dashboard ───────────────────────────────────────────── */}
        {activeTab === 'overview' && (
          <div role="tabpanel" id="scanner-panel-overview" aria-labelledby="scanner-tab-overview" className="mt-5 space-y-5">
            <Panel className="overflow-hidden">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3">
                <SectionLabel>Live Scan Metrics</SectionLabel>
                <span className="font-mono text-[9.5px] uppercase tracking-widest text-slate-600">
                  {assessment.provenance}
                </span>
              </div>
              <div className="grid grid-cols-2 gap-px bg-white/[0.05] sm:grid-cols-3 lg:grid-cols-6">
                {[
                  { label: 'Assets Scanned', value: dashboardMetrics.totalAssetsScanned, color: ACCENT.cyan },
                  { label: 'Components', value: dashboardMetrics.totalFindings, color: ACCENT.blue },
                  { label: 'Critical', value: dashboardMetrics.criticalFindings, color: ACCENT.rose },
                  { label: 'Vulnerable', value: dashboardMetrics.vulnerableFindings, color: ACCENT.amber },
                  { label: 'PQC Ready', value: dashboardMetrics.pqcReady, color: ACCENT.emerald },
                  { label: 'Vulnerable Assets', value: dashboardMetrics.vulnerableAssets, color: ACCENT.violet },
                ].map((metric) => (
                  <div key={metric.label} className="bg-[#080d1a] px-4 py-4">
                    <p className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-500">{metric.label}</p>
                    <p className="mt-2 text-3xl font-black tracking-tight" style={{ color: metric.color }}>
                      <CountUp value={metric.value} />
                    </p>
                  </div>
                ))}
              </div>
              <div className="grid grid-cols-2 gap-px bg-white/[0.05] lg:grid-cols-4">
                <div className="bg-[#080d1a] px-4 py-4">
                  <p className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-500">Posture Score</p>
                  <p className="mt-2 text-2xl font-black" style={{ color: scoreColor(assessment.executive.encryptionScore) }}>
                    {assessment.executive.encryptionScore}/100
                  </p>
                  <Meter value={assessment.executive.encryptionScore} className="mt-2" />
                </div>
                <div className="bg-[#080d1a] px-4 py-4">
                  <p className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-500">Risk Level</p>
                  <p className="mt-2 text-2xl font-black text-slate-100">{dashboardRiskLabel}</p>
                  <p className="mt-1 font-mono text-[10px] text-slate-600">Exposure {dashboardMetrics.riskScore}/100</p>
                </div>
                <div className="bg-[#080d1a] px-4 py-4">
                  <p className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-500">PQC Readiness</p>
                  <p className="mt-2 text-2xl font-black" style={{ color: scoreColor(dashboardMetrics.pqcReadiness) }}>
                    {dashboardMetrics.pqcReadiness}%
                  </p>
                  <Meter value={dashboardMetrics.pqcReadiness} className="mt-2" />
                </div>
                <div className="bg-[#080d1a] px-4 py-4">
                  <p className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-500">Next Scheduled</p>
                  <p className="mt-2 text-[15px] font-black text-slate-100">
                    {nextScheduledScan ? new Date(nextScheduledScan.scheduledFor).toLocaleString() : 'None scheduled'}
                  </p>
                  <button
                    type="button"
                    onClick={handleOpenSchedule}
                    className="mt-2 inline-flex items-center gap-1.5 text-[11px] font-bold text-cyan-300 transition-colors hover:text-cyan-200"
                  >
                    <Calendar className="h-3 w-3" /> Schedule a scan
                  </button>
                </div>
              </div>
            </Panel>

            <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-2">
              <Reveal>
                <Panel className="h-full overflow-hidden">
                  <div className="border-b border-white/[0.06] px-5 py-3">
                    <SectionLabel accent={ACCENT.rose}>Severity Distribution</SectionLabel>
                  </div>
                  <div className="space-y-3 px-5 py-4">
                    {riskDistributionRows.map((row) => (
                      <div key={row.label}>
                        <div className="flex items-center justify-between text-[12px]">
                          <span className="text-slate-300">{row.label}</span>
                          <span className="font-mono text-slate-400">
                            {row.count} ({((row.count / dashboardSeverityTotal) * 100).toFixed(1)}%)
                          </span>
                        </div>
                        <Meter value={(row.count / dashboardSeverityTotal) * 100} color={row.color} className="mt-1.5" />
                      </div>
                    ))}
                    {dashboardFindings.length === 0 && (
                      <p className="py-4 text-center text-[12px] text-slate-600">
                        No findings recorded yet — the distribution appears after the first scan.
                      </p>
                    )}
                  </div>
                </Panel>
              </Reveal>

              <Reveal delay={0.05}>
                <Panel className="h-full overflow-hidden">
                  <div className="border-b border-white/[0.06] px-5 py-3">
                    <SectionLabel accent={ACCENT.amber}>Top Vulnerable Algorithms</SectionLabel>
                  </div>
                  {topVulnerableAlgorithmRows.length === 0 ? (
                    <p className="px-5 py-8 text-center text-[12px] text-slate-600">
                      No quantum-vulnerable algorithm has been recorded for this tenant.
                    </p>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full min-w-[24rem] border-collapse text-left">
                        <thead>
                          <tr className="border-b border-white/[0.06] font-mono text-[9.5px] uppercase tracking-[0.14em] text-slate-500">
                            <th scope="col" className="px-5 py-2.5 font-bold">Algorithm</th>
                            <th scope="col" className="px-3 py-2.5 text-center font-bold">Observations</th>
                            <th scope="col" className="px-5 py-2.5 text-right font-bold">Worst Severity</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-white/[0.04]">
                          {topVulnerableAlgorithmRows.map((row) => (
                            <tr key={row.algo} className="transition-colors hover:bg-white/[0.02]">
                              <td className="px-5 py-2.5 font-mono text-[12px] text-slate-200">{row.algo}</td>
                              <td className="px-3 py-2.5 text-center font-mono text-[12px] text-slate-400">{row.assets}</td>
                              <td className="px-5 py-2.5 text-right">
                                <StatusPill
                                  status={row.risk === 'CRITICAL' || row.risk === 'HIGH' ? 'critical' : row.risk === 'MEDIUM' ? 'warning' : 'pass'}
                                  label={row.risk}
                                />
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </Panel>
              </Reveal>

              <Reveal>
                <Panel className="h-full overflow-hidden">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3">
                    <SectionLabel accent={ACCENT.cyan}>Posture Trend</SectionLabel>
                    <span className="font-mono text-[9.5px] uppercase tracking-widest text-slate-600">
                      One point per recorded scan
                    </span>
                  </div>
                  {riskTrendPoints.length < 2 ? (
                    <p className="px-5 py-8 text-center text-[12px] leading-relaxed text-slate-600">
                      A trend needs at least two recorded scans. {riskTrendPoints.length === 1 ? 'One scan is on record.' : 'No scan is on record yet.'}
                    </p>
                  ) : (
                    <div className="px-5 py-5">
                      <PostureTrendChart points={riskTrendPoints} />
                    </div>
                  )}
                </Panel>
              </Reveal>

              <Reveal delay={0.05}>
                <Panel className="h-full overflow-hidden">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-5 py-3">
                    <SectionLabel accent={ACCENT.emerald}>Recent Scan Activity</SectionLabel>
                    <button
                      type="button"
                      onClick={() => handleTabSelect('history')}
                      className="text-[11px] font-bold text-cyan-300 transition-colors hover:text-cyan-200"
                    >
                      View all
                    </button>
                  </div>
                  {displayedHistory.length === 0 ? (
                    <p className="px-5 py-8 text-center text-[12px] text-slate-600">{historyEmptyText}</p>
                  ) : (
                    <ul className="divide-y divide-white/[0.05]">
                      {displayedHistory.slice(0, 6).map((entry) => (
                        <li key={entry.scanId} className="flex items-center justify-between gap-3 px-5 py-2.5">
                          <span className="flex min-w-0 items-center gap-2.5">
                            <Target className="h-3.5 w-3.5 shrink-0 text-cyan-400/70" />
                            <span className="min-w-0">
                              <span className="block truncate text-[12.5px] text-slate-200">{entry.target}</span>
                              <span className="block font-mono text-[10px] text-slate-600">
                                {new Date(entry.startedAt).toLocaleString()} · {formatMs(entry.durationMs)}
                              </span>
                            </span>
                          </span>
                          <StatusPill
                            status={entry.status === 'completed' ? 'pass' : entry.status === 'failed' ? 'fail' : 'warning'}
                            label={entry.status}
                          />
                        </li>
                      ))}
                    </ul>
                  )}
                </Panel>
              </Reveal>
            </div>

            <Reveal>
              <ScannerCoverage assessment={assessment} />
            </Reveal>
          </div>
        )}

        {/* ── Findings ─────────────────────────────────────────────────── */}
        {activeTab === 'findings' && (
          <div role="tabpanel" id="scanner-panel-findings" aria-labelledby="scanner-tab-findings" className="mt-5 space-y-4">
            <Panel className="flex flex-wrap items-center gap-3 px-4 py-3">
              <div className="relative min-w-[200px] max-w-md flex-1">
                <Search aria-hidden className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" />
                <input
                  type="search"
                  aria-label="Search findings"
                  placeholder="Search algorithms, evidence, locations…"
                  value={searchQ}
                  onChange={(event) => setSearchQ(event.target.value)}
                  className="w-full rounded-lg border border-white/[0.08] bg-[#040810]/80 py-2 pl-10 pr-4 text-[13px] text-white outline-none transition-colors placeholder:text-slate-600 focus:border-cyan-400/50"
                />
              </div>
              {['critical', 'high', 'medium', 'low', 'safe'].map((severity) => {
                const active = sevFilter === severity;
                const count = dashboardFindings.filter((finding) => finding.threatLevel.toLowerCase() === severity).length;
                return (
                  <button
                    key={severity}
                    type="button"
                    aria-pressed={active}
                    onClick={() => setSevFilter(active ? null : severity)}
                    className={`rounded-lg border px-3 py-1.5 text-[11.5px] font-bold uppercase tracking-wider transition-colors ${
                      active
                        ? `${sevColor(severity).br} ${sevColor(severity).b} ${sevColor(severity).t}`
                        : 'border-white/[0.08] text-slate-500 hover:text-slate-200'
                    }`}
                  >
                    {severity} ({count})
                  </button>
                );
              })}
              {showMitigationNextStep && (
                <Link
                  to={`/dashboard/migration-planner?source=scanner&scanId=${encodeURIComponent(jobId || 'latest')}`}
                  className="ml-auto inline-flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-cyan-400 to-violet-500 px-3.5 py-1.5 text-[11.5px] font-black text-[#04060e] no-underline transition-opacity hover:opacity-90"
                >
                  Mitigate findings <ChevronRight className="h-3.5 w-3.5" />
                </Link>
              )}
            </Panel>

            <div className="space-y-2">
              {filteredFindings.length === 0 ? (
                <Panel className="px-5 py-12 text-center">
                  <p className="text-[12.5px] text-slate-500">
                    {dashboardFindings.length === 0
                      ? 'Run an authorized scan to discover cryptographic findings.'
                      : 'No finding matches the current filters.'}
                  </p>
                </Panel>
              ) : (
                filteredFindings.map((finding, index) => (
                  <FindingRow
                    key={finding.id}
                    finding={finding}
                    index={index}
                    expanded={expandedFinding === finding.id}
                    onToggle={() => setExpandedFinding(expandedFinding === finding.id ? null : finding.id)}
                  />
                ))
              )}
            </div>
          </div>
        )}

        {/* ── Telemetry ────────────────────────────────────────────────── */}
        {activeTab === 'logs' && (
          <div role="tabpanel" id="scanner-panel-logs" aria-labelledby="scanner-tab-logs" className="mt-5">
            <Panel className="overflow-hidden">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] px-4 py-3">
                <div className="flex min-w-0 items-center gap-2.5">
                  <Terminal className="h-4 w-4 shrink-0 text-cyan-400" />
                  <div className="min-w-0">
                    <SectionLabel>Scanner Telemetry</SectionLabel>
                    <p className="mt-1 truncate font-mono text-[10px] text-slate-600">
                      {jobId || 'awaiting job id'} · {progress}% · {logs.length} lines
                    </p>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setTerminalPinned((value) => !value)}
                    className="rounded-lg border border-white/[0.08] px-2.5 py-1.5 font-mono text-[10px] font-bold uppercase tracking-wider text-slate-400 transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
                  >
                    {terminalPinned ? 'Auto-scroll' : 'Manual'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setTerminalPaused((value) => !value)}
                    className="rounded-lg border border-white/[0.08] px-2.5 py-1.5 font-mono text-[10px] font-bold uppercase tracking-wider text-slate-400 transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
                  >
                    {terminalPaused ? 'Resume' : 'Pause'}
                  </button>
                  <button
                    type="button"
                    onClick={handleCopyLogs}
                    disabled={logs.length === 0}
                    aria-label="Copy telemetry to clipboard"
                    className="rounded-lg border border-white/[0.08] p-1.5 text-slate-400 transition-colors hover:border-cyan-400/30 hover:text-cyan-300 disabled:opacity-30"
                  >
                    <Copy className="h-3.5 w-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={handleDownloadReport}
                    disabled={logs.length === 0 && findings.length === 0}
                    aria-label="Download scan report"
                    className="rounded-lg border border-white/[0.08] p-1.5 text-slate-400 transition-colors hover:border-cyan-400/30 hover:text-cyan-300 disabled:opacity-30"
                  >
                    <Download className="h-3.5 w-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={handleClearTerminal}
                    disabled={isRunning || logs.length === 0}
                    aria-label="Clear telemetry"
                    className="rounded-lg border border-white/[0.08] p-1.5 text-slate-400 transition-colors hover:border-rose-400/30 hover:text-rose-300 disabled:opacity-30"
                  >
                    <Eraser className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-px bg-white/[0.05] sm:grid-cols-4 lg:grid-cols-8">
                {[
                  ['Assets', liveCounts.assets, ACCENT.cyan],
                  ['Components', liveCounts.components, ACCENT.blue],
                  ['Critical', liveCounts.critical, ACCENT.rose],
                  ['High', liveCounts.high, ACCENT.amber],
                  ['Medium', liveCounts.medium, '#facc15'],
                  ['Low', liveCounts.low, ACCENT.emerald],
                  ['PQC Ready', liveCounts.pqcReady, ACCENT.emerald],
                  ['Vulnerable', liveCounts.vulnerable, ACCENT.rose],
                ].map(([label, value, color]) => (
                  <div key={String(label)} className="bg-[#080d1a] px-3 py-2.5">
                    <p className="font-mono text-[9px] uppercase tracking-[0.14em] text-slate-500">{label}</p>
                    <p className="mt-1 text-lg font-black" style={{ color: color as string }}>{value as number}</p>
                  </div>
                ))}
              </div>

              <div className="h-[440px] space-y-1 overflow-y-auto bg-[#04060e]/60 p-4 font-mono text-[11px]">
                {logs.length === 0 ? (
                  <p className="grid h-full place-items-center font-sans text-[12px] text-slate-600">
                    Awaiting authorized scan initiation…
                  </p>
                ) : (
                  logs.map((entry, index) => {
                    const severity = entry.severity ? sevColor(entry.severity.toLowerCase()) : null;
                    return (
                      <div key={`${entry.timestamp}-${index}`} className={`break-words leading-relaxed ${logColor(entry.level)}`}>
                        <span className="inline-block w-14 text-slate-700">[{entry.elapsed || '00:00'}]</span>
                        <span className={`inline-block w-20 font-bold ${logColor(entry.level)}`}>[{entry.level}]</span>
                        {severity && (
                          <span className={`mr-2 rounded border px-1.5 py-0.5 text-[9px] ${severity.br} ${severity.b} ${severity.t}`}>
                            {entry.severity}
                          </span>
                        )}
                        {entry.phase && <span className="mr-2 text-slate-600">[{entry.phase}]</span>}
                        {entry.moduleName && <span className="mr-2 text-cyan-400/60">[{entry.moduleName}]</span>}
                        <span>{entry.message}</span>
                      </div>
                    );
                  })
                )}
                {copiedLogs && <div className="text-emerald-400">[copy] Telemetry copied to clipboard</div>}
                {isRunning && <div className="mt-2 animate-pulse text-cyan-400/60">|</div>}
                <div ref={logEndRef} />
              </div>
            </Panel>
          </div>
        )}

        {/* ── History ──────────────────────────────────────────────────── */}
        {activeTab === 'history' && (
          <div role="tabpanel" id="scanner-panel-history" aria-labelledby="scanner-tab-history" className="mt-5 space-y-4">
            <Panel className="flex flex-wrap items-center justify-between gap-3 px-5 py-3">
              <SectionLabel>Audit-Ready Scan History</SectionLabel>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => void handleToggleTimeframe()}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-3 py-1.5 text-[11.5px] font-semibold text-slate-300 transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
                >
                  <Calendar className="h-3.5 w-3.5" />
                  {historyTimeframe === 'all' ? 'All time' : 'Last 7 days'} · {displayedHistory.length}
                </button>
                <button
                  type="button"
                  onClick={fetchHistory}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-3 py-1.5 text-[11.5px] font-semibold text-slate-300 transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${historyLoading ? 'animate-spin' : ''}`} /> Refresh
                </button>
              </div>
            </Panel>

            <div className="grid grid-cols-[minmax(0,1fr)] items-start gap-4 xl:grid-cols-[minmax(0,0.95fr)_minmax(0,1.35fr)]">
              <div className="space-y-3">
                {displayedHistory.length === 0 ? (
                  <Panel className="px-5 py-12 text-center">
                    <p className="text-[12.5px] text-slate-500">{historyEmptyText}</p>
                  </Panel>
                ) : (
                  displayedHistory.map((entry) => (
                    <Panel
                      key={entry.scanId}
                      className={`cursor-pointer px-4 py-4 transition-colors ${
                        selectedHistoryEntry?.scanId === entry.scanId ? 'border-cyan-400/35' : 'hover:border-white/[0.14]'
                      }`}
                      onClick={() => setSelectedHistoryId(entry.scanId)}
                    >
                      <div className="flex flex-col justify-between gap-3 lg:flex-row lg:items-center">
                        <div className="flex min-w-0 items-center gap-3">
                          <History className="h-4 w-4 shrink-0 text-cyan-400/70" />
                          <div className="min-w-0">
                            <p className="truncate text-[13px] font-bold text-slate-100">{entry.scanId}</p>
                            <p className="truncate font-mono text-[10px] text-slate-600">
                              {new Date(entry.startedAt).toLocaleString()} · {formatMs(entry.durationMs)}
                            </p>
                          </div>
                        </div>
                        <div className="flex flex-wrap items-center gap-2">
                          {[
                            ['Components', entry.detectedComponents, ACCENT.blue],
                            ['Vulnerable', entry.vulnerableFindings, ACCENT.rose],
                            ['PQC Ready', entry.pqcReadyFindings, ACCENT.emerald],
                            ['Q-Score', entry.qScore ?? '—', ACCENT.cyan],
                          ].map(([label, value, color]) => (
                            <div key={String(label)} className="rounded-lg border border-white/[0.07] bg-white/[0.02] px-2.5 py-1.5 text-center">
                              <p className="text-[13px] font-black" style={{ color: color as string }}>{String(value)}</p>
                              <p className="font-mono text-[8.5px] uppercase tracking-wider text-slate-600">{label}</p>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div className="mt-3 flex flex-wrap gap-2">
                        <button
                          type="button"
                          onClick={(event) => { event.stopPropagation(); setSelectedHistoryId(entry.scanId); }}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/25 px-2.5 py-1.5 text-[11px] font-bold text-cyan-300 transition-colors hover:bg-cyan-400/10"
                        >
                          <Eye className="h-3 w-3" /> Review
                        </button>
                        <button
                          type="button"
                          onClick={(event) => { event.stopPropagation(); handleOpenHistoryInFindings(entry); }}
                          disabled={!entry.findings?.length}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-2.5 py-1.5 text-[11px] font-semibold text-slate-400 transition-colors hover:text-white disabled:opacity-30"
                        >
                          Open in findings
                        </button>
                        <button
                          type="button"
                          onClick={(event) => { event.stopPropagation(); handleDownloadHistoryAudit(entry); }}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-2.5 py-1.5 text-[11px] font-semibold text-slate-400 transition-colors hover:text-white"
                        >
                          <Download className="h-3 w-3" /> Audit JSON
                        </button>
                        <button
                          type="button"
                          onClick={(event) => { event.stopPropagation(); setPendingDeleteEntry(entry); }}
                          disabled={deletingScanId === entry.scanId}
                          title="Delete this scan and all of its data"
                          className="ml-auto inline-flex items-center gap-1.5 rounded-lg border border-rose-400/25 px-2.5 py-1.5 text-[11px] font-bold text-rose-300 transition-colors hover:bg-rose-500/10 disabled:opacity-40"
                        >
                          {deletingScanId === entry.scanId ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Trash2 className="h-3 w-3" />}
                          {deletingScanId === entry.scanId ? 'Deleting' : 'Delete'}
                        </button>
                      </div>

                      <dl className="mt-3 grid gap-x-4 gap-y-1 border-t border-white/[0.06] pt-3 text-[11px] md:grid-cols-2">
                        {[
                          ['Target', entry.target],
                          ['Status', entry.status],
                          ['CBOM records', entry.linkedCbomRecords?.length || 0],
                          ['Exposure nodes', entry.linkedExposureNodes?.length || 0],
                          ['Modules', entry.scannerModulesUsed?.length || entry.moduleStates?.filter((module) => module.status !== 'Skipped').length || 0],
                          ['Persisted findings', entry.findings?.length || 0],
                        ].map(([label, value]) => (
                          <div key={String(label)} className="flex min-w-0 gap-2">
                            <dt className="shrink-0 text-slate-600">{label}:</dt>
                            <dd className="truncate text-slate-400">{String(value)}</dd>
                          </div>
                        ))}
                      </dl>
                    </Panel>
                  ))
                )}
              </div>

              <Panel className="overflow-hidden">
                {!selectedHistoryEntry ? (
                  <p className="px-5 py-12 text-center text-[12.5px] text-slate-500">
                    Select a scan to review its persisted findings.
                  </p>
                ) : (
                  <div>
                    <div className="flex flex-col justify-between gap-4 border-b border-white/[0.06] px-5 py-4 lg:flex-row lg:items-start">
                      <div className="min-w-0">
                        <SectionLabel>Persisted Audit Detail</SectionLabel>
                        <h3 className="mt-2 break-all text-[15px] font-black text-white">{selectedHistoryEntry.scanId}</h3>
                        <p className="mt-1 truncate font-mono text-[11px] text-slate-500">{selectedHistoryEntry.target}</p>
                        <p className="mt-0.5 font-mono text-[10px] text-slate-600">
                          {new Date(selectedHistoryEntry.startedAt).toLocaleString()} · {formatMs(selectedHistoryEntry.durationMs)}
                        </p>
                      </div>
                      <div className="grid shrink-0 grid-cols-3 gap-2 sm:grid-cols-5">
                        {[
                          ['Critical', selectedHistorySeverityCounts.critical, ACCENT.rose],
                          ['High', selectedHistorySeverityCounts.high, ACCENT.amber],
                          ['Medium', selectedHistorySeverityCounts.medium, '#facc15'],
                          ['Low', selectedHistorySeverityCounts.low, ACCENT.emerald],
                          ['Safe', selectedHistorySeverityCounts.safe, ACCENT.cyan],
                        ].map(([label, value, color]) => (
                          <div key={String(label)} className="rounded-lg border border-white/[0.07] bg-white/[0.02] px-2.5 py-1.5 text-center">
                            <p className="text-[13px] font-black" style={{ color: color as string }}>{String(value)}</p>
                            <p className="font-mono text-[8.5px] uppercase tracking-wider text-slate-600">{label}</p>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-3 border-b border-white/[0.06] px-5 py-3">
                      <div className="relative min-w-[200px] flex-1">
                        <Search aria-hidden className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" />
                        <input
                          type="search"
                          aria-label="Search persisted findings"
                          placeholder="Search persisted findings…"
                          value={historyFindingSearch}
                          onChange={(event) => setHistoryFindingSearch(event.target.value)}
                          className="w-full rounded-lg border border-white/[0.08] bg-[#040810]/80 py-2 pl-10 pr-4 text-[13px] text-white outline-none transition-colors placeholder:text-slate-600 focus:border-cyan-400/50"
                        />
                      </div>
                      {['critical', 'high', 'medium', 'low', 'safe'].map((severity) => {
                        const active = historySeverityFilter === severity;
                        return (
                          <button
                            key={severity}
                            type="button"
                            aria-pressed={active}
                            onClick={() => setHistorySeverityFilter(active ? null : severity)}
                            className={`rounded-lg border px-2.5 py-1.5 text-[11px] font-bold uppercase tracking-wider transition-colors ${
                              active
                                ? `${sevColor(severity).br} ${sevColor(severity).b} ${sevColor(severity).t}`
                                : 'border-white/[0.08] text-slate-500 hover:text-slate-200'
                            }`}
                          >
                            {severity}
                          </button>
                        );
                      })}
                    </div>

                    <div className="max-h-[620px] space-y-2 overflow-y-auto p-3">
                      {filteredHistoryFindings.length === 0 ? (
                        <p className="py-12 text-center text-[12.5px] text-slate-500">
                          {selectedHistoryFindings.length === 0
                            ? 'No persisted finding was recorded for this scan.'
                            : 'No persisted finding matches the current filters.'}
                        </p>
                      ) : (
                        filteredHistoryFindings.map((finding, index) => (
                          <FindingRow
                            key={finding.id}
                            finding={finding}
                            index={index}
                            expanded={expandedHistoryFinding === finding.id}
                            onToggle={() =>
                              setExpandedHistoryFinding(expandedHistoryFinding === finding.id ? null : finding.id)
                            }
                          />
                        ))
                      )}
                    </div>
                  </div>
                )}
              </Panel>
            </div>
          </div>
        )}

        {/* ── Agent collectors ─────────────────────────────────────────── */}
        {activeTab === 'agents' && canUseAgents && (
          <div role="tabpanel" id="scanner-panel-agents" aria-labelledby="scanner-tab-agents" className="mt-5">
            <AgentCollectorConsole />
          </div>
        )}

        {/* ── Settings ─────────────────────────────────────────────────── */}
        {activeTab === 'settings' && (
          <div role="tabpanel" id="scanner-panel-settings" aria-labelledby="scanner-tab-settings" className="mt-5">
            {canUseAgents ? (
              <AgentSettingsConsole />
            ) : (
              <Panel className="px-6 py-10 text-center">
                <span className="mx-auto grid h-11 w-11 place-items-center rounded-xl border border-violet-400/30 bg-violet-500/10 text-violet-300">
                  <Lock className="h-5 w-5" />
                </span>
                <h3 className="mt-3 text-[15px] font-black text-white">Collector settings require a plan</h3>
                <p className="mx-auto mt-1.5 max-w-md text-[12.5px] leading-relaxed text-slate-400">
                  Agent Collector policy management is available on the Basic plan and above. Scanning, findings and
                  history remain fully available on your current plan.
                </p>
                <Link
                  to="/dashboard/settings?tab=billing"
                  className="mt-4 inline-flex items-center gap-1.5 rounded-lg border border-violet-400/30 px-3.5 py-2 text-[12px] font-bold text-violet-300 no-underline transition-colors hover:bg-violet-500/10"
                >
                  <Lock className="h-3.5 w-3.5" /> Compare plans
                </Link>
              </Panel>
            )}
          </div>
        )}
        </div>
        )}
      </div>

      {/* ── Schedule dialog ─────────────────────────────────────────────── */}
      <Modal open={scheduleOpen} onClose={() => setScheduleOpen(false)} title="Schedule Scan" maxWidthClassName="max-w-lg">
        <div className="space-y-4 px-5 py-5">
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="block">
              <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-slate-500">Date</span>
              <input
                type="date"
                value={scheduleDate}
                min={dateInputFor(0)}
                onChange={(event) => setScheduleDate(event.target.value)}
                className="mt-1 w-full rounded-lg border border-white/[0.1] bg-white/[0.03] px-3 py-2 text-[13px] text-white outline-none focus:border-cyan-400/50"
              />
            </label>
            <label className="block">
              <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-slate-500">Time</span>
              <input
                type="time"
                value={scheduleTime}
                onChange={(event) => setScheduleTime(event.target.value)}
                className="mt-1 w-full rounded-lg border border-white/[0.1] bg-white/[0.03] px-3 py-2 text-[13px] text-white outline-none focus:border-cyan-400/50"
              />
            </label>
          </div>

          <div className="rounded-xl border border-white/[0.07] bg-white/[0.02] px-4 py-3">
            <p className="font-mono text-[10px] font-bold uppercase tracking-wider text-slate-500">Targets</p>
            <p className="mt-1 break-words font-mono text-[12px] text-slate-300">
              {targets.length > 0
                ? targets.map((target) => target.normalized || target.raw).join(', ')
                : history[0]?.target || 'No authorized target queued'}
            </p>
          </div>

          {scheduledScans.filter((scan) => Date.parse(scan.scheduledFor) > Date.now()).length > 0 && (
            <div className="rounded-xl border border-white/[0.07] bg-white/[0.02] px-4 py-3">
              <p className="font-mono text-[10px] font-bold uppercase tracking-wider text-slate-500">Upcoming</p>
              <ul className="mt-2 max-h-28 space-y-1.5 overflow-y-auto">
                {scheduledScans
                  .filter((scan) => Date.parse(scan.scheduledFor) > Date.now())
                  .slice(0, 3)
                  .map((scan) => (
                    <li key={scan.id} className="flex items-center justify-between gap-3 text-[12px]">
                      <span className="text-slate-300">{new Date(scan.scheduledFor).toLocaleString()}</span>
                      <span className="font-mono text-slate-600">{scan.targets.length} target(s)</span>
                    </li>
                  ))}
              </ul>
            </div>
          )}

          <p className="text-[11px] leading-relaxed text-slate-600">
            Schedules are stored on this device for this account and start the same authorized scan when you return.
          </p>

          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setScheduleOpen(false)}
              className="rounded-lg border border-white/[0.1] px-4 py-2 text-[12px] font-semibold text-slate-400 transition-colors hover:text-white"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleSaveSchedule}
              className="rounded-lg bg-gradient-to-r from-cyan-400 to-violet-500 px-4 py-2 text-[12px] font-black text-[#04060e] transition-opacity hover:opacity-90"
            >
              Save schedule
            </button>
          </div>
        </div>
      </Modal>

      {/* ── Delete confirmation ─────────────────────────────────────────── */}
      <Modal
        open={Boolean(pendingDeleteEntry)}
        onClose={() => { if (!deletingScanId) setPendingDeleteEntry(null); }}
        title="Delete this scan?"
        maxWidthClassName="max-w-lg"
      >
        {pendingDeleteEntry && (
          <div className="space-y-4 px-5 py-5">
            <div className="flex items-start gap-4">
              <span className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-rose-400/30 bg-rose-500/10 text-rose-300">
                <Trash2 className="h-5 w-5" />
              </span>
              <p className="text-[12.5px] leading-relaxed text-slate-400">
                This permanently removes the scan and everything it produced — findings, CBOM components, exposures,
                certificates and events — from every dashboard and report. This cannot be undone.
              </p>
            </div>

            <div className="rounded-xl border border-white/[0.07] bg-white/[0.02] px-4 py-3 text-[11.5px]">
              <div className="mb-2 flex items-center justify-between gap-3">
                <span className="truncate font-mono font-bold text-slate-200">{pendingDeleteEntry.scanId}</span>
                <StatusPill status={pendingDeleteEntry.status === 'completed' ? 'pass' : 'warning'} label={pendingDeleteEntry.status} />
              </div>
              <p className="mb-3 truncate text-slate-500">
                <span className="font-bold text-slate-400">Target:</span> {pendingDeleteEntry.target}
              </p>
              <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-slate-500 sm:grid-cols-4">
                <span><span className="font-bold text-slate-300">{pendingDeleteEntry.detectedComponents}</span> Components</span>
                <span><span className="font-bold text-rose-300">{pendingDeleteEntry.vulnerableFindings}</span> Vulnerable</span>
                <span><span className="font-bold text-slate-300">{pendingDeleteEntry.linkedCbomRecords?.length || 0}</span> CBOM</span>
                <span><span className="font-bold text-slate-300">{pendingDeleteEntry.linkedExposureNodes?.length || 0}</span> Exposures</span>
              </div>
              <p className="mt-3 border-t border-white/[0.06] pt-2.5 text-[10.5px] text-slate-600">
                Assets scanned by other retained scans are preserved — only records unique to this scan are removed.
              </p>
            </div>

            <div className="flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={() => setPendingDeleteEntry(null)}
                disabled={Boolean(deletingScanId)}
                className="rounded-lg border border-white/[0.1] px-4 py-2 text-[12px] font-semibold text-slate-400 transition-colors hover:text-white disabled:opacity-40"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => deleteHistoryEntry(pendingDeleteEntry.scanId)}
                disabled={Boolean(deletingScanId)}
                className="inline-flex items-center gap-2 rounded-lg border border-rose-400/40 bg-rose-500/15 px-4 py-2 text-[12px] font-black uppercase tracking-wider text-rose-200 transition-colors hover:bg-rose-500/25 disabled:opacity-50"
              >
                {deletingScanId ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
                {deletingScanId ? 'Deleting…' : 'Delete permanently'}
              </button>
            </div>
          </div>
        )}
      </Modal>

      {/* ── Toast ───────────────────────────────────────────────────────── */}
      <AnimatePresence>
        {toast && (
          <motion.div
            role="status"
            aria-live="polite"
            initial={{ opacity: 0, y: 40, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 16, scale: 0.97 }}
            className="fixed bottom-6 right-6 z-[80] flex items-center gap-3 rounded-xl border border-cyan-400/25 bg-[#080d1a]/95 px-5 py-3 text-[13px] font-medium text-white shadow-[0_24px_60px_-30px_rgba(0,0,0,0.9)] backdrop-blur-xl"
          >
            <Sparkles className="h-4 w-4 shrink-0 text-cyan-300" />
            <span>{toast}</span>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

/* ================================================================== atoms == */

/**
 * Export bar — the authenticated mirror of /public-scan's. Every action exports
 * evidence that already exists; nothing is synthesised at export time.
 */
function ScannerExportBar({
  onCsv,
  onJson,
  onPrint,
}: {
  onCsv: () => void;
  onJson: () => void;
  onPrint: () => void;
}) {
  const actions = [
    { label: 'CSV', icon: FileSpreadsheet, onClick: onCsv, hint: 'Summary, findings, history and telemetry' },
    { label: 'JSON', icon: FileJson, onClick: onJson, hint: 'Full machine-readable scan report' },
    { label: 'Print', icon: Download, onClick: onPrint, hint: 'Print this assessment to PDF' },
  ];
  return (
    <div className="flex flex-wrap items-center gap-2">
      {actions.map((action) => (
        <button
          key={action.label}
          type="button"
          onClick={action.onClick}
          title={action.hint}
          className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-[11.5px] font-semibold text-slate-300 transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
        >
          <action.icon className="h-3.5 w-3.5" />
          {action.label}
        </button>
      ))}
    </div>
  );
}

/**
 * The scan rail — the authenticated counterpart to /public-scan's stage rail.
 * Stages are the scanner's six discovery surfaces, and each one's state is
 * aggregated from the REAL module states the backend published for it.
 */
function ScanModuleRail({
  modules,
  progress,
  status,
  isRunning,
}: {
  modules: ModuleState[];
  progress: number;
  status: ScanStatus;
  isRunning: boolean;
}) {
  const runFinished = status === 'completed' || status === 'failed' || status === 'cancelled';

  /**
   * Stage state, derived strictly from what the scanner's module ledger reported.
   *
   * The previous rule collapsed three very different situations into one grey
   * "Skipped" chip: a surface that genuinely did not apply, a surface that had
   * measured most of its modules but was missing one that never reported, and a
   * run that was cut short. That is why a scan which had read 10 TLS/cipher
   * findings still announced "Transport & Ciphers · SKIPPED".
   *
   * The states are now disjoint and each one means exactly one thing:
   *   complete   — every module in the surface resolved, at least one measured
   *   partial    — measured, but a module is still unresolved (a real gap)
   *   n/a        — every module in the surface legitimately did not apply
   *   failed     — a module in the surface errored
   *   running / waiting — the run has not reached this surface yet
   */
  const stages = SCANNER_NODE_BLUEPRINTS.map((blueprint) => {
    const owned = modules.filter((module) => SCANNER_NODE_MODULES[blueprint.key]?.includes(module.id));
    const done = owned.filter((module) => module.status === 'Completed' || module.status === 'No findings');
    const notApplicable = owned.filter((module) => module.status === 'Skipped');
    const failed = owned.filter((module) => module.status === 'Failed');
    const running = owned.some((module) => module.status === 'Running');
    const unresolved = owned.filter((module) => module.status === 'Queued');
    const resolved = done.length + notApplicable.length;

    // Some modules measured, some never reported: "complete" would overstate
    // coverage and "skipped" would erase the work that did happen, so a
    // finished run with a gap is reported as Partial.
    const settledState: 'complete' | 'partial' | 'na' | 'waiting' =
      resolved === owned.length
        ? (notApplicable.length === owned.length ? 'na' : 'complete')
        : runFinished
          ? (done.length > 0 ? 'partial' : 'waiting')
          : 'waiting';

    const state: 'waiting' | 'running' | 'complete' | 'partial' | 'failed' | 'na' =
      owned.length === 0
        ? 'waiting'
        : failed.length > 0
          ? 'failed'
          : running
            ? 'running'
            : settledState;

    const findingCount = owned.reduce((sum, module) => sum + module.findingsCount, 0);
    const measuredDenominator = owned.length - notApplicable.length;
    return {
      key: blueprint.key,
      label: blueprint.title,
      state,
      detail: owned.length === 0
        ? 'Awaiting module catalog'
        : `${done.length}/${measuredDenominator || owned.length} modules${
            notApplicable.length ? ` · ${notApplicable.length} n/a` : ''
          }${unresolved.length && runFinished ? ` · ${unresolved.length} unreported` : ''} · ${findingCount} findings`,
      // Reason lines, verbatim from the backend ledger, shown as the row title so
      // "n/a" is always answerable.
      reason: [
        ...notApplicable.map((module) => `${module.name}: ${module.reason || 'not applicable'}`),
        ...failed.map((module) => `${module.name}: ${module.error || module.reason || 'failed'}`),
      ].join('\n'),
    };
  });

  const STATE_STYLE = {
    waiting: { color: ACCENT.slate, label: 'Waiting' },
    running: { color: ACCENT.cyan, label: 'Running' },
    complete: { color: ACCENT.emerald, label: 'Complete' },
    partial: { color: ACCENT.amber, label: 'Partial' },
    failed: { color: ACCENT.rose, label: 'Failed' },
    na: { color: ACCENT.slate, label: 'Not applicable' },
  } as const;

  return (
    <Panel className="overflow-hidden">
      <div className="flex items-center justify-between gap-3 border-b border-white/[0.06] px-4 py-3">
        <SectionLabel>Discovery Workflow</SectionLabel>
        {isRunning && (
          <span className="flex shrink-0 items-center gap-1.5 font-mono text-[10px] font-bold text-cyan-300">
            <Loader2 className="h-3 w-3 animate-spin" />
            {progress}%
          </span>
        )}
      </div>
      <p className="px-4 pt-3 font-mono text-[9.5px] uppercase tracking-[0.16em] text-slate-500">
        Authorized Estate Scan · {status}
      </p>

      <ol className="space-y-1 px-4 py-3">
        {stages.map((stage, index) => {
          const style = STATE_STYLE[stage.state];
          return (
            <li key={stage.key} className="flex items-start gap-3 py-1.5">
              <span
                className="relative grid h-7 w-7 shrink-0 place-items-center rounded-full border text-[11px] font-black transition-colors"
                style={{ borderColor: `${style.color}55`, backgroundColor: `${style.color}14`, color: style.color }}
              >
                {stage.state === 'complete' ? (
                  <CheckCircle2 className="h-3.5 w-3.5" />
                ) : stage.state === 'failed' ? (
                  <XCircle className="h-3.5 w-3.5" />
                ) : stage.state === 'na' ? (
                  <MinusCircle className="h-3.5 w-3.5" />
                ) : stage.state === 'partial' ? (
                  <AlertTriangle className="h-3.5 w-3.5" />
                ) : (
                  index + 1
                )}
                {stage.state === 'running' && (
                  <motion.span
                    className="absolute inset-0 rounded-full border"
                    style={{ borderColor: style.color }}
                    animate={{ scale: [1, 1.35], opacity: [0.6, 0] }}
                    transition={{ duration: 1.4, repeat: Infinity, ease: 'easeOut' }}
                  />
                )}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex items-baseline justify-between gap-2">
                  <p
                    className="truncate text-[13px] font-bold"
                    style={{ color: stage.state === 'waiting' ? '#94a3b8' : '#e2e8f0' }}
                  >
                    {stage.label}
                  </p>
                  <span className="shrink-0 font-mono text-[9px] uppercase tracking-widest" style={{ color: style.color }}>
                    {style.label}
                  </span>
                </div>
                <p
                  className="truncate text-[11px] text-slate-500"
                  title={stage.reason ? `${stage.detail}\n\n${stage.reason}` : stage.detail}
                >
                  {stage.detail}
                </p>
                {/* A non-measuring surface always states why, inline — the
                    operator should never have to guess what "n/a" covered. */}
                {(stage.state === 'na' || stage.state === 'failed') && stage.reason && (
                  <p className="mt-0.5 line-clamp-2 text-[10.5px] leading-snug text-slate-600">
                    {stage.reason.split('\n')[0]}
                  </p>
                )}
              </div>
            </li>
          );
        })}
      </ol>

      <div className="h-1 w-full bg-white/[0.05]">
        <motion.div
          className="h-full bg-gradient-to-r from-cyan-400 to-violet-500"
          animate={{ width: `${progress}%` }}
          transition={{ duration: 0.4, ease: 'easeOut' }}
        />
      </div>
    </Panel>
  );
}

/**
 * Target composer — the authenticated equivalent of the public hero's single
 * domain field. An authorized scan needs a queue and an explicit authorization
 * acknowledgement, so the composer carries both.
 */
function TargetComposer({
  inputText,
  onInputChange,
  onAdd,
  targets,
  onRemoveTarget,
  onClearTargets,
  authorizationAccepted,
  onAuthorizationChange,
  preview,
}: {
  inputText: string;
  onInputChange: (value: string) => void;
  onAdd: () => void;
  targets: ValidatedAsset[];
  onRemoveTarget: (index: number) => void;
  onClearTargets: () => void;
  authorizationAccepted: boolean;
  onAuthorizationChange: (value: boolean) => void;
  preview: ValidatedAsset[];
}) {
  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-3 lg:grid-cols-2">
      <div className="rounded-xl border border-cyan-400/25 bg-[#040810]/85 p-3 shadow-[0_0_34px_-22px_rgba(34,211,238,0.9)] transition-colors focus-within:border-cyan-400/55">
        <label htmlFor="scanner-targets" className="font-mono text-[9.5px] font-bold uppercase tracking-[0.16em] text-slate-500">
          Authorized assets
        </label>
        <textarea
          id="scanner-targets"
          value={inputText}
          onChange={(event) => onInputChange(event.target.value)}
          rows={4}
          spellCheck={false}
          placeholder={'example.com\nhttps://api.company.com\nhttps://github.com/company/repo\nssh://bastion.company.com:22'}
          className="mt-2 w-full resize-none bg-transparent font-mono text-[13px] text-white outline-none placeholder:text-slate-700"
        />

        {preview.length > 0 && (
          <ul className="mt-2 max-h-24 space-y-0.5 overflow-y-auto font-mono text-[10.5px]">
            {preview.map((asset, index) => (
              <li
                key={`${asset.raw}-${index}`}
                className={`flex items-center gap-2 ${asset.valid ? 'text-emerald-400' : 'text-rose-400'}`}
              >
                {asset.valid ? <CheckCircle2 className="h-3 w-3 shrink-0" /> : <XCircle className="h-3 w-3 shrink-0" />}
                <span className="truncate">{asset.raw}</span>
                <span className="ml-auto shrink-0 text-slate-600">{asset.valid ? asset.type : asset.error}</span>
              </li>
            ))}
          </ul>
        )}

        <label className="mt-3 flex cursor-pointer items-start gap-2.5 rounded-lg border border-white/[0.07] bg-white/[0.02] px-3 py-2.5">
          <input
            type="checkbox"
            checked={authorizationAccepted}
            onChange={(event) => onAuthorizationChange(event.target.checked)}
            className="mt-0.5 h-3.5 w-3.5 shrink-0 accent-cyan-400"
          />
          <span className="text-[11px] leading-relaxed text-slate-400">
            I confirm these assets belong to this account or are explicitly authorized for defensive cryptographic
            inventory and compliance scanning. No exploitation, credential collection or stealth scanning is performed.
          </span>
        </label>

        <div className="mt-3 flex justify-end">
          <button
            type="button"
            onClick={onAdd}
            disabled={!inputText.trim()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/30 bg-cyan-400/10 px-3.5 py-2 text-[12px] font-bold text-cyan-300 transition-colors hover:bg-cyan-400/15 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <Plus className="h-3.5 w-3.5" /> Add to queue
          </button>
        </div>
      </div>

      <div className="flex flex-col rounded-xl border border-white/[0.08] bg-[#040810]/70 p-3">
        <div className="flex items-center justify-between gap-2">
          <p className="flex items-center gap-2 font-mono text-[9.5px] font-bold uppercase tracking-[0.16em] text-slate-500">
            <Network className="h-3 w-3" /> Scan queue ({targets.length})
          </p>
          {targets.length > 0 && (
            <button
              type="button"
              onClick={onClearTargets}
              aria-label="Clear the scan queue"
              className="text-slate-600 transition-colors hover:text-rose-400"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        <div className="mt-2 min-h-[9.5rem] flex-1 space-y-1.5 overflow-y-auto pr-1">
          {targets.length === 0 ? (
            <div className="grid h-[9.5rem] place-items-center rounded-lg border border-dashed border-white/[0.08] text-center">
              <p className="px-4 text-[11.5px] text-slate-600">
                No authorized target queued.
                <br />
                Add assets on the left to begin.
              </p>
            </div>
          ) : (
            targets.map((target, index) => (
              <div
                key={`${target.host}-${target.port}-${index}`}
                className="group flex items-center justify-between gap-2 rounded-lg border border-white/[0.07] bg-white/[0.02] px-3 py-2"
              >
                <span className="flex min-w-0 items-center gap-2.5">
                  <span className="grid h-6 w-6 shrink-0 place-items-center rounded border border-cyan-400/20 bg-cyan-400/[0.08]">
                    <Globe className="h-3 w-3 text-cyan-400/70" />
                  </span>
                  <span className="min-w-0">
                    <span className="block truncate text-[12.5px] font-semibold text-slate-200">{target.host}</span>
                    <span className="block font-mono text-[9.5px] uppercase text-slate-600">
                      {target.type}
                      {target.port ? ` :${target.port}` : ''}
                    </span>
                  </span>
                </span>
                <button
                  type="button"
                  onClick={() => onRemoveTarget(index)}
                  aria-label={`Remove ${target.host} from the scan queue`}
                  className="shrink-0 text-slate-700 opacity-0 transition-all hover:text-rose-400 focus-visible:opacity-100 group-hover:opacity-100"
                >
                  <XCircle className="h-4 w-4" />
                </button>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * Posture trend — one point per recorded scan, plotted from each scan's own
 * persisted Q-score. There is no synthetic smoothing and no invented history:
 * with fewer than two recorded scans the caller renders an explanation instead.
 */
function PostureTrendChart({ points }: { points: Array<{ scanId: string; at: string; score: number }> }) {
  const width = 300;
  const height = 96;
  const padding = 8;
  const step = points.length > 1 ? (width - padding * 2) / (points.length - 1) : 0;
  const yFor = (score: number) => padding + (1 - score / 100) * (height - padding * 2);
  const coords = points.map((point, index) => ({ ...point, x: padding + index * step, y: yFor(point.score) }));
  const line = coords.map((point, index) => `${index === 0 ? 'M' : 'L'} ${point.x} ${point.y}`).join(' ');
  const area = `${line} L ${coords[coords.length - 1].x} ${height} L ${coords[0].x} ${height} Z`;
  const latest = points[points.length - 1];
  const first = points[0];
  const delta = latest.score - first.score;

  return (
    <div>
      <svg viewBox={`0 0 ${width} ${height}`} className="h-24 w-full" role="img" aria-label={`Posture score across ${points.length} recorded scans, currently ${latest.score} out of 100`}>
        <defs>
          <linearGradient id="scanner-posture-trend" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={ACCENT.cyan} stopOpacity="0.22" />
            <stop offset="100%" stopColor={ACCENT.cyan} stopOpacity="0" />
          </linearGradient>
        </defs>
        {[25, 50, 75].map((tick) => (
          <line
            key={tick}
            x1={padding}
            y1={yFor(tick)}
            x2={width - padding}
            y2={yFor(tick)}
            stroke="rgba(255,255,255,0.05)"
            strokeDasharray="3 3"
          />
        ))}
        <path d={area} fill="url(#scanner-posture-trend)" />
        <path d={line} fill="none" stroke={ACCENT.cyan} strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
        {coords.map((point) => (
          <circle key={point.scanId} cx={point.x} cy={point.y} r={3} fill={scoreColor(point.score)} stroke="#080d1a" strokeWidth={1.2}>
            <title>{`${new Date(point.at).toLocaleString()} — ${point.score}/100`}</title>
          </circle>
        ))}
      </svg>
      <div className="mt-2 flex items-center justify-between font-mono text-[10px] text-slate-600">
        <span>{new Date(first.at).toLocaleDateString()}</span>
        <span style={{ color: delta >= 0 ? ACCENT.emerald : ACCENT.rose }}>
          {delta >= 0 ? '+' : ''}
          {delta} pts across {points.length} scans
        </span>
        <span>{new Date(latest.at).toLocaleDateString()}</span>
      </div>
    </div>
  );
}

/**
 * One expandable finding. Shared by the Findings tab and the History tab's
 * persisted-findings list so the two can never drift apart visually.
 */
function FindingRow({
  finding,
  index,
  expanded,
  onToggle,
}: {
  finding: DefensiveFinding;
  index: number;
  expanded: boolean;
  onToggle: () => void;
}) {
  const severity = finding.threatLevel.toLowerCase();
  const tone = sevColor(severity);
  const Icon = targetIcon(finding.category);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay: Math.min(index * 0.02, 0.4) }}
    >
      <Panel className="overflow-hidden">
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={expanded}
          className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-white/[0.02] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-cyan-400/40"
        >
          <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: tone.hex }} />
          <Icon className="h-4 w-4 shrink-0 text-slate-600" />
          <span className="min-w-0 flex-1">
            <span className="flex flex-wrap items-center gap-2">
              <span className="text-[13px] font-bold text-slate-100">{finding.algorithm}</span>
              <StatusPill
                status={severity === 'critical' || severity === 'high' ? 'critical' : severity === 'safe' ? 'pass' : 'warning'}
                label={finding.threatLevel}
              />
              <span className="font-mono text-[10px] text-slate-600">{finding.status}</span>
            </span>
            <span className="mt-0.5 block truncate font-mono text-[10.5px] text-slate-600">{finding.location}</span>
          </span>
          <span className="hidden shrink-0 text-right lg:block">
            <span className="block text-[11px] font-bold text-emerald-300/80">{finding.pqcReplacement || 'Review'}</span>
            <span className="block font-mono text-[9.5px] text-slate-700">{finding.detectionMethod}</span>
          </span>
          <ChevronRight className={`h-4 w-4 shrink-0 text-slate-700 transition-transform ${expanded ? 'rotate-90 text-cyan-400' : ''}`} />
        </button>

        <AnimatePresence initial={false}>
          {expanded && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
              className="overflow-hidden border-t border-white/[0.06]"
            >
              <div className="px-4 py-4">
                <dl className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                  {[
                    ['Category', finding.category],
                    ['Key size', finding.keySize ? `${finding.keySize} bit` : 'Unknown'],
                    ['Source', finding.source],
                    ['PQC replacement', finding.pqcReplacement || 'Manual review'],
                  ].map(([label, value]) => (
                    <div key={String(label)} className="rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2">
                      <dt className="font-mono text-[9px] uppercase tracking-wider text-slate-600">{label}</dt>
                      <dd className="mt-0.5 truncate font-mono text-[11.5px] text-slate-300" title={String(value)}>
                        {String(value)}
                      </dd>
                    </div>
                  ))}
                </dl>
                <p className="mt-3 text-[12px] leading-relaxed text-slate-400">{finding.description}</p>
                <div className="mt-2 rounded-lg border border-cyan-400/15 bg-cyan-400/[0.04] px-3 py-2">
                  <p className="font-mono text-[9px] uppercase tracking-wider text-cyan-400/70">Evidence</p>
                  <p className="mt-0.5 break-words text-[11.5px] text-slate-300">{finding.evidence}</p>
                </div>
                <div className="mt-2 rounded-lg border border-emerald-400/15 bg-emerald-400/[0.04] px-3 py-2">
                  <p className="font-mono text-[9px] uppercase tracking-wider text-emerald-400/70">Remediation</p>
                  <p className="mt-0.5 text-[11.5px] text-emerald-200/85">{finding.recommendation}</p>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </Panel>
    </motion.div>
  );
}
