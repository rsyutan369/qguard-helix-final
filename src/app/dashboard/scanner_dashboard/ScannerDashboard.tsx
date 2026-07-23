import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useSearchParams } from 'react-router-dom';
import { useSubscription } from '@/hooks/use-subscription';
import { tierMeets } from '@/lib/subscription-access';
import { isOwnerEmail } from '@/lib/admin-access';
import {
  Play, Pause, Shield, AlertTriangle, Activity, Terminal,
  Radio, Target, Search, ChevronRight, CheckCircle2, XCircle,
  Loader2, Server, Database, Globe, Wifi, Lock, Layers,
  Plus, Trash2, History, Network, RefreshCw, Copy, Download,
  RotateCcw, Eraser, FileWarning, KeyRound, Settings, Eye,
  PowerOff, ClipboardCheck, Package, Cloud, Code2, HardDrive,
  Calendar, ChevronDown, Cpu, Sparkles
} from 'lucide-react';
import { useAuth } from '@/contexts/auth-context';
import {
  parseAssetInput,
  deduplicateAssets,
  type ValidatedAsset
} from '@/lib/scanner/asset-validator';
import { useScannerIntelligence } from '@/lib/scanner/use-scanner-intelligence';
import { mandatoryPqcStackMetadata } from '@/lib/crypto/mandatory-pqc-stack';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import AgentCollectorConsole from '@/components/agent-collector/AgentCollectorConsole';
import AgentSettingsConsole from '@/components/agent-collector/AgentSettingsConsole';

type ScanStatus = 'idle' | 'queued' | 'running' | 'analyzing' | 'completed' | 'failed' | 'cancelled';
type TabId = 'setup' | 'overview' | 'findings' | 'logs' | 'history' | 'agents' | 'settings';

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

type DefensiveFinding = {
  id: string;
  algorithm: string;
  category: string;
  location: string;
  threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';
  status: string;
  description: string;
  recommendation: string;
  pqcReplacement: string | null;
  keySize: number | null;
  evidence: string;
  detectionMethod: string;
  source: string;
};

type ScanSummary = {
  targetsScanned: number;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  safe: number;
  vulnerable: number;
  pqcReady: number;
  riskScore: number;
  qScore: number;
};

type LogEntry = {
  timestamp: string;
  level: 'INFO' | 'WARN' | 'ERROR' | 'SUCCESS';
  message: string;
  phase?: string;
  severity?: DefensiveFinding['threatLevel'];
  elapsed?: string;
  moduleName?: string;
};

type ModuleStatus = 'Queued' | 'Running' | 'Completed' | 'Failed' | 'Skipped' | 'No findings';

type ModuleState = {
  id: string;
  name: string;
  status: ModuleStatus;
  target?: string;
  startedAt: string | null;
  completedAt: string | null;
  durationMs: number | null;
  findingsCount: number;
  severityCounts?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    safe: number;
  };
  error: string | null;
};

type HistoryEntry = {
  scanId: string;
  userId: string;
  target: string;
  scanType: string;
  startedAt: string;
  completedAt: string | null;
  durationMs: number | null;
  status: string;
  detectedComponents: number;
  vulnerableFindings: number;
  pqcReadyFindings: number;
  riskScore: number | null;
  qScore: number | null;
  telemetry: any[];
  moduleStates?: ModuleState[];
  scannerModulesUsed?: string[];
  summary?: ScanSummary | null;
  findings?: DefensiveFinding[];
  recommendations?: string[];
  enterpriseScanner2?: any;
  errorLogs: string[];
  linkedCbomRecords: string[];
  linkedAssetRecords: string[];
  linkedExposureNodes: string[];
};

type ScheduledScan = {
  id: string;
  scheduledFor: string;
  createdAt: string;
  status: 'scheduled';
  targets: string[];
};

type HistoryTimeframe = 'last7' | 'all';

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

function sevColor(s: string) {
  switch (s.toLowerCase()) {
    case 'critical': return { t: 'text-red-400', b: 'bg-red-500/10', br: 'border-red-500/30', d: 'bg-red-500' };
    case 'high': return { t: 'text-orange-400', b: 'bg-orange-500/10', br: 'border-orange-500/30', d: 'bg-orange-500' };
    case 'medium': return { t: 'text-yellow-400', b: 'bg-yellow-500/10', br: 'border-yellow-500/30', d: 'bg-yellow-500' };
    case 'low': return { t: 'text-green-400', b: 'bg-green-500/10', br: 'border-green-500/30', d: 'bg-green-500' };
    case 'safe': return { t: 'text-green-400', b: 'bg-green-500/10', br: 'border-green-500/30', d: 'bg-green-500' };
    default: return { t: 'text-cyan-400', b: 'bg-cyan-500/10', br: 'border-cyan-500/30', d: 'bg-cyan-500' };
  }
}

function logColor(level: string) {
  switch (level) {
    case 'WARN': return 'text-yellow-400';
    case 'ERROR': return 'text-red-500';
    case 'SUCCESS': return 'text-green-400';
    default: return 'text-white/50';
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

function moduleStatusColor(status: ModuleStatus) {
  switch (status) {
    case 'Running': return 'border-gold/40 bg-gold/10 text-gold';
    case 'Completed': return 'border-green-500/30 bg-green-500/10 text-green-400';
    case 'Failed': return 'border-red-500/30 bg-red-500/10 text-red-400';
    case 'Skipped': return 'border-white/10 bg-white/[0.03] text-white/35';
    case 'No findings': return 'border-cyan-500/25 bg-cyan-500/10 text-cyan-400';
    default: return 'border-white/10 bg-[#0f1428]/30 text-white/35';
  }
}

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

function formatCompactNumber(value: number) {
  return Number.isFinite(value) ? value.toLocaleString() : '0';
}

function formatTrend(current: number, previous: number) {
  if (!Number.isFinite(current) || !Number.isFinite(previous)) return '0% vs previous 7 days';
  if (previous <= 0) return current > 0 ? 'new vs previous 7 days' : '0% vs previous 7 days';
  const delta = ((current - previous) / previous) * 100;
  const sign = delta > 0 ? '+' : delta < 0 ? '-' : '';
  return `${sign}${Math.abs(delta).toFixed(1)}% vs previous 7 days`;
}

function trendClass(current: number, previous: number, higherIsBetter: boolean) {
  if (previous <= 0) return current > 0 && higherIsBetter ? 'text-green-400' : current > 0 ? 'text-yellow-400' : 'text-white/35';
  const improved = higherIsBetter ? current >= previous : current <= previous;
  return improved ? 'text-green-400' : 'text-red-400';
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

const GLASS_PANEL_CLASSES = 'group relative overflow-hidden rounded-xl border border-[#FFD36B]/20 bg-[#0f1428]/45 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(255,211,107,0.03),0_0_40px_rgba(255,211,107,0.14)] transition-all duration-500 hover:-translate-y-1 hover:border-[#FFD36B]/70 hover:bg-[#0f1428]/65 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.3),inset_0_-24px_60px_rgba(255,211,107,0.15),0_8px_30px_rgba(0,0,0,0.5),0_0_60px_rgba(255,211,107,0.5),0_0_120px_rgba(255,211,107,0.2)] hover:z-10 before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FFF4C0]/70 before:to-transparent before:transition-all before:duration-500 group-hover:before:opacity-100 group-hover:before:shadow-[0_0_15px_rgba(255,211,107,0.9)] group-hover:before:via-[#FFF4C0] after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-48 after:w-48 after:rounded-full after:bg-[#FFD36B]/10 after:blur-3xl after:transition-all after:duration-500 group-hover:after:opacity-100 group-hover:after:bg-[#FFD36B]/25 group-hover:after:blur-[36px] text-white';

export default function ScannerDashboard() {
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedTab = scannerTabFromParam(searchParams.get('tab'));
  const { session, user } = useAuth();

  // Agent Collector Scanners are a PRO+ capability. Basic can run scans and view
  // findings, but not the agent-collector tab or its API. Owner is always Elite.
  const subscription = useSubscription();
  const canUseAgents = isOwnerEmail(user?.email) || (subscription.isActive && tierMeets(subscription.tier, 'pro'));

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
    setProgress(0);
    setJobId(null);
    setCopiedLogs(false);
    setTerminalPaused(false);
    setTerminalPinned(false);
    setScanStartedAt(startedAtMs);
    setStatus('queued');
    setActiveTab('overview');
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
          }

          if (event.summary) setSummary(event.summary);
          if (Array.isArray(event.moduleStates)) setModules(event.moduleStates);
          if (event.type === 'scan-complete') {
            setStatus('completed');
            setProgress(100);
            setActiveTab('findings');
            await fetchHistory();
          }
          if (event.type === 'scan-failed') {
            setStatus('failed');
            setError(event.message || 'Scan failed');
            await fetchHistory();
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

  const riskLabel = summary
    ? summary.riskScore >= 80 ? 'Critical' : summary.riskScore >= 60 ? 'High' : summary.riskScore >= 40 ? 'Medium' : 'Low'
    : 'Idle';

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
  const previousSevenDayHistory = history.filter((entry) => isHistoryEntryInLastDays(entry, 7, 7));
  const historyMetrics = historyMetricSnapshot(displayedHistory);
  const previousMetrics = historyMetricSnapshot(previousSevenDayHistory);
  const currentScanReadiness = summary?.totalFindings
    ? Math.round(((summary.pqcReady ?? 0) / Math.max(1, summary.totalFindings)) * 100)
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
  const dashboardMetrics = status !== 'idle' && summary
    ? {
        totalAssetsScanned: summary.targetsScanned,
        vulnerableAssets: summary.vulnerable > 0 ? Math.max(1, summary.targetsScanned) : 0,
        riskScore: summary.riskScore,
        criticalFindings: summary.critical,
        pqcReadiness: currentScanReadiness,
        totalFindings: summary.totalFindings,
        vulnerableFindings: summary.vulnerable,
        pqcReady: summary.pqcReady,
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
  const dashboardFindings = findings.length > 0
    ? findings
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
  const assetOutcomeRows = [
    { label: 'Scanned', value: dashboardMetrics.totalAssetsScanned, color: '#3b82f6' },
    { label: 'Vulnerable', value: dashboardMetrics.vulnerableAssets, color: '#ef4444' },
    { label: 'Findings', value: dashboardMetrics.totalFindings, color: '#f97316' },
    { label: 'PQC Ready', value: dashboardMetrics.pqcReady, color: '#22c55e' },
    { label: 'Scheduled', value: scheduledScans.filter((scan) => Date.parse(scan.scheduledFor) > Date.now()).length, color: '#a855f7' },
  ];
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
  const terminalVisible = status !== 'idle' || logs.length > 0;
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

  const kpis = [
    { label: 'Assets', value: `${liveCounts.assets}`, icon: Server, color: 'text-white' },
    { label: 'Components', value: `${liveCounts.components}`, icon: Target, color: 'text-white' },
    { label: 'Critical', value: `${liveCounts.critical}`, icon: AlertTriangle, color: 'text-red-400' },
    { label: 'High', value: `${liveCounts.high}`, icon: AlertTriangle, color: 'text-orange-400' },
    { label: 'Medium', value: `${liveCounts.medium}`, icon: FileWarning, color: 'text-yellow-400' },
    { label: 'Low', value: `${liveCounts.low}`, icon: Shield, color: 'text-green-400' },
    { label: 'Vulnerable', value: `${liveCounts.vulnerable}`, icon: AlertTriangle, color: 'text-red-400' },
    { label: 'PQC Ready', value: `${liveCounts.pqcReady}`, icon: CheckCircle2, color: 'text-green-400' },
    { label: 'Risk', value: summary ? `${summary.riskScore}/100` : 'N/A', icon: Shield, color: summary && summary.riskScore >= 60 ? 'text-red-400' : 'text-green-400' },
    { label: 'Q-Score', value: summary ? `${summary.qScore}/100` : 'N/A', icon: Activity, color: 'text-gold' },
    { label: 'Status', value: riskLabel, icon: Radio, color: 'text-cyan-400' },
  ];

  return (
    <div className="p-6 lg:p-8 space-y-6 min-h-screen">
      <WorkflowRail activeStage="discovery" />
      <header className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-black uppercase tracking-tight text-white">
            PQC Remediation <span className="text-gold">Scanner</span>
          </h1>
          <p className="text-white/50 mt-1 text-sm">
            Authorized cryptographic discovery, CBOM generation, approved patch orchestration, validation, rollback, and PQC readiness reporting.
          </p>
        </div>
        <div className="flex gap-3 items-center">
          {isRunning ? (
            <button onClick={handleCancel} className="px-5 py-2.5 rounded-lg border border-yellow-500/40 bg-yellow-500/10 text-yellow-400 text-[10px] font-black uppercase tracking-[0.15em] flex items-center gap-2 hover:bg-yellow-500/20 transition-colors">
              <Pause className="h-3.5 w-3.5" /> Cancel Scan
            </button>
          ) : (
            <button
              onClick={handleStart}
              disabled={targets.length === 0 || !authorizationAccepted || !session?.access_token}
              className="px-5 py-2.5 rounded-lg border border-gold/40 bg-gold/10 text-gold text-[10px] font-black uppercase tracking-[0.15em] flex items-center gap-2 hover:bg-gold/20 transition-colors shadow-[0_0_20px_rgba(212,175,55,0.15)] disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Play className="h-3.5 w-3.5" /> Start Authorized Scan
            </button>
          )}
          {isRunning && (
            <div className="px-4 py-2 border border-gold/30 bg-gold/5 rounded-lg text-[10px] font-black text-gold uppercase tracking-[0.15em] flex items-center gap-2">
              <Radio className="h-3 w-3 animate-pulse" /> Live SSE
            </div>
          )}
        </div>
      </header>

      {error && (
        <div className="rounded-xl border border-red-500/25 bg-red-500/10 p-4 text-sm text-red-300 flex items-start gap-3">
          <XCircle className="h-4 w-4 mt-0.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {status !== 'idle' && activeTab !== 'setup' && (
        <div className="rounded-xl border p-5 glass-panel">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-3">
              {isRunning && <Loader2 className="h-4 w-4 text-gold animate-spin" />}
              {status === 'completed' && <CheckCircle2 className="h-4 w-4 text-green-400" />}
              {status === 'failed' && <XCircle className="h-4 w-4 text-red-400" />}
              <span className="text-xs font-black uppercase tracking-[0.15em] text-white/60">{status}</span>
            </div>
            <span className="text-lg font-black text-gold">{progress}%</span>
          </div>
          <div className="h-2.5 rounded-full bg-white/[0.06] overflow-hidden">
            <motion.div
              className={`h-full rounded-full ${status === 'completed' ? 'bg-green-500' : status === 'failed' ? 'bg-red-500' : 'bg-gradient-to-r from-gold via-yellow-300 to-gold'}`}
              animate={{ width: `${progress}%` }}
              transition={{ duration: 0.25 }}
            />
          </div>
        </div>
      )}

      {terminalVisible && (
        <div className="grid xl:grid-cols-[minmax(0,1fr)_380px] gap-4">
          <div className="rounded-xl border overflow-hidden shadow-[0_0_35px_rgba(212,175,55,0.08)] glass-panel">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 px-4 py-3 border-b border-gold/10 bg-gold/[0.04]">
              <div className="flex items-center gap-3 min-w-0">
                <Terminal className="h-4 w-4 text-gold" />
                <div>
                  <div className="text-[10px] font-black uppercase tracking-[0.18em] text-white/60">Live Terminal Telemetry</div>
                  <div className="text-[10px] text-white/30 font-mono truncate">{jobId || 'waiting-for-job-id'} - {progress}%</div>
                </div>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                <button onClick={() => setTerminalPaused((value) => !value)} className="px-2.5 py-1.5 rounded-md border border-gold/15 text-[9px] font-black uppercase tracking-wider text-white/55 hover:text-gold hover:border-gold/40 transition-colors">
                  {terminalPaused ? 'Resume View' : 'Pause View'}
                </button>
                <button onClick={() => setTerminalPinned((value) => !value)} className="px-2.5 py-1.5 rounded-md border border-gold/15 text-[9px] font-black uppercase tracking-wider text-white/55 hover:text-gold hover:border-gold/40 transition-colors">
                  {terminalPinned ? 'Auto-scroll' : 'Manual'}
                </button>
                <button onClick={handleCopyLogs} disabled={logs.length === 0} className="p-1.5 rounded-md border border-gold/15 text-white/45 hover:text-gold hover:border-gold/40 disabled:opacity-30 transition-colors" title="Copy logs">
                  <Copy className="h-3.5 w-3.5" />
                </button>
                <button onClick={handleDownloadReport} disabled={logs.length === 0 && findings.length === 0} className="p-1.5 rounded-md border border-gold/15 text-white/45 hover:text-gold hover:border-gold/40 disabled:opacity-30 transition-colors" title="Download scan report">
                  <Download className="h-3.5 w-3.5" />
                </button>
                <button onClick={handleClearTerminal} disabled={isRunning || logs.length === 0} className="p-1.5 rounded-md border border-gold/15 text-white/45 hover:text-red-400 hover:border-red-500/30 disabled:opacity-30 transition-colors" title="Clear terminal after completion">
                  <Eraser className="h-3.5 w-3.5" />
                </button>
                {isRunning && (
                  <button onClick={handleCancel} className="px-2.5 py-1.5 rounded-md border border-yellow-500/30 bg-yellow-500/10 text-[9px] font-black uppercase tracking-wider text-yellow-400 hover:bg-yellow-500/20 transition-colors">
                    Cancel
                  </button>
                )}
              </div>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-px border-b border-gold/10 bg-gold/10">
              {[
                ['Assets', liveCounts.assets, 'text-white'],
                ['Components', liveCounts.components, 'text-white'],
                ['Critical', liveCounts.critical, 'text-red-400'],
                ['High', liveCounts.high, 'text-orange-400'],
                ['Medium', liveCounts.medium, 'text-yellow-400'],
                ['Low', liveCounts.low, 'text-green-400'],
                ['PQC Ready', liveCounts.pqcReady, 'text-green-400'],
                ['Vulnerable', liveCounts.vulnerable, 'text-red-400'],
              ].map(([label, value, color]) => (
                <div key={label as string} className="px-3 py-2 glass-panel">
                  <div className="text-[8px] uppercase tracking-wider text-white/25 font-black">{label}</div>
                  <div className={`text-lg font-black ${color}`}>{value}</div>
                </div>
              ))}
            </div>

            <div className="h-[360px] overflow-y-auto p-4 font-mono text-[11px] space-y-1 bg-[radial-gradient(circle_at_top_right,rgba(212,175,55,0.06),transparent_30%)]">
              {logs.length === 0 ? (
                <div className="h-full flex items-center justify-center text-white/15 uppercase tracking-widest text-[10px] font-black">
                  Awaiting authorized scan initiation...
                </div>
              ) : logs.map((entry, index) => {
                const severity = entry.severity ? sevColor(entry.severity.toLowerCase()) : null;
                return (
                  <div key={`${entry.timestamp}-${index}`} className={`leading-relaxed break-words ${logColor(entry.level)}`}>
                    <span className="text-white/20 inline-block w-14">[{entry.elapsed || '00:00'}]</span>
                    <span className={`font-bold inline-block w-20 ${logColor(entry.level)}`}>[{entry.level}]</span>
                    {severity && <span className={`mr-2 px-1.5 py-0.5 rounded border text-[9px] ${severity.br} ${severity.b} ${severity.t}`}>{entry.severity}</span>}
                    {entry.phase && <span className="text-white/30 mr-2">[{entry.phase}]</span>}
                    {entry.moduleName && <span className="text-gold/50 mr-2">[{entry.moduleName}]</span>}
                    <span>{entry.message}</span>
                  </div>
                );
              })}
              {copiedLogs && <div className="text-green-400">[copy] Telemetry copied to clipboard</div>}
              {isRunning && <div className="text-gold/50 animate-pulse mt-2">|</div>}
              <div ref={logEndRef} />
            </div>
          </div>

          <div className="rounded-xl border overflow-hidden glass-panel">
            <div className="px-4 py-3 border-b border-gold/10 bg-gold/[0.04] flex items-center justify-between">
              <div className="text-[10px] font-black uppercase tracking-[0.18em] text-white/60">Module Execution Timeline</div>
              <div className="text-[10px] text-white/30 font-mono">{modules.filter((module) => module.status === 'Completed').length}/{modules.length || 0}</div>
            </div>
            <div className="max-h-[456px] overflow-y-auto p-3 space-y-2">
              {modules.length === 0 ? (
                <div className="text-center text-white/20 text-[10px] uppercase tracking-widest font-bold py-16">
                  Module queue will appear when the backend stream starts
                </div>
              ) : modules.map((module) => (
                <div key={module.id} className="rounded-lg border border-gold/10 bg-white/[0.02] p-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="text-xs font-bold text-white/75 truncate">{module.name}</div>
                      <div className="text-[9px] text-white/25 font-mono truncate">{module.target || 'queued'}</div>
                    </div>
                    <span className={`shrink-0 px-2 py-1 rounded border text-[8px] font-black uppercase tracking-wider ${moduleStatusColor(module.status)}`}>
                      {module.status}
                    </span>
                  </div>
                  <div className="grid grid-cols-3 gap-2 mt-3 text-[9px]">
                    <div>
                      <div className="text-white/25 uppercase font-black">Duration</div>
                      <div className="text-white/55 font-mono">{formatMs(module.durationMs)}</div>
                    </div>
                    <div>
                      <div className="text-white/25 uppercase font-black">Findings</div>
                      <div className="text-white/55 font-mono">{module.findingsCount}</div>
                    </div>
                    <div>
                      <div className="text-white/25 uppercase font-black">Started</div>
                      <div className="text-white/55 font-mono">{module.startedAt ? new Date(module.startedAt).toLocaleTimeString() : 'N/A'}</div>
                    </div>
                  </div>
                  {module.error && (
                    <div className="mt-3 rounded-md border border-red-500/20 bg-red-500/10 p-2">
                      <div className="text-[8px] font-black uppercase tracking-wider text-red-400/70 mb-1">Error Details</div>
                      <div className="text-[10px] text-red-300 leading-relaxed">{module.error}</div>
                      {!isRunning && (
                        <button onClick={() => handleRetryFailedModule(module)} className="mt-2 px-2.5 py-1.5 rounded border border-red-500/25 text-[8px] font-black uppercase tracking-wider text-red-300 hover:bg-red-500/10 transition-colors flex items-center gap-1.5">
                          <RotateCcw className="h-3 w-3" /> Retry Failed Module
                        </button>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {failedModules.length > 0 && (
        <div className="rounded-xl border border-red-500/25 bg-red-500/10 p-4">
          <div className="flex items-center gap-2 text-red-300 text-xs font-black uppercase tracking-[0.15em] mb-2">
            <XCircle className="h-4 w-4" /> Module Errors
          </div>
          <div className="space-y-2">
            {failedModules.map((module) => (
              <div key={module.id} className="text-xs text-red-200/80 flex flex-col md:flex-row md:items-center justify-between gap-2">
                <span><strong>{module.name}:</strong> {module.error || 'Module failed'}</span>
                {!isRunning && (
                  <button onClick={() => handleRetryFailedModule(module)} className="px-3 py-1.5 rounded border border-red-500/30 text-[9px] font-black uppercase tracking-wider text-red-300 hover:bg-red-500/10 transition-colors">
                    Retry Failed Module
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="flex gap-1 border-b border-gold/10 pb-0 overflow-x-auto">
        {[
          { id: 'setup' as TabId, label: 'Scanner' },
          { id: 'history' as TabId, label: 'History' },
          { id: 'agents' as TabId, label: 'Agent Collector Scanners' },
          { id: 'settings' as TabId, label: 'Settings' },
          { id: 'overview' as TabId, label: 'Live Dashboard' },
          { id: 'findings' as TabId, label: `Findings (${dashboardFindings.length})` },
          { id: 'logs' as TabId, label: 'Telemetry' },
        ].filter((tab) => tab.id !== 'agents' || canUseAgents).map((tab) => (
          <button
            key={tab.id}
            onClick={() => handleTabSelect(tab.id)}
            className={`px-4 py-2.5 text-[10px] font-black uppercase tracking-[0.15em] border-b-2 transition-all -mb-px whitespace-nowrap ${
              activeTab === tab.id ? 'border-gold text-gold' : 'border-transparent text-white/35 hover:text-white/55'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'setup' && (
        <div className="space-y-8 animate-in fade-in duration-500">
          {/* 1. Cloned Premium Gold Header Section */}
          <header className="flex flex-col xl:flex-row xl:items-end justify-between gap-6 mb-6 mt-2">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <div className="p-2 rounded bg-gold/10 border border-gold/20">
                  <Cpu className="w-6 h-6 text-gold" />
                </div>
                <h1 className="text-3xl font-black uppercase tracking-tight text-white leading-none">
                  PQC <span className="text-gold">Scanner</span>
                </h1>
              </div>
              <p className="text-white/50 text-sm font-medium">Discover and analyze quantum-vulnerable cryptographic assets across your infrastructure.</p>
            </div>

            {/* Action Buttons */}
            <div className="flex items-center gap-3 overflow-x-auto pb-1 xl:pb-0 shrink-0 select-none custom-scrollbar">
              {/* Scan Now / Stop Scan Button */}
              <button
                onClick={() => {
                  if (isRunning) {
                    void handleCancel();
                    showToast('Quantum scan terminated by operator.');
                  } else {
                    if (targets.length === 0) {
                      showToast('Please enter and add authorized targets to the Scan Queue below.');
                      return;
                    }
                    if (!authorizationAccepted) {
                      showToast('Please accept the authorization check before initiating the scan.');
                      return;
                    }
                    void handleStart();
                    showToast('Quantum scanning engines initialized...');
                  }
                }}
                className={`px-4 py-2.5 border rounded-lg text-white transition-all flex items-center gap-2 group shrink-0 ${
                  isRunning
                    ? 'border-red-500/30 bg-red-500/10 hover:bg-red-500/20'
                    : 'bg-gold/10 hover:bg-gold/20 border-gold/30 shadow-[0_0_20px_rgba(212,175,55,0.15)] animate-pulse'
                }`}
              >
                {isRunning ? (
                  <Pause className="w-4 h-4 text-red-500 animate-pulse" />
                ) : (
                  <Play className="w-4 h-4 text-gold group-hover:scale-110 transition-transform" />
                )}
                <div className="text-left leading-none">
                  <div className={`text-[10px] font-black uppercase tracking-wider ${isRunning ? 'text-red-400' : 'text-gold'}`}>
                    {isRunning ? 'Stop Scan' : 'Scan Now'}
                  </div>
                  <div className="text-[9px] text-white/40 font-bold uppercase mt-0.5">
                    {isRunning ? 'Scan in Progress' : 'Start New Scan'}
                  </div>
                </div>
              </button>

              {/* Schedule Scan */}
              <button
                onClick={handleOpenSchedule}
                className="px-4 py-2.5 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg text-white transition-all flex items-center gap-2 group shrink-0"
              >
                <Calendar className="w-4 h-4 text-gold group-hover:rotate-12 transition-transform" />
                <div className="text-left leading-none">
                  <div className="text-[10px] font-black uppercase tracking-wider text-white">Schedule Scan</div>
                  <div className="text-[9px] text-white/40 font-bold uppercase mt-0.5">
                    {nextScheduledScan ? new Date(nextScheduledScan.scheduledFor).toLocaleDateString() : 'Automate Scans'}
                  </div>
                </div>
              </button>

              {/* Export Report */}
              <button
                onClick={handleExportScannerReport}
                className="px-4 py-2.5 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg text-white transition-all flex items-center gap-2 group shrink-0"
              >
                <Download className="w-4 h-4 text-gold group-hover:-translate-y-0.5 transition-transform" />
                <div className="text-left leading-none">
                  <div className="text-[10px] font-black uppercase tracking-wider text-white">Export Report</div>
                  <div className="text-[9px] text-white/40 font-bold uppercase mt-0.5">Download Results</div>
                </div>
              </button>

              {/* Timeframe toggle — All Time ⇄ Last 7 Days */}
              <div className="relative group/dropdown shrink-0">
                <button
                  onClick={() => void handleToggleTimeframe()}
                  title={historyTimeframe === 'all' ? 'Showing all recorded scans — click to filter to the last 7 days' : 'Showing the last 7 days — click to show all recorded scans'}
                  className="px-4 py-2.5 bg-white/5 border border-white/10 rounded-lg text-white hover:border-gold/30 transition-all flex items-center gap-3 text-left"
                >
                  <Calendar className="w-4 h-4 text-gold shrink-0" />
                  <div className="leading-none">
                    <div className="text-[10px] font-black uppercase tracking-wider text-white">{historyTimeframe === 'all' ? 'All Time' : 'Last 7 Days'}</div>
                    <div className="text-[9px] text-white/40 font-bold uppercase mt-0.5">{displayedHistory.length} {displayedHistory.length === 1 ? 'Scan' : 'Scans'}</div>
                  </div>
                  <ChevronDown className="w-3.5 h-3.5 text-white/40 group-hover/dropdown:text-gold transition-colors ml-1 shrink-0" />
                </button>
              </div>
            </div>
          </header>

          {/* 2. Metrics Grid (5 Columns) */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-6 mb-6">
            {/* Metric 1: Total Assets Scanned */}
            <div className={`p-5 flex items-center justify-between ${GLASS_PANEL_CLASSES}`}>
              <div className="space-y-1">
                <span className="text-[9px] font-bold text-white/40 uppercase tracking-widest block">TOTAL ASSETS SCANNED</span>
                <span className="text-2xl font-black text-white block leading-none font-mono">
                  {formatCompactNumber(dashboardMetrics.totalAssetsScanned)}
                </span>
                <span className={`text-[10px] font-black uppercase tracking-wider block pt-1 font-sans ${trendClass(dashboardMetrics.totalAssetsScanned, previousMetrics.totalAssetsScanned, true)}`}>
                  {formatTrend(dashboardMetrics.totalAssetsScanned, previousMetrics.totalAssetsScanned)}
                </span>
              </div>
              <div className="shrink-0 ml-4">
                <Layers className="w-6 h-6 text-gold drop-shadow-[0_0_6px_rgba(255,211,107,0.4)]" />
              </div>
            </div>

            {/* Metric 2: Vulnerable Assets */}
            <div className={`p-5 flex items-center justify-between ${GLASS_PANEL_CLASSES}`}>
              <div className="space-y-1">
                <span className="text-[9px] font-bold text-white/40 uppercase tracking-widest block">VULNERABLE ASSETS</span>
                <span className="text-2xl font-black text-white block leading-none font-mono">
                  {formatCompactNumber(dashboardMetrics.vulnerableAssets)}
                </span>
                <span className={`text-[10px] font-black uppercase tracking-wider block pt-1 font-sans ${trendClass(dashboardMetrics.vulnerableAssets, previousMetrics.vulnerableAssets, false)}`}>
                  {formatTrend(dashboardMetrics.vulnerableAssets, previousMetrics.vulnerableAssets)}
                </span>
              </div>
              <div className="shrink-0 ml-4">
                <AlertTriangle className="w-6 h-6 text-gold drop-shadow-[0_0_6px_rgba(255,211,107,0.4)]" />
              </div>
            </div>

            {/* Metric 3: Risk Score */}
            <div className={`p-5 flex items-center justify-between ${GLASS_PANEL_CLASSES}`}>
              <div className="space-y-1">
                <span className="text-[9px] font-bold text-white/40 uppercase tracking-widest block">RISK SCORE</span>
                <span className="text-2xl font-black text-white block leading-none font-mono">
                  {dashboardMetrics.riskScore}/100
                </span>
                <span className={`text-[10px] font-black uppercase tracking-wider block pt-1 font-sans ${trendClass(dashboardMetrics.riskScore, previousMetrics.riskScore, false)}`}>
                  {dashboardRiskLabel}
                </span>
              </div>
              <div className="shrink-0 ml-4">
                <svg className="w-16 h-8" viewBox="0 0 60 20">
                  <path
                    d="M0,15 Q10,12 20,18 T40,6 T60,2"
                    fill="none"
                    stroke="#ef4444"
                    strokeWidth="2.5"
                    strokeLinecap="round"
                    className="drop-shadow-[0_0_4px_rgba(239,68,68,0.5)]"
                  />
                </svg>
              </div>
            </div>

            {/* Metric 4: Critical Findings */}
            <div className={`p-5 flex items-center justify-between ${GLASS_PANEL_CLASSES} border-red-500/30 shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(239,68,68,0.03),0_0_40px_rgba(239,68,68,0.1)] hover:border-red-500/70 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.3),inset_0_-24px_60px_rgba(239,68,68,0.15),0_8px_30px_rgba(0,0,0,0.5),0_0_60px_rgba(239,68,68,0.4)]`}>
              <div className="space-y-1">
                <span className="text-[9px] font-bold text-white/40 uppercase tracking-widest block font-mono">CRITICAL FINDINGS</span>
                <span className="text-2xl font-black text-red-500 block leading-none font-mono">
                  {formatCompactNumber(dashboardMetrics.criticalFindings)}
                </span>
                <span className={`text-[10px] font-black uppercase tracking-wider block pt-1 font-sans ${trendClass(dashboardMetrics.criticalFindings, previousMetrics.criticalFindings, false)}`}>
                  {formatTrend(dashboardMetrics.criticalFindings, previousMetrics.criticalFindings)}
                </span>
              </div>
              <div className="shrink-0 ml-4">
                <Target className="w-6 h-6 text-red-500 drop-shadow-[0_0_6px_rgba(239,68,68,0.4)]" />
              </div>
            </div>

            {/* Metric 5: PQC Readiness */}
            <div className={`p-5 flex items-center justify-between ${GLASS_PANEL_CLASSES}`}>
              <div className="space-y-1">
                <span className="text-[9px] font-bold text-white/40 uppercase tracking-widest block font-mono">PQC READINESS</span>
                <span className="text-2xl font-black text-white block leading-none font-mono">
                  {dashboardMetrics.pqcReadiness}%
                </span>
                <span className={`text-[10px] font-black uppercase tracking-wider block pt-1 font-sans ${trendClass(dashboardMetrics.pqcReadiness, previousMetrics.pqcReadiness, true)}`}>
                  {formatTrend(dashboardMetrics.pqcReadiness, previousMetrics.pqcReadiness)}
                </span>
              </div>
              <div className="shrink-0 ml-4">
                <svg className="w-12 h-12 rotate-[-90deg]">
                  <circle cx="24" cy="24" r="18" stroke="rgba(255,255,255,0.05)" strokeWidth="4" fill="none" />
                  <circle
                    cx="24" cy="24" r="18"
                    stroke="#10b981" strokeWidth="4" fill="none"
                    strokeDasharray={`${2 * Math.PI * 18}`}
                    strokeDashoffset={`${2 * Math.PI * 18 * (1 - Math.max(0, Math.min(100, dashboardMetrics.pqcReadiness)) / 100)}`}
                    strokeLinecap="round"
                    className="drop-shadow-[0_0_4px_rgba(16,185,129,0.5)]"
                  />
                </svg>
              </div>
            </div>
          </div>

          <div className="grid lg:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div className={GLASS_PANEL_CLASSES + " p-5"}>
              <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60 mb-4 flex items-center gap-2">
                <Target className="h-4 w-4 text-gold" /> Authorized Asset Input
              </h2>
              <p className="text-xs text-white/40 mb-4 leading-relaxed">
                Enter domains, URLs, public IPs, GitHub repository URLs, or SSH endpoints that you own or are explicitly authorized to assess.
              </p>
              <textarea
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder={'example.com\nhttps://api.company.com\nhttps://github.com/company/repo\nssh://bastion.company.com:22'}
                className="w-full h-40 border rounded-lg p-4 text-sm font-mono focus:outline-none focus:transition-colors text-white placeholder-white/20 resize-none mb-4 glass-panel"
              />
              <label className="flex items-start gap-3 rounded-lg border border-gold/10 bg-white/[0.02] p-3 mb-4 cursor-pointer">
                <input
                  type="checkbox"
                  checked={authorizationAccepted}
                  onChange={(e) => setAuthorizationAccepted(e.target.checked)}
                  className="mt-1 accent-[#D4AF37]"
                />
                <span className="text-xs text-white/45 leading-relaxed">
                  I confirm these assets belong to this account or are explicitly authorized for defensive cryptographic inventory and compliance scanning. No exploitation, credential collection, or stealth scanning will be performed.
                </span>
              </label>
              <div className="flex justify-end">
                <button
                  onClick={handleParseInput}
                  disabled={!inputText.trim()}
                  className="px-4 py-2 rounded-lg border border-gold/30 bg-gold/10 text-gold text-[10px] font-black uppercase tracking-[0.15em] flex items-center gap-2 hover:bg-gold/20 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <Plus className="h-3.5 w-3.5" /> Add Targets
                </button>
              </div>
            </div>

            {inputText && (
              <div className="rounded-xl border border-white/10 bg-white/5 p-4">
                <div className="text-xs font-bold text-white/50 mb-2">Live Validation</div>
                <div className="space-y-1 max-h-32 overflow-y-auto font-mono text-[10px]">
                  {parseAssetInput(inputText).slice(0, 6).map((asset, index) => (
                    <div key={`${asset.raw}-${index}`} className={`flex items-center gap-2 ${asset.valid ? 'text-green-400' : 'text-red-400'}`}>
                      {asset.valid ? <CheckCircle2 className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}
                      <span className="truncate">{asset.raw}</span>
                      <span className="text-white/30 ml-2">{asset.valid ? asset.type : asset.error}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className={GLASS_PANEL_CLASSES + " p-5 flex flex-col"}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60 flex items-center gap-2">
                <Network className="h-4 w-4 text-gold" /> Scan Queue ({targets.length})
              </h2>
              {targets.length > 0 && (
                <button onClick={() => setTargets([])} className="text-white/30 hover:text-red-400 transition-colors" title="Clear all targets">
                  <Trash2 className="h-4 w-4" />
                </button>
              )}
            </div>
            <div className="flex-1 overflow-y-auto space-y-2 pr-2 min-h-[250px]">
              {targets.length === 0 ? (
                <div className="h-full flex items-center justify-center text-white/20 text-xs uppercase tracking-widest font-bold border-2 border-dashed border-white/5 rounded-lg">
                  No authorized targets queued
                </div>
              ) : targets.map((target, index) => (
                <div key={`${target.host}-${target.port}-${index}`} className="flex items-center justify-between p-3 rounded-lg border border-gold/10 bg-white/[0.02] group">
                  <div className="flex items-center gap-3 overflow-hidden">
                    <div className="h-6 w-6 rounded bg-gold/10 border border-gold/20 flex items-center justify-center shrink-0">
                      <Globe className="h-3 w-3 text-gold/60" />
                    </div>
                    <div className="min-w-0">
                      <div className="text-sm font-bold text-white/80 truncate">{target.host}</div>
                      <div className="text-[9px] font-mono text-white/30 uppercase">{target.type} {target.port ? `:${target.port}` : ''}</div>
                    </div>
                  </div>
                  <button onClick={() => setTargets(targets.filter((_, idx) => idx !== index))} className="opacity-0 group-hover:opacity-100 text-white/20 hover:text-red-400 p-1 transition-all">
                    <XCircle className="h-4 w-4" />
                  </button>
                </div>
              ))}
            </div>
            <div className="mt-4 pt-4 border-t border-gold/10">
              <button
                onClick={handleStart}
                disabled={targets.length === 0 || isRunning || !authorizationAccepted || !session?.access_token}
                className="w-full py-3 rounded-lg bg-gold text-black text-xs font-black uppercase tracking-[0.15em] flex items-center justify-center gap-2 hover:bg-yellow-400 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Play className="h-4 w-4" /> Start Defensive Scan
              </button>
            </div>
          </div>
        </div>
      </div>
      )}

      {activeTab === 'agents' && canUseAgents && <AgentCollectorConsole />}

      {activeTab === 'settings' && (
        canUseAgents ? (
          <AgentSettingsConsole />
        ) : (
          <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-8 text-center">
            <p className="text-sm text-white/55">Agent Collector settings require the <span className="font-bold text-white/80">Pro</span> plan or higher.</p>
          </div>
        )
      )}

      {activeTab === 'overview' && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
            {kpis.map((kpi, index) => (
              <motion.div key={kpi.label} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * 0.04 }} className={GLASS_PANEL_CLASSES + " p-4"}>
                <div className="flex items-center gap-1.5 mb-1.5">
                  <kpi.icon className="h-3 w-3 text-gold/40" />
                  <span className="text-[9px] font-black uppercase tracking-[0.15em] text-white/35">{kpi.label}</span>
                </div>
                <div className={`text-2xl font-black ${kpi.color}`}>{kpi.value}</div>
              </motion.div>
            ))}
          </div>

          {/* Cloned Metrics & Activity Dashboard (2 Cards Per Row) */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

            {/* Row 1 : Vulnerabilities by Type and Top Vulnerable Algorithms */}

            {/* 1. Vulnerabilities by Type Card */}
            <div className={GLASS_PANEL_CLASSES + " p-5 flex flex-col justify-between"}>
              <div className="relative z-10 space-y-2">
                <h3 className="text-xs font-black uppercase tracking-[0.2em] text-[#FFD36B] mb-2">Vulnerabilities by Type</h3>

                <div className="space-y-1.5">
                  {[
                    { label: 'RSA', count: 1256, max: 1500, color: 'from-red-600 to-red-500', shadow: 'shadow-[0_0_8px_rgba(239,68,68,0.3)]' },
                    { label: 'ECC', count: 865, max: 1500, color: 'from-orange-600 to-orange-500', shadow: 'shadow-[0_0_8px_rgba(249,115,22,0.3)]' },
                    { label: 'Weak TLS', count: 643, max: 1500, color: 'from-yellow-600 to-yellow-500', shadow: 'shadow-[0_0_8px_rgba(234,179,8,0.3)]' },
                    { label: 'SHA-1', count: 512, max: 1500, color: 'from-yellow-500 to-yellow-400', shadow: 'shadow-[0_0_8px_rgba(234,179,8,0.2)]' },
                    { label: 'MD5', count: 276, max: 1500, color: 'from-amber-500 to-amber-400', shadow: 'shadow-[0_0_8px_rgba(245,158,11,0.2)]' },
                    { label: '3DES', count: 214, max: 1500, color: 'from-amber-400 to-yellow-400', shadow: 'shadow-[0_0_8px_rgba(250,204,21,0.2)]' },
                    { label: 'Other', count: 187, max: 1500, color: 'from-gold/70 to-gold/50', shadow: 'shadow-[0_0_8px_rgba(212,175,55,0.2)]' }
                  ].map((item) => {
                    const pct = (item.count / item.max) * 100;
                    return (
                      <div key={item.label} className="space-y-0.5">
                        <div className="flex items-center justify-between text-[8px] font-bold">
                          <span className="text-white/50 font-mono tracking-wider">{item.label}</span>
                          <span className="text-white/80 font-mono">{item.count.toLocaleString()}</span>
                        </div>
                        <div className="h-1 rounded-full bg-white/[0.04] overflow-hidden flex">
                          <div
                            className={`h-full rounded-full bg-gradient-to-r ${item.color} ${item.shadow}`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* 2. Top Vulnerable Algorithms Card */}
            <div className={GLASS_PANEL_CLASSES + " p-5 flex flex-col justify-between"}>
              <div className="relative z-10">
                <h3 className="text-xs font-black uppercase tracking-[0.2em] text-[#FFD36B] mb-2">Top Vulnerable Algorithms</h3>
                <div className="overflow-x-auto scrollbar-none">
                  <table className="w-full text-left text-[8px] font-bold">
                    <thead>
                      <tr className="border-b border-gold/10 text-white/30 uppercase tracking-[0.1em]">
                        <th className="pb-1 font-black">Algorithm</th>
                        <th className="pb-1 font-black text-center">Assets</th>
                        <th className="pb-1 font-black text-right">Risk Level</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gold/5 text-white/70">
                      {topVulnerableAlgorithmRows.length === 0 ? (
                        <tr>
                          <td colSpan={3} className="py-6 text-center text-white/25 uppercase tracking-widest">No vulnerable algorithms recorded</td>
                        </tr>
                      ) : topVulnerableAlgorithmRows.map((row, idx) => (
                        <tr key={idx} className="hover:bg-white/5 transition-colors">
                          <td className="py-1 font-mono">{row.algo}</td>
                          <td className="py-1 font-mono text-center">{formatCompactNumber(row.assets)}</td>
                          <td className={`py-1 font-black text-right uppercase tracking-wider ${row.color}`}>{row.risk}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            {/* Row 2 : Recent Alerts and Scan Activities */}

            {/* 3. Recent Alerts Card */}
            <div className={GLASS_PANEL_CLASSES + " p-5 flex flex-col justify-between"}>
              <div className="relative z-10 space-y-3.5">
                <h3 className="text-xs font-black uppercase tracking-[0.2em] text-[#FFD36B]">Recent Alerts</h3>

                <div className="space-y-3">
                  {[
                    { title: 'Critical Vulnerability Detected', desc: 'RSA-1024 key detected on web-server-01', time: '5m ago', type: 'critical' },
                    { title: 'Weak TLS Version Detected', desc: 'TLS 1.0 enabled on api.payment.local', time: '15m ago', type: 'warning' },
                    { title: 'Expired Certificate Found', desc: 'Certificate expired on mail.enterprise.com', time: '27m ago', type: 'critical' },
                    { title: 'Deprecated Algorithm Detected', desc: 'SHA-1 usage detected on legacy-app-02', time: '45m ago', type: 'warning' },
                    { title: 'New Asset Discovered', desc: '10.0.50.23 added to scan scope', time: '1h ago', type: 'info' }
                  ].map((alert, idx) => {
                    const isCritical = alert.type === 'critical';
                    const isWarning = alert.type === 'warning';
                    return (
                      <div key={idx} className="flex gap-2">
                        <div className="shrink-0 mt-0.5">
                          {isCritical ? (
                            <div className="w-5.5 h-5.5 rounded-full bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-500">
                              <AlertTriangle className="w-3 h-3" />
                            </div>
                          ) : isWarning ? (
                            <div className="w-5.5 h-5.5 rounded-full bg-yellow-500/10 border border-yellow-500/20 flex items-center justify-center text-yellow-500">
                              <AlertTriangle className="w-3 h-3" />
                            </div>
                          ) : (
                            <div className="w-5.5 h-5.5 rounded-full bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
                              <Globe className="w-3 h-3" />
                            </div>
                          )}
                        </div>

                        <div className="min-w-0 flex-1">
                          <div className="flex items-center justify-between gap-1">
                            <span className={`text-[8.5px] font-black uppercase tracking-wider ${isCritical ? 'text-red-400' : isWarning ? 'text-yellow-400' : 'text-cyan-400'}`}>
                              {alert.title}
                            </span>
                            <span className="text-[7.5px] font-mono text-white/30 shrink-0">{alert.time}</span>
                          </div>
                          <p className="text-[9px] text-white/50 mt-0.5 leading-normal break-words">{alert.desc}</p>
                        </div>
                      </div>
                    );
                  })}
                </div>

                <button className="w-full text-center text-[8.5px] font-black uppercase tracking-widest text-gold/70 hover:text-gold hover:underline pt-2 border-t border-gold/5 block">
                  View All Alerts →
                </button>
              </div>
            </div>

            {/* 4. Scan Activities Card */}
            <div className={GLASS_PANEL_CLASSES + " p-5 flex flex-col justify-between"}>
              <div className="relative z-10 space-y-2">
                <h3 className="text-xs font-black uppercase tracking-[0.2em] text-[#FFD36B] mb-1">Scan Activities</h3>

                <div className="space-y-1.5">
                  {[
                    { title: 'Full Infrastructure Scan', time: 'May 24, 2025 10:30 AM', status: 'Completed' },
                    { title: 'Web Applications Scan', time: 'May 24, 2025 02:15 AM', status: 'Completed' },
                    { title: 'Internal Network Scan', time: 'May 23, 2025 10:30 PM', status: 'Completed' },
                    { title: 'Cloud Assets Scan', time: 'May 23, 2025 05:20 PM', status: 'Completed' },
                    { title: 'Certificates Scan', time: 'May 23, 2025 01:10 PM', status: 'Completed' }
                  ].map((scan, idx) => (
                    <div key={idx} className="flex items-center justify-between p-1.5 rounded border border-gold/5 bg-white/[0.01] hover:bg-white/5 transition-colors">
                      <div className="flex items-center gap-1.5 min-w-0">
                        <Target className="w-3 h-3 text-gold/60 shrink-0" />
                        <div className="min-w-0">
                          <div className="text-[8.5px] font-bold text-white/70 leading-none truncate">{scan.title}</div>
                          <div className="text-[7.5px] font-mono text-white/30 mt-0.5">{scan.time}</div>
                        </div>
                      </div>
                      <span className="px-1 py-0.5 rounded border border-green-500/20 bg-green-500/10 text-green-400 text-[7px] font-black uppercase tracking-wider shrink-0">
                        {scan.status}
                      </span>
                    </div>
                  ))}
                </div>

                <button className="w-full text-center text-[8.5px] font-black uppercase tracking-widest text-gold/70 hover:text-gold hover:underline pt-1">
                  View All Scans →
                </button>
              </div>
            </div>

            {/* Row 3 : Scan Outcomes and PQC Migration Readiness */}

            {/* 5. Scan Outcomes Card */}
            <div className={GLASS_PANEL_CLASSES + " p-5 flex flex-col justify-between"}>
              <div className="relative z-10">
                <h3 className="text-xs font-black uppercase tracking-[0.2em] text-[#FFD36B] mb-4">Scan Outcomes</h3>
                <div className="flex items-center justify-between gap-4">
                  {/* SVG Donut */}
                  <div className="relative w-28 h-28 flex items-center justify-center shrink-0">
                    <svg className="w-full h-full transform rotate-[-90deg]" viewBox="0 0 100 100">
                      <circle cx="50" cy="50" r="40" stroke="rgba(255,255,255,0.03)" strokeWidth="8" fill="none" />

                      {/* Other: 4.4% -> grey (#6b7280) */}
                      <circle
                        cx="50" cy="50" r="40"
                        stroke="#6b7280" strokeWidth="8" fill="none"
                        strokeDasharray="11.1 251.2"
                        strokeDashoffset="-240.3"
                        strokeLinecap="round"
                        className="drop-shadow-[0_0_6px_rgba(107,114,128,0.5)]"
                      />

                      {/* Test: 12.8% -> purple (#a855f7) */}
                      <circle
                        cx="50" cy="50" r="40"
                        stroke="#a855f7" strokeWidth="8" fill="none"
                        strokeDasharray="32.2 251.2"
                        strokeDashoffset="-208.1"
                        strokeLinecap="round"
                        className="drop-shadow-[0_0_6px_rgba(168,85,247,0.5)]"
                      />

                      {/* Development: 22.1% -> orange (#f97316) */}
                      <circle
                        cx="50" cy="50" r="40"
                        stroke="#f97316" strokeWidth="8" fill="none"
                        strokeDasharray="55.5 251.2"
                        strokeDashoffset="-152.6"
                        strokeLinecap="round"
                        className="drop-shadow-[0_0_6px_rgba(249,115,22,0.5)]"
                      />

                      {/* Staging: 16.8% -> teal (#14b8a6) */}
                      <circle
                        cx="50" cy="50" r="40"
                        stroke="#14b8a6" strokeWidth="8" fill="none"
                        strokeDasharray="42.2 251.2"
                        strokeDashoffset="-110.3"
                        strokeLinecap="round"
                        className="drop-shadow-[0_0_6px_rgba(20,184,166,0.5)]"
                      />

                      {/* Production: 43.9% -> blue (#3b82f6) */}
                      <circle
                        cx="50" cy="50" r="40"
                        stroke="#3b82f6" strokeWidth="8" fill="none"
                        strokeDasharray="110.3 251.2"
                        strokeDashoffset="0"
                        strokeLinecap="round"
                        className="drop-shadow-[0_0_6px_rgba(59,130,246,0.5)]"
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                      <span className="text-sm font-black text-white leading-none font-mono">{formatCompactNumber(dashboardMetrics.totalAssetsScanned)}</span>
                      <span className="text-[7px] text-white/30 font-bold uppercase mt-1">Assets</span>
                    </div>
                  </div>

                  {/* Legend */}
                  <div className="space-y-1 flex-1 text-[8px] font-bold">
                    {assetOutcomeRows.map((row) => (
                      <div key={row.label} className="flex items-center justify-between text-white/70">
                        <span className="flex items-center gap-1">
                          <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: row.color }} /> {row.label}
                        </span>
                        <span className="font-mono text-white/50">{formatCompactNumber(row.value)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* 6. PQC Migration Readiness Card */}
            <div className={GLASS_PANEL_CLASSES + " p-5 flex flex-col justify-between shrink-0"}>
              <div className="relative z-10 space-y-3">
                <h3 className="text-xs font-black uppercase tracking-[0.2em] text-[#FFD36B]">PQC Migration Readiness</h3>

                <div className="flex items-center gap-4">
                  {/* Progress Circle */}
                  <div className="relative w-16 h-16 flex items-center justify-center shrink-0">
                    <svg className="w-full h-full rotate-[-90deg]">
                      <circle cx="32" cy="32" r="26" stroke="rgba(255,255,255,0.03)" strokeWidth="5" fill="none" />
                      <circle
                        cx="32" cy="32" r="26"
                        stroke="#FFD36B" strokeWidth="5" fill="none"
                        strokeDasharray={`${2 * Math.PI * 26}`}
                        strokeDashoffset={`${2 * Math.PI * 26 * (1 - Math.max(0, Math.min(100, dashboardMetrics.pqcReadiness)) / 100)}`}
                        strokeLinecap="round"
                        className="drop-shadow-[0_0_6px_rgba(255,211,107,0.5)]"
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className="text-xs font-black text-white font-mono">{dashboardMetrics.pqcReadiness}%</span>
                    </div>
                  </div>

                  <div className="flex-1 space-y-0.5">
                    <div className="text-sm font-black text-white">Ready</div>
                    <div className={`text-[9px] font-black uppercase tracking-wider flex items-center gap-0.5 ${trendClass(dashboardMetrics.pqcReadiness, previousMetrics.pqcReadiness, true)}`}>
                      {formatTrend(dashboardMetrics.pqcReadiness, previousMetrics.pqcReadiness)}
                    </div>
                  </div>
                </div>

                <button className="w-full text-center text-[8.5px] font-black uppercase tracking-widest text-gold/70 hover:text-gold hover:underline pt-2 border-t border-gold/5 block">
                  View Migration Dashboard →
                </button>
              </div>
            </div>

            {/* Row 4 : Risk Trend (Last 30 days) and Risk Distribution */}

            {/* 7. Risk Trend Card */}
            <div className={GLASS_PANEL_CLASSES + " p-5 flex flex-col justify-between"}>
              <div className="relative z-10 space-y-3">
                <h3 className="text-xs font-black uppercase tracking-[0.2em] text-[#FFD36B]">Risk Trend (Last 30 Days)</h3>
                <div className="relative h-24 w-full">
                  <svg className="w-full h-full" viewBox="0 0 300 100" preserveAspectRatio="none">
                    {/* Y Axis Grid Lines */}
                    <line x1="0" y1="20" x2="300" y2="20" stroke="rgba(255,255,255,0.03)" strokeWidth="1" strokeDasharray="3 3" />
                    <line x1="0" y1="50" x2="300" y2="50" stroke="rgba(255,255,255,0.03)" strokeWidth="1" strokeDasharray="3 3" />
                    <line x1="0" y1="80" x2="300" y2="80" stroke="rgba(255,255,255,0.03)" strokeWidth="1" strokeDasharray="3 3" />

                    {/* Gradient fill under the line */}
                    <defs>
                      <linearGradient id="riskTrendGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#FFD36B" stopOpacity="0.15" />
                        <stop offset="100%" stopColor="#FFD36B" stopOpacity="0" />
                      </linearGradient>
                    </defs>

                    {/* Fill path */}
                    <path
                      d="M 15,75 Q 50,60 85,72 T 155,50 T 225,25 T 285,15 L 285,100 L 15,100 Z"
                      fill="url(#riskTrendGrad)"
                    />

                    {/* Golden Line Path */}
                    <path
                      d="M 15,75 Q 50,60 85,72 T 155,50 T 225,25 T 285,15"
                      fill="none"
                      stroke="#FFD36B"
                      strokeWidth="2"
                      className="drop-shadow-[0_0_6px_rgba(255,211,107,0.6)]"
                    />

                    {/* Interactive glowing points */}
                    {[
                      { x: 15, y: 75, val: 34 },
                      { x: 50, y: 60, val: 45 },
                      { x: 85, y: 72, val: 38 },
                      { x: 120, y: 58, val: 48 },
                      { x: 155, y: 50, val: 55 },
                      { x: 190, y: 35, val: 68 },
                      { x: 225, y: 25, val: 78 },
                      { x: 255, y: 32, val: 72 },
                      { x: 285, y: 15, val: 89 }
                    ].map((pt, idx) => (
                      <g key={idx} className="group/pt cursor-pointer">
                        <circle
                          cx={pt.x}
                          cy={pt.y}
                          r="3.5"
                          fill="#FFD36B"
                          stroke="#0f1428"
                          strokeWidth="1.2"
                          className="transition-all duration-300 group-hover/pt:r-5"
                        />
                        <circle
                          cx={pt.x}
                          cy={pt.y}
                          r="7"
                          fill="#FFD36B"
                          opacity="0.2"
                          className="animate-ping"
                          style={{ animationDuration: '3s', animationDelay: `${idx * 0.3}s` }}
                        />
                      </g>
                    ))}
                  </svg>
                </div>
                {/* X Axis Labels */}
                <div className="flex justify-between text-[7px] font-mono text-white/30 uppercase px-1">
                  <span>Apr 25</span>
                  <span>May 2</span>
                  <span>May 9</span>
                  <span>May 16</span>
                  <span>May 23</span>
                </div>
              </div>
            </div>

            {/* 8. Risk Distribution Card */}
            <div className={GLASS_PANEL_CLASSES + " p-5 flex flex-col justify-between"}>
              <div className="relative z-10">
                <h3 className="text-xs font-black uppercase tracking-[0.2em] text-[#FFD36B] mb-4">Risk Distribution</h3>
                <div className="flex items-center justify-between gap-4">
                  {/* SVG Donut */}
                  <div className="relative w-28 h-28 flex items-center justify-center shrink-0">
                    <svg className="w-full h-full transform rotate-[-90deg]" viewBox="0 0 100 100">
                      <circle cx="50" cy="50" r="40" stroke="rgba(255,255,255,0.03)" strokeWidth="8" fill="none" />

                      {/* Secure: 13.9% -> color: cyan/teal (#06b6d4) */}
                      <circle
                        cx="50" cy="50" r="40"
                        stroke="#06b6d4" strokeWidth="8" fill="none"
                        strokeDasharray="34.9 251.2"
                        strokeDashoffset="0"
                        strokeLinecap="round"
                        className="drop-shadow-[0_0_6px_rgba(6,182,212,0.5)]"
                      />

                      {/* Low: 36.4% -> color: green (#22c55e) */}
                      <circle
                        cx="50" cy="50" r="40"
                        stroke="#22c55e" strokeWidth="8" fill="none"
                        strokeDasharray="91.4 251.2"
                        strokeDashoffset="-34.9"
                        strokeLinecap="round"
                        className="drop-shadow-[0_0_6px_rgba(34,197,94,0.5)]"
                      />

                      {/* Medium: 32.9% -> color: yellow (#eab308) */}
                      <circle
                        cx="50" cy="50" r="40"
                        stroke="#eab308" strokeWidth="8" fill="none"
                        strokeDasharray="82.6 251.2"
                        strokeDashoffset="-126.3"
                        strokeLinecap="round"
                        className="drop-shadow-[0_0_6px_rgba(234,179,8,0.5)]"
                      />

                      {/* High: 14.3% -> color: orange (#f97316) */}
                      <circle
                        cx="50" cy="50" r="40"
                        stroke="#f97316" strokeWidth="8" fill="none"
                        strokeDasharray="35.9 251.2"
                        strokeDashoffset="-208.9"
                        strokeLinecap="round"
                        className="drop-shadow-[0_0_6px_rgba(249,115,22,0.5)]"
                      />

                      {/* Critical: 2.5% -> color: red (#ef4444) */}
                      <circle
                        cx="50" cy="50" r="40"
                        stroke="#ef4444" strokeWidth="8" fill="none"
                        strokeDasharray="6.3 251.2"
                        strokeDashoffset="-244.8"
                        strokeLinecap="round"
                        className="drop-shadow-[0_0_6px_rgba(239,68,68,0.5)]"
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                      <span className="text-sm font-black text-white leading-none font-mono">{formatCompactNumber(dashboardMetrics.totalFindings)}</span>
                      <span className="text-[7px] text-white/30 font-bold uppercase mt-1">Findings</span>
                    </div>
                  </div>

                  {/* Legend */}
                  <div className="space-y-1 flex-1 text-[8px] font-bold">
                    {riskDistributionRows.map((row) => (
                      <div key={row.label} className="flex items-center justify-between text-white/70">
                        <span className="flex items-center gap-1">
                          <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: row.color }} /> {row.label}
                        </span>
                        <span className="font-mono text-white/50">
                          {formatCompactNumber(row.count)} ({((row.count / dashboardSeverityTotal) * 100).toFixed(1)}%)
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>

          </div>

          <div className={GLASS_PANEL_CLASSES + " p-5"}>
            <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60 mb-3">Defensive Scanner Scope</h2>
            <div className="grid md:grid-cols-3 gap-3 text-xs text-white/45">
              <div className="rounded-lg border border-gold/10 bg-white/[0.02] p-3">Public TLS certificate, protocol, cipher, API header, web crypto, GitHub code-pattern, and SSH public metadata checks.</div>
              <div className="rounded-lg border border-gold/10 bg-white/[0.02] p-3">No exploitation, credential collection, stealth behavior, persistence, or unauthorized reconnaissance.</div>
              <div className="rounded-lg border border-gold/10 bg-white/[0.02] p-3">Results persist per authenticated user and populate CBOM, assets, exposure map, history, and audit records.</div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'findings' && (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-3 items-center">
            <div className="relative flex-1 min-w-[200px] max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-white/25" />
              <input
                type="text"
                placeholder="Search algorithms, evidence, locations..."
                value={searchQ}
                onChange={(e) => setSearchQ(e.target.value)}
                className="w-full border rounded-lg py-2.5 pl-10 pr-4 text-sm focus:outline-none focus:transition-colors text-white placeholder-white/20 glass-panel"
              />
            </div>
            {['critical', 'high', 'medium', 'low', 'safe'].map((severity) => (
              <button key={severity} onClick={() => setSevFilter(sevFilter === severity ? null : severity)} className={`text-[10px] font-black uppercase tracking-wider px-3 py-2 rounded-lg border transition-all ${sevFilter === severity ? `${sevColor(severity).br} ${sevColor(severity).b} ${sevColor(severity).t}` : 'text-white/35 hover:'} glass-panel`}>
                {severity} ({dashboardFindings.filter((finding) => finding.threatLevel.toLowerCase() === severity).length})
              </button>
            ))}
            {showMitigationNextStep && (
              <a
                href={`/dashboard/migration-planner?source=scanner&scanId=${encodeURIComponent(jobId || 'latest')}`}
                className="inline-flex items-center gap-2 rounded-lg border border-gold/40 bg-gold/10 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-gold transition-all hover:border-gold/70 hover:bg-gold/20"
                aria-label="Go to the migration planner to mitigate scanner findings"
              >
                Next Step
                <ChevronRight className="h-3.5 w-3.5" />
              </a>
            )}
          </div>

          <div className="space-y-2 max-h-[650px] overflow-y-auto pr-1">
            {filteredFindings.length === 0 ? (
              <div className="text-center py-16 text-white/20 text-xs uppercase tracking-widest font-bold">
                {dashboardFindings.length === 0 ? 'Run an authorized scan to discover cryptographic findings' : 'No findings match filters'}
              </div>
            ) : filteredFindings.map((finding, index) => {
              const severity = finding.threatLevel.toLowerCase();
              const sc = sevColor(severity);
              const isExpanded = expandedFinding === finding.id;
              const Icon = targetIcon(finding.category);
              return (
                <motion.div key={finding.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: Math.min(index * 0.02, 0.5) }} className={`rounded-xl border overflow-hidden ${sc.br} ${sc.b}`}>
                  <button onClick={() => setExpandedFinding(isExpanded ? null : finding.id)} className="w-full text-left p-4 flex items-center gap-3 group">
                    <span className={`h-2.5 w-2.5 rounded-full shrink-0 ${sc.d}`} />
                    <Icon className="h-4 w-4 text-gold/40 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-0.5">
                        <span className="text-xs font-bold text-white/80">{finding.algorithm}</span>
                        <span className={`text-[9px] font-black uppercase tracking-wider px-1.5 py-0.5 rounded border ${sc.br} ${sc.b} ${sc.t}`}>{finding.threatLevel}</span>
                        <span className="text-[9px] font-bold text-gold/50">{finding.status}</span>
                      </div>
                      <div className="text-[10px] text-white/35 font-mono truncate">{finding.location}</div>
                    </div>
                    <div className="text-right shrink-0 hidden lg:block">
                      <div className="text-[10px] font-bold text-gold/60">{finding.pqcReplacement || 'Review'}</div>
                      <div className="text-[9px] text-white/20">{finding.detectionMethod}</div>
                    </div>
                    <ChevronRight className={`h-4 w-4 text-white/15 shrink-0 transition-transform ${isExpanded ? 'rotate-90 text-gold' : ''}`} />
                  </button>
                  <AnimatePresence>
                    {isExpanded && (
                      <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="border-t px-4 py-4 glass-panel">
                        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-3 mb-3">
                          <div className="p-2.5 rounded-lg border border-gold/10 bg-white/[0.015]">
                            <div className="text-[8px] font-black uppercase tracking-wider text-white/25 mb-0.5">Category</div>
                            <div className="text-xs font-mono text-white/70">{finding.category}</div>
                          </div>
                          <div className="p-2.5 rounded-lg border border-gold/10 bg-white/[0.015]">
                            <div className="text-[8px] font-black uppercase tracking-wider text-white/25 mb-0.5">Key Size</div>
                            <div className="text-xs font-mono text-white/70">{finding.keySize ? `${finding.keySize} bit` : 'Unknown'}</div>
                          </div>
                          <div className="p-2.5 rounded-lg border border-gold/10 bg-white/[0.015]">
                            <div className="text-[8px] font-black uppercase tracking-wider text-white/25 mb-0.5">Source</div>
                            <div className="text-xs font-mono text-cyan-400">{finding.source}</div>
                          </div>
                          <div className="p-2.5 rounded-lg border border-gold/10 bg-white/[0.015]">
                            <div className="text-[8px] font-black uppercase tracking-wider text-white/25 mb-0.5">Replacement</div>
                            <div className="text-xs font-mono text-green-400">{finding.pqcReplacement || 'Manual review'}</div>
                          </div>
                        </div>
                        <p className="text-xs text-white/45 leading-relaxed mb-2">{finding.description}</p>
                        <div className="p-2.5 rounded-lg border border-gold/15 bg-gold/[0.03] mb-2">
                          <div className="text-[8px] font-black uppercase tracking-wider text-gold/70 mb-0.5">Evidence</div>
                          <div className="text-xs text-white/60">{finding.evidence}</div>
                        </div>
                        <div className="p-2.5 rounded-lg border border-green-500/15 bg-green-500/[0.03]">
                          <div className="text-[8px] font-black uppercase tracking-wider text-green-400/60 mb-0.5">Remediation</div>
                          <div className="text-xs text-green-400/80">{finding.recommendation}</div>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </motion.div>
              );
            })}
          </div>
        </div>
      )}

      {activeTab === 'logs' && (
        <div className={GLASS_PANEL_CLASSES + " overflow-hidden flex flex-col h-[600px]"}>
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-gold/10 bg-gold/[0.03] shrink-0">
            <Terminal className="h-3.5 w-3.5 text-gold/50" />
            <span className="text-[10px] font-black uppercase tracking-[0.15em] text-white/50">Scanner Telemetry</span>
            <span className="ml-auto text-[10px] text-white/20 font-mono">{logs.length} lines</span>
          </div>
          <div className="p-4 overflow-y-auto flex-1 font-mono text-[11px] space-y-1">
            {logs.length === 0 ? (
              <div className="text-white/15 text-center py-12 uppercase tracking-widest text-[10px] font-bold">Awaiting authorized scan initiation...</div>
            ) : logs.map((entry, index) => (
              <div key={`${entry.timestamp}-${index}`} className={`leading-relaxed break-words ${logColor(entry.level)}`}>
                <span className="text-white/15 inline-block w-20">{entry.timestamp.split('T')[1]?.slice(0, 12) || entry.timestamp}</span>
                <span className={`font-bold inline-block w-20 ${logColor(entry.level)}`}>[{entry.level}]</span>
                {entry.phase && <span className="text-white/30 mr-2">[{entry.phase}]</span>}
                {entry.message}
              </div>
            ))}
            {isRunning && <div className="text-gold/50 animate-pulse mt-2">|</div>}
            <div ref={logEndRef} />
          </div>
        </div>
      )}

      {activeTab === 'history' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60">Audit-Ready Scan History</h2>
            <button onClick={fetchHistory} className="text-[10px] font-black uppercase tracking-wider text-gold flex items-center gap-2">
              <RefreshCw className={`h-3.5 w-3.5 ${historyLoading ? 'animate-spin' : ''}`} /> Refresh
            </button>
          </div>
          <div className="grid xl:grid-cols-[minmax(360px,0.95fr)_minmax(520px,1.35fr)] gap-4 items-start">
          <div className="space-y-3">
            {displayedHistory.length === 0 ? (
              <div className="text-center py-16 text-white/20 text-xs uppercase tracking-widest font-bold border border-dashed border-white/10 rounded-xl">
                {historyEmptyText}
              </div>
            ) : displayedHistory.map((entry) => (
              <div
                key={entry.scanId}
                onClick={() => setSelectedHistoryId(entry.scanId)}
                className={`${GLASS_PANEL_CLASSES} p-4 cursor-pointer ${selectedHistoryEntry?.scanId === entry.scanId ? 'border-gold/70 bg-gold/[0.04]' : ''}`}
              >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-3">
                  <div className="flex items-center gap-3">
                    <History className="h-5 w-5 text-gold/60" />
                    <div>
                      <div className="text-sm font-bold text-white/80">{entry.scanId}</div>
                      <div className="text-[10px] text-white/30 font-mono">{new Date(entry.startedAt).toLocaleString()} - {formatMs(entry.durationMs)}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 flex-wrap">
                    <div className="px-3 py-1.5 rounded border border-white/5 text-center glass-panel">
                      <div className="text-sm font-black text-white">{entry.detectedComponents}</div>
                      <div className="text-[8px] uppercase tracking-wider text-white/30 font-bold">Components</div>
                    </div>
                    <div className="px-3 py-1.5 rounded border border-red-500/10 text-center glass-panel">
                      <div className="text-sm font-black text-red-400">{entry.vulnerableFindings}</div>
                      <div className="text-[8px] uppercase tracking-wider text-white/30 font-bold">Vulnerable</div>
                    </div>
                    <div className="px-3 py-1.5 rounded border border-green-500/10 text-center glass-panel">
                      <div className="text-sm font-black text-green-400">{entry.pqcReadyFindings}</div>
                      <div className="text-[8px] uppercase tracking-wider text-white/30 font-bold">PQC Ready</div>
                    </div>
                    <div className="px-3 py-1.5 rounded border text-center glass-panel">
                      <div className="text-sm font-black text-gold">{entry.qScore ?? 'N/A'}</div>
                      <div className="text-[8px] uppercase tracking-wider text-white/30 font-bold">Q-Score</div>
                    </div>
                  </div>
                </div>
                <div className="flex flex-wrap gap-2 mb-3">
                  <button
                    onClick={(event) => {
                      event.stopPropagation();
                      setSelectedHistoryId(entry.scanId);
                    }}
                    className="px-3 py-1.5 rounded border border-gold/25 text-[9px] font-black uppercase tracking-wider text-gold hover:bg-gold/10 transition-colors flex items-center gap-1.5"
                  >
                    <Eye className="h-3 w-3" /> Review Findings
                  </button>
                  <button
                    onClick={(event) => {
                      event.stopPropagation();
                      handleOpenHistoryInFindings(entry);
                    }}
                    disabled={!entry.findings?.length}
                    className="px-3 py-1.5 rounded border border-white/10 text-[9px] font-black uppercase tracking-wider text-white/50 hover:text-white hover:bg-white/5 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                  >
                    Open In Findings
                  </button>
                  <button
                    onClick={(event) => {
                      event.stopPropagation();
                      handleDownloadHistoryAudit(entry);
                    }}
                    className="px-3 py-1.5 rounded border border-white/10 text-[9px] font-black uppercase tracking-wider text-white/50 hover:text-white hover:bg-white/5 transition-colors flex items-center gap-1.5"
                  >
                    <Download className="h-3 w-3" /> Audit JSON
                  </button>
                </div>
                <div className="text-[10px] text-white/40 border-t border-gold/5 pt-3 grid md:grid-cols-2 gap-2">
                  <span><span className="font-bold text-white/60 mr-2">Target:</span>{entry.target}</span>
                  <span><span className="font-bold text-white/60 mr-2">Status:</span>{entry.status}</span>
                  <span><span className="font-bold text-white/60 mr-2">CBOM Records:</span>{entry.linkedCbomRecords?.length || 0}</span>
                  <span><span className="font-bold text-white/60 mr-2">Exposure Nodes:</span>{entry.linkedExposureNodes?.length || 0}</span>
                  <span><span className="font-bold text-white/60 mr-2">Modules:</span>{entry.scannerModulesUsed?.length || entry.moduleStates?.filter((module) => module.status !== 'Skipped').length || 0}</span>
                  <span><span className="font-bold text-white/60 mr-2">Errors:</span>{entry.errorLogs?.length || 0}</span>
                  <span><span className="font-bold text-white/60 mr-2">Persisted Findings:</span>{entry.findings?.length || 0}</span>
                </div>
              </div>
            ))}
          </div>

          <div className={GLASS_PANEL_CLASSES + " p-4"}>
            {!selectedHistoryEntry ? (
              <div className="text-center py-16 text-white/20 text-xs uppercase tracking-widest font-bold">
                Select a scan to review persisted findings
              </div>
            ) : (
              <div className="space-y-4">
                <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                  <div>
                    <div className="text-[10px] font-black uppercase tracking-[0.18em] text-gold mb-2">Persisted Audit Details</div>
                    <h3 className="text-base font-black text-white/85 break-all">{selectedHistoryEntry.scanId}</h3>
                    <div className="text-[10px] text-white/35 font-mono mt-1">{selectedHistoryEntry.target}</div>
                    <div className="text-[10px] text-white/30 font-mono mt-1">
                      {new Date(selectedHistoryEntry.startedAt).toLocaleString()} - {formatMs(selectedHistoryEntry.durationMs)}
                    </div>
                  </div>
                  <div className="grid grid-cols-3 sm:grid-cols-5 gap-2 shrink-0">
                    {[
                      ['Critical', selectedHistorySeverityCounts.critical, 'text-red-400'],
                      ['High', selectedHistorySeverityCounts.high, 'text-orange-400'],
                      ['Medium', selectedHistorySeverityCounts.medium, 'text-yellow-400'],
                      ['Low', selectedHistorySeverityCounts.low, 'text-green-400'],
                      ['Safe', selectedHistorySeverityCounts.safe, 'text-green-400'],
                    ].map(([label, count, color]) => (
                      <div key={String(label)} className="px-3 py-2 rounded border border-white/5 text-center glass-panel">
                        <div className={`text-sm font-black ${color}`}>{count}</div>
                        <div className="text-[8px] uppercase tracking-wider text-white/30 font-bold">{label}</div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex flex-wrap gap-3 items-center">
                  <div className="relative flex-1 min-w-[220px]">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-white/25" />
                    <input
                      type="text"
                      placeholder="Search persisted findings..."
                      value={historyFindingSearch}
                      onChange={(event) => setHistoryFindingSearch(event.target.value)}
                      className="w-full border rounded-lg py-2.5 pl-10 pr-4 text-sm focus:outline-none focus:transition-colors text-white placeholder-white/20 glass-panel"
                    />
                  </div>
                  {['critical', 'high', 'medium', 'low', 'safe'].map((severity) => (
                    <button
                      key={severity}
                      onClick={() => setHistorySeverityFilter(historySeverityFilter === severity ? null : severity)}
                      className={`text-[10px] font-black uppercase tracking-wider px-3 py-2 rounded-lg border transition-all ${historySeverityFilter === severity ? `${sevColor(severity).br} ${sevColor(severity).b} ${sevColor(severity).t}` : 'text-white/35'} glass-panel`}
                    >
                      {severity}
                    </button>
                  ))}
                </div>

                <div className="space-y-2 max-h-[620px] overflow-y-auto pr-1">
                  {filteredHistoryFindings.length === 0 ? (
                    <div className="text-center py-16 text-white/20 text-xs uppercase tracking-widest font-bold border border-dashed border-white/10 rounded-xl">
                      {selectedHistoryFindings.length === 0 ? 'No persisted findings were recorded for this scan' : 'No persisted findings match filters'}
                    </div>
                  ) : filteredHistoryFindings.map((finding, index) => {
                    const severity = finding.threatLevel.toLowerCase();
                    const sc = sevColor(severity);
                    const isExpanded = expandedHistoryFinding === finding.id;
                    const Icon = targetIcon(finding.category);
                    return (
                      <motion.div key={finding.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: Math.min(index * 0.015, 0.35) }} className={`rounded-xl border overflow-hidden ${sc.br} ${sc.b}`}>
                        <button onClick={() => setExpandedHistoryFinding(isExpanded ? null : finding.id)} className="w-full text-left p-4 flex items-center gap-3 group">
                          <span className={`h-2.5 w-2.5 rounded-full shrink-0 ${sc.d}`} />
                          <Icon className="h-4 w-4 text-gold/40 shrink-0" />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap mb-0.5">
                              <span className="text-xs font-bold text-white/80">{finding.algorithm}</span>
                              <span className={`text-[9px] font-black uppercase tracking-wider px-1.5 py-0.5 rounded border ${sc.br} ${sc.b} ${sc.t}`}>{finding.threatLevel}</span>
                              <span className="text-[9px] font-bold text-gold/50">{finding.status}</span>
                            </div>
                            <div className="text-[10px] text-white/35 font-mono truncate">{finding.location}</div>
                          </div>
                          <div className="text-right shrink-0 hidden lg:block">
                            <div className="text-[10px] font-bold text-gold/60">{finding.pqcReplacement || 'Review'}</div>
                            <div className="text-[9px] text-white/20">{finding.detectionMethod}</div>
                          </div>
                          <ChevronRight className={`h-4 w-4 text-white/15 shrink-0 transition-transform ${isExpanded ? 'rotate-90 text-gold' : ''}`} />
                        </button>
                        <AnimatePresence>
                          {isExpanded && (
                            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="border-t px-4 py-4 glass-panel">
                              <div className="grid md:grid-cols-2 xl:grid-cols-4 gap-3 mb-3">
                                <div className="p-2.5 rounded-lg border border-gold/10 bg-white/[0.015]">
                                  <div className="text-[8px] font-black uppercase tracking-wider text-white/25 mb-0.5">Category</div>
                                  <div className="text-xs font-mono text-white/70">{finding.category}</div>
                                </div>
                                <div className="p-2.5 rounded-lg border border-gold/10 bg-white/[0.015]">
                                  <div className="text-[8px] font-black uppercase tracking-wider text-white/25 mb-0.5">Key Size</div>
                                  <div className="text-xs font-mono text-white/70">{finding.keySize ? `${finding.keySize} bit` : 'Unknown'}</div>
                                </div>
                                <div className="p-2.5 rounded-lg border border-gold/10 bg-white/[0.015]">
                                  <div className="text-[8px] font-black uppercase tracking-wider text-white/25 mb-0.5">Source</div>
                                  <div className="text-xs font-mono text-cyan-400">{finding.source}</div>
                                </div>
                                <div className="p-2.5 rounded-lg border border-gold/10 bg-white/[0.015]">
                                  <div className="text-[8px] font-black uppercase tracking-wider text-white/25 mb-0.5">Replacement</div>
                                  <div className="text-xs font-mono text-green-400">{finding.pqcReplacement || 'Manual review'}</div>
                                </div>
                              </div>
                              <p className="text-xs text-white/45 leading-relaxed mb-2">{finding.description}</p>
                              <div className="p-2.5 rounded-lg border border-gold/15 bg-gold/[0.03] mb-2">
                                <div className="text-[8px] font-black uppercase tracking-wider text-gold/70 mb-0.5">Evidence</div>
                                <div className="text-xs text-white/60 break-words">{finding.evidence}</div>
                              </div>
                              <div className="p-2.5 rounded-lg border border-green-500/15 bg-green-500/[0.03]">
                                <div className="text-[8px] font-black uppercase tracking-wider text-green-400/60 mb-0.5">Remediation</div>
                                <div className="text-xs text-green-400/80">{finding.recommendation}</div>
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </motion.div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
          </div>
        </div>
      )}

      <AnimatePresence>
        {scheduleOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-40 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
            onClick={() => setScheduleOpen(false)}
          >
            <motion.div
              initial={{ opacity: 0, y: 20, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 12, scale: 0.98 }}
              onClick={(event) => event.stopPropagation()}
              className={`${GLASS_PANEL_CLASSES} w-full max-w-lg p-5`}
            >
              <div className="flex items-start justify-between gap-4 mb-5">
                <div>
                  <div className="text-[10px] font-black uppercase tracking-[0.18em] text-gold mb-2">Schedule Scan</div>
                  <h3 className="text-lg font-black text-white/90">Select Scan Date</h3>
                </div>
                <button
                  onClick={() => setScheduleOpen(false)}
                  className="rounded-lg border border-white/10 p-2 text-white/45 hover:text-white hover:border-gold/30 transition-colors"
                  aria-label="Close schedule dialog"
                >
                  <XCircle className="h-4 w-4" />
                </button>
              </div>

              <div className="grid sm:grid-cols-2 gap-3 mb-4">
                <label className="block">
                  <span className="text-[9px] font-black uppercase tracking-wider text-white/35">Date</span>
                  <input
                    type="date"
                    value={scheduleDate}
                    min={dateInputFor(0)}
                    onChange={(event) => setScheduleDate(event.target.value)}
                    className="mt-1 w-full rounded-lg border border-gold/15 bg-white/[0.03] px-3 py-2 text-sm text-white focus:outline-none focus:border-gold/50"
                  />
                </label>
                <label className="block">
                  <span className="text-[9px] font-black uppercase tracking-wider text-white/35">Time</span>
                  <input
                    type="time"
                    value={scheduleTime}
                    onChange={(event) => setScheduleTime(event.target.value)}
                    className="mt-1 w-full rounded-lg border border-gold/15 bg-white/[0.03] px-3 py-2 text-sm text-white focus:outline-none focus:border-gold/50"
                  />
                </label>
              </div>

              <div className="rounded-lg border border-gold/10 bg-white/[0.02] p-3 mb-4">
                <div className="text-[9px] font-black uppercase tracking-wider text-white/30 mb-1">Targets</div>
                <div className="text-xs text-white/60 font-mono break-words">
                  {targets.length > 0
                    ? targets.map((target) => target.normalized || target.raw).join(', ')
                    : history[0]?.target || 'No authorized target queued'}
                </div>
              </div>

              {scheduledScans.length > 0 && (
                <div className="rounded-lg border border-white/10 bg-white/[0.02] p-3 mb-4">
                  <div className="text-[9px] font-black uppercase tracking-wider text-white/30 mb-2">Upcoming</div>
                  <div className="space-y-2 max-h-28 overflow-y-auto">
                    {scheduledScans
                      .filter((scan) => Date.parse(scan.scheduledFor) > Date.now())
                      .slice(0, 3)
                      .map((scan) => (
                        <div key={scan.id} className="flex items-center justify-between gap-3 text-xs">
                          <span className="text-white/65">{new Date(scan.scheduledFor).toLocaleString()}</span>
                          <span className="text-white/30 font-mono">{scan.targets.length} target(s)</span>
                        </div>
                      ))}
                  </div>
                </div>
              )}

              <div className="flex justify-end gap-2">
                <button
                  onClick={() => setScheduleOpen(false)}
                  className="px-4 py-2 rounded-lg border border-white/10 text-[10px] font-black uppercase tracking-wider text-white/45 hover:text-white hover:bg-white/5 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSaveSchedule}
                  className="px-4 py-2 rounded-lg border border-gold/30 bg-gold/10 text-[10px] font-black uppercase tracking-wider text-gold hover:bg-gold/20 transition-colors"
                >
                  Save Schedule
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {toast && (
          <motion.div
            initial={{ opacity: 0, y: 50, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 20, scale: 0.95 }}
            className="fixed bottom-6 right-6 z-50 px-6 py-3 rounded-lg border border-[#FFD36B]/30 bg-[#0f1428]/90 backdrop-blur-xl shadow-[0_0_30px_rgba(255,211,107,0.3)] text-white font-medium flex items-center gap-3 text-sm"
          >
            <Sparkles className="w-5 h-5 text-gold animate-pulse" />
            <span>{toast}</span>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
