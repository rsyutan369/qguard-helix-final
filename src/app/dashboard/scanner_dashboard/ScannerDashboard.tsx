import { useCallback, useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useSearchParams } from 'react-router-dom';
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
import { mandatoryPqcStackMetadata } from '@/lib/crypto/mandatory-pqc-stack';

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
};

type OperatorPatchFormState = {
  assetClass: string;
  optionId: string;
  connectorId: string;
  target: string;
  migrationJobId: string;
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

const DEFAULT_AGENT_SCAN_TYPES = AGENT_SCAN_TYPE_OPTIONS.map((item) => item.id);
const REMEDIATION_WORKFLOW_STAGES = ['DISCOVER', 'ANALYZE', 'APPROVE', 'PATCH', 'VALIDATE', 'MONITOR', 'REPORT'];
const MANDATORY_QUANTUM_STACK = mandatoryPqcStackMetadata();
const MANDATORY_QUANTUM_STACK_GROUPS = [
  { title: 'Libraries', items: MANDATORY_QUANTUM_STACK.requiredLibraries },
  { title: 'Key Exchange', items: [MANDATORY_QUANTUM_STACK.keyExchange.primary, MANDATORY_QUANTUM_STACK.keyExchange.hybrid] },
  { title: 'Signatures', items: [MANDATORY_QUANTUM_STACK.signatures.primary, MANDATORY_QUANTUM_STACK.signatures.hybrid] },
  { title: 'Data Protection', items: [MANDATORY_QUANTUM_STACK.encryption.symmetric, MANDATORY_QUANTUM_STACK.kdf.primary, ...MANDATORY_QUANTUM_STACK.hashes] },
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
  const [historyTimeframe, setHistoryTimeframe] = useState<HistoryTimeframe>('last7');
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
  });
  const [operatorPatchForm, setOperatorPatchForm] = useState<OperatorPatchFormState>({
    assetClass: 'kubernetes',
    optionId: 'k8s-ingress-tls-profile',
    connectorId: '',
    target: 'https://api.customer.com',
    migrationJobId: '',
  });
  const [operatorEvidenceJson, setOperatorEvidenceJson] = useState('[\n  {\n    "evidenceType": "tls-protocol",\n    "assetName": "api.customer.com",\n    "target": "https://api.customer.com",\n    "host": "api.customer.com",\n    "port": 443,\n    "protocol": "TLS",\n    "observedAlgorithm": "TLS-1.3",\n    "rawEvidence": { "operatorValidation": true, "hndlRisk": false }\n  }\n]');
  const abortRef = useRef<AbortController | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);

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
    fetchAgents();
  }, [fetchAgents, fetchHistory]);

  useEffect(() => {
    if (!session?.access_token || !['agents', 'settings'].includes(activeTab)) {
      setAgentSyncConnected(false);
      return;
    }

    const source = new EventSource(`/api/v1/agent-scanner/stream?token=${encodeURIComponent(session.access_token)}`);

    source.onopen = () => setAgentSyncConnected(true);
    source.onerror = () => setAgentSyncConnected(false);
    source.addEventListener('agent-scanner-sync', (message) => {
      try {
        const snapshot = JSON.parse((message as MessageEvent).data || '{}');
        const nextAgents = Array.isArray(snapshot.agents) ? snapshot.agents : [];
        setAgents(nextAgents);
        if (Array.isArray(snapshot.evidence)) setAgentEvidence(snapshot.evidence);
        if (Array.isArray(snapshot.alerts)) setAgentAlerts(snapshot.alerts);
        if (Array.isArray(snapshot.connectors)) setConnectors(snapshot.connectors);
        if (Array.isArray(snapshot.operatorActions)) setOperatorActions(snapshot.operatorActions);
        if (Array.isArray(snapshot.patchOptions)) setPatchOptionGroups(snapshot.patchOptions);
        setSelectedAgentId((current) => current || nextAgents[0]?.id || null);
        setAgentSyncLastEventAt(snapshot.generatedAt || new Date().toISOString());
        setOperatorPatchForm((current) => ({
          ...current,
          connectorId: current.connectorId || snapshot.connectors?.[0]?.id || '',
        }));
      } catch {
        setAgentSyncConnected(false);
      }
    });

    return () => {
      source.close();
      setAgentSyncConnected(false);
    };
  }, [activeTab, session?.access_token]);

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

  const handleShowLast7Days = useCallback(async () => {
    setHistoryTimeframe('last7');
    setActiveTab('history');
    await fetchHistory();
    showToast('Showing scans from the last 7 days.');
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
    scanTypes: DEFAULT_AGENT_SCAN_TYPES,
    alertThreshold: 'moderate',
  }), [connectorForm.allowedPaths, connectorForm.allowedTargets]);

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
          },
          policy: connectorPolicyFromForm(),
          metadata: {
            source: 'dashboard-operator-patch-workflow',
            connectorMode: 'operator-approved',
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
          payload: {
            createdFrom: 'Agent Collector Scanners',
            tenant: user?.id,
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

  const handleUpdateOperatorAction = useCallback(async (actionId: string, nextStatus: string) => {
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
          message: `Operator marked patch action as ${nextStatus}.`,
        }),
      });
      const json = await response.json();
      if (!response.ok) throw new Error(json?.error?.message || 'Unable to update operator action');
      await fetchAgents();
      showToast(`Patch action marked ${nextStatus}.`);
    } catch (err) {
      setAgentsError(err instanceof Error ? err.message : 'Operator action update failed');
    } finally {
      setAgentsLoading(false);
    }
  }, [authHeaders, fetchAgents, showToast]);

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
    ? 'No authorized scan history available'
    : historyTimeframe === 'last7'
      ? 'No scans recorded in the last 7 days'
      : 'No authorized scan history available';

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
    setAgentForm((current) => ({
      ...current,
      name: selectedAgent.name || current.name,
      environment: selectedAgent.metadata?.environment || current.environment || 'production',
      enabled: policy.enabled,
      allowedTargets: policy.allowedTargets.join('\n'),
      allowedPaths: policy.allowedPaths.join('\n'),
      intervalSeconds: String(policy.intervalSeconds),
      scanTypes: policy.scanTypes,
      alertThreshold: policy.alertThreshold,
    }));
    showToast('Selected agent policy loaded into settings.');
  }, [selectedAgent, showToast]);

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

  const commandAgentId = selectedAgent?.id || oneTimeAgentToken?.agentId || 'agent_id_here';
  const dockerCommand = `docker run -d \\
  --name qguard-collector \\
  -e QGUARD_TENANT_ID="${tenantId}" \\
  -e QGUARD_AGENT_ID="${commandAgentId}" \\
  -e QGUARD_AGENT_TOKEN="agent_token_here" \\
  -e QGUARD_API_URL="${apiUrlPlaceholder}" \\
  -e QGUARD_ENABLE_REMEDIATION="true" \\
  -e QGUARD_ENABLE_CONFIG_PATCHES="true" \\
  -e QGUARD_NATIVE_RUNTIME_ENABLED="true" \\
  -e QGUARD_NATIVE_CAPTURE_SECONDS="8" \\
  -e QGUARD_SCAN_SYSTEM_CERTS="true" \\
  qguard/collector-agent:latest`;
  const composeCommand = `services:
  qguard-collector:
    image: qguard/collector-agent:latest
    restart: unless-stopped
    environment:
      QGUARD_TENANT_ID: "${tenantId}"
      QGUARD_AGENT_ID: "${commandAgentId}"
      QGUARD_AGENT_TOKEN: "agent_token_here"
      QGUARD_API_URL: "${apiUrlPlaceholder}"
      QGUARD_ENABLE_REMEDIATION: "true"
      QGUARD_ENABLE_CONFIG_PATCHES: "true"
      QGUARD_NATIVE_RUNTIME_ENABLED: "true"
      QGUARD_NATIVE_CAPTURE_SECONDS: "8"
      QGUARD_SCAN_SYSTEM_CERTS: "true"`;
  const systemdCommand = `[Unit]
Description=QGuard Local Scanner Agent
After=network-online.target

[Service]
WorkingDirectory=/opt/qguard
Environment=QGUARD_TENANT_ID=${tenantId}
Environment=QGUARD_AGENT_ID=${commandAgentId}
Environment=QGUARD_AGENT_TOKEN=agent_token_here
Environment=QGUARD_API_URL=${apiUrlPlaceholder}
Environment=QGUARD_ENABLE_REMEDIATION=true
Environment=QGUARD_ENABLE_CONFIG_PATCHES=true
Environment=QGUARD_NATIVE_RUNTIME_ENABLED=true
Environment=QGUARD_NATIVE_CAPTURE_SECONDS=8
Environment=QGUARD_SCAN_SYSTEM_CERTS=true
ExecStart=/usr/bin/npm run agent:watch
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target`;
  const powershellCommand = `$env:QGUARD_TENANT_ID="${tenantId}"
$env:QGUARD_AGENT_ID="${commandAgentId}"
$env:QGUARD_AGENT_TOKEN="agent_token_here"
$env:QGUARD_API_URL="${apiUrlPlaceholder}"
$env:QGUARD_ENABLE_REMEDIATION="true"
$env:QGUARD_ENABLE_CONFIG_PATCHES="true"
$env:QGUARD_NATIVE_RUNTIME_ENABLED="true"
$env:QGUARD_NATIVE_CAPTURE_SECONDS="8"
$env:QGUARD_SCAN_SYSTEM_CERTS="true"
npm run agent:watch`;
  const helmCommand = `helm install qguard-collector ./charts/qguard-collector \\
  --set tenantId="${tenantId}" \\
  --set agentId="${commandAgentId}" \\
  --set agentToken="agent_token_here" \\
  --set apiUrl="${apiUrlPlaceholder}" \\
  --set remediation.enabled=true \\
  --set remediation.configPatches=true \\
  --set nativeRuntime.enabled=true \\
  --set nativeRuntime.captureSeconds=8 \\
  --set nativeRuntime.scanSystemCerts=true`;

  const workflowSteps = [
    {
      title: 'Register Collector Agent',
      description: 'Create a tenant-bound collector record for this customer account.',
      action: 'Complete the registration form and create an agent.',
      status: agents.length > 0 ? 'Completed' : 'Pending setup',
      message: agents.length > 0 ? `${agents.length} collector agent(s) registered for this tenant.` : 'No collector agent has been registered yet.',
      snippet: 'POST /api/v1/agent-scanner/agents/enroll',
    },
    {
      title: 'Generate Secure Agent Token',
      description: 'Generate a one-time token. The backend stores only a token hash.',
      action: 'Create or rotate a token, then store it securely.',
      status: oneTimeAgentToken ? 'Completed' : agents.length > 0 ? 'Pending setup' : 'Queued',
      message: oneTimeAgentToken ? `One-time token ${oneTimeAgentToken.mode}. Copy it now.` : 'Token is displayed only at creation or rotation time.',
      snippet: 'QGUARD_AGENT_TOKEN="agent_token_here"',
    },
    {
      title: 'Install Agent Package',
      description: 'Deploy the collector by Docker, systemd, PowerShell, or Kubernetes.',
      action: 'Use one of the copyable deployment commands below.',
      status: selectedAgent ? 'Running' : 'Queued',
      message: selectedAgent ? 'Install command is ready with tenant and agent placeholders.' : 'Create an agent first.',
      snippet: 'npm run agent:watch',
    },
    {
      title: 'Configure Tenant ID and API Endpoint',
      description: 'Bind the collector to this tenant and the QGuard API endpoint.',
      action: 'Set QGUARD_TENANT_ID, QGUARD_AGENT_ID, QGUARD_AGENT_TOKEN, and QGUARD_API_URL.',
      status: selectedAgent ? 'Running' : 'Queued',
      message: `Tenant ID: ${tenantId}`,
      snippet: `QGUARD_API_URL="${apiUrlPlaceholder}"`,
    },
    {
      title: 'Start Agent Service',
      description: 'Run the collector continuously so heartbeats and evidence keep flowing.',
      action: 'Start the collector process or background service.',
      status: selectedAgent?.last_seen_at ? 'Completed' : selectedAgent ? 'Pending setup' : 'Queued',
      message: selectedAgent?.last_seen_at ? `Last seen ${formatDateTime(selectedAgent.last_seen_at)}.` : 'No heartbeat received yet.',
      snippet: 'npm run agent:watch',
    },
    {
      title: 'Verify Connection',
      description: 'Confirm the collector heartbeat is tenant-scoped and healthy.',
      action: 'Check Connection Status and Registered Agents.',
      status: onlineAgents > 0 ? 'Completed' : agents.length > 0 ? 'Pending setup' : 'Queued',
      message: onlineAgents > 0 ? `${onlineAgents} collector(s) online.` : 'Waiting for first heartbeat.',
      snippet: 'GET /api/v1/agent-scanner/agents',
    },
    {
      title: 'Run Authorized Scan',
      description: 'The agent scans only assigned targets and paths from policy.',
      action: 'Assign scan scope and keep the collector running.',
      status: agentEvidence.length > 0 ? 'Completed' : agents.length > 0 ? 'Running' : 'Queued',
      message: agentEvidence.length > 0 ? `${agentEvidence.length} evidence record(s) uploaded.` : 'No collector evidence received yet.',
      snippet: 'POST /api/v1/agent-scanner/agent/evidence',
    },
    {
      title: 'Approve Remediation Change',
      description: 'Tenant administrators approve, reject, or schedule operator patch actions before any change is executed.',
      action: 'Create a patch action and approve it from Operator Patch Workflow.',
      status: operatorActionStats.active > 0 || operatorActionStats.validated > 0 ? 'Running' : operatorActions.length > 0 ? 'Pending setup' : 'Queued',
      message: operatorActions.length > 0 ? `${operatorActions.length} change action(s) tracked with RBAC and approval metadata.` : 'No approved remediation action yet.',
      snippet: 'POST /api/v1/agent-scanner/remediation/operator-actions',
    },
    {
      title: 'Patch, Validate, and Roll Back',
      description: 'Guarded agents and connectors create snapshots, apply approved changes, validate after state, and roll back failed local patches.',
      action: 'Run the patcher with remediation enabled and submit validation evidence.',
      status: operatorActionStats.validated > 0 ? 'Completed' : operatorActionStats.active > 0 ? 'Running' : 'Queued',
      message: operatorActionStats.validated > 0 ? `${operatorActionStats.validated} action(s) validated.` : 'Waiting for before/after evidence and verification results.',
      snippet: 'DISCOVER -> ANALYZE -> APPROVE -> PATCH -> VALIDATE -> MONITOR -> REPORT',
    },
    {
      title: 'Review Results',
      description: 'Evidence is normalized into CBOM, assets, exposure, history, alerts, and remediation audit trails.',
      action: 'Open CBOM, Assets, Crypto Exposure, History, and PQC Orchestration.',
      status: agentEvidence.length > 0 || agentAlerts.length > 0 ? 'Completed' : 'Queued',
      message: agentAlerts.length > 0 ? `${agentAlerts.length} alert(s) available.` : 'Results appear after evidence is processed.',
      snippet: '/dashboard/cbom /dashboard/assets /dashboard/crypto-exposure /dashboard/pqc-orchestration',
    },
  ];

  const filteredFindings = findings.filter((finding) => {
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
          { id: 'findings' as TabId, label: `Findings (${findings.length})` },
          { id: 'logs' as TabId, label: 'Telemetry' },
        ].map((tab) => (
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

              {/* Timeframe Dropdown */}
              <div className="relative group/dropdown shrink-0">
                <button
                  onClick={() => void handleShowLast7Days()}
                  className="px-4 py-2.5 bg-white/5 border border-white/10 rounded-lg text-white hover:border-gold/30 transition-all flex items-center gap-3 text-left"
                >
                  <Calendar className="w-4 h-4 text-gold shrink-0" />
                  <div className="leading-none">
                    <div className="text-[10px] font-black uppercase tracking-wider text-white">Last 7 Days</div>
                    <div className="text-[9px] text-white/40 font-bold uppercase mt-0.5">{displayedHistory.length} Scans</div>
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

      {activeTab === 'agents' && (
        <div className="space-y-6">
          {agentsError && (
            <div className="rounded-xl border border-red-500/25 bg-red-500/10 p-4 text-sm text-red-300 flex items-start gap-3">
              <XCircle className="h-4 w-4 mt-0.5 shrink-0" />
              <span>{agentsError}</span>
            </div>
          )}

          <div className={GLASS_PANEL_CLASSES + " p-5"}>
            <div className="flex flex-col xl:flex-row xl:items-start justify-between gap-4">
              <div>
                <h2 className="text-lg font-black uppercase tracking-tight text-white">
                  Active PQC Remediation <span className="text-gold">Platform</span>
                </h2>
                <p className="mt-2 max-w-4xl text-xs leading-relaxed text-white/45">
                  Deployed collectors and operator patchers now follow a guarded remediation lifecycle: discover, analyze, approve, patch, validate, monitor, and report with tenant-scoped telemetry.
                </p>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {REMEDIATION_CONTROL_SUMMARY.map(([label, value]) => (
                  <div key={label} className="rounded-lg border border-gold/10 bg-white/[0.02] p-3">
                    <div className="text-[8px] font-black uppercase tracking-wider text-white/30">{label}</div>
                    <div className="mt-1 text-[10px] font-bold leading-snug text-white/65">{value}</div>
                  </div>
                ))}
              </div>
            </div>
            <div className="mt-4 flex flex-wrap gap-1.5">
              {REMEDIATION_WORKFLOW_STAGES.map((stage, index) => (
                <span key={stage} className="rounded border border-gold/15 bg-gold/[0.06] px-2.5 py-1 text-[9px] font-black uppercase tracking-wider text-gold/80">
                  {index + 1}. {stage}
                </span>
              ))}
            </div>
            <div className="mt-4 grid md:grid-cols-2 xl:grid-cols-4 gap-3">
              {REMEDIATION_READINESS_GROUPS.map((group) => (
                <div key={group.title} className="rounded-lg border border-gold/10 bg-white/[0.02] p-4">
                  <div className="text-[9px] font-black uppercase tracking-[0.18em] text-gold/70">{group.title}</div>
                  <div className="mt-3 space-y-2">
                    {group.items.map((item) => (
                      <div key={item} className="flex items-start gap-2 text-[10px] leading-relaxed text-white/50">
                        <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0 text-green-400" />
                        <span>{item}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-4 rounded-lg border border-green-400/10 bg-green-400/[0.035] p-4">
              <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-3">
                <div>
                  <div className="text-[9px] font-black uppercase tracking-[0.18em] text-green-300/80">Mandatory Quantum Stack</div>
                  <p className="mt-2 max-w-3xl text-[10px] leading-relaxed text-white/48">
                    Approved agents and operator patchers use this stack for remediation plans, safe config patches, validation evidence, and rollback-aware audit records when the target platform supports the required controls.
                  </p>
                </div>
                <span className="rounded border border-green-400/20 bg-green-400/10 px-2.5 py-1 text-[9px] font-black uppercase tracking-wider text-green-300">
                  {MANDATORY_QUANTUM_STACK.version}
                </span>
              </div>
              <div className="mt-3 grid sm:grid-cols-2 xl:grid-cols-4 gap-2">
                {MANDATORY_QUANTUM_STACK_GROUPS.map((group) => (
                  <div key={group.title} className="rounded border border-green-400/10 bg-black/20 p-3">
                    <div className="text-[9px] font-black uppercase tracking-wider text-white/35">{group.title}</div>
                    <div className="mt-2 flex flex-wrap gap-1">
                      {group.items.map((item) => (
                        <span key={item} className="rounded border border-green-400/10 bg-green-400/[0.06] px-1.5 py-0.5 text-[8px] font-bold text-green-100/70">{item}</span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="mt-4 grid xl:grid-cols-[minmax(0,1fr)_minmax(360px,0.8fr)] gap-4">
              <div className="rounded-lg border border-cyan-400/10 bg-cyan-400/[0.035] p-4">
                <div className="text-[9px] font-black uppercase tracking-[0.18em] text-cyan-300/80">Supported Remediation Environments</div>
                <div className="mt-3 grid sm:grid-cols-2 xl:grid-cols-4 gap-2">
                  {SUPPORTED_ENVIRONMENT_GROUPS.map((group) => (
                    <div key={group.title} className="rounded border border-white/10 bg-black/20 p-3">
                      <div className="text-[10px] font-black uppercase tracking-wider text-white/65">{group.title}</div>
                      <div className="mt-2 flex flex-wrap gap-1">
                        {group.items.map((item) => (
                          <span key={item} className="rounded border border-white/10 bg-white/[0.03] px-1.5 py-0.5 text-[8px] font-bold text-white/40">{item}</span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              <div className="rounded-lg border border-gold/10 bg-gold/[0.04] p-4">
                <div className="text-[9px] font-black uppercase tracking-[0.18em] text-gold/80">Local Collector Clarification</div>
                <div className="mt-3 space-y-2">
                  {LOCAL_COLLECTOR_CLARIFICATIONS.map(([question, answer]) => (
                    <div key={question} className="rounded border border-gold/10 bg-black/20 p-2.5">
                      <div className="text-[9px] font-black uppercase tracking-wider text-white/35">{question}</div>
                      <div className="mt-1 text-[10px] leading-relaxed text-white/55">{answer}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="grid lg:grid-cols-[minmax(0,1fr)_360px] gap-6">
            <div className={GLASS_PANEL_CLASSES + " p-5"}>
              <div className="flex flex-col md:flex-row md:items-start justify-between gap-4 mb-5">
                <div>
                  <h2 className="text-lg font-black uppercase tracking-tight text-white">
                    Agent Collector <span className="text-gold">Scanners</span>
                  </h2>
                  <p className="text-xs text-white/45 mt-1 leading-relaxed max-w-3xl">
                    Register tenant-bound collectors, deploy them inside authorized customer environments, and stream real cryptographic evidence back to QGuard for CBOM, assets, exposure, history, and alerts.
                  </p>
                </div>
                <button
                  onClick={fetchAgents}
                  className="px-3 py-2 rounded-lg border border-gold/20 text-[10px] font-black uppercase tracking-wider text-gold hover:bg-gold/10 transition-colors flex items-center gap-2 shrink-0"
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${agentsLoading ? 'animate-spin' : ''}`} /> Refresh
                </button>
              </div>

              <div className="grid sm:grid-cols-2 xl:grid-cols-4 gap-3">
                {[
                  { label: 'Registered Agents', value: agents.length, icon: Server, color: 'text-white' },
                  { label: 'Online', value: onlineAgents, icon: Radio, color: 'text-green-400' },
                  { label: 'Unhealthy', value: unhealthyAgents, icon: AlertTriangle, color: 'text-orange-400' },
                  { label: 'Revoked', value: revokedAgents, icon: PowerOff, color: 'text-white/45' },
                ].map((item) => (
                  <div key={item.label} className="rounded-lg border border-gold/10 bg-white/[0.02] p-4">
                    <div className="flex items-center gap-2 text-[9px] font-black uppercase tracking-[0.15em] text-white/35 mb-2">
                      <item.icon className="h-3.5 w-3.5 text-gold/45" /> {item.label}
                    </div>
                    <div className={`text-2xl font-black ${item.color}`}>{item.value}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className={GLASS_PANEL_CLASSES + " p-5"}>
              <h3 className="text-xs font-black uppercase tracking-[0.18em] text-white/60 mb-3 flex items-center gap-2">
                <Shield className="h-4 w-4 text-gold" /> Tenant Isolation
              </h3>
              <div className="space-y-3 text-xs text-white/45 leading-relaxed">
                <p>Agents, tokens, evidence, telemetry, alerts, scan history, CBOM, assets, and exposure records are scoped to the authenticated tenant.</p>
                <div className="rounded-lg border border-gold/10 bg-gold/[0.03] p-3">
                  <div className="text-[9px] font-black uppercase tracking-wider text-gold/70 mb-1">Tenant ID</div>
                  <div className="font-mono text-white/70 break-all">{tenantId}</div>
                </div>
                <p>Agent tokens are generated once, hashed at rest, and never displayed again after creation or rotation.</p>
              </div>
            </div>
          </div>

          <div className="grid xl:grid-cols-[420px_minmax(0,1fr)] gap-6">
            <div className="space-y-4">
              <div className={GLASS_PANEL_CLASSES + " p-5"}>
                <h3 className="text-xs font-black uppercase tracking-[0.18em] text-white/60 mb-4 flex items-center gap-2">
                  <Plus className="h-4 w-4 text-gold" /> Create New Collector Agent
                </h3>
                <div className="space-y-3">
                  <input
                    value={agentForm.name}
                    onChange={(e) => setAgentForm((prev) => ({ ...prev, name: e.target.value }))}
                    placeholder="Agent name"
                    className="w-full border rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none focus: glass-panel"
                  />
                  <select
                    value={agentForm.environment}
                    onChange={(e) => setAgentForm((prev) => ({ ...prev, environment: e.target.value }))}
                    className="w-full border rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none focus: glass-panel"
                  >
                    {['production', 'staging', 'development', 'dr', 'lab'].map((env) => <option key={env} value={env}>{env}</option>)}
                  </select>
                  <textarea
                    value={agentForm.allowedTargets}
                    onChange={(e) => setAgentForm((prev) => ({ ...prev, allowedTargets: e.target.value }))}
                    className="w-full h-24 border rounded-lg p-3 text-xs font-mono text-white focus:outline-none focus:resize-none glass-panel"
                    placeholder={'https://api.customer.com\napi.customer.com:443\nssh://server.customer.com:22'}
                  />
                  <div className="rounded-lg border border-cyan-400/10 bg-cyan-400/[0.04] p-3 text-[10px] leading-relaxed text-white/45">
                    <span className="font-black uppercase tracking-wider text-cyan-300/80">Allowed Targets:</span> network endpoints the agent may scan, such as HTTPS APIs, TLS hosts, IP:port pairs, or SSH URLs. Enter the exact host, URL, or endpoint that belongs to this tenant.
                  </div>
                  <textarea
                    value={agentForm.allowedPaths}
                    onChange={(e) => setAgentForm((prev) => ({ ...prev, allowedPaths: e.target.value }))}
                    className="w-full h-20 border rounded-lg p-3 text-xs font-mono text-white focus:outline-none focus:resize-none glass-panel"
                    placeholder={'C:\\Apps\\CustomerApi\\config\nC:\\nginx\\conf\n/opt/customer-api/config\n/etc/nginx/sites-enabled'}
                  />
                  <div className="rounded-lg border border-gold/10 bg-gold/[0.04] p-3 text-[10px] leading-relaxed text-white/45">
                    <span className="font-black uppercase tracking-wider text-gold/80">Allowed Paths:</span> local filesystem roots visible to the agent process. Use Windows, Linux, Docker mount, or Kubernetes mounted paths where TLS, OpenSSL, Nginx, app, or service config files actually live.
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <input
                      value={agentForm.intervalSeconds}
                      onChange={(e) => setAgentForm((prev) => ({ ...prev, intervalSeconds: e.target.value }))}
                      placeholder="Interval seconds"
                      className="border rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none focus: glass-panel"
                    />
                    <select
                      value={agentForm.alertThreshold}
                      onChange={(e) => setAgentForm((prev) => ({ ...prev, alertThreshold: e.target.value }))}
                      className="border rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none focus: glass-panel"
                    >
                      {['low', 'moderate', 'medium', 'high', 'critical'].map((severity) => <option key={severity} value={severity}>{severity}</option>)}
                    </select>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                    {AGENT_SCAN_TYPE_OPTIONS.map((scanType) => (
                      <label key={scanType.id} className="flex items-start gap-2 rounded-lg border border-gold/10 bg-white/[0.02] px-3 py-2 text-white/50 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={agentForm.scanTypes.includes(scanType.id)}
                          onChange={(e) => setAgentForm((prev) => ({
                            ...prev,
                            scanTypes: e.target.checked
                              ? Array.from(new Set([...prev.scanTypes, scanType.id]))
                              : prev.scanTypes.filter((item) => item !== scanType.id),
                          }))}
                          className="mt-0.5 accent-[#D4AF37]"
                        />
                        <span>
                          <span className="block text-[10px] font-black uppercase tracking-wider text-white/60">{scanType.label}</span>
                          <span className="mt-0.5 block text-[9px] normal-case leading-snug tracking-normal text-white/35">{scanType.detail}</span>
                        </span>
                      </label>
                    ))}
                  </div>
                  <button
                    onClick={handleCreateAgent}
                    disabled={agentsLoading || !agentForm.name.trim() || agentForm.scanTypes.length === 0}
                    className="w-full py-3 rounded-lg bg-gold text-black text-xs font-black uppercase tracking-[0.15em] flex items-center justify-center gap-2 hover:bg-yellow-400 transition-colors disabled:opacity-50"
                  >
                    {agentsLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
                    Create Agent and Generate Token
                  </button>
                </div>
              </div>

              {oneTimeAgentToken && (
                <div className="rounded-xl border border-yellow-500/25 bg-yellow-500/10 p-5">
                  <div className="flex items-start gap-3">
                    <KeyRound className="h-5 w-5 text-yellow-400 shrink-0" />
                    <div className="min-w-0 flex-1">
                      <h3 className="text-xs font-black uppercase tracking-[0.18em] text-yellow-300 mb-2">One-Time Agent Token</h3>
                      <p className="text-xs text-yellow-100/70 mb-3">Copy this token now. It is not recoverable after this page state is cleared.</p>
                      <div className="rounded-lg border border-yellow-500/20 p-3 font-mono text-[11px] text-yellow-100 break-all glass-panel">{oneTimeAgentToken.token}</div>
                      <div className="mt-3 flex gap-2">
                        <button onClick={() => copyPlainText(oneTimeAgentToken.token, 'one-time-token')} className="px-3 py-2 rounded-lg border border-yellow-500/30 text-[10px] font-black uppercase tracking-wider text-yellow-300 hover:bg-yellow-500/10 flex items-center gap-2">
                          <Copy className="h-3.5 w-3.5" /> {copiedCommand === 'one-time-token' ? 'Copied' : 'Copy Token'}
                        </button>
                        <button onClick={() => setOneTimeAgentToken(null)} className="px-3 py-2 rounded-lg border border-white/10 text-[10px] font-black uppercase tracking-wider text-white/45 hover:text-white">
                          Dismiss
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="space-y-4">
              <div className={GLASS_PANEL_CLASSES + " p-5"}>
                <button
                  type="button"
                  onClick={() => setIsAgentSetupWorkflowOpen((current) => !current)}
                  className="mb-1 flex w-full items-center justify-between gap-3 text-left"
                >
                  <span className="text-xs font-black uppercase tracking-[0.18em] text-white/60 flex items-center gap-2">
                    <ClipboardCheck className="h-4 w-4 text-gold" /> Agent Setup Workflow
                  </span>
                  <ChevronDown className={`h-4 w-4 transition-transform ${isAgentSetupWorkflowOpen ? 'rotate-180 text-gold' : 'text-white/45'}`} />
                </button>
                {isAgentSetupWorkflowOpen && (
                  <div className="mt-4 grid md:grid-cols-2 gap-3">
                    {workflowSteps.map((step, index) => (
                      <div key={step.title} className="rounded-lg border border-gold/10 bg-white/[0.02] p-4">
                        <div className="flex items-start justify-between gap-3 mb-2">
                          <div>
                            <div className="text-[9px] font-black uppercase tracking-[0.18em] text-gold/60">Step {index + 1}</div>
                            <div className="text-sm font-bold text-white/80">{step.title}</div>
                          </div>
                          <span className={`px-2 py-1 rounded border text-[8px] font-black uppercase tracking-wider ${agentStatusClass(step.status)}`}>{step.status}</span>
                        </div>
                        <p className="text-xs text-white/45 leading-relaxed mb-2">{step.description}</p>
                        <div className="text-[10px] text-white/35 mb-3"><span className="font-black text-white/50">Action:</span> {step.action}</div>
                        <div className="rounded-md border p-2 font-mono text-[10px] text-gold/70 break-all glass-panel">{step.snippet}</div>
                        <div className="mt-2 text-[10px] text-white/35">{step.message}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className={GLASS_PANEL_CLASSES + " p-5"}>
                <button
                  type="button"
                  onClick={() => setIsInstallationCommandsOpen((current) => !current)}
                  className="mb-1 flex w-full items-center justify-between gap-3 text-left"
                >
                  <span className="text-xs font-black uppercase tracking-[0.18em] text-white/60 flex items-center gap-2">
                    <Terminal className="h-4 w-4 text-gold" /> Installation Commands
                  </span>
                  <ChevronDown className={`h-4 w-4 transition-transform ${isInstallationCommandsOpen ? 'rotate-180 text-gold' : 'text-white/45'}`} />
                </button>
                {isInstallationCommandsOpen && (
                  <>
                    <div className="mt-4 grid xl:grid-cols-2 gap-3">
                      {[
                        { key: 'docker', label: 'Docker', icon: Package, command: dockerCommand },
                        { key: 'compose', label: 'Docker Compose', icon: HardDrive, command: composeCommand },
                        { key: 'systemd', label: 'Linux systemd', icon: Server, command: systemdCommand },
                        { key: 'powershell', label: 'Windows PowerShell', icon: Terminal, command: powershellCommand },
                        { key: 'helm', label: 'Kubernetes / Helm', icon: Cloud, command: helmCommand },
                      ].map((block) => (
                        <div key={block.key} className="rounded-lg border border-gold/10 bg-white/[0.02] overflow-hidden">
                          <div className="flex items-center justify-between gap-2 px-3 py-2 border-b border-gold/10 bg-gold/[0.03]">
                            <div className="flex items-center gap-2 text-[10px] font-black uppercase tracking-wider text-white/55">
                              <block.icon className="h-3.5 w-3.5 text-gold/60" /> {block.label}
                            </div>
                            <button onClick={() => copyPlainText(block.command, block.key)} className="p-1.5 rounded border border-gold/15 text-white/45 hover:text-gold hover:border-gold/40 transition-colors" title={`Copy ${block.label} command`}>
                              <Copy className="h-3.5 w-3.5" />
                            </button>
                          </div>
                          <pre className="p-3 text-[10px] text-white/60 font-mono overflow-x-auto whitespace-pre-wrap">{block.command}</pre>
                          {copiedCommand === block.key && <div className="px-3 pb-3 text-[10px] text-green-400">Copied {block.label} command</div>}
                        </div>
                      ))}
                    </div>
                    <div className="mt-3 text-[10px] text-white/35">
                      Commands intentionally use placeholders for agent tokens. Paste the one-time token only in the customer-controlled deployment environment.
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>

          <div className="grid xl:grid-cols-[420px_minmax(0,1fr)] gap-6">
            <div className={GLASS_PANEL_CLASSES + " p-5"}>
              <h3 className="text-xs font-black uppercase tracking-[0.18em] text-white/60 mb-4 flex items-center gap-2">
                <Cloud className="h-4 w-4 text-gold" /> Connector Access
              </h3>
              <div className="space-y-3">
                <select
                  value={connectorForm.provider}
                  onChange={(e) => setConnectorForm((prev) => ({
                    ...prev,
                    provider: e.target.value,
                    displayName: prev.displayName || `${e.target.value} Connector`,
                  }))}
                  className="w-full border rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none glass-panel"
                >
                  {CONNECTOR_PROVIDER_OPTIONS.map((provider) => (
                    <option key={provider} value={provider}>{provider}</option>
                  ))}
                </select>
                <input
                  value={connectorForm.displayName}
                  onChange={(e) => setConnectorForm((prev) => ({ ...prev, displayName: e.target.value }))}
                  placeholder="Connector display name"
                  className="w-full border rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none glass-panel"
                />
                <textarea
                  value={connectorForm.scopes}
                  onChange={(e) => setConnectorForm((prev) => ({ ...prev, scopes: e.target.value }))}
                  className="w-full h-24 border rounded-lg p-3 text-xs font-mono text-white focus:outline-none resize-none glass-panel"
                  placeholder={'kubernetes:read\nkubernetes:patch:ingress\naws:acm:read\naws:elasticloadbalancing:modify-listener\ncloudflare:zone:edit'}
                />
                <div className="rounded-lg border border-gold/10 bg-gold/[0.04] p-3 text-[10px] leading-relaxed text-white/45">
                  <span className="font-black uppercase tracking-wider text-gold/80">Connector Credentials:</span> register least-privilege provider scopes for cloud, Kubernetes, web, SaaS, PKI, database, or network device APIs. Do not paste private keys into migration jobs; use the tenant connector or approved operator patch action.
                </div>
                <textarea
                  value={connectorForm.allowedTargets}
                  onChange={(e) => setConnectorForm((prev) => ({ ...prev, allowedTargets: e.target.value }))}
                  className="w-full h-20 border rounded-lg p-3 text-xs font-mono text-white focus:outline-none resize-none glass-panel"
                  placeholder={'https://api.customer.com\nlb.customer.com:443\nnamespace/default/ingress/customer-api\narn:aws:elasticloadbalancing:region:acct:listener/app/app-lb/listener-id'}
                />
                <textarea
                  value={connectorForm.allowedPaths}
                  onChange={(e) => setConnectorForm((prev) => ({ ...prev, allowedPaths: e.target.value }))}
                  className="w-full h-20 border rounded-lg p-3 text-xs font-mono text-white focus:outline-none resize-none glass-panel"
                  placeholder={'/etc/kubernetes/manifests\n/repos/customer-api\n/opt/customer-api/config'}
                />
                <div className="rounded-lg border border-cyan-400/10 bg-cyan-400/[0.04] p-3 text-[10px] leading-relaxed text-white/45">
                  <span className="font-black uppercase tracking-wider text-cyan-300/80">Connector Targets:</span> use provider resource IDs, ARNs, Kubernetes resources, SaaS app IDs, endpoint URLs, APIs, CDN zones, load balancer IDs, certificate IDs, KMS/HSM keys, or database resources. Use paths only when the connector can actually read or patch that repository or mounted configuration.
                </div>
                <button
                  onClick={handleCreateConnector}
                  disabled={agentsLoading || !connectorForm.provider.trim() || !connectorForm.scopes.trim()}
                  className="w-full py-3 rounded-lg border border-gold/30 bg-gold/10 text-gold text-xs font-black uppercase tracking-[0.15em] flex items-center justify-center gap-2 hover:bg-gold hover:text-black transition-colors disabled:opacity-50"
                >
                  {agentsLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Cloud className="h-4 w-4" />}
                  Register Connector
                </button>
                <div className="text-[10px] leading-relaxed text-white/35">
                  Connectors are scoped by tenant, policy, target, path, and declared permissions. They create operator-approved workflows; they do not execute hidden changes.
                </div>
              </div>
            </div>

            <div className={GLASS_PANEL_CLASSES + " p-5"}>
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-4">
                <h3 className="text-xs font-black uppercase tracking-[0.18em] text-white/60 flex items-center gap-2">
                  <Settings className="h-4 w-4 text-gold" /> Operator Patch Workflow
                </h3>
                <div className="grid grid-cols-4 gap-2 text-center">
                  {[
                    ['Actions', operatorActionStats.total],
                    ['Active', operatorActionStats.active],
                    ['Blocked', operatorActionStats.blocked],
                    ['Validated', operatorActionStats.validated],
                  ].map(([label, value]) => (
                    <div key={label} className="rounded-lg border border-gold/10 bg-white/[0.02] px-3 py-2">
                      <div className="text-[8px] font-black uppercase tracking-wider text-white/30">{label}</div>
                      <div className="text-sm font-black text-white/80">{value}</div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="grid lg:grid-cols-2 gap-4">
                <div className="space-y-3">
                  <div className="grid sm:grid-cols-2 gap-3">
                    <select
                      value={operatorPatchForm.assetClass}
                      onChange={(e) => {
                        const nextGroup = patchOptionGroups.find((group) => group.assetClass === e.target.value);
                        setOperatorPatchForm((prev) => ({ ...prev, assetClass: e.target.value, optionId: nextGroup?.options?.[0]?.id || prev.optionId }));
                      }}
                      className="border rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none glass-panel"
                    >
                      {patchOptionGroups.map((group) => (
                        <option key={group.assetClass} value={group.assetClass}>{group.assetClass.replace(/_/g, ' ')}</option>
                      ))}
                    </select>
                    <select
                      value={operatorPatchForm.optionId}
                      onChange={(e) => setOperatorPatchForm((prev) => ({ ...prev, optionId: e.target.value }))}
                      className="border rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none glass-panel"
                    >
                      {selectedPatchGroup.options.map((option) => (
                        <option key={option.id} value={option.id}>{option.label}</option>
                      ))}
                    </select>
                  </div>
                  <select
                    value={operatorPatchForm.connectorId}
                    onChange={(e) => setOperatorPatchForm((prev) => ({ ...prev, connectorId: e.target.value }))}
                    className="w-full border rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none glass-panel"
                  >
                    <option value="">No connector / agent validation only</option>
                    {connectors.map((connector) => (
                      <option key={connector.id} value={connector.id}>{connector.display_name || connector.provider} ({connector.status || 'connected'})</option>
                    ))}
                  </select>
                  <input
                    value={operatorPatchForm.target}
                    onChange={(e) => setOperatorPatchForm((prev) => ({ ...prev, target: e.target.value }))}
                    placeholder="https://api.customer.com, namespace/default/ingress/customer-api, arn:aws:..., or identity-app-id"
                    className="w-full border rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none glass-panel"
                  />
                  <div className="rounded-lg border border-white/10 bg-white/[0.02] p-3 text-[10px] leading-relaxed text-white/42">
                    Patch Target is the exact resource to change or validate: endpoint URL for TLS, Kubernetes namespace/name/kind for ingress or cert-manager, cloud ARN/resource ID for load balancers or KMS, or identity application ID for signing policy.
                  </div>
                  <input
                    value={operatorPatchForm.migrationJobId}
                    onChange={(e) => setOperatorPatchForm((prev) => ({ ...prev, migrationJobId: e.target.value }))}
                    placeholder="Optional migration job ID from PQC Orchestration"
                    className="w-full border rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none glass-panel"
                  />
                  {selectedPatchOption && (
                    <div className="rounded-lg border border-gold/10 bg-white/[0.02] p-3">
                      <div className="text-xs font-bold text-white/75">{selectedPatchOption.summary}</div>
                      <div className="mt-2 text-[10px] text-white/40">{selectedPatchOption.validation}</div>
                      {selectedPatchOption.executionContract && (
                        <div className="mt-3 grid grid-cols-2 gap-2 text-[9px]">
                          {[
                            ['Approval', selectedPatchOption.executionContract.approvalRequired ? 'Required' : 'Optional'],
                            ['RBAC', selectedPatchOption.executionContract.rbacRequired ? 'Required' : 'Optional'],
                            ['Rollback', selectedPatchOption.executionContract.rollback?.automaticOnValidationFailure ? 'Automatic' : 'Manual'],
                            ['Heartbeat', '30-60s'],
                          ].map(([label, value]) => (
                            <div key={label} className="rounded border border-gold/10 bg-black/20 px-2 py-1.5">
                              <span className="font-black uppercase tracking-wider text-white/30">{label}: </span>
                              <span className="font-bold text-white/60">{value}</span>
                            </div>
                          ))}
                        </div>
                      )}
                      <div className="mt-3 rounded border border-green-400/10 bg-green-400/[0.035] p-2.5">
                        <div className="text-[9px] font-black uppercase tracking-wider text-green-300/80">Patch Stack</div>
                        <div className="mt-2 grid grid-cols-2 gap-1.5 text-[8px]">
                          {[
                            ['KEX', selectedMandatoryStack?.keyExchange?.hybrid || 'X25519 + ML-KEM-768'],
                            ['Signature', selectedMandatoryStack?.signatures?.hybrid || 'Ed25519 + ML-DSA-65'],
                            ['Cipher', selectedMandatoryStack?.encryption?.symmetric || 'AES-256-GCM'],
                            ['KDF/Hash', `${selectedMandatoryStack?.kdf?.primary || 'HKDF-SHA3-256'} / ${(selectedMandatoryStack?.hashes || ['SHA3-256', 'SHA3-512']).join(', ')}`],
                          ].map(([label, value]) => (
                            <div key={label} className="rounded border border-green-400/10 bg-black/20 px-2 py-1">
                              <span className="font-black uppercase tracking-wider text-white/30">{label}: </span>
                              <span className="font-bold text-green-100/70">{value}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                      {selectedPatchOption.requiresConnector && (
                        <div className={`mt-2 text-[10px] ${selectedMissingScopes.length ? 'text-yellow-300' : 'text-green-400'}`}>
                          {selectedMissingScopes.length ? `Missing scopes: ${selectedMissingScopes.join(', ')}` : 'Connector scope check passed.'}
                        </div>
                      )}
                    </div>
                  )}
                  <button
                    onClick={handleCreateOperatorAction}
                    disabled={agentsLoading || !selectedPatchOption || (selectedPatchOption.requiresConnector && !operatorPatchForm.connectorId)}
                    className="w-full py-3 rounded-lg bg-gold text-black text-xs font-black uppercase tracking-[0.15em] flex items-center justify-center gap-2 hover:bg-yellow-400 transition-colors disabled:opacity-50"
                  >
                    {agentsLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ClipboardCheck className="h-4 w-4" />}
                    Create Patch Action
                  </button>
                </div>

                <div className="space-y-3">
                  <textarea
                    value={operatorEvidenceJson}
                    onChange={(e) => setOperatorEvidenceJson(e.target.value)}
                    className="w-full h-40 border rounded-lg p-3 text-[10px] font-mono text-white focus:outline-none resize-none glass-panel"
                    placeholder="Validation evidence JSON array"
                  />
                  <div className="max-h-72 overflow-y-auto space-y-2">
                    {operatorActions.length === 0 ? (
                      <div className="rounded-lg border border-gold/10 bg-white/[0.02] p-6 text-center text-xs font-bold uppercase tracking-widest text-white/20">
                        No operator patch actions yet
                      </div>
                    ) : operatorActions.slice(0, 8).map((action) => {
                      const workflow = Array.isArray(action.patch_plan?.workflow) ? action.patch_plan.workflow : REMEDIATION_WORKFLOW_STAGES;
                      const contract = action.patch_plan?.executionContract || action.metadata?.executionContract || {};
                      const rollbackPlan = action.patch_plan?.rollbackPlan || contract.rollback || {};
                      const verification = action.metadata?.lastRemediationState?.verification || action.patch_plan?.verification || action.validation || {};
                      const validationStatus = verification.migrationSuccessful === true || action.validation?.passed === true
                        ? 'Verification passed'
                        : verification.rollbackRequired === true || action.validation?.passed === false
                          ? 'Rollback required'
                          : 'Awaiting verification';
                      return (
                        <div key={action.id} className="rounded-lg border border-gold/10 bg-white/[0.02] p-3">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <div className="text-xs font-bold text-white/80">{action.patch_plan?.optionLabel || action.action_type || 'Patch action'}</div>
                              <div className="text-[10px] font-mono text-white/30">{action.id}</div>
                            </div>
                            <span className={`px-2 py-1 rounded border text-[8px] font-black uppercase tracking-wider ${agentStatusClass(action.status || 'planned')}`}>{action.status || 'planned'}</span>
                          </div>
                          <div className="mt-2 text-[10px] text-white/40">{action.asset_class} {action.patch_plan?.target ? `-> ${action.patch_plan.target}` : ''}</div>
                          <div className="mt-3 grid grid-cols-2 gap-2 text-[9px]">
                            {[
                              ['Workflow', workflow.join(' -> ')],
                              ['Snapshots', rollbackPlan.configurationSnapshot || contract.snapshotsRequired ? 'Required' : 'Pending'],
                              ['Rollback', rollbackPlan.automaticRollbackOnValidationFailure || contract.automaticOnValidationFailure ? 'Automatic' : 'Manual'],
                              ['Verification', validationStatus],
                            ].map(([label, value]) => (
                              <div key={label} className="rounded border border-gold/10 bg-black/20 px-2 py-1.5">
                                <div className="font-black uppercase tracking-wider text-white/25">{label}</div>
                                <div className="mt-0.5 truncate text-white/55" title={String(value)}>{value}</div>
                              </div>
                            ))}
                          </div>
                          <div className="mt-3 flex flex-wrap gap-1.5">
                            <button type="button" onClick={() => handleUpdateOperatorAction(action.id, 'approved')} className="px-2 py-1.5 rounded border border-gold/20 text-[9px] font-black uppercase tracking-wider text-gold hover:bg-gold/10">Approve</button>
                            <button type="button" onClick={() => handleUpdateOperatorAction(action.id, 'scheduled')} className="px-2 py-1.5 rounded border border-yellow-400/20 text-[9px] font-black uppercase tracking-wider text-yellow-300 hover:bg-yellow-400/10">Schedule</button>
                            <button type="button" onClick={() => handleUpdateOperatorAction(action.id, 'rejected')} className="px-2 py-1.5 rounded border border-white/15 text-[9px] font-black uppercase tracking-wider text-white/55 hover:bg-white/[0.05]">Reject</button>
                            <button type="button" onClick={() => handleUpdateOperatorAction(action.id, 'applied')} className="px-2 py-1.5 rounded border border-cyan-400/20 text-[9px] font-black uppercase tracking-wider text-cyan-300 hover:bg-cyan-400/10">Applied</button>
                            <button type="button" onClick={() => handleValidateOperatorAction(action.id)} className="px-2 py-1.5 rounded border border-green-400/20 text-[9px] font-black uppercase tracking-wider text-green-300 hover:bg-green-400/10">Validate</button>
                            <button type="button" onClick={() => handleUpdateOperatorAction(action.id, 'failed')} className="px-2 py-1.5 rounded border border-red-400/20 text-[9px] font-black uppercase tracking-wider text-red-300 hover:bg-red-400/10">Fail</button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="grid xl:grid-cols-[minmax(0,1fr)_420px] gap-6">
            <div className={GLASS_PANEL_CLASSES + " overflow-hidden"}>
              <div className="px-5 py-4 border-b border-gold/10 flex flex-col md:flex-row md:items-center justify-between gap-3">
                <h3 className="text-xs font-black uppercase tracking-[0.18em] text-white/60 flex items-center gap-2">
                  <Server className="h-4 w-4 text-gold" /> Registered Agents
                </h3>
                <div className="text-[10px] text-white/30 font-mono">{agents.length} tenant-scoped record(s)</div>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left min-w-[980px]">
                  <thead className="bg-gold/[0.03] border-b border-gold/10">
                    <tr className="text-[9px] uppercase tracking-[0.15em] text-white/35">
                      {['Agent', 'Tenant', 'Environment', 'Status', 'Version', 'Last seen', 'Health', 'Scope', 'Recent scans', 'Actions'].map((heading) => (
                        <th key={heading} className="px-4 py-3 font-black">{heading}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {agents.length === 0 ? (
                      <tr>
                        <td colSpan={10} className="px-4 py-14 text-center text-white/20 text-xs uppercase tracking-widest font-bold">
                          No collector agents registered for this tenant
                        </td>
                      </tr>
                    ) : agents.map((agent) => {
                      const policy = normalizeAgentPolicy(agent.policy);
                      const displayStatus = agentDisplayStatus(agent);
                      const recentScanCount = agentEvidence.filter((item) => item.agent_id === agent.id).length;
                      return (
                        <tr key={agent.id} className={`border-b border-gold/5 hover:bg-gold/[0.03] transition-colors ${selectedAgent?.id === agent.id ? 'bg-gold/[0.04]' : ''}`}>
                          <td className="px-4 py-3">
                            <button onClick={() => setSelectedAgentId(agent.id)} className="text-left">
                              <div className="text-sm font-bold text-white/80">{agent.name}</div>
                              <div className="text-[10px] font-mono text-white/30">{agent.id}</div>
                            </button>
                          </td>
                          <td className="px-4 py-3 text-[10px] font-mono text-white/35">{agent.user_id.slice(0, 8)}...</td>
                          <td className="px-4 py-3 text-xs text-white/50">{agent.metadata?.environment || 'production'}</td>
                          <td className="px-4 py-3"><span className={`px-2 py-1 rounded border text-[8px] font-black uppercase tracking-wider ${agentStatusClass(displayStatus)}`}>{displayStatus}</span></td>
                          <td className="px-4 py-3 text-xs font-mono text-white/50">{agent.version || 'unknown'}</td>
                          <td className="px-4 py-3 text-xs text-white/45">{formatDateTime(agent.last_seen_at)}</td>
                          <td className="px-4 py-3 text-xs text-white/45">{isAgentOnline(agent) ? 'Healthy' : agent.revoked_at ? 'Revoked' : 'Needs heartbeat'}</td>
                          <td className="px-4 py-3 text-xs text-white/45">{policy.allowedTargets.length + policy.allowedPaths.length} item(s)</td>
                          <td className="px-4 py-3 text-xs text-white/45">{recentScanCount}</td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-1.5">
                              <button onClick={() => setSelectedAgentId(agent.id)} className="p-1.5 rounded border border-gold/15 text-white/45 hover:text-gold" title="View details"><Eye className="h-3.5 w-3.5" /></button>
                              <button onClick={() => copyPlainText(dockerCommand.replace(commandAgentId, agent.id), `install-${agent.id}`)} className="p-1.5 rounded border border-gold/15 text-white/45 hover:text-gold" title="Copy install command"><Copy className="h-3.5 w-3.5" /></button>
                              <button onClick={() => handleAssignCurrentScope(agent.id)} className="p-1.5 rounded border border-gold/15 text-white/45 hover:text-gold" title="Assign scan scope"><Settings className="h-3.5 w-3.5" /></button>
                              <button onClick={() => handleRotateAgentToken(agent.id)} className="p-1.5 rounded border border-yellow-500/20 text-yellow-400/70 hover:text-yellow-300" title="Rotate token"><KeyRound className="h-3.5 w-3.5" /></button>
                              <button onClick={() => handleRevokeAgent(agent.id)} className="p-1.5 rounded border border-orange-500/20 text-orange-400/70 hover:text-orange-300" title="Revoke"><PowerOff className="h-3.5 w-3.5" /></button>
                              <button onClick={() => handleDeleteAgent(agent.id)} className="p-1.5 rounded border border-red-500/20 text-red-400/70 hover:text-red-300" title="Delete"><Trash2 className="h-3.5 w-3.5" /></button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="space-y-4">
              <div className={GLASS_PANEL_CLASSES + " p-5"}>
                <h3 className="text-xs font-black uppercase tracking-[0.18em] text-white/60 mb-4 flex items-center gap-2">
                  <Activity className="h-4 w-4 text-gold" /> Connection Status
                </h3>
                {selectedAgent ? (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <div className="text-sm font-bold text-white/80">{selectedAgent.name}</div>
                        <div className="text-[10px] font-mono text-white/30">{selectedAgent.id}</div>
                      </div>
                      <span className={`px-2 py-1 rounded border text-[8px] font-black uppercase tracking-wider ${agentStatusClass(agentDisplayStatus(selectedAgent))}`}>{agentDisplayStatus(selectedAgent)}</span>
                    </div>
                    {[
                      ['Hostname / IP', `${selectedAgent.hostname || 'pending'}${selectedAgent.metadata?.lastIpAddress ? ` / ${selectedAgent.metadata.lastIpAddress}` : ''}`],
                      ['Environment', selectedAgent.metadata?.environment || 'production'],
                      ['Version', selectedAgent.version || 'unknown'],
                      ['Last seen', formatDateTime(selectedAgent.last_seen_at)],
                      ['Last scan', formatDateTime(selectedAgentLastScan)],
                      ['Assigned scope', `${selectedAgentPolicy.allowedTargets.length} target(s), ${selectedAgentPolicy.allowedPaths.length} path(s)`],
                    ].map(([label, value]) => (
                      <div key={label} className="rounded-lg border border-gold/10 bg-white/[0.02] p-3">
                        <div className="text-[8px] font-black uppercase tracking-wider text-white/25 mb-1">{label}</div>
                        <div className="text-xs text-white/60 break-all">{value}</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-10 text-white/20 text-xs uppercase tracking-widest font-bold">Select or create an agent</div>
                )}
              </div>

              <div className={GLASS_PANEL_CLASSES + " p-5"}>
                <h3 className="text-xs font-black uppercase tracking-[0.18em] text-white/60 mb-4 flex items-center gap-2">
                  <Terminal className="h-4 w-4 text-gold" /> Recent Telemetry
                </h3>
                <div className="space-y-2 max-h-72 overflow-y-auto">
                  {[...selectedAgentAlerts.slice(0, 5).map((alert) => ({
                    id: alert.id,
                    label: alert.title || alert.category || 'Scanner alert',
                    detail: alert.message || alert.severity || 'Alert recorded',
                    time: alert.created_at,
                    color: sevColor(alert.severity || 'low').t,
                  })), ...selectedAgentEvidence.slice(0, 6).map((evidence) => ({
                    id: evidence.id,
                    label: evidence.evidence_type || 'scanner_evidence',
                    detail: `${evidence.observed_algorithm || 'metadata'} ${evidence.host || evidence.file_path || evidence.asset_name || ''}`,
                    time: evidence.observed_at || evidence.created_at,
                    color: 'text-cyan-400',
                  }))].slice(0, 8).map((event) => (
                    <div key={event.id} className="rounded-lg border border-gold/10 bg-white/[0.02] p-3">
                      <div className={`text-[10px] font-black uppercase tracking-wider ${event.color}`}>{event.label}</div>
                      <div className="text-xs text-white/50 mt-1 break-all">{event.detail}</div>
                      <div className="text-[9px] text-white/25 mt-2">{formatDateTime(event.time)}</div>
                    </div>
                  ))}
                  {selectedAgent && selectedAgentAlerts.length === 0 && selectedAgentEvidence.length === 0 && (
                    <div className="text-center py-8 text-white/20 text-xs uppercase tracking-widest font-bold">
                      No real telemetry received yet
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>

          <div className="grid lg:grid-cols-2 gap-6">
            <div className={GLASS_PANEL_CLASSES + " p-5"}>
              <button
                type="button"
                onClick={() => setIsSecurityNotesOpen((current) => !current)}
                className="mb-1 flex w-full items-center justify-between gap-3 text-left"
              >
                <span className="text-xs font-black uppercase tracking-[0.18em] text-white/60 flex items-center gap-2">
                  <Lock className="h-4 w-4 text-gold" /> Security Notes
                </span>
                <ChevronDown className={`h-4 w-4 transition-transform ${isSecurityNotesOpen ? 'rotate-180 text-gold' : 'text-white/45'}`} />
              </button>
              {isSecurityNotesOpen && (
                <div className="mt-4 grid md:grid-cols-2 gap-3 text-xs text-white/45 leading-relaxed">
                  {[
                    'Collectors are outbound-only and do not expose inbound ports.',
                    'Tokens are hashed at rest and are shown only once during creation or rotation.',
                    'Server-side policy enforcement rejects evidence outside allowed targets and paths.',
                    'The collector skips secrets, private keys, credential stores, .env files, and unapproved directories.',
                    'Every agent, scan, evidence record, alert, CBOM record, asset, and exposure is scoped by tenant user ID.',
                    'Patch connectors require least-privilege scopes, RBAC, tenant admin approval, change approval, snapshots, validation, and audit logging before execution.',
                  ].map((note) => (
                    <div key={note} className="rounded-lg border border-gold/10 bg-white/[0.02] p-3">{note}</div>
                  ))}
                </div>
              )}
            </div>

            <div className={GLASS_PANEL_CLASSES + " p-5"}>
              <button
                type="button"
                onClick={() => setIsTroubleshootingOpen((current) => !current)}
                className="mb-1 flex w-full items-center justify-between gap-3 text-left"
              >
                <span className="text-xs font-black uppercase tracking-[0.18em] text-white/60 flex items-center gap-2">
                  <FileWarning className="h-4 w-4 text-gold" /> Troubleshooting
                </span>
                <ChevronDown className={`h-4 w-4 transition-transform ${isTroubleshootingOpen ? 'rotate-180 text-gold' : 'text-white/45'}`} />
              </button>
              {isTroubleshootingOpen && (
                <div className="mt-4 space-y-2">
                  {[
                    ['Agent not connecting', 'Verify QGUARD_API_URL, outbound HTTPS access, and that agent:watch is running.'],
                    ['Invalid token', 'Rotate the token and update the customer deployment environment. Tokens are not recoverable.'],
                    ['Tenant ID mismatch', 'Use the tenant ID shown in this tab and confirm the agent belongs to this account.'],
                    ['API URL unreachable', 'Check DNS, TLS inspection, proxy configuration, and firewall egress policy.'],
                    ['Firewall blocking outbound connection', 'Allow outbound HTTPS to the QGuard API host. No inbound access is required.'],
                    ['Collector version outdated', 'Update the deployed collector image/package and restart the service.'],
                    ['SSE/WebSocket disconnected', 'Refresh dashboard telemetry; agent evidence remains persisted by backend API upload.'],
                    ['Scan job stuck', 'Check agent heartbeat, policy scope, and backend scanner_alerts for module failures.'],
                    ['No telemetry received', 'Confirm allowedTargets or allowedPaths are configured and reachable from the customer machine.'],
                  ].map(([issue, fix]) => (
                    <div key={issue} className="rounded-lg border border-gold/10 bg-white/[0.02] p-3">
                      <div className="text-xs font-bold text-white/75">{issue}</div>
                      <div className="text-xs text-white/40 mt-1">{fix}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'settings' && (
        <div className="space-y-6">
          {agentsError && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-xs text-red-100">
              {agentsError}
            </div>
          )}

          <div className={GLASS_PANEL_CLASSES + " p-5"}>
            <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4">
              <div>
                <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60 flex items-center gap-2">
                  <Settings className="h-4 w-4 text-gold" /> Scanner Settings
                </h2>
                <p className="mt-2 text-xs text-white/40">Tenant-scoped configuration, policy enforcement, and live collector state.</p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <span className={`rounded border px-3 py-2 text-[9px] font-black uppercase tracking-wider ${agentSyncConnected ? 'border-green-500/30 bg-green-500/10 text-green-300' : 'border-yellow-500/25 bg-yellow-500/10 text-yellow-200'}`}>
                  {agentSyncConnected ? 'SSE Connected' : 'Manual Sync'}
                </span>
                <button
                  type="button"
                  onClick={handleRefreshAgentSettings}
                  className="inline-flex items-center gap-2 rounded border border-gold/20 bg-gold/10 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-gold hover:bg-gold/15"
                >
                  <RefreshCw className="h-3.5 w-3.5" /> Refresh
                </button>
                <button
                  type="button"
                  onClick={handleLoadSelectedAgentPolicy}
                  disabled={!selectedAgent}
                  className="inline-flex items-center gap-2 rounded border border-gold/20 bg-white/[0.03] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-white/60 hover:text-gold disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <ClipboardCheck className="h-3.5 w-3.5" /> Load Selected
                </button>
                <button
                  type="button"
                  onClick={handleApplyScannerSettings}
                  disabled={settingsSaving || !settingsCanSave}
                  className="inline-flex items-center gap-2 rounded border border-green-500/30 bg-green-500/10 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-green-300 hover:bg-green-500/15 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {settingsSaving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <CheckCircle2 className="h-3.5 w-3.5" />} Apply Policy
                </button>
              </div>
            </div>

            <div className="mt-5 grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
              {[
                { label: 'Registered', value: agents.length, icon: Server },
                { label: 'Online', value: onlineAgents, icon: Radio },
                { label: 'Revoked', value: revokedAgents, icon: PowerOff },
                { label: 'Open Alerts', value: openAgentAlerts.length, icon: AlertTriangle },
                { label: 'Evidence', value: agentEvidence.length, icon: Database },
                { label: 'Actions', value: operatorActionStats.total, icon: ClipboardCheck },
              ].map(({ label, value, icon: Icon }) => (
                <div key={label} className="rounded-lg border border-gold/10 bg-white/[0.02] p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[8px] font-black uppercase tracking-wider text-white/30">{label}</span>
                    <Icon className="h-3.5 w-3.5 text-gold/50" />
                  </div>
                  <div className="mt-2 text-xl font-black text-white">{value}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="grid xl:grid-cols-[minmax(0,1.15fr)_minmax(360px,0.85fr)] gap-6">
            <div className={GLASS_PANEL_CLASSES + " p-5"}>
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 mb-5">
                <h3 className="text-xs font-black uppercase tracking-[0.18em] text-white/60 flex items-center gap-2">
                  <Shield className="h-4 w-4 text-gold" /> Agent Policy
                </h3>
                <div className="flex flex-wrap items-center gap-2">
                  <select
                    value={settingsApplyMode}
                    onChange={(event) => setSettingsApplyMode(event.target.value as 'selected' | 'all')}
                    className="rounded border border-gold/15 bg-black/20 px-3 py-2 text-xs text-white/70 outline-none focus:border-gold/50"
                  >
                    <option value="selected">Selected agent</option>
                    <option value="all">All active agents</option>
                  </select>
                  <span className="rounded border border-gold/10 bg-white/[0.02] px-3 py-2 text-[9px] font-black uppercase tracking-wider text-white/35">
                    {settingsTargetCount} target{settingsTargetCount === 1 ? '' : 's'}
                  </span>
                </div>
              </div>

              <div className="grid md:grid-cols-2 gap-4">
                <label className="md:col-span-2 flex items-center justify-between gap-4 rounded-lg border border-gold/10 bg-white/[0.02] p-4">
                  <span>
                    <span className="block text-[9px] font-black uppercase tracking-wider text-gold/60">Policy Status</span>
                    <span className="block text-xs text-white/40 mt-1">Server-side enforcement for collector telemetry and evidence.</span>
                  </span>
                  <input
                    type="checkbox"
                    checked={agentForm.enabled}
                    onChange={(event) => setAgentForm((current) => ({ ...current, enabled: event.target.checked }))}
                    className="h-5 w-5 accent-gold"
                  />
                </label>

                <label className="space-y-2">
                  <span className="text-[9px] font-black uppercase tracking-wider text-white/35">Agent Name</span>
                  <input
                    value={agentForm.name}
                    onChange={(event) => setAgentForm((current) => ({ ...current, name: event.target.value }))}
                    className="w-full rounded border border-gold/15 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-gold/50"
                  />
                </label>

                <label className="space-y-2">
                  <span className="text-[9px] font-black uppercase tracking-wider text-white/35">Environment</span>
                  <select
                    value={agentForm.environment}
                    onChange={(event) => setAgentForm((current) => ({ ...current, environment: event.target.value }))}
                    className="w-full rounded border border-gold/15 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-gold/50"
                  >
                    <option value="production">Production</option>
                    <option value="staging">Staging</option>
                    <option value="development">Development</option>
                    <option value="dr">DR</option>
                  </select>
                </label>

                <label className="space-y-2">
                  <span className="text-[9px] font-black uppercase tracking-wider text-white/35">Heartbeat Interval</span>
                  <input
                    type="number"
                    min={30}
                    max={60}
                    step={30}
                    value={agentForm.intervalSeconds}
                    onChange={(event) => setAgentForm((current) => ({ ...current, intervalSeconds: event.target.value }))}
                    className="w-full rounded border border-gold/15 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-gold/50"
                  />
                </label>

                <label className="space-y-2">
                  <span className="text-[9px] font-black uppercase tracking-wider text-white/35">Alert Threshold</span>
                  <select
                    value={agentForm.alertThreshold}
                    onChange={(event) => setAgentForm((current) => ({ ...current, alertThreshold: event.target.value }))}
                    className="w-full rounded border border-gold/15 bg-black/20 px-3 py-2 text-sm text-white outline-none focus:border-gold/50"
                  >
                    <option value="low">Low</option>
                    <option value="moderate">Moderate</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </label>

                <div className="md:col-span-2 space-y-2">
                  <span className="text-[9px] font-black uppercase tracking-wider text-white/35">Scan Types</span>
                  <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-2">
                    {AGENT_SCAN_TYPE_OPTIONS.map((scanType) => (
                      <label key={scanType.id} className="flex items-start gap-2 rounded border border-gold/10 bg-white/[0.02] px-3 py-2 text-white/60">
                        <input
                          type="checkbox"
                          checked={agentForm.scanTypes.includes(scanType.id)}
                          onChange={(event) => setAgentForm((current) => ({
                            ...current,
                            scanTypes: event.target.checked
                              ? Array.from(new Set([...current.scanTypes, scanType.id]))
                              : current.scanTypes.filter((item) => item !== scanType.id),
                          }))}
                          className="mt-0.5 accent-gold"
                        />
                        <span>
                          <span className="block text-[10px] font-black uppercase tracking-wider text-white/65">{scanType.label}</span>
                          <span className="mt-0.5 block text-[9px] normal-case leading-snug tracking-normal text-white/35">{scanType.detail}</span>
                        </span>
                      </label>
                    ))}
                  </div>
                </div>

                <label className="space-y-2">
                  <span className="text-[9px] font-black uppercase tracking-wider text-white/35">Authorized Targets</span>
                  <textarea
                    rows={6}
                    value={agentForm.allowedTargets}
                    onChange={(event) => setAgentForm((current) => ({ ...current, allowedTargets: event.target.value }))}
                    className="w-full resize-none rounded border border-gold/15 bg-black/20 px-3 py-2 font-mono text-xs text-white/70 outline-none focus:border-gold/50"
                  />
                  <span className="block text-[10px] leading-relaxed text-white/35">Authorization allowlist: URLs, hostnames, IP:port pairs, SSH URLs, provider resource IDs, ARNs, Kubernetes resources, SaaS app IDs, CDN zones, certificate IDs, KMS/HSM keys, or database resources.</span>
                </label>

                <label className="space-y-2">
                  <span className="text-[9px] font-black uppercase tracking-wider text-white/35">Authorized Paths</span>
                  <textarea
                    rows={6}
                    value={agentForm.allowedPaths}
                    onChange={(event) => setAgentForm((current) => ({ ...current, allowedPaths: event.target.value }))}
                    className="w-full resize-none rounded border border-gold/15 bg-black/20 px-3 py-2 font-mono text-xs text-white/70 outline-none focus:border-gold/50"
                  />
                  <span className="block text-[10px] leading-relaxed text-white/35">Filesystem allowlist only: local paths visible to the installed agent, service account, container mount, or sidecar.</span>
                </label>
              </div>

              <div className="mt-5 flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={handleApplyScannerSettings}
                  disabled={settingsSaving || !settingsCanSave}
                  className="inline-flex items-center gap-2 rounded border border-green-500/30 bg-green-500/10 px-4 py-2 text-[10px] font-black uppercase tracking-wider text-green-300 hover:bg-green-500/15 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {settingsSaving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <CheckCircle2 className="h-3.5 w-3.5" />} Apply Settings
                </button>
                <button
                  type="button"
                  onClick={handleCreateAgent}
                  disabled={agentsLoading}
                  className="inline-flex items-center gap-2 rounded border border-gold/20 bg-gold/10 px-4 py-2 text-[10px] font-black uppercase tracking-wider text-gold hover:bg-gold/15 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <Plus className="h-3.5 w-3.5" /> Create Agent
                </button>
                <button
                  type="button"
                  onClick={() => copyPlainText(JSON.stringify(editableAgentPolicy, null, 2), 'settings-policy-json')}
                  className="inline-flex items-center gap-2 rounded border border-gold/15 bg-white/[0.03] px-4 py-2 text-[10px] font-black uppercase tracking-wider text-white/60 hover:text-gold"
                >
                  <Copy className="h-3.5 w-3.5" /> Copy Policy
                </button>
              </div>
            </div>

            <div className="space-y-6">
              <div className={GLASS_PANEL_CLASSES + " p-5"}>
                <div className="flex items-center justify-between gap-3 mb-4">
                  <h3 className="text-xs font-black uppercase tracking-[0.18em] text-white/60 flex items-center gap-2">
                    <Server className="h-4 w-4 text-gold" /> Selected Agent
                  </h3>
                  <span className={`rounded border px-2 py-1 text-[8px] font-black uppercase tracking-wider ${selectedAgent ? agentStatusClass(agentDisplayStatus(selectedAgent)) : 'border-white/10 text-white/35'}`}>
                    {selectedAgent ? agentDisplayStatus(selectedAgent) : 'None'}
                  </span>
                </div>

                <select
                  value={selectedAgent?.id || ''}
                  onChange={(event) => setSelectedAgentId(event.target.value || null)}
                  className="mb-4 w-full rounded border border-gold/15 bg-black/20 px-3 py-2 text-sm text-white/70 outline-none focus:border-gold/50"
                >
                  <option value="">No agent selected</option>
                  {agents.map((agent) => (
                    <option key={agent.id} value={agent.id}>{agent.name || agent.id}</option>
                  ))}
                </select>

                {selectedAgent ? (
                  <div className="grid grid-cols-2 gap-3">
                    {[
                      ['Environment', selectedAgent.metadata?.environment || 'production'],
                      ['Last seen', formatDateTime(selectedAgent.last_seen_at)],
                      ['Last scan', formatDateTime(selectedAgentLastScan)],
                      ['Policy scope', `${selectedAgentPolicy.allowedTargets.length + selectedAgentPolicy.allowedPaths.length} item(s)`],
                      ['Evidence', selectedAgentEvidence.length],
                      ['Alerts', selectedAgentAlerts.length],
                    ].map(([label, value]) => (
                      <div key={label} className="rounded-lg border border-gold/10 bg-white/[0.02] p-3">
                        <div className="text-[8px] font-black uppercase tracking-wider text-white/30 mb-1">{label}</div>
                        <div className="text-xs text-white/65 break-all">{value}</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="rounded-lg border border-gold/10 bg-white/[0.02] p-4 text-xs text-white/40">No collector agent is selected.</div>
                )}

                <div className="mt-4 flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={handleLoadSelectedAgentPolicy}
                    disabled={!selectedAgent}
                    className="inline-flex items-center gap-2 rounded border border-gold/15 bg-white/[0.03] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-white/60 hover:text-gold disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    <ClipboardCheck className="h-3.5 w-3.5" /> Load
                  </button>
                  <button
                    type="button"
                    onClick={() => selectedAgent && handleRotateAgentToken(selectedAgent.id)}
                    disabled={!selectedAgent || agentsLoading}
                    className="inline-flex items-center gap-2 rounded border border-yellow-500/25 bg-yellow-500/10 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-yellow-300 hover:bg-yellow-500/15 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    <KeyRound className="h-3.5 w-3.5" /> Rotate
                  </button>
                  <button
                    type="button"
                    onClick={() => selectedAgent && handleRevokeAgent(selectedAgent.id)}
                    disabled={!selectedAgent || agentsLoading}
                    className="inline-flex items-center gap-2 rounded border border-orange-500/25 bg-orange-500/10 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-orange-300 hover:bg-orange-500/15 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    <PowerOff className="h-3.5 w-3.5" /> Revoke
                  </button>
                  <button
                    type="button"
                    onClick={() => selectedAgent && handleDeleteAgent(selectedAgent.id)}
                    disabled={!selectedAgent || agentsLoading}
                    className="inline-flex items-center gap-2 rounded border border-red-500/25 bg-red-500/10 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-red-300 hover:bg-red-500/15 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    <Trash2 className="h-3.5 w-3.5" /> Delete
                  </button>
                </div>

                {oneTimeAgentToken && (
                  <div className="mt-4 rounded-lg border border-green-500/20 bg-green-500/10 p-3">
                    <div className="text-[8px] font-black uppercase tracking-wider text-green-300 mb-1">One-Time Token</div>
                    <button
                      type="button"
                      onClick={() => copyPlainText(oneTimeAgentToken.token, `agent-token-${oneTimeAgentToken.agentId}`)}
                      className="font-mono text-[11px] text-green-100/80 break-all text-left hover:text-green-100"
                    >
                      {oneTimeAgentToken.token}
                    </button>
                  </div>
                )}
              </div>

              <div className={GLASS_PANEL_CLASSES + " p-5"}>
                <h3 className="text-xs font-black uppercase tracking-[0.18em] text-white/60 mb-4 flex items-center gap-2">
                  <Activity className="h-4 w-4 text-gold" /> Sync and Alerts
                </h3>
                <div className="grid grid-cols-2 gap-3">
                  {[
                    ['Live stream', agentSyncConnected ? 'Connected' : 'Disconnected'],
                    ['Last sync', formatDateTime(agentSyncLastEventAt)],
                    ['Connectors', connectors.length],
                    ['Open alerts', openAgentAlerts.length],
                  ].map(([label, value]) => (
                    <div key={label} className="rounded-lg border border-gold/10 bg-white/[0.02] p-3">
                      <div className="text-[8px] font-black uppercase tracking-wider text-white/30 mb-1">{label}</div>
                      <div className="text-xs text-white/65 break-all">{value}</div>
                    </div>
                  ))}
                </div>
                <div className="mt-4 flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={handleAcknowledgeOpenAgentAlerts}
                    disabled={settingsSaving || openAgentAlerts.length === 0}
                    className="inline-flex items-center gap-2 rounded border border-gold/20 bg-gold/10 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-gold hover:bg-gold/15 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    <CheckCircle2 className="h-3.5 w-3.5" /> Acknowledge Alerts
                  </button>
                  <button
                    type="button"
                    onClick={handleRefreshAgentSettings}
                    className="inline-flex items-center gap-2 rounded border border-gold/15 bg-white/[0.03] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-white/60 hover:text-gold"
                  >
                    <RefreshCw className="h-3.5 w-3.5" /> Sync Now
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div className={GLASS_PANEL_CLASSES + " p-5"}>
            <h3 className="text-xs font-black uppercase tracking-[0.18em] text-white/60 mb-4 flex items-center gap-2">
              <Code2 className="h-4 w-4 text-gold" /> Tenant API References
            </h3>
            <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-3 font-mono text-[11px] text-white/50">
              {[
                'POST /api/v1/agent-scanner/agents/enroll',
                'GET /api/v1/agent-scanner/agents',
                'GET /api/v1/agent-scanner/stream',
                'PUT /api/v1/agent-scanner/agents/{agentId}/policy',
                'POST /api/v1/agent-scanner/agents/{agentId}/token/rotate',
                'POST /api/v1/agent-scanner/agent/heartbeat',
                'POST /api/v1/agent-scanner/agent/runtime-events',
                'POST /api/v1/agent-scanner/agent/evidence',
                'POST /api/v1/agent-scanner/alerts/{alertId}/acknowledge',
              ].map((route) => (
                <div key={route} className="rounded-lg border border-gold/10 bg-white/[0.02] p-3">{route}</div>
              ))}
            </div>
          </div>
        </div>
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
                {severity} ({findings.filter((finding) => finding.threatLevel.toLowerCase() === severity).length})
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
                {findings.length === 0 ? 'Run an authorized scan to discover cryptographic findings' : 'No findings match filters'}
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
