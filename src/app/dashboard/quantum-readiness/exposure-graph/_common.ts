import {
  AppWindow,
  Award,
  Box,
  Boxes,
  Building2,
  Cloud,
  Database,
  FileKey2,
  Fingerprint,
  Globe,
  HardDrive,
  KeyRound,
  Laptop,
  Lock,
  Mail,
  Network,
  Puzzle,
  Router,
  Server,
  Share2,
  Terminal,
  Webhook,
  type LucideIcon,
} from 'lucide-react';
import type { AssetCategory, EdgeTrustClass, NodePosture, PriorityLabel } from '@/types/exposure-graph';
import { AMBER, BLUE, CYAN, EMERALD, GOLD, GREEN, ORANGE, RED, SLATE, TEAL, VIOLET } from '../_shared';

/* Five-state cryptographic posture legend (🔴 🟡 🟢 🔵 ⚪). */
export const POSTURE_COLOR: Record<NodePosture, string> = {
  vulnerable: RED,
  hybrid: AMBER,
  pqc: EMERALD,
  migrating: BLUE,
  unknown: SLATE,
};

export const POSTURE_LABEL: Record<NodePosture, string> = {
  vulnerable: 'Quantum Vulnerable',
  hybrid: 'Hybrid Migration',
  pqc: 'PQC Ready',
  migrating: 'Migration In Progress',
  unknown: 'Unknown / Unverified',
};

export const PRIORITY_COLOR: Record<PriorityLabel, string> = {
  Critical: RED,
  High: ORANGE,
  Medium: GOLD,
  Low: GREEN,
};

export const TRUST_CLASS_LABEL: Record<EdgeTrustClass, string> = {
  tls: 'TLS Trust',
  mtls: 'Mutual TLS',
  'certificate-chain': 'Certificate Chain',
  api: 'API Trust',
  ssh: 'SSH Trust',
  vpn: 'VPN Trust',
  identity: 'Identity Federation',
  kms: 'KMS Dependency',
  'service-mesh': 'Service Mesh Trust',
  cloud: 'Cloud IAM / Hosting',
  communication: 'Communication Path',
  dependency: 'Dependency',
};

export const TRUST_CLASS_COLOR: Record<EdgeTrustClass, string> = {
  tls: CYAN,
  mtls: TEAL,
  'certificate-chain': VIOLET,
  api: BLUE,
  ssh: GOLD,
  vpn: ORANGE,
  identity: VIOLET,
  kms: GOLD,
  'service-mesh': TEAL,
  cloud: SLATE,
  communication: SLATE,
  dependency: SLATE,
};

export const CATEGORY_ICON: Record<AssetCategory, LucideIcon> = {
  'certificate-authority': Award,
  kms: KeyRound,
  hsm: Lock,
  'identity-provider': Fingerprint,
  pki: FileKey2,
  'vpn-gateway': Router,
  'load-balancer': Network,
  api: Webhook,
  database: Database,
  kubernetes: Boxes,
  container: Box,
  'cloud-resource': Cloud,
  server: Server,
  vm: HardDrive,
  workstation: Laptop,
  'web-application': Globe,
  saas: AppWindow,
  email: Mail,
  dns: Share2,
  directory: Building2,
  'ssh-server': Terminal,
  'tls-endpoint': Lock,
  vendor: Building2,
  service: Puzzle,
};
