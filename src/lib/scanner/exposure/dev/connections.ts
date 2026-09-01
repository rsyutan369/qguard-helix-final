/**
 * Dev connection registry (Spec-2 §9, §33, §34, §44).
 *
 * The Dev tab can reach beyond a repository into live clusters, cloud accounts
 * and container registries. Every one of those needs a credential, and the
 * specification is emphatic about how credentials must be handled:
 *
 *   §44 "Read-only by default. Minimum required permissions. Encrypted
 *        credentials. No credential logging. Explicit scope selection."
 *   §18 "Never expose tokens to the browser unnecessarily. Never log access
 *        tokens."
 *
 * So: a connection is created server-side, its secret material is stored in the
 * connection record's server-only field, and the API only ever returns the
 * REDACTED view. `PublicConnection` is the shape the browser sees, and it has no
 * field that could carry a secret.
 *
 * §33/§34 "Do not automatically scan every cluster accessible to the user's
 * credentials." A connection carries an explicit SCOPE — namespaces, regions,
 * services — and the engines refuse to read outside it.
 */

import type { EngineCredential } from '../engine-contract';

export type ConnectionKind = 'kubernetes' | 'aws' | 'azure' | 'gcp' | 'registry' | 'git-provider';

export interface DevConnection {
  id: string;
  userId: string;
  kind: ConnectionKind;
  /** Operator-chosen name, shown in the UI. */
  label: string;
  /** Cluster endpoint, cloud account id, registry host, provider host. */
  endpoint: string;
  /** Explicit scope. Empty means "not yet scoped" and blocks scanning. */
  scope: {
    namespaces?: string[];
    regions?: string[];
    services?: string[];
    repositories?: string[];
  };
  /** Server-only. Never serialised to the browser. */
  secret: Record<string, string>;
  createdAt: string;
  lastVerifiedAt: string | null;
  /** Result of the last real connectivity + permission probe. */
  status: ConnectionStatus;
  statusDetail: string;
  /** Permissions the probe actually confirmed. */
  grantedPermissions: string[];
  /** Permissions requested but denied — drives "Not Assessed" (§43). */
  deniedPermissions: string[];
}

export type ConnectionStatus = 'unverified' | 'connected' | 'degraded' | 'unauthorized' | 'unreachable';

/** The browser-safe projection. Structurally incapable of carrying a secret. */
export interface PublicConnection {
  id: string;
  kind: ConnectionKind;
  label: string;
  endpoint: string;
  scope: DevConnection['scope'];
  createdAt: string;
  lastVerifiedAt: string | null;
  status: ConnectionStatus;
  statusDetail: string;
  grantedPermissions: string[];
  deniedPermissions: string[];
  /** Always true — restated in the UI so the access model is visible (§44). */
  readOnly: true;
}

export function toPublicConnection(connection: DevConnection): PublicConnection {
  return {
    id: connection.id,
    kind: connection.kind,
    label: connection.label,
    endpoint: redactEndpoint(connection.endpoint),
    scope: connection.scope,
    createdAt: connection.createdAt,
    lastVerifiedAt: connection.lastVerifiedAt,
    status: connection.status,
    statusDetail: connection.statusDetail,
    grantedPermissions: connection.grantedPermissions,
    deniedPermissions: connection.deniedPermissions,
    readOnly: true,
  };
}

/** Strip any credential a user pasted into a URL before it is displayed. */
export function redactEndpoint(endpoint: string): string {
  return endpoint.replace(/^(\w+:\/\/)[^@/]+@/, '$1[REDACTED]@').replace(/([?&](?:token|key|sig|signature|password)=)[^&]+/gi, '$1[REDACTED]');
}

export function toEngineCredential(connection: DevConnection): EngineCredential | null {
  switch (connection.kind) {
    case 'kubernetes': return { kind: 'kubeconfig', value: connection.secret };
    case 'aws': return { kind: 'aws', value: connection.secret };
    case 'azure': return { kind: 'azure', value: connection.secret };
    case 'gcp': return { kind: 'gcp', value: connection.secret };
    case 'registry': return { kind: 'registry', value: connection.secret };
    case 'git-provider': return { kind: 'git-token', value: connection.secret };
    default: return null;
  }
}

/* ─────────────────────────────────────────────── required-permission sets ── */

/**
 * The MINIMUM permissions each connector requests (§44, Spec-2 §9).
 *
 * These are published in the UI before the operator connects, so what the
 * platform will do with the credential is stated up front rather than
 * discovered afterwards. Nothing here is a write permission.
 */
export const REQUIRED_PERMISSIONS: Record<ConnectionKind, Array<{ permission: string; why: string }>> = {
  kubernetes: [
    { permission: 'get,list namespaces', why: 'Enumerate the namespaces you scope the assessment to.' },
    { permission: 'get,list deployments,statefulsets,daemonsets,pods', why: 'Read workload security context and image provenance.' },
    { permission: 'get,list services,ingresses,networkpolicies', why: 'Read network exposure and ingress TLS configuration.' },
    { permission: 'get,list secrets (metadata only)', why: 'Identify TLS secrets and their type. Secret DATA is never read.' },
    { permission: 'get,list roles,clusterroles,rolebindings,clusterrolebindings', why: 'Analyse RBAC escalation paths.' },
  ],
  aws: [
    { permission: 'sts:GetCallerIdentity', why: 'Confirm which account and principal the credential belongs to.' },
    { permission: 'acm:ListCertificates, acm:DescribeCertificate', why: 'Read managed certificate algorithms and key sizes.' },
    { permission: 'kms:ListKeys, kms:DescribeKey, kms:GetKeyRotationStatus', why: 'Read key specs, origin and rotation posture.' },
    { permission: 'elasticloadbalancing:DescribeLoadBalancers, DescribeListeners', why: 'Read TLS security policies on listeners.' },
    { permission: 's3:ListAllMyBuckets, s3:GetBucketEncryption', why: 'Read storage encryption configuration.' },
    { permission: 'iam:GetAccountSummary', why: 'Read account-level identity posture.' },
  ],
  azure: [
    { permission: 'Reader on the subscription', why: 'Enumerate resources in the subscriptions you scope.' },
    { permission: 'Key Vault Reader', why: 'Read key and certificate metadata — never key material.' },
  ],
  gcp: [
    { permission: 'roles/viewer (or cloudkms.viewer + compute.viewer)', why: 'Enumerate resources and read KMS key metadata.' },
  ],
  registry: [
    { permission: 'pull / read', why: 'Read image manifests and config blobs. Push is never requested.' },
  ],
  'git-provider': [
    { permission: 'repo:read / read_repository', why: 'Read the repository tree and file contents. Write is never requested.' },
  ],
};

export const CONNECTION_LABEL: Record<ConnectionKind, string> = {
  kubernetes: 'Kubernetes cluster',
  aws: 'AWS account',
  azure: 'Azure subscription',
  gcp: 'Google Cloud project',
  registry: 'Container registry',
  'git-provider': 'Git provider',
};

/* ──────────────────────────────────────────────────────────── validation ── */

export interface ConnectionInput {
  kind: ConnectionKind;
  label: string;
  endpoint: string;
  secret: Record<string, string>;
  scope?: DevConnection['scope'];
}

/**
 * Validate a connection request before anything is stored.
 *
 * The endpoint checks are also an SSRF control: a cluster endpoint that
 * resolves to a loopback or link-local address would let a tenant use the
 * platform's own network position to reach the platform's own metadata service.
 */
export interface ValidationVerdict {
  ok: boolean;
  /** Present whenever `ok` is false. */
  error?: string;
}

export function validateConnectionInput(input: ConnectionInput): ValidationVerdict {
  if (!input.label?.trim()) return { ok: false, error: 'A connection name is required.' };
  if (input.label.length > 120) return { ok: false, error: 'Connection name is too long.' };

  switch (input.kind) {
    case 'kubernetes': {
      if (!input.endpoint?.trim()) return { ok: false, error: 'The cluster API server URL is required.' };
      const endpointCheck = validateRemoteEndpoint(input.endpoint);
      if (!endpointCheck.ok) return endpointCheck;
      if (!input.secret?.token?.trim()) {
        return { ok: false, error: 'A read-only ServiceAccount token is required. Create one with the RBAC listed above and paste the token.' };
      }
      return { ok: true };
    }
    case 'aws': {
      if (!input.secret?.accessKeyId?.trim() || !input.secret?.secretAccessKey?.trim()) {
        return { ok: false, error: 'An AWS access key id and secret access key are required. Use a dedicated read-only IAM user or role.' };
      }
      if (!/^(AKIA|ASIA)[0-9A-Z]{16}$/.test(input.secret.accessKeyId.trim())) {
        return { ok: false, error: 'That does not look like an AWS access key id.' };
      }
      return { ok: true };
    }
    case 'azure': {
      const required = ['tenantId', 'clientId', 'clientSecret', 'subscriptionId'];
      const missing = required.filter((key) => !input.secret?.[key]?.trim());
      if (missing.length) return { ok: false, error: `Azure connection requires: ${missing.join(', ')}.` };
      return { ok: true };
    }
    case 'gcp': {
      if (!input.secret?.serviceAccountJson?.trim()) {
        return { ok: false, error: 'A service-account key JSON is required.' };
      }
      try {
        const parsed = JSON.parse(input.secret.serviceAccountJson);
        if (!parsed.client_email || !parsed.private_key || !parsed.project_id) {
          return { ok: false, error: 'The service-account JSON is missing client_email, private_key or project_id.' };
        }
      } catch {
        return { ok: false, error: 'The service-account JSON could not be parsed.' };
      }
      return { ok: true };
    }
    case 'registry': {
      if (!input.endpoint?.trim()) return { ok: false, error: 'A registry host is required.' };
      return validateRemoteEndpoint(input.endpoint);
    }
    case 'git-provider': {
      if (!input.secret?.token?.trim()) return { ok: false, error: 'A read-only access token is required.' };
      return { ok: true };
    }
    default:
      return { ok: false, error: 'Unsupported connection type.' };
  }
}

const PRIVATE_HOST = /^(localhost|127\.|0\.|10\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|\[?::1\]?|\[?fc00:|\[?fd00:|\[?fe80:)/i;
const BLOCKED_HOSTNAMES = new Set(['metadata.google.internal', 'instance-data', 'metadata.azure.com', '169.254.169.254']);

/** SSRF guard for any operator-supplied endpoint. */
export function validateRemoteEndpoint(endpoint: string): ValidationVerdict {
  let url: URL;
  try {
    url = new URL(endpoint.includes('://') ? endpoint : `https://${endpoint}`);
  } catch {
    return { ok: false, error: 'The endpoint is not a valid URL.' };
  }
  if (url.protocol !== 'https:') {
    return { ok: false, error: 'Only https endpoints are accepted — a plaintext control-plane connection would expose the credential in transit.' };
  }
  const host = url.hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.has(host) || PRIVATE_HOST.test(host)) {
    return {
      ok: false,
      error: 'Private, loopback and cloud-metadata addresses cannot be used as a connection endpoint. Expose the API server through a reachable, authenticated endpoint, or run the QGuard agent inside the network instead.',
    };
  }
  return { ok: true };
}
