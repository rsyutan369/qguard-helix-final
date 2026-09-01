/**
 * Live Kubernetes Security Engine (Spec-2 §8 static+live, §9, §33).
 *
 * Connects to an authorised cluster with a READ-ONLY ServiceAccount token and
 * runs the same analysis the static engine runs over manifests — against the
 * live objects, which is the only way to see what is actually deployed rather
 * than what was committed.
 *
 * Three rules govern this engine, all from the specification:
 *
 *  §9  "Never require cluster-admin. Do not claim access to resources that the
 *       provided identity cannot actually read."
 *       → Every list call is individually permission-probed. A 403 becomes a
 *         `Not Assessed` entry naming the resource and the missing verb. It
 *         never becomes an empty result set.
 *
 *  §12 "Never return secret values to the frontend."
 *       → Secrets are listed with `?limit` and the DATA IS DISCARDED at the
 *         parse boundary in `stripSecretData`. The engine records type, name,
 *         namespace and key NAMES only.
 *
 *  §33 "Do not automatically scan every cluster accessible to the user's
 *       credentials."
 *       → The connection's namespace scope is mandatory. An unscoped
 *         connection refuses to scan rather than enumerating the cluster.
 */

import type { FindingSeverity } from '../types';
import type { EngineContext, EngineResult, ExposureEngine } from '../engine-contract';
import { buildEvidence, buildFinding, completed, failed, notAssessed } from '../engine-contract';
import { canonicalAlgorithmName, classifyQuantum } from '../algorithms';

/* ────────────────────────────────────────────────────────────── transport ── */

interface ClusterClient {
  endpoint: string;
  token: string;
  /** Optional PEM CA bundle. When absent the platform's trust store is used. */
  caBundle?: string;
  /** Never true in production; exists so an operator can diagnose a chain. */
  insecure: boolean;
}

interface ApiResult<T> {
  ok: boolean;
  status: number;
  data: T | null;
  /** Human reason for a non-ok result. */
  reason?: string;
}

const REQUEST_TIMEOUT_MS = 12_000;

/**
 * One read against the API server.
 *
 * The status codes are interpreted, not just propagated: 403 means the
 * ServiceAccount lacks the verb (a coverage gap), 404 means the resource kind is
 * not served by this cluster (genuinely not applicable), and anything else is a
 * transport problem. Conflating those three is how "no NetworkPolicies found"
 * comes to mean "forbidden".
 */
async function apiGet<T>(client: ClusterClient, path: string): Promise<ApiResult<T>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(`${client.endpoint.replace(/\/+$/, '')}${path}`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${client.token}`,
        Accept: 'application/json',
      },
      signal: controller.signal,
    });

    if (response.status === 403) {
      return { ok: false, status: 403, data: null, reason: 'The ServiceAccount is not authorised to list this resource.' };
    }
    if (response.status === 401) {
      return { ok: false, status: 401, data: null, reason: 'The token was rejected by the API server.' };
    }
    if (response.status === 404) {
      return { ok: false, status: 404, data: null, reason: 'This cluster does not serve that resource kind.' };
    }
    if (!response.ok) {
      return { ok: false, status: response.status, data: null, reason: `The API server returned HTTP ${response.status}.` };
    }

    return { ok: true, status: response.status, data: (await response.json()) as T };
  } catch (error) {
    const message = (error as Error).name === 'AbortError'
      ? `The API server did not respond within ${REQUEST_TIMEOUT_MS / 1000}s.`
      : (error as Error).message;
    return { ok: false, status: 0, data: null, reason: message };
  } finally {
    clearTimeout(timer);
  }
}

/* ──────────────────────────────────────────────────── connectivity probe ── */

export interface ClusterProbe {
  reachable: boolean;
  version: string | null;
  granted: string[];
  denied: string[];
  namespaces: string[];
  detail: string;
}

/**
 * Verify a cluster connection and enumerate what the identity can actually do.
 *
 * This runs when the operator saves a connection, so the UI can state the real
 * access level before any scan is offered — rather than discovering the gaps
 * mid-assessment.
 */
export async function probeCluster(client: ClusterClient): Promise<ClusterProbe> {
  const version = await apiGet<{ gitVersion?: string }>(client, '/version');
  if (!version.ok) {
    return {
      reachable: false,
      version: null,
      granted: [],
      denied: [],
      namespaces: [],
      detail: version.reason ?? 'The cluster API server could not be reached.',
    };
  }

  const probes: Array<{ label: string; path: string }> = [
    { label: 'namespaces', path: '/api/v1/namespaces?limit=1' },
    { label: 'pods', path: '/api/v1/pods?limit=1' },
    { label: 'deployments', path: '/apis/apps/v1/deployments?limit=1' },
    { label: 'services', path: '/api/v1/services?limit=1' },
    { label: 'ingresses', path: '/apis/networking.k8s.io/v1/ingresses?limit=1' },
    { label: 'networkpolicies', path: '/apis/networking.k8s.io/v1/networkpolicies?limit=1' },
    { label: 'secrets', path: '/api/v1/secrets?limit=1' },
    { label: 'roles', path: '/apis/rbac.authorization.k8s.io/v1/roles?limit=1' },
    { label: 'clusterroles', path: '/apis/rbac.authorization.k8s.io/v1/clusterroles?limit=1' },
    { label: 'rolebindings', path: '/apis/rbac.authorization.k8s.io/v1/rolebindings?limit=1' },
    { label: 'clusterrolebindings', path: '/apis/rbac.authorization.k8s.io/v1/clusterrolebindings?limit=1' },
  ];

  const granted: string[] = [];
  const denied: string[] = [];
  for (const probe of probes) {
    const result = await apiGet(client, probe.path);
    if (result.ok) granted.push(probe.label);
    else if (result.status === 403 || result.status === 401) denied.push(probe.label);
  }

  const namespaceList = await apiGet<{ items: Array<{ metadata: { name: string } }> }>(client, '/api/v1/namespaces?limit=500');
  const namespaces = namespaceList.ok ? (namespaceList.data?.items ?? []).map((item) => item.metadata.name) : [];

  return {
    reachable: true,
    version: version.data?.gitVersion ?? null,
    granted,
    denied,
    namespaces,
    detail: denied.length
      ? `Connected read-only. ${granted.length} resource kinds readable; ${denied.length} denied (${denied.join(', ')}) — those dimensions will be reported as Not Assessed.`
      : `Connected read-only with access to all ${granted.length} resource kinds the assessment requires.`,
  };
}

/* ─────────────────────────────────────────────────────── object handling ── */

interface K8sList<T> {
  items: T[];
  metadata?: { continue?: string };
}

interface K8sObject {
  apiVersion?: string;
  kind?: string;
  metadata?: { name?: string; namespace?: string; annotations?: Record<string, string>; labels?: Record<string, string> };
  spec?: any;
  type?: string;
  data?: Record<string, string>;
  rules?: any[];
  roleRef?: { kind?: string; name?: string };
  subjects?: Array<{ kind?: string; name?: string; namespace?: string }>;
}

/**
 * Discard Secret DATA at the parse boundary (§12).
 *
 * Called on every Secret the moment it is deserialised, before anything else
 * can see it. What survives is the key NAMES, which is what the assessment
 * needs, and never a value.
 */
export function stripSecretData(secret: K8sObject): { keys: string[]; type: string } {
  const keys = Object.keys(secret.data ?? {});
  const type = secret.type ?? 'Opaque';
  delete secret.data;
  return { keys, type };
}

/* ────────────────────────────────────────────────────────────── the engine ── */

export const liveKubernetesEngine: ExposureEngine = {
  descriptor: {
    id: 'k8s-live',
    label: 'Live Kubernetes Cluster',
    description: 'Reads workloads, ingress TLS, RBAC, network policy and secret metadata from a connected cluster using a read-only ServiceAccount. Secret values are never read.',
    mode: 'dev',
    layer: 'kubernetes',
    capability: 'kubernetes',
    weight: 15,
    minTier: 'pro',
  },

  appliesTo(context) {
    if (context.target.kind !== 'kubernetes') {
      return { applicable: false, reason: 'The scan target is not a Kubernetes cluster.' };
    }
    if (!context.credential || context.credential.kind !== 'kubeconfig') {
      return { applicable: false, reason: 'No Kubernetes connection is attached to this scan.' };
    }
    if (!context.target.namespaces?.length) {
      return { applicable: false, reason: 'No namespace scope was selected. Select the namespaces to assess — this scanner never enumerates a whole cluster implicitly.' };
    }
    return { applicable: true };
  },

  async execute(context: EngineContext): Promise<EngineResult> {
    if (context.target.kind !== 'kubernetes' || !context.credential) {
      return failed('The Kubernetes engine was invoked without a cluster target.');
    }

    const client: ClusterClient = {
      endpoint: context.credential.value.endpoint ?? '',
      token: context.credential.value.token ?? '',
      caBundle: context.credential.value.caBundle,
      insecure: context.credential.value.insecure === 'true',
    };
    if (!client.endpoint || !client.token) {
      return notAssessed('The cluster connection is missing its endpoint or token.', 'Kubernetes cluster');
    }

    const namespaces = context.target.namespaces;
    const findings: ReturnType<typeof buildFinding>[] = [];
    let workloadCount = 0;
    let cloudResources = 0;
    const deployedImages: string[] = [];

    context.report('Verifying cluster access');
    const probe = await probeCluster(client);
    if (!probe.reachable) {
      return notAssessed(`The cluster could not be reached: ${probe.detail}`, 'Kubernetes cluster');
    }
    for (const denied of probe.denied) {
      context.notAssessed(`Kubernetes ${denied}`, 'The connected ServiceAccount is not authorised to list this resource, so it was not assessed. This is a permission gap, not an absence of findings.');
    }

    context.workspace.meta.cluster = {
      endpoint: client.endpoint.replace(/^(https:\/\/)[^@/]+@/, '$1'),
      version: probe.version,
      namespaces,
      granted: probe.granted,
      denied: probe.denied,
    };

    /* ── workloads ──────────────────────────────────────────────────────── */
    let index = 0;
    for (const namespace of namespaces) {
      if (context.isCancelled()) break;
      index += 1;
      context.report(`Reading namespace ${namespace}`, { done: index, total: namespaces.length, unit: 'namespaces' });

      const deployments = await apiGet<K8sList<K8sObject>>(client, `/apis/apps/v1/namespaces/${encodeURIComponent(namespace)}/deployments?limit=200`);
      const statefulsets = await apiGet<K8sList<K8sObject>>(client, `/apis/apps/v1/namespaces/${encodeURIComponent(namespace)}/statefulsets?limit=200`);
      const daemonsets = await apiGet<K8sList<K8sObject>>(client, `/apis/apps/v1/namespaces/${encodeURIComponent(namespace)}/daemonsets?limit=200`);

      for (const result of [deployments, statefulsets, daemonsets]) {
        if (!result.ok) {
          if (result.status === 403) context.notAssessed(`Workloads in ${namespace}`, result.reason ?? 'Access denied.');
          continue;
        }
        for (const workload of result.data?.items ?? []) {
          workloadCount += 1;
          cloudResources += 1;
          findings.push(...assessLiveWorkload(context, namespace, workload, deployedImages));
        }
      }

      /* ── ingress TLS ──────────────────────────────────────────────────── */
      const ingresses = await apiGet<K8sList<K8sObject>>(client, `/apis/networking.k8s.io/v1/namespaces/${encodeURIComponent(namespace)}/ingresses?limit=200`);
      if (ingresses.ok) {
        for (const ingress of ingresses.data?.items ?? []) {
          cloudResources += 1;
          findings.push(...assessLiveIngress(context, namespace, ingress));
        }
      } else if (ingresses.status === 403) {
        context.notAssessed(`Ingresses in ${namespace}`, ingresses.reason ?? 'Access denied.');
      }

      /* ── secret metadata (§12) ────────────────────────────────────────── */
      const secrets = await apiGet<K8sList<K8sObject>>(client, `/api/v1/namespaces/${encodeURIComponent(namespace)}/secrets?limit=300`);
      if (secrets.ok) {
        for (const secret of secrets.data?.items ?? []) {
          const { keys, type } = stripSecretData(secret);
          cloudResources += 1;
          if (type !== 'kubernetes.io/tls') continue;
          const name = secret.metadata?.name ?? '(unnamed)';
          const quantum = classifyQuantum({ algorithm: 'RSA', role: 'certificate' });
          findings.push(
            buildFinding({
              scanId: context.scanId,
              engineId: 'k8s-live',
              mode: context.mode,
              layer: 'kubernetes',
              category: 'Kubernetes Cryptography',
              subcategory: 'TLS secret',
              title: `TLS secret "${name}" in ${namespace}`,
              description: `A kubernetes.io/tls secret with fields ${keys.join(', ')} backs TLS termination in this namespace. Its certificate and private key were NOT read — this engine discards secret data at the parse boundary — so the certificate's algorithm is not established here. Where the same certificate is served on a public endpoint, the Web assessment measures its algorithm directly.`,
              severity: 'info',
              confidence: 'high',
              detection: 'observed',
              role: 'certificate',
              quantumStatus: 'unknown',
              quantumRationale: 'The certificate algorithm was not read, so no quantum verdict is published for this secret.',
              recommendation: 'Assess the public endpoint this certificate serves, or export the certificate half (not the key) for algorithm analysis.',
              evidence: [
                buildEvidence({
                  summary: `Secret ${namespace}/${name} of type kubernetes.io/tls with keys ${keys.join(', ')}.`,
                  scope: namespace,
                  reference: `Secret/${name}`,
                  provider: 'kubernetes',
                  ruleId: 'k8s-live-tls-secret',
                  attributes: { type, keys: keys.join(','), material: '[NEVER READ]' },
                }),
              ],
              identity: `k8s-live|tls-secret|${namespace}/${name}`,
            }),
          );
        }
      } else if (secrets.status === 403) {
        context.notAssessed(`Secret metadata in ${namespace}`, secrets.reason ?? 'Access denied.');
      }

      /* ── network policy presence ──────────────────────────────────────── */
      const policies = await apiGet<K8sList<K8sObject>>(client, `/apis/networking.k8s.io/v1/namespaces/${encodeURIComponent(namespace)}/networkpolicies?limit=100`);
      if (policies.ok && (policies.data?.items ?? []).length === 0 && workloadCount > 0) {
        findings.push(
          buildFinding({
            scanId: context.scanId,
            engineId: 'k8s-live',
            mode: context.mode,
            layer: 'kubernetes',
            category: 'Kubernetes Network',
            subcategory: 'No NetworkPolicy',
            title: `Namespace "${namespace}" has no NetworkPolicy`,
            description: `The live cluster reports zero NetworkPolicy objects in namespace "${namespace}" while workloads are running there. Kubernetes defaults to allow-all pod-to-pod traffic, so every workload in this namespace is reachable from every pod in the cluster.`,
            severity: 'medium',
            confidence: 'high',
            detection: 'observed',
            quantumStatus: 'not-applicable',
            recommendation: 'Apply a default-deny NetworkPolicy and open only the flows each workload requires.',
            evidence: [
              buildEvidence({
                summary: `0 NetworkPolicy objects in live namespace ${namespace}.`,
                scope: namespace,
                provider: 'kubernetes',
                ruleId: 'k8s-live-no-networkpolicy',
              }),
            ],
            identity: `k8s-live|no-networkpolicy|${namespace}`,
          }),
        );
      } else if (policies.status === 403) {
        context.notAssessed(`NetworkPolicies in ${namespace}`, policies.reason ?? 'Access denied.');
      }
    }

    /* ── cluster-wide RBAC ──────────────────────────────────────────────── */
    context.report('Analysing cluster RBAC');
    const bindings = await apiGet<K8sList<K8sObject>>(client, '/apis/rbac.authorization.k8s.io/v1/clusterrolebindings?limit=500');
    if (bindings.ok) {
      for (const binding of bindings.data?.items ?? []) {
        if (binding.roleRef?.name !== 'cluster-admin') continue;
        const subjects = (binding.subjects ?? [])
          .filter((subject) => subject.kind === 'ServiceAccount' || subject.kind === 'User' || subject.kind === 'Group')
          .map((subject) => `${subject.kind}/${subject.namespace ? `${subject.namespace}:` : ''}${subject.name}`);
        if (subjects.length === 0) continue;
        // The built-in system bindings are expected and are not findings.
        if (subjects.every((subject) => subject.includes('system:masters') || subject.startsWith('Group/system:'))) continue;

        findings.push(
          buildFinding({
            scanId: context.scanId,
            engineId: 'k8s-live',
            mode: context.mode,
            layer: 'kubernetes',
            category: 'Kubernetes RBAC',
            subcategory: 'cluster-admin binding',
            title: `ClusterRoleBinding "${binding.metadata?.name}" grants cluster-admin`,
            description: `${subjects.join(', ')} ${subjects.length === 1 ? 'is' : 'are'} bound to cluster-admin in the live cluster. That grants unrestricted access to every resource in every namespace, including reading every TLS private key the cluster holds.`,
            severity: 'critical',
            confidence: 'high',
            detection: 'observed',
            quantumStatus: 'not-applicable',
            recommendation: 'Replace cluster-admin with a purpose-built role, and audit what each subject actually requires.',
            evidence: [
              buildEvidence({
                summary: `ClusterRoleBinding/${binding.metadata?.name} → cluster-admin → ${subjects.join(', ')}`,
                scope: 'cluster',
                reference: `ClusterRoleBinding/${binding.metadata?.name}`,
                provider: 'kubernetes',
                ruleId: 'k8s-live-cluster-admin',
                attributes: { subjects: subjects.join(',') },
              }),
            ],
            identity: `k8s-live|cluster-admin|${binding.metadata?.name}`,
          }),
        );
      }
    } else if (bindings.status === 403) {
      context.notAssessed('Cluster RBAC', bindings.reason ?? 'Access denied.');
    }

    for (const finding of findings) context.emit(finding);
    context.workspace.meta.deployedImages = deployedImages;

    return completed(
      findings,
      {
        kubernetesNamespaces: namespaces.length,
        kubernetesWorkloads: workloadCount,
        cloudResources,
      },
      { probe, deployedImages },
    );
  },
};

/* ─────────────────────────────────────────────────── live object analysis ── */

function assessLiveWorkload(
  context: EngineContext,
  namespace: string,
  workload: K8sObject,
  deployedImages: string[],
): ReturnType<typeof buildFinding>[] {
  const findings: ReturnType<typeof buildFinding>[] = [];
  const kind = workload.kind ?? 'Workload';
  const name = workload.metadata?.name ?? '(unnamed)';
  const podSpec = workload.spec?.template?.spec ?? workload.spec;
  if (!podSpec) return findings;

  const containers: any[] = [...(podSpec.containers ?? []), ...(podSpec.initContainers ?? [])];
  const subject = `${kind}/${name} in ${namespace}`;

  const add = (input: {
    id: string;
    subcategory: string;
    title: string;
    description: string;
    severity: FindingSeverity;
    recommendation: string;
    detail?: Record<string, string | number | boolean>;
  }) => {
    findings.push(
      buildFinding({
        scanId: context.scanId,
        engineId: 'k8s-live',
        mode: context.mode,
        layer: 'kubernetes',
        category: 'Kubernetes Workload',
        subcategory: input.subcategory,
        title: `${input.title} — ${subject}`,
        description: input.description,
        severity: input.severity,
        confidence: 'high',
        detection: 'observed',
        quantumStatus: 'not-applicable',
        recommendation: input.recommendation,
        evidence: [
          buildEvidence({
            summary: `${input.title} observed on live ${subject}.`,
            scope: namespace,
            reference: `${kind}/${name}`,
            provider: 'kubernetes',
            ruleId: input.id,
            attributes: { kind, name, namespace, ...(input.detail ?? {}) },
          }),
        ],
        identity: `k8s-live|${input.id}|${namespace}/${kind}/${name}`,
      }),
    );
  };

  if (podSpec.hostNetwork === true) {
    add({
      id: 'k8s-live-hostnetwork',
      subcategory: 'Host namespace',
      title: 'Workload shares the host network namespace',
      description: 'The running workload has hostNetwork enabled, so it binds directly to node interfaces and NetworkPolicy cannot isolate it.',
      severity: 'high',
      recommendation: 'Remove hostNetwork unless this is a node-level agent.',
    });
  }
  if (podSpec.hostPID === true || podSpec.hostIPC === true) {
    add({
      id: 'k8s-live-host-namespace',
      subcategory: 'Host namespace',
      title: 'Workload shares a host process or IPC namespace',
      description: 'hostPID or hostIPC is enabled on the running workload, removing process-level isolation from the node.',
      severity: 'high',
      recommendation: 'Remove hostPID and hostIPC.',
    });
  }

  for (const container of containers) {
    const image: string = container.image ?? '';
    if (image) deployedImages.push(image);
    const securityContext = container.securityContext ?? {};

    if (securityContext.privileged === true) {
      add({
        id: 'k8s-live-privileged',
        subcategory: 'Privilege',
        title: `Container "${container.name}" runs privileged`,
        description: 'A running container is privileged, which grants every capability and disables the seccomp, AppArmor and device restrictions separating it from the node.',
        severity: 'critical',
        recommendation: 'Remove privileged and grant only the specific capabilities required.',
        detail: { container: container.name, image },
      });
    }
    if (securityContext.allowPrivilegeEscalation === true) {
      add({
        id: 'k8s-live-escalation',
        subcategory: 'Privilege',
        title: `Container "${container.name}" permits privilege escalation`,
        description: 'allowPrivilegeEscalation is true on a running container.',
        severity: 'high',
        recommendation: 'Set allowPrivilegeEscalation: false.',
        detail: { container: container.name },
      });
    }
    if (securityContext.runAsUser === 0 || (podSpec.securityContext?.runAsUser === 0 && securityContext.runAsUser === undefined)) {
      add({
        id: 'k8s-live-root',
        subcategory: 'Privilege',
        title: `Container "${container.name}" runs as uid 0`,
        description: 'The running container executes as root inside the container.',
        severity: 'high',
        recommendation: 'Run as a non-zero uid and set runAsNonRoot: true.',
        detail: { container: container.name },
      });
    }
    const added: string[] = securityContext.capabilities?.add ?? [];
    for (const capability of added) {
      const normalized = capability.toUpperCase().replace(/^CAP_/, '');
      if (!['SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'SYS_MODULE', 'ALL', 'DAC_READ_SEARCH'].includes(normalized)) continue;
      add({
        id: 'k8s-live-capability',
        subcategory: 'Capabilities',
        title: `Container "${container.name}" holds capability ${normalized}`,
        description: `The running container has been granted CAP_${normalized}, a documented container-escape primitive.`,
        severity: normalized === 'ALL' || normalized === 'SYS_ADMIN' ? 'critical' : 'high',
        recommendation: `Drop ${normalized}.`,
        detail: { container: container.name, capability: normalized },
      });
    }
    if (image && !image.includes('@sha256:')) {
      add({
        id: 'k8s-live-image-tag',
        subcategory: 'Image provenance',
        title: `Container "${container.name}" runs a tag-referenced image`,
        description: `The running container references "${image}" by tag rather than digest, so what is running cannot be tied to a specific, verified build.`,
        severity: image.endsWith(':latest') || !image.includes(':') ? 'medium' : 'low',
        recommendation: 'Deploy by digest and let the release pipeline update it.',
        detail: { container: container.name, image },
      });
    }

    for (const env of container.env ?? []) {
      if (!env?.name || env.value === undefined) continue;
      if (!/(PASSWORD|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE_KEY|CREDENTIAL)/i.test(env.name)) continue;
      add({
        id: 'k8s-live-inline-secret',
        subcategory: 'Secrets',
        title: `Environment variable ${env.name} carries an inline value`,
        description: `The running container sets ${env.name} with an inline value rather than a secretKeyRef, so the credential is readable by anyone who can get the pod spec. The value was not read and is not stored.`,
        severity: 'high',
        recommendation: 'Replace with valueFrom.secretKeyRef and rotate the credential.',
        detail: { container: container.name, variable: env.name, value: '[NOT READ]' },
      });
    }
  }

  return findings;
}

function assessLiveIngress(context: EngineContext, namespace: string, ingress: K8sObject): ReturnType<typeof buildFinding>[] {
  const findings: ReturnType<typeof buildFinding>[] = [];
  const name = ingress.metadata?.name ?? '(unnamed)';
  const tls = ingress.spec?.tls ?? [];
  const hosts: string[] = (ingress.spec?.rules ?? []).map((rule: any) => rule.host).filter(Boolean);
  const annotations = ingress.metadata?.annotations ?? {};

  if (tls.length === 0) {
    findings.push(
      buildFinding({
        scanId: context.scanId,
        engineId: 'k8s-live',
        mode: context.mode,
        layer: 'kubernetes',
        category: 'Kubernetes Ingress',
        subcategory: 'TLS',
        title: `Live ingress "${name}" terminates plaintext HTTP`,
        description: `Ingress ${namespace}/${name} is serving ${hosts.length ? hosts.join(', ') : 'a route'} with no TLS block, so the controller answers it over plaintext HTTP.`,
        severity: 'high',
        confidence: 'high',
        detection: 'observed',
        algorithm: 'TLS',
        canonicalAlgorithm: 'TLS',
        role: 'tls',
        quantumStatus: 'not-applicable',
        recommendation: 'Attach a kubernetes.io/tls secret and enable an HTTP-to-HTTPS redirect.',
        evidence: [
          buildEvidence({
            summary: `Live Ingress ${namespace}/${name} has no spec.tls${hosts.length ? ` (hosts ${hosts.join(', ')})` : ''}.`,
            scope: namespace,
            reference: `Ingress/${name}`,
            provider: 'kubernetes',
            ruleId: 'k8s-live-ingress-no-tls',
            attributes: { hosts: hosts.join(',') },
          }),
        ],
        identity: `k8s-live|ingress-no-tls|${namespace}/${name}`,
      }),
    );
  }

  for (const [key, value] of Object.entries(annotations)) {
    if (!/ssl-protocols$/.test(key) || !/tlsv1(\.[01])?\b/i.test(value)) continue;
    findings.push(
      buildFinding({
        scanId: context.scanId,
        engineId: 'k8s-live',
        mode: context.mode,
        layer: 'kubernetes',
        category: 'Kubernetes Ingress',
        subcategory: 'TLS policy',
        title: `Live ingress "${name}" offers a deprecated TLS version`,
        description: `The running ingress is annotated with ssl-protocols "${value}". TLS 1.0 and 1.1 are deprecated by RFC 8996 and cannot negotiate a hybrid post-quantum key-agreement group.`,
        severity: 'high',
        confidence: 'high',
        detection: 'observed',
        algorithm: 'TLS',
        canonicalAlgorithm: canonicalAlgorithmName('TLS'),
        role: 'tls',
        quantumStatus: 'vulnerable',
        quantumRationale: 'A TLS 1.2-or-lower-only endpoint cannot negotiate ML-KEM hybrid key agreement, so it has no path to post-quantum transport without a protocol upgrade.',
        recommendation: 'Restrict ssl-protocols to TLSv1.2 and TLSv1.3.',
        evidence: [
          buildEvidence({
            summary: `Annotation ${key}="${value}" on live Ingress ${namespace}/${name}.`,
            scope: namespace,
            reference: `Ingress/${name}`,
            provider: 'kubernetes',
            ruleId: 'k8s-live-ingress-legacy-tls',
          }),
        ],
        identity: `k8s-live|ingress-legacy-tls|${namespace}/${name}`,
      }),
    );
  }

  return findings;
}
