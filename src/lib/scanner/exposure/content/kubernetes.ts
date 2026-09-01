/**
 * Kubernetes Security Engine™ (Spec-2 §8, §10, §11, §12, §13, §14, §15, §16).
 *
 * Static analysis of Kubernetes manifests, Helm charts and Kustomize overlays,
 * covering four distinct concerns the specification separates:
 *
 *   WORKLOAD    privilege, host namespaces, capabilities, image provenance
 *   CRYPTO      Ingress TLS, TLS secrets, mTLS, service-mesh trust material
 *   RBAC        wildcard verbs, cluster-admin bindings, escalation paths
 *   NETWORK     workloads with no NetworkPolicy, permissive ingress/egress
 *
 * Two honesty rules run through all of it:
 *
 *  §12 "Never return secret values to the frontend."  A `kubernetes.io/tls`
 *      secret's `tls.key` is a private key in base64. This engine records that
 *      the field EXISTS and what algorithm the certificate half declares — it
 *      never decodes, stores or forwards the key half.
 *
 *  §15 "Do not only scan raw Helm templates."  A Helm template whose
 *      securityContext lives behind `{{- if .Values.securityContext }}` has NOT
 *      been shown to lack one. Findings on unrendered templates are therefore
 *      reported at reduced confidence with the templating stated, and the
 *      absence-of-control rules are suppressed entirely — an unrendered
 *      template can prove presence, never absence.
 */

import type { FindingConfidence, FindingSeverity } from '../types';
import type { EngineContext, EngineResult, ExposureEngine, WorkspaceFile } from '../engine-contract';
import { buildEvidence, buildFinding, completed } from '../engine-contract';
import { canonicalAlgorithmName, classifyQuantum } from '../algorithms';
import {
  documentApiVersion,
  documentKind,
  documentName,
  documentNamespace,
  isHelmTemplate,
  nodesByKey,
  nodesMatching,
  splitDocuments,
  valueAt,
  type YamlDocument,
  type YamlNode,
} from './mini-yaml';

/* ──────────────────────────────────────────────────────────────── vocabulary ── */

const WORKLOAD_KINDS = new Set(['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'ReplicaSet', 'ReplicationController']);
const RBAC_KINDS = new Set(['Role', 'ClusterRole', 'RoleBinding', 'ClusterRoleBinding']);

/** Capabilities whose grant is a container escape primitive. */
const DANGEROUS_CAPABILITIES = new Set([
  'SYS_ADMIN', 'SYS_PTRACE', 'SYS_MODULE', 'SYS_RAWIO', 'SYS_BOOT', 'SYS_TIME',
  'NET_ADMIN', 'NET_RAW', 'DAC_READ_SEARCH', 'DAC_OVERRIDE', 'SETUID', 'SETGID', 'ALL',
]);

const SENSITIVE_HOST_PATHS = ['/', '/etc', '/var/run/docker.sock', '/var/lib/kubelet', '/proc', '/sys', '/root', '/var/run/containerd'];

/* ────────────────────────────────────────────────────────────────── engine ── */

export const kubernetesEngine: ExposureEngine = {
  descriptor: {
    id: 'kubernetes-security',
    label: 'Kubernetes Security',
    description: 'Analyses Kubernetes manifests, Helm charts and Kustomize overlays for workload privilege, RBAC escalation, network exposure and TLS/certificate cryptography.',
    mode: 'local',
    layer: 'kubernetes',
    capability: 'kubernetes',
    dependsOn: ['file-discovery'],
    weight: 14,
  },

  appliesTo(context) {
    const has = context.workspace.files.some(
      (file) => file.content && (file.classification === 'kubernetes' || file.classification === 'helm'),
    );
    return has
      ? { applicable: true }
      : { applicable: false, reason: 'No Kubernetes manifests, Helm charts or Kustomize overlays were found in scope.' };
  },

  async execute(context: EngineContext): Promise<EngineResult> {
    const files = context.workspace.files.filter(
      (file) => file.content && !context.isExcluded(file.path) && (file.classification === 'kubernetes' || file.classification === 'helm'),
    );

    const findings: ReturnType<typeof buildFinding>[] = [];
    const namespaces = new Set<string>();
    const workloads = new Set<string>();
    const workloadsByNamespace = new Map<string, string[]>();
    const networkPolicyNamespaces = new Set<string>();
    let processed = 0;
    let templated = 0;

    for (const file of files) {
      if (context.isCancelled()) break;
      processed += 1;
      context.report(`Reading ${file.path}`, { done: processed, total: files.length, unit: 'manifests' });

      const content = file.content as string;
      const documents = splitDocuments(content);

      for (const document of documents) {
        const kind = documentKind(document);
        if (!kind) continue;
        const helmTemplated = isHelmTemplate(document.text);
        if (helmTemplated) templated += 1;

        const name = documentName(document) ?? '(unnamed)';
        const namespace = documentNamespace(document) ?? 'default';
        namespaces.add(namespace);

        if (WORKLOAD_KINDS.has(kind)) {
          workloads.add(`${namespace}/${kind}/${name}`);
          const list = workloadsByNamespace.get(namespace) ?? [];
          list.push(`${kind}/${name}`);
          workloadsByNamespace.set(namespace, list);
          findings.push(...analyseWorkload(context, file, document, kind, name, namespace, helmTemplated));
        }

        if (kind === 'Secret') {
          findings.push(...analyseSecret(context, file, document, name, namespace, helmTemplated));
        }

        if (kind === 'Ingress') {
          findings.push(...analyseIngress(context, file, document, name, namespace, helmTemplated));
        }

        if (RBAC_KINDS.has(kind)) {
          findings.push(...analyseRbac(context, file, document, kind, name, namespace, helmTemplated));
        }

        if (kind === 'NetworkPolicy') {
          networkPolicyNamespaces.add(namespace);
          findings.push(...analyseNetworkPolicy(context, file, document, name, namespace, helmTemplated));
        }

        if (kind === 'Service') {
          findings.push(...analyseService(context, file, document, name, namespace, helmTemplated));
        }

        if (document.degraded && document.degradedReason) {
          context.notAssessed(`${file.path} (${kind}/${name})`, document.degradedReason);
        }
      }
    }

    /* ── absence of NetworkPolicy, per namespace (Spec-2 §14) ───────────── */
    for (const [namespace, list] of workloadsByNamespace) {
      if (networkPolicyNamespaces.has(namespace)) continue;
      findings.push(
        buildFinding({
          scanId: context.scanId,
          engineId: 'kubernetes-security',
          mode: context.mode,
          layer: 'kubernetes',
          category: 'Kubernetes Network',
          subcategory: 'No NetworkPolicy',
          title: `Namespace "${namespace}" declares workloads but no NetworkPolicy`,
          description: `${list.length} workload${list.length === 1 ? '' : 's'} (${list.slice(0, 4).join(', ')}${list.length > 4 ? `, +${list.length - 4} more` : ''}) are declared in namespace "${namespace}", and no NetworkPolicy is declared alongside them in the scanned manifests. Kubernetes defaults to allow-all pod-to-pod traffic, so every one of these workloads is reachable from every other pod in the cluster. This is an observation about the MANIFESTS in scope — a policy applied out-of-band would not be visible here.`,
          severity: 'medium',
          confidence: 'medium',
          detection: 'observed',
          quantumStatus: 'not-applicable',
          recommendation: `Add a default-deny NetworkPolicy for namespace "${namespace}" and open only the flows each workload needs.`,
          evidence: [
            buildEvidence({
              summary: `No NetworkPolicy manifest found for namespace "${namespace}" among ${list.length} workload manifests.`,
              scope: namespace,
              ruleId: 'k8s-no-networkpolicy',
              localOnly: context.mode === 'local',
              attributes: { namespace, workloadCount: list.length },
            }),
          ],
          identity: `k8s|no-networkpolicy|${namespace}`,
        }),
      );
    }

    for (const finding of findings) context.emit(finding);

    if (templated > 0) {
      context.notAssessed(
        'Helm-rendered effective configuration',
        `${templated} manifest${templated === 1 ? ' is' : 's are'} Helm templates. Values behind Go templating cannot be evaluated statically, so absence-of-control rules were suppressed for them and presence findings are reported at reduced confidence. Render the chart (helm template) and re-scan the output for a definitive assessment.`,
      );
    }

    return completed(
      findings,
      {
        kubernetesNamespaces: namespaces.size,
        kubernetesWorkloads: workloads.size,
        notAssessed: templated
          ? [{ dimension: 'Helm-rendered effective configuration', reason: `${templated} manifests are unrendered Helm templates.`, engineId: 'kubernetes-security' }]
          : [],
      },
      { namespaces: [...namespaces], workloads: [...workloads], templatedManifests: templated },
    );
  },
};

/* ─────────────────────────────────────────────────────────────── workloads ── */

function analyseWorkload(
  context: EngineContext,
  file: WorkspaceFile,
  document: YamlDocument,
  kind: string,
  name: string,
  namespace: string,
  templated: boolean,
): ReturnType<typeof buildFinding>[] {
  const findings: ReturnType<typeof buildFinding>[] = [];
  const subject = `${kind}/${name} in ${namespace}`;
  const confidence: FindingConfidence = templated ? 'medium' : 'high';

  const add = (input: {
    id: string;
    subcategory: string;
    title: string;
    description: string;
    severity: FindingSeverity;
    recommendation: string;
    node?: YamlNode | null;
    /** Absence rules must not fire on an unrendered template. */
    absence?: boolean;
    /** Set when the matched node's value is itself credential material. */
    redactValue?: boolean;
  }) => {
    if (input.absence && templated) return;
    findings.push(
      buildFinding({
        scanId: context.scanId,
        engineId: 'kubernetes-security',
        mode: context.mode,
        layer: 'kubernetes',
        category: 'Kubernetes Workload',
        subcategory: input.subcategory,
        title: `${input.title} — ${subject}`,
        description: templated
          ? `${input.description} This manifest is an unrendered Helm template, so the effective value may differ once values are applied.`
          : input.description,
        severity: input.severity,
        confidence,
        detection: 'observed',
        quantumStatus: 'not-applicable',
        recommendation: input.recommendation,
        evidence: [
          buildEvidence({
            summary: `${input.title} in ${file.path}${input.node ? `:${input.node.line}` : ''}`,
            file: file.path,
            line: input.node?.line,
            /* `redactValue` exists because the shared snippet redactor keys off
               a secret-shaped IDENTIFIER, and a Kubernetes inline secret's key
               is the literal word `value` — the variable name that makes it
               sensitive lives on a sibling node. The rule that knows the value
               is a credential is the one that has to say so. */
            snippet: input.redactValue
              ? `${input.node?.key ?? 'value'}: [REDACTED]`
              : input.node?.value
                ? `${input.node.key}: ${input.node.value}`
                : undefined,
            scope: namespace,
            reference: subject,
            ruleId: input.id,
            localOnly: context.mode === 'local',
            attributes: { kind, name, namespace, helmTemplated: templated },
          }),
        ],
        identity: `${file.path}|${input.id}|${namespace}/${kind}/${name}`,
      }),
    );
  };

  /* ── host namespaces ────────────────────────────────────────────────── */
  for (const [key, label, severity] of [
    ['hostNetwork', 'Host network namespace shared', 'high'],
    ['hostPID', 'Host PID namespace shared', 'high'],
    ['hostIPC', 'Host IPC namespace shared', 'high'],
  ] as const) {
    const node = nodesByKey(document, key).find((entry) => entry.value === 'true');
    if (!node) continue;
    add({
      id: `k8s-${key.toLowerCase()}`,
      subcategory: 'Host namespace',
      title: label,
      description: `${key} is true, so the pod shares the node's ${key.replace('host', '').toLowerCase()} namespace. Isolation between the workload and the node is removed for that dimension.`,
      severity,
      recommendation: `Remove ${key}: true unless the workload is a node-level agent that genuinely requires it.`,
      node,
    });
  }

  /* ── privileged / escalation ────────────────────────────────────────── */
  const privileged = nodesByKey(document, 'privileged').find((entry) => entry.value === 'true');
  if (privileged) {
    add({
      id: 'k8s-privileged',
      subcategory: 'Privilege',
      title: 'Privileged container',
      description: 'A container runs privileged, which grants all capabilities and disables the seccomp, AppArmor and device restrictions that separate the container from the node.',
      severity: 'critical',
      recommendation: 'Remove `privileged: true` and grant only the specific capabilities required.',
      node: privileged,
    });
  }

  const escalation = nodesByKey(document, 'allowPrivilegeEscalation').find((entry) => entry.value === 'true');
  if (escalation) {
    add({
      id: 'k8s-privilege-escalation',
      subcategory: 'Privilege',
      title: 'Privilege escalation permitted',
      description: 'allowPrivilegeEscalation is true, so a process in the container can gain more privileges than its parent through setuid binaries or file capabilities.',
      severity: 'high',
      recommendation: 'Set allowPrivilegeEscalation: false in the container securityContext.',
      node: escalation,
    });
  }

  /* ── runs as root ───────────────────────────────────────────────────── */
  const runAsNonRoot = nodesByKey(document, 'runAsNonRoot');
  const runAsUser = nodesByKey(document, 'runAsUser');
  const rootUser = runAsUser.find((entry) => entry.value === '0');
  if (rootUser) {
    add({
      id: 'k8s-run-as-root',
      subcategory: 'Privilege',
      title: 'Container explicitly runs as uid 0',
      description: 'runAsUser is 0, so the container process runs as root inside the container. A container escape then starts from root.',
      severity: 'high',
      recommendation: 'Run as a non-zero uid and set runAsNonRoot: true.',
      node: rootUser,
    });
  } else if (runAsNonRoot.length === 0 && runAsUser.length === 0) {
    add({
      id: 'k8s-no-runasnonroot',
      subcategory: 'Privilege',
      title: 'No runAsNonRoot or runAsUser declared',
      description: 'Neither runAsNonRoot nor runAsUser is declared, so the container runs as whichever user the image specifies — which is root for most base images.',
      severity: 'medium',
      recommendation: 'Set runAsNonRoot: true and an explicit runAsUser in the pod securityContext.',
      absence: true,
    });
  }

  /* ── securityContext presence ───────────────────────────────────────── */
  if (nodesByKey(document, 'securityContext').length === 0) {
    add({
      id: 'k8s-no-securitycontext',
      subcategory: 'Hardening',
      title: 'No securityContext declared',
      description: 'The workload declares no securityContext at pod or container level, so every hardening default is inherited from the cluster\'s Pod Security admission configuration rather than stated by the workload.',
      severity: 'medium',
      recommendation: 'Declare a securityContext with runAsNonRoot, readOnlyRootFilesystem, allowPrivilegeEscalation: false and a dropped capability set.',
      absence: true,
    });
  }

  /* ── read-only root filesystem ──────────────────────────────────────── */
  const readOnlyRoot = nodesByKey(document, 'readOnlyRootFilesystem');
  if (readOnlyRoot.length > 0 && readOnlyRoot.every((entry) => entry.value === 'false')) {
    add({
      id: 'k8s-writable-root',
      subcategory: 'Hardening',
      title: 'Writable root filesystem',
      description: 'readOnlyRootFilesystem is false, so a compromised process can write to the container image filesystem and persist within the running container.',
      severity: 'low',
      recommendation: 'Set readOnlyRootFilesystem: true and mount an emptyDir for genuinely writable paths.',
      node: readOnlyRoot[0],
    });
  }

  /* ── capabilities ───────────────────────────────────────────────────── */
  for (const node of nodesMatching(document, '**capabilities.add[]')) {
    const capability = (node.value ?? '').toUpperCase().replace(/^CAP_/, '');
    if (!DANGEROUS_CAPABILITIES.has(capability)) continue;
    add({
      id: 'k8s-dangerous-capability',
      subcategory: 'Capabilities',
      title: `Dangerous capability ${capability} granted`,
      description: `The container is granted CAP_${capability}. ${capability === 'ALL' ? 'Granting ALL is equivalent to running privileged.' : 'This capability is a documented container-escape primitive.'}`,
      severity: capability === 'ALL' || capability === 'SYS_ADMIN' ? 'critical' : 'high',
      recommendation: `Remove ${capability} from capabilities.add and drop ALL by default.`,
      node,
    });
  }

  /* ── host path mounts ───────────────────────────────────────────────── */
  for (const node of nodesMatching(document, '**hostPath.path')) {
    const path = node.value ?? '';
    const sensitive = SENSITIVE_HOST_PATHS.some((candidate) => path === candidate || path.startsWith(`${candidate}/`));
    add({
      id: 'k8s-hostpath',
      subcategory: 'Volumes',
      title: `hostPath volume mounts ${path}`,
      description: sensitive
        ? `The pod mounts the sensitive host path ${path}. ${path === '/var/run/docker.sock' ? 'Mounting the container runtime socket grants control of every container on the node.' : 'This path exposes node state to the workload and is a common escape route.'}`
        : `The pod mounts the host path ${path}. hostPath volumes couple the workload to a specific node and bypass the storage isolation the cluster provides.`,
      severity: sensitive ? 'critical' : 'medium',
      recommendation: sensitive
        ? 'Remove the mount, or replace it with a purpose-built CSI driver that exposes only what the workload needs.'
        : 'Use a PersistentVolumeClaim or emptyDir instead of a hostPath.',
      node,
    });
  }

  /* ── image provenance (Spec-2 §10) ──────────────────────────────────── */
  for (const node of nodesMatching(document, '**containers[].image')) {
    const image = node.value ?? '';
    if (!image || image.includes('{{')) continue;
    if (image.includes('@sha256:')) continue;
    const tag = image.split(':')[1];
    add({
      id: 'k8s-image-not-digest-pinned',
      subcategory: 'Image provenance',
      title: `Image "${image}" is not pinned to a digest`,
      description: `The container image is referenced by ${tag && tag !== 'latest' ? `tag "${tag}"` : 'the mutable "latest" tag'}, which is a moving pointer. The image that runs cannot be proved to be the image that was assessed.`,
      severity: !tag || tag === 'latest' ? 'medium' : 'low',
      recommendation: 'Reference images by immutable digest and let a controller update the digest on promotion.',
      node,
    });
  }

  /* ── resource limits ────────────────────────────────────────────────── */
  if (nodesByKey(document, 'limits').length === 0) {
    add({
      id: 'k8s-no-resource-limits',
      subcategory: 'Resources',
      title: 'No resource limits declared',
      description: 'The workload declares no CPU or memory limits, so a single misbehaving pod can starve every other workload scheduled on the node.',
      severity: 'low',
      recommendation: 'Declare resources.limits for CPU and memory, and matching requests.',
      absence: true,
    });
  }

  /* ── sensitive environment variables ────────────────────────────────── */
  for (const node of nodesMatching(document, '**env[].name')) {
    const variable = (node.value ?? '').toUpperCase();
    if (!/(PASSWORD|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE_KEY|CREDENTIAL)/.test(variable)) continue;
    // A valueFrom.secretKeyRef sibling is the CORRECT pattern; only an inline
    // `value` is an exposure. The sibling lives at the same sequence index.
    const base = node.path.replace(/\.name$/, '');
    const inlineValue = document.nodes.find((entry) => entry.path === `${base}.value`);
    if (!inlineValue) continue;
    add({
      id: 'k8s-inline-secret-env',
      subcategory: 'Secrets',
      title: `Environment variable ${variable} carries an inline value`,
      description: `${variable} is set with an inline value rather than a secretKeyRef, so the credential is stored in the manifest and in the pod spec, readable by anyone with get access to the workload. The value has been redacted and is not stored.`,
      severity: 'high',
      recommendation: 'Replace the inline value with valueFrom.secretKeyRef, and rotate the credential.',
      node: inlineValue,
      redactValue: true,
    });
  }

  return findings;
}

/* ───────────────────────────────────────────────────────────────── secrets ── */

function analyseSecret(
  context: EngineContext,
  file: WorkspaceFile,
  document: YamlDocument,
  name: string,
  namespace: string,
  templated: boolean,
): ReturnType<typeof buildFinding>[] {
  const findings: ReturnType<typeof buildFinding>[] = [];
  const type = valueAt(document, 'type') ?? 'Opaque';
  const dataNodes = document.nodes.filter((node) => node.path.startsWith('data.') || node.path.startsWith('stringData.'));

  /* A committed Secret manifest with populated data is credential material in
     version control, whatever its type. The VALUES are never read. */
  const populated = dataNodes.filter((node) => node.value && node.value.length > 8 && !node.value.includes('{{'));
  if (populated.length > 0) {
    findings.push(
      buildFinding({
        scanId: context.scanId,
        engineId: 'kubernetes-security',
        mode: context.mode,
        layer: 'secret',
        category: 'Kubernetes Secret',
        subcategory: type,
        title: `Secret "${name}" carries ${populated.length} populated field${populated.length === 1 ? '' : 's'} in version control`,
        description: `A Kubernetes Secret of type ${type} is committed with populated ${dataNodes[0]?.path.startsWith('stringData') ? 'stringData' : 'data'} fields (${populated.map((node) => node.key).join(', ')}). Kubernetes Secrets are base64-encoded, not encrypted, so committing one publishes the credential. This engine records that the fields exist and never decodes, stores or transmits their values.`,
        severity: type === 'kubernetes.io/tls' ? 'critical' : 'high',
        confidence: templated ? 'medium' : 'high',
        detection: 'observed',
        quantumStatus: type === 'kubernetes.io/tls' ? 'unknown' : 'not-applicable',
        quantumRationale:
          type === 'kubernetes.io/tls'
            ? 'The certificate half determines the quantum exposure; it is assessed by the certificate engine where the material is separately in scope. The private half is never decoded here.'
            : undefined,
        recommendation: 'Remove the Secret from version control, rotate every value it carried, and adopt an external secret store (External Secrets Operator, Sealed Secrets, or a CSI secret driver).',
        evidence: [
          buildEvidence({
            summary: `Secret ${namespace}/${name} (${type}) with populated fields at ${file.path}:${document.startLine}`,
            file: file.path,
            line: populated[0]?.line ?? document.startLine,
            scope: namespace,
            reference: `Secret/${name}`,
            ruleId: 'k8s-committed-secret',
            localOnly: context.mode === 'local',
            attributes: {
              secretType: type,
              fields: populated.map((node) => node.key).join(','),
              material: '[REDACTED]',
            },
          }),
        ],
        identity: `${file.path}|k8s-secret|${namespace}/${name}`,
      }),
    );
  }

  return findings;
}

/* ───────────────────────────────────────────────────────────────── ingress ── */

function analyseIngress(
  context: EngineContext,
  file: WorkspaceFile,
  document: YamlDocument,
  name: string,
  namespace: string,
  templated: boolean,
): ReturnType<typeof buildFinding>[] {
  const findings: ReturnType<typeof buildFinding>[] = [];
  const tlsNodes = nodesMatching(document, 'spec.tls**');
  const hosts = nodesMatching(document, 'spec.rules[].host').map((node) => node.value).filter(Boolean) as string[];

  const add = (input: {
    id: string;
    title: string;
    description: string;
    severity: FindingSeverity;
    recommendation: string;
    node?: YamlNode | null;
    algorithm?: string;
    quantumStatus?: ReturnType<typeof classifyQuantum>;
  }) => {
    findings.push(
      buildFinding({
        scanId: context.scanId,
        engineId: 'kubernetes-security',
        mode: context.mode,
        layer: 'kubernetes',
        category: 'Kubernetes Ingress',
        subcategory: 'TLS',
        title: `${input.title} — Ingress/${name} in ${namespace}`,
        description: input.description,
        severity: input.severity,
        confidence: templated ? 'medium' : 'high',
        detection: 'observed',
        algorithm: input.algorithm,
        canonicalAlgorithm: input.algorithm ? canonicalAlgorithmName(input.algorithm) : undefined,
        role: 'tls',
        quantumStatus: input.quantumStatus?.status ?? 'not-applicable',
        quantumRationale: input.quantumStatus?.rationale,
        recommendation: input.recommendation,
        evidence: [
          buildEvidence({
            summary: `${input.title} at ${file.path}:${input.node?.line ?? document.startLine}`,
            file: file.path,
            line: input.node?.line ?? document.startLine,
            scope: namespace,
            reference: `Ingress/${name}${hosts.length ? ` (${hosts.join(', ')})` : ''}`,
            ruleId: input.id,
            localOnly: context.mode === 'local',
            attributes: { hosts: hosts.join(','), namespace },
          }),
        ],
        identity: `${file.path}|${input.id}|${namespace}/${name}`,
      }),
    );
  };

  if (tlsNodes.length === 0 && !templated) {
    add({
      id: 'k8s-ingress-no-tls',
      title: 'Ingress declares no TLS block',
      description: `Ingress "${name}" exposes ${hosts.length ? hosts.join(', ') : 'a route'} with no spec.tls block, so the ingress controller terminates plaintext HTTP for it. Everything the route carries — credentials, tokens, personal data — crosses the network unprotected.`,
      severity: 'high',
      recommendation: 'Add a spec.tls entry referencing a kubernetes.io/tls secret, and enable an HTTP-to-HTTPS redirect on the controller.',
    });
  }

  /* ── controller annotations that weaken TLS ─────────────────────────── */
  const annotations = document.nodes.filter((node) => node.path.startsWith('metadata.annotations.'));
  for (const annotation of annotations) {
    const key = annotation.path.replace('metadata.annotations.', '');
    const value = (annotation.value ?? '').toLowerCase();

    if (/ssl-redirect$/.test(key) && (value === 'false' || value === '"false"')) {
      add({
        id: 'k8s-ingress-no-redirect',
        title: 'HTTPS redirect disabled on the ingress',
        description: 'The controller annotation disables the HTTP-to-HTTPS redirect, so clients that arrive over plaintext stay on plaintext.',
        severity: 'medium',
        recommendation: 'Set the ssl-redirect annotation to true.',
        node: annotation,
      });
    }

    if (/ssl-protocols$/.test(key) && /tlsv1(\.[01])?\b/.test(value)) {
      add({
        id: 'k8s-ingress-legacy-tls',
        title: 'Ingress offers a deprecated TLS version',
        description: `The ingress controller is configured to offer ${value}. TLS 1.0 and 1.1 are deprecated by RFC 8996 and cannot negotiate a hybrid post-quantum group.`,
        severity: 'high',
        recommendation: 'Restrict ssl-protocols to TLSv1.2 and TLSv1.3.',
        node: annotation,
        algorithm: 'TLS',
        quantumStatus: classifyQuantum({ algorithm: 'TLS', role: 'tls' }),
      });
    }

    if (/ssl-ciphers$/.test(key) && /(rc4|3des|null|export|md5)/.test(value)) {
      add({
        id: 'k8s-ingress-weak-cipher',
        title: 'Ingress permits a weak cipher suite',
        description: `The ingress cipher list includes a legacy suite (${value.slice(0, 120)}).`,
        severity: 'high',
        recommendation: 'Restrict the cipher list to modern AEAD suites.',
        node: annotation,
        algorithm: 'TLS',
      });
    }

    if (/backend-protocol$/.test(key) && value.includes('http') && !value.includes('https')) {
      add({
        id: 'k8s-ingress-plaintext-backend',
        title: 'Ingress talks to its backend over plaintext',
        description: 'The backend-protocol annotation is HTTP, so traffic is re-encrypted at the edge but travels in the clear inside the cluster. Without mTLS this is unauthenticated east-west traffic.',
        severity: 'medium',
        recommendation: 'Use HTTPS to the backend, or enforce mTLS through a service mesh.',
        node: annotation,
        algorithm: 'TLS',
        quantumStatus: classifyQuantum({ algorithm: 'TLS', role: 'tls' }),
      });
    }

    if (/(cert-manager\.io\/(cluster-)?issuer)$/.test(key)) {
      add({
        id: 'k8s-ingress-cert-manager',
        title: 'Certificate issuance is automated through cert-manager',
        description: `The ingress delegates certificate issuance to cert-manager issuer "${annotation.value}". Automated issuance is the prerequisite for a fast post-quantum certificate rollover, because it removes the manual step from every renewal.`,
        severity: 'info',
        recommendation: 'Confirm the issuer profile can request ML-DSA certificates once the CA supports them.',
        node: annotation,
      });
    }
  }

  return findings;
}

/* ──────────────────────────────────────────────────────────────────── RBAC ── */

function analyseRbac(
  context: EngineContext,
  file: WorkspaceFile,
  document: YamlDocument,
  kind: string,
  name: string,
  namespace: string,
  templated: boolean,
): ReturnType<typeof buildFinding>[] {
  const findings: ReturnType<typeof buildFinding>[] = [];

  const add = (input: { id: string; title: string; description: string; severity: FindingSeverity; recommendation: string; node?: YamlNode | null }) => {
    findings.push(
      buildFinding({
        scanId: context.scanId,
        engineId: 'kubernetes-security',
        mode: context.mode,
        layer: 'kubernetes',
        category: 'Kubernetes RBAC',
        subcategory: kind,
        title: `${input.title} — ${kind}/${name}`,
        description: input.description,
        severity: input.severity,
        confidence: templated ? 'medium' : 'high',
        detection: 'observed',
        quantumStatus: 'not-applicable',
        recommendation: input.recommendation,
        evidence: [
          buildEvidence({
            summary: `${input.title} at ${file.path}:${input.node?.line ?? document.startLine}`,
            file: file.path,
            line: input.node?.line ?? document.startLine,
            scope: kind.startsWith('Cluster') ? 'cluster' : namespace,
            reference: `${kind}/${name}`,
            ruleId: input.id,
            localOnly: context.mode === 'local',
          }),
        ],
        identity: `${file.path}|${input.id}|${kind}/${name}`,
      }),
    );
  };

  if (kind === 'Role' || kind === 'ClusterRole') {
    const verbs = nodesMatching(document, 'rules[].verbs[]');
    const resources = nodesMatching(document, 'rules[].resources[]');
    const apiGroups = nodesMatching(document, 'rules[].apiGroups[]');

    const wildcardVerb = verbs.find((node) => node.value === '*');
    const wildcardResource = resources.find((node) => node.value === '*');
    const wildcardGroup = apiGroups.find((node) => node.value === '*');

    if (wildcardVerb && wildcardResource) {
      add({
        id: 'k8s-rbac-wildcard-all',
        title: 'Role grants every verb on every resource',
        description: `${kind} "${name}" grants verbs: ["*"] on resources: ["*"]${wildcardGroup ? ' across all API groups' : ''}. Any subject bound to it can do anything the API server permits${kind === 'ClusterRole' ? ', cluster-wide' : ' in its namespace'} — including reading every Secret and creating privileged pods.`,
        severity: kind === 'ClusterRole' ? 'critical' : 'high',
        recommendation: 'Enumerate the specific verbs and resources the subject needs. A wildcard grant cannot be reviewed.',
        node: wildcardVerb,
      });
    } else if (wildcardVerb) {
      add({
        id: 'k8s-rbac-wildcard-verb',
        title: 'Role grants wildcard verbs',
        description: `${kind} "${name}" grants verbs: ["*"], which includes delete, patch and escalate on the listed resources.`,
        severity: 'high',
        recommendation: 'List the verbs explicitly.',
        node: wildcardVerb,
      });
    }

    /* Secrets access is the RBAC finding that matters most for cryptography:
       it is the path from a workload identity to key material. */
    const secretRule = resources.find((node) => node.value === 'secrets');
    if (secretRule) {
      const ruleIndex = secretRule.path.match(/rules\[(\d+)\]/)?.[1];
      const ruleVerbs = verbs
        .filter((node) => node.path.startsWith(`rules[${ruleIndex}]`))
        .map((node) => node.value);
      const canRead = ruleVerbs.some((verb) => verb === '*' || verb === 'get' || verb === 'list' || verb === 'watch');
      if (canRead) {
        add({
          id: 'k8s-rbac-secrets-read',
          title: 'Role can read Secrets',
          description: `${kind} "${name}" grants ${ruleVerbs.join(', ')} on secrets. Any subject bound to this role can read TLS private keys, signing keys and service credentials${kind === 'ClusterRole' ? ' in every namespace' : ` in ${namespace}`}. This is the primary escalation path from a workload identity to cryptographic key material.`,
          severity: kind === 'ClusterRole' ? 'high' : 'medium',
          recommendation: 'Scope secret access with resourceNames to the exact secrets the workload needs, and prefer a CSI secret driver that never grants API-level read.',
          node: secretRule,
        });
      }
    }

    const escalate = verbs.find((node) => node.value === 'escalate' || node.value === 'bind' || node.value === 'impersonate');
    if (escalate) {
      add({
        id: 'k8s-rbac-escalate',
        title: `Role grants the "${escalate.value}" verb`,
        description: `${kind} "${name}" grants "${escalate.value}", which lets a subject grant itself permissions it does not currently hold. This is a privilege-escalation path regardless of how narrow the rest of the role is.`,
        severity: 'critical',
        recommendation: `Remove the "${escalate.value}" verb unless this role belongs to a controller that provably needs it.`,
        node: escalate,
      });
    }
  }

  if (kind === 'RoleBinding' || kind === 'ClusterRoleBinding') {
    const roleRef = valueAt(document, 'roleRef.name');
    const subjects = nodesMatching(document, 'subjects[].name');

    if (roleRef === 'cluster-admin') {
      const bound = subjects.map((node) => node.value).filter(Boolean).join(', ');
      add({
        id: 'k8s-rbac-cluster-admin',
        title: 'Binding grants cluster-admin',
        description: `${kind} "${name}" binds the built-in cluster-admin role to ${bound || 'an unnamed subject'}. cluster-admin is unrestricted access to the entire cluster, including every Secret in every namespace.`,
        severity: 'critical',
        recommendation: 'Replace cluster-admin with a purpose-built role that lists the exact permissions required.',
        node: nodeLine(document, 'roleRef.name'),
      });
    }

    const anonymous = subjects.find((node) => node.value === 'system:anonymous' || node.value === 'system:unauthenticated');
    if (anonymous) {
      add({
        id: 'k8s-rbac-anonymous',
        title: 'Binding grants access to unauthenticated subjects',
        description: `${kind} "${name}" binds a role to ${anonymous.value}, granting the permissions to callers who have not authenticated at all.`,
        severity: 'critical',
        recommendation: 'Remove the binding.',
        node: anonymous,
      });
    }

    const defaultServiceAccount = subjects.find((node) => node.value === 'default');
    if (defaultServiceAccount) {
      add({
        id: 'k8s-rbac-default-sa',
        title: 'Binding grants permissions to the default ServiceAccount',
        description: `${kind} "${name}" binds a role to the "default" ServiceAccount. Every pod in the namespace that does not name its own ServiceAccount inherits these permissions.`,
        severity: 'high',
        recommendation: 'Create a dedicated ServiceAccount per workload and bind the role to that instead.',
        node: defaultServiceAccount,
      });
    }
  }

  return findings;
}

function nodeLine(document: YamlDocument, path: string): YamlNode | null {
  return document.nodes.find((node) => node.path === path) ?? null;
}

/* ──────────────────────────────────────────────────────── network policy ─── */

function analyseNetworkPolicy(
  context: EngineContext,
  file: WorkspaceFile,
  document: YamlDocument,
  name: string,
  namespace: string,
  templated: boolean,
): ReturnType<typeof buildFinding>[] {
  const findings: ReturnType<typeof buildFinding>[] = [];

  // `from: [{}]` / `to: [{}]` — an empty peer selector allows everything.
  const emptyIngress = document.nodes.find((node) => /^spec\.ingress\[\d+\]$/.test(node.path) && node.value === '{}');
  const wideIngress = document.nodes.find((node) => node.path.match(/^spec\.ingress\[\d+\]\.from\[\d+\]$/) && (node.value === '{}' || node.value === null));

  if (emptyIngress || wideIngress) {
    findings.push(
      buildFinding({
        scanId: context.scanId,
        engineId: 'kubernetes-security',
        mode: context.mode,
        layer: 'kubernetes',
        category: 'Kubernetes Network',
        subcategory: 'Permissive policy',
        title: `NetworkPolicy "${name}" allows ingress from every source`,
        description: 'The policy declares an ingress rule with an empty peer selector, which allows traffic from every pod in every namespace. A policy that permits everything provides documentation, not isolation.',
        severity: 'medium',
        confidence: templated ? 'low' : 'medium',
        detection: 'observed',
        quantumStatus: 'not-applicable',
        recommendation: 'Name the specific podSelector or namespaceSelector each flow requires.',
        evidence: [
          buildEvidence({
            summary: `Empty ingress peer selector at ${file.path}:${(emptyIngress ?? wideIngress)!.line}`,
            file: file.path,
            line: (emptyIngress ?? wideIngress)!.line,
            scope: namespace,
            reference: `NetworkPolicy/${name}`,
            ruleId: 'k8s-permissive-networkpolicy',
            localOnly: context.mode === 'local',
          }),
        ],
        identity: `${file.path}|k8s-permissive-networkpolicy|${namespace}/${name}`,
      }),
    );
  }

  return findings;
}

/* ───────────────────────────────────────────────────────────────── service ── */

function analyseService(
  context: EngineContext,
  file: WorkspaceFile,
  document: YamlDocument,
  name: string,
  namespace: string,
  templated: boolean,
): ReturnType<typeof buildFinding>[] {
  const findings: ReturnType<typeof buildFinding>[] = [];
  const type = valueAt(document, 'spec.type');
  if (type !== 'LoadBalancer' && type !== 'NodePort') return findings;

  const ports = nodesMatching(document, 'spec.ports[].port').map((node) => Number(node.value)).filter((port) => Number.isFinite(port));
  const plaintextPorts = ports.filter((port) => [80, 8080, 8000, 3000, 5000, 9200, 5432, 3306, 6379, 27017, 9092].includes(port));

  findings.push(
    buildFinding({
      scanId: context.scanId,
      engineId: 'kubernetes-security',
      mode: context.mode,
      layer: 'kubernetes',
      category: 'Kubernetes Network',
      subcategory: 'Exposure',
      title: `Service "${name}" is exposed as ${type}`,
      description: plaintextPorts.length
        ? `Service "${name}" is a ${type} publishing port${plaintextPorts.length === 1 ? '' : 's'} ${plaintextPorts.join(', ')}, which are conventionally plaintext protocols. A ${type} service reaches outside the cluster, so any of these ports that genuinely carries plaintext is exposed without transport protection.`
        : `Service "${name}" is a ${type}, so it reaches outside the cluster. Confirm the exposure is intended and that the published ports terminate TLS.`,
      severity: plaintextPorts.length ? 'medium' : 'low',
      confidence: templated ? 'low' : 'medium',
      detection: 'observed',
      algorithm: 'TLS',
      canonicalAlgorithm: 'TLS',
      role: 'tls',
      quantumStatus: 'not-applicable',
      quantumRationale: 'The quantum exposure of this route depends on the key agreement the terminating endpoint negotiates, which is not visible in the manifest.',
      recommendation: plaintextPorts.length
        ? 'Terminate TLS at an Ingress or gateway rather than publishing the plaintext port directly, and restrict the load-balancer source ranges.'
        : 'Restrict loadBalancerSourceRanges to the networks that require access.',
      evidence: [
        buildEvidence({
          summary: `Service ${namespace}/${name} type ${type}${ports.length ? `, ports ${ports.join(', ')}` : ''}`,
          file: file.path,
          line: document.startLine,
          scope: namespace,
          reference: `Service/${name}`,
          ruleId: 'k8s-exposed-service',
          localOnly: context.mode === 'local',
          attributes: { type, ports: ports.join(',') },
        }),
      ],
      identity: `${file.path}|k8s-exposed-service|${namespace}/${name}`,
    }),
  );

  return findings;
}
