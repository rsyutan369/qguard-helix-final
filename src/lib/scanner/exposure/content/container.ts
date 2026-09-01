/**
 * Container Security Engine™ (Spec-2 §4, §5, §6).
 *
 * Reads Dockerfiles, Containerfiles and Compose files as INSTRUCTION STREAMS
 * rather than as text, because almost every meaningful container finding is
 * about the relationship between instructions: a `USER` that never appears, a
 * `COPY` of a key followed by a `RUN rm` that does not actually remove it from
 * the layer, an `ADD` of a remote URL over plaintext.
 *
 * It also does the job Spec-2 §5 asks for explicitly: correlate the base image
 * and installed packages with the application's cryptography, so
 * `FROM ubuntu → apt-get install openssl` becomes a crypto dependency in the
 * CBOM rather than a line of shell.
 */

import type { FindingSeverity } from '../types';
import type { EngineContext, EngineResult, ExposureEngine, WorkspaceFile } from '../engine-contract';
import { buildEvidence, buildFinding, completed } from '../engine-contract';
import { canonicalAlgorithmName, classifyQuantum } from '../algorithms';

/* ──────────────────────────────────────────────────────── instruction model ── */

export interface DockerInstruction {
  instruction: string;
  args: string;
  line: number;
  /** Build stage this instruction belongs to (`FROM … AS build`). */
  stage: string | null;
}

/** Parse a Dockerfile into instructions, joining line continuations. */
export function parseDockerfile(content: string): DockerInstruction[] {
  const out: DockerInstruction[] = [];
  const lines = content.split('\n');
  let stage: string | null = null;
  let index = 0;

  while (index < lines.length) {
    let raw = lines[index];
    const startLine = index + 1;
    index += 1;
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Join continuations.
    while (raw.trimEnd().endsWith('\\') && index < lines.length) {
      raw = `${raw.trimEnd().slice(0, -1)} ${lines[index]}`;
      index += 1;
    }

    const match = raw.trim().match(/^([A-Za-z]+)\s+([\s\S]*)$/);
    if (!match) continue;
    const instruction = match[1].toUpperCase();
    const args = match[2].trim();

    if (instruction === 'FROM') {
      const asMatch = args.match(/\s+AS\s+(\S+)\s*$/i);
      stage = asMatch ? asMatch[1] : null;
    }

    out.push({ instruction, args, line: startLine, stage });
  }

  return out;
}

/* ──────────────────────────────────────────────────── crypto package table ── */

/** OS packages that bring cryptography into the image. */
const CRYPTO_PACKAGES: Record<string, { algorithms: string[]; library: string; note: string }> = {
  openssl: { algorithms: ['RSA', 'ECDSA', 'AES', 'TLS'], library: 'OpenSSL', note: 'OpenSSL provides the image\'s TLS and general cryptography.' },
  'libssl-dev': { algorithms: ['RSA', 'ECDSA', 'TLS'], library: 'OpenSSL', note: 'OpenSSL development headers.' },
  'libssl1.1': { algorithms: ['RSA', 'ECDSA', 'TLS'], library: 'OpenSSL 1.1', note: 'OpenSSL 1.1 is out of support and has no post-quantum key agreement.' },
  libgcrypt: { algorithms: ['RSA', 'AES', 'SHA-2'], library: 'libgcrypt', note: 'GnuPG cryptography library.' },
  gnutls: { algorithms: ['RSA', 'ECDSA', 'TLS'], library: 'GnuTLS', note: 'Alternative TLS stack.' },
  'ca-certificates': { algorithms: ['TLS'], library: 'CA bundle', note: 'Trust anchors for TLS verification.' },
  gnupg: { algorithms: ['RSA', 'AES'], library: 'GnuPG', note: 'OpenPGP implementation.' },
  'openssh-client': { algorithms: ['RSA', 'Ed25519', 'Diffie-Hellman'], library: 'OpenSSH', note: 'SSH client cryptography.' },
  'openssh-server': { algorithms: ['RSA', 'Ed25519', 'Diffie-Hellman'], library: 'OpenSSH', note: 'SSH host keys are generated in the image or at first boot.' },
  nss: { algorithms: ['RSA', 'ECDSA', 'TLS'], library: 'NSS', note: 'Network Security Services.' },
  liboqs: { algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA'], library: 'liboqs', note: 'Open Quantum Safe library — post-quantum primitives are available in this image.' },
};

/** Base images with a known cryptographic posture worth stating. */
const BASE_IMAGE_NOTES: Array<{ match: RegExp; note: string; severity: FindingSeverity }> = [
  { match: /^scratch$/i, note: 'A scratch base has no TLS trust store; the application must embed its own CA bundle.', severity: 'info' },
  { match: /^(alpine|.*\/alpine)(:|$)/i, note: 'Alpine links against musl and typically ships LibreSSL/OpenSSL via apk — confirm which TLS stack the runtime actually uses.', severity: 'info' },
  { match: /^(distroless|gcr\.io\/distroless)/i, note: 'Distroless images ship a CA bundle but no shell, which is a good hardening posture.', severity: 'info' },
];

/* ────────────────────────────────────────────────────────────── the engine ── */

export const containerEngine: ExposureEngine = {
  descriptor: {
    id: 'container-security',
    label: 'Container Security',
    description: 'Analyses Dockerfiles and Compose files for privilege, secret, base-image and cryptographic-library exposure, and links installed crypto packages into the CBOM.',
    mode: 'local',
    layer: 'container',
    capability: 'container',
    dependsOn: ['file-discovery'],
    weight: 10,
  },

  appliesTo(context) {
    return context.workspace.files.some((file) => file.content && file.classification === 'container')
      ? { applicable: true }
      : { applicable: false, reason: 'No Dockerfile, Containerfile or Compose file was found in scope.' };
  },

  async execute(context: EngineContext): Promise<EngineResult> {
    const files = context.workspace.files.filter(
      (file) => file.content && !context.isExcluded(file.path) && file.classification === 'container',
    );

    const findings: ReturnType<typeof buildFinding>[] = [];
    const images = new Set<string>();
    let processed = 0;

    for (const file of files) {
      if (context.isCancelled()) break;
      processed += 1;
      context.report(`Analysing ${file.path}`, { done: processed, total: files.length, unit: 'files' });

      const isCompose = file.basename.startsWith('docker-compose') || file.basename.startsWith('compose');
      if (isCompose) {
        findings.push(...analyseCompose(context, file, images));
        continue;
      }

      const instructions = parseDockerfile(file.content as string);
      findings.push(...analyseDockerfile(context, file, instructions, images));
    }

    for (const finding of findings) context.emit(finding);

    return completed(findings, { containers: files.length, images: images.size }, { images: [...images] });
  },
};

/* ─────────────────────────────────────────────────────── Dockerfile rules ── */

function analyseDockerfile(
  context: EngineContext,
  file: WorkspaceFile,
  instructions: DockerInstruction[],
  images: Set<string>,
): ReturnType<typeof buildFinding>[] {
  const findings: ReturnType<typeof buildFinding>[] = [];
  const add = (input: Omit<Parameters<typeof buildFinding>[0], 'scanId' | 'engineId' | 'mode' | 'layer'>) => {
    findings.push(
      buildFinding({
        ...input,
        scanId: context.scanId,
        engineId: 'container-security',
        mode: context.mode,
        layer: 'container',
      }),
    );
  };

  const froms = instructions.filter((entry) => entry.instruction === 'FROM');
  const finalStage = froms[froms.length - 1];
  const users = instructions.filter((entry) => entry.instruction === 'USER');
  const runs = instructions.filter((entry) => entry.instruction === 'RUN');
  const copies = instructions.filter((entry) => entry.instruction === 'COPY' || entry.instruction === 'ADD');
  const envs = instructions.filter((entry) => entry.instruction === 'ENV' || entry.instruction === 'ARG');

  /* ── base image ─────────────────────────────────────────────────────── */
  for (const from of froms) {
    const image = from.args.replace(/\s+AS\s+\S+\s*$/i, '').trim();
    images.add(image);
    const pinnedByDigest = image.includes('@sha256:');
    const tag = image.split('@')[0].split(':')[1];

    if (!pinnedByDigest && (!tag || tag === 'latest')) {
      add({
        category: 'Container Configuration',
        subcategory: 'Unpinned base image',
        title: `Base image "${image}" is not pinned`,
        description:
          'The base image is referenced by a mutable tag rather than an immutable digest, so the image that is built tomorrow may not be the image that was assessed today. Spec §6 requires evidence to be anchored to a digest wherever one is available.',
        severity: tag === 'latest' || !tag ? 'medium' : 'low',
        confidence: 'high',
        detection: 'observed',
        quantumStatus: 'not-applicable',
        recommendation: `Pin the base image by digest: FROM ${image.split(':')[0]}@sha256:<digest>.`,
        evidence: [
          buildEvidence({
            summary: `FROM ${image} at ${file.path}:${from.line}`,
            file: file.path,
            line: from.line,
            snippet: `FROM ${from.args}`,
            ruleId: 'container-unpinned-base',
            localOnly: context.mode === 'local',
          }),
        ],
        identity: `${file.path}|unpinned-base|${image}`,
      });
    }

    for (const note of BASE_IMAGE_NOTES) {
      if (!note.match.test(image)) continue;
      add({
        category: 'Container Configuration',
        subcategory: 'Base image posture',
        title: `Base image "${image}" — cryptographic posture`,
        description: note.note,
        severity: note.severity,
        confidence: 'high',
        detection: 'observed',
        quantumStatus: 'not-applicable',
        evidence: [
          buildEvidence({
            summary: `FROM ${image} at ${file.path}:${from.line}`,
            file: file.path,
            line: from.line,
            ruleId: 'container-base-posture',
            localOnly: context.mode === 'local',
          }),
        ],
        identity: `${file.path}|base-posture|${image}`,
      });
    }
  }

  /* ── runs as root ───────────────────────────────────────────────────── */
  const finalUser = users.filter((entry) => !finalStage || entry.line > finalStage.line).pop();
  if (!finalUser || /^(root|0)(\s|:|$)/.test(finalUser.args)) {
    add({
      category: 'Container Configuration',
      subcategory: 'Privilege',
      title: `Container runs as root — ${file.path}`,
      description: finalUser
        ? 'The final build stage explicitly sets USER root, so every process in the container runs with uid 0.'
        : 'No USER instruction appears in the final build stage, so the container runs as root by default. A compromised process then has full control of the container filesystem, including any mounted key material.',
      severity: 'high',
      confidence: 'high',
      detection: 'observed',
      quantumStatus: 'not-applicable',
      recommendation: 'Create an unprivileged user and add `USER <uid>` as the last instruction of the final stage.',
      evidence: [
        buildEvidence({
          summary: finalUser ? `USER ${finalUser.args} at ${file.path}:${finalUser.line}` : `No USER instruction in ${file.path}`,
          file: file.path,
          line: finalUser?.line,
          ruleId: 'container-runs-as-root',
          localOnly: context.mode === 'local',
        }),
      ],
      identity: `${file.path}|runs-as-root`,
    });
  }

  /* ── secrets in build args and env ──────────────────────────────────── */
  for (const env of envs) {
    const match = env.args.match(/\b([A-Za-z0-9_]*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)[A-Za-z0-9_]*)\s*=\s*(\S+)/i);
    if (!match) continue;
    const value = match[2].replace(/^["']|["']$/g, '');
    if (!value || value.startsWith('$') || value.length < 8) continue;
    add({
      category: 'Container Configuration',
      subcategory: 'Secret in image',
      title: `${env.instruction} ${match[1]} carries a value into the image layer`,
      description: `${env.instruction} values are baked into the image and are readable by anyone who can pull it, including through \`docker history\`. The value has been redacted and is not stored.`,
      severity: env.instruction === 'ENV' ? 'critical' : 'high',
      confidence: 'medium',
      detection: 'observed',
      quantumStatus: 'not-applicable',
      recommendation: 'Use BuildKit secret mounts (`RUN --mount=type=secret`) or inject the value at runtime from a secret manager.',
      evidence: [
        buildEvidence({
          summary: `${env.instruction} ${match[1]} at ${file.path}:${env.line}. Value redacted.`,
          file: file.path,
          line: env.line,
          snippet: `${env.instruction} ${match[1]}=[REDACTED]`,
          ruleId: 'container-secret-in-layer',
          localOnly: context.mode === 'local',
        }),
      ],
      identity: `${file.path}|secret-env|${match[1]}`,
    });
  }

  /* ── key material copied in ─────────────────────────────────────────── */
  for (const copy of copies) {
    if (/\.(pem|key|p12|pfx|jks|keystore|crt)\b/i.test(copy.args) && !/--from=/.test(copy.args)) {
      const isCertOnly = /\.(crt|cer|pem)\b/i.test(copy.args) && !/\.(key|p12|pfx|jks|keystore)\b/i.test(copy.args);
      add({
        category: 'Container Configuration',
        subcategory: 'Key material in image',
        title: `${copy.instruction} places key or certificate material in the image`,
        description: isCertOnly
          ? 'Certificate material is copied into the image. Public certificates are not secret, but baking them in makes rotation a rebuild.'
          : 'Private key or keystore material is copied into an image layer. Layers are immutable — a later RUN that deletes the file does not remove it from the layer it was added in, and anyone who can pull the image can recover it.',
        severity: isCertOnly ? 'low' : 'critical',
        confidence: 'medium',
        detection: 'observed',
        quantumStatus: 'unknown',
        quantumRationale: 'The key material\'s algorithm determines its quantum exposure; the certificate engine reports it where the file is in scope.',
        recommendation: isCertOnly
          ? 'Mount trust material at runtime so it can be rotated without a rebuild.'
          : 'Mount private key material at runtime from a secret store or a CSI driver; never add it to a layer.',
        evidence: [
          buildEvidence({
            summary: `${copy.instruction} ${copy.args} at ${file.path}:${copy.line}`,
            file: file.path,
            line: copy.line,
            snippet: `${copy.instruction} ${copy.args}`,
            ruleId: 'container-key-in-layer',
            localOnly: context.mode === 'local',
          }),
        ],
        identity: `${file.path}|key-in-layer|${copy.line}`,
      });
    }

    if (copy.instruction === 'ADD' && /^https?:\/\//i.test(copy.args)) {
      const plaintext = /^http:\/\//i.test(copy.args);
      add({
        category: 'Container Configuration',
        subcategory: 'Remote fetch',
        title: `ADD downloads from a remote URL${plaintext ? ' over plaintext HTTP' : ''}`,
        description: plaintext
          ? 'ADD fetches a remote artefact over plaintext HTTP during the build, so the build is trivially tamperable by anyone on the network path.'
          : 'ADD fetches a remote artefact during the build. The content is not verified against a checksum, so the build depends on the remote host remaining honest and available.',
        severity: plaintext ? 'high' : 'medium',
        confidence: 'high',
        detection: 'observed',
        algorithm: 'TLS',
        canonicalAlgorithm: 'TLS',
        role: 'tls',
        quantumStatus: 'not-applicable',
        recommendation: 'Use HTTPS, verify a pinned checksum after download, and prefer a vendored or registry-hosted artefact.',
        evidence: [
          buildEvidence({
            summary: `ADD ${copy.args} at ${file.path}:${copy.line}`,
            file: file.path,
            line: copy.line,
            snippet: `ADD ${copy.args}`,
            ruleId: 'container-remote-add',
            localOnly: context.mode === 'local',
          }),
        ],
        identity: `${file.path}|remote-add|${copy.line}`,
      });
    }
  }

  /* ── insecure package installation ──────────────────────────────────── */
  for (const run of runs) {
    if (/(--allow-unauthenticated|--force-yes|--no-check-certificate|--insecure\b|-k\s+https|GPGCHECK=0|gpgcheck\s*=\s*0|--trusted-host|--allow-untrusted)/i.test(run.args)) {
      add({
        category: 'Container Configuration',
        subcategory: 'Unverified package install',
        title: 'Package installation bypasses signature or TLS verification',
        description: 'A RUN instruction disables package signature checking or TLS verification during installation, which removes the supply-chain integrity control the package manager exists to provide.',
        severity: 'high',
        confidence: 'high',
        detection: 'observed',
        role: 'integrity',
        quantumStatus: 'not-applicable',
        recommendation: 'Remove the bypass flag and import the correct signing key or CA certificate instead.',
        evidence: [
          buildEvidence({
            summary: `Unverified install at ${file.path}:${run.line}`,
            file: file.path,
            line: run.line,
            snippet: `RUN ${run.args}`,
            ruleId: 'container-unverified-install',
            localOnly: context.mode === 'local',
          }),
        ],
        identity: `${file.path}|unverified-install|${run.line}`,
      });
    }

    if (/curl\s[^|]*\|\s*(sudo\s+)?(ba)?sh/i.test(run.args) || /wget\s[^|]*\|\s*(sudo\s+)?(ba)?sh/i.test(run.args)) {
      add({
        category: 'Container Configuration',
        subcategory: 'Pipe to shell',
        title: 'Build pipes a downloaded script directly into a shell',
        description: 'The build downloads a script and executes it without verification. Whatever the remote host serves at build time becomes part of the image.',
        severity: 'high',
        confidence: 'high',
        detection: 'observed',
        quantumStatus: 'not-applicable',
        recommendation: 'Download to a file, verify a pinned checksum or signature, then execute.',
        evidence: [
          buildEvidence({
            summary: `Pipe-to-shell at ${file.path}:${run.line}`,
            file: file.path,
            line: run.line,
            snippet: `RUN ${run.args}`,
            ruleId: 'container-pipe-to-shell',
            localOnly: context.mode === 'local',
          }),
        ],
        identity: `${file.path}|pipe-to-shell|${run.line}`,
      });
    }

    /* ── crypto packages → CBOM ─────────────────────────────────────── */
    for (const [packageName, entry] of Object.entries(CRYPTO_PACKAGES)) {
      const pattern = new RegExp(`(?:^|[\\s'"])${packageName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?=[\\s'"=]|$)`, 'i');
      if (!pattern.test(run.args)) continue;
      if (!/\b(apt-get|apt|apk|yum|dnf|microdnf|zypper|pacman)\b/i.test(run.args)) continue;

      for (const algorithm of entry.algorithms) {
        const quantum = classifyQuantum({ algorithm, role: 'tls' });
        if (quantum.status !== 'vulnerable' && quantum.status !== 'pqc') continue;
        add({
          category: 'Container Cryptography',
          subcategory: entry.library,
          title: `${entry.library} in the image brings ${canonicalAlgorithmName(algorithm)}`,
          description: `${entry.note} ${quantum.rationale} This is inferred from the package installation, not from an observed call site.`,
          severity: quantum.status === 'vulnerable' ? 'medium' : 'info',
          confidence: 'medium',
          detection: 'inferred',
          algorithm,
          canonicalAlgorithm: canonicalAlgorithmName(algorithm),
          library: entry.library,
          component: packageName,
          role: 'tls',
          quantumStatus: quantum.status,
          quantumRationale: quantum.rationale,
          recommendation: quantum.migrationTarget ? `Track ${entry.library} for ${quantum.migrationTarget} support.` : undefined,
          evidence: [
            buildEvidence({
              summary: `${packageName} installed at ${file.path}:${run.line}`,
              file: file.path,
              line: run.line,
              snippet: `RUN ${run.args}`,
              ruleId: `container-crypto-package:${packageName}`,
              localOnly: context.mode === 'local',
            }),
          ],
          identity: `${file.path}|crypto-package|${packageName}|${algorithm}`,
        });
      }
    }
  }

  /* ── health check ───────────────────────────────────────────────────── */
  if (!instructions.some((entry) => entry.instruction === 'HEALTHCHECK')) {
    add({
      category: 'Container Configuration',
      subcategory: 'Observability',
      title: `No HEALTHCHECK declared — ${file.path}`,
      description: 'The image declares no health check, so an orchestrator cannot distinguish a running container from a working one without an externally configured probe.',
      severity: 'low',
      confidence: 'high',
      detection: 'observed',
      quantumStatus: 'not-applicable',
      recommendation: 'Add a HEALTHCHECK, or declare readiness and liveness probes in the Kubernetes manifest.',
      evidence: [
        buildEvidence({
          summary: `No HEALTHCHECK instruction in ${file.path}`,
          file: file.path,
          ruleId: 'container-no-healthcheck',
          localOnly: context.mode === 'local',
        }),
      ],
      identity: `${file.path}|no-healthcheck`,
    });
  }

  return findings;
}

/* ────────────────────────────────────────────────────────── Compose rules ── */

function analyseCompose(context: EngineContext, file: WorkspaceFile, images: Set<string>): ReturnType<typeof buildFinding>[] {
  const findings: ReturnType<typeof buildFinding>[] = [];
  const content = file.content as string;
  const lines = content.split('\n');

  const add = (
    input: Omit<Parameters<typeof buildFinding>[0], 'scanId' | 'engineId' | 'mode' | 'layer'>,
  ) => {
    findings.push(
      buildFinding({ ...input, scanId: context.scanId, engineId: 'container-security', mode: context.mode, layer: 'container' }),
    );
  };

  const rules: Array<{ id: string; pattern: RegExp; title: string; description: string; severity: FindingSeverity; recommendation: string }> = [
    {
      id: 'compose-privileged',
      pattern: /^\s*privileged\s*:\s*true\b/,
      title: 'Service runs privileged',
      description: 'A Compose service declares `privileged: true`, which disables container isolation entirely — the process has effectively the same access as root on the host.',
      severity: 'critical',
      recommendation: 'Remove `privileged` and grant only the specific capabilities the workload needs.',
    },
    {
      id: 'compose-host-network',
      pattern: /^\s*network_mode\s*:\s*["']?host["']?\b/,
      title: 'Service uses host networking',
      description: 'The service shares the host network namespace, so it can bind host ports directly and network policy cannot isolate it.',
      severity: 'high',
      recommendation: 'Use a bridge or user-defined network and publish only the ports required.',
    },
    {
      id: 'compose-docker-socket',
      pattern: /\/var\/run\/docker\.sock/,
      title: 'Docker socket mounted into a container',
      description: 'Mounting the Docker socket grants the container full control of the Docker daemon, which is equivalent to root on the host.',
      severity: 'critical',
      recommendation: 'Remove the mount, or place a tightly scoped socket proxy in front of it.',
    },
    {
      id: 'compose-root-mount',
      pattern: /^\s*-\s*["']?\/(?::|\s|$)/,
      title: 'Host root filesystem mounted',
      description: 'The host root filesystem is mounted into the container.',
      severity: 'critical',
      recommendation: 'Mount only the specific paths the workload requires, read-only where possible.',
    },
    {
      id: 'compose-latest-tag',
      pattern: /^\s*image\s*:\s*\S+:latest\s*$/,
      title: 'Service pinned to the `latest` tag',
      description: 'The service references a mutable `latest` tag, so what runs in production is not what was assessed.',
      severity: 'medium',
      recommendation: 'Pin the image by digest.',
    },
  ];

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line || /^\s*#/.test(line)) continue;

    const imageMatch = line.match(/^\s*image\s*:\s*["']?([^\s"']+)/);
    if (imageMatch) images.add(imageMatch[1]);

    for (const rule of rules) {
      if (!rule.pattern.test(line)) continue;
      add({
        category: 'Container Configuration',
        subcategory: 'Compose',
        title: `${rule.title} — ${file.path}`,
        description: rule.description,
        severity: rule.severity,
        confidence: 'high',
        detection: 'observed',
        quantumStatus: 'not-applicable',
        recommendation: rule.recommendation,
        evidence: [
          buildEvidence({
            summary: `${rule.title} at ${file.path}:${index + 1}`,
            file: file.path,
            line: index + 1,
            snippet: line,
            ruleId: rule.id,
            localOnly: context.mode === 'local',
          }),
        ],
        identity: `${file.path}|${rule.id}|${index}`,
      });
    }
  }

  return findings;
}
