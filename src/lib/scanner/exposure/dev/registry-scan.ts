/**
 * Container Registry Engine (Spec-2 §6, §7).
 *
 * Reads OCI / Docker Registry v2 image manifests and config blobs, read-only,
 * to establish what an image ACTUALLY contains — as opposed to what its
 * Dockerfile said it would.
 *
 * §6: "Always prefer immutable image digests over tags when establishing
 *      evidence."  Every finding here is anchored to the manifest digest the
 *      registry returned, not to the tag that was requested, so re-running the
 *      assessment against a moved tag produces a different, comparable record
 *      rather than silently the same one.
 *
 * §7: "The scanner must use read-only access whenever possible. Never require
 *      registry write permissions for scanning."  Only GET is issued. Anonymous
 *      pull works for public images; a credential only widens what is visible.
 *
 * What this engine reads: the manifest (or manifest list), the CONFIG blob —
 * which carries the entrypoint, user, env, exposed ports and the full history
 * of build instructions — and the layer descriptors. It does NOT download layer
 * blobs: a base image is hundreds of megabytes and the config alone answers
 * every question in §6.
 */

import type { FindingSeverity } from '../types';
import type { EngineContext, EngineResult, ExposureEngine } from '../engine-contract';
import { buildEvidence, buildFinding, completed, notAssessed } from '../engine-contract';
import { canonicalAlgorithmName, classifyQuantum } from '../algorithms';

const TIMEOUT_MS = 15_000;
const MANIFEST_ACCEPT = [
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.docker.distribution.manifest.v2+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
].join(', ');

/* ────────────────────────────────────────────────────────── image reference ── */

export interface ImageRef {
  registry: string;
  repository: string;
  tag: string | null;
  digest: string | null;
  original: string;
}

/**
 * Parse a container image reference.
 *
 * The subtlety is deciding whether the first path segment is a registry host or
 * a Docker Hub namespace: `myorg/app` is Docker Hub, `ghcr.io/myorg/app` is not.
 * The rule Docker itself uses is that the first segment is a registry only when
 * it contains a dot or a colon, or is exactly `localhost`.
 */
export function parseImageRef(input: string): ImageRef | null {
  const raw = input.trim();
  if (!raw) return null;

  let remainder = raw;
  let digest: string | null = null;
  let tag: string | null = null;

  const atIndex = remainder.lastIndexOf('@');
  if (atIndex > 0) {
    digest = remainder.slice(atIndex + 1);
    remainder = remainder.slice(0, atIndex);
    if (!/^sha256:[0-9a-f]{64}$/.test(digest)) return null;
  }

  const lastColon = remainder.lastIndexOf(':');
  const lastSlash = remainder.lastIndexOf('/');
  if (lastColon > lastSlash) {
    tag = remainder.slice(lastColon + 1);
    remainder = remainder.slice(0, lastColon);
  }

  const segments = remainder.split('/');
  const first = segments[0];
  const hasRegistry = segments.length > 1 && (first.includes('.') || first.includes(':') || first === 'localhost');

  const registry = hasRegistry ? first : 'registry-1.docker.io';
  let repository = hasRegistry ? segments.slice(1).join('/') : remainder;
  // Docker Hub official images live under `library/`.
  if (!hasRegistry && !repository.includes('/')) repository = `library/${repository}`;

  if (!repository) return null;
  return { registry, repository, tag: digest ? null : (tag ?? 'latest'), digest, original: raw };
}

/* ───────────────────────────────────────────────────────────────── client ── */

interface RegistryAuth {
  username?: string;
  password?: string;
  /** A pre-obtained bearer token, when the operator supplied one. */
  token?: string;
}

interface RegistryResult<T> {
  ok: boolean;
  status: number;
  data: T | null;
  digest?: string;
  reason?: string;
  denied?: boolean;
}

const tokenCache = new Map<string, { token: string; expiresAt: number }>();

/**
 * Obtain a pull token when the registry challenges with `WWW-Authenticate`.
 *
 * This is the Docker Registry v2 token flow. It is implemented here because the
 * `scope` in the challenge is what limits the token to `pull` on one
 * repository — using a static credential would grant whatever the credential
 * itself carries, which may include push.
 */
async function resolveToken(challenge: string, auth: RegistryAuth): Promise<string | null> {
  const realm = challenge.match(/realm="([^"]+)"/)?.[1];
  if (!realm) return null;
  const service = challenge.match(/service="([^"]+)"/)?.[1];
  const scope = challenge.match(/scope="([^"]+)"/)?.[1];

  const cacheKey = `${realm}|${service}|${scope}|${auth.username ?? ''}`;
  const cached = tokenCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now() + 30_000) return cached.token;

  const url = new URL(realm);
  if (service) url.searchParams.set('service', service);
  // Force pull-only, whatever the challenge asked for.
  if (scope) url.searchParams.set('scope', scope.replace(/:[^:]*$/, ':pull'));

  const headers: Record<string, string> = {};
  if (auth.username && auth.password) {
    headers.Authorization = `Basic ${Buffer.from(`${auth.username}:${auth.password}`).toString('base64')}`;
  }

  try {
    const response = await fetch(url.toString(), { headers });
    if (!response.ok) return null;
    const json = (await response.json()) as { token?: string; access_token?: string; expires_in?: number };
    const token = json.token ?? json.access_token;
    if (!token) return null;
    tokenCache.set(cacheKey, { token, expiresAt: Date.now() + (json.expires_in ?? 300) * 1000 });
    return token;
  } catch {
    return null;
  }
}

async function registryGet<T>(
  ref: ImageRef,
  path: string,
  auth: RegistryAuth,
  accept: string,
): Promise<RegistryResult<T>> {
  const url = `https://${ref.registry}/v2/${ref.repository}${path}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  const attempt = async (bearer: string | null) => {
    const headers: Record<string, string> = { Accept: accept };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    else if (auth.token) headers.Authorization = `Bearer ${auth.token}`;
    else if (auth.username && auth.password) {
      headers.Authorization = `Basic ${Buffer.from(`${auth.username}:${auth.password}`).toString('base64')}`;
    }
    return fetch(url, { headers, signal: controller.signal });
  };

  try {
    let response = await attempt(null);

    if (response.status === 401) {
      const challenge = response.headers.get('www-authenticate');
      if (challenge) {
        const token = await resolveToken(challenge, auth);
        if (token) response = await attempt(token);
      }
    }

    if (response.status === 401 || response.status === 403) {
      return {
        ok: false,
        status: response.status,
        data: null,
        denied: true,
        reason: 'The registry refused the pull. A private image needs a read-only credential attached to this connection.',
      };
    }
    if (response.status === 404) {
      return { ok: false, status: 404, data: null, reason: 'The registry does not have that repository or reference.' };
    }
    if (!response.ok) {
      return { ok: false, status: response.status, data: null, reason: `The registry returned HTTP ${response.status}.` };
    }

    return {
      ok: true,
      status: response.status,
      data: (await response.json()) as T,
      digest: response.headers.get('docker-content-digest') ?? undefined,
    };
  } catch (error) {
    const message = (error as Error).name === 'AbortError' ? `The registry did not respond within ${TIMEOUT_MS / 1000}s.` : (error as Error).message;
    return { ok: false, status: 0, data: null, reason: message };
  } finally {
    clearTimeout(timer);
  }
}

/* ─────────────────────────────────────────────────────────── image inspect ── */

export interface ImageInspection {
  ref: ImageRef;
  digest: string | null;
  architecture: string | null;
  os: string | null;
  user: string | null;
  entrypoint: string[] | null;
  exposedPorts: string[];
  env: string[];
  /** Build history commands, from the config blob. */
  history: string[];
  layers: number;
  /** Total layer size in bytes, from the manifest descriptors. */
  sizeBytes: number;
  labels: Record<string, string>;
}

export async function inspectImage(ref: ImageRef, auth: RegistryAuth = {}): Promise<RegistryResult<ImageInspection>> {
  const reference = ref.digest ?? ref.tag ?? 'latest';
  const manifest = await registryGet<any>(ref, `/manifests/${reference}`, auth, MANIFEST_ACCEPT);
  if (!manifest.ok || !manifest.data) return { ...manifest, data: null };

  let resolved = manifest.data;
  let digest = manifest.digest ?? ref.digest ?? null;

  /* A manifest LIST points at per-architecture manifests. Pick amd64/linux
     when present — that is what almost every server workload runs — and say so
     in the evidence rather than silently assessing an arm64 variant. */
  if (Array.isArray(resolved.manifests)) {
    const preferred =
      resolved.manifests.find((entry: any) => entry.platform?.architecture === 'amd64' && entry.platform?.os === 'linux') ??
      resolved.manifests.find((entry: any) => entry.platform?.os === 'linux') ??
      resolved.manifests[0];
    if (!preferred?.digest) {
      return { ok: false, status: 0, data: null, reason: 'The manifest list contained no usable platform manifest.' };
    }
    const child = await registryGet<any>(ref, `/manifests/${preferred.digest}`, auth, MANIFEST_ACCEPT);
    if (!child.ok || !child.data) return { ...child, data: null };
    resolved = child.data;
    digest = preferred.digest;
  }

  const configDigest = resolved.config?.digest;
  let config: any = {};
  if (configDigest) {
    const blob = await registryGet<any>(ref, `/blobs/${configDigest}`, auth, 'application/json, application/vnd.oci.image.config.v1+json');
    if (blob.ok && blob.data) config = blob.data;
  }

  const layers: any[] = resolved.layers ?? [];

  return {
    ok: true,
    status: 200,
    data: {
      ref,
      digest,
      architecture: config.architecture ?? null,
      os: config.os ?? null,
      user: config.config?.User || null,
      entrypoint: config.config?.Entrypoint ?? null,
      exposedPorts: Object.keys(config.config?.ExposedPorts ?? {}),
      env: config.config?.Env ?? [],
      history: (config.history ?? []).map((entry: any) => String(entry.created_by ?? '')).filter(Boolean),
      layers: layers.length,
      sizeBytes: layers.reduce((sum, layer) => sum + (Number(layer.size) || 0), 0),
      labels: config.config?.Labels ?? {},
    },
  };
}

/* ────────────────────────────────────────────────────────────── the engine ── */

const CRYPTO_IN_HISTORY: Array<{ pattern: RegExp; library: string; algorithms: string[]; note: string }> = [
  { pattern: /\bopenssl\b/i, library: 'OpenSSL', algorithms: ['RSA', 'ECDSA', 'TLS'], note: 'OpenSSL is installed in the image and provides its TLS and general cryptography.' },
  { pattern: /\blibssl1\.1\b/i, library: 'OpenSSL 1.1', algorithms: ['RSA', 'ECDSA', 'TLS'], note: 'OpenSSL 1.1 is out of upstream support and has no hybrid post-quantum key agreement.' },
  { pattern: /\bgnutls\b/i, library: 'GnuTLS', algorithms: ['RSA', 'ECDSA', 'TLS'], note: 'GnuTLS is installed as an alternative TLS stack.' },
  { pattern: /\bliboqs\b|\boqs-provider\b/i, library: 'liboqs', algorithms: ['ML-KEM', 'ML-DSA'], note: 'The Open Quantum Safe library is installed, so post-quantum primitives are available in this image.' },
  { pattern: /\bopenssh\b/i, library: 'OpenSSH', algorithms: ['RSA', 'Ed25519'], note: 'OpenSSH is installed in the image.' },
];

export const registryEngine: ExposureEngine = {
  descriptor: {
    id: 'registry-scan',
    label: 'Container Registry',
    description: 'Reads OCI image manifests and config blobs read-only, anchoring every finding to the immutable digest rather than the tag.',
    mode: 'dev',
    layer: 'registry',
    capability: 'registry',
    weight: 10,
    minTier: 'pro',
  },

  appliesTo(context) {
    if (context.target.kind === 'container') return { applicable: true };
    const images = (context.workspace.meta.images as string[] | undefined) ?? [];
    const deployed = (context.workspace.meta.deployedImages as string[] | undefined) ?? [];
    return images.length + deployed.length > 0
      ? { applicable: true }
      : { applicable: false, reason: 'No container images were discovered in scope, so there is nothing to pull manifests for.' };
  },

  async execute(context: EngineContext): Promise<EngineResult> {
    const auth: RegistryAuth = {
      username: context.credential?.value?.username,
      password: context.credential?.value?.password,
      token: context.credential?.value?.token,
    };

    const candidates = new Set<string>();
    if (context.target.kind === 'container') candidates.add(context.target.image);
    for (const image of (context.workspace.meta.images as string[] | undefined) ?? []) candidates.add(image);
    for (const image of (context.workspace.meta.deployedImages as string[] | undefined) ?? []) candidates.add(image);

    const images = [...candidates].filter((image) => image && !image.includes('{{') && !image.includes('$'));
    if (images.length === 0) {
      return notAssessed('No resolvable container image references were in scope.', 'Container images');
    }

    const findings: ReturnType<typeof buildFinding>[] = [];
    const inspected: ImageInspection[] = [];
    let index = 0;

    for (const image of images.slice(0, 25)) {
      if (context.isCancelled()) break;
      index += 1;
      context.report(`Inspecting ${image}`, { done: index, total: Math.min(images.length, 25), unit: 'images' });

      const ref = parseImageRef(image);
      if (!ref) {
        context.notAssessed(`Image ${image}`, 'The reference could not be parsed, so the image was not inspected.');
        continue;
      }

      const inspection = await inspectImage(ref, auth);
      if (!inspection.ok || !inspection.data) {
        context.notAssessed(
          `Image ${image}`,
          inspection.reason ?? 'The image manifest could not be read, so nothing about this image was assessed.',
        );
        continue;
      }

      const data = inspection.data;
      inspected.push(data);
      const anchor = data.digest ?? 'unknown digest';

      const add = (input: { id: string; title: string; description: string; severity: FindingSeverity; recommendation: string; subcategory: string }) => {
        findings.push(
          buildFinding({
            scanId: context.scanId,
            engineId: 'registry-scan',
            mode: context.mode,
            layer: 'registry',
            category: 'Container Image',
            subcategory: input.subcategory,
            title: `${input.title} — ${ref.repository}`,
            description: input.description,
            severity: input.severity,
            confidence: 'high',
            detection: 'observed',
            quantumStatus: 'not-applicable',
            component: `${ref.registry}/${ref.repository}`,
            recommendation: input.recommendation,
            evidence: [
              buildEvidence({
                summary: `${input.title} in ${ref.registry}/${ref.repository}@${anchor}`,
                reference: `${ref.registry}/${ref.repository}@${anchor}`,
                provider: ref.registry,
                ruleId: input.id,
                attributes: {
                  digest: anchor,
                  tag: ref.tag ?? '',
                  architecture: data.architecture ?? '',
                  os: data.os ?? '',
                  layers: data.layers,
                  sizeMb: Math.round(data.sizeBytes / 1_000_000),
                },
              }),
            ],
            identity: `registry|${input.id}|${ref.registry}/${ref.repository}|${anchor}`,
          }),
        );
      };

      /* ── runs as root ────────────────────────────────────────────────── */
      if (!data.user || data.user === 'root' || data.user === '0') {
        add({
          id: 'registry-runs-as-root',
          subcategory: 'Privilege',
          title: 'Published image runs as root',
          description: `The image config sets User to "${data.user || '(unset)'}", so containers created from this exact digest run as uid 0 unless the orchestrator overrides it. This is what the registry actually holds, independent of what any Dockerfile in the repository says.`,
          severity: 'high',
          recommendation: 'Add a USER instruction to the final build stage and rebuild.',
        });
      }

      /* ── secrets baked into the image ────────────────────────────────── */
      for (const variable of data.env) {
        const [name, ...rest] = variable.split('=');
        const value = rest.join('=');
        if (!/(PASSWORD|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE_KEY|CREDENTIAL)/i.test(name)) continue;
        if (!value || value.length < 8) continue;
        add({
          id: 'registry-env-secret',
          subcategory: 'Secrets',
          title: `Image environment carries ${name}`,
          description: `The published image config sets ${name} to a value baked into the image. Anyone who can pull this digest can read it with \`docker inspect\`. The value has been redacted and is not stored.`,
          severity: 'critical',
          recommendation: 'Rebuild without the value and inject it at runtime from a secret manager. Rotate the credential — it is in every copy of this image that has been pulled.',
        });
      }

      /* ── build history: crypto libraries and unsafe steps ────────────── */
      const historyText = data.history.join('\n');
      for (const entry of CRYPTO_IN_HISTORY) {
        if (!entry.pattern.test(historyText)) continue;
        for (const algorithm of entry.algorithms) {
          const quantum = classifyQuantum({ algorithm, role: 'tls' });
          if (quantum.status !== 'vulnerable' && quantum.status !== 'pqc') continue;
          findings.push(
            buildFinding({
              scanId: context.scanId,
              engineId: 'registry-scan',
              mode: context.mode,
              layer: 'registry',
              category: 'Container Cryptography',
              subcategory: entry.library,
              title: `${ref.repository} ships ${entry.library} providing ${canonicalAlgorithmName(algorithm)}`,
              description: `${entry.note} ${quantum.rationale} Established from the image's own build history at digest ${anchor}, which is what is actually deployed.`,
              severity: quantum.status === 'vulnerable' ? 'medium' : 'info',
              confidence: 'medium',
              detection: 'inferred',
              algorithm,
              canonicalAlgorithm: canonicalAlgorithmName(algorithm),
              library: entry.library,
              role: 'tls',
              component: `${ref.registry}/${ref.repository}`,
              quantumStatus: quantum.status,
              quantumRationale: quantum.rationale,
              recommendation: quantum.migrationTarget ? `Track ${entry.library} for ${quantum.migrationTarget} support in the base image.` : undefined,
              evidence: [
                buildEvidence({
                  summary: `${entry.library} installed during the build of ${ref.repository}@${anchor}.`,
                  reference: `${ref.registry}/${ref.repository}@${anchor}`,
                  provider: ref.registry,
                  ruleId: `registry-crypto:${entry.library}`,
                  attributes: { digest: anchor, library: entry.library },
                }),
              ],
              identity: `registry|crypto|${ref.repository}|${entry.library}|${algorithm}`,
            }),
          );
        }
      }

      if (/(curl|wget)[^\n|]*\|\s*(ba)?sh/i.test(historyText)) {
        add({
          id: 'registry-pipe-to-shell',
          subcategory: 'Supply chain',
          title: 'Image was built by piping a download into a shell',
          description: 'The build history shows a remote script executed directly from a download. Whatever the remote host served at build time is baked into this digest, and cannot now be verified.',
          severity: 'medium',
          recommendation: 'Rebuild with a checksum-verified download.',
        });
      }

      /* ── provenance labels are a positive signal ─────────────────────── */
      const revision = data.labels['org.opencontainers.image.revision'];
      const source = data.labels['org.opencontainers.image.source'];
      if (revision || source) {
        findings.push(
          buildFinding({
            scanId: context.scanId,
            engineId: 'registry-scan',
            mode: context.mode,
            layer: 'registry',
            category: 'Container Image',
            subcategory: 'Provenance',
            title: `${ref.repository} carries OCI provenance labels`,
            description: `The image declares ${source ? `source ${source}` : ''}${source && revision ? ' at ' : ''}${revision ? `revision ${revision}` : ''}, which ties this digest back to the commit that produced it. That link is what makes cross-layer correlation between repository and deployment evidence provable rather than inferred.`,
            severity: 'info',
            confidence: 'high',
            detection: 'observed',
            quantumStatus: 'not-applicable',
            component: `${ref.registry}/${ref.repository}`,
            evidence: [
              buildEvidence({
                summary: `OCI labels on ${ref.repository}@${anchor}.`,
                reference: `${ref.registry}/${ref.repository}@${anchor}`,
                provider: ref.registry,
                ruleId: 'registry-provenance',
                attributes: { source: source ?? '', revision: revision ?? '', digest: anchor },
              }),
            ],
            identity: `registry|provenance|${ref.repository}|${anchor}`,
          }),
        );
      }
    }

    for (const finding of findings) context.emit(finding);
    context.workspace.meta.inspectedImages = inspected.map((entry) => ({
      repository: entry.ref.repository,
      registry: entry.ref.registry,
      digest: entry.digest,
      layers: entry.layers,
      sizeBytes: entry.sizeBytes,
    }));

    return completed(findings, { images: inspected.length, containers: inspected.length }, { inspected: inspected.length });
  },
};
