/**
 * Google Cloud adapter (Spec-2 §18, §21).
 *
 * Service-account JWT → OAuth access token → read-only REST calls. The
 * assertion is signed here with `node:crypto` rather than by pulling in the
 * Google auth library, for the same reason the AWS adapter hand-rolls SigV4:
 * six read-only calls do not justify the dependency, and the private key stays
 * inside one function's scope.
 *
 * Cloud KMS is where the interesting cryptography lives, and §21 has the same
 * trap as §19's KMS clause: a `GOOGLE_SYMMETRIC_ENCRYPTION` key is AES-256 and
 * quantum-resistant, while `RSA_SIGN_PKCS1_4096_SHA512` and
 * `EC_SIGN_P256_SHA256` in the same key ring are Shor-broken. The verdict is
 * per key version's algorithm, never per service.
 */

import { createSign } from 'node:crypto';

const TIMEOUT_MS = 12_000;

export interface GcpCredentials {
  /** The raw service-account key JSON, as pasted by the operator. */
  serviceAccountJson: string;
  /** Optional override; otherwise taken from the key's project_id. */
  projectId?: string;
}

interface ServiceAccountKey {
  client_email: string;
  private_key: string;
  project_id: string;
  token_uri?: string;
}

export interface GcpCallResult<T> {
  ok: boolean;
  status: number;
  data: T | null;
  reason?: string;
  denied?: boolean;
}

/* ───────────────────────────────────────────────────────────────── tokens ── */

const tokenCache = new Map<string, { token: string; expiresAt: number }>();

function base64Url(input: string | Buffer): string {
  return Buffer.from(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function parseServiceAccount(json: string): ServiceAccountKey | null {
  try {
    const parsed = JSON.parse(json) as ServiceAccountKey;
    if (!parsed.client_email || !parsed.private_key || !parsed.project_id) return null;
    return parsed;
  } catch {
    return null;
  }
}

/** Mint a read-only access token from the service-account key. */
export async function getAccessToken(credentials: GcpCredentials): Promise<GcpCallResult<string>> {
  const key = parseServiceAccount(credentials.serviceAccountJson);
  if (!key) {
    return { ok: false, status: 0, data: null, reason: 'The service-account key JSON could not be parsed.' };
  }

  const cached = tokenCache.get(key.client_email);
  if (cached && cached.expiresAt > Date.now() + 60_000) {
    return { ok: true, status: 200, data: cached.token };
  }

  const issuedAt = Math.floor(Date.now() / 1000);
  const header = base64Url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claims = base64Url(
    JSON.stringify({
      iss: key.client_email,
      // Read-only scopes only. `cloud-platform.read-only` covers inventory;
      // cloudkms viewer covers key metadata. Neither can mutate anything.
      scope: 'https://www.googleapis.com/auth/cloud-platform.read-only',
      aud: key.token_uri ?? 'https://oauth2.googleapis.com/token',
      exp: issuedAt + 3600,
      iat: issuedAt,
    }),
  );

  let signature: string;
  try {
    const signer = createSign('RSA-SHA256');
    signer.update(`${header}.${claims}`);
    signature = base64Url(signer.sign(key.private_key));
  } catch (error) {
    return { ok: false, status: 0, data: null, reason: `The service-account private key could not sign the assertion: ${(error as Error).message}` };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const response = await fetch(key.token_uri ?? 'https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: `${header}.${claims}.${signature}`,
      }).toString(),
      signal: controller.signal,
    });
    const json = (await response.json()) as { access_token?: string; expires_in?: number; error_description?: string };
    if (!response.ok || !json.access_token) {
      return {
        ok: false,
        status: response.status,
        data: null,
        denied: response.status === 401 || response.status === 403,
        reason: json.error_description ?? `Google returned HTTP ${response.status} for the token request.`,
      };
    }
    tokenCache.set(key.client_email, { token: json.access_token, expiresAt: Date.now() + (json.expires_in ?? 3600) * 1000 });
    return { ok: true, status: 200, data: json.access_token };
  } catch (error) {
    return { ok: false, status: 0, data: null, reason: (error as Error).message };
  } finally {
    clearTimeout(timer);
  }
}

async function gcpGet<T>(credentials: GcpCredentials, url: string): Promise<GcpCallResult<T>> {
  const token = await getAccessToken(credentials);
  if (!token.ok || !token.data) return { ok: false, status: token.status, data: null, reason: token.reason, denied: token.denied };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      headers: { Authorization: `Bearer ${token.data}`, Accept: 'application/json' },
      signal: controller.signal,
    });
    if (response.status === 403) {
      return { ok: false, status: 403, data: null, denied: true, reason: 'The service account is not authorised for this API, so this dimension was not assessed.' };
    }
    if (!response.ok) {
      return { ok: false, status: response.status, data: null, reason: `Google Cloud returned HTTP ${response.status}.` };
    }
    return { ok: true, status: 200, data: (await response.json()) as T };
  } catch (error) {
    const message = (error as Error).name === 'AbortError' ? `Google Cloud did not respond within ${TIMEOUT_MS / 1000}s.` : (error as Error).message;
    return { ok: false, status: 0, data: null, reason: message };
  } finally {
    clearTimeout(timer);
  }
}

/* ──────────────────────────────────────────────────────────────── probes ─── */

export interface GcpProbe {
  reachable: boolean;
  projectId: string | null;
  serviceAccount: string | null;
  granted: string[];
  denied: string[];
  detail: string;
}

export async function probeGcp(credentials: GcpCredentials): Promise<GcpProbe> {
  const key = parseServiceAccount(credentials.serviceAccountJson);
  if (!key) {
    return { reachable: false, projectId: null, serviceAccount: null, granted: [], denied: [], detail: 'The service-account key JSON could not be parsed.' };
  }
  const projectId = credentials.projectId ?? key.project_id;

  const token = await getAccessToken(credentials);
  if (!token.ok) {
    return { reachable: false, projectId, serviceAccount: key.client_email, granted: [], denied: [], detail: token.reason ?? 'Authentication failed.' };
  }

  const checks: Array<{ label: string; url: string }> = [
    { label: 'KMS key rings', url: `https://cloudkms.googleapis.com/v1/projects/${projectId}/locations/global/keyRings` },
    { label: 'storage buckets', url: `https://storage.googleapis.com/storage/v1/b?project=${projectId}&maxResults=1` },
    { label: 'compute instances', url: `https://compute.googleapis.com/compute/v1/projects/${projectId}/aggregated/instances?maxResults=1` },
    { label: 'SSL policies', url: `https://compute.googleapis.com/compute/v1/projects/${projectId}/aggregated/sslPolicies?maxResults=1` },
  ];

  const granted: string[] = [];
  const denied: string[] = [];
  for (const check of checks) {
    const result = await gcpGet(credentials, check.url);
    if (result.ok) granted.push(check.label);
    else if (result.denied) denied.push(check.label);
  }

  return {
    reachable: true,
    projectId,
    serviceAccount: key.client_email,
    granted,
    denied,
    detail: denied.length
      ? `Connected read-only as ${key.client_email}. ${granted.length} APIs readable; ${denied.length} denied (${denied.join(', ')}) — those dimensions will be reported as Not Assessed.`
      : `Connected read-only as ${key.client_email} with access to all ${granted.length} APIs the assessment requires.`,
  };
}

/* ────────────────────────────────────────────────────────────────── KMS ──── */

export interface GcpCryptoKey {
  name: string;
  purpose: string | null;
  algorithm: string | null;
  protectionLevel: string | null;
  rotationPeriod: string | null;
  nextRotationTime: string | null;
  state: string | null;
  keyRing: string;
  location: string;
}

const KMS_LOCATIONS = ['global', 'us', 'europe', 'asia'];

export async function listCryptoKeys(credentials: GcpCredentials, projectId: string): Promise<GcpCallResult<GcpCryptoKey[]>> {
  const keys: GcpCryptoKey[] = [];
  let anySuccess = false;
  let lastReason: string | undefined;
  let denied = false;

  for (const location of KMS_LOCATIONS) {
    const rings = await gcpGet<{ keyRings?: Array<{ name: string }> }>(
      credentials,
      `https://cloudkms.googleapis.com/v1/projects/${projectId}/locations/${location}/keyRings`,
    );
    if (!rings.ok) {
      lastReason = rings.reason;
      denied = denied || Boolean(rings.denied);
      continue;
    }
    anySuccess = true;

    for (const ring of (rings.data?.keyRings ?? []).slice(0, 20)) {
      const cryptoKeys = await gcpGet<{
        cryptoKeys?: Array<{
          name: string;
          purpose?: string;
          rotationPeriod?: string;
          nextRotationTime?: string;
          primary?: { algorithm?: string; protectionLevel?: string; state?: string };
          versionTemplate?: { algorithm?: string; protectionLevel?: string };
        }>;
      }>(credentials, `https://cloudkms.googleapis.com/v1/${ring.name}/cryptoKeys`);
      if (!cryptoKeys.ok) continue;

      for (const key of cryptoKeys.data?.cryptoKeys ?? []) {
        keys.push({
          name: key.name,
          purpose: key.purpose ?? null,
          algorithm: key.primary?.algorithm ?? key.versionTemplate?.algorithm ?? null,
          protectionLevel: key.primary?.protectionLevel ?? key.versionTemplate?.protectionLevel ?? null,
          rotationPeriod: key.rotationPeriod ?? null,
          nextRotationTime: key.nextRotationTime ?? null,
          state: key.primary?.state ?? null,
          keyRing: ring.name.split('/').pop() ?? ring.name,
          location,
        });
      }
    }
  }

  if (!anySuccess) {
    return { ok: false, status: denied ? 403 : 0, data: null, denied, reason: lastReason ?? 'No Cloud KMS location could be read.' };
  }
  return { ok: true, status: 200, data: keys };
}

/**
 * Map a Cloud KMS algorithm to (algorithm, key size, role) — the §21 analogue
 * of the AWS KMS rule.
 */
export function describeGcpKeyAlgorithm(algorithm: string | null): {
  algorithm: string;
  keySize: number | null;
  role: 'encryption' | 'signature' | 'key-management' | 'unknown';
  note: string;
} {
  const value = (algorithm ?? '').toUpperCase();

  if (value.startsWith('GOOGLE_SYMMETRIC_ENCRYPTION') || value.startsWith('AES')) {
    return {
      algorithm: 'AES',
      keySize: 256,
      role: 'key-management',
      note: 'A Google symmetric KMS key is AES-256-GCM. Grover halves its effective strength, which 256 bits absorbs — it is not a post-quantum migration candidate.',
    };
  }
  if (value.startsWith('RSA_')) {
    const bits = Number(value.match(/_(\d{4})_/)?.[1]) || null;
    const signing = value.includes('SIGN');
    return {
      algorithm: 'RSA',
      keySize: bits,
      role: signing ? 'signature' : 'encryption',
      note: `An RSA-${bits ?? '?'} Cloud KMS key used for ${signing ? 'signing' : 'decryption'} is broken by Shor's algorithm and IS a migration candidate.`,
    };
  }
  if (value.startsWith('EC_')) {
    const bits = value.includes('P256') ? 256 : value.includes('P384') ? 384 : value.includes('SECP256K1') ? 256 : null;
    return {
      algorithm: 'ECDSA',
      keySize: bits,
      role: 'signature',
      note: 'An elliptic-curve Cloud KMS signing key is broken by Shor\'s algorithm and IS a migration candidate.',
    };
  }
  if (value.startsWith('HMAC_')) {
    return { algorithm: 'HMAC', keySize: null, role: 'unknown', note: 'An HMAC key is symmetric and is not a post-quantum migration candidate.' };
  }
  if (value.startsWith('PQ_') || value.includes('ML_DSA') || value.includes('SLH_DSA')) {
    return { algorithm: value.includes('SLH') ? 'SLH-DSA' : 'ML-DSA', keySize: null, role: 'signature', note: 'A post-quantum signing key is already migrated.' };
  }
  return { algorithm: value || 'Unknown', keySize: null, role: 'unknown', note: 'The key algorithm was not recognised, so no quantum verdict is published for it.' };
}

/* ────────────────────────────────────────────────────────── SSL policies ─── */

export interface GcpSslPolicy {
  name: string;
  minTlsVersion: string | null;
  profile: string | null;
  enabledFeatures: string[];
  region: string;
}

export async function listSslPolicies(credentials: GcpCredentials, projectId: string): Promise<GcpCallResult<GcpSslPolicy[]>> {
  const result = await gcpGet<{ items?: Record<string, { sslPolicies?: Array<{ name: string; minTlsVersion?: string; profile?: string; enabledFeatures?: string[] }> }> }>(
    credentials,
    `https://compute.googleapis.com/compute/v1/projects/${projectId}/aggregated/sslPolicies`,
  );
  if (!result.ok || !result.data) return { ...result, data: null };

  const policies: GcpSslPolicy[] = [];
  for (const [scope, entry] of Object.entries(result.data.items ?? {})) {
    for (const policy of entry.sslPolicies ?? []) {
      policies.push({
        name: policy.name,
        minTlsVersion: policy.minTlsVersion ?? null,
        profile: policy.profile ?? null,
        enabledFeatures: policy.enabledFeatures ?? [],
        region: scope.replace('regions/', '').replace('global/', 'global'),
      });
    }
  }
  return { ok: true, status: 200, data: policies };
}

/* ───────────────────────────────────────────────────────────── storage ───── */

export interface GcpBucket {
  name: string;
  location: string;
  defaultKmsKeyName: string | null;
  uniformBucketLevelAccess: boolean | null;
  publicAccessPrevention: string | null;
}

export async function listBuckets(credentials: GcpCredentials, projectId: string): Promise<GcpCallResult<GcpBucket[]>> {
  const result = await gcpGet<{ items?: Array<{ name: string; location: string; encryption?: { defaultKmsKeyName?: string }; iamConfiguration?: any }> }>(
    credentials,
    `https://storage.googleapis.com/storage/v1/b?project=${encodeURIComponent(projectId)}&maxResults=200`,
  );
  if (!result.ok || !result.data) return { ...result, data: null };

  return {
    ok: true,
    status: 200,
    data: (result.data.items ?? []).map((bucket) => ({
      name: bucket.name,
      location: bucket.location,
      defaultKmsKeyName: bucket.encryption?.defaultKmsKeyName ?? null,
      uniformBucketLevelAccess: bucket.iamConfiguration?.uniformBucketLevelAccess?.enabled ?? null,
      publicAccessPrevention: bucket.iamConfiguration?.publicAccessPrevention ?? null,
    })),
  };
}
