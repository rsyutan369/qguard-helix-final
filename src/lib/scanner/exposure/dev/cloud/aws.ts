/**
 * AWS cloud adapter (Spec-2 §18, §19, §22).
 *
 * Server-side only — it uses `node:crypto` for SigV4. Read-only: every call
 * below is a List/Describe/Get, and the permission set is published to the
 * operator before they connect.
 *
 * §19 has a specific, easily-failed instruction: "For AWS KMS, distinguish the
 * cryptographic role and service capabilities rather than simply labeling KMS as
 * quantum safe." A KMS key is not a quantum verdict on its own — a
 * SYMMETRIC_DEFAULT key wraps data keys with AES-256 and is quantum-resistant,
 * while an RSA_2048 or ECC_NIST_P256 key spec is a signing/wrapping key that
 * Shor breaks. This adapter reads the `KeySpec` and `KeyUsage` and classifies
 * per key, which is the only honest way to do it.
 */

import { createHash, createHmac } from 'node:crypto';

/* ────────────────────────────────────────────────────────────────── SigV4 ── */

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

const SIGNED_HEADERS_ALGORITHM = 'AWS4-HMAC-SHA256';

function sha256Hex(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

function hmac(key: Buffer | string, value: string): Buffer {
  return createHmac('sha256', key).update(value, 'utf8').digest();
}

function amzDate(date: Date): { amz: string; short: string } {
  const amz = date.toISOString().replace(/[:-]|\.\d{3}/g, '');
  return { amz, short: amz.slice(0, 8) };
}

/**
 * Sign a request with SigV4.
 *
 * Deliberately handwritten rather than pulling in the AWS SDK: the SDK is a
 * ~20 MB dependency tree for six read-only API calls, and the signing algorithm
 * is a hundred lines. The credential never leaves this function's scope.
 */
export function signRequest(input: {
  method: string;
  service: string;
  region: string;
  host: string;
  path: string;
  query?: Record<string, string>;
  body?: string;
  headers?: Record<string, string>;
  credentials: AwsCredentials;
  now?: Date;
}): { url: string; headers: Record<string, string> } {
  const now = input.now ?? new Date();
  const { amz, short } = amzDate(now);
  const body = input.body ?? '';
  const payloadHash = sha256Hex(body);

  const canonicalQuery = Object.entries(input.query ?? {})
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([key, value]) => `${encodeRfc3986(key)}=${encodeRfc3986(value)}`)
    .join('&');

  const headers: Record<string, string> = {
    host: input.host,
    'x-amz-date': amz,
    'x-amz-content-sha256': payloadHash,
    ...(input.credentials.sessionToken ? { 'x-amz-security-token': input.credentials.sessionToken } : {}),
    ...(input.headers ?? {}),
  };

  const sortedHeaderNames = Object.keys(headers)
    .map((name) => name.toLowerCase())
    .sort();
  const canonicalHeaders = sortedHeaderNames
    .map((name) => `${name}:${String(headers[Object.keys(headers).find((key) => key.toLowerCase() === name)!]).trim()}\n`)
    .join('');
  const signedHeaders = sortedHeaderNames.join(';');

  const canonicalRequest = [
    input.method.toUpperCase(),
    input.path || '/',
    canonicalQuery,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  const scope = `${short}/${input.region}/${input.service}/aws4_request`;
  const stringToSign = [SIGNED_HEADERS_ALGORITHM, amz, scope, sha256Hex(canonicalRequest)].join('\n');

  const kDate = hmac(`AWS4${input.credentials.secretAccessKey}`, short);
  const kRegion = hmac(kDate, input.region);
  const kService = hmac(kRegion, input.service);
  const kSigning = hmac(kService, 'aws4_request');
  const signature = createHmac('sha256', kSigning).update(stringToSign, 'utf8').digest('hex');

  return {
    url: `https://${input.host}${input.path || '/'}${canonicalQuery ? `?${canonicalQuery}` : ''}`,
    headers: {
      ...headers,
      Authorization: `${SIGNED_HEADERS_ALGORITHM} Credential=${input.credentials.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
    },
  };
}

function encodeRfc3986(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
}

/* ─────────────────────────────────────────────────────────────── requests ── */

const AWS_TIMEOUT_MS = 12_000;

export interface AwsCallResult<T> {
  ok: boolean;
  status: number;
  data: T | null;
  /** Why the call did not succeed. Distinguishes denied from unavailable. */
  reason?: string;
  denied?: boolean;
}

async function awsCall<T>(input: {
  service: string;
  region: string;
  host?: string;
  path?: string;
  query?: Record<string, string>;
  target?: string;
  body?: unknown;
  credentials: AwsCredentials;
  accept?: 'json' | 'xml';
}): Promise<AwsCallResult<T>> {
  const host = input.host ?? `${input.service}.${input.region}.amazonaws.com`;
  const body = input.body === undefined ? '' : JSON.stringify(input.body);
  const headers: Record<string, string> = {};
  if (input.target) {
    headers['content-type'] = 'application/x-amz-json-1.1';
    headers['x-amz-target'] = input.target;
  }

  const signed = signRequest({
    method: input.body === undefined && !input.target ? 'GET' : 'POST',
    service: input.service,
    region: input.region,
    host,
    path: input.path ?? '/',
    query: input.query,
    body,
    headers,
    credentials: input.credentials,
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), AWS_TIMEOUT_MS);
  try {
    const response = await fetch(signed.url, {
      method: input.body === undefined && !input.target ? 'GET' : 'POST',
      headers: signed.headers,
      body: input.body === undefined && !input.target ? undefined : body,
      signal: controller.signal,
    });

    const text = await response.text();

    if (!response.ok) {
      const denied = response.status === 403 || /AccessDenied|UnauthorizedOperation|not authorized/i.test(text);
      return {
        ok: false,
        status: response.status,
        data: null,
        denied,
        reason: denied
          ? 'The IAM principal is not authorised for this call, so this dimension was not assessed.'
          : `AWS returned HTTP ${response.status}.`,
      };
    }

    if (input.accept === 'xml') return { ok: true, status: response.status, data: text as unknown as T };
    try {
      return { ok: true, status: response.status, data: JSON.parse(text) as T };
    } catch {
      return { ok: true, status: response.status, data: text as unknown as T };
    }
  } catch (error) {
    const message = (error as Error).name === 'AbortError' ? `AWS did not respond within ${AWS_TIMEOUT_MS / 1000}s.` : (error as Error).message;
    return { ok: false, status: 0, data: null, reason: message };
  } finally {
    clearTimeout(timer);
  }
}

/* ──────────────────────────────────────────────────────────────── probes ─── */

export interface AwsIdentity {
  account: string;
  arn: string;
  userId: string;
}

export async function getCallerIdentity(credentials: AwsCredentials, region = 'us-east-1'): Promise<AwsCallResult<AwsIdentity>> {
  const result = await awsCall<string>({
    service: 'sts',
    region,
    host: 'sts.amazonaws.com',
    path: '/',
    query: { Action: 'GetCallerIdentity', Version: '2011-06-15' },
    credentials,
    accept: 'xml',
  });
  if (!result.ok || !result.data) return { ...result, data: null };

  const xml = result.data;
  const account = xml.match(/<Account>([^<]+)<\/Account>/)?.[1] ?? '';
  const arn = xml.match(/<Arn>([^<]+)<\/Arn>/)?.[1] ?? '';
  const userId = xml.match(/<UserId>([^<]+)<\/UserId>/)?.[1] ?? '';
  return { ok: true, status: result.status, data: { account, arn, userId } };
}

/* ── ACM ─────────────────────────────────────────────────────────────────── */

export interface AcmCertificate {
  arn: string;
  domainName: string;
  keyAlgorithm: string | null;
  signatureAlgorithm: string | null;
  status: string | null;
  notAfter: string | null;
  inUseBy: string[];
  type: string | null;
}

export async function listCertificates(credentials: AwsCredentials, region: string): Promise<AwsCallResult<AcmCertificate[]>> {
  const list = await awsCall<{ CertificateSummaryList?: Array<{ CertificateArn: string; DomainName: string; KeyAlgorithm?: string }> }>({
    service: 'acm',
    region,
    target: 'CertificateManager.ListCertificates',
    body: { MaxItems: 100 },
    credentials,
  });
  if (!list.ok || !list.data) return { ...list, data: null };

  const summaries = list.data.CertificateSummaryList ?? [];
  const certificates: AcmCertificate[] = [];

  for (const summary of summaries.slice(0, 60)) {
    const describe = await awsCall<{
      Certificate?: {
        CertificateArn: string;
        DomainName: string;
        KeyAlgorithm?: string;
        SignatureAlgorithm?: string;
        Status?: string;
        NotAfter?: number;
        InUseBy?: string[];
        Type?: string;
      };
    }>({
      service: 'acm',
      region,
      target: 'CertificateManager.DescribeCertificate',
      body: { CertificateArn: summary.CertificateArn },
      credentials,
    });
    const detail = describe.data?.Certificate;
    certificates.push({
      arn: summary.CertificateArn,
      domainName: detail?.DomainName ?? summary.DomainName,
      keyAlgorithm: detail?.KeyAlgorithm ?? summary.KeyAlgorithm ?? null,
      signatureAlgorithm: detail?.SignatureAlgorithm ?? null,
      status: detail?.Status ?? null,
      notAfter: detail?.NotAfter ? new Date(detail.NotAfter * 1000).toISOString() : null,
      inUseBy: detail?.InUseBy ?? [],
      type: detail?.Type ?? null,
    });
  }

  return { ok: true, status: 200, data: certificates };
}

/* ── KMS ─────────────────────────────────────────────────────────────────── */

export interface KmsKey {
  keyId: string;
  arn: string;
  keySpec: string | null;
  keyUsage: string | null;
  origin: string | null;
  enabled: boolean;
  rotationEnabled: boolean | null;
  description: string | null;
  manager: string | null;
}

export async function listKmsKeys(credentials: AwsCredentials, region: string): Promise<AwsCallResult<KmsKey[]>> {
  const list = await awsCall<{ Keys?: Array<{ KeyId: string; KeyArn: string }> }>({
    service: 'kms',
    region,
    target: 'TrentService.ListKeys',
    body: { Limit: 200 },
    credentials,
  });
  if (!list.ok || !list.data) return { ...list, data: null };

  const keys: KmsKey[] = [];
  for (const entry of (list.data.Keys ?? []).slice(0, 80)) {
    const describe = await awsCall<{
      KeyMetadata?: {
        KeyId: string;
        Arn: string;
        KeySpec?: string;
        CustomerMasterKeySpec?: string;
        KeyUsage?: string;
        Origin?: string;
        Enabled?: boolean;
        Description?: string;
        KeyManager?: string;
      };
    }>({
      service: 'kms',
      region,
      target: 'TrentService.DescribeKey',
      body: { KeyId: entry.KeyId },
      credentials,
    });
    const metadata = describe.data?.KeyMetadata;
    if (!metadata) continue;

    /* Rotation status is only meaningful for customer-managed symmetric keys;
       asking about an AWS-managed key returns an error that is not a finding. */
    let rotationEnabled: boolean | null = null;
    if (metadata.KeyManager === 'CUSTOMER') {
      const rotation = await awsCall<{ KeyRotationEnabled?: boolean }>({
        service: 'kms',
        region,
        target: 'TrentService.GetKeyRotationStatus',
        body: { KeyId: entry.KeyId },
        credentials,
      });
      rotationEnabled = rotation.ok ? Boolean(rotation.data?.KeyRotationEnabled) : null;
    }

    keys.push({
      keyId: metadata.KeyId,
      arn: metadata.Arn,
      keySpec: metadata.KeySpec ?? metadata.CustomerMasterKeySpec ?? null,
      keyUsage: metadata.KeyUsage ?? null,
      origin: metadata.Origin ?? null,
      enabled: metadata.Enabled !== false,
      rotationEnabled,
      description: metadata.Description ?? null,
      manager: metadata.KeyManager ?? null,
    });
  }

  return { ok: true, status: 200, data: keys };
}

/**
 * Map a KMS KeySpec to (algorithm, key size, role) — the §19 requirement.
 *
 * This is the function that stops KMS from being labelled "quantum safe"
 * wholesale. A SYMMETRIC_DEFAULT key really is AES-256 and really is
 * quantum-resistant; an RSA_2048 signing key in the same account really is
 * broken by Shor. They are different rows with different verdicts.
 */
export function describeKmsKeySpec(keySpec: string | null, keyUsage: string | null): {
  algorithm: string;
  keySize: number | null;
  role: 'encryption' | 'signature' | 'key-management' | 'unknown';
  note: string;
} {
  const spec = (keySpec ?? '').toUpperCase();
  const usage = (keyUsage ?? '').toUpperCase();

  if (spec === 'SYMMETRIC_DEFAULT' || spec === '') {
    return {
      algorithm: 'AES',
      keySize: 256,
      role: 'key-management',
      note: 'A symmetric KMS key wraps data keys with AES-256-GCM. Grover halves its effective strength, which 256 bits already absorbs — this key is not a post-quantum migration candidate.',
    };
  }
  if (spec.startsWith('RSA_')) {
    const bits = Number(spec.replace('RSA_', '')) || null;
    return {
      algorithm: 'RSA',
      keySize: bits,
      role: usage === 'SIGN_VERIFY' ? 'signature' : 'encryption',
      note: `An RSA-${bits ?? '?'} KMS key used for ${usage === 'SIGN_VERIFY' ? 'signing' : 'encryption'} is broken by Shor's algorithm and IS a migration candidate, regardless of the service it lives in.`,
    };
  }
  if (spec.startsWith('ECC_')) {
    const curve = spec.replace('ECC_NIST_', '').replace('ECC_SECG_', '');
    const bits = curve.includes('P256') ? 256 : curve.includes('P384') ? 384 : curve.includes('P521') ? 521 : null;
    return {
      algorithm: 'ECDSA',
      keySize: bits,
      role: 'signature',
      note: `An elliptic-curve KMS key (${curve}) is broken by Shor's algorithm and IS a migration candidate.`,
    };
  }
  if (spec.startsWith('HMAC_')) {
    return {
      algorithm: 'HMAC',
      keySize: Number(spec.replace('HMAC_', '')) || null,
      role: 'unknown',
      note: 'An HMAC KMS key is symmetric and is not a post-quantum migration candidate.',
    };
  }
  if (spec.startsWith('SM2')) {
    return { algorithm: 'SM2', keySize: 256, role: 'signature', note: 'SM2 is an elliptic-curve scheme and is broken by Shor\'s algorithm.' };
  }
  return { algorithm: spec || 'Unknown', keySize: null, role: 'unknown', note: 'The key specification was not recognised, so no quantum verdict is published for it.' };
}

/* ── Load balancers ──────────────────────────────────────────────────────── */

export interface LoadBalancerListener {
  loadBalancerArn: string;
  loadBalancerName: string;
  dnsName: string;
  scheme: string | null;
  listenerArn: string;
  protocol: string | null;
  port: number | null;
  sslPolicy: string | null;
  certificateArns: string[];
}

export async function listLoadBalancerListeners(credentials: AwsCredentials, region: string): Promise<AwsCallResult<LoadBalancerListener[]>> {
  const list = await awsCall<string>({
    service: 'elasticloadbalancing',
    region,
    path: '/',
    query: { Action: 'DescribeLoadBalancers', Version: '2015-12-01' },
    credentials,
    accept: 'xml',
  });
  if (!list.ok || !list.data) return { ...list, data: null };

  const balancers = [...list.data.matchAll(/<member>([\s\S]*?)<\/member>/g)]
    .map((match) => match[1])
    .filter((block) => block.includes('<LoadBalancerArn>'))
    .map((block) => ({
      arn: block.match(/<LoadBalancerArn>([^<]+)<\/LoadBalancerArn>/)?.[1] ?? '',
      name: block.match(/<LoadBalancerName>([^<]+)<\/LoadBalancerName>/)?.[1] ?? '',
      dnsName: block.match(/<DNSName>([^<]+)<\/DNSName>/)?.[1] ?? '',
      scheme: block.match(/<Scheme>([^<]+)<\/Scheme>/)?.[1] ?? null,
    }))
    .filter((balancer) => balancer.arn);

  const listeners: LoadBalancerListener[] = [];
  for (const balancer of balancers.slice(0, 40)) {
    const result = await awsCall<string>({
      service: 'elasticloadbalancing',
      region,
      path: '/',
      query: { Action: 'DescribeListeners', Version: '2015-12-01', LoadBalancerArn: balancer.arn },
      credentials,
      accept: 'xml',
    });
    if (!result.ok || !result.data) continue;

    for (const match of result.data.matchAll(/<member>([\s\S]*?)<\/member>/g)) {
      const block = match[1];
      if (!block.includes('<ListenerArn>')) continue;
      listeners.push({
        loadBalancerArn: balancer.arn,
        loadBalancerName: balancer.name,
        dnsName: balancer.dnsName,
        scheme: balancer.scheme,
        listenerArn: block.match(/<ListenerArn>([^<]+)<\/ListenerArn>/)?.[1] ?? '',
        protocol: block.match(/<Protocol>([^<]+)<\/Protocol>/)?.[1] ?? null,
        port: Number(block.match(/<Port>(\d+)<\/Port>/)?.[1]) || null,
        sslPolicy: block.match(/<SslPolicy>([^<]+)<\/SslPolicy>/)?.[1] ?? null,
        certificateArns: [...block.matchAll(/<CertificateArn>([^<]+)<\/CertificateArn>/g)].map((entry) => entry[1]),
      });
    }
  }

  return { ok: true, status: 200, data: listeners };
}

/** Interpret an ELB security policy name. */
export function describeSslPolicy(policy: string | null): {
  minimumProtocol: string;
  legacy: boolean;
  supportsTls13: boolean;
  note: string;
} {
  const name = policy ?? '';
  if (!name) {
    return { minimumProtocol: 'unknown', legacy: false, supportsTls13: false, note: 'No SSL policy was reported for this listener.' };
  }
  const supportsTls13 = /TLS13/i.test(name);
  const legacy = /2015|2016|TLS-1-0|TLS-1-1/i.test(name) && !supportsTls13;
  const minimumProtocol = /TLS-1-2|TLS13-1-2/i.test(name) ? 'TLS 1.2' : /TLS-1-1/i.test(name) ? 'TLS 1.1' : /TLS-1-0|2015|2016/i.test(name) ? 'TLS 1.0' : 'TLS 1.2';
  return {
    minimumProtocol,
    legacy,
    supportsTls13,
    note: supportsTls13
      ? 'The policy enables TLS 1.3, which is the prerequisite for hybrid post-quantum key agreement once AWS offers it.'
      : legacy
        ? 'The policy permits a deprecated TLS version and cannot negotiate TLS 1.3, so this listener has no path to hybrid post-quantum key agreement.'
        : 'The policy requires TLS 1.2 but does not enable TLS 1.3.',
  };
}

/* ── S3 ──────────────────────────────────────────────────────────────────── */

export interface S3BucketEncryption {
  bucket: string;
  algorithm: string | null;
  kmsKeyArn: string | null;
  bucketKeyEnabled: boolean | null;
  /** True when the API said the bucket has no encryption configuration. */
  unconfigured: boolean;
  denied: boolean;
}

export async function listBucketEncryption(credentials: AwsCredentials, region: string): Promise<AwsCallResult<S3BucketEncryption[]>> {
  const list = await awsCall<string>({
    service: 's3',
    region,
    host: 's3.amazonaws.com',
    path: '/',
    credentials,
    accept: 'xml',
  });
  if (!list.ok || !list.data) return { ...list, data: null };

  const buckets = [...list.data.matchAll(/<Name>([^<]+)<\/Name>/g)].map((match) => match[1]);
  const results: S3BucketEncryption[] = [];

  for (const bucket of buckets.slice(0, 60)) {
    const encryption = await awsCall<string>({
      service: 's3',
      region,
      host: `${bucket}.s3.amazonaws.com`,
      path: '/',
      query: { encryption: '' },
      credentials,
      accept: 'xml',
    });

    if (!encryption.ok) {
      results.push({
        bucket,
        algorithm: null,
        kmsKeyArn: null,
        bucketKeyEnabled: null,
        unconfigured: /ServerSideEncryptionConfigurationNotFoundError/i.test(String(encryption.reason ?? '')) || encryption.status === 404,
        denied: Boolean(encryption.denied),
      });
      continue;
    }

    const xml = encryption.data ?? '';
    results.push({
      bucket,
      algorithm: xml.match(/<SSEAlgorithm>([^<]+)<\/SSEAlgorithm>/)?.[1] ?? null,
      kmsKeyArn: xml.match(/<KMSMasterKeyID>([^<]+)<\/KMSMasterKeyID>/)?.[1] ?? null,
      bucketKeyEnabled: /<BucketKeyEnabled>true<\/BucketKeyEnabled>/i.test(xml),
      unconfigured: false,
      denied: false,
    });
  }

  return { ok: true, status: 200, data: results };
}
