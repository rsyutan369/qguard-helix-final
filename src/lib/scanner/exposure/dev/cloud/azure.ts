/**
 * Azure cloud adapter (Spec-2 §18, §20).
 *
 * OAuth 2.0 client-credentials against Entra ID, then read-only Azure Resource
 * Manager calls. The service principal needs `Reader` on the subscription and
 * `Key Vault Reader` for key metadata; nothing here requires or requests a
 * write permission, and no key or secret VALUE is ever fetched — Key Vault's
 * data-plane `getSecret` is deliberately not implemented in this adapter.
 */

import { createHash } from 'node:crypto';

const ARM = 'https://management.azure.com';
const TIMEOUT_MS = 12_000;

export interface AzureCredentials {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  subscriptionId: string;
}

export interface AzureCallResult<T> {
  ok: boolean;
  status: number;
  data: T | null;
  reason?: string;
  denied?: boolean;
}

/* ───────────────────────────────────────────────────────────────── tokens ── */

interface CachedToken {
  token: string;
  expiresAt: number;
}

const tokenCache = new Map<string, CachedToken>();

/**
 * Acquire an ARM access token.
 *
 * Cached until 60s before expiry, keyed by (tenant, client, SECRET DIGEST) — a
 * scan makes dozens of ARM calls and re-authenticating on each one both wastes
 * time and trips Entra ID's throttling. The secret digest is part of the key
 * because tenant and client ids are not secret: without it, a second caller who
 * knew them could be handed a token minted with someone else's secret.
 */
export async function getArmToken(credentials: AzureCredentials): Promise<AzureCallResult<string>> {
  const secretDigest = createHash('sha256').update(credentials.clientSecret).digest('hex');
  const cacheKey = `${credentials.tenantId}:${credentials.clientId}:${secretDigest}`;
  const cached = tokenCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now() + 60_000) {
    return { ok: true, status: 200, data: cached.token };
  }

  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: credentials.clientId,
    client_secret: credentials.clientSecret,
    scope: 'https://management.azure.com/.default',
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const response = await fetch(`https://login.microsoftonline.com/${encodeURIComponent(credentials.tenantId)}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
      signal: controller.signal,
    });
    const json = (await response.json()) as { access_token?: string; expires_in?: number; error_description?: string };
    if (!response.ok || !json.access_token) {
      return {
        ok: false,
        status: response.status,
        data: null,
        denied: response.status === 401 || response.status === 403,
        // The error description can echo the client id but never the secret.
        reason: json.error_description?.split('\n')[0] ?? `Entra ID returned HTTP ${response.status}.`,
      };
    }
    tokenCache.set(cacheKey, { token: json.access_token, expiresAt: Date.now() + (json.expires_in ?? 3600) * 1000 });
    return { ok: true, status: 200, data: json.access_token };
  } catch (error) {
    return { ok: false, status: 0, data: null, reason: (error as Error).message };
  } finally {
    clearTimeout(timer);
  }
}

async function armGet<T>(credentials: AzureCredentials, path: string, apiVersion: string): Promise<AzureCallResult<T>> {
  const token = await getArmToken(credentials);
  if (!token.ok || !token.data) return { ok: false, status: token.status, data: null, reason: token.reason, denied: token.denied };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const separator = path.includes('?') ? '&' : '?';
    const response = await fetch(`${ARM}${path}${separator}api-version=${apiVersion}`, {
      headers: { Authorization: `Bearer ${token.data}`, Accept: 'application/json' },
      signal: controller.signal,
    });
    if (response.status === 403) {
      return { ok: false, status: 403, data: null, denied: true, reason: 'The service principal lacks Reader on this scope, so it was not assessed.' };
    }
    if (!response.ok) {
      return { ok: false, status: response.status, data: null, reason: `Azure Resource Manager returned HTTP ${response.status}.` };
    }
    return { ok: true, status: 200, data: (await response.json()) as T };
  } catch (error) {
    const message = (error as Error).name === 'AbortError' ? `Azure did not respond within ${TIMEOUT_MS / 1000}s.` : (error as Error).message;
    return { ok: false, status: 0, data: null, reason: message };
  } finally {
    clearTimeout(timer);
  }
}

/* ─────────────────────────────────────────────────────────────── probes ──── */

export interface AzureProbe {
  reachable: boolean;
  subscriptionName: string | null;
  granted: string[];
  denied: string[];
  detail: string;
}

export async function probeAzure(credentials: AzureCredentials): Promise<AzureProbe> {
  const subscription = await armGet<{ displayName?: string }>(credentials, `/subscriptions/${credentials.subscriptionId}`, '2020-01-01');
  if (!subscription.ok) {
    return {
      reachable: false,
      subscriptionName: null,
      granted: [],
      denied: [],
      detail: subscription.reason ?? 'The subscription could not be read.',
    };
  }

  const checks: Array<{ label: string; path: string; apiVersion: string }> = [
    { label: 'resources', path: `/subscriptions/${credentials.subscriptionId}/resources?$top=1`, apiVersion: '2021-04-01' },
    { label: 'key vaults', path: `/subscriptions/${credentials.subscriptionId}/providers/Microsoft.KeyVault/vaults?$top=1`, apiVersion: '2022-07-01' },
    { label: 'storage accounts', path: `/subscriptions/${credentials.subscriptionId}/providers/Microsoft.Storage/storageAccounts`, apiVersion: '2023-01-01' },
    { label: 'application gateways', path: `/subscriptions/${credentials.subscriptionId}/providers/Microsoft.Network/applicationGateways`, apiVersion: '2023-05-01' },
  ];

  const granted: string[] = [];
  const denied: string[] = [];
  for (const check of checks) {
    const result = await armGet(credentials, check.path, check.apiVersion);
    if (result.ok) granted.push(check.label);
    else if (result.denied) denied.push(check.label);
  }

  return {
    reachable: true,
    subscriptionName: subscription.data?.displayName ?? null,
    granted,
    denied,
    detail: denied.length
      ? `Connected read-only. ${granted.length} resource types readable; ${denied.length} denied (${denied.join(', ')}) — those dimensions will be reported as Not Assessed.`
      : `Connected read-only with Reader access to all ${granted.length} resource types the assessment requires.`,
  };
}

/* ────────────────────────────────────────────────────────────── inventory ── */

export interface AzureKeyVault {
  id: string;
  name: string;
  location: string;
  softDeleteEnabled: boolean | null;
  purgeProtectionEnabled: boolean | null;
  rbacAuthorization: boolean | null;
  publicNetworkAccess: string | null;
}

export async function listKeyVaults(credentials: AzureCredentials): Promise<AzureCallResult<AzureKeyVault[]>> {
  const result = await armGet<{ value?: Array<{ id: string; name: string; location: string; properties?: any }> }>(
    credentials,
    `/subscriptions/${credentials.subscriptionId}/providers/Microsoft.KeyVault/vaults`,
    '2022-07-01',
  );
  if (!result.ok || !result.data) return { ...result, data: null };

  return {
    ok: true,
    status: 200,
    data: (result.data.value ?? []).map((vault) => ({
      id: vault.id,
      name: vault.name,
      location: vault.location,
      softDeleteEnabled: vault.properties?.enableSoftDelete ?? null,
      purgeProtectionEnabled: vault.properties?.enablePurgeProtection ?? null,
      rbacAuthorization: vault.properties?.enableRbacAuthorization ?? null,
      publicNetworkAccess: vault.properties?.publicNetworkAccess ?? null,
    })),
  };
}

export interface AzureStorageAccount {
  id: string;
  name: string;
  location: string;
  minimumTlsVersion: string | null;
  httpsOnly: boolean | null;
  allowBlobPublicAccess: boolean | null;
  encryptionKeySource: string | null;
  infrastructureEncryption: boolean | null;
}

export async function listStorageAccounts(credentials: AzureCredentials): Promise<AzureCallResult<AzureStorageAccount[]>> {
  const result = await armGet<{ value?: Array<{ id: string; name: string; location: string; properties?: any }> }>(
    credentials,
    `/subscriptions/${credentials.subscriptionId}/providers/Microsoft.Storage/storageAccounts`,
    '2023-01-01',
  );
  if (!result.ok || !result.data) return { ...result, data: null };

  return {
    ok: true,
    status: 200,
    data: (result.data.value ?? []).map((account) => ({
      id: account.id,
      name: account.name,
      location: account.location,
      minimumTlsVersion: account.properties?.minimumTlsVersion ?? null,
      httpsOnly: account.properties?.supportsHttpsTrafficOnly ?? null,
      allowBlobPublicAccess: account.properties?.allowBlobPublicAccess ?? null,
      encryptionKeySource: account.properties?.encryption?.keySource ?? null,
      infrastructureEncryption: account.properties?.encryption?.requireInfrastructureEncryption ?? null,
    })),
  };
}

export interface AzureApplicationGateway {
  id: string;
  name: string;
  location: string;
  sslPolicyName: string | null;
  minProtocolVersion: string | null;
  cipherSuites: string[];
  httpListeners: Array<{ name: string; protocol: string | null }>;
}

export async function listApplicationGateways(credentials: AzureCredentials): Promise<AzureCallResult<AzureApplicationGateway[]>> {
  const result = await armGet<{ value?: Array<{ id: string; name: string; location: string; properties?: any }> }>(
    credentials,
    `/subscriptions/${credentials.subscriptionId}/providers/Microsoft.Network/applicationGateways`,
    '2023-05-01',
  );
  if (!result.ok || !result.data) return { ...result, data: null };

  return {
    ok: true,
    status: 200,
    data: (result.data.value ?? []).map((gateway) => ({
      id: gateway.id,
      name: gateway.name,
      location: gateway.location,
      sslPolicyName: gateway.properties?.sslPolicy?.policyName ?? null,
      minProtocolVersion: gateway.properties?.sslPolicy?.minProtocolVersion ?? null,
      cipherSuites: gateway.properties?.sslPolicy?.cipherSuites ?? [],
      httpListeners: (gateway.properties?.httpListeners ?? []).map((listener: any) => ({
        name: listener.name,
        protocol: listener.properties?.protocol ?? null,
      })),
    })),
  };
}

/**
 * Interpret an Application Gateway SSL policy.
 *
 * `minProtocolVersion` is the field that matters; the predefined policy NAMES
 * are not self-describing (AppGwSslPolicy20170401S allows TLS 1.2 while
 * AppGwSslPolicy20150501 allows TLS 1.0), which is exactly the kind of detail a
 * name-matching rule gets wrong.
 */
export function describeAzureTlsPolicy(minProtocolVersion: string | null, policyName: string | null): {
  minimum: string;
  legacy: boolean;
  note: string;
} {
  const explicit = (minProtocolVersion ?? '').replace('TLSv', 'TLS ').replace('_', '.');
  if (explicit) {
    const legacy = /1\.0|1\.1/.test(explicit);
    return {
      minimum: explicit,
      legacy,
      note: legacy
        ? `The gateway accepts ${explicit}, which is deprecated by RFC 8996 and cannot negotiate a hybrid post-quantum key-agreement group.`
        : `The gateway requires ${explicit} or better.`,
    };
  }
  if (policyName === 'AppGwSslPolicy20150501') {
    return { minimum: 'TLS 1.0', legacy: true, note: 'The predefined policy AppGwSslPolicy20150501 permits TLS 1.0.' };
  }
  return {
    minimum: 'unknown',
    legacy: false,
    note: 'No explicit minimum protocol version is set on this gateway, so its floor is the Azure default for the predefined policy in use. It was not independently verified.',
  };
}
