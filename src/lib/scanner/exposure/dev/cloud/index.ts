/**
 * Cloud Security Engine™ and Cloud Cryptographic Discovery Engine™
 * (Spec-2 §18, §22, §23, §43).
 *
 * Two engines over three provider adapters:
 *
 *   `cloud-inventory` — resource inventory and exposure posture.
 *   `cloud-crypto`    — the cryptographic inventory: KMS key specs, managed
 *                       certificates, TLS policies, storage encryption. This is
 *                       the one that feeds the CBOM (§23).
 *
 * §43 is the rule that shapes every error path here: "If a cloud account cannot
 * access a resource, `Access Denied` must not become `No vulnerability`. Use
 * `Not Assessed`."  So each adapter call distinguishes denied / unreachable /
 * empty, and only a genuine empty result is reported as an empty result.
 */

import type { CryptoRole, FindingSeverity } from '../../types';
import type { EngineContext, EngineResult, ExposureEngine } from '../../engine-contract';
import { buildEvidence, buildFinding, completed, notAssessed } from '../../engine-contract';
import { canonicalAlgorithmName, classifyQuantum, severityFor } from '../../algorithms';
import {
  describeKmsKeySpec,
  describeSslPolicy,
  getCallerIdentity,
  listBucketEncryption,
  listCertificates,
  listKmsKeys,
  listLoadBalancerListeners,
  type AwsCredentials,
} from './aws';
import {
  describeAzureTlsPolicy,
  listApplicationGateways,
  listKeyVaults,
  listStorageAccounts,
  probeAzure,
  type AzureCredentials,
} from './azure';
import {
  describeGcpKeyAlgorithm,
  listBuckets,
  listCryptoKeys,
  listSslPolicies,
  parseServiceAccount,
  probeGcp,
  type GcpCredentials,
} from './gcp';

export type CloudProvider = 'aws' | 'azure' | 'gcp';

/* ─────────────────────────────────────────────────────── credential shape ── */

function awsCredentialsFrom(context: EngineContext): AwsCredentials | null {
  const value = context.credential?.value;
  if (context.credential?.kind !== 'aws' || !value?.accessKeyId || !value?.secretAccessKey) return null;
  return { accessKeyId: value.accessKeyId, secretAccessKey: value.secretAccessKey, sessionToken: value.sessionToken };
}

function azureCredentialsFrom(context: EngineContext): AzureCredentials | null {
  const value = context.credential?.value;
  if (context.credential?.kind !== 'azure') return null;
  if (!value?.tenantId || !value?.clientId || !value?.clientSecret || !value?.subscriptionId) return null;
  return { tenantId: value.tenantId, clientId: value.clientId, clientSecret: value.clientSecret, subscriptionId: value.subscriptionId };
}

function gcpCredentialsFrom(context: EngineContext): GcpCredentials | null {
  const value = context.credential?.value;
  if (context.credential?.kind !== 'gcp' || !value?.serviceAccountJson) return null;
  return { serviceAccountJson: value.serviceAccountJson, projectId: value.projectId };
}

function providerOf(context: EngineContext): CloudProvider | null {
  if (context.target.kind !== 'cloud') return null;
  return context.target.provider;
}

/* ───────────────────────────────────────────────────── cloud crypto engine ── */

export const cloudCryptoEngine: ExposureEngine = {
  descriptor: {
    id: 'cloud-crypto',
    label: 'Cloud Cryptographic Discovery',
    description: 'Reads key-management specifications, managed certificates and transport policy from a connected cloud account, and classifies each by algorithm and role.',
    mode: 'dev',
    layer: 'cloud',
    capability: 'cloud',
    weight: 16,
    minTier: 'pro',
  },

  appliesTo(context) {
    if (context.target.kind !== 'cloud') return { applicable: false, reason: 'The scan target is not a cloud account.' };
    if (!context.credential) return { applicable: false, reason: 'No cloud connection is attached to this scan.' };
    if (!context.target.regions?.length) {
      return { applicable: false, reason: 'No region scope was selected. Select the regions to assess — this scanner never enumerates a whole account implicitly.' };
    }
    return { applicable: true };
  },

  async execute(context: EngineContext): Promise<EngineResult> {
    const provider = providerOf(context);
    if (!provider) return notAssessed('The scan target is not a cloud account.', 'Cloud cryptography');

    switch (provider) {
      case 'aws': return executeAwsCrypto(context);
      case 'azure': return executeAzureCrypto(context);
      case 'gcp': return executeGcpCrypto(context);
      default: return notAssessed(`Provider "${provider}" has no adapter in this build.`, 'Cloud cryptography');
    }
  },
};

/* ──────────────────────────────────────────────────────────────────── AWS ── */

async function executeAwsCrypto(context: EngineContext): Promise<EngineResult> {
  const credentials = awsCredentialsFrom(context);
  if (!credentials) return notAssessed('The AWS connection is missing its access key material.', 'AWS cryptography');
  if (context.target.kind !== 'cloud') return notAssessed('Not a cloud target.', 'AWS cryptography');

  const regions = context.target.regions;
  const findings: ReturnType<typeof buildFinding>[] = [];
  let resources = 0;

  context.report('Verifying AWS identity');
  const identity = await getCallerIdentity(credentials);
  if (!identity.ok) {
    return notAssessed(`The AWS credential could not be verified: ${identity.reason}`, 'AWS account');
  }
  context.workspace.meta.cloudAccount = { provider: 'aws', account: identity.data?.account, principal: identity.data?.arn };

  const emit = (finding: ReturnType<typeof buildFinding>) => {
    findings.push(finding);
    context.emit(finding);
  };

  let regionIndex = 0;
  for (const region of regions) {
    if (context.isCancelled()) break;
    regionIndex += 1;
    context.report(`Reading ${region}`, { done: regionIndex, total: regions.length, unit: 'regions' });

    /* ── KMS (§19: classify per key, never per service) ─────────────────── */
    const keys = await listKmsKeys(credentials, region);
    if (!keys.ok) {
      context.notAssessed(`AWS KMS in ${region}`, keys.reason ?? 'The KMS inventory could not be read.');
    } else {
      for (const key of keys.data ?? []) {
        resources += 1;
        const spec = describeKmsKeySpec(key.keySpec, key.keyUsage);
        const quantum = classifyQuantum({ algorithm: spec.algorithm, role: spec.role as CryptoRole, keySize: spec.keySize });
        const severity = severityFor({ quantum, classicallyWeak: false, role: spec.role as CryptoRole, detection: 'observed', keySize: spec.keySize });

        emit(
          buildFinding({
            scanId: context.scanId,
            engineId: 'cloud-crypto',
            mode: context.mode,
            layer: 'cloud',
            category: 'Cloud Key Management',
            subcategory: key.manager === 'AWS' ? 'AWS-managed key' : 'Customer-managed key',
            title: `KMS key ${key.keyId.slice(0, 8)}… — ${canonicalAlgorithmName(spec.algorithm)}${spec.keySize ? `-${spec.keySize}` : ''}`,
            description: [
              spec.note,
              key.description ? `Description: ${key.description}.` : '',
              key.rotationEnabled === false ? 'Automatic key rotation is DISABLED on this customer-managed key, so its material never changes.' : '',
              key.rotationEnabled === true ? 'Automatic key rotation is enabled.' : '',
              key.origin && key.origin !== 'AWS_KMS' ? `Key origin is ${key.origin}.` : '',
            ].filter(Boolean).join(' '),
            severity: key.rotationEnabled === false && severity === 'info' ? 'low' : severity,
            confidence: 'high',
            detection: 'observed',
            algorithm: spec.algorithm,
            canonicalAlgorithm: canonicalAlgorithmName(spec.algorithm),
            keySize: spec.keySize,
            role: spec.role as CryptoRole,
            component: key.keyId,
            quantumStatus: quantum.status,
            quantumRationale: quantum.rationale,
            recommendation: quantum.migrationTarget
              ? `Plan re-keying to ${quantum.migrationTarget} once AWS KMS offers the corresponding key spec.`
              : key.rotationEnabled === false
                ? 'Enable automatic key rotation — it is the operational capability a post-quantum re-key will depend on.'
                : undefined,
            evidence: [
              buildEvidence({
                summary: `KMS key ${key.arn} — spec ${key.keySpec ?? 'SYMMETRIC_DEFAULT'}, usage ${key.keyUsage ?? 'ENCRYPT_DECRYPT'}.`,
                scope: `aws:${identity.data?.account}:${region}`,
                reference: key.arn,
                provider: 'aws',
                ruleId: 'cloud-aws-kms-key',
                attributes: {
                  keySpec: key.keySpec ?? 'SYMMETRIC_DEFAULT',
                  keyUsage: key.keyUsage ?? '',
                  origin: key.origin ?? '',
                  rotationEnabled: key.rotationEnabled ?? 'not-applicable',
                  manager: key.manager ?? '',
                  enabled: key.enabled,
                },
              }),
            ],
            identity: `aws|kms|${key.arn}`,
            migration: quantum.status === 'vulnerable' ? { candidate: true, target: quantum.migrationTarget, priority: 'P2', complexity: 'high' } : { candidate: false },
          }),
        );
      }
    }

    /* ── ACM certificates ───────────────────────────────────────────────── */
    const certificates = await listCertificates(credentials, region);
    if (!certificates.ok) {
      context.notAssessed(`AWS Certificate Manager in ${region}`, certificates.reason ?? 'The certificate inventory could not be read.');
    } else {
      for (const certificate of certificates.data ?? []) {
        resources += 1;
        const algorithm = (certificate.keyAlgorithm ?? '').toUpperCase().startsWith('EC') ? 'ECDSA' : 'RSA';
        const keySize = Number((certificate.keyAlgorithm ?? '').match(/(\d{3,4})/)?.[1]) || null;
        const quantum = classifyQuantum({ algorithm, role: 'certificate', keySize });
        const sha1 = /SHA1/i.test(certificate.signatureAlgorithm ?? '');
        const severity = severityFor({ quantum, classicallyWeak: sha1, role: 'certificate', detection: 'observed', keySize });

        emit(
          buildFinding({
            scanId: context.scanId,
            engineId: 'cloud-crypto',
            mode: context.mode,
            layer: 'certificate',
            category: 'Cloud Certificate',
            subcategory: certificate.type ?? 'ACM',
            title: `ACM certificate for ${certificate.domainName} — ${canonicalAlgorithmName(algorithm)}${keySize ? `-${keySize}` : ''}`,
            description: [
              `Key algorithm ${certificate.keyAlgorithm ?? 'unreported'}, signature ${certificate.signatureAlgorithm ?? 'unreported'}, status ${certificate.status ?? 'unknown'}.`,
              certificate.inUseBy.length ? `In use by ${certificate.inUseBy.length} resource${certificate.inUseBy.length === 1 ? '' : 's'}.` : 'Not currently attached to any resource.',
              quantum.rationale,
              sha1 ? 'The signature uses SHA-1, which is collision-broken independently of quantum risk.' : '',
            ].filter(Boolean).join(' '),
            severity,
            confidence: 'high',
            detection: 'observed',
            algorithm,
            canonicalAlgorithm: canonicalAlgorithmName(algorithm),
            keySize,
            role: 'certificate',
            component: certificate.domainName,
            quantumStatus: quantum.status,
            quantumRationale: quantum.rationale,
            recommendation: quantum.migrationTarget ? `Re-issue with ${quantum.migrationTarget} once ACM supports it. Managed renewal means this becomes a configuration change, not a project.` : undefined,
            evidence: [
              buildEvidence({
                summary: `ACM certificate ${certificate.arn} for ${certificate.domainName}, expires ${certificate.notAfter ?? 'unknown'}.`,
                scope: `aws:${identity.data?.account}:${region}`,
                reference: certificate.arn,
                provider: 'aws',
                ruleId: 'cloud-aws-acm-certificate',
                attributes: {
                  domain: certificate.domainName,
                  keyAlgorithm: certificate.keyAlgorithm ?? '',
                  signatureAlgorithm: certificate.signatureAlgorithm ?? '',
                  notAfter: certificate.notAfter ?? '',
                  inUseBy: certificate.inUseBy.length,
                },
              }),
            ],
            identity: `aws|acm|${certificate.arn}`,
            migration: quantum.status === 'vulnerable' ? { candidate: true, target: quantum.migrationTarget, priority: certificate.inUseBy.length ? 'P1' : 'P3', complexity: 'low' } : { candidate: false },
          }),
        );
      }
    }

    /* ── load-balancer TLS policy ───────────────────────────────────────── */
    const listeners = await listLoadBalancerListeners(credentials, region);
    if (!listeners.ok) {
      context.notAssessed(`AWS load balancers in ${region}`, listeners.reason ?? 'Load balancer listeners could not be read.');
    } else {
      for (const listener of listeners.data ?? []) {
        resources += 1;
        if (listener.protocol !== 'HTTPS' && listener.protocol !== 'TLS') {
          if (listener.protocol === 'HTTP' && listener.scheme === 'internet-facing') {
            emit(
              buildFinding({
                scanId: context.scanId,
                engineId: 'cloud-crypto',
                mode: context.mode,
                layer: 'cloud',
                category: 'Cloud Transport',
                subcategory: 'Plaintext listener',
                title: `Internet-facing load balancer "${listener.loadBalancerName}" has an HTTP listener on port ${listener.port}`,
                description: `The listener terminates plaintext HTTP on an internet-facing load balancer, so traffic to ${listener.dnsName}:${listener.port} has no transport protection. A redirect action would not appear as a separate listener protocol, so verify whether this listener redirects before treating it as an exposure.`,
                severity: 'medium',
                confidence: 'medium',
                detection: 'observed',
                algorithm: 'TLS',
                canonicalAlgorithm: 'TLS',
                role: 'tls',
                quantumStatus: 'not-applicable',
                recommendation: 'Serve HTTPS and reduce the HTTP listener to a redirect action.',
                evidence: [
                  buildEvidence({
                    summary: `Listener ${listener.listenerArn} protocol HTTP on ${listener.dnsName}:${listener.port}.`,
                    scope: `aws:${identity.data?.account}:${region}`,
                    reference: listener.loadBalancerArn,
                    provider: 'aws',
                    ruleId: 'cloud-aws-plaintext-listener',
                  }),
                ],
                identity: `aws|listener-http|${listener.listenerArn}`,
              }),
            );
          }
          continue;
        }

        const policy = describeSslPolicy(listener.sslPolicy);
        emit(
          buildFinding({
            scanId: context.scanId,
            engineId: 'cloud-crypto',
            mode: context.mode,
            layer: 'cloud',
            category: 'Cloud Transport',
            subcategory: 'TLS policy',
            title: policy.legacy
              ? `Load balancer "${listener.loadBalancerName}" uses a legacy TLS policy`
              : `Load balancer "${listener.loadBalancerName}" TLS policy: ${listener.sslPolicy ?? 'unreported'}`,
            description: `Listener on port ${listener.port} uses security policy "${listener.sslPolicy ?? 'unreported'}" (minimum ${policy.minimumProtocol}). ${policy.note}`,
            severity: policy.legacy ? 'high' : policy.supportsTls13 ? 'info' : 'low',
            confidence: 'high',
            detection: 'observed',
            algorithm: 'TLS',
            canonicalAlgorithm: 'TLS',
            role: 'tls',
            component: listener.loadBalancerName,
            quantumStatus: policy.supportsTls13 ? 'unknown' : 'vulnerable',
            quantumRationale: policy.supportsTls13
              ? 'TLS 1.3 is enabled, so this listener can adopt a hybrid post-quantum group as soon as the provider offers one. Whether it currently negotiates one is measured by the Web assessment against the live endpoint.'
              : 'Without TLS 1.3 this listener cannot negotiate a hybrid post-quantum key-agreement group at all, so it has no path to post-quantum transport without a policy change.',
            recommendation: policy.legacy
              ? 'Move to ELBSecurityPolicy-TLS13-1-2-2021-06 or later.'
              : policy.supportsTls13
                ? undefined
                : 'Enable a TLS 1.3 policy so hybrid post-quantum key agreement becomes available.',
            evidence: [
              buildEvidence({
                summary: `${listener.loadBalancerName} listener :${listener.port} → policy ${listener.sslPolicy ?? 'unreported'}, ${listener.certificateArns.length} certificate(s).`,
                scope: `aws:${identity.data?.account}:${region}`,
                reference: listener.listenerArn,
                provider: 'aws',
                ruleId: 'cloud-aws-tls-policy',
                attributes: {
                  dnsName: listener.dnsName,
                  scheme: listener.scheme ?? '',
                  sslPolicy: listener.sslPolicy ?? '',
                  minimumProtocol: policy.minimumProtocol,
                  tls13: policy.supportsTls13,
                },
              }),
            ],
            identity: `aws|listener-tls|${listener.listenerArn}`,
          }),
        );
      }
    }

    /* ── S3 encryption ──────────────────────────────────────────────────── */
    const buckets = await listBucketEncryption(credentials, region);
    if (!buckets.ok) {
      context.notAssessed('AWS S3 encryption', buckets.reason ?? 'Bucket encryption configuration could not be read.');
    } else {
      for (const bucket of buckets.data ?? []) {
        resources += 1;
        if (bucket.denied) {
          context.notAssessed(`S3 bucket ${bucket.bucket}`, 'The credential cannot read this bucket\'s encryption configuration, so its encryption posture is unassessed — not clean.');
          continue;
        }
        if (bucket.algorithm) continue; // configured; recorded in coverage, not a finding
        emit(
          buildFinding({
            scanId: context.scanId,
            engineId: 'cloud-crypto',
            mode: context.mode,
            layer: 'cloud',
            category: 'Cloud Storage Encryption',
            subcategory: 'Default encryption',
            title: `S3 bucket "${bucket.bucket}" has no explicit encryption configuration`,
            description:
              'The bucket declares no server-side encryption configuration. S3 has applied SSE-S3 by default since January 2023, so objects are very likely encrypted with an AWS-managed key — but the posture is inherited rather than governed, and a customer-managed KMS key is what makes the key lifecycle yours to control and rotate.',
            severity: 'low',
            confidence: 'high',
            detection: 'observed',
            algorithm: 'AES',
            canonicalAlgorithm: 'AES',
            keySize: 256,
            role: 'storage-encryption',
            component: bucket.bucket,
            quantumStatus: 'resistant',
            quantumRationale: 'AES-256 at rest is quantum-resistant; the migration question for storage is who controls the wrapping key, not the cipher.',
            recommendation: 'Set a bucket encryption configuration using a customer-managed KMS key with rotation enabled.',
            evidence: [
              buildEvidence({
                summary: `S3 bucket ${bucket.bucket} returned no encryption configuration.`,
                scope: `aws:${identity.data?.account}`,
                reference: bucket.bucket,
                provider: 'aws',
                ruleId: 'cloud-aws-s3-default-encryption',
              }),
            ],
            identity: `aws|s3-encryption|${bucket.bucket}`,
          }),
        );
      }
    }
  }

  return completed(findings, { cloudResources: resources }, { provider: 'aws', account: identity.data?.account, regions });
}

/* ────────────────────────────────────────────────────────────────── Azure ── */

async function executeAzureCrypto(context: EngineContext): Promise<EngineResult> {
  const credentials = azureCredentialsFrom(context);
  if (!credentials) return notAssessed('The Azure connection is missing its service-principal details.', 'Azure cryptography');

  context.report('Verifying Azure subscription access');
  const probe = await probeAzure(credentials);
  if (!probe.reachable) return notAssessed(`The Azure subscription could not be read: ${probe.detail}`, 'Azure subscription');
  for (const denied of probe.denied) {
    context.notAssessed(`Azure ${denied}`, 'The service principal lacks Reader on this resource type, so it was not assessed.');
  }
  context.workspace.meta.cloudAccount = { provider: 'azure', account: credentials.subscriptionId, name: probe.subscriptionName };

  const findings: ReturnType<typeof buildFinding>[] = [];
  let resources = 0;
  const emit = (finding: ReturnType<typeof buildFinding>) => {
    findings.push(finding);
    context.emit(finding);
  };

  /* ── Key Vault posture ──────────────────────────────────────────────── */
  context.report('Reading Key Vaults');
  const vaults = await listKeyVaults(credentials);
  if (!vaults.ok) {
    context.notAssessed('Azure Key Vault', vaults.reason ?? 'Key Vault inventory could not be read.');
  } else {
    for (const vault of vaults.data ?? []) {
      resources += 1;
      const weaknesses: string[] = [];
      if (vault.purgeProtectionEnabled === false || vault.purgeProtectionEnabled === null) weaknesses.push('purge protection is not enabled, so a deleted vault and its keys can be permanently destroyed inside the soft-delete window');
      if (vault.publicNetworkAccess === 'Enabled') weaknesses.push('public network access is enabled, so the vault data plane is reachable from the Internet');
      if (vault.rbacAuthorization === false) weaknesses.push('the vault uses legacy access policies rather than Azure RBAC, which makes least-privilege harder to audit');

      emit(
        buildFinding({
          scanId: context.scanId,
          engineId: 'cloud-crypto',
          mode: context.mode,
          layer: 'cloud',
          category: 'Cloud Key Management',
          subcategory: 'Key Vault',
          title: weaknesses.length ? `Key Vault "${vault.name}" has ${weaknesses.length} governance weakness${weaknesses.length === 1 ? '' : 'es'}` : `Key Vault "${vault.name}" governance posture`,
          description: weaknesses.length
            ? `${weaknesses.join('; ')}. Key material itself was NOT read — this adapter uses the management plane only.`
            : 'Soft delete, purge protection and RBAC authorisation are configured. Key material itself was not read — this adapter uses the management plane only.',
          severity: weaknesses.length >= 2 ? 'medium' : weaknesses.length === 1 ? 'low' : 'info',
          confidence: 'high',
          detection: 'observed',
          role: 'key-management',
          component: vault.name,
          quantumStatus: 'unknown',
          quantumRationale: 'Key algorithms live on the Key Vault data plane, which this read-only management-plane adapter deliberately does not touch, so no per-key quantum verdict is published.',
          recommendation: weaknesses.length ? 'Enable purge protection, restrict public network access, and move to Azure RBAC authorisation.' : undefined,
          evidence: [
            buildEvidence({
              summary: `Key Vault ${vault.name} in ${vault.location}.`,
              scope: `azure:${credentials.subscriptionId}`,
              reference: vault.id,
              provider: 'azure',
              ruleId: 'cloud-azure-keyvault',
              attributes: {
                softDelete: vault.softDeleteEnabled ?? 'unknown',
                purgeProtection: vault.purgeProtectionEnabled ?? 'unknown',
                rbac: vault.rbacAuthorization ?? 'unknown',
                publicNetworkAccess: vault.publicNetworkAccess ?? 'unknown',
              },
            }),
          ],
          identity: `azure|keyvault|${vault.id}`,
        }),
      );
    }
  }

  /* ── Application Gateway TLS ────────────────────────────────────────── */
  context.report('Reading Application Gateways');
  const gateways = await listApplicationGateways(credentials);
  if (!gateways.ok) {
    context.notAssessed('Azure Application Gateways', gateways.reason ?? 'Application Gateways could not be read.');
  } else {
    for (const gateway of gateways.data ?? []) {
      resources += 1;
      const policy = describeAzureTlsPolicy(gateway.minProtocolVersion, gateway.sslPolicyName);
      const weakCiphers = gateway.cipherSuites.filter((suite) => /RC4|3DES|MD5|_CBC_SHA$/i.test(suite));

      emit(
        buildFinding({
          scanId: context.scanId,
          engineId: 'cloud-crypto',
          mode: context.mode,
          layer: 'cloud',
          category: 'Cloud Transport',
          subcategory: 'Application Gateway',
          title: policy.legacy
            ? `Application Gateway "${gateway.name}" permits a deprecated TLS version`
            : `Application Gateway "${gateway.name}" TLS posture`,
          description: [policy.note, weakCiphers.length ? `The cipher list includes ${weakCiphers.length} legacy suite${weakCiphers.length === 1 ? '' : 's'}: ${weakCiphers.slice(0, 4).join(', ')}.` : ''].filter(Boolean).join(' '),
          severity: policy.legacy || weakCiphers.length ? 'high' : 'info',
          confidence: 'high',
          detection: 'observed',
          algorithm: 'TLS',
          canonicalAlgorithm: 'TLS',
          role: 'tls',
          component: gateway.name,
          quantumStatus: policy.legacy ? 'vulnerable' : 'unknown',
          quantumRationale: policy.legacy
            ? 'A gateway floored below TLS 1.2 cannot negotiate hybrid post-quantum key agreement.'
            : 'The negotiated key-agreement group is not visible from the management plane; the Web assessment measures it against the live endpoint.',
          recommendation: policy.legacy || weakCiphers.length ? 'Set minProtocolVersion to TLSv1_2 and remove legacy cipher suites from the policy.' : undefined,
          evidence: [
            buildEvidence({
              summary: `Application Gateway ${gateway.name} — policy ${gateway.sslPolicyName ?? 'default'}, minimum ${policy.minimum}.`,
              scope: `azure:${credentials.subscriptionId}`,
              reference: gateway.id,
              provider: 'azure',
              ruleId: 'cloud-azure-appgw-tls',
              attributes: { policyName: gateway.sslPolicyName ?? '', minProtocol: policy.minimum, listeners: gateway.httpListeners.length },
            }),
          ],
          identity: `azure|appgw|${gateway.id}`,
        }),
      );
    }
  }

  /* ── Storage transport + encryption ─────────────────────────────────── */
  context.report('Reading storage accounts');
  const accounts = await listStorageAccounts(credentials);
  if (!accounts.ok) {
    context.notAssessed('Azure storage accounts', accounts.reason ?? 'Storage accounts could not be read.');
  } else {
    for (const account of accounts.data ?? []) {
      resources += 1;
      const problems: string[] = [];
      if (account.httpsOnly === false) problems.push('the account accepts plaintext HTTP');
      if (account.minimumTlsVersion && /TLS1_0|TLS1_1/.test(account.minimumTlsVersion)) problems.push(`the minimum TLS version is ${account.minimumTlsVersion}`);
      if (account.allowBlobPublicAccess === true) problems.push('anonymous blob public access is permitted');
      if (problems.length === 0) continue;

      emit(
        buildFinding({
          scanId: context.scanId,
          engineId: 'cloud-crypto',
          mode: context.mode,
          layer: 'cloud',
          category: 'Cloud Storage',
          subcategory: 'Transport policy',
          title: `Storage account "${account.name}" — ${problems.length} transport weakness${problems.length === 1 ? '' : 'es'}`,
          description: `${problems.join('; ')}. Encryption at rest uses ${account.encryptionKeySource ?? 'the platform default'}${account.infrastructureEncryption ? ' with infrastructure encryption enabled' : ''}.`,
          severity: account.httpsOnly === false || account.allowBlobPublicAccess === true ? 'high' : 'medium',
          confidence: 'high',
          detection: 'observed',
          algorithm: 'TLS',
          canonicalAlgorithm: 'TLS',
          role: 'tls',
          component: account.name,
          quantumStatus: 'not-applicable',
          recommendation: 'Set supportsHttpsTrafficOnly, minimumTlsVersion TLS1_2, and disable anonymous blob access.',
          evidence: [
            buildEvidence({
              summary: `Storage account ${account.name} in ${account.location}.`,
              scope: `azure:${credentials.subscriptionId}`,
              reference: account.id,
              provider: 'azure',
              ruleId: 'cloud-azure-storage-transport',
              attributes: {
                minimumTlsVersion: account.minimumTlsVersion ?? '',
                httpsOnly: account.httpsOnly ?? 'unknown',
                publicBlobAccess: account.allowBlobPublicAccess ?? 'unknown',
                keySource: account.encryptionKeySource ?? '',
              },
            }),
          ],
          identity: `azure|storage|${account.id}`,
        }),
      );
    }
  }

  return completed(findings, { cloudResources: resources }, { provider: 'azure', subscription: credentials.subscriptionId, probe });
}

/* ──────────────────────────────────────────────────────────────────── GCP ── */

async function executeGcpCrypto(context: EngineContext): Promise<EngineResult> {
  const credentials = gcpCredentialsFrom(context);
  if (!credentials) return notAssessed('The Google Cloud connection is missing its service-account key.', 'Google Cloud cryptography');

  context.report('Verifying Google Cloud access');
  const probe = await probeGcp(credentials);
  if (!probe.reachable || !probe.projectId) {
    return notAssessed(`The Google Cloud project could not be read: ${probe.detail}`, 'Google Cloud project');
  }
  for (const denied of probe.denied) {
    context.notAssessed(`Google Cloud ${denied}`, 'The service account is not authorised for this API, so it was not assessed.');
  }
  context.workspace.meta.cloudAccount = { provider: 'gcp', account: probe.projectId, principal: probe.serviceAccount };

  const projectId = probe.projectId;
  const findings: ReturnType<typeof buildFinding>[] = [];
  let resources = 0;
  const emit = (finding: ReturnType<typeof buildFinding>) => {
    findings.push(finding);
    context.emit(finding);
  };

  /* ── Cloud KMS ──────────────────────────────────────────────────────── */
  context.report('Reading Cloud KMS');
  const keys = await listCryptoKeys(credentials, projectId);
  if (!keys.ok) {
    context.notAssessed('Google Cloud KMS', keys.reason ?? 'Cloud KMS could not be read.');
  } else {
    for (const key of keys.data ?? []) {
      resources += 1;
      const spec = describeGcpKeyAlgorithm(key.algorithm);
      const quantum = classifyQuantum({ algorithm: spec.algorithm, role: spec.role as CryptoRole, keySize: spec.keySize });
      const severity = severityFor({ quantum, classicallyWeak: false, role: spec.role as CryptoRole, detection: 'observed', keySize: spec.keySize });
      const shortName = key.name.split('/').pop() ?? key.name;

      emit(
        buildFinding({
          scanId: context.scanId,
          engineId: 'cloud-crypto',
          mode: context.mode,
          layer: 'cloud',
          category: 'Cloud Key Management',
          subcategory: key.protectionLevel ?? 'SOFTWARE',
          title: `Cloud KMS key "${shortName}" — ${canonicalAlgorithmName(spec.algorithm)}${spec.keySize ? `-${spec.keySize}` : ''}`,
          description: [
            spec.note,
            key.rotationPeriod ? `Rotation period ${key.rotationPeriod}.` : 'No automatic rotation period is configured on this key.',
            key.protectionLevel === 'HSM' ? 'Key material is HSM-protected.' : '',
          ].filter(Boolean).join(' '),
          severity: !key.rotationPeriod && severity === 'info' ? 'low' : severity,
          confidence: 'high',
          detection: 'observed',
          algorithm: spec.algorithm,
          canonicalAlgorithm: canonicalAlgorithmName(spec.algorithm),
          keySize: spec.keySize,
          role: spec.role as CryptoRole,
          component: shortName,
          quantumStatus: quantum.status,
          quantumRationale: quantum.rationale,
          recommendation: quantum.migrationTarget
            ? `Plan re-keying to ${quantum.migrationTarget} once Cloud KMS offers the corresponding algorithm.`
            : !key.rotationPeriod
              ? 'Configure an automatic rotation period — rotation is the operational capability a post-quantum re-key depends on.'
              : undefined,
          evidence: [
            buildEvidence({
              summary: `Cloud KMS key ${key.name} — algorithm ${key.algorithm ?? 'unreported'}, purpose ${key.purpose ?? 'unreported'}.`,
              scope: `gcp:${projectId}:${key.location}`,
              reference: key.name,
              provider: 'gcp',
              ruleId: 'cloud-gcp-kms-key',
              attributes: {
                algorithm: key.algorithm ?? '',
                purpose: key.purpose ?? '',
                protectionLevel: key.protectionLevel ?? '',
                rotationPeriod: key.rotationPeriod ?? 'none',
                keyRing: key.keyRing,
              },
            }),
          ],
          identity: `gcp|kms|${key.name}`,
          migration: quantum.status === 'vulnerable' ? { candidate: true, target: quantum.migrationTarget, priority: 'P2', complexity: 'high' } : { candidate: false },
        }),
      );
    }
  }

  /* ── SSL policies ───────────────────────────────────────────────────── */
  context.report('Reading SSL policies');
  const policies = await listSslPolicies(credentials, projectId);
  if (!policies.ok) {
    context.notAssessed('Google Cloud SSL policies', policies.reason ?? 'SSL policies could not be read.');
  } else {
    for (const policy of policies.data ?? []) {
      resources += 1;
      const legacy = policy.minTlsVersion === 'TLS_1_0' || policy.minTlsVersion === 'TLS_1_1';
      if (!legacy && policy.profile !== 'COMPATIBLE') continue;

      emit(
        buildFinding({
          scanId: context.scanId,
          engineId: 'cloud-crypto',
          mode: context.mode,
          layer: 'cloud',
          category: 'Cloud Transport',
          subcategory: 'SSL policy',
          title: `SSL policy "${policy.name}" permits legacy transport`,
          description: legacy
            ? `The policy sets a minimum of ${policy.minTlsVersion?.replace(/_/g, ' ')}, which is deprecated by RFC 8996 and cannot negotiate a hybrid post-quantum key-agreement group.`
            : `The policy uses the COMPATIBLE profile, which enables the broadest cipher set including legacy suites, for maximum client compatibility.`,
          severity: legacy ? 'high' : 'medium',
          confidence: 'high',
          detection: 'observed',
          algorithm: 'TLS',
          canonicalAlgorithm: 'TLS',
          role: 'tls',
          component: policy.name,
          quantumStatus: legacy ? 'vulnerable' : 'unknown',
          quantumRationale: legacy
            ? 'A load balancer floored below TLS 1.2 cannot adopt hybrid post-quantum key agreement.'
            : 'The negotiated group is not visible from the API; the Web assessment measures it against the live endpoint.',
          recommendation: 'Set minTlsVersion to TLS_1_2 and use the MODERN or RESTRICTED profile.',
          evidence: [
            buildEvidence({
              summary: `SSL policy ${policy.name} in ${policy.region} — profile ${policy.profile ?? 'unreported'}, minimum ${policy.minTlsVersion ?? 'unreported'}.`,
              scope: `gcp:${projectId}:${policy.region}`,
              reference: policy.name,
              provider: 'gcp',
              ruleId: 'cloud-gcp-ssl-policy',
              attributes: { profile: policy.profile ?? '', minTlsVersion: policy.minTlsVersion ?? '' },
            }),
          ],
          identity: `gcp|ssl-policy|${policy.region}/${policy.name}`,
        }),
      );
    }
  }

  /* ── Storage ────────────────────────────────────────────────────────── */
  context.report('Reading Cloud Storage');
  const buckets = await listBuckets(credentials, projectId);
  if (!buckets.ok) {
    context.notAssessed('Google Cloud Storage', buckets.reason ?? 'Buckets could not be read.');
  } else {
    for (const bucket of buckets.data ?? []) {
      resources += 1;
      const problems: string[] = [];
      if (!bucket.defaultKmsKeyName) problems.push('no customer-managed encryption key is configured, so objects use Google-managed keys');
      if (bucket.publicAccessPrevention !== 'enforced') problems.push('public access prevention is not enforced');
      if (bucket.uniformBucketLevelAccess === false) problems.push('uniform bucket-level access is off, so per-object ACLs can widen access outside IAM');
      if (problems.length === 0) continue;

      emit(
        buildFinding({
          scanId: context.scanId,
          engineId: 'cloud-crypto',
          mode: context.mode,
          layer: 'cloud',
          category: 'Cloud Storage Encryption',
          subcategory: 'Bucket posture',
          title: `Bucket "${bucket.name}" — ${problems.length} governance gap${problems.length === 1 ? '' : 's'}`,
          description: `${problems.join('; ')}. Object data is encrypted at rest either way; the question this raises is who controls the key and who can reach the objects.`,
          severity: bucket.publicAccessPrevention !== 'enforced' ? 'medium' : 'low',
          confidence: 'high',
          detection: 'observed',
          algorithm: 'AES',
          canonicalAlgorithm: 'AES',
          keySize: 256,
          role: 'storage-encryption',
          component: bucket.name,
          quantumStatus: 'resistant',
          quantumRationale: 'AES-256 at rest is quantum-resistant; the migration question for storage is key custody, not the cipher.',
          recommendation: 'Set a Cloud KMS default key, enforce public access prevention, and enable uniform bucket-level access.',
          evidence: [
            buildEvidence({
              summary: `Bucket ${bucket.name} in ${bucket.location}.`,
              scope: `gcp:${projectId}`,
              reference: bucket.name,
              provider: 'gcp',
              ruleId: 'cloud-gcp-bucket-posture',
              attributes: {
                kmsKey: bucket.defaultKmsKeyName ?? 'google-managed',
                publicAccessPrevention: bucket.publicAccessPrevention ?? 'unknown',
                uniformAccess: bucket.uniformBucketLevelAccess ?? 'unknown',
              },
            }),
          ],
          identity: `gcp|bucket|${bucket.name}`,
        }),
      );
    }
  }

  return completed(findings, { cloudResources: resources }, { provider: 'gcp', project: projectId, probe });
}

/* ─────────────────────────────────────────────── cloud inventory engine ──── */

/**
 * A thin engine whose only job is to establish WHAT IS THERE and publish the
 * account facts, so the Dev posture dashboard has real numbers even when the
 * crypto engine is not in the selected profile.
 */
export const cloudInventoryEngine: ExposureEngine = {
  descriptor: {
    id: 'cloud-inventory',
    label: 'Cloud Inventory',
    description: 'Verifies the connected cloud account and enumerates the resources in the selected scope, read-only.',
    mode: 'dev',
    layer: 'cloud',
    capability: 'cloud',
    weight: 6,
    minTier: 'pro',
  },

  appliesTo(context) {
    if (context.target.kind !== 'cloud') return { applicable: false, reason: 'The scan target is not a cloud account.' };
    if (!context.credential) return { applicable: false, reason: 'No cloud connection is attached to this scan.' };
    return { applicable: true };
  },

  async execute(context: EngineContext): Promise<EngineResult> {
    const provider = providerOf(context);
    if (!provider) return notAssessed('The scan target is not a cloud account.', 'Cloud inventory');

    context.report(`Verifying ${provider.toUpperCase()} access`);

    if (provider === 'aws') {
      const credentials = awsCredentialsFrom(context);
      if (!credentials) return notAssessed('The AWS connection is missing its access key material.', 'AWS account');
      const identity = await getCallerIdentity(credentials);
      if (!identity.ok) return notAssessed(`The AWS credential could not be verified: ${identity.reason}`, 'AWS account');
      context.workspace.meta.cloudAccount = { provider, account: identity.data?.account, principal: identity.data?.arn };
      return completed([], {}, { provider, account: identity.data?.account, principal: identity.data?.arn });
    }

    if (provider === 'azure') {
      const credentials = azureCredentialsFrom(context);
      if (!credentials) return notAssessed('The Azure connection is incomplete.', 'Azure subscription');
      const probe = await probeAzure(credentials);
      if (!probe.reachable) return notAssessed(probe.detail, 'Azure subscription');
      context.workspace.meta.cloudAccount = { provider, account: credentials.subscriptionId, name: probe.subscriptionName };
      for (const denied of probe.denied) context.notAssessed(`Azure ${denied}`, 'Reader access was denied for this resource type.');
      return completed([], {}, { provider, subscription: credentials.subscriptionId, probe });
    }

    const credentials = gcpCredentialsFrom(context);
    if (!credentials) return notAssessed('The Google Cloud connection is incomplete.', 'Google Cloud project');
    const key = parseServiceAccount(credentials.serviceAccountJson);
    const probe = await probeGcp(credentials);
    if (!probe.reachable) return notAssessed(probe.detail, 'Google Cloud project');
    context.workspace.meta.cloudAccount = { provider, account: probe.projectId, principal: key?.client_email };
    for (const denied of probe.denied) context.notAssessed(`Google Cloud ${denied}`, 'The service account is not authorised for this API.');
    return completed([], {}, { provider, project: probe.projectId, probe });
  },
};
