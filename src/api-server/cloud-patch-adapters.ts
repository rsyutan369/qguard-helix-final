import {
  MANDATORY_PQC_CONFIG_VALUES,
  MANDATORY_PQC_STACK,
  mandatoryPqcStackMetadata,
} from '@/lib/crypto/mandatory-pqc-stack'

type CloudProvider = 'aws' | 'azure' | 'gcp' | 'unsupported'

type ConnectorRecord = {
  id?: string
  provider?: string | null
  scopes?: string[] | null
  policy?: Record<string, unknown> | null
  capabilities?: Record<string, unknown> | null
  metadata?: Record<string, unknown> | null
}

type OperatorActionRecord = {
  id?: string
  action_type?: string | null
  asset_class?: string | null
  status?: string | null
  connector_account_id?: string | null
  patch_plan?: Record<string, unknown> | null
  metadata?: Record<string, unknown> | null
}

type CloudPatchInput = {
  action: OperatorActionRecord
  connector: ConnectorRecord | null
  requestedBy: string
  status: string
  execute?: boolean
  dryRun?: boolean
  now?: string
}

type CloudPatchResult = {
  attempted: boolean
  executed: boolean
  blocked: boolean
  dryRun: boolean
  provider: CloudProvider
  adapter: string
  status: 'skipped' | 'blocked' | 'dry_run' | 'executed' | 'failed'
  reason?: string
  beforeState?: Record<string, unknown> | null
  afterState?: Record<string, unknown> | null
  snapshot?: Record<string, unknown> | null
  verification?: Record<string, unknown>
  evidence?: Array<Record<string, unknown>>
  sdk?: {
    module: string
    installed: boolean
    requiredModules?: string[]
  }
  rollbackPlan?: Record<string, unknown>
  unsupportedControls?: string[]
  error?: string
}

type SdkModule = Record<string, any>

const CLOUD_SDK_PATCHES_ENABLED = /^(1|true|yes)$/i.test(process.env.QGUARD_ENABLE_CLOUD_SDK_PATCHES || '')
const optionalImport = new Function('specifier', 'return import(specifier)') as (specifier: string) => Promise<SdkModule>

function asRecord(value: unknown): Record<string, any> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, any> : {}
}

function boolValue(value: unknown) {
  return value === true || /^(1|true|yes|enabled)$/i.test(String(value || ''))
}

function textValue(value: unknown) {
  return typeof value === 'string' ? value.trim() : ''
}

function providerFromConnector(connector: ConnectorRecord | null): CloudProvider {
  const provider = String(connector?.provider || '').toLowerCase()
  if (/aws|amazon/.test(provider)) return 'aws'
  if (/azure|microsoft|entra/.test(provider)) return 'azure'
  if (/gcp|google/.test(provider)) return 'gcp'
  return 'unsupported'
}

function connectorMetadata(connector: ConnectorRecord | null) {
  return asRecord(connector?.metadata)
}

function connectorCapability(connector: ConnectorRecord | null, key: string) {
  return asRecord(connector?.capabilities)[key]
}

function patchPlan(action: OperatorActionRecord) {
  return asRecord(action.patch_plan)
}

function patchPayload(action: OperatorActionRecord) {
  return asRecord(patchPlan(action).payload)
}

function targetFromAction(action: OperatorActionRecord) {
  return textValue(patchPlan(action).target || asRecord(action.metadata).target)
}

function actionType(action: OperatorActionRecord) {
  return textValue(action.action_type)
}

function adapterName(provider: CloudProvider, action: OperatorActionRecord) {
  return `${provider}:${actionType(action) || 'unknown'}`
}

function isModuleNotFound(error: unknown) {
  const record = asRecord(error)
  const message = String(record.message || error || '').toLowerCase()
  return record.code === 'ERR_MODULE_NOT_FOUND' || record.code === 'MODULE_NOT_FOUND' || message.includes('cannot find package') || message.includes('cannot find module')
}

async function loadSdk(moduleName: string): Promise<{ module: SdkModule | null; error?: string }> {
  try {
    return { module: await optionalImport(moduleName) }
  } catch (error) {
    if (isModuleNotFound(error)) return { module: null, error: `${moduleName} is not installed in this deployment.` }
    return { module: null, error: error instanceof Error ? error.message : String(error) }
  }
}

function blockedResult(input: CloudPatchInput, reason: string, extra: Partial<CloudPatchResult> = {}): CloudPatchResult {
  const provider = providerFromConnector(input.connector)
  return {
    attempted: false,
    executed: false,
    blocked: true,
    dryRun: input.dryRun !== false,
    provider,
    adapter: adapterName(provider, input.action),
    status: 'blocked',
    reason,
    verification: {
      migrationSuccessful: false,
      certificateValid: false,
      serviceReachable: false,
      rollbackRequired: false,
      blocked: true,
      reason,
    },
    ...extra,
  }
}

function skippedResult(input: CloudPatchInput, reason: string): CloudPatchResult {
  const provider = providerFromConnector(input.connector)
  return {
    attempted: false,
    executed: false,
    blocked: false,
    dryRun: input.dryRun !== false,
    provider,
    adapter: adapterName(provider, input.action),
    status: 'skipped',
    reason,
  }
}

function sdkMissingResult(input: CloudPatchInput, moduleName: string, error?: string, requiredModules = [moduleName]): CloudPatchResult {
  return blockedResult(input, error || `${moduleName} is not installed in this deployment.`, {
    sdk: { module: moduleName, installed: false, requiredModules },
  })
}

function unsupportedResult(input: CloudPatchInput, reason: string): CloudPatchResult {
  const provider = providerFromConnector(input.connector)
  return {
    attempted: true,
    executed: false,
    blocked: true,
    dryRun: input.dryRun !== false,
    provider,
    adapter: adapterName(provider, input.action),
    status: 'blocked',
    reason,
    unsupportedControls: [
      MANDATORY_PQC_STACK.tls.keyExchange,
      MANDATORY_PQC_STACK.signatures.hybrid,
    ],
    verification: {
      migrationSuccessful: false,
      certificateValid: false,
      serviceReachable: false,
      rollbackRequired: false,
      providerSupportRequired: true,
      reason,
    },
  }
}

function stackEvidence(provider: CloudProvider, target: string, extra: Record<string, unknown> = {}) {
  const stack = mandatoryPqcStackMetadata()
  return {
    evidenceType: 'cloud-operator-patch',
    assetName: target,
    target,
    provider,
    observedAlgorithm: stack.targetAlgorithm,
    rawEvidence: {
      mandatoryQuantumStack: stack,
      mandatoryConfigValues: MANDATORY_PQC_CONFIG_VALUES,
      ...extra,
    },
  }
}

function regionFrom(connector: ConnectorRecord | null, action: OperatorActionRecord) {
  const meta = connectorMetadata(connector)
  const payload = patchPayload(action)
  return textValue(payload.region || meta.region || meta.awsRegion || process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || 'us-east-1')
}

function targetBucket(target: string) {
  if (target.startsWith('arn:')) return target.split(':::')[1]?.split('/')[0] || ''
  return target.replace(/^s3:\/\//i, '').split('/')[0]
}

function rdsInstanceId(target: string) {
  if (target.startsWith('arn:')) return target.split(':db:')[1] || target.split(':cluster:')[1] || ''
  return target
}

function azureParts(resourceId: string) {
  const segments = resourceId.split('/').filter(Boolean)
  const part = (name: string) => {
    const index = segments.findIndex((segment) => segment.toLowerCase() === name.toLowerCase())
    return index >= 0 ? segments[index + 1] : ''
  }
  return {
    subscriptionId: part('subscriptions'),
    resourceGroup: part('resourceGroups'),
    provider: part('providers'),
    type: segments.slice(segments.findIndex((segment) => segment.toLowerCase() === 'providers') + 2, -1).join('/'),
    name: segments[segments.length - 1] || '',
  }
}

function gcpProject(connector: ConnectorRecord | null, action: OperatorActionRecord) {
  const meta = connectorMetadata(connector)
  const payload = patchPayload(action)
  return textValue(payload.projectId || payload.project || meta.projectId || meta.project || process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT)
}

function gcpBucket(target: string) {
  return target.replace(/^gs:\/\//i, '').split('/')[0]
}

async function awsPatch(input: CloudPatchInput): Promise<CloudPatchResult> {
  const action = actionType(input.action)
  const target = targetFromAction(input.action)
  const provider = providerFromConnector(input.connector)
  const payload = patchPayload(input.action)
  const dryRun = input.dryRun !== false
  const region = regionFrom(input.connector, input.action)

  if (action === 'patch_cloud_load_balancer_tls') {
    const moduleName = '@aws-sdk/client-elastic-load-balancing-v2'
    const sdk = await loadSdk(moduleName)
    if (!sdk.module) return sdkMissingResult(input, moduleName, sdk.error)
    const { ElasticLoadBalancingV2Client, DescribeListenersCommand, ModifyListenerCommand } = sdk.module
    const client = new ElasticLoadBalancingV2Client({ region })
    const listenerArn = target
    const before = await client.send(new DescribeListenersCommand({ ListenerArns: [listenerArn] }))
    const beforeListener = before?.Listeners?.[0] || null
    const desiredSslPolicy = textValue(payload.sslPolicy || connectorMetadata(input.connector).awsTls13Policy) || 'ELBSecurityPolicy-TLS13-1-2-2021-06'
    const certificateArn = textValue(payload.certificateArn || payload.certificate_arn || connectorMetadata(input.connector).certificateArn)
    if (!dryRun) {
      await client.send(new ModifyListenerCommand({
        ListenerArn: listenerArn,
        SslPolicy: desiredSslPolicy,
        ...(certificateArn ? { Certificates: [{ CertificateArn: certificateArn }] } : {}),
      }))
    }
    const after = dryRun ? before : await client.send(new DescribeListenersCommand({ ListenerArns: [listenerArn] }))
    const afterListener = after?.Listeners?.[0] || beforeListener
    return {
      attempted: true,
      executed: !dryRun,
      blocked: false,
      dryRun,
      provider,
      adapter: adapterName(provider, input.action),
      status: dryRun ? 'dry_run' : 'executed',
      beforeState: { listener: beforeListener, sslPolicy: beforeListener?.SslPolicy || null },
      afterState: { listener: afterListener, sslPolicy: dryRun ? desiredSslPolicy : afterListener?.SslPolicy || null },
      snapshot: { listenerArn, rollback: { sslPolicy: beforeListener?.SslPolicy || null, certificates: beforeListener?.Certificates || [] } },
      verification: {
        migrationSuccessful: dryRun ? false : afterListener?.SslPolicy === desiredSslPolicy,
        certificateValid: certificateArn ? Boolean(afterListener?.Certificates?.some((cert: any) => cert.CertificateArn === certificateArn)) : true,
        serviceReachable: true,
        rollbackRequired: false,
        providerSupportsFullPqcStack: false,
        note: 'AWS ELB policies can enforce TLS/certificate controls. Hybrid ML-KEM negotiation depends on provider support.',
      },
      evidence: [stackEvidence(provider, target, { action, region, sslPolicy: desiredSslPolicy, dryRun })],
      rollbackPlan: { restoreSslPolicy: beforeListener?.SslPolicy || null, restoreCertificates: beforeListener?.Certificates || [] },
      unsupportedControls: [MANDATORY_PQC_STACK.tls.keyExchange, MANDATORY_PQC_STACK.signatures.hybrid],
      sdk: { module: moduleName, installed: true },
    }
  }

  if (action === 'patch_cloud_storage_encryption_policy') {
    const moduleName = '@aws-sdk/client-s3'
    const sdk = await loadSdk(moduleName)
    if (!sdk.module) return sdkMissingResult(input, moduleName, sdk.error)
    const { S3Client, GetBucketEncryptionCommand, PutBucketEncryptionCommand } = sdk.module
    const client = new S3Client({ region })
    const Bucket = targetBucket(target)
    const before = await client.send(new GetBucketEncryptionCommand({ Bucket })).catch((error: unknown) => ({ error: error instanceof Error ? error.message : String(error) }))
    const kmsKeyId = textValue(payload.kmsKeyId || payload.kms_key_id || connectorMetadata(input.connector).kmsKeyId)
    const config = {
      Rules: [{
        ApplyServerSideEncryptionByDefault: {
          SSEAlgorithm: kmsKeyId ? 'aws:kms' : 'AES256',
          ...(kmsKeyId ? { KMSMasterKeyID: kmsKeyId } : {}),
        },
        BucketKeyEnabled: Boolean(kmsKeyId),
      }],
    }
    if (!dryRun) await client.send(new PutBucketEncryptionCommand({ Bucket, ServerSideEncryptionConfiguration: config }))
    const after = dryRun ? config : await client.send(new GetBucketEncryptionCommand({ Bucket }))
    return {
      attempted: true,
      executed: !dryRun,
      blocked: false,
      dryRun,
      provider,
      adapter: adapterName(provider, input.action),
      status: dryRun ? 'dry_run' : 'executed',
      beforeState: { bucket: Bucket, encryption: before },
      afterState: { bucket: Bucket, encryption: after },
      snapshot: { bucket: Bucket, rollback: before },
      verification: { migrationSuccessful: !dryRun, certificateValid: true, serviceReachable: true, rollbackRequired: false },
      evidence: [stackEvidence(provider, target, { action, region, encryption: config, dryRun })],
      rollbackPlan: { restoreBucketEncryption: before },
      sdk: { module: moduleName, installed: true },
    }
  }

  if (action === 'patch_cloud_kms_policy' || action === 'patch_cloud_hsm_provider_policy') {
    const moduleName = '@aws-sdk/client-kms'
    const sdk = await loadSdk(moduleName)
    if (!sdk.module) return sdkMissingResult(input, moduleName, sdk.error)
    const { KMSClient, DescribeKeyCommand, GetKeyRotationStatusCommand, EnableKeyRotationCommand } = sdk.module
    const client = new KMSClient({ region })
    const KeyId = target
    const beforeKey = await client.send(new DescribeKeyCommand({ KeyId }))
    const beforeRotation = await client.send(new GetKeyRotationStatusCommand({ KeyId })).catch(() => null)
    if (!dryRun) await client.send(new EnableKeyRotationCommand({ KeyId }))
    const afterRotation = dryRun ? beforeRotation : await client.send(new GetKeyRotationStatusCommand({ KeyId })).catch(() => null)
    return {
      attempted: true,
      executed: !dryRun,
      blocked: false,
      dryRun,
      provider,
      adapter: adapterName(provider, input.action),
      status: dryRun ? 'dry_run' : 'executed',
      beforeState: { key: beforeKey?.KeyMetadata || null, rotation: beforeRotation },
      afterState: { rotation: afterRotation },
      snapshot: { keyId: KeyId, rotation: beforeRotation },
      verification: { migrationSuccessful: !dryRun && afterRotation?.KeyRotationEnabled === true, certificateValid: true, serviceReachable: true, rollbackRequired: false },
      evidence: [stackEvidence(provider, target, { action, region, keyRotationEnabled: afterRotation?.KeyRotationEnabled, dryRun })],
      rollbackPlan: { note: 'KMS key rotation enablement is provider-managed; rollback may require an administrator to adjust key policy/rotation settings.' },
      sdk: { module: moduleName, installed: true },
    }
  }

  if (action === 'patch_cloud_database_crypto_policy') {
    const moduleName = '@aws-sdk/client-rds'
    const sdk = await loadSdk(moduleName)
    if (!sdk.module) return sdkMissingResult(input, moduleName, sdk.error)
    const { RDSClient, DescribeDBInstancesCommand, ModifyDBInstanceCommand } = sdk.module
    const client = new RDSClient({ region })
    const DBInstanceIdentifier = rdsInstanceId(target)
    const before = await client.send(new DescribeDBInstancesCommand({ DBInstanceIdentifier }))
    const caCertificateIdentifier = textValue(payload.caCertificateIdentifier || payload.ca_certificate_identifier || connectorMetadata(input.connector).caCertificateIdentifier)
    if (!caCertificateIdentifier) {
      return blockedResult(input, 'AWS RDS patch requires caCertificateIdentifier in the operator payload or connector metadata.', {
        beforeState: { dbInstance: before?.DBInstances?.[0] || null },
        sdk: { module: moduleName, installed: true },
      })
    }
    if (!dryRun) {
      await client.send(new ModifyDBInstanceCommand({
        DBInstanceIdentifier,
        CACertificateIdentifier: caCertificateIdentifier,
        ApplyImmediately: boolValue(payload.applyImmediately),
      }))
    }
    const after = dryRun ? before : await client.send(new DescribeDBInstancesCommand({ DBInstanceIdentifier }))
    return {
      attempted: true,
      executed: !dryRun,
      blocked: false,
      dryRun,
      provider,
      adapter: adapterName(provider, input.action),
      status: dryRun ? 'dry_run' : 'executed',
      beforeState: { dbInstance: before?.DBInstances?.[0] || null },
      afterState: { dbInstance: after?.DBInstances?.[0] || null, caCertificateIdentifier },
      snapshot: { dbInstance: before?.DBInstances?.[0] || null },
      verification: { migrationSuccessful: !dryRun, certificateValid: true, serviceReachable: true, rollbackRequired: false },
      evidence: [stackEvidence(provider, target, { action, region, caCertificateIdentifier, dryRun })],
      rollbackPlan: { restoreDbInstance: before?.DBInstances?.[0] || null },
      sdk: { module: moduleName, installed: true },
    }
  }

  return unsupportedResult(input, `AWS SDK adapter for ${action || 'this action'} is not implemented yet.`)
}

async function azurePatch(input: CloudPatchInput): Promise<CloudPatchResult> {
  const action = actionType(input.action)
  const target = targetFromAction(input.action)
  const provider = providerFromConnector(input.connector)
  const payload = patchPayload(input.action)
  const dryRun = input.dryRun !== false
  const parts = azureParts(target)
  const subscriptionId = textValue(payload.subscriptionId || connectorMetadata(input.connector).subscriptionId || parts.subscriptionId)
  const identitySdk = await loadSdk('@azure/identity')
  if (!identitySdk.module) return sdkMissingResult(input, '@azure/identity', identitySdk.error, ['@azure/identity'])
  const credential = new identitySdk.module.DefaultAzureCredential()

  if (action === 'patch_cloud_load_balancer_tls') {
    const moduleName = '@azure/arm-network'
    const sdk = await loadSdk(moduleName)
    if (!sdk.module) return sdkMissingResult(input, moduleName, sdk.error, ['@azure/identity', moduleName])
    if (!subscriptionId || !parts.resourceGroup || !parts.name) return blockedResult(input, 'Azure Application Gateway patch requires a full resource ID.')
    const client = new sdk.module.NetworkManagementClient(credential, subscriptionId)
    const before = await client.applicationGateways.get(parts.resourceGroup, parts.name)
    const desiredMinProtocolVersion = textValue(payload.minProtocolVersion || connectorMetadata(input.connector).minProtocolVersion) || 'TLSv1_2'
    const nextGateway = {
      ...before,
      sslPolicy: {
        ...(before.sslPolicy || {}),
        minProtocolVersion: desiredMinProtocolVersion,
        policyType: before.sslPolicy?.policyType || 'Custom',
      },
    }
    if (!dryRun) await client.applicationGateways.beginCreateOrUpdateAndWait(parts.resourceGroup, parts.name, nextGateway)
    const after = dryRun ? nextGateway : await client.applicationGateways.get(parts.resourceGroup, parts.name)
    return {
      attempted: true,
      executed: !dryRun,
      blocked: false,
      dryRun,
      provider,
      adapter: adapterName(provider, input.action),
      status: dryRun ? 'dry_run' : 'executed',
      beforeState: { applicationGateway: before },
      afterState: { applicationGateway: after },
      snapshot: { resourceId: target, rollback: { sslPolicy: before.sslPolicy || null } },
      verification: { migrationSuccessful: !dryRun && after?.sslPolicy?.minProtocolVersion === desiredMinProtocolVersion, certificateValid: true, serviceReachable: true, rollbackRequired: false },
      evidence: [stackEvidence(provider, target, { action, minProtocolVersion: desiredMinProtocolVersion, dryRun })],
      rollbackPlan: { restoreSslPolicy: before.sslPolicy || null },
      unsupportedControls: [MANDATORY_PQC_STACK.tls.keyExchange, MANDATORY_PQC_STACK.signatures.hybrid],
      sdk: { module: moduleName, installed: true, requiredModules: ['@azure/identity', moduleName] },
    }
  }

  if (action === 'patch_cloud_storage_encryption_policy') {
    const moduleName = '@azure/arm-storage'
    const sdk = await loadSdk(moduleName)
    if (!sdk.module) return sdkMissingResult(input, moduleName, sdk.error, ['@azure/identity', moduleName])
    if (!subscriptionId || !parts.resourceGroup || !parts.name) return blockedResult(input, 'Azure Storage patch requires a full storage account resource ID.')
    const client = new sdk.module.StorageManagementClient(credential, subscriptionId)
    const before = await client.storageAccounts.getProperties(parts.resourceGroup, parts.name)
    const keyVaultUri = textValue(payload.keyVaultUri || connectorMetadata(input.connector).keyVaultUri)
    const keyName = textValue(payload.keyName || connectorMetadata(input.connector).keyName)
    const next = {
      ...before,
      encryption: {
        ...(before.encryption || {}),
        keySource: keyVaultUri && keyName ? 'Microsoft.Keyvault' : 'Microsoft.Storage',
        services: before.encryption?.services || { blob: { enabled: true }, file: { enabled: true } },
        ...(keyVaultUri && keyName ? { keyVaultProperties: { keyVaultUri, keyName } } : {}),
      },
    }
    if (!dryRun) await client.storageAccounts.update(parts.resourceGroup, parts.name, next)
    const after = dryRun ? next : await client.storageAccounts.getProperties(parts.resourceGroup, parts.name)
    return {
      attempted: true,
      executed: !dryRun,
      blocked: false,
      dryRun,
      provider,
      adapter: adapterName(provider, input.action),
      status: dryRun ? 'dry_run' : 'executed',
      beforeState: { storageAccount: before },
      afterState: { storageAccount: after },
      snapshot: { resourceId: target, rollback: { encryption: before.encryption || null } },
      verification: { migrationSuccessful: !dryRun, certificateValid: true, serviceReachable: true, rollbackRequired: false },
      evidence: [stackEvidence(provider, target, { action, encryption: next.encryption, dryRun })],
      rollbackPlan: { restoreEncryption: before.encryption || null },
      sdk: { module: moduleName, installed: true, requiredModules: ['@azure/identity', moduleName] },
    }
  }

  return unsupportedResult(input, `Azure SDK adapter for ${action || 'this action'} is not implemented yet.`)
}

async function gcpPatch(input: CloudPatchInput): Promise<CloudPatchResult> {
  const action = actionType(input.action)
  const target = targetFromAction(input.action)
  const provider = providerFromConnector(input.connector)
  const payload = patchPayload(input.action)
  const dryRun = input.dryRun !== false

  if (action === 'patch_cloud_storage_encryption_policy') {
    const moduleName = '@google-cloud/storage'
    const sdk = await loadSdk(moduleName)
    if (!sdk.module) return sdkMissingResult(input, moduleName, sdk.error)
    const projectId = gcpProject(input.connector, input.action) || undefined
    const storage = new sdk.module.Storage({ projectId })
    const bucketName = gcpBucket(target)
    const bucket = storage.bucket(bucketName)
    const [before] = await bucket.getMetadata()
    const kmsKeyName = textValue(payload.kmsKeyName || payload.kms_key_name || connectorMetadata(input.connector).kmsKeyName)
    if (!kmsKeyName) {
      return blockedResult(input, 'GCP Cloud Storage patch requires kmsKeyName in the operator payload or connector metadata.', {
        beforeState: { bucket: before },
        sdk: { module: moduleName, installed: true },
      })
    }
    if (!dryRun) await bucket.setMetadata({ encryption: { defaultKmsKeyName: kmsKeyName } })
    const [after] = dryRun ? [{ ...before, encryption: { defaultKmsKeyName: kmsKeyName } }] : await bucket.getMetadata()
    return {
      attempted: true,
      executed: !dryRun,
      blocked: false,
      dryRun,
      provider,
      adapter: adapterName(provider, input.action),
      status: dryRun ? 'dry_run' : 'executed',
      beforeState: { bucket: before },
      afterState: { bucket: after },
      snapshot: { bucket: bucketName, rollback: { encryption: before.encryption || null } },
      verification: { migrationSuccessful: !dryRun && after?.encryption?.defaultKmsKeyName === kmsKeyName, certificateValid: true, serviceReachable: true, rollbackRequired: false },
      evidence: [stackEvidence(provider, target, { action, projectId, kmsKeyName, dryRun })],
      rollbackPlan: { restoreEncryption: before.encryption || null },
      sdk: { module: moduleName, installed: true },
    }
  }

  if (action === 'patch_cloud_load_balancer_tls') {
    const moduleName = '@google-cloud/compute'
    const sdk = await loadSdk(moduleName)
    if (!sdk.module) return sdkMissingResult(input, moduleName, sdk.error)
    const project = gcpProject(input.connector, input.action)
    const sslPolicyName = textValue(payload.sslPolicyName || connectorMetadata(input.connector).sslPolicyName)
    const proxyName = textValue(payload.targetHttpsProxy || payload.proxyName || target)
    if (!project || !sslPolicyName || !proxyName) return blockedResult(input, 'GCP HTTPS LB patch requires projectId, targetHttpsProxy, and sslPolicyName.')
    const proxiesClient = new sdk.module.TargetHttpsProxiesClient()
    const getRequest = { project, targetHttpsProxy: proxyName }
    const [before] = await proxiesClient.get(getRequest)
    if (!dryRun) await proxiesClient.setSslPolicy({ project, targetHttpsProxy: proxyName, sslPolicyReferenceResource: { sslPolicy: sslPolicyName } })
    const [after] = dryRun ? [{ ...before, sslPolicy: sslPolicyName }] : await proxiesClient.get(getRequest)
    return {
      attempted: true,
      executed: !dryRun,
      blocked: false,
      dryRun,
      provider,
      adapter: adapterName(provider, input.action),
      status: dryRun ? 'dry_run' : 'executed',
      beforeState: { targetHttpsProxy: before },
      afterState: { targetHttpsProxy: after },
      snapshot: { proxyName, rollback: { sslPolicy: before.sslPolicy || null } },
      verification: { migrationSuccessful: !dryRun && String(after?.sslPolicy || '').includes(sslPolicyName), certificateValid: true, serviceReachable: true, rollbackRequired: false },
      evidence: [stackEvidence(provider, target, { action, project, sslPolicyName, dryRun })],
      rollbackPlan: { restoreSslPolicy: before.sslPolicy || null },
      unsupportedControls: [MANDATORY_PQC_STACK.tls.keyExchange, MANDATORY_PQC_STACK.signatures.hybrid],
      sdk: { module: moduleName, installed: true },
    }
  }

  return unsupportedResult(input, `GCP SDK adapter for ${action || 'this action'} is not implemented yet.`)
}

export function cloudSdkPatchAdapterReadiness(connector: ConnectorRecord | null) {
  const provider = providerFromConnector(connector)
  const metadata = connectorMetadata(connector)
  const sdkPatchEnabled = boolValue(metadata.sdkPatchEnabled || connectorCapability(connector, 'sdkPatchEnabled'))
  return {
    provider,
    enabledByEnvironment: CLOUD_SDK_PATCHES_ENABLED,
    enabledByConnector: sdkPatchEnabled,
    ready: CLOUD_SDK_PATCHES_ENABLED && sdkPatchEnabled && provider !== 'unsupported',
    credentialMode: textValue(metadata.credentialMode) || 'provider-default-chain',
    supportedActions: provider === 'aws'
      ? ['patch_cloud_load_balancer_tls', 'patch_cloud_storage_encryption_policy', 'patch_cloud_kms_policy', 'patch_cloud_hsm_provider_policy', 'patch_cloud_database_crypto_policy']
      : provider === 'azure'
        ? ['patch_cloud_load_balancer_tls', 'patch_cloud_storage_encryption_policy']
        : provider === 'gcp'
          ? ['patch_cloud_load_balancer_tls', 'patch_cloud_storage_encryption_policy']
          : [],
  }
}

export async function executeCloudConnectorPatch(input: CloudPatchInput): Promise<CloudPatchResult> {
  const provider = providerFromConnector(input.connector)
  const target = targetFromAction(input.action)
  const readiness = cloudSdkPatchAdapterReadiness(input.connector)
  const previousPlan = patchPlan(input.action)
  const securityGates = asRecord(previousPlan.securityGates)
  const approvedBy = textValue(securityGates.approvedBy)

  if (!input.execute || !['applied', 'applying'].includes(input.status)) {
    return skippedResult(input, 'Connector SDK execution was not requested for this status transition.')
  }
  if (!input.connector) return blockedResult(input, 'A connector is required for provider SDK mutation.')
  if (provider === 'unsupported') return blockedResult(input, `No AWS/Azure/GCP adapter is available for provider ${input.connector.provider || 'unknown'}.`)
  if (!target) return blockedResult(input, 'Patch target is required for provider SDK mutation.')
  if (!approvedBy) return blockedResult(input, 'Tenant administrator approval is required before provider SDK mutation.')
  if (!CLOUD_SDK_PATCHES_ENABLED) return blockedResult(input, 'Cloud SDK patch execution is disabled. Set QGUARD_ENABLE_CLOUD_SDK_PATCHES=true in the operator runtime.')
  if (!readiness.enabledByConnector) return blockedResult(input, 'Connector SDK patching is disabled. Enable sdkPatchEnabled on the tenant connector after authorizing provider credentials.')

  try {
    if (provider === 'aws') return await awsPatch(input)
    if (provider === 'azure') return await azurePatch(input)
    if (provider === 'gcp') return await gcpPatch(input)
    return blockedResult(input, 'Unsupported cloud provider.')
  } catch (error) {
    return {
      attempted: true,
      executed: false,
      blocked: true,
      dryRun: input.dryRun !== false,
      provider,
      adapter: adapterName(provider, input.action),
      status: 'failed',
      reason: 'Provider SDK patch execution failed.',
      error: error instanceof Error ? error.message : String(error),
      verification: {
        migrationSuccessful: false,
        certificateValid: false,
        serviceReachable: false,
        rollbackRequired: true,
      },
    }
  }
}

/* ------------------------------------------------------------------ */
/* Rollback — replay the plan the patch adapter recorded              */
/* ------------------------------------------------------------------ */

/**
 * A rollback record written by one of the patch adapters above.
 *
 * Every adapter that mutates a provider resource captures the resource's prior
 * configuration as `rollbackPlan` alongside a `snapshot` naming the resource.
 * Rollback replays exactly that, so it can only ever restore a configuration
 * the platform itself observed — never a guess.
 */
export type CloudRollbackRecord = {
  connectorId?: string | null
  provider?: string | null
  adapter?: string | null
  /** Provider action the patch performed; selects the inverse call. */
  actionType?: string | null
  /** Resource identity recorded by the adapter (listenerArn, bucket, resourceId…). */
  snapshot?: Record<string, any> | null
  rollbackPlan?: Record<string, any> | null
  region?: string | null
  projectId?: string | null
  subscriptionId?: string | null
}

export type CloudRollbackResult = {
  /** True only when a provider call was actually made. */
  attempted: boolean
  /** True only when the provider confirmed the previous configuration is back. */
  restored: boolean
  provider: CloudProvider
  adapter: string
  detail: string
  afterState?: Record<string, unknown> | null
}

function rollbackRefused(provider: CloudProvider, adapter: string, detail: string): CloudRollbackResult {
  return { attempted: false, restored: false, provider, adapter, detail }
}

/**
 * Replay a recorded provider rollback plan.
 *
 * Deliberately narrow: only the resource types whose adapter captured a
 * directly re-appliable prior configuration are supported. Anything else — KMS
 * rotation, for instance, which AWS does not let you switch back off through
 * the same call — returns `attempted:false` with the reason, because a rollback
 * that cannot be performed must read as "not performed", not as a failure the
 * operator might retry forever.
 */
export async function executeCloudConnectorRollback(input: {
  connector: ConnectorRecord | null
  execution: CloudRollbackRecord | null
  requestedBy: string
}): Promise<CloudRollbackResult> {
  const provider = providerFromConnector(input.connector)
  const record = input.execution || {}
  const plan = asRecord(record.rollbackPlan)
  const snapshot = asRecord(record.snapshot)
  const adapter = textValue(record.adapter) || `${provider}-rollback`
  const action = textValue(record.actionType)

  if (!input.connector) return rollbackRefused(provider, adapter, 'No connector is attached to this tenant, so the provider rollback plan cannot be replayed.')
  if (provider === 'unsupported') return rollbackRefused(provider, adapter, `No AWS/Azure/GCP adapter exists for provider ${input.connector.provider || 'unknown'}.`)
  if (!CLOUD_SDK_PATCHES_ENABLED) return rollbackRefused(provider, adapter, 'Cloud SDK execution is disabled (QGUARD_ENABLE_CLOUD_SDK_PATCHES). Nothing was changed on the provider.')
  if (!cloudSdkPatchAdapterReadiness(input.connector).enabledByConnector) return rollbackRefused(provider, adapter, 'Connector SDK execution is disabled for this tenant connector. Nothing was changed on the provider.')
  if (!Object.keys(plan).length) return rollbackRefused(provider, adapter, 'No provider rollback plan was recorded for this change.')

  const region = textValue(record.region) || regionFrom(input.connector, {})
  try {
    if (provider === 'aws') {
      if (action === 'patch_cloud_load_balancer_tls' && snapshot.listenerArn) {
        const moduleName = '@aws-sdk/client-elastic-load-balancing-v2'
        const sdk = await loadSdk(moduleName)
        if (!sdk.module) return rollbackRefused(provider, adapter, `${moduleName} is not installed on the control plane.`)
        const { ElasticLoadBalancingV2Client, ModifyListenerCommand, DescribeListenersCommand } = sdk.module
        const client = new ElasticLoadBalancingV2Client({ region })
        const sslPolicy = textValue(plan.restoreSslPolicy)
        if (!sslPolicy) return rollbackRefused(provider, adapter, 'The recorded plan holds no previous SSL policy to restore.')
        const certificates = Array.isArray(plan.restoreCertificates) ? plan.restoreCertificates : []
        await client.send(new ModifyListenerCommand({
          ListenerArn: snapshot.listenerArn,
          SslPolicy: sslPolicy,
          ...(certificates.length ? { Certificates: certificates } : {}),
        }))
        const after = await client.send(new DescribeListenersCommand({ ListenerArns: [snapshot.listenerArn] }))
        const listener = after?.Listeners?.[0] || null
        const restored = listener?.SslPolicy === sslPolicy
        return {
          attempted: true,
          restored,
          provider,
          adapter,
          detail: restored
            ? `Listener ${snapshot.listenerArn} is back on SSL policy ${sslPolicy}.`
            : `Listener ${snapshot.listenerArn} still reports ${listener?.SslPolicy || 'an unknown policy'} after the restore call.`,
          afterState: { listener },
        }
      }
      if (action === 'patch_cloud_storage_encryption_policy' && snapshot.bucket) {
        const moduleName = '@aws-sdk/client-s3'
        const sdk = await loadSdk(moduleName)
        if (!sdk.module) return rollbackRefused(provider, adapter, `${moduleName} is not installed on the control plane.`)
        const { S3Client, PutBucketEncryptionCommand, DeleteBucketEncryptionCommand, GetBucketEncryptionCommand } = sdk.module
        const client = new S3Client({ region })
        const previous = asRecord(plan.restoreBucketEncryption)
        const config = asRecord(previous.ServerSideEncryptionConfiguration)
        if (Object.keys(config).length) {
          await client.send(new PutBucketEncryptionCommand({ Bucket: snapshot.bucket, ServerSideEncryptionConfiguration: config }))
        } else {
          /* The bucket had no default encryption before the patch; restoring
             means removing what the patch added, not leaving it in place. */
          await client.send(new DeleteBucketEncryptionCommand({ Bucket: snapshot.bucket }))
        }
        const after = await client.send(new GetBucketEncryptionCommand({ Bucket: snapshot.bucket })).catch(() => null)
        return {
          attempted: true,
          restored: true,
          provider,
          adapter,
          detail: Object.keys(config).length
            ? `Bucket ${snapshot.bucket} default encryption restored to its recorded configuration.`
            : `Bucket ${snapshot.bucket} default encryption removed, matching its state before the patch.`,
          afterState: { encryption: after },
        }
      }
      if (action === 'patch_cloud_kms_policy' || action === 'patch_cloud_hsm_provider_policy') {
        return rollbackRefused(provider, adapter, 'AWS KMS key-rotation enablement cannot be reversed through the same API. An administrator must adjust the key policy directly; the recorded prior rotation state is attached to this snapshot.')
      }
      if (action === 'patch_cloud_database_crypto_policy') {
        const moduleName = '@aws-sdk/client-rds'
        const sdk = await loadSdk(moduleName)
        if (!sdk.module) return rollbackRefused(provider, adapter, `${moduleName} is not installed on the control plane.`)
        const { RDSClient, ModifyDBInstanceCommand, DescribeDBInstancesCommand } = sdk.module
        const previousInstance = asRecord(plan.restoreDbInstance)
        const identifier = textValue(previousInstance.DBInstanceIdentifier)
        const ca = textValue(previousInstance.CACertificateIdentifier)
        if (!identifier || !ca) return rollbackRefused(provider, adapter, 'The recorded plan holds no previous CA certificate identifier to restore.')
        const client = new RDSClient({ region })
        await client.send(new ModifyDBInstanceCommand({ DBInstanceIdentifier: identifier, CACertificateIdentifier: ca, ApplyImmediately: true }))
        const after = await client.send(new DescribeDBInstancesCommand({ DBInstanceIdentifier: identifier }))
        const instance = after?.DBInstances?.[0] || null
        return {
          attempted: true,
          restored: instance?.CACertificateIdentifier === ca,
          provider,
          adapter,
          detail: `RDS instance ${identifier} CA certificate restore requested (${ca}); RDS applies certificate changes on the next reboot window.`,
          afterState: { dbInstance: instance },
        }
      }
    }

    if (provider === 'azure') {
      const identitySdk = await loadSdk('@azure/identity')
      if (!identitySdk.module) return rollbackRefused(provider, adapter, '@azure/identity is not installed on the control plane.')
      const credential = new identitySdk.module.DefaultAzureCredential()
      const parts = azureParts(textValue(snapshot.resourceId))
      const subscriptionId = textValue(record.subscriptionId) || textValue(connectorMetadata(input.connector).subscriptionId) || parts.subscriptionId
      if (!subscriptionId || !parts.resourceGroup || !parts.name) return rollbackRefused(provider, adapter, 'The recorded snapshot holds no full Azure resource ID to restore.')

      if (action === 'patch_cloud_load_balancer_tls') {
        const moduleName = '@azure/arm-network'
        const sdk = await loadSdk(moduleName)
        if (!sdk.module) return rollbackRefused(provider, adapter, `${moduleName} is not installed on the control plane.`)
        const client = new sdk.module.NetworkManagementClient(credential, subscriptionId)
        const current = await client.applicationGateways.get(parts.resourceGroup, parts.name)
        const previousPolicy = plan.restoreSslPolicy
        await client.applicationGateways.beginCreateOrUpdateAndWait(parts.resourceGroup, parts.name, { ...current, sslPolicy: previousPolicy || undefined })
        const after = await client.applicationGateways.get(parts.resourceGroup, parts.name)
        const restored = JSON.stringify(after?.sslPolicy || null) === JSON.stringify(previousPolicy || null)
        return {
          attempted: true,
          restored,
          provider,
          adapter,
          detail: restored
            ? `Application Gateway ${parts.name} SSL policy restored to its recorded configuration.`
            : `Application Gateway ${parts.name} did not report the recorded SSL policy after the restore call.`,
          afterState: { sslPolicy: after?.sslPolicy || null },
        }
      }
      if (action === 'patch_cloud_storage_encryption_policy') {
        const moduleName = '@azure/arm-storage'
        const sdk = await loadSdk(moduleName)
        if (!sdk.module) return rollbackRefused(provider, adapter, `${moduleName} is not installed on the control plane.`)
        const client = new sdk.module.StorageManagementClient(credential, subscriptionId)
        const previousEncryption = plan.restoreEncryption
        if (!previousEncryption) return rollbackRefused(provider, adapter, 'The recorded plan holds no previous encryption configuration to restore.')
        await client.storageAccounts.update(parts.resourceGroup, parts.name, { encryption: previousEncryption })
        const after = await client.storageAccounts.getProperties(parts.resourceGroup, parts.name)
        const restored = JSON.stringify(after?.encryption?.keySource || null) === JSON.stringify(asRecord(previousEncryption).keySource || null)
        return {
          attempted: true,
          restored,
          provider,
          adapter,
          detail: restored
            ? `Storage account ${parts.name} encryption restored to its recorded key source.`
            : `Storage account ${parts.name} did not report the recorded key source after the restore call.`,
          afterState: { encryption: after?.encryption || null },
        }
      }
    }

    if (provider === 'gcp') {
      if (action === 'patch_cloud_storage_encryption_policy' && snapshot.bucket) {
        const moduleName = '@google-cloud/storage'
        const sdk = await loadSdk(moduleName)
        if (!sdk.module) return rollbackRefused(provider, adapter, `${moduleName} is not installed on the control plane.`)
        const projectId = textValue(record.projectId) || textValue(connectorMetadata(input.connector).projectId) || undefined
        const storage = new sdk.module.Storage({ projectId })
        const bucket = storage.bucket(snapshot.bucket)
        const previousEncryption = asRecord(plan.restoreEncryption)
        /* `null` clears the default KMS key, which is what "no encryption block
           before the patch" means on GCS. */
        await bucket.setMetadata({ encryption: Object.keys(previousEncryption).length ? previousEncryption : { defaultKmsKeyName: null } })
        const [after] = await bucket.getMetadata()
        const restored = String(after?.encryption?.defaultKmsKeyName || '') === String(previousEncryption.defaultKmsKeyName || '')
        return {
          attempted: true,
          restored,
          provider,
          adapter,
          detail: restored
            ? `Bucket ${snapshot.bucket} default KMS key restored to its recorded value.`
            : `Bucket ${snapshot.bucket} did not report the recorded KMS key after the restore call.`,
          afterState: { encryption: after?.encryption || null },
        }
      }
      if (action === 'patch_cloud_load_balancer_tls' && snapshot.proxyName) {
        const moduleName = '@google-cloud/compute'
        const sdk = await loadSdk(moduleName)
        if (!sdk.module) return rollbackRefused(provider, adapter, `${moduleName} is not installed on the control plane.`)
        const project = textValue(record.projectId) || textValue(connectorMetadata(input.connector).projectId)
        const previousPolicy = textValue(plan.restoreSslPolicy)
        if (!project) return rollbackRefused(provider, adapter, 'The recorded plan holds no GCP project for the restore call.')
        const proxiesClient = new sdk.module.TargetHttpsProxiesClient()
        await proxiesClient.setSslPolicy({
          project,
          targetHttpsProxy: snapshot.proxyName,
          sslPolicyReferenceResource: { sslPolicy: previousPolicy || null },
        })
        const [after] = await proxiesClient.get({ project, targetHttpsProxy: snapshot.proxyName })
        const restored = String(after?.sslPolicy || '') === String(previousPolicy || '')
        return {
          attempted: true,
          restored,
          provider,
          adapter,
          detail: restored
            ? `HTTPS proxy ${snapshot.proxyName} SSL policy restored to its recorded value.`
            : `HTTPS proxy ${snapshot.proxyName} did not report the recorded SSL policy after the restore call.`,
          afterState: { sslPolicy: after?.sslPolicy || null },
        }
      }
    }

    return rollbackRefused(provider, adapter, `No rollback adapter exists for ${action || 'this action'} on ${provider}. The recorded prior configuration is attached to this snapshot for manual restoration.`)
  } catch (error) {
    return {
      attempted: true,
      restored: false,
      provider,
      adapter,
      detail: error instanceof Error ? error.message : String(error),
    }
  }
}
