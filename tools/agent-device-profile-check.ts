import assert from 'node:assert/strict'
import { exclusivelyObservedByAgent, deviceAliasMap, foldDeviceAssetGraph, observationDescriptor } from '../src/lib/agent-installer/device-profile'
import { cbomComponentKey, partitionAssetInventory } from '../src/lib/scanner/asset-components'
import { algorithmFamily } from '../src/lib/governance/subjects'
import { buildAssetRegister } from '../src/lib/assets/asset-register'

let passed = 0
const check = (condition: unknown, label: string) => { assert.ok(condition, label); passed++; console.log(`PASS ${label}`) }
const agent = { id: 'agent-a', user_id: 'tenant-a', name: 'TestVM_Collector', hostname: 'TestVM' }
const profile = { id: 'device-a', user_id: 'tenant-a', name: 'TestVM', type: 'device', metadata: { deviceProfile: { agentId: 'agent-a', hostname: 'TestVM', subjects: [{ id: 'cert-a' }, { id: 'cert-b' }] } } }
const alias = (id: string, agentId = 'agent-a') => ({ id, user_id: 'tenant-a', name: `Certificate ${id}`, metadata: { scanSources: [{ agentId }], consolidatedIntoAssetId: 'device-a' } })
const web = { id: 'web-a', user_id: 'tenant-a', name: '21st.dev', type: 'web-application', metadata: {} }
check(exclusivelyObservedByAgent(alias('cert-a'), agent), 'proven agent-owned observations are eligible for device consolidation')
check(!exclusivelyObservedByAgent(web, agent), 'unrelated website is not eligible')
check(!exclusivelyObservedByAgent({ id: 'ambiguous', user_id: agent.user_id, metadata: { source: `agent:${agent.name}` } }, agent), 'a matching display name alone cannot authorize consolidation')
check(!exclusivelyObservedByAgent({ ...alias('cert-a'), user_id: 'tenant-b' }, agent), 'foreign-tenant asset is refused')
check(!exclusivelyObservedByAgent({ ...alias('shared'), metadata: { scanSources: [{ agentId: 'agent-a' }, { agentId: 'agent-b' }] } }, agent), 'a shared asset is never silently claimed by one agent')
check(!exclusivelyObservedByAgent({ ...alias('manual'), metadata: { bindingTarget: true, createdVia: 'agent-binding', scanSources: [{ agentId: 'agent-a' }] } }, agent), 'explicit application binding is preserved')
check(deviceAliasMap([profile, alias('cert-a'), web]).get('cert-a') === 'device-a', 'audit alias resolves to the one real profile')
check(deviceAliasMap([{ ...profile, user_id: 'tenant-b' }, alias('cert-a')]).size === 0, 'cross-tenant alias is refused')
check(deviceAliasMap([alias('cert-a')]).size === 0, 'missing canonical profile never hides evidence')
const component = (id: string, asset_id: string, subject: string) => ({ id, asset_id, name: 'signature: RSA-2048', algorithm: 'RSA-2048', item_type: 'signature', is_vulnerable: true, metadata: { discoveredTarget: subject, evidenceRecord: { agentId: 'agent-a', assetName: subject } } })
const first = component('c1', 'cert-a', 'Certificate A')
const second = component('c2', 'cert-b', 'Certificate B')
const graph = foldDeviceAssetGraph({ assets: [profile, alias('cert-a'), alias('cert-b'), web], inventory: [first, second], exposures: [{ id: 'e1', asset_id: 'cert-a' }], results: [{ id: 'r1', asset_id: 'cert-b' }], vulnerabilities: [] })
check(graph.assets.length === 2 && graph.assets.some((asset) => asset.id === 'web-a'), 'asset quantity counts one device and the independent website')
check(graph.inventory.length === 2 && graph.inventory.every((row) => row.asset_id === 'device-a'), 'all inventory rows are retained under the canonical profile')
check(graph.exposures[0].id === 'e1' && graph.results[0].id === 'r1', 'original evidence and result IDs survive graph consolidation')
check(first.asset_id === 'cert-a', 'read projection never mutates the persisted historical input')
check(cbomComponentKey(graph.inventory[0]) !== cbomComponentKey(graph.inventory[1]), 'two certificates sharing RSA remain distinct components inside one device')
const repeatScan = { ...graph.inventory[0], id: 'next-scan' }
check(cbomComponentKey(graph.inventory[0]) === cbomComponentKey(repeatScan), 'repeat scans do not duplicate the same component identity')
const certificate = observationDescriptor({ evidence_type: 'crypto-library', asset_type: 'certificate', asset_name: 'CN=Root A', certificate_fingerprint: 'fingerprint-a' })!
check(certificate.itemType === 'certificate' && certificate.algorithm === 'Unknown', 'legacy store certificates are represented without inventing their algorithm')
const rawCertificate = { id: 'ungraded', asset_id: 'device-a', item_type: certificate.itemType, name: certificate.name, algorithm: certificate.algorithm, is_vulnerable: false, is_quantum_safe: false }
const partition = partitionAssetInventory([...graph.inventory, rawCertificate], algorithmFamily)
check(partition.counts.components === 3 && partition.counts.unclassified === 1, 'ungraded certificates appear as unclassified components, never falsely safe')
check(observationDescriptor({ evidence_type: 'config-reference', asset_type: 'host_process', asset_name: 'StartMenu' }) === null, 'a generic process observation is not fabricated into a cryptographic component')
const register = buildAssetRegister({ snapshot: { summary: {}, assets: { assets: [{ ...profile, cryptoInventory: [...graph.inventory, rawCertificate], postureObservations: [{ id: 'f1', asset_id: profile.id, name: 'Rule: Insecure config', algorithm: 'Insecure config', is_vulnerable: true, exposure_level: 'high' }] }] } } })
check(register.rows.length === 1 && register.rows[0].componentList.length === 3, 'device register carries all measured cryptographic components')
check(register.rows[0].postureList.length === 1 && register.rows[0].deviceProfile?.hostname === 'TestVM', 'configuration findings and host identity remain in the same asset profile')
check(register.rows[0].componentList.some((row) => row.observedSubject === 'Certificate B'), 'component details retain their individual observed subjects')
console.log(`Device-profile checks passed: ${passed}`)
