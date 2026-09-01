/**
 * Connector engine registration — SERVER ONLY.
 *
 * Importing this module makes the live Kubernetes, container registry and
 * cloud engines executable. It is deliberately the ONLY place that imports
 * them, and nothing in a browser bundle may import it.
 *
 * WHY THIS FILE EXISTS: the cloud adapters sign requests with `node:crypto` and
 * the registry adapter uses `Buffer`. When `registry.ts` imported them
 * directly, every browser surface that reads the engine registry — the engine
 * selector, the profile list, the health panel — pulled that module graph into
 * the client bundle and the page failed to load with "Module node:crypto has
 * been externalized for browser compatibility".
 *
 * Keeping the descriptors as data in `registry.ts` and the implementations
 * behind this side-effect import makes the boundary structural: the browser
 * cannot accidentally reach a Node-only engine, because it has no import path
 * to one.
 */

import { registerConnectorEngines } from '../registry';
import { liveKubernetesEngine } from './k8s-live';
import { registryEngine } from './registry-scan';
import { cloudCryptoEngine, cloudInventoryEngine } from './cloud';

registerConnectorEngines([liveKubernetesEngine, registryEngine, cloudInventoryEngine, cloudCryptoEngine]);

export { liveKubernetesEngine, registryEngine, cloudInventoryEngine, cloudCryptoEngine };
