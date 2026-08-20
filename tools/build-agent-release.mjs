#!/usr/bin/env node
/**
 * Qguard Helix Agent — release builder.
 *
 * Bundles tools/qguard-agent/agent.ts (plus its collector modules and the shared
 * mandatory PQC stack) into ONE dependency-free CommonJS file that runs on any
 * Node 18+ host, then publishes a manifest carrying the version, byte size and
 * SHA-256 digest.
 *
 * The digest is the integrity anchor for the whole installer chain (spec §7,
 * §22): every generated installer embeds it and refuses to execute a runtime
 * whose hash does not match.
 *
 * Artifacts are written to tools/qguard-agent/dist/ — deliberately NOT public/,
 * because the runtime is served only through the authenticated
 * /api/v1/agent-installer/runtime endpoint.
 *
 * Usage: npm run agent:release
 */

import { build } from 'esbuild'
import { createHash } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '..')
const entry = path.join(repoRoot, 'tools', 'qguard-agent', 'agent.ts')
const outDir = path.join(repoRoot, 'tools', 'qguard-agent', 'dist')

/** Read AGENT_VERSION from the shared release module so there is one source of truth. */
async function readAgentVersion() {
  const source = await readFile(path.join(repoRoot, 'src', 'lib', 'agent-installer', 'agent-release.ts'), 'utf8')
  const match = source.match(/AGENT_VERSION\s*=\s*'([^']+)'/)
  if (!match) throw new Error('AGENT_VERSION not found in src/lib/agent-installer/agent-release.ts')
  return match[1]
}

async function main() {
  const version = await readAgentVersion()
  await mkdir(outDir, { recursive: true })

  const outFile = path.join(outDir, 'qguard-agent.cjs')

  const result = await build({
    entryPoints: [entry],
    outfile: outFile,
    bundle: true,
    platform: 'node',
    target: 'node18',
    format: 'cjs',
    minify: false, // auditable by the customer — this runs on their infrastructure
    sourcemap: false,
    legalComments: 'none',
    logLevel: 'info',
    metafile: true,
    banner: {
      js: [
        '/*',
        ' * Qguard Helix Lightweight Agent',
        ` * Version ${version}`,
        ' *',
        ' * Single-file collector runtime. No third-party dependencies: Node core only.',
        ' * Verify this file against the SHA-256 published by your Qguard Helix control',
        ' * plane before executing it.',
        ' */',
      ].join('\n'),
    },
    define: {
      'process.env.QGUARD_AGENT_BUILD_VERSION': JSON.stringify(version),
    },
  })

  const bytes = await readFile(outFile)
  const sha256 = createHash('sha256').update(bytes).digest('hex')
  const sha3 = createHash('sha3-256').update(bytes).digest('hex')

  const externalDeps = Object.keys(result.metafile.inputs)
    .filter((input) => input.includes('node_modules'))
  if (externalDeps.length > 0) {
    throw new Error(`Agent bundle must stay dependency-free, found: ${externalDeps.join(', ')}`)
  }

  const manifest = {
    product: 'qguard-helix-agent',
    version,
    channel: 'stable',
    runtime: {
      filename: 'qguard-agent.cjs',
      bytes: bytes.length,
      sha256,
      sha3_256: sha3,
      requiresNode: '>=18',
      format: 'cjs',
      dependencies: 'none (Node core only)',
    },
    builtAt: new Date().toISOString(),
    sourceModules: Object.keys(result.metafile.inputs).sort(),
  }

  await writeFile(path.join(outDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
  await writeFile(path.join(outDir, 'qguard-agent.cjs.sha256'), `${sha256}  qguard-agent.cjs\n`, 'utf8')

  console.log('')
  console.log(`  Qguard Helix Agent ${version}`)
  console.log(`  ${outFile}`)
  console.log(`  ${(bytes.length / 1024).toFixed(1)} KB   sha256 ${sha256}`)
  console.log(`  ${manifest.sourceModules.length} source modules, 0 external dependencies`)
  console.log('')
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
