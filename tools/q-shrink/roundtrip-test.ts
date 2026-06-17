/**
 * Q-Shrink Vault Engine™ — Round-Trip Reversibility Test
 *
 * Proves the core contract: restore(optimize(x)) === x, byte-for-byte, across
 * compressible, incompressible, deduplicated, empty, and bundled inputs — plus
 * tamper detection. Runs under Node (CompressionStream is a global in Node 18+).
 *
 *   npx tsx tools/q-shrink/roundtrip-test.ts
 */

import { webcrypto } from 'node:crypto'
import {
  analyzeFiles,
  isQShrinkPackage,
  optimizeBundle,
  optimizeFile,
  restoreFile,
  restorePackage,
} from '../../src/lib/vault/q-shrink/index.ts'

let passed = 0
let failed = 0

function check(name: string, cond: boolean, detail = ''): void {
  if (cond) {
    passed++
    console.log(`  ✓ ${name}`)
  } else {
    failed++
    console.error(`  ✗ ${name} ${detail}`)
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n)
  // Fill in <=65536 chunks (webcrypto limit).
  for (let off = 0; off < n; off += 65536) {
    webcrypto.getRandomValues(out.subarray(off, Math.min(n, off + 65536)))
  }
  return out
}

function textBlob(repeat: number): Uint8Array {
  const line = 'The quantum vault optimizes plaintext before post-quantum encryption. '
  return new TextEncoder().encode(line.repeat(repeat))
}

async function roundTrip(name: string, data: Uint8Array, mime?: string): Promise<void> {
  const { package: pkg, applied, report } = await optimizeFile(data, { path: name, mime })
  const restored = await restoreFile(pkg, report)
  const ratio = report.logicalSize > 0 ? (report.optimizedSize / report.logicalSize) : 1
  check(
    `${name} (${data.length}B) round-trips`,
    bytesEqual(restored, data),
    `restored ${restored.length}B`,
  )
  check(
    `${name} never inflates (stored ${pkg.length}B <= ${data.length}B)`,
    pkg.length <= data.length || !applied,
  )
  console.log(
    `      applied=${applied} stored=${pkg.length}B reduction=${report.reductionPercent.toFixed(1)}% ` +
      `codec=${report.codec} dedup=${report.dedupRatio.toFixed(2)}x ratio=${(ratio).toFixed(3)} ` +
      `entropy=${report.entropyBitsPerByte.toFixed(2)}`,
  )
}

async function main(): Promise<void> {
  console.log('\nQ-Shrink Vault Engine — round-trip reversibility\n')
  check('CompressionStream available', typeof CompressionStream !== 'undefined')

  console.log('\n[single-file round trips]')
  await roundTrip('empty.bin', new Uint8Array(0))
  await roundTrip('one-byte.bin', new Uint8Array([0x42]))
  await roundTrip('tiny.txt', new TextEncoder().encode('hello vault'))
  await roundTrip('log.txt', textBlob(5000), 'text/plain') // highly compressible
  await roundTrip('random.bin', randomBytes(512 * 1024), 'application/octet-stream') // incompressible
  await roundTrip('precompressed.jpg', randomBytes(256 * 1024), 'image/jpeg') // type-skipped

  // Heavy intra-file deduplication: a 16 KiB block repeated 256 times (4 MiB).
  const block = randomBytes(16 * 1024)
  const dupe = new Uint8Array(block.length * 256)
  for (let i = 0; i < 256; i++) dupe.set(block, i * block.length)
  await roundTrip('backup.img', dupe, 'application/octet-stream')

  // Structured binary with embedded text regions.
  const mixed = new Uint8Array(1024 * 1024)
  mixed.set(textBlob(2000), 0)
  mixed.set(randomBytes(256 * 1024), 400 * 1024)
  await roundTrip('mixed.dat', mixed)

  console.log('\n[dedup correctness]')
  {
    const block2 = randomBytes(16 * 1024)
    const dupe2 = new Uint8Array(block2.length * 100)
    for (let i = 0; i < 100; i++) dupe2.set(block2, i * block2.length)
    const r = await optimizeFile(dupe2, { path: 'dedup.bin' })
    check('100x duplicate block dedupes to few unique chunks', r.report.uniqueChunks < r.report.totalChunks / 10,
      `unique=${r.report.uniqueChunks} total=${r.report.totalChunks}`)
    check('100x duplicate block achieves >80% reduction', r.report.reductionPercent > 80,
      `${r.report.reductionPercent.toFixed(1)}%`)
  }

  console.log('\n[folder bundle cross-file dedup]')
  {
    // Shared content is a large random blob so content-defined chunk boundaries
    // are stable and identical across files (the realistic dedup case: the same
    // attachment/library/base-image embedded in several files).
    const shared = randomBytes(256 * 1024)
    const fileA = new Uint8Array([...shared, ...new TextEncoder().encode('UNIQUE-TAIL-A')])
    const fileB = new Uint8Array([...shared, ...new TextEncoder().encode('UNIQUE-TAIL-B')])
    const fileC = new Uint8Array([...new TextEncoder().encode('UNIQUE-HEAD-C-'), ...shared])
    const inputs = [
      { path: 'docs/a.bin', data: fileA },
      { path: 'docs/b.bin', data: fileB },
      { path: 'docs/c.bin', data: fileC },
    ]
    const { package: pkg, report } = await optimizeBundle(inputs)
    check('bundle is a QSHRN1 package', isQShrinkPackage(pkg))
    const restored = await restorePackage(pkg)
    check('bundle restores all 3 files', restored.length === 3)
    let allMatch = true
    for (let i = 0; i < inputs.length; i++) {
      if (!bytesEqual(inputs[i].data, restored[i].data)) allMatch = false
      if (inputs[i].path !== restored[i].path) allMatch = false
    }
    check('bundle files restore byte-for-byte with paths', allMatch)
    check('cross-file dedup found shared chunks', report.dedupRatio > 1.5,
      `dedupRatio=${report.dedupRatio.toFixed(2)}`)
    console.log(`      bundle stored=${pkg.length}B logical=${report.logicalSize}B reduction=${report.reductionPercent.toFixed(1)}%`)
  }

  console.log('\n[integrity / tamper detection]')
  {
    const data = textBlob(4000)
    const { package: pkg } = await optimizeFile(data, { path: 'tamper.txt' })
    check('optimized file is a QSHRN1 package', isQShrinkPackage(pkg))
    // Flip a byte deep in the payload section.
    const tampered = pkg.slice()
    tampered[tampered.length - 5] ^= 0xff
    let threw = false
    try {
      await restorePackage(tampered)
    } catch {
      threw = true
    }
    check('tampered container is rejected on restore', threw)
  }

  console.log('\n[magic-collision safety]')
  {
    // A real, non-optimized user file whose plaintext *begins with the QSHRN1
    // magic* (e.g. a binary asset, or a previously-downloaded vault container that
    // is re-uploaded). If optimize emitted this as a raw passthrough, restore would
    // mis-detect it as a container and destroy it. optimize must wrap it instead so
    // the magic stays authoritative and the round-trip is exact.
    const magicHeader = new Uint8Array([0x51, 0x53, 0x48, 0x52, 0x4e, 0x31, 0x01]) // "QSHRN1" + v1

    // Case 1: incompressible (random) body — the no-inflation path would normally
    // store raw, which is exactly where the collision used to cause data loss.
    const collide = randomBytes(100 * 1024)
    collide.set(magicHeader, 0)
    const r1 = await optimizeFile(collide, { path: 'asset.bin', mime: 'application/octet-stream' })
    check('magic-collision (incompressible) is wrapped, not passed through raw',
      isQShrinkPackage(r1.package) && r1.applied)
    check('magic-collision (incompressible) restores byte-for-byte',
      bytesEqual(await restoreFile(r1.package, r1.report), collide))

    // Case 2: small file that is exactly the 7 magic bytes (below the 18-byte
    // header floor). It can never be a valid container, so it safely passes
    // through and restores unchanged.
    const r2 = await optimizeFile(magicHeader, { path: 'tiny-magic.bin' })
    check('sub-header magic file restores byte-for-byte',
      bytesEqual(await restoreFile(r2.package, r2.report), magicHeader))
  }

  console.log('\n[analyzer dry-run]')
  {
    const analysis = await analyzeFiles([{ path: 'a.log', data: textBlob(6000) }])
    check('analyzer reports reversible=true', analysis.reversible)
    check('analyzer reports a positive reduction', analysis.reductionPercent > 50,
      `${analysis.reductionPercent.toFixed(1)}%`)
  }

  console.log(`\nResult: ${passed} passed, ${failed} failed\n`)
  if (failed > 0) process.exit(1)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
