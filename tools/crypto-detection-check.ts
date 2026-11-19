/**
 * Cryptographic detection catalogue — regression suite.
 *
 * The repository/dependency scanner reported ZERO findings for source that
 * demonstrably used MD5 and RSA. The cause was not the pipeline: the pattern
 * catalogue matched algorithm NAMES (`/\bRSA\b/`, case-sensitive) while real
 * code passes lowercase strings to factories — `createHash('md5')`,
 * `generateKeyPairSync('rsa')`. Nothing detected the idioms, so "0 findings"
 * was indistinguishable from "clean repository".
 *
 * This suite feeds each engine content that MUST trigger (positive control),
 * content that MUST NOT (false-positive control), and asserts the catalogue's
 * structural invariants.
 *
 *   npx tsx tools/crypto-detection-check.ts
 */
import { EventEmitter } from 'node:events'
import type { ClientRequest, IncomingMessage, RequestOptions } from 'node:http'
import https from 'node:https'
import { Readable } from 'node:stream'
import { mock } from 'node:test'
import {
  CRYPTO_PATTERNS,
  PRIORITY_EXTENSIONS,
  SCANNABLE_EXTENSIONS,
  SCANNABLE_FILENAMES,
  isScannablePath,
} from '../src/lib/scanner/web-scanner/crypto-patterns'
import { scanWebCrypto } from '../src/lib/scanner/web-scanner/web-crypto-scanner'
import { safeLookup } from '../src/lib/scanner/public-scan/safe-dns'

let failures = 0
function assert(condition: boolean, label: string) {
  if (condition) console.log(`  ok   ${label}`)
  else {
    failures += 1
    console.log(`  FAIL ${label}`)
  }
}

/** The matcher github-scanner runs, line by line, over each file. */
function detect(content: string): Array<{ algorithm: string; label: string; threatLevel: string; line: number }> {
  const out: Array<{ algorithm: string; label: string; threatLevel: string; line: number }> = []
  const lines = content.split('\n')
  for (let i = 0; i < lines.length; i++) {
    for (const pattern of CRYPTO_PATTERNS) {
      if (lines[i].match(pattern.regex)) {
        out.push({ algorithm: pattern.algorithm, label: pattern.label, threatLevel: pattern.threatLevel, line: i + 1 })
      }
    }
  }
  return out
}

const algosIn = (content: string) => detect(content).map((h) => h.algorithm.toLowerCase()).join(' | ')

/* ------------------------------------------------------ structural checks -- */

function verifyCatalogue() {
  console.log('\n=== Catalogue structure ===')
  const ids = CRYPTO_PATTERNS.map((p) => p.id)
  assert(new Set(ids).size === ids.length, `Pattern ids are unique (${ids.length})`)
  assert(
    CRYPTO_PATTERNS.every((p) => p.label && p.algorithm && p.category && p.description),
    'Every pattern carries a label, algorithm, category and description',
  )
  assert(
    CRYPTO_PATTERNS.every((p) => ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE'].includes(p.threatLevel)),
    'Every pattern carries a valid threat level',
  )
  const pqc = CRYPTO_PATTERNS.filter((p) => p.category === 'Post-Quantum')
  assert(pqc.length >= 5, `Post-quantum algorithms are detectable (${pqc.length} patterns)`)
  assert(
    pqc.every((p) => p.threatLevel === 'SAFE'),
    'Every post-quantum pattern is rated SAFE — a PQC-migrated repo must be able to score as such',
  )
  const deps = CRYPTO_PATTERNS.filter((p) => p.category === 'Dependency')
  assert(deps.length >= 5, `Dependency manifests are detectable (${deps.length} patterns)`)
  // Regex objects with /g are stateful across .match() calls on the same object.
  assert(
    CRYPTO_PATTERNS.every((p) => !p.regex.global),
    'No pattern uses the /g flag (lastIndex would leak between files)',
  )
}

/* -------------------------------------------------- language positive set -- */

const LANGUAGE_CASES: Array<{ language: string; source: string; expect: string[] }> = [
  {
    language: 'Node.js / TypeScript',
    source: `
      import { createHash, createCipheriv, generateKeyPairSync, createECDH } from 'crypto'
      const h = createHash('md5')
      const s = createHash('sha1')
      const ok = createHash('sha256')
      const c = createCipheriv('des-ede3-cbc', key, iv)
      const r = createCipheriv('rc4', key, null)
      const weak = createCipheriv('aes-128-ecb', key, null)
      const good = createCipheriv('aes-256-gcm', key, iv)
      const kp = generateKeyPairSync('rsa', { modulusLength: 2048 })
      const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' })
      const dh = createECDH('secp256k1')
      const token = Math.random().toString(36) + '_secret'
    `,
    expect: ['md5', 'sha-1', 'rsa', 'legacy symmetric cipher', 'aes-ecb', 'ecc/dh', 'ecdh/dh', 'non-csprng'],
  },
  {
    language: 'Python',
    source: `
      import hashlib
      from cryptography.hazmat.primitives.asymmetric import rsa, ec
      from cryptography.hazmat.primitives.ciphers import algorithms
      h = hashlib.md5()
      s = hashlib.sha1()
      ok = hashlib.sha3_256()
      key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
      curve = ec.SECP256R1()
      legacy = algorithms.TripleDES(k)
    `,
    expect: ['md5/sha-1', 'rsa', 'ecdsa/ecdh', 'legacy symmetric cipher'],
  },
  {
    language: 'Java',
    source: `
      MessageDigest md = MessageDigest.getInstance("MD5");
      Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");
      Cipher e = Cipher.getInstance("AES/ECB/PKCS5Padding");
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
      Signature sig = Signature.getInstance("SHA256withECDSA");
    `,
    expect: ['md5/sha-1', 'legacy symmetric cipher', 'aes-ecb', 'dsa/dh/eddsa', 'rsa/ecdsa/dsa signature'],
  },
  {
    language: 'Go',
    source: `
      import (
        "crypto/md5"
        "crypto/rc4"
        "crypto/ecdsa"
        "crypto/elliptic"
      )
      c := elliptic.P256()
      tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
    `,
    expect: ['md5/sha-1/des/rc4', 'ecdsa/ed25519/dsa', 'tls trust bypass'],
  },
  {
    language: '.NET / C#',
    source: `
      using System.Security.Cryptography;
      var md5 = MD5.Create();
      var sha1 = new SHA1Managed();
      var des = new TripleDESCryptoServiceProvider();
      var rsa = new RSACryptoServiceProvider(2048);
    `,
    expect: ['md5/sha-1', 'legacy symmetric cipher', 'rsa'],
  },
  {
    language: 'Rust',
    source: `
      use md5::Md5;
      use sha1::Sha1;
      use x25519_dalek::EphemeralSecret;
      use k256::ecdsa::SigningKey;
    `,
    expect: ['md5/sha-1', 'ecc/eddsa'],
  },
  {
    language: 'PHP / Ruby',
    source: `
      $h = md5($data);
      $s = sha1($data);
      digest = Digest::MD5.hexdigest(data)
      key = OpenSSL::PKey::RSA.new(2048)
    `,
    expect: ['md5/sha-1', 'rsa/dsa/dh/ec'],
  },
  {
    language: 'Apple / Swift',
    source: `
      CC_MD5(data, len, &digest)
      let alg = kCCAlgorithm3DES
      let key = SecKeyCreateRandomKey(attrs, &error)
    `,
    expect: ['md5/sha-1/3des/rc4', 'rsa'],
  },
]

function verifyLanguageDetection() {
  console.log('\n=== Positive control: source-code detection by language ===')
  for (const testCase of LANGUAGE_CASES) {
    const found = algosIn(testCase.source)
    const missing = testCase.expect.filter((expected) => !found.includes(expected))
    assert(missing.length === 0, `${testCase.language}: detects ${testCase.expect.length} planted primitives${missing.length ? ` — MISSING ${missing.join(', ')}` : ''}`)
  }
}

/* ------------------------------------------------------- PQC + manifests -- */

function verifyPostQuantumDetection() {
  console.log('\n=== Positive control: post-quantum detection ===')
  const cases: Array<[string, string]> = [
    ['ML-KEM', `const kem = new MlKem768(); // ML-KEM-768`],
    ['Kyber', `use pqcrypto_kyber::kyber768;`],
    ['ML-DSA', `signature = ML-DSA-65.sign(msg)`],
    ['Dilithium', `import { dilithium3 } from 'pqc'`],
    ['SLH-DSA / SPHINCS+', `alg = "SPHINCS+-SHA2-128s"`],
    ['Falcon', `sig = Falcon-512.verify(m)`],
    ['liboqs', `#include <oqs/oqs.h>\nlink liboqs`],
    ['Hybrid group', `curves = X25519MLKEM768`],
  ]
  for (const [label, source] of cases) {
    const hits = detect(source)
    const pq = hits.filter((h) => h.threatLevel === 'SAFE')
    assert(pq.length > 0, `${label} is detected and rated SAFE (${pq.map((h) => h.algorithm).join(', ') || 'NONE'})`)
  }
}

function verifyDependencyDetection() {
  console.log('\n=== Positive control: dependency manifests ===')
  const manifests: Array<[string, string, string]> = [
    ['package.json', `{ "dependencies": { "crypto-js": "^4.1.1", "jsonwebtoken": "^9.0.0" } }`, 'client/server crypto library'],
    ['requirements.txt', `pycryptodome==3.19.0\ncryptography>=41.0`, 'python crypto library'],
    ['go.mod', `require golang.org/x/crypto v0.17.0`, 'go crypto module'],
    ['Cargo.toml', `[dependencies]\nring = "0.17"\nrsa = "0.9"`, 'rust crypto crate'],
    ['pom.xml', `<artifactId>bcprov-jdk18on</artifactId>`, 'java crypto library'],
    ['Gemfile', `gem "openssl"\ngem "jwt"`, 'crypto library'],
  ]
  for (const [file, content, expected] of manifests) {
    const found = algosIn(content)
    assert(found.includes(expected), `${file}: dependency detected (${found || 'NONE'})`)
    assert(isScannablePath(file), `${file}: is selected for scanning`)
  }
}

function verifyFileSelection() {
  console.log('\n=== File selection ===')
  for (const path of [
    'go.mod', 'go.sum', 'Gemfile', 'Dockerfile', 'Pipfile', 'requirements.txt',
    'src/app/crypto.ts', 'pkg/tls.go', 'Cargo.toml', 'pom.xml', 'config/nginx.conf',
    'certs/server.pem', '.env',
  ]) {
    assert(isScannablePath(path), `selected: ${path}`)
  }
  for (const path of ['README.md', 'docs/guide.md', 'assets/logo.png', 'LICENSE', 'video.mp4']) {
    assert(!isScannablePath(path), `not selected: ${path}`)
  }
  assert(SCANNABLE_FILENAMES.size > 20, `Extension-less manifests are enumerated (${SCANNABLE_FILENAMES.size})`)
  assert(SCANNABLE_EXTENSIONS.has('.txt') && SCANNABLE_EXTENSIONS.has('.mod'), 'requirements.txt and go.mod extensions are scannable')
  assert(PRIORITY_EXTENSIONS.size > 0, 'Priority extensions are configured')
}

/* ------------------------------------------------ false-positive controls -- */

function verifyNoFalsePositives() {
  console.log('\n=== False-positive control ===')
  const benign: Array<[string, string]> = [
    ['plain prose', 'This function returns a list of items. It is a good idea to cache them.'],
    ['random seed', 'const seed = Math.floor(Date.now() / 1000); rng.setSeed(seed);'],
    ['ordinary identifiers', 'const description = "hello"; let index = 0; return items.map(i => i.id);'],
    ['HTML markup', '<div class="container"><span>Ideas</span></div>'],
    ['SQL', 'SELECT id, name FROM users WHERE created_at > NOW() - INTERVAL 7 DAY;'],
  ]
  for (const [label, content] of benign) {
    const hits = detect(content)
    assert(hits.length === 0, `${label}: no spurious detections${hits.length ? ` — got ${hits.map((h) => h.label).join(', ')}` : ''}`)
  }

  // "seed" must not be mistaken for the SEED block cipher.
  assert(
    detect('let seed = 42; regenerate(seed);').length === 0,
    'the word "seed" does not trigger the SEED cipher pattern',
  )
  // "idea" must not be mistaken for the IDEA cipher.
  assert(
    detect('// this is a good idea for later').length === 0,
    'the word "idea" does not trigger the IDEA cipher pattern',
  )
}

/* --------------------------------------------------- client-side scanner -- */

const VULNERABLE_PAGE = `<!doctype html><html><head><script>
const alg = { name: "RSA-OAEP", modulusLength: 2048 };
await crypto.subtle.generateKey(alg, true, ["encrypt"]);
const sigAlg = "ECDSA"; const curve = "P-256";
import CryptoJS from "crypto-js";
const digest = await crypto.subtle.digest("SHA-1", buf);
const aead = "AES-GCM";
const pq = "X25519MLKEM768";
</script><script src="/bundle.js"></script></head><body>x</body></html>`

const BUNDLE = `const p = "RSASSA-PKCS1-v1_5"; nacl.sign(m,k); const k = "-----BEGIN RSA PRIVATE KEY-----";`

async function verifyClientScanner() {
  console.log('\n=== Positive control: client-side web crypto scanner ===')
  const scannerRequests: Array<{ path: string; lookup: RequestOptions['lookup'] }> = []
  const requestFixture = mock.method(https, 'request', ((url: URL, options: RequestOptions, receive: (response: IncomingMessage) => void) => {
    scannerRequests.push({ path: url.pathname, lookup: options.lookup })
    const bundle = url.pathname === '/bundle.js'
    const response = Object.assign(Readable.from([Buffer.from(bundle ? BUNDLE : VULNERABLE_PAGE)]), {
      statusCode: 200,
      headers: { 'content-type': bundle ? 'application/javascript' : 'text/html' },
    }) as IncomingMessage
    return Object.assign(new EventEmitter(), {
      end: () => queueMicrotask(() => receive(response)),
    }) as ClientRequest
  }) as typeof https.request)
  const result = await scanWebCrypto('https://example.com/').finally(() => requestFixture.mock.restore())
  assert(scannerRequests.map(({ path }) => path).join(',') === '/,/bundle.js', 'reads the page and its linked bundle')
  assert(scannerRequests.every(({ lookup }) => lookup === safeLookup), 'all resource connections use the public DNS policy')

  const names = result.patterns.map((p) => p.algorithm).join(' | ')
  assert(result.patterns.length > 0, `finds planted client-side patterns (${result.patterns.length})`)
  for (const expected of ['RSA-OAEP', 'ECDSA', 'SHA-1', 'AES-GCM']) {
    assert(names.includes(expected), `detects ${expected}`)
  }
  assert(names.includes('Hybrid ML-KEM'), 'detects a hybrid post-quantum group in client code')
  assert(
    result.patterns.some((p) => p.source.includes('/bundle.js')),
    'fetches and scans external bundles, not only inline script',
  )
  assert(
    result.patterns.some((p) => p.algorithm === 'Private Key'),
    'detects an embedded private key inside an external bundle',
  )
  assert(
    result.patterns.some((p) => p.threatLevel === 'SAFE'),
    'can credit quantum-safe client-side cryptography, not only flag failures',
  )
}

/* ------------------------------------------------------------------ driver */

async function main() {
  console.log(`Catalogue: ${CRYPTO_PATTERNS.length} source patterns`)
  verifyCatalogue()
  verifyLanguageDetection()
  verifyPostQuantumDetection()
  verifyDependencyDetection()
  verifyFileSelection()
  verifyNoFalsePositives()
  await verifyClientScanner()

  console.log('')
  if (failures > 0) {
    console.error(`${failures} crypto detection check(s) FAILED.`)
    process.exitCode = 1
    return
  }
  console.log('All crypto detection checks passed.')
  process.exitCode = 0
}

main()
