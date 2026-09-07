/**
 * Dependency Analysis Engine (§13, §24).
 *
 * Parses every dependency manifest and lockfile in the corpus across the nine
 * ecosystems the platform supports, then answers the question the CBOM actually
 * needs: WHICH DEPENDENCIES BRING CRYPTOGRAPHY, and what does each one bring?
 *
 * §13 "Do not invent CVEs."  There is no vulnerability database in this engine
 * and none is faked. Advisory intelligence is a separate, pluggable layer; when
 * it is absent the engine says so in coverage rather than reporting zero known
 * vulnerabilities, because zero-because-unchecked and zero-because-clean are
 * not the same answer.
 *
 * The crypto relevance table is the valuable part: `jsonwebtoken` implies RSA
 * and ECDSA token signing; `liboqs` implies ML-KEM and ML-DSA; `bcrypt` implies
 * password hashing and nothing quantum-relevant at all. That mapping is what
 * turns a dependency list into the `Application → jsonwebtoken → OpenSSL → RSA
 * → Quantum Vulnerable` chain §24 asks for.
 */

import type { CryptoRole } from '../types';
import type { EngineContext, EngineResult, ExposureEngine, WorkspaceFile } from '../engine-contract';
import { buildEvidence, buildFinding, completed, reportStride } from '../engine-contract';
import { canonicalAlgorithmName, classifyQuantum, severityFor, describeAlgorithm } from '../algorithms';

/* ───────────────────────────────────────────────────────────── ecosystems ── */

export type Ecosystem =
  | 'npm' | 'pypi' | 'maven' | 'gradle' | 'nuget' | 'go' | 'cargo' | 'composer'
  | 'rubygems' | 'cocoapods' | 'swiftpm' | 'pub' | 'hex' | 'unknown';

export interface ParsedDependency {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  direct: boolean;
  /** Where it was declared. */
  file: string;
  line?: number;
  /** Dev/test-only dependency. */
  scope?: 'runtime' | 'development' | 'test' | 'optional' | 'peer' | 'build';
}

/* ──────────────────────────────────────────── crypto relevance catalogue ─── */

export interface CryptoDependency {
  /** Package name, exact or a prefix ending in `/` or `:`. */
  match: string;
  ecosystems: Ecosystem[];
  /** Algorithms this package brings, canonical names. */
  algorithms: string[];
  role: CryptoRole;
  library?: string;
  note: string;
}

export const CRYPTO_DEPENDENCIES: CryptoDependency[] = [
  /* ── Node / npm ─────────────────────────────────────────────────────── */
  { match: 'jsonwebtoken', ecosystems: ['npm'], algorithms: ['RSA', 'ECDSA', 'HMAC'], role: 'token-signing', note: 'Signs and verifies JWTs; RS*/ES* algorithms are quantum-vulnerable, HS* are not.' },
  { match: 'jose', ecosystems: ['npm'], algorithms: ['RSA', 'ECDSA', 'Ed25519', 'AES'], role: 'token-signing', note: 'JOSE/JWS/JWE implementation covering RSA, ECDSA and EdDSA.' },
  { match: 'node-forge', ecosystems: ['npm'], algorithms: ['RSA', 'AES', 'SHA-1', 'MD5'], role: 'unknown', library: 'forge', note: 'Pure-JS crypto toolkit; ships legacy primitives including MD5 and SHA-1.' },
  { match: 'bcrypt', ecosystems: ['npm', 'pypi', 'rubygems'], algorithms: ['bcrypt'], role: 'password-derivation', note: 'Password hashing only — not a quantum migration candidate.' },
  { match: 'bcryptjs', ecosystems: ['npm'], algorithms: ['bcrypt'], role: 'password-derivation', note: 'Password hashing only.' },
  { match: 'argon2', ecosystems: ['npm', 'pypi', 'cargo'], algorithms: ['Argon2'], role: 'password-derivation', note: 'Memory-hard password hashing.' },
  { match: 'crypto-js', ecosystems: ['npm'], algorithms: ['AES', 'SHA-2', 'MD5', 'SHA-1'], role: 'encryption', note: 'Browser crypto library; also exposes MD5 and SHA-1.' },
  { match: 'tweetnacl', ecosystems: ['npm'], algorithms: ['X25519', 'Ed25519', 'ChaCha20-Poly1305'], role: 'unknown', library: 'NaCl', note: 'Curve25519-based; quantum-vulnerable asymmetric primitives.' },
  { match: 'libsodium', ecosystems: ['npm', 'pypi', 'composer', 'cargo'], algorithms: ['X25519', 'Ed25519', 'ChaCha20-Poly1305', 'Argon2'], role: 'unknown', library: 'libsodium', note: 'Modern crypto library; asymmetric halves are Curve25519 and quantum-vulnerable.' },
  { match: 'node-jose', ecosystems: ['npm'], algorithms: ['RSA', 'ECDSA', 'AES'], role: 'token-signing', note: 'JOSE implementation.' },
  { match: 'openpgp', ecosystems: ['npm'], algorithms: ['RSA', 'ECDSA', 'AES'], role: 'encryption', note: 'OpenPGP; RSA and ECC key material is quantum-vulnerable.' },
  { match: 'ssh2', ecosystems: ['npm'], algorithms: ['RSA', 'ECDSA', 'Ed25519', 'Diffie-Hellman'], role: 'authentication', note: 'SSH client/server; host and user keys are quantum-vulnerable.' },
  { match: 'node-rsa', ecosystems: ['npm'], algorithms: ['RSA'], role: 'unknown', note: 'RSA key generation and operations.' },
  { match: 'elliptic', ecosystems: ['npm'], algorithms: ['ECDSA', 'ECDH'], role: 'unknown', note: 'Elliptic-curve implementation.' },
  { match: 'liboqs-node', ecosystems: ['npm'], algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA'], role: 'unknown', library: 'liboqs', note: 'Open Quantum Safe bindings — post-quantum primitives.' },
  { match: '@noble/post-quantum', ecosystems: ['npm'], algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA'], role: 'unknown', note: 'Audited JS post-quantum primitives.' },
  { match: '@noble/curves', ecosystems: ['npm'], algorithms: ['ECDSA', 'Ed25519', 'X25519'], role: 'unknown', note: 'Elliptic curves; quantum-vulnerable.' },
  { match: 'axios', ecosystems: ['npm'], algorithms: ['TLS'], role: 'tls', note: 'HTTP client — inherits the runtime TLS stack.' },

  /* ── Python ─────────────────────────────────────────────────────────── */
  { match: 'cryptography', ecosystems: ['pypi'], algorithms: ['RSA', 'ECDSA', 'ECDH', 'AES', 'SHA-2', 'Ed25519'], role: 'unknown', library: 'OpenSSL', note: 'Python cryptography library, backed by OpenSSL.' },
  { match: 'pycryptodome', ecosystems: ['pypi'], algorithms: ['RSA', 'AES', 'DSA', 'SHA-2'], role: 'unknown', note: 'PyCryptodome primitives.' },
  { match: 'pycrypto', ecosystems: ['pypi'], algorithms: ['RSA', 'AES', 'DES', 'MD5'], role: 'unknown', note: 'Unmaintained since 2014 — replace with pycryptodome.' },
  { match: 'pyjwt', ecosystems: ['pypi'], algorithms: ['RSA', 'ECDSA', 'HMAC'], role: 'token-signing', note: 'JWT signing and verification.' },
  { match: 'paramiko', ecosystems: ['pypi'], algorithms: ['RSA', 'ECDSA', 'Ed25519', 'Diffie-Hellman'], role: 'authentication', note: 'SSH implementation.' },
  { match: 'pyopenssl', ecosystems: ['pypi'], algorithms: ['RSA', 'ECDSA', 'TLS'], role: 'tls', library: 'OpenSSL', note: 'OpenSSL bindings.' },
  { match: 'passlib', ecosystems: ['pypi'], algorithms: ['bcrypt', 'Argon2', 'PBKDF2'], role: 'password-derivation', note: 'Password hashing framework.' },
  { match: 'oqs', ecosystems: ['pypi'], algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA'], role: 'unknown', library: 'liboqs', note: 'Open Quantum Safe Python bindings.' },
  { match: 'requests', ecosystems: ['pypi'], algorithms: ['TLS'], role: 'tls', note: 'HTTP client — inherits the runtime TLS stack.' },

  /* ── Java / Maven / Gradle ──────────────────────────────────────────── */
  { match: 'org.bouncycastle', ecosystems: ['maven', 'gradle'], algorithms: ['RSA', 'ECDSA', 'AES', 'ML-KEM', 'ML-DSA'], role: 'unknown', library: 'Bouncy Castle', note: 'Bouncy Castle — carries both classical and post-quantum providers depending on version.' },
  { match: 'io.jsonwebtoken', ecosystems: ['maven', 'gradle'], algorithms: ['RSA', 'ECDSA', 'HMAC'], role: 'token-signing', note: 'JJWT token signing.' },
  { match: 'com.nimbusds', ecosystems: ['maven', 'gradle'], algorithms: ['RSA', 'ECDSA', 'AES'], role: 'token-signing', note: 'Nimbus JOSE+JWT.' },
  { match: 'org.springframework.security', ecosystems: ['maven', 'gradle'], algorithms: ['RSA', 'AES', 'bcrypt'], role: 'authentication', note: 'Spring Security — password encoders and token signing.' },
  { match: 'com.jcraft', ecosystems: ['maven', 'gradle'], algorithms: ['RSA', 'Diffie-Hellman'], role: 'authentication', note: 'JSch SSH.' },

  /* ── Go ─────────────────────────────────────────────────────────────── */
  { match: 'golang.org/x/crypto', ecosystems: ['go'], algorithms: ['Ed25519', 'X25519', 'ChaCha20-Poly1305', 'bcrypt', 'Argon2'], role: 'unknown', note: 'Extended Go crypto packages.' },
  { match: 'github.com/golang-jwt/jwt', ecosystems: ['go'], algorithms: ['RSA', 'ECDSA', 'HMAC'], role: 'token-signing', note: 'JWT signing.' },
  { match: 'github.com/dgrijalva/jwt-go', ecosystems: ['go'], algorithms: ['RSA', 'ECDSA', 'HMAC'], role: 'token-signing', note: 'Unmaintained JWT library — migrate to golang-jwt/jwt.' },
  { match: 'github.com/cloudflare/circl', ecosystems: ['go'], algorithms: ['ML-KEM', 'ML-DSA', 'X25519'], role: 'unknown', library: 'CIRCL', note: 'Cloudflare CIRCL — includes post-quantum primitives.' },
  { match: 'github.com/open-quantum-safe', ecosystems: ['go'], algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA'], role: 'unknown', library: 'liboqs', note: 'Open Quantum Safe.' },

  /* ── Rust ───────────────────────────────────────────────────────────── */
  { match: 'ring', ecosystems: ['cargo'], algorithms: ['ECDSA', 'Ed25519', 'AES', 'HMAC'], role: 'unknown', note: 'BoringSSL-derived Rust crypto.' },
  { match: 'rustls', ecosystems: ['cargo'], algorithms: ['TLS', 'ECDH', 'AES'], role: 'tls', note: 'Modern Rust TLS stack.' },
  { match: 'openssl', ecosystems: ['cargo', 'npm', 'pypi'], algorithms: ['RSA', 'ECDSA', 'AES', 'TLS'], role: 'tls', library: 'OpenSSL', note: 'OpenSSL bindings.' },
  { match: 'pqcrypto', ecosystems: ['cargo'], algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA'], role: 'unknown', note: 'PQClean-derived Rust post-quantum primitives. Confirm whether the crate implements the FIPS-standardised parameter sets or the earlier NIST round submissions — the key sizes are identical, so only the crate version distinguishes them.' },
  { match: 'ml-kem', ecosystems: ['cargo'], algorithms: ['ML-KEM'], role: 'key-exchange', note: 'FIPS 203 key encapsulation.' },
  { match: 'aes-gcm', ecosystems: ['cargo'], algorithms: ['AES'], role: 'encryption', note: 'AES-GCM AEAD.' },
  { match: 'argon2', ecosystems: ['cargo'], algorithms: ['Argon2'], role: 'password-derivation', note: 'Password hashing.' },

  /* ── .NET / NuGet ───────────────────────────────────────────────────── */
  { match: 'BouncyCastle', ecosystems: ['nuget'], algorithms: ['RSA', 'ECDSA', 'AES', 'ML-KEM'], role: 'unknown', library: 'Bouncy Castle', note: 'Bouncy Castle for .NET.' },
  { match: 'System.IdentityModel.Tokens.Jwt', ecosystems: ['nuget'], algorithms: ['RSA', 'ECDSA', 'HMAC'], role: 'token-signing', note: 'JWT handling.' },
  { match: 'Microsoft.IdentityModel', ecosystems: ['nuget'], algorithms: ['RSA', 'ECDSA'], role: 'token-signing', note: 'Token validation.' },

  /* ── PHP / Ruby ─────────────────────────────────────────────────────── */
  { match: 'firebase/php-jwt', ecosystems: ['composer'], algorithms: ['RSA', 'ECDSA', 'HMAC'], role: 'token-signing', note: 'JWT signing.' },
  { match: 'paragonie/', ecosystems: ['composer'], algorithms: ['X25519', 'ChaCha20-Poly1305'], role: 'unknown', note: 'Paragon Initiative crypto libraries.' },
  { match: 'jwt', ecosystems: ['rubygems'], algorithms: ['RSA', 'ECDSA', 'HMAC'], role: 'token-signing', note: 'Ruby JWT.' },
  { match: 'rbnacl', ecosystems: ['rubygems'], algorithms: ['X25519', 'Ed25519'], role: 'unknown', library: 'libsodium', note: 'libsodium bindings.' },
];

/** Known-unmaintained packages. A maintenance fact, not a CVE. */
const UNMAINTAINED = new Set(['pycrypto', 'github.com/dgrijalva/jwt-go', 'request', 'node-uuid']);

/* ────────────────────────────────────────────────────────────── parsing ──── */

/** Parse every supported manifest / lockfile in the corpus. */
export function parseDependencies(files: WorkspaceFile[]): ParsedDependency[] {
  const found: ParsedDependency[] = [];
  for (const file of files) {
    if (!file.content) continue;
    switch (file.basename) {
      case 'package.json':
        found.push(...parsePackageJson(file));
        break;
      case 'requirements.txt':
      case 'requirements-dev.txt':
        found.push(...parseRequirementsTxt(file));
        break;
      case 'pyproject.toml':
        found.push(...parsePyprojectToml(file));
        break;
      case 'setup.py':
        found.push(...parseSetupPy(file));
        break;
      case 'pipfile':
        found.push(...parsePipfile(file));
        break;
      case 'go.mod':
        found.push(...parseGoMod(file));
        break;
      case 'cargo.toml':
        found.push(...parseCargoToml(file));
        break;
      case 'pom.xml':
        found.push(...parsePomXml(file));
        break;
      case 'build.gradle':
      case 'build.gradle.kts':
        found.push(...parseGradle(file));
        break;
      case 'composer.json':
        found.push(...parseComposerJson(file));
        break;
      case 'gemfile':
        found.push(...parseGemfile(file));
        break;
      case 'package.swift':
        found.push(...parseSwiftPackage(file));
        break;
      case 'pubspec.yaml':
        found.push(...parsePubspec(file));
        break;
      case 'go.sum':
        found.push(...parseGoSum(file));
        break;
      default:
        if (file.basename.endsWith('.csproj') || file.basename.endsWith('.fsproj') || file.basename.endsWith('.vbproj')) {
          found.push(...parseCsproj(file));
        } else if (file.basename === 'packages.config') {
          found.push(...parsePackagesConfig(file));
        }
        break;
    }
  }
  return dedupe(found);
}

function dedupe(list: ParsedDependency[]): ParsedDependency[] {
  const map = new Map<string, ParsedDependency>();
  for (const item of list) {
    const key = `${item.ecosystem}|${item.name.toLowerCase()}`;
    const existing = map.get(key);
    // A direct declaration always beats a transitive one.
    if (!existing || (!existing.direct && item.direct)) map.set(key, item);
  }
  return [...map.values()];
}

function safeJson(content: string): any | null {
  try {
    return JSON.parse(content);
  } catch {
    return null;
  }
}

function parsePackageJson(file: WorkspaceFile): ParsedDependency[] {
  const json = safeJson(file.content as string);
  if (!json) return [];
  const out: ParsedDependency[] = [];
  const sections: Array<[string, ParsedDependency['scope']]> = [
    ['dependencies', 'runtime'],
    ['devDependencies', 'development'],
    ['peerDependencies', 'peer'],
    ['optionalDependencies', 'optional'],
  ];
  for (const [key, scope] of sections) {
    const block = json[key];
    if (!block || typeof block !== 'object') continue;
    for (const [name, version] of Object.entries(block)) {
      out.push({ name, version: String(version), ecosystem: 'npm', direct: true, file: file.path, scope });
    }
  }
  return out;
}

function parseRequirementsTxt(file: WorkspaceFile): ParsedDependency[] {
  const out: ParsedDependency[] = [];
  const lines = (file.content as string).split('\n');
  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) return;
    const match = trimmed.match(/^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*([=<>!~]{1,2}\s*[0-9][^\s;#]*)?/);
    if (!match) return;
    out.push({
      name: match[1],
      version: (match[2] ?? '').replace(/\s+/g, '') || 'unpinned',
      ecosystem: 'pypi',
      direct: true,
      file: file.path,
      line: index + 1,
      scope: file.basename.includes('dev') ? 'development' : 'runtime',
    });
  });
  return out;
}

/**
 * Read `name = [ … ]` / `"name": [ … ]` pairs, respecting nested brackets.
 *
 * A regex cannot do this correctly. `\[([\s\S]*?)\]` stops at the first `]`,
 * and a PEP 508 requirement may contain one of its own —
 * `coverage[toml]==5.0.4` truncated the whole extras list at "coverage[toml",
 * losing every dependency after it and inventing a version of "[toml". A depth
 * walker that skips quoted regions is a dozen lines and is exact.
 */
function readNamedLists(block: string): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  const header = /["']?([A-Za-z0-9._-]+)["']?\s*[=:]\s*\[/g;
  let match: RegExpExecArray | null;

  while ((match = header.exec(block)) !== null) {
    let depth = 1;
    let index = header.lastIndex;
    let quote: string | null = null;

    while (index < block.length && depth > 0) {
      const char = block[index];
      if (quote) {
        if (char === '\\') index += 1;
        else if (char === quote) quote = null;
      } else if (char === '"' || char === "'") {
        quote = char;
      } else if (char === '[') {
        depth += 1;
      } else if (char === ']') {
        depth -= 1;
      }
      index += 1;
    }

    if (depth !== 0) continue; // unterminated list — skip rather than guess
    out.push([match[1], block.slice(header.lastIndex, index - 1)]);
    header.lastIndex = index;
  }

  return out;
}

function parsePyprojectToml(file: WorkspaceFile): ParsedDependency[] {
  const out: ParsedDependency[] = [];
  const content = file.content as string;

  const pushList = (body: string, scope: ParsedDependency['scope']) => {
    for (const entry of body.split(',')) {
      const cleaned = entry.trim().replace(/^["']|["']$/g, '').trim();
      if (!cleaned || cleaned.startsWith('#')) continue;
      const match = cleaned.match(/^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(.*)$/);
      if (!match) continue;
      out.push({ name: match[1], version: match[2] || 'unpinned', ecosystem: 'pypi', direct: true, file: file.path, scope });
    }
  };

  // PEP 621 `dependencies = ["pkg>=1.0", …]`
  const pep621 = content.match(/^dependencies\s*=\s*\[([\s\S]*?)\]/m);
  if (pep621) pushList(pep621[1], 'runtime');

  /* PEP 621 optional-dependencies (extras).
     Missing these is not a rounding error: the crypto backend of a Python
     library is very often an EXTRA (`pip install pyjwt[crypto]`), so a parser
     that reads only the required list reports a JWT library as having no
     cryptographic dependencies at all. */
  const extrasBlock = content.match(/\[project\.optional-dependencies\]([\s\S]*?)(?:\n\[|$)/);
  if (extrasBlock) {
    for (const [name, body] of readNamedLists(extrasBlock[1])) {
      pushList(body, /dev|test|lint|doc/i.test(name) ? 'development' : 'optional');
    }
  }
  // Poetry `[tool.poetry.dependencies]`
  const poetry = content.match(/\[tool\.poetry\.dependencies\]([\s\S]*?)(?:\n\[|$)/);
  if (poetry) {
    for (const line of poetry[1].split('\n')) {
      const match = line.match(/^\s*([A-Za-z0-9._-]+)\s*=\s*(.+)$/);
      if (!match || match[1] === 'python') continue;
      out.push({ name: match[1], version: match[2].replace(/["'{},]/g, '').trim() || 'unpinned', ecosystem: 'pypi', direct: true, file: file.path });
    }
  }
  return out;
}

/**
 * setup.py `install_requires` / `extras_require`.
 *
 * Read with a regex rather than executed, per §60: repository code is never run
 * during a scan, so a dynamically-computed dependency list is simply not
 * visible — which is a limitation, not a claim of completeness.
 */
function parseSetupPy(file: WorkspaceFile): ParsedDependency[] {
  const out: ParsedDependency[] = [];
  const content = file.content as string;

  const collect = (body: string, scope: ParsedDependency['scope']) => {
    for (const match of body.matchAll(/["']([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*([^"']*)["']/g)) {
      out.push({ name: match[1], version: match[2].trim() || 'unpinned', ecosystem: 'pypi', direct: true, file: file.path, scope });
    }
  };

  const install = content.match(/install_requires\s*=\s*\[([\s\S]*?)\]/);
  if (install) collect(install[1], 'runtime');

  const extras = content.match(/extras_require\s*=\s*\{([\s\S]*?)\n\s*\}/);
  if (extras) {
    for (const [name, body] of readNamedLists(extras[1])) {
      collect(body, /dev|test|lint|doc/i.test(name) ? 'development' : 'optional');
    }
  }

  return out;
}

function parsePipfile(file: WorkspaceFile): ParsedDependency[] {
  const out: ParsedDependency[] = [];
  const content = file.content as string;
  for (const [section, scope] of [['packages', 'runtime'], ['dev-packages', 'development']] as const) {
    const block = content.match(new RegExp(`\\[${section}\\]([\\s\\S]*?)(?:\\n\\[|$)`));
    if (!block) continue;
    for (const line of block[1].split('\n')) {
      const match = line.match(/^\s*"?([A-Za-z0-9._-]+)"?\s*=\s*(.+)$/);
      if (!match) continue;
      out.push({ name: match[1], version: match[2].replace(/["'{}]/g, '').trim() || '*', ecosystem: 'pypi', direct: true, file: file.path, scope });
    }
  }
  return out;
}

function parseGoMod(file: WorkspaceFile): ParsedDependency[] {
  const out: ParsedDependency[] = [];
  const lines = (file.content as string).split('\n');
  let inRequire = false;
  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (trimmed.startsWith('require (')) {
      inRequire = true;
      return;
    }
    if (inRequire && trimmed === ')') {
      inRequire = false;
      return;
    }
    const single = trimmed.match(/^require\s+(\S+)\s+(\S+)/);
    if (single) {
      out.push({ name: single[1], version: single[2], ecosystem: 'go', direct: true, file: file.path, line: index + 1 });
      return;
    }
    if (!inRequire) return;
    const match = trimmed.match(/^(\S+)\s+(\S+)(\s+\/\/\s+indirect)?/);
    if (!match || trimmed.startsWith('//')) return;
    out.push({ name: match[1], version: match[2], ecosystem: 'go', direct: !match[3], file: file.path, line: index + 1 });
  });
  return out;
}

function parseGoSum(file: WorkspaceFile): ParsedDependency[] {
  const out: ParsedDependency[] = [];
  const seen = new Set<string>();
  for (const line of (file.content as string).split('\n')) {
    const match = line.match(/^(\S+)\s+(v\S+?)(?:\/go\.mod)?\s+h1:/);
    if (!match || seen.has(match[1])) continue;
    seen.add(match[1]);
    out.push({ name: match[1], version: match[2], ecosystem: 'go', direct: false, file: file.path });
  }
  return out;
}

function parseCargoToml(file: WorkspaceFile): ParsedDependency[] {
  const out: ParsedDependency[] = [];
  const content = file.content as string;
  for (const [section, scope] of [['dependencies', 'runtime'], ['dev-dependencies', 'development'], ['build-dependencies', 'build']] as const) {
    const block = content.match(new RegExp(`\\[${section}\\]([\\s\\S]*?)(?:\\n\\[[a-z]|$)`));
    if (!block) continue;
    for (const line of block[1].split('\n')) {
      const match = line.match(/^\s*([A-Za-z0-9._-]+)\s*=\s*(.+)$/);
      if (!match) continue;
      const versionMatch = match[2].match(/version\s*=\s*"([^"]+)"/) ?? match[2].match(/^"([^"]+)"/);
      out.push({ name: match[1], version: versionMatch?.[1] ?? 'workspace', ecosystem: 'cargo', direct: true, file: file.path, scope });
    }
  }
  return out;
}

function parsePomXml(file: WorkspaceFile): ParsedDependency[] {
  const out: ParsedDependency[] = [];
  const content = file.content as string;
  const regex = /<dependency>([\s\S]*?)<\/dependency>/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(content)) !== null) {
    const group = match[1].match(/<groupId>([^<]+)<\/groupId>/)?.[1]?.trim();
    const artifact = match[1].match(/<artifactId>([^<]+)<\/artifactId>/)?.[1]?.trim();
    const version = match[1].match(/<version>([^<]+)<\/version>/)?.[1]?.trim();
    const scope = match[1].match(/<scope>([^<]+)<\/scope>/)?.[1]?.trim();
    if (!group || !artifact) continue;
    out.push({
      name: `${group}:${artifact}`,
      version: version ?? 'managed',
      ecosystem: 'maven',
      direct: true,
      file: file.path,
      scope: scope === 'test' ? 'test' : scope === 'provided' ? 'build' : 'runtime',
    });
  }
  return out;
}

function parseGradle(file: WorkspaceFile): ParsedDependency[] {
  const out: ParsedDependency[] = [];
  const regex = /\b(implementation|api|compileOnly|runtimeOnly|testImplementation|annotationProcessor)\s*[( ]\s*['"]([^'"]+)['"]/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(file.content as string)) !== null) {
    const parts = match[2].split(':');
    if (parts.length < 2) continue;
    out.push({
      name: `${parts[0]}:${parts[1]}`,
      version: parts[2] ?? 'managed',
      ecosystem: 'gradle',
      direct: true,
      file: file.path,
      scope: match[1].startsWith('test') ? 'test' : 'runtime',
    });
  }
  return out;
}

function parseComposerJson(file: WorkspaceFile): ParsedDependency[] {
  const json = safeJson(file.content as string);
  if (!json) return [];
  const out: ParsedDependency[] = [];
  for (const [key, scope] of [['require', 'runtime'], ['require-dev', 'development']] as const) {
    const block = json[key];
    if (!block || typeof block !== 'object') continue;
    for (const [name, version] of Object.entries(block)) {
      if (name === 'php' || name.startsWith('ext-')) continue;
      out.push({ name, version: String(version), ecosystem: 'composer', direct: true, file: file.path, scope });
    }
  }
  return out;
}

function parseGemfile(file: WorkspaceFile): ParsedDependency[] {
  const out: ParsedDependency[] = [];
  const regex = /^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?/gm;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(file.content as string)) !== null) {
    out.push({ name: match[1], version: match[2] ?? 'unpinned', ecosystem: 'rubygems', direct: true, file: file.path });
  }
  return out;
}

function parseSwiftPackage(file: WorkspaceFile): ParsedDependency[] {
  const out: ParsedDependency[] = [];
  const regex = /\.package\(\s*url:\s*"([^"]+)"[^)]*?(?:from:\s*"([^"]+)")?/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(file.content as string)) !== null) {
    const name = match[1].replace(/\.git$/, '').split('/').slice(-2).join('/');
    out.push({ name, version: match[2] ?? 'unpinned', ecosystem: 'swiftpm', direct: true, file: file.path });
  }
  return out;
}

function parsePubspec(file: WorkspaceFile): ParsedDependency[] {
  const out: ParsedDependency[] = [];
  const content = file.content as string;
  const block = content.match(/^dependencies:([\s\S]*?)(?:^\w|$)/m);
  if (!block) return out;
  for (const line of block[1].split('\n')) {
    const match = line.match(/^\s{2}([a-z0-9_]+):\s*(.*)$/);
    if (!match) continue;
    out.push({ name: match[1], version: match[2].trim() || 'any', ecosystem: 'pub', direct: true, file: file.path });
  }
  return out;
}

function parseCsproj(file: WorkspaceFile): ParsedDependency[] {
  const out: ParsedDependency[] = [];
  const regex = /<PackageReference\s+Include="([^"]+)"(?:\s+Version="([^"]+)")?/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(file.content as string)) !== null) {
    out.push({ name: match[1], version: match[2] ?? 'managed', ecosystem: 'nuget', direct: true, file: file.path });
  }
  return out;
}

function parsePackagesConfig(file: WorkspaceFile): ParsedDependency[] {
  const out: ParsedDependency[] = [];
  const regex = /<package\s+id="([^"]+)"\s+version="([^"]+)"/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(file.content as string)) !== null) {
    out.push({ name: match[1], version: match[2], ecosystem: 'nuget', direct: true, file: file.path });
  }
  return out;
}

/* ─────────────────────────────────────────────────── crypto relevance ────── */

export function cryptoRelevance(dependency: ParsedDependency): CryptoDependency | null {
  const name = dependency.name.toLowerCase();
  for (const entry of CRYPTO_DEPENDENCIES) {
    if (!entry.ecosystems.includes(dependency.ecosystem)) continue;
    const match = entry.match.toLowerCase();
    if (name === match) return entry;
    // Prefix matches only on a package-namespace boundary, never mid-word:
    // `openssl` must not match `openssl-probe`'s parent `openssl` incorrectly,
    // and `jwt` must not match `jwtsanity`.
    if (match.endsWith('/') || match.endsWith(':')) {
      if (name.startsWith(match)) return entry;
    } else if (name.startsWith(`${match}/`) || name.startsWith(`${match}:`) || name.startsWith(`${match}-`) && entry.match.length > 6) {
      return entry;
    }
  }
  return null;
}

/* ────────────────────────────────────────────────────────────── the engine ── */

export const dependencyEngine: ExposureEngine = {
  descriptor: {
    id: 'dependency-analysis',
    label: 'Dependency Analysis',
    description: 'Parses manifests and lockfiles across nine ecosystems and maps each dependency to the cryptography it brings into the application.',
    mode: 'local',
    layer: 'dependency',
    capability: 'dependencies',
    dependsOn: ['file-discovery'],
    weight: 12,
  },

  appliesTo(context) {
    const has = context.workspace.files.some(
      (file) => file.content && (file.classification === 'manifest' || file.classification === 'lockfile'),
    );
    return has
      ? { applicable: true }
      : { applicable: false, reason: 'No dependency manifest or lockfile was found in scope.' };
  },

  async execute(context: EngineContext): Promise<EngineResult> {
    const files = context.workspace.files.filter(
      (file) => file.content && !context.isExcluded(file.path) && (file.classification === 'manifest' || file.classification === 'lockfile'),
    );

    context.report('Parsing dependency manifests', { done: 0, total: files.length, unit: 'manifests' });
    const dependencies = parseDependencies(files);
    const excluded = new Set((context.workspace.meta.excludedDependencies as string[] | undefined) ?? []);
    const inScope = dependencies.filter((dependency) => !excluded.has(dependency.name.toLowerCase()));

    const findings: ReturnType<typeof buildFinding>[] = [];
    const enriched: Array<{
      name: string;
      version: string;
      ecosystem: string;
      direct: boolean;
      cryptoRelevant: boolean;
      quantumRelevant: boolean;
    }> = [];

    let index = 0;
    /* One update per ~2% of the work, whatever the corpus size. */
    const dependencyStride = reportStride(inScope.length);
    for (const dependency of inScope) {
      if (context.isCancelled()) break;
      index += 1;
      if (index % dependencyStride === 0) {
        context.report('Mapping cryptographic relevance', { done: index, total: inScope.length, unit: 'dependencies' });
      }

      const relevance = cryptoRelevance(dependency);
      let quantumRelevant = false;

      if (relevance) {
        for (const algorithm of relevance.algorithms) {
          const canonical = canonicalAlgorithmName(algorithm);
          const entry = describeAlgorithm(algorithm);
          const quantum = classifyQuantum({ algorithm, role: relevance.role });
          if (quantum.quantumRelevant) quantumRelevant = true;

          // Only publish a finding for cryptography that MATTERS. A bcrypt
          // dependency is a true observation and a useless finding — it is
          // recorded in the CBOM and the dependency table, not raised as an
          // issue.
          if (quantum.status !== 'vulnerable' && !entry?.classicallyWeak) continue;

          const severity = severityFor({
            quantum,
            classicallyWeak: entry?.classicallyWeak ?? false,
            role: relevance.role,
            detection: 'inferred',
          });

          const finding = buildFinding({
            scanId: context.scanId,
            engineId: 'dependency-analysis',
            mode: context.mode,
            layer: 'dependency',
            category: 'Dependency Cryptography',
            subcategory: dependency.ecosystem,
            title: `${dependency.name}@${dependency.version} brings ${canonical}`,
            description: `${relevance.note} ${quantum.rationale} This is inferred from the dependency declaration, not read from a call site — confirm the algorithm is actually exercised before scheduling migration work.`,
            severity,
            confidence: 'medium',
            detection: 'inferred',
            algorithm,
            canonicalAlgorithm: canonical,
            role: relevance.role,
            library: relevance.library,
            component: dependency.name,
            version: dependency.version,
            quantumStatus: quantum.status,
            quantumRationale: quantum.rationale,
            recommendation: quantum.migrationTarget
              ? `Track ${dependency.name} for ${quantum.migrationTarget} support, and confirm which of its algorithms this application actually uses.`
              : `Replace ${canonical} usage supplied by ${dependency.name}.`,
            evidence: [
              buildEvidence({
                summary: `${dependency.name}@${dependency.version} declared in ${dependency.file}`,
                file: dependency.file,
                line: dependency.line,
                ruleId: `dependency-crypto:${relevance.match}`,
                localOnly: context.mode === 'local',
                attributes: {
                  ecosystem: dependency.ecosystem,
                  scope: dependency.scope ?? 'runtime',
                  direct: dependency.direct,
                  library: relevance.library ?? '',
                },
              }),
            ],
            identity: `${dependency.ecosystem}|${dependency.name}|${canonical}`,
            migration: quantum.quantumRelevant && quantum.status === 'vulnerable'
              ? { candidate: true, target: quantum.migrationTarget, priority: severity === 'critical' ? 'P1' : 'P2', complexity: 'medium' }
              : { candidate: false },
          });
          findings.push(finding);
          context.emit(finding);
        }
      }

      if (UNMAINTAINED.has(dependency.name.toLowerCase())) {
        const finding = buildFinding({
          scanId: context.scanId,
          engineId: 'dependency-analysis',
          mode: context.mode,
          layer: 'dependency',
          category: 'Supply Chain',
          subcategory: 'Unmaintained dependency',
          title: `${dependency.name} is no longer maintained`,
          description: `${dependency.name} is a package this engine knows to be unmaintained. It will not receive cryptographic fixes, which makes it a standing supply-chain risk independent of any specific vulnerability. No CVE is claimed here — this engine carries no vulnerability database.`,
          severity: 'medium',
          confidence: 'high',
          detection: 'observed',
          component: dependency.name,
          version: dependency.version,
          quantumStatus: 'not-applicable',
          recommendation: 'Replace with a maintained equivalent.',
          evidence: [
            buildEvidence({
              summary: `${dependency.name}@${dependency.version} declared in ${dependency.file}`,
              file: dependency.file,
              line: dependency.line,
              ruleId: 'dependency-unmaintained',
              localOnly: context.mode === 'local',
            }),
          ],
          identity: `${dependency.ecosystem}|${dependency.name}|unmaintained`,
        });
        findings.push(finding);
        context.emit(finding);
      }

      enriched.push({
        name: dependency.name,
        version: dependency.version,
        ecosystem: dependency.ecosystem,
        direct: dependency.direct,
        cryptoRelevant: Boolean(relevance),
        quantumRelevant,
      });
    }

    context.notAssessed(
      'Dependency vulnerability advisories',
      'This engine carries no vulnerability database, so no CVE claim is made about any dependency. Connect an advisory source to assess known vulnerabilities.',
    );

    context.workspace.meta.dependencies = enriched;

    return completed(
      findings,
      {
        dependencies: enriched.length,
        notAssessed: [
          {
            dimension: 'Dependency vulnerability advisories',
            reason: 'No advisory database is connected; known-vulnerability status is unassessed rather than clean.',
            engineId: 'dependency-analysis',
          },
        ],
      },
      { dependencies: enriched },
    );
  },
};
