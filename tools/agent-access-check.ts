/**
 * Agent role, scan-module and control-plane entitlement — offline verification.
 *
 * Three boundaries are asserted, all of them things that fail silently when
 * they break:
 *
 *  1. THE ROLE MATRIX. Which plan may hold which agent role. Written out
 *     explicitly, because this is the table a product decision changes and a
 *     test that recomputes policy from policy cannot catch a wrong policy.
 *
 *  2. THE ROUTER. That enrolment resolves the role SERVER-side and does not
 *     take it from caller metadata (§41), that the installer re-checks at
 *     package time, and that the write-capable job queue re-checks per poll.
 *     A role gate that quietly disappears in a refactor hands a Basic tenant an
 *     agent that can rewrite their TLS configuration, with no visible symptom.
 *
 *  3. THE CONTROL PLANE. §2's exact defect — `production` + `localhost` — must
 *     be refused, and the legitimate combinations must still pass. This is the
 *     check that keeps the environment separation real rather than documented.
 *
 * Run: npx tsx tools/agent-access-check.ts
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  AGENT_ROLE_MIN_TIER,
  agentRoleDenialMessage,
  agentRolesForTier,
  agentScanTypesForTier,
  BASIC_AGENT_SCAN_TYPES,
  filterAgentScanTypes,
  PRO_AGENT_SCAN_TYPES,
  resolveAgentRoleAccess,
  type AccessTier,
  type AgentRoleId,
} from '../src/lib/subscription-access';
import {
  readAgentEnvironment,
  validateControlPlane,
  type AgentEnvironment,
} from '../src/lib/agent-installer/agent-environment';
import { AGENT_ROLES } from '../src/lib/agent-installer/agent-release';
import { findAlgorithm } from '../src/lib/crypto/knowledge-base/algorithms';
import { findLibrary } from '../src/lib/crypto/knowledge-base/apis';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(label: string, condition: boolean, detail?: string): void {
  if (condition) {
    passed += 1;
    return;
  }
  failed += 1;
  failures.push(`${label}${detail ? ` — ${detail}` : ''}`);
}

function section(title: string): void {
  console.log(`\n\x1b[36m── ${title} ${'─'.repeat(Math.max(0, 58 - title.length))}\x1b[0m`);
}

/* ═════════════════════════════════════════════════════ 1. the role matrix ══ */

interface RoleExpectation {
  label: string;
  tier: AccessTier;
  isActive: boolean;
  authenticated: boolean;
  collector: boolean;
  scanner: boolean;
  patcher: boolean;
  operator: boolean;
}

/**
 * The policy, written out.
 *
 * The line is `mutatesTargets`: the two read-only roles are Basic, the two that
 * write to a host are Pro.
 */
const EXPECTED: RoleExpectation[] = [
  { label: 'anonymous',          tier: 'none',    isActive: false, authenticated: false, collector: false, scanner: false, patcher: false, operator: false },
  { label: 'signed in, no plan', tier: 'none',    isActive: false, authenticated: true,  collector: false, scanner: false, patcher: false, operator: false },
  { label: 'Starter (active)',   tier: 'starter', isActive: true,  authenticated: true,  collector: false, scanner: false, patcher: false, operator: false },
  { label: 'Basic (active)',     tier: 'basic',   isActive: true,  authenticated: true,  collector: true,  scanner: true,  patcher: false, operator: false },
  { label: 'Pro (active)',       tier: 'pro',     isActive: true,  authenticated: true,  collector: true,  scanner: true,  patcher: true,  operator: true  },
  { label: 'Elite (active)',     tier: 'elite',   isActive: true,  authenticated: true,  collector: true,  scanner: true,  patcher: true,  operator: true  },
  /* A lapsed plan keeps its tier but loses every role, including the read-only
     ones — an agent is a running process on a customer host, not a report. */
  { label: 'Pro (past_due)',     tier: 'pro',     isActive: false, authenticated: true,  collector: false, scanner: false, patcher: false, operator: false },
  { label: 'Elite (cancelled)',  tier: 'elite',   isActive: false, authenticated: true,  collector: false, scanner: false, patcher: false, operator: false },
];

const ALL_ROLES: AgentRoleId[] = ['collector', 'scanner', 'patcher', 'operator'];

function checkRoleMatrix(): void {
  section('Agent role matrix (plan × role)');

  for (const row of EXPECTED) {
    for (const role of ALL_ROLES) {
      const access = resolveAgentRoleAccess(role, row.tier, row.isActive, row.authenticated);
      const expected = row[role];
      check(
        `${row.label} → ${role} ${expected ? 'allowed' : 'refused'}`,
        access.allowed === expected,
        `got ${access.allowed ? 'allowed' : `refused (${access.reason})`}`,
      );
    }
  }

  section('The read/write line is the tier line');

  /* This is the invariant the whole design rests on: a role that can modify a
     host is never available below Pro. Asserted against the ROLE CATALOGUE's
     own `mutatesTargets` flag, so adding a fifth write-capable role at Basic
     fails here rather than in production. */
  for (const definition of AGENT_ROLES) {
    const required = AGENT_ROLE_MIN_TIER[definition.id as AgentRoleId];
    if (definition.mutatesTargets) {
      check(
        `${definition.label} writes to the host → requires Pro`,
        required === 'pro',
        `requires ${required} — a host-modifying role must not be available below Pro`,
      );
    } else {
      check(
        `${definition.label} is read-only → available on Basic`,
        required === 'basic',
        `requires ${required}`,
      );
    }
  }

  section('Role catalogue and policy matrix cannot drift');

  /* `subscription-access.ts` restates the role ids as a string union so it can
     stay dependency-free. That is a duplication, and this is the seam that
     stops it becoming a divergence. */
  const catalogueIds = AGENT_ROLES.map((role) => role.id).sort();
  const policyIds = Object.keys(AGENT_ROLE_MIN_TIER).sort();
  check(
    'every catalogue role has a tier, and vice versa',
    catalogueIds.join(',') === policyIds.join(','),
    `catalogue=[${catalogueIds.join(',')}] policy=[${policyIds.join(',')}]`,
  );

  section('Refusal reasons are actionable');

  const lapsed = resolveAgentRoleAccess('collector', 'elite', false, true);
  check('lapsed Elite → inactive-subscription', lapsed.reason === 'inactive-subscription', String(lapsed.reason));
  check(
    'lapsed message does not say "upgrade"',
    !/upgrade/i.test(agentRoleDenialMessage(lapsed, 'Collector')),
    agentRoleDenialMessage(lapsed, 'Collector'),
  );

  const basicOnPatcher = resolveAgentRoleAccess('patcher', 'basic', true, true);
  check('Basic on Patcher → tier-too-low', basicOnPatcher.reason === 'tier-too-low', String(basicOnPatcher.reason));
  check(
    'Basic-on-Patcher message names Pro and says why',
    /\bPro\b/.test(agentRoleDenialMessage(basicOnPatcher, 'Patcher')) &&
      /host configuration/i.test(agentRoleDenialMessage(basicOnPatcher, 'Patcher')),
    agentRoleDenialMessage(basicOnPatcher, 'Patcher'),
  );
}

/* ═══════════════════════════════════════════════════ 2. the scan modules ═══ */

function checkScanModules(): void {
  section('Agent scan modules by tier');

  check('no plan runs no modules', agentScanTypesForTier('none').length === 0);
  check('Starter runs no modules', agentScanTypesForTier('starter').length === 0);
  check(
    `Basic runs the ${BASIC_AGENT_SCAN_TYPES.length} host modules`,
    agentScanTypesForTier('basic').length === BASIC_AGENT_SCAN_TYPES.length,
    `got ${agentScanTypesForTier('basic').length}`,
  );
  check(
    `Pro adds the ${PRO_AGENT_SCAN_TYPES.length} beyond-the-host modules`,
    agentScanTypesForTier('pro').length === BASIC_AGENT_SCAN_TYPES.length + PRO_AGENT_SCAN_TYPES.length,
    `got ${agentScanTypesForTier('pro').length}`,
  );
  check(
    'Elite matches Pro',
    agentScanTypesForTier('elite').join(',') === agentScanTypesForTier('pro').join(','),
  );

  /* The two lists must not overlap, or a module would be counted twice and the
     "Pro adds N" arithmetic above would be quietly wrong. */
  const overlap = BASIC_AGENT_SCAN_TYPES.filter((type) => PRO_AGENT_SCAN_TYPES.includes(type));
  check('Basic and Pro module lists are disjoint', overlap.length === 0, overlap.join(','));

  section('Denied modules are reported, never dropped silently');

  const cloudRequest = ['tls', 'certificates', 'cloud_kms', 'kubernetes'];
  const basicResult = filterAgentScanTypes('basic', cloudRequest);
  check(
    'Basic keeps its host modules',
    basicResult.allowed.join(',') === 'tls,certificates',
    basicResult.allowed.join(','),
  );
  check(
    'Basic REPORTS the modules it dropped',
    basicResult.denied.join(',') === 'cloud_kms,kubernetes',
    `denied=[${basicResult.denied.join(',')}] — a silently dropped module leaves a dimension nobody looked at reading as clean`,
  );

  const proResult = filterAgentScanTypes('pro', cloudRequest);
  check('Pro keeps all four', proResult.allowed.length === 4 && proResult.denied.length === 0);

  section('Basic gets a genuinely useful host inventory');

  /* The point of giving Basic the collector at all: it must cover the
     dimensions the Quantum Readiness engine actually consumes. */
  for (const essential of ['tls', 'certificates', 'pki', 'ssh', 'packages', 'libraries', 'configs']) {
    check(`Basic collects "${essential}"`, agentScanTypesForTier('basic').includes(essential));
  }
  for (const proOnly of ['cloud_kms', 'cloud_hsm', 'kubernetes', 'service_mesh', 'hsm']) {
    check(`"${proOnly}" is Pro-only`, !agentScanTypesForTier('basic').includes(proOnly));
  }
}

/* ═══════════════════════════════════════════════ 3. the control plane ══════ */

function checkControlPlane(): void {
  section('Control-plane environment policy (§2, §3, §61, §62)');

  /* The exact combination §2 names as the defect. */
  const theDefect = validateControlPlane('http://localhost:3000', 'production');
  check('production + http://localhost:3000 is REFUSED', !theDefect.ok);
  check(
    'and the refusal names both problems',
    theDefect.errors.some((e) => /HTTPS/i.test(e)) && theDefect.errors.some((e) => /loopback|private/i.test(e)),
    theDefect.errors.join(' | '),
  );

  const cases: Array<{ url: string; env: AgentEnvironment; ok: boolean; why: string }> = [
    { url: 'https://api.qguardhelix.com', env: 'production', ok: true, why: 'the intended production shape' },
    { url: 'http://api.qguardhelix.com', env: 'production', ok: false, why: 'plaintext to a remote host' },
    { url: 'https://127.0.0.1', env: 'production', ok: false, why: 'HTTPS but loopback' },
    { url: 'https://10.0.0.5', env: 'production', ok: false, why: 'HTTPS but RFC1918' },
    { url: 'https://192.168.1.10', env: 'production', ok: false, why: 'HTTPS but RFC1918' },
    { url: 'https://172.16.4.4', env: 'production', ok: false, why: 'HTTPS but RFC1918' },
    { url: 'https://api-staging.qguardhelix.com', env: 'staging', ok: true, why: 'staging over HTTPS' },
    { url: 'http://api-staging.qguardhelix.com', env: 'staging', ok: false, why: 'staging must be HTTPS' },
    { url: 'http://localhost:3000', env: 'development', ok: true, why: 'the whole point of having environments' },
    { url: 'http://127.0.0.1:3000', env: 'development', ok: true, why: 'loopback by IP' },
    { url: 'http://api.qguardhelix.com', env: 'development', ok: false, why: 'plaintext to a REMOTE host, even in dev' },
    { url: 'ftp://api.qguardhelix.com', env: 'production', ok: false, why: 'unsupported scheme' },
    { url: 'not-a-url', env: 'production', ok: false, why: 'unparseable' },
    { url: '', env: 'production', ok: false, why: 'unset' },
  ];

  for (const testCase of cases) {
    const result = validateControlPlane(testCase.url, testCase.env);
    check(
      `${testCase.env.padEnd(11)} ${testCase.url || '(empty)'} → ${testCase.ok ? 'accepted' : 'refused'}`,
      result.ok === testCase.ok,
      `${testCase.why}; errors=[${result.errors.join(' | ')}]`,
    );
  }

  section('Hostname matching is not substring matching');

  /* A substring test would accept this as production because the hostname
     merely CONTAINS a permitted string — and reject the legitimate host below. */
  check(
    'localhost.evil.example is not treated as loopback',
    validateControlPlane('https://localhost.evil.example', 'production').ok,
    'a substring check would have refused a legitimate remote host',
  );
  check(
    'my-localhost-proxy.example.com is allowed in production',
    validateControlPlane('https://my-localhost-proxy.example.com', 'production').ok,
  );

  section('Environment defaults to the safe-to-be-wrong value');

  check('unset → development', readAgentEnvironment(undefined) === 'development');
  check('garbage → development', readAgentEnvironment('prod-ish') === 'development');
  check('"production" → production', readAgentEnvironment('production') === 'production');
  check('case-insensitive', readAgentEnvironment('PRODUCTION') === 'production');
}

/* ══════════════════════════════════════════════════════ 4. the router ══════ */

function checkRouter(): void {
  section('Server-side enforcement (§41: role is never caller-asserted)');

  const scanner = readFileSync(join(process.cwd(), 'src', 'api-server', 'agent-scanner.ts'), 'utf8');
  const installer = readFileSync(join(process.cwd(), 'src', 'api-server', 'agent-installer.ts'), 'utf8');
  const guard = readFileSync(join(process.cwd(), 'src', 'api-server', 'subscription-guard.ts'), 'utf8');

  check(
    'enrolment resolves the role through decideAgentRole',
    /router\.post\('\/agents\/enroll'[\s\S]{0,4000}?decideAgentRole\(/.test(scanner),
    'the role must be checked against the plan before the agent row is written',
  );
  check(
    'enrolment writes the SERVER-resolved role, overriding caller metadata',
    /role: resolvedRole/.test(scanner) && /roleResolvedBy: 'control-plane'/.test(scanner),
    'metadata is spread in verbatim, so `role` must be written after it',
  );
  check(
    'enrolment derives capabilities from the resolved role',
    /\.\.\.agentRole\(resolvedRole\)\.capabilities/.test(scanner),
    'a caller asking for remediation:true on a collector must still get a collector',
  );
  check(
    'enrolment clamps the scan-module list to the plan',
    /decideScanTypes\(/.test(scanner) && /scanTypesDeniedByPlan/.test(scanner),
    'and records what it removed',
  );
  check(
    'the write-capable job queue re-checks entitlement per poll',
    /agentMayWrite\(client, agent, 'remediation'\)/.test(scanner),
    'a downgrade must stop work reaching agents that already exist',
  );
  check(
    'installer re-checks the role at package time',
    /decideAgentRole\(req as AgentEntitlementRequest/.test(installer),
    'an agent row survives a downgrade; fresh installers for a write role must not',
  );
  check(
    'installer refuses an insecure control plane',
    /CONTROL_PLANE_INSECURE/.test(installer) && /assertControlPlane\(/.test(installer),
    'the last point at which the platform controls what an agent will talk to',
  );

  section('Gateway tier floor matches the role matrix');

  check(
    'agent-scanner is gated at BASIC',
    /\{ prefix: '\/api\/v1\/agent-scanner', tier: 'basic' \}/.test(guard),
    'Basic must reach the collector; the write roles are held back per-role',
  );
  check(
    'agent-installer is gated at BASIC',
    /\{ prefix: '\/api\/v1\/agent-installer', tier: 'basic' \}/.test(guard),
  );
  check(
    'the gateway explains why the per-role split is not expressible here',
    /agent-entitlement/.test(guard),
    'without the note, a maintainer raises this prefix back to `pro` and locks Basic out',
  );

  section('Agent runtime fails closed on an insecure control plane');

  const agent = readFileSync(join(process.cwd(), 'tools', 'qguard-agent', 'agent.ts'), 'utf8');
  check(
    'the runtime validates its control plane before enrolling',
    /assertSecureControlPlane\(\)/.test(agent) && /validateControlPlane\(API_URL/.test(agent),
  );
  check(
    'and exits rather than continuing',
    /process\.exit\(78\)/.test(agent),
    'EX_CONFIG — an agent must not run against an unverified control plane',
  );
}


/* ═══════════════════════════════════ 5. dependency evidence honesty ════════ */

/**
 * A dependency proves a library is PRESENT, never that an algorithm is USED.
 *
 * The agent's package classifier used to map names to a specific algorithm and
 * key size — `openssl` -> RSA-2048, `libsodium` -> RSA-2048, `bcrypt` ->
 * SHA-256, `crypto-js` -> AES-128. Three of those were factually wrong
 * (libsodium ships no RSA; bcrypt is Blowfish-derived) and all four invented a
 * key size that appears in no manifest. Those rows then flowed into the CBOM,
 * the vulnerable-component count and the migration plan as measurements.
 *
 * This asserts the honest reading survives: library first, algorithm only when
 * the package name itself states one, and nothing at all for a package that is
 * not cryptographic.
 */
function checkDependencyEvidence(): void {
  section('Dependency evidence: availability, not usage');

  /* Mirrors the precedence in `packageAlgorithmEvidence`. */
  const classify = (name: string): { kind: 'library' | 'algorithm' | 'none'; value: string } => {
    const library = findLibrary(name);
    if (library) return { kind: 'library', value: library.canonicalName };
    const algorithm = findAlgorithm(name);
    if (algorithm) return { kind: 'algorithm', value: algorithm.canonicalName };
    return { kind: 'none', value: '' };
  };

  const expectations: Array<{ pkg: string; kind: 'library' | 'algorithm' | 'none'; why: string }> = [
    { pkg: 'openssl',      kind: 'library',   why: 'provides dozens of algorithms; a dependency proves none of them' },
    { pkg: 'libsodium',    kind: 'library',   why: 'previously reported as RSA-2048 — libsodium ships no RSA at all' },
    { pkg: 'bcrypt',       kind: 'library',   why: 'previously reported as SHA-256 — bcrypt is Blowfish-derived' },
    { pkg: 'crypto-js',    kind: 'library',   why: 'previously reported as AES-128, inventing a key size' },
    { pkg: 'jsonwebtoken', kind: 'library',   why: 'the signing algorithm is chosen per call, not by the dependency' },
    { pkg: 'node-forge',   kind: 'library',   why: 'previously reported as RSA-2048' },
    { pkg: 'ssh2',         kind: 'library',   why: 'a client library; negotiated algorithms are a runtime property' },
    { pkg: 'liboqs',       kind: 'library',   why: 'post-quantum capable — availability, still not usage' },
    { pkg: 'ml-kem-768',   kind: 'algorithm', why: 'the package NAME states the algorithm' },
    { pkg: 'left-pad',     kind: 'none',      why: 'not cryptographic' },
    { pkg: 'express',      kind: 'none',      why: 'not cryptographic' },
  ];

  for (const expectation of expectations) {
    const result = classify(expectation.pkg);
    check(
      `${expectation.pkg.padEnd(14)} → ${expectation.kind}`,
      result.kind === expectation.kind,
      `got ${result.kind}${result.value ? ` (${result.value})` : ''} — ${expectation.why}`,
    );
  }

  section('No dependency evidence carries a fabricated key size');

  const source = readFileSync(join(process.cwd(), 'tools', 'qguard-agent', 'agent.ts'), 'utf8');
  const classifier = source.slice(
    source.indexOf('function packageAlgorithmEvidence('),
    source.indexOf('function isPackageManifest('),
  );
  check(
    'the classifier names no key size',
    !/RSA-(1024|2048|3072|4096)|AES-(128|256)|ECC-P256|ECDSA-P256/.test(classifier),
    'a manifest states no key size, so the classifier must not invent one',
  );
  check(
    'the classifier delegates to the shared catalogue',
    /findLibrary\(/.test(classifier) && /findAlgorithm\(/.test(classifier),
    'algorithm facts must come from the knowledge base, never a local table',
  );
  check(
    'library evidence is reported at LOW confidence',
    /confidence: 'low'/.test(classifier),
    'a manifest entry is the weakest evidence the platform accepts',
  );
}

/* ══════════════════════════════════════════════════════════════════ main ═══ */

function main(): void {
  console.log('\x1b[1mQGuard Helix — agent role, module and control-plane entitlement\x1b[0m');
  console.log('Offline. Asserts the policy, the routers and the agent runtime.\n');

  checkRoleMatrix();
  checkScanModules();
  checkControlPlane();
  checkRouter();
  checkDependencyEvidence();

  console.log(`\n\x1b[1m${'═'.repeat(66)}\x1b[0m`);
  if (failed === 0) {
    console.log(`\x1b[32m✓ ${passed} checks passed\x1b[0m`);
    return;
  }
  console.log(`\x1b[31m✗ ${failed} of ${passed + failed} checks failed\x1b[0m\n`);
  for (const failure of failures) console.log(`  \x1b[31m•\x1b[0m ${failure}`);
  process.exitCode = 1;
}

main();
