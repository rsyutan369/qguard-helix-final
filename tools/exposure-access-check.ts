/**
 * Exposure mode entitlement — offline verification.
 *
 * The Web / Local / Dev gate is a revenue boundary AND a security boundary, so
 * it gets a check tool rather than a manual pass. Three things are asserted:
 *
 *  1. THE MATRIX. Every (plan x mode) combination resolves to the documented
 *     answer. This is the table a product decision would change, so it is
 *     written out explicitly rather than derived — a test that recomputes the
 *     policy from the policy cannot catch a wrong policy.
 *
 *  2. THE ROUTER. Every route in src/api-server/exposure.ts that starts,
 *     reads, cancels or persists a Local or Dev assessment actually carries a
 *     `requireMode(...)` guard. This is the assertion that matters most: the
 *     UI gate is cosmetic, and a route that quietly loses its guard in a future
 *     refactor is a paid feature given away with no visible symptom.
 *
 *  3. THE EXEMPTIONS. The endpoints that must stay anonymous — capability
 *     disclosure, the engine registry, the planner and the entitlement probe —
 *     are still anonymous, because the product's front door depends on them and
 *     over-gating is as much a defect as under-gating.
 *
 * Run: npx tsx tools/exposure-access-check.ts
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  EXPOSURE_MODE_MIN_TIER,
  exposureModeDenialMessage,
  plansIncluding,
  resolveExposureModeAccess,
  type AccessTier,
  type ExposureScanMode,
} from '../src/lib/subscription-access';

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

/* ═══════════════════════════════════════════════════════════ 1. the matrix ══ */

/**
 * The policy, written out. Rows are what a caller IS; columns are whether they
 * may run each mode.
 *
 *   anonymous  web only — the public assessment is the front door
 *   starter    web only — Starter is QGuard Messaging; it buys nothing here
 *   basic      web + local
 *   pro        web + local + dev
 *   elite      everything
 */
interface Expectation {
  label: string;
  tier: AccessTier;
  isActive: boolean;
  authenticated: boolean;
  web: boolean;
  local: boolean;
  dev: boolean;
}

const EXPECTED: Expectation[] = [
  { label: 'anonymous visitor',      tier: 'none',    isActive: false, authenticated: false, web: true, local: false, dev: false },
  { label: 'signed in, no plan',     tier: 'none',    isActive: false, authenticated: true,  web: true, local: false, dev: false },
  { label: 'Starter (active)',       tier: 'starter', isActive: true,  authenticated: true,  web: true, local: false, dev: false },
  { label: 'Basic (active)',         tier: 'basic',   isActive: true,  authenticated: true,  web: true, local: true,  dev: false },
  { label: 'Pro (active)',           tier: 'pro',     isActive: true,  authenticated: true,  web: true, local: true,  dev: true  },
  { label: 'Elite (active)',         tier: 'elite',   isActive: true,  authenticated: true,  web: true, local: true,  dev: true  },
  /* A lapsed subscription keeps its tier but loses access. The Web assessment
     survives, because it never depended on a plan in the first place. */
  { label: 'Basic (past_due)',       tier: 'basic',   isActive: false, authenticated: true,  web: true, local: false, dev: false },
  { label: 'Elite (cancelled)',      tier: 'elite',   isActive: false, authenticated: true,  web: true, local: false, dev: false },
];

function checkMatrix(): void {
  section('Entitlement matrix (plan × mode)');

  for (const row of EXPECTED) {
    for (const mode of ['web', 'local', 'dev'] as ExposureScanMode[]) {
      const access = resolveExposureModeAccess(mode, row.tier, row.isActive, row.authenticated);
      const expected = row[mode];
      check(
        `${row.label} → ${mode} ${expected ? 'allowed' : 'refused'}`,
        access.allowed === expected,
        `got ${access.allowed ? 'allowed' : `refused (${access.reason})`}`,
      );
    }
  }

  section('Refusal reasons are actionable');

  /* Three refusals need three different next steps. Collapsing them sends a
     paying customer with an expired card to the pricing page. */
  const anon = resolveExposureModeAccess('local', 'none', false, false);
  check('anonymous → unauthenticated', anon.reason === 'unauthenticated', String(anon.reason));

  const starter = resolveExposureModeAccess('local', 'starter', true, true);
  check('Starter on Local → tier-too-low', starter.reason === 'tier-too-low', String(starter.reason));

  const lapsed = resolveExposureModeAccess('local', 'elite', false, true);
  check(
    'lapsed Elite → inactive-subscription, not tier-too-low',
    lapsed.reason === 'inactive-subscription',
    `got ${lapsed.reason} — a lapsed Elite customer must not be told to upgrade`,
  );

  const basicOnDev = resolveExposureModeAccess('dev', 'basic', true, true);
  check('Basic on Dev → tier-too-low', basicOnDev.reason === 'tier-too-low', String(basicOnDev.reason));

  section('Denial messages name the real blocker');

  check(
    'lapsed message does not say "upgrade"',
    !/upgrade/i.test(exposureModeDenialMessage(lapsed)),
    exposureModeDenialMessage(lapsed),
  );
  check(
    'Basic-on-Dev message names Pro',
    /\bPro\b/.test(exposureModeDenialMessage(basicOnDev)),
    exposureModeDenialMessage(basicOnDev),
  );
  check(
    'anonymous message points at the free Web assessment',
    /web/i.test(exposureModeDenialMessage(anon)),
    exposureModeDenialMessage(anon),
  );
  check('allowed access carries no message', exposureModeDenialMessage(
    resolveExposureModeAccess('web', 'none', false, false),
  ) === '');

  section('Plan ribbons match the matrix');

  check('Local is included in Basic, Pro, Elite',
    plansIncluding('local').join(',') === 'basic,pro,elite', plansIncluding('local').join(','));
  check('Dev is included in Pro, Elite',
    plansIncluding('dev').join(',') === 'pro,elite', plansIncluding('dev').join(','));
  check('Web needs no plan', EXPOSURE_MODE_MIN_TIER.web === 'none');
}

/* ═══════════════════════════════════════════════════════════ 2. the router ══ */

/**
 * Routes that MUST carry a mode guard, and which mode.
 *
 * Kept as a literal list rather than inferred from the file, because the point
 * of the check is to notice when the file changes. An inferred list would
 * happily follow a route that lost its guard.
 */
const GUARDED_ROUTES: Array<{ method: string; path: string; mode: ExposureScanMode; why: string }> = [
  { method: 'post',   path: '/dev/validate',              mode: 'dev',   why: 'resolves a repository through a platform adapter' },
  { method: 'post',   path: '/scans',                     mode: 'dev',   why: 'starts a server-side Dev assessment' },
  { method: 'get',    path: '/scans',                     mode: 'dev',   why: 'lists the tenant’s Dev scan history' },
  { method: 'get',    path: '/scans/:scanId',             mode: 'dev',   why: 'reads a Dev scan' },
  { method: 'post',   path: '/scans/:scanId/cancel',      mode: 'dev',   why: 'controls a running Dev scan' },
  { method: 'get',    path: '/scans/:scanId/events',      mode: 'dev',   why: 'streams a Dev scan' },
  { method: 'get',    path: '/scans/:scanId/findings',    mode: 'dev',   why: 'reads Dev findings' },
  { method: 'get',    path: '/scans/:scanId/exposures',   mode: 'dev',   why: 'reads Dev exposures' },
  { method: 'get',    path: '/scans/:scanId/cbom',        mode: 'dev',   why: 'exports the Dev CBOM' },
  { method: 'post',   path: '/scans/:scanId/sync',        mode: 'dev',   why: 'persists a Dev assessment into the estate' },
  { method: 'get',    path: '/dev/connections',           mode: 'dev',   why: 'lists connector credentials' },
  { method: 'post',   path: '/dev/connections',           mode: 'dev',   why: 'stores connector credentials' },
  { method: 'post',   path: '/dev/connections/:id/verify', mode: 'dev',  why: 'uses a connector credential' },
  { method: 'delete', path: '/dev/connections/:id',       mode: 'dev',   why: 'mutates connector credentials' },
  { method: 'post',   path: '/local/sync',                mode: 'local', why: 'persists a Local assessment into the estate' },
];

/** Endpoints that must stay reachable without an account. */
const ANONYMOUS_ROUTES = [
  { method: 'get', path: '/capabilities', why: 'capability disclosure — what each mode does' },
  { method: 'get', path: '/engines',      why: 'engine registry and health disclosure' },
  { method: 'get', path: '/entitlement',  why: 'tells an anonymous caller what they may run' },
  { method: 'post', path: '/plan',        why: 'the planner proposes engines; it executes nothing' },
  { method: 'get', path: '/dev/connection-requirements', why: 'documents the permissions a connector needs' },
];

function checkRouter(): void {
  section('Router enforcement (src/api-server/exposure.ts)');

  const source = readFileSync(join(process.cwd(), 'src', 'api-server', 'exposure.ts'), 'utf8');

  for (const route of GUARDED_ROUTES) {
    /* Match the declaration line for this exact method+path and read what
       middleware follows it. */
    const escaped = route.path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const pattern = new RegExp(`router\\.${route.method}\\(\\s*'${escaped}'\\s*,\\s*([A-Za-z_$][\\w$]*)\\s*\\(?`);
    const match = source.match(pattern);

    if (!match) {
      check(`${route.method.toUpperCase()} ${route.path} exists`, false, 'route not found — was it renamed?');
      continue;
    }

    check(
      `${route.method.toUpperCase()} ${route.path} → requireMode('${route.mode}')`,
      match[1] === 'requireMode' && source.slice(match.index ?? 0, (match.index ?? 0) + 200).includes(`requireMode('${route.mode}')`),
      `first middleware is \`${match[1]}\` — ${route.why}`,
    );
  }

  section('Anonymous surfaces stay anonymous');

  for (const route of ANONYMOUS_ROUTES) {
    const escaped = route.path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    /* Capture whatever follows the path: a named middleware, or the start of an
       inline handler when there is no middleware at all. An anonymous route
       normally takes the inline form, so it must not read as "route missing". */
    const pattern = new RegExp(`router\\.${route.method}\\(\\s*'${escaped}'\\s*,\\s*(async\\b|\\(|[A-Za-z_$][\\w$]*)`);
    const match = source.match(pattern);
    if (!match) {
      check(`${route.method.toUpperCase()} ${route.path} exists`, false, 'route not found');
      continue;
    }
    const guard = match[1].trim();
    const inlineHandler = guard === '(' || guard === 'async';
    check(
      `${route.method.toUpperCase()} ${route.path} is not plan-gated`,
      inlineHandler || (guard !== 'requireMode' && guard !== 'requireUserAuth'),
      `guarded by \`${guard}\` — ${route.why}`,
    );
  }

  section('The gate cannot be bypassed by an unguarded route');

  /* Any route mentioning a Dev or Local execution surface that this tool does
     not know about is a gap in the list above, not a pass. */
  const declared = new Set(GUARDED_ROUTES.map((r) => `${r.method} ${r.path}`).concat(
    ANONYMOUS_ROUTES.map((r) => `${r.method} ${r.path}`),
  ));
  const found = [...source.matchAll(/router\.(get|post|put|patch|delete)\(\s*'([^']+)'/g)]
    .map((m) => `${m[1]} ${m[2]}`);
  const unknown = found.filter((route) => !declared.has(route));

  check(
    'every exposure route is classified as gated or anonymous',
    unknown.length === 0,
    unknown.length ? `unclassified: ${unknown.join(', ')} — add each to GUARDED_ROUTES or ANONYMOUS_ROUTES` : undefined,
  );

  section('Server and UI read the same matrix');

  check(
    'the router imports the shared policy rather than restating it',
    source.includes("from '@/lib/subscription-access'") && source.includes('resolveExposureModeAccess'),
    'exposure.ts must not hard-code its own tier table',
  );
  check(
    'entitlement resolution goes through the billing-backed resolver',
    source.includes('resolveEntitlement'),
    'a plan read that does not hit billing_subscriptions can be spoofed by profiles.tier',
  );
  check(
    'mode enforcement fails CLOSED on a billing read error',
    /ENTITLEMENT_UNAVAILABLE/.test(source),
    'an infra failure must refuse the scan, not grant it',
  );
}

/* ══════════════════════════════════════════════════════════════════ main ═══ */

function main(): void {
  console.log('\x1b[1mQGuard Helix — exposure mode entitlement\x1b[0m');
  console.log('Offline. Asserts the Web/Local/Dev gate on both the policy and the router.\n');

  checkMatrix();
  checkRouter();

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
