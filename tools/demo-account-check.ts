/**
 * Demo / test account — offline assertion suite.
 *
 *   npx tsx tools/demo-account-check.ts
 *
 * The demo account is the only identity in the platform that authenticates
 * without Supabase, so the properties that keep it safe cannot be left to
 * inspection. This tool asserts them directly, needs no network, no database
 * and no running server, and is the thing to run before and after touching
 * anything in `src/lib/demo-account.ts` or its call sites.
 *
 * What it proves:
 *   1. OFF by default          — with no flag set, the demo token authenticates
 *                                nothing.
 *   2. ON only with the flag   — and then only for the exact token.
 *   3. Elite, not owner        — every subscription-gated module opens; the
 *                                owner-only surfaces stay shut.
 *   4. Route parity            — the tier the demo account resolves to actually
 *                                satisfies every entry in the access matrix.
 *   5. Single owner            — no demo constant is duplicated outside the
 *                                module that owns it.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

let failures = 0
let checks = 0

function assert(condition: boolean, label: string, detail = '') {
  checks += 1
  if (condition) {
    console.log(`  PASS  ${label}`)
    return
  }
  failures += 1
  console.log(`  FAIL  ${label}${detail ? `\n        ${detail}` : ''}`)
}

function section(title: string) {
  console.log(`\n${title}`)
}

async function main() {
  // The module reads the flag on every call, so the suite can toggle it.
  delete process.env.VITE_DEMO_ACCOUNT
  delete process.env.DEMO_ACCOUNT

  const demo = await import('../src/lib/demo-account')
  const access = await import('../src/lib/subscription-access')
  const admin = await import('../src/lib/admin-access')

  console.log('Demo account check\n==================')

  section('1. Disabled by default')
  assert(!demo.isDemoModeEnabled(), 'demo mode is off with no env flag set')
  assert(
    !demo.isDemoToken(demo.DEMO_ACCESS_TOKEN),
    'the demo token authenticates nothing while the flag is off',
    'isDemoToken() must be false without the flag, or a leaked token would work in production',
  )
  assert(!demo.isDemoSessionActive(), 'no demo session is reported while the flag is off')

  section('2. Enabled only by the explicit flag')
  process.env.VITE_DEMO_ACCOUNT = 'true'
  assert(demo.isDemoModeEnabled(), `${demo.DEMO_ENV_FLAG}=true enables demo mode`)
  assert(demo.isDemoToken(demo.DEMO_ACCESS_TOKEN), 'the demo token is accepted while enabled')
  assert(!demo.isDemoToken('some-other-token'), 'an unrelated token is still rejected')
  assert(!demo.isDemoToken(''), 'an empty token is rejected')
  assert(
    demo.isDemoCredential(demo.DEMO_ACCOUNT_EMAIL.toUpperCase(), demo.DEMO_ACCOUNT_PASSWORD),
    'the demo email matches case-insensitively',
  )
  assert(
    !demo.isDemoCredential(demo.DEMO_ACCOUNT_EMAIL, 'wrong-password'),
    'the demo email with a wrong password is not a demo credential',
  )

  process.env.VITE_DEMO_ACCOUNT = 'false'
  assert(!demo.isDemoModeEnabled(), 'the flag set to "false" does not enable demo mode')
  process.env.VITE_DEMO_ACCOUNT = 'true'

  section('3. Elite tier, NOT platform owner')
  const user = demo.createDemoUser()
  const session = demo.createDemoSession()
  assert(user.id === demo.DEMO_ACCOUNT_USER_ID, 'the demo user carries the fixed demo id')
  assert(session.access_token === demo.DEMO_ACCESS_TOKEN, 'the demo session carries the demo token')
  assert(
    (session.expires_at ?? 0) * 1000 > Date.now(),
    'the demo session is not already expired',
  )
  assert(demo.DEMO_ACCOUNT_TIER === 'elite', 'the demo account resolves to the Elite tier')
  assert(
    !admin.isOwnerEmail(demo.DEMO_ACCOUNT_EMAIL),
    'the demo email is NOT the platform owner email',
    'owner unlocks /dashboard/admin and Revenue Intelligence — a demo account must not',
  )
  assert(
    !admin.canUseAdminDashboard(user),
    'the demo user cannot reach the Owner Administrator dashboard',
  )
  assert(demo.demoEntitlement().isOwner === false, 'the demo entitlement is not an owner entitlement')
  assert(demo.demoEntitlement().isActive === true, 'the demo entitlement grants access')

  section('4. Every subscription-gated route opens at the demo tier')
  const tier = demo.DEMO_ACCOUNT_TIER
  const routes = [
    '/dashboard',
    '/dashboard/settings',
    '/dashboard/scanner',
    '/dashboard/quantum-readiness',
    '/dashboard/migration-planner',
    '/dashboard/shadow-crypto',
    '/dashboard/live-migration',
    '/dashboard/pqauth',
    '/dashboard/trust-dashboard',
    '/dashboard/qkms',
    '/dashboard/compliance',
    '/dashboard/audit-vault',
    '/dashboard/runtime-telemetry',
    '/dashboard/vault',
    '/dashboard/pki',
  ]
  const blocked = routes.filter((route) => !access.canAccessPath(tier, route))
  assert(
    blocked.length === 0,
    `all ${routes.length} sampled module routes open at tier "${tier}"`,
    blocked.length ? `blocked: ${blocked.join(', ')}` : '',
  )
  assert(
    access.TIER_RANK[tier] === Math.max(...Object.values(access.TIER_RANK)),
    'the demo tier is the top of the tier ladder (no module can out-rank it)',
  )

  section('5. Demo constants live in exactly one module')
  const owned = path.join('src', 'lib', 'demo-account.ts')
  const literals = [demo.DEMO_ACCESS_TOKEN, demo.DEMO_ACCOUNT_USER_ID, demo.DEMO_ACCOUNT_PASSWORD]
  const offenders: string[] = []

  const skipDirs = new Set(['node_modules', 'dist', '.git', 'test_images', 'video-production'])
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      if (skipDirs.has(entry)) continue
      const full = path.join(dir, entry)
      if (statSync(full).isDirectory()) {
        walk(full)
        continue
      }
      if (!/\.(ts|tsx)$/.test(entry)) continue
      const relative = path.relative(ROOT, full)
      if (relative === owned || relative === path.join('tools', 'demo-account-check.ts')) continue
      const source = readFileSync(full, 'utf8')
      for (const literal of literals) {
        if (source.includes(literal)) offenders.push(`${relative} contains a hardcoded demo literal`)
      }
    }
  }
  walk(path.join(ROOT, 'src'))
  walk(path.join(ROOT, 'tools'))

  assert(
    offenders.length === 0,
    'no file outside src/lib/demo-account.ts hardcodes a demo token, id or password',
    offenders.join('\n        '),
  )

  section('6. Call sites still import the guard')
  const wiring: Array<[string, string[]]> = [
    ['src/lib/supabase-server.ts', ['isDemoToken', 'createDemoUser']],
    ['src/lib/server-auth.ts', ['isDemoToken', 'createDemoUser']],
    ['src/api-server/subscription-guard.ts', ['isDemoUserId', 'isDemoModeEnabled']],
    ['src/hooks/use-subscription.ts', ['isDemoUserId', 'isDemoModeEnabled']],
    ['src/contexts/auth-context.tsx', ['isDemoCredential', 'isDemoSessionActive']],
    ['src/lib/supabase.ts', ['isDemoSessionActive']],
  ]
  for (const [file, symbols] of wiring) {
    const source = readFileSync(path.join(ROOT, file), 'utf8')
    const missing = symbols.filter((symbol) => !source.includes(symbol))
    assert(missing.length === 0, `${file} wires the demo guard`, missing.length ? `missing: ${missing.join(', ')}` : '')
  }

  console.log(`\n${checks - failures}/${checks} checks passed`)
  if (failures > 0) {
    console.log(`${failures} FAILED`)
    process.exit(1)
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
