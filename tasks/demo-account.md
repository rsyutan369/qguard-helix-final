# Demo / Test Account (Supabase-free sign-in)

## Goal
Sign in to Qguard Helix and reach every ELITE-tier module while the tenant's
Supabase project is restricted (`exceed_egress_quota`), so platform features can
still be demonstrated and tested. Temporary; removable in one commit.

## Constraint that shapes the design
The Supabase project restriction disables the WHOLE project API, not just
GoTrue. So this cannot be "log in against Supabase with a seeded user" — the
identity itself has to exist outside Supabase, on both the browser and the
Express API side.

## Threat model / safety rules
1. OFF by default. Enabled only by an explicit env flag (`VITE_DEMO_ACCOUNT=true`)
   read by BOTH the browser bundle and the API server. Absent flag = the demo
   token is an unknown token and `getServerUser` returns null (401), exactly as today.
2. The demo identity is NOT the platform owner. `/dashboard/admin`,
   `/api/v1/admin` and Revenue Intelligence stay closed (`isOwnerEmail` is the
   only key to those, and the demo email is not it).
3. Enabled state is visible in the UI (badge) and logged loudly at API boot, so
   it can never be mistaken for a real session or shipped unnoticed.
4. One module owns every demo constant, so removal is `git rm` + revert of the
   call sites listed below.

## Execution plan
| # | File | Change |
|---|------|--------|
| 1 | `src/lib/demo-account.ts` (new) | Single source of truth: flag, identity, token, tier, session factory, storage helpers. Isomorphic (no browser/Node-only API at module scope). |
| 2 | `src/contexts/auth-context.tsx` | `signIn` short-circuits on demo credentials; session restored on reload; `signOut` clears it without calling Supabase. |
| 3 | `src/lib/supabase.ts` | Demo overlay on the exported client's `.auth` so every `supabase.auth.getSession()/getUser()` caller (9 files) sees the demo session. `.from()`/`.channel()` untouched. |
| 4 | `src/hooks/use-subscription.ts` | Demo user resolves to `elite` / `active` without a billing query. |
| 5 | `src/app/authentication/login/page.tsx` | "Continue as demo" button, rendered only when the flag is on. |
| 6 | `src/components/DemoModeBadge.tsx` (new) + `src/App.tsx` | Persistent "DEMO SESSION" badge while active. |
| 7 | `src/lib/supabase-server.ts` | `getServerUser` returns the demo user for the demo token (flag-gated) before any JWKS work. |
| 8 | `src/lib/server-auth.ts` | Same short-circuit for the legacy `getServerUserFromToken`. |
| 9 | `src/api-server/subscription-guard.ts` | `resolveEntitlement` returns Elite/active for the demo user. |
| 10 | `vite.config.ts` | Add the flag to the env allow-list copied into `process.env` (dev API server). |
| 11 | `.env.example` | Document the flag + credentials. |
| 12 | `tools/demo-account-check.ts` | Offline assertion suite: default-off, tier ladder, owner isolation, single-module ownership. |

## Validation strategy
- `npx tsx tools/demo-account-check.ts` — must pass with the flag both off and on.
- `npm run lint` (tsc --noEmit) — clean.
- Browser: sign in with the demo credentials, confirm every nav section renders,
  confirm `/dashboard/admin` is refused.

## Known limitation (state honestly, do not paper over)
The demo account restores ACCESS, not DATA. Every Supabase-backed panel still
reads a restricted project and will render its empty state. Live engines that
compute in-process (Public Scan, Scanner, Crypto Exposure Web/Local/Dev) do
produce real results because they stream over SSE and only *persist* to Supabase.
Full data fidelity needs a reachable Supabase project — the codebase already
supports a second one via `VITE_SUPABASE_FALLBACK_URL` / `..._ANON_KEY`.

## Rollback
Delete `src/lib/demo-account.ts`, `src/components/DemoModeBadge.tsx`,
`tools/demo-account-check.ts`, and revert the 8 call sites above. Or simply
remove `VITE_DEMO_ACCOUNT` from `.env` to make it inert.
