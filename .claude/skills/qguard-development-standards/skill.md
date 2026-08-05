---
name: qguard-development-standards
description: Coding, naming, commenting and tooling standards for QGuard Helix, including the Windows/PowerShell and shell-escaping traps that have caused real defects. Use when writing or reviewing any code in this repository, running scripts, or performing scripted edits.
priority: high
owner: qguard-helix
version: 1.0
---

# Development Standards

## Code style

Match the surrounding code — comment density, naming, idiom. A file that reads as
though one person wrote it is worth more than a file that follows an external
style guide.

- Strong typing; no `any` on a public boundary.
- Reusable modules over duplicated logic. If backend and frontend need the same
  rule, extract a **pure, dependency-free module** and import it from both.
- Every code path handles error, loading and empty states.
- No dead code, no hardcoded values, no duplicate APIs or telemetry pipelines.

## Comments explain WHY, and encode hard-won facts

The valuable comment is the one that stops the next person reverting a fix.

```ts
/* A measurement is never downgraded to "not applicable".
   Module states are per RUN, not per target, so in a mixed queue
   (example.com + a GitHub repo) the repository pass would otherwise mark the
   TLS modules inapplicable and erase evidence the earlier target produced. */
const alreadyMeasured = state.status === 'Completed' || state.status === 'No findings'
if (alreadyMeasured && patch.status === 'Skipped') return
```

```ts
// `includes('symmetric')` also matches "asymmetric"; match the surface exactly
// so an RSA observation is never filed as a cipher suite.
if (category.includes('cipher') || category === 'symmetric encryption') return 'cipher-suite-scanner'
```

Do not write comments that restate the code. Do write comments that name the bug
the line prevents.

## Naming

- Files: `kebab-case.ts`; React components `PascalCase.tsx`.
- Surface-local modules use a leading underscore (`_intel.ts`, `_sections.tsx`).
- Status vocabularies are closed unions, never free strings.
- Prefer names that state the contract: `evidenceModules` vs `modules`,
  `decompositionScore` vs `score2`.

## Scripted edits — the escaping trap

A `python - <<'PY'` heredoc wrote a literal `0x08` **backspace byte** instead of
the two characters `\b`, silently disabling a regex. `grep`, `sed` and file
readers all render `0x08` as nothing, so the source *looked* correct.

**Use the Edit tool for anything containing regex escapes.** If a scripted edit is
unavoidable:

```bash
# verify afterwards — must print 0
python -c "import io;d=io.open('f.ts','rb').read();print(d.count(b'\x08')+d.count(b'\x0c')+d.count(b'\x0b'))"
```

Also: use `with open(...)` in Python edit scripts. A bare
`io.open(p,'wb').write(data)` has been observed not to flush on Windows.

## Windows / PowerShell

- PowerShell here is **5.1**: no `&&`, no `||`, no ternary, no `??`.
  Use `A; if ($?) { B }`.
- Do not redirect a native executable's stderr inside PowerShell — it wraps
  lines in ErrorRecords and sets `$?` false even on exit 0.
- `.ps1` files written by tools are BOM-less UTF-8 and get parsed as ANSI —
  keep scripts **pure ASCII**, or em-dashes become phantom parse errors.
- Prefer the Bash tool for POSIX-style work; both are available.

## Tool scripts

- `process.exitCode`, not `process.exit()`, when the script opened a server or
  socket — forcing exit races libuv teardown on Windows and turns a passing run
  into exit 127.
- Print `ok` / `FAIL` per assertion so failures are greppable.
- Keep them dependency-free and runnable with `npx tsx`.

## Definition of done

- [ ] Types pass for the files you touched.
- [ ] `npm run build` succeeds.
- [ ] The relevant `tools/*-check.ts` pass, output quoted.
- [ ] New behaviour has a test that fails without the change.
- [ ] Comments encode any non-obvious reason.
- [ ] Knowledge captured per `qguard-knowledge-base`.
- [ ] Anything unverified is stated plainly, not implied.

## Reporting work

Report outcomes faithfully. If tests fail, say so and quote the output. If a step
was skipped or could not be run — no browser, no credentials, no live instance —
say which, rather than describing the work in a way that implies it was checked.
Overstated completeness is the most expensive error in a knowledge base, because
it is inherited.
