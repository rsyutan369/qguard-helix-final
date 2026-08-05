---
name: qguard-debugging-rca
description: Systematic root-cause analysis for QGuard Helix, plus the specific investigative traps this codebase has already produced. Use when a bug's cause is unclear, when a symptom does not match the obvious explanation, when a fix would only hide a symptom, or when reading the code has failed to explain the behaviour.
priority: critical
owner: qguard-helix
version: 1.0
---

# Debugging & Root Cause Analysis

**Eliminate root causes; never patch symptoms.** A fix that makes a symptom
disappear without explaining it has hidden a defect, not removed one.

## Method

1. **Reproduce deterministically.** If you cannot reproduce it, you cannot know
   you fixed it.
2. **Derive the fingerprint.** Work out what each candidate cause would produce,
   then compare against the observed numbers. This is the fastest technique in
   this codebase — see the worked example below.
3. **Confirm at the source.** Instrument or probe the actual value; do not infer
   it from reading.
4. **Expect several causes.** The Discovery Workflow bug had **four independent
   root causes**. Finding one plausible cause is not finishing.
5. **Fix at source, then re-verify** with a check that would have failed before.

## Worked example — fingerprinting

Symptom: nearly every Discovery Workflow surface read SKIPPED, with these counts:
Asset Discovery 2/3 · 28 findings; Transport 2/3 · 11; Code 1/4 · 0; Posture 2/7 · 32.

Reasoning: `audit-history-logger` showed **32**, but the backend sets it to `1`.
32 was the *web scanner's total finding count* — the value its report-generator
module reports. That single number proved the UI state was frozen at the moment
the nested `report-generator` completed, i.e. the client had accepted a
**per-target** `scan-complete` as the end of the whole job.

The mismatched number identified the cause before any code was read.

## Traps this codebase has produced

**Invisible bytes.** A shell heredoc wrote a literal `0x08` backspace instead of
`\b`, so a regex silently never matched. `grep`, `sed` and file readers all
render `0x08` as nothing — the source *looked* correct.

```bash
python -c "import io;d=io.open('f.ts','rb').read();print(d.count(b'\x08'))"
```

Same trap for `\f \v \a`. Prefer the Edit tool over shell heredocs for anything
containing regex escapes.

**Substring collisions.** `includes('symmetric')` matches `"asymmetric"`.
`hash(` is a substring of `createHash(`. `includes('hash')` claims
`"Web Crypto (hash)"`. Always test a substring rule against its superstrings.

**Case sensitivity.** `/\bRSA\b/` will not match `'rsa'`. Real code uses
lowercase algorithm strings.

**Absence is not evidence.** A module with no state was rendered as "skipped".
"Nothing reported" and "reported nothing" are different facts and must have
different representations.

**Zero is ambiguous.** Zero findings means *found nothing* or *could not look*.
Prove which with a positive control before drawing any conclusion.

**Order-of-execution assumptions.** Per-module counts recomputed from `results`
were wrong during the first target, because `results` is only appended when a
target *finishes*.

**Silent config gates.** Unauthenticated GitHub API is 60 req/hr/IP. The engine
was correct; the environment was exhausted. Check
`curl -s https://api.github.com/rate_limit` before suspecting code.

**Stale runtime.** Express routes register at server start — a route change
without a restart looks like the edit had no effect. `VITE_`-prefixed env vars
are inlined at build time; editing `.env` without rebuilding changes nothing.

## When your own test fails

Suspect the test first. Several assertions written during this work were wrong:

- asserting `.yaml` was not a priority extension — it is
- asserting one finding where several *distinct* rules legitimately fire
- a fixture reason that did not match the module it described

A failing assertion is a hypothesis about the code. Check the hypothesis before
changing the code.

## Escalation ladder

| Step | Action |
|---|---|
| 1 | Search `qguard-common-issues-fixes` for the symptom |
| 2 | Fingerprint: which cause predicts these exact numbers? |
| 3 | Probe the real value (script the engine directly, `curl` the route) |
| 4 | Positive control: prove the component works at all |
| 5 | Byte-level check for invisible characters |
| 6 | Fix at source; add a check that fails without the fix |
| 7 | Record the entry in `qguard-common-issues-fixes` |

## Reporting a root cause

State the **causal chain**, not the fix:

> The nested web scan emits its own `scan-complete` per target. The API forwarded
> it verbatim. The client treated it as terminal, so it marked every
> not-yet-reported module skipped and graded a partial estate.

If you found multiple causes, list them all — reporting one implies the others
were not there.
