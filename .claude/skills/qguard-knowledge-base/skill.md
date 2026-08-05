---
name: qguard-knowledge-base
description: Index and router for the QGuard Helix engineering knowledge base. Use at the START of any QGuard Helix development task to find the skill that already covers it — architecture, scanner engines, crypto detection, data integrity, debugging, testing, or a previously-resolved issue. Also defines how to GROW the knowledge base after every task.
priority: critical
owner: qguard-helix
version: 1.0
---

# QGuard Helix Engineering Knowledge Base

This is the institutional memory of the platform. Its purpose is that **no
problem is solved twice** and **no architectural decision is silently reversed**.

## How to use it

Before writing code for QGuard Helix:

1. **Check `qguard-common-issues-fixes` first.** If the symptom you are looking
   at appears there, the root cause and the proven fix are already written down.
   Symptoms are indexed by what the *user* sees, not by what the code does.
2. Load the domain skill for the area you are touching (table below).
3. Load `qguard-data-integrity` for ANY change that produces a number the UI
   displays. This is the most frequently violated contract in the platform.
4. Load `qguard-testing-validation` before claiming work is complete.

## Two skill families — do not confuse them

| Family | Skills | Answers |
|---|---|---|
| **Role advisors** (pre-existing) | `scanner-engineer`, `pqc-architech`, `migration-engineer`, `UX-Engineer`, `governance-architech`, `telemetry-auditor`, … | *What should be assessed and why* — domain responsibility |
| **Engineering knowledge** (this set) | the `qguard-*` skills | *How this codebase actually works, and what already went wrong* |

Use both: the advisor tells you what a good answer looks like, the engineering
skill tells you where the code is and which traps are already known.

## Router

| Working on… | Load |
|---|---|
| Platform structure, module communication, where code lives | `qguard-architecture` |
| Express `/api/v1`, Supabase, SSE, background work | `qguard-backend-engineering` |
| React, hooks, state, consuming SSE, render performance | `qguard-frontend-engineering` |
| Any displayed number, KPI, score, count | `qguard-data-integrity` |
| Scanner module execution, the Discovery Workflow, ledger | `qguard-scanner-orchestration` |
| Detecting algorithms in code / dependencies | `qguard-crypto-detection` |
| GitHub/GitLab/Bitbucket/Azure DevOps/local uploads | `qguard-source-discovery` |
| ML-KEM / ML-DSA / SLH-DSA / hybrid classification | `qguard-pqc-detection` |
| A bug with an unclear cause | `qguard-debugging-rca` |
| A symptom that feels familiar | `qguard-common-issues-fixes` |
| Proving work is done | `qguard-testing-validation` |
| Caching, budgets, scale | `qguard-performance` |
| Tenant isolation, secrets, credentials | `qguard-security-practices` |
| Naming, comments, tooling, shell traps | `qguard-development-standards` |

Shared contracts live in `.claude/skills/_shared/`:
`production-truth-rules.md`, `pqc-standards.md`, `security-standards.md`,
`telemetry-rules.md`, `ux-principles.md`, `verification-checklist.md`.

## The three non-negotiables

Everything else is guidance. These three are contracts:

1. **Single Source of Truth.** A value is computed in exactly one place and read
   everywhere else. Two panels showing the same concept must read the same
   variable, not two variables that "should" agree.
2. **Never fabricate.** No placeholder metrics, no invented telemetry, no score
   for a dimension that was not measured. Unmeasured renders as *Unknown* or
   *Not applicable with a reason* — never as zero, and never as a pass.
3. **Verification is completion.** Implementation is not done. Done means a
   check ran, and its output is quoted.

## Growing the knowledge base — do this every time

After ANY task that produced non-obvious knowledge:

1. **Does an existing skill cover this area?** Update it. Prefer updating over
   creating; a fragmented base is worse than a dense one.
2. **Was a bug involved?** Add a Problem → Root Cause → Solution → Prevention
   entry to `qguard-common-issues-fixes`. The Prevention line is mandatory —
   an entry without one has not been learned from.
3. **Did an assumption turn out wrong?** Record the assumption AND why it was
   plausible. Future-you will make it again otherwise.
4. **Did a check catch something reading the code did not?** Record the check
   command in `qguard-testing-validation`. Tests that caught real bugs are the
   highest-value artefacts in the repository.
5. **Keep entries specific.** "Be careful with state" teaches nothing.
   "`await fetchHistory()` inside the SSE reader stalls frame consumption"
   teaches something.

### Quality bar for an entry

An entry earns its place if it answers at least one of:

- Would someone otherwise spend an hour rediscovering this?
- Does it contradict a reasonable assumption?
- Does it name a file, function or command you would otherwise have to hunt for?

Delete entries that turn out to be wrong. A stale knowledge base is a liability.
