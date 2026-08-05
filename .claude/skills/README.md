# QGuard Helix Claude Skills Knowledge Base

Two complementary families of skills live here.

## 1. Role advisors — *what* to assess

Domain authorities defining responsibilities, standards and what a good answer
looks like.

`scanner-engineer` · `discovery-engineer` · `pqc-architech` · `migration-engineer`
`intelligence-engineer` · `observability-engineer` · `telemetry-auditor`
`trust-engineer` · `ecosystem-engineer` · `governance-architech` · `UX-Engineer`
`PQAuth-architech` · `Qkms-enginner` · `quantum-vault-engineer`
`Report_Generation_Skills` · `Harvest_Now_Decrypt_Later`
`AI_Compliance_Advisor` · `AI_Crypto_Agility_Advisor` · `AI_Cryptography_Advisor`
`AI_Executive_Advisor` · `AI_Migration_Advisor`

## 2. Engineering knowledge — *how this codebase works*

Where the code lives, the patterns that are proven here, and every issue already
diagnosed and fixed.

| Category | Skill |
|---|---|
| **Index / router** | `qguard-knowledge-base` |
| Architecture | `qguard-architecture` |
| Backend engineering | `qguard-backend-engineering` |
| Frontend engineering | `qguard-frontend-engineering` |
| Enterprise UI & UX | `qguard-enterprise-ux` |
| Data integrity (SSOT) | `qguard-data-integrity` |
| Scanner orchestration | `qguard-scanner-orchestration` |
| Cryptographic detection | `qguard-crypto-detection` |
| Source discovery | `qguard-source-discovery` |
| Post-quantum detection | `qguard-pqc-detection` |
| Migration platform | `qguard-migration-platform` |
| Reporting & analytics | `qguard-reporting-analytics` |
| Sophia AI Copilot | `qguard-sophia-ai` |
| Performance & scale | `qguard-performance` |
| Security practices | `qguard-security-practices` |
| Testing & validation | `qguard-testing-validation` |
| Debugging & RCA | `qguard-debugging-rca` |
| **Common issues & fixes** | `qguard-common-issues-fixes` |
| Development standards | `qguard-development-standards` |

Shared contracts: `_shared/` — `production-truth-rules.md`, `pqc-standards.md`,
`security-standards.md`, `telemetry-rules.md`, `ux-principles.md`,
`verification-checklist.md`.

## Start here

1. `qguard-knowledge-base` — routes you to the right skill.
2. `qguard-common-issues-fixes` — if you have a symptom, it may already be solved.
3. The domain skill for the area you are touching.
4. `qguard-testing-validation` — before claiming anything is done.

## The three non-negotiables

1. **Single Source of Truth** — one computation, many readers.
2. **Never fabricate** — unmeasured renders as Unknown, never as zero or a pass.
3. **Verification is completion** — quote the command and its output.

## Keeping it alive

After any task producing non-obvious knowledge: update the existing skill
(preferred) or add one; add a Problem → Root Cause → Solution → **Prevention**
entry to `qguard-common-issues-fixes`; record any check that caught a real bug.
Delete entries that turn out to be wrong — a stale knowledge base is a liability.

Format: `.claude/skills/<name>/skill.md`, YAML frontmatter with
`name`, `description`, `priority`, `owner`, `version`. The `description` is what
Claude matches on — write it as *when to use this*, not as a title.
