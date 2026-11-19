# Branch consolidation and CI repair — 2026-11-19

## Branch decisions

`backup/pre-integration-20261119` preserves the original working branch at
`7b8103b`. `codex/consolidate-main-cleanup` records the branch reconciliation.

| Branch | Decision |
| --- | --- |
| `feature/qguard-offline-mesh-xfer-vault` | Retain its current application changes; consolidate unpublished commits into a clean delivery snapshot so generated multi-gigabyte files are not uploaded. The original branch is retained. |
| `feature/local-agent-deploy` | Reconcile the unique commit while retaining newer request signing, policy handling, and write authority already present in the working branch. |
| `origin/claude/assets-dashboard-theme-redesign-j2usde` | Retain the newer asset register. It supersedes the old redesign and preserves source provenance, scan freshness, shared inventory calculations, and scoped exports. |
| `origin/claude/quantum-vault-encryption-review-551bzm` | Integrate recipient fingerprint confirmation and passphrase checks; preserve current v5 containers, provider-backed cryptography, legacy import protections, and version 1.5.3. |
| Other feature, marketing, and local Claude branches | Already ancestors of `origin/main`; no additional code needs merging. |

`codex/main-ready-clean` is the delivery branch based on `origin/main`. Its
snapshot excludes generated output and browser-test profiles while retaining
those local files. Original branch history remains available in the backup and
integration branches. Do not push the original oversized feature branch or use
`git push --all`.

## CI failure evidence

The failures were inspected using the authenticated GitHub Actions API:

- CI run `42001650858`, container job: setup fails because
  `aquasecurity/trivy-action@0.28.0` does not exist. Use `@v0.28.0`.
- The same run, secret scan: 70 findings were individually checked against
  their committed lines. They are source hashes, public certificate digests,
  and a tokenizer model identifier. `.gitleaksignore` records those exact
  historical fingerprints; no rules or entire files are excluded.
- Deploy API run `42001650916`: `digitalocean/action-doctl@v2` reports
  `Input required and not supplied: token`. The owner confirmed that this
  DigitalOcean Kubernetes workflow is obsolete. Remove the workflow and its
  unused shared deployment action; retain the API image verification in CI.

## Cleanup

- Remove the obsolete script that granted subscriptions to fixed QA accounts.
- Remove the stray `src/app/test_write_access.txt` file.
- Remove old source-copy/hash snapshots and generated test-results JSON.
- Remove seven generated `.report-smoke/dedup-out.*` reports.
- Stop tracking `output/`, `.codex-tmp/`, `.codex-logs/`, and `.playwright-cli/`;
  keep their local contents and ignore future generated output.
- Require explicit QA account configuration in the two remaining live probes.
- Keep useful regression suites, crypto self-tests, deployment probes, and
  automatic rollback checks.

No remote branches or database records were deleted. Existing unstaged deletions
under `Website_Creation_Resources/` and `videos/` belong to the user's prior work
and were not staged as part of this consolidation.

## Verification

- Root TypeScript check and client bundle boundary: passed.
- Web production build: passed; existing bundle-size/tooling warnings remain.
- Messaging TypeScript check and production build: passed.
- Messaging frontend: 89 files, 771 tests passed with experimental Node Web
  Storage disabled. The package test command now applies this documented fix.
- Deployment-readiness checks: 57 passed.
- Agent scope and write-authority checks: 83 passed.
- Native Rust, remaining domain suites, and delivery secret scan: see the final
  verification result before publishing.

Docker Desktop's Linux engine is not running on this machine, so the API image
could not be built locally. A successful image run on GitHub remains necessary.

## Publishing

After the remaining verification is complete, publish the delivery branch:

```powershell
git push -u origin codex/main-ready-clean
```

Open a pull request with base `main` and compare `codex/main-ready-clean`.
Review the combined changes and wait for CI before merging. Once merged:

```powershell
git switch main
git pull --ff-only origin main
```

Keep the backup until the merged application and installer have been verified.
Only delete obsolete remote branches after confirming their changes landed.
