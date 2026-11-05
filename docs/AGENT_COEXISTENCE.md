# Multiple agents on one host or asset

Collector, Scanner, Patcher and Migration Operator may share a host and an asset
profile. Deploy each role with a distinct agent identity, and select the **same
existing asset** as Assigned asset. A hostname alone is not sufficient evidence
to merge two machines. Reuse an identity only when upgrading that same agent.

| Role | Work | Write authority |
| --- | --- | --- |
| Collector | Scoped inventory and runtime observations | Read-only |
| Scanner | Scoped cryptographic assessment | Read-only |
| Patcher | Explicitly approved remediation jobs | Authorized configuration paths |
| Migration Operator | Explicitly approved migration jobs | Authorized migration/configuration scope |

The platform keeps enrollment, signing keys, queues, heartbeats and scan receipts
per agent. Components and findings are collected into the assigned asset, with
their original reporting agent retained. Concurrent metadata updates use database
compare-and-set retries. An unknown or partial observation cannot clear another
agent's measured exposure.

## Install or upgrade

Generate new **1.6.3 or later** installers for every deployed identity in the Agent
Center. Old downloaded scripts retain their original logic and runtime digest.
Keep all four agents assigned to the intended host's existing asset profile.
Authorize writes only for Patcher/Migration Operator and only for approved scope.

Windows uses `QGuardHelixAgent-<agent-id>` and
`%ProgramData%\QGuardHelix\Agents\<agent-id>`. Linux uses
`qguard-agent-<agent-id>.service` with per-agent configuration and signing state.
Docker has an agent-specific Compose project and private signing-state volume.
Kubernetes has an agent-specific namespace, including credentials, deployment,
and PVC, so deleting one manifest does not delete another agent's resources.
Downloaded artifact filenames also include the agent ID.

Installed legacy identities retain their signing keys when migrated. If several
roles previously overwrote the legacy shared slot, rerun each role's new installer
once. The Windows installer requires Administrator; native Linux services run as
root. Portable writer processes also need access to the shared coordination
directory and their authorized target files; a permission failure withholds work.

## How changes are coordinated

Read-only collection and scanning can run concurrently. A writer acquires the
shared host mutation lock **before** polling for write jobs. Other writers report
that they are waiting and leave their jobs pending. One job is dispatched per poll.
The lock covers precheck, patching, validation and automatic rollback.

The server atomically claims each job for one executor. Another Patcher cannot
win the same claim. A job must match the executor's asset binding as well as its
path/target policy; an identical file path on another machine is insufficient.
Patcher and Migration Operator queues enforce their separate execution classes.
A role-specific refusal does not mark a job globally blocked for other agents.

Writers also lock beside the canonical target file, under `.qguard-coordination`.
Containers sharing a writable configuration volume therefore share its lock even
when their installation paths differ. Mount that entire writable configuration
directory, including its coordination directory, when sharing it between
containers. Single-file bind mounts cannot support guarded atomic replacement.
Do not place configuration files on a filesystem that lacks atomic creation and
replacement semantics. Kubernetes templates grant no new host privileges or
configuration mounts automatically.

Configuration replacement is atomic, so scans read a complete old or new file.
Windows replacement preserves the existing file ACL; POSIX replacement preserves
mode and ownership. A stale write or automatic rollback is withheld if the
configuration changed after inspection. A rollback that already matches the
verified pre-change digest performs no additional write. Explicit manual restores
retain their existing authorization and verification requirements.

Pre-change snapshot IDs are stable per tenant/job, with uniqueness enforced by
the database. Concurrent jobs receive different snapshots, and competing claims
for the same job reuse its snapshot. Integrity is checked before dispatch.

The backend withholds write jobs and rollback dispatch from runtimes older than
1.6.3 because they do not participate in shared-host coordination. Read-only scans
continue under their existing version/security rules. Upgrade every writer before
relying on these guarantees; already-running older jobs must finish or be stopped.

## Lock recovery and diagnostics

Locks are released after work or a handled error. A confirmed-dead process on the
same host can be recovered automatically. A live owner is never evicted because a
job takes longer than expected. If a lock owner cannot be identified, belongs to
another container/node, or its record is damaged, execution stays withheld. Stop
or verify the owner before removing that specific stale lock; never delete an
active lock directory. This preserves safety when process liveness cannot be
proved across container or host boundaries.

Windows startup logs are in the agent's private `agent.log`; Linux uses the
agent-specific systemd journal. Waiting messages describe actual lock contention.
The scan receipt and activity timeline remain specific to the reporting agent.

## Verification

- `npx tsx tools/agent-coexistence-check.ts`: four real processes, concurrent
  readers, serialized writes, stale-write refusal, dead-owner recovery, and
  unique parseable deployment artifacts.
- `npx tsx tools/agent-coexistence-live-check.ts`: isolated QA tenants, four real
  role scans, shared profile/provenance, concurrent queue writes, atomic claims,
  role boundaries, snapshot uniqueness and tenant isolation.
- Existing startup, transport, rollback and scan-observability suites.

Windows replacement behavior: [Microsoft ReplaceFile documentation](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew).
