# Device cleanup - October 30, 2026

C: free space increased from 16.12 GB to 53.32 GB.
Deleted 270477 files totaling 39.29 GiB in logical file lengths. Physical free-space changes differ because of filesystem accounting and concurrent activity.

## Removed

- Application crash dumps: 0.033 GiB.
- Browser disposable cache: 2.418 GiB.
- Browser shader cache: 0.035 GiB.
- External Rust debug build cache: 8.413 GiB.
- Generated test output (scripts and tracked files preserved): 0.011 GiB.
- npm download cache: 1.406 GiB.
- npm logs: 0 GiB.
- pip download cache: 0.029 GiB.
- Regenerable web build output: 0.269 GiB.
- Rust debug build cache: 16.293 GiB.
- Temporary files older than 24 hours: 9.927 GiB.
- VS Code crash dumps: 0.225 GiB.
- VS Code disposable cache: 0.231 GiB.
- Windows temporary files older than 24 hours: 0 GiB.

## Memory
- Closed Copilot, Signal, and Teams as requested. Processes remaining: 0.
- Available RAM at verification: 1.31 GiB of 15.76 GiB.
- VMware was left untouched as requested.

- vmware-vmx: 6.63 GiB summed working set.
- chrome: 2.06 GiB summed working set.
- ChatGPT: 1.16 GiB summed working set.
- svchost: 0.99 GiB summed working set.
- Code: 0.6 GiB summed working set.
- explorer: 0.32 GiB summed working set.
- mksSandbox: 0.31 GiB summed working set.
- node: 0.28 GiB summed working set.

## Preserved and verified
- Existing Git status unchanged, excluding this cleanup report folder: True.
- Preserved tracked files, test source scripts, personal files, credentials, installed dependencies, release installers, Android source, and Docker data.
- Skipped 540 locked or denied file/directory operations and 6022 recent temporary/log files.
- Rust debug caches will be regenerated on the next debug build.

## Large remaining storage locations (logical sizes measured before cleanup)
- OneDrive: 195.15 GiB.
- Fortinet installation files: 38.61 GiB.
- Docker data: 34.06 GiB. Docker engine was unavailable, so no Docker data was pruned.
- D: backup drive: essentially full; E: backup drive: 12.59 GiB free. Backup contents were preserved.

