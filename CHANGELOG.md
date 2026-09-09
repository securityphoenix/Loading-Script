# Changelog — Phoenix Loading Scripts (public mirror)

Repository-level release log. Each bundle also keeps its own detailed changelog:

- [`Loading_Script_V5_PUB/CHANGELOG.md`](Loading_Script_V5_PUB/CHANGELOG.md)
- [`LEGACY_Loading_Script_V2_PUB/CHANGELOG.md`](LEGACY_Loading_Script_V2_PUB/CHANGELOG.md)

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Each bundle is versioned independently with [SemVer](https://semver.org/).

## 2026-09-09 — `loading-v5-v5.0.0`, `loading-v2-v2.0.0`

First tracked release of the public mirror.

### Added

- **Versioning.** Every bundle now has a `VERSION` file and a `CHANGELOG.md`.
  - `Loading_Script_V5_PUB` → `5.0.0` (realigned from the previous `3.x` series)
  - `LEGACY_Loading_Script_V2_PUB` → `2.0.0` (first formal version)
- **Release tags.** `loading-v5-v<VERSION>` and `loading-v2-v<VERSION>`, so a pipeline can
  pin an exact release.
- **`README.md` and `CHANGELOG.md`** at the repository root and in each bundle.
- **`.gitignore`** covering caches, runtime logs, OS noise and credential files.

### Fixed — repository hygiene

- Removed 236 files that should never have been public: `.DS_Store`, `__pycache__`,
  compiled `*.pyc`, and 139 runtime `*.log` files (including
  `phoenix-scanner-service/logs/job-*.log`).
- Removed 124 runtime scan files from `phoenix-scanner-service/uploads/` and the service
  database under `phoenix-scanner-service/data/`.
- Removed stray duplicate documents (`CHANGELOG copy.md`,
  `JSON_AND_GENERIC_IMPORTER_MAPPING_GUIDE copy.md`).

### Security

- Redacted Phoenix personal access tokens and client IDs that the previous publish had
  left in `config_multi_scanner.ini`, `unit_tests/` and `REFERENCE_DOCUMENTATION/`.
  **If you cloned this repository before 2026-09-09, treat any `pat1_...` value you find in
  your clone as compromised and report it.** The affected tokens are being rotated.
- The publish tool's sanitizer was hardened to catch commented-out assignments
  (`#client_secret = ...`), vendor-prefixed keys (`phoenix_client_secret`,
  `PHOENIX_CLIENT_SECRET`), inline command flags (`-F "phoenix_client_secret=..."`), and
  Phoenix PAT literals anywhere in a file.
- The sanitizer now leaves source code and documentation placeholders alone, so published
  scripts still run and published examples still read.

## Before 2026-09-09

The mirror was published as a rolling snapshot with no version numbers or tags. Bundle
history from that period is in each bundle's own `CHANGELOG.md`.
