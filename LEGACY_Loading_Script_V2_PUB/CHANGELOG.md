# Changelog - Phoenix Loading Script V2 (Legacy)

All notable changes to the legacy Phoenix loading scripts (V2) are recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Rule:** every change to this folder MUST add an entry here before it is published.
See `CLAUDE.md` in this folder and `../UTILS_PUBLISH_TO_PUBLIC.md`.

> **Status: maintenance only.** V2 receives security and compatibility fixes only.
> New scanners, new formats and new features go to `../Loading_Script_V5`.

## [2.0.0] - 2026-09-09 - **Baseline release and release tracking**

### ✨ Added

- `VERSION` — single source of truth for the release number of this bundle.
- `CHANGELOG.md` — this file. First formal changelog for V2.
- `README.md` — entry point, scanner list, upgrade note pointing at V5.
- `CLAUDE.md` — mandatory changelog rule for anyone (human or agent) editing this folder.
- `.publishignore` — per-bundle deny list applied by the publish tool. Keeps sample scan
  data, client data and internal-only notes out of the public repo.
- Publish gate in `../publish_utils_to_public_repo.py` (see the V5 changelog for details).
  The public copy is published to `LEGACY_Loading_Script_V2_PUB` and tagged
  `loading-v2-v<VERSION>`.

### 📚 Documentation

- **`README.md` — new "How it works" section** with four diagrams:
  - the end-to-end flow, showing that V2 uploads the **raw** scanner file and Phoenix
    parses it **server side**;
  - a sequence diagram of every API call, in order;
  - V5 and V2 side by side, so the design difference is visible in one picture;
  - a decision flowchart for whether to migrate.
- **New "Why V2 is not recommended" section**: ten concrete limitations, each paired with
  what V5 does instead. The headline ones are credentials living in the source file,
  no control over field mapping, one script per scanner, and no batching.
- A worked before-and-after showing the same import in V2 and in V5.

### 📌 Baseline contents

This release records the existing V2 tree as the `2.0.0` baseline. No script behaviour
changed. The scripts covered are:

| Script | Purpose |
|--------|---------|
| `Phoenix_import_script.py` | Single-file import to Phoenix, with scanner-type validation |
| `phoenix_multi_import.py` | Multi-file / multi-scanner import driver |
| `aqua_import2-1.py`, `aqua_import2-2.py` | Aqua Security scan import |
| `snyk_import.py`, `snyk_import2.py` | Snyk scan import |
| `sonarqube_import_pipeline.py` | SonarQube import from a CI pipeline |
| `sonarqube_import2 simple_file_v2 copy.py` | SonarQube import from a local file |
| `thrivi_Scan.py` | Trivy scan import |

### 🎯 Why This Matters

- V2 is still in use by older pipelines. It now has a version number that a pipeline can pin.
- Anything shipped from V2 to the public repo is now traceable to a tag.
