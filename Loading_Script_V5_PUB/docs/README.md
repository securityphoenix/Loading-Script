# Documentation — Phoenix Multi-Scanner Import Tool (V5)

Start at [`../README.md`](../README.md) for what the tool is and how it works, and
[`../QUICK_START.md`](../QUICK_START.md) to run your first import.

Everything else lives here, in four folders.

| Folder | What is in it |
|---|---|
| `guides/` | How to do a thing. Setup, configuration, asset naming, tagging, batching, troubleshooting. |
| `reference/` | How the tool is built. Architecture, call flow, the API it talks to, the scanner support matrix, how to add a scanner. |
| `scanners/` | Notes for one scanner. Trivy, Prowler, Phoenix CSV. |
| `releases/` | Release notes for older versions. Current history is in [`../CHANGELOG.md`](../CHANGELOG.md). |

## Where do I start?

| I want to... | Read this |
|---|---|
| Run my first import | [`../QUICK_START.md`](../QUICK_START.md) |
| See every scanner I can import | [`reference/SCANNER_SUPPORT_MATRIX.md`](reference/SCANNER_SUPPORT_MATRIX.md) |
| Understand every command-line flag | [`guides/MULTI_SCANNER_COMMAND_GUIDE.md`](guides/MULTI_SCANNER_COMMAND_GUIDE.md) |
| Set up the config file | [`guides/CONFIGURATION_GUIDE.md`](guides/CONFIGURATION_GUIDE.md) · [`guides/CONFIG_FILE_GUIDE.md`](guides/CONFIG_FILE_GUIDE.md) |
| Choose direct upload or the client/service | [`guides/CLIENT_SERVER_VS_DIRECT_UPLOAD_GUIDE.md`](guides/CLIENT_SERVER_VS_DIRECT_UPLOAD_GUIDE.md) |
| Control how assets get named | [`guides/ASSET_NAMING_GUIDE.md`](guides/ASSET_NAMING_GUIDE.md) |
| Add CI metadata as tags | [`guides/TAG_CONFIGURATION_GUIDE.md`](guides/TAG_CONFIGURATION_GUIDE.md) |
| Understand `new` vs `merge` vs `delta` | [`guides/BATCHING_AND_IMPORT_TYPES.md`](guides/BATCHING_AND_IMPORT_TYPES.md) |
| Work out why an import failed | [`guides/TROUBLESHOOTING.md`](guides/TROUBLESHOOTING.md) · [`guides/DEBUG_AND_ERROR_LOGGING_GUIDE.md`](guides/DEBUG_AND_ERROR_LOGGING_GUIDE.md) |
| Hide hostnames and IPs before sending | [`guides/README_DATA_ANONYMIZER.md`](guides/README_DATA_ANONYMIZER.md) |
| Add support for a new scanner | [`reference/ADDING_NEW_SCANNER.md`](reference/ADDING_NEW_SCANNER.md) · [`reference/SCANNER_TRANSLATOR_GUIDE.md`](reference/SCANNER_TRANSLATOR_GUIDE.md) |
| See which Phoenix API calls are made | [`reference/PHOENIX_API_INTERACTION_GUIDE.md`](reference/PHOENIX_API_INTERACTION_GUIDE.md) |
| Read the code path end to end | [`reference/FUNCTION_CALL_FLOW_GUIDE.md`](reference/FUNCTION_CALL_FLOW_GUIDE.md) |

## Scanner notes

| Scanner | Document |
|---|---|
| Trivy | [`scanners/TRIVY_QUICK_START.md`](scanners/TRIVY_QUICK_START.md) · [`scanners/TRIVY_USAGE_GUIDE.md`](scanners/TRIVY_USAGE_GUIDE.md) · [`scanners/TRIVY_QUICK_REFERENCE.md`](scanners/TRIVY_QUICK_REFERENCE.md) |
| Prowler | [`scanners/PROWLER_UPLOAD_GUIDE.md`](scanners/PROWLER_UPLOAD_GUIDE.md) |
| Phoenix CSV | [`scanners/PHOENIX_CSV_README.md`](scanners/PHOENIX_CSV_README.md) · [`scanners/PHOENIX_CSV_QUICK_REFERENCE.md`](scanners/PHOENIX_CSV_QUICK_REFERENCE.md) |

Every other scanner is covered by the support matrix and the command guide. There are
200+ of them; only the ones with quirks get their own page.
