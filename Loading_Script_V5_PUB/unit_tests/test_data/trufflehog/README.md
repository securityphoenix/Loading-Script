# TruffleHog Jenkins fixtures

`jenkins_wrapper_v1_sanitized.json` is a sanitized derivative of the client
artifact supplied for this investigation as `findings.json`.

Sanitization performed:

- customer hostnames, project paths, job names, timestamps, and identifiers were
  replaced with synthetic values;
- every secret-bearing value was replaced with an explicit `MUST_NOT_USE_*`
  sentinel;
- the observed top-level keys, nesting, field names, and JSON value types were
  retained;
- the observed empty `RawV2` and `Redacted` values were retained; and
- a second synthetic build was added with matching secret sentinels to test
  repeated-build deduplication.

This fixture is repository evidence for the client-specific
`schema_version: "1.0"` envelope. It is not asserted to be an official
TruffleHog output contract. The fixture's sentinels are never suitable for an
actual scan; tests assert they never reach the Phoenix payload or logs.
