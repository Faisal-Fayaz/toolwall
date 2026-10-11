# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Base64-aware response scrubbing. `ImageContent.data`, `AudioContent.data` and
  `EmbeddedResource.blob` are decoded before inspection. Payloads that decode as
  text are scrubbed and re-encoded so they still work; binary payloads containing
  a credential are dropped rather than rewritten.
- Size-based decision-log rotation (`--log-max-bytes`, `--log-keep`), with
  generations read newest-first so `replay` sees a consistent window across
  rotation boundaries.
- `readRecent` streams and bounds, so replaying a large log no longer requires
  loading all of it into memory.
- `toolwall logs` — shows which log files exist and their sizes.
- `toolwall replay --limit N` — replay only the N most recent records.
- `SECURITY.md`, including an explicit statement of what toolwall does *not*
  protect against.
- Private vulnerability reporting and Dependabot security updates on the
  repository.

### Fixed
- `npm view` reporting a package as available does not prove it is *publishable*:
  npm separately rejects names too similar to existing ones. The publish gate now
  documents this.

## [0.1.0] — 2026-10-11

First release. Published as `gatewall`; the CLI binary is `toolwall`.

### Added

**Policy engine**
- Rego compiled to WebAssembly by OPA, evaluated in-process at ~2 ms per call.
- Precedence is deny > ask > allow: every matching rule is collected, then the
  strongest effect wins. First-match semantics are not used.
- Rules are data, not Rego expressions, so policies can be written in plain
  JSON without installing a toolchain.
- Built-in host builtins: symlink-resolving path containment, credential-path
  detection, and recursive redaction.
- Fails closed. A policy that throws, returns nonsense, or is malformed denies
  the call and says so.

**Adapters**
- MCP stdio proxy: gates `tools/list` and re-checks `tools/call`. Filtering is
  UX; the per-call gate is the boundary, because a client can construct a
  `tools/call` without ever listing.
- Hook adapters for **Claude Code**, **Cursor** and **Codex**, covering the
  agents' built-in `Bash`/`Read`/`Write` tools, which never traverse MCP.
- Codex renders `ask` as `deny`: it parses the field but does not enforce it,
  and continuing the call would fail open.

**Approval**
- `ask` surfaces toolwall's reason to the host agent's own prompt, so the user
  sees why rather than clicking through unexplained friction.
- `toolwall approve` mints a one-shot grant scoped to the exact call, so the
  identical retry passes once.
- Grants downgrade `ask` → `allow` only. No grant can unlock a `deny`.

**Replay**
- Re-evaluates recorded history against a candidate policy.
- Separates what the policy does from what grants did, so calls allowed by a
  grant are reported as grant-dependent rather than as policy drift.
- Exits non-zero only on a genuine policy change that would newly block a call,
  so it can gate CI.

**Secrets**
- `{{secret:name}}` references substituted at the proxy boundary; the reference,
  not the credential, is what reaches logs.
- Upstream responses scrubbed before the agent sees them, by literal value and
  by credential shape (`ghp_`, `sk-`, `AKIA`, `AIza`, `xox*`, JWTs, PEM blocks,
  `Bearer`). Redactions are visible rather than silently truncating.
- Unknown secret references fail closed instead of being forwarded upstream.
- `toolwall scrub` — redact secrets from text before sharing it.

**Packaging**
- 152 kB, precompiled policy, no OPA binary, no build step.
- Verified by installing the tarball into a clean project with no OPA present
  and running the CLI.

### Known limitations
See [SECURITY.md](SECURITY.md). Chiefly: shell safety is not a security
boundary, path rules do not apply to shell commands, and scrubbing cannot see a
credential rendered as pixels.

[Unreleased]: https://github.com/Faisal-Fayaz/toolwall/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Faisal-Fayaz/toolwall/releases/tag/v0.1.0