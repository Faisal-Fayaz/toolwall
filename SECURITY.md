# Security Policy

## Scope: what toolwall does and does not protect against

Being explicit here matters more than usual, because a security tool that is
misunderstood is worse than no security tool. Please read this before relying on
anything below.

### What it does

- **Argument-level policy.** Calls are judged on what they *do*, not which tool
  they are. `read_file` is benign until someone points it at `.env`.
- **Response scrubbing.** Upstream results are scrubbed before the agent sees
  them — by literal secret value and by credential shape — including base64
  payloads in `ImageContent`, `AudioContent` and `EmbeddedResource.blob`.
- **Referenced credentials.** The agent passes `{{secret:name}}`; the real value
  is substituted at the proxy boundary and never reaches the model or the log.
- **Default-deny.** A policy that errors denies the call rather than allowing
  it.

### What it does NOT do — read this part

- **Shell safety is not a security boundary.** `command_contains` matches
  substrings in the raw command line. It catches `git push --force` and is
  defeated by `$(...)`, `eval`, variable expansion, aliases, or a renamed
  binary. **If you need a real boundary for shell execution, use OS-level
  isolation** — a container with a read-only root and an egress allowlist.
  toolwall does not provide one and does not claim to.
- **Path rules do not apply to shell commands.** `/etc/passwd` inside
  `cat /etc/passadow` is not matched by `arg_path_prefix`; a command is not a
  path. No attempt is made to extract paths from shell strings, because that
  requires the same evadable parsing described above.
- **Scrubbing is not a complete control.** A credential rendered as *pixels* in
  a screenshot is invisible to byte search — that is OCR. Scrubbing reduces
  accidental exposure; it does not eliminate it.
- **It is a policy layer, not a sandbox.** toolwall gates what it can observe.
  It cannot constrain what a subprocess does after a permitted call returns.
- **Filtering `tools/list` is not authorization.** A hidden tool is still
  re-checked on `tools/call`, because a client can construct that request
  without ever listing. Both gates exist for this reason.
- **Codex hook support is partial by host design.** Codex parses
  `permissionDecision: "ask"` but does not enforce it — an unsupported field
  makes it mark the run failed and *continue the call*. toolwall therefore
  renders every `ask` as a `deny` for Codex. Cursor's CLI has partial hook
  support, and `beforeReadFile` denials are not always honoured there.

## Supported versions

Only the latest release receives security fixes.

| Version | Supported |
|---|---|
| 0.1.x | ✅ |
| < 0.1.0 | ❌ |

## Accepted risk: sprintf-js (GHSA-hp3w-g68c-fv3c)

Dependabot reports a medium advisory for `sprintf-js`, pulled in transitively by
`@open-policy-agent/opa-wasm`. It is **the latest published version and there is
no patch** (checked against the advisory).

It is a denial of service via unbounded precision specifiers in `sprintf`. It is
not reachable from agent input here:

- Format strings live in the `.rego` policy, which the operator writes and
  which is compiled to WebAssembly ahead of time. Agent-controlled data arrives
  as `input` and is never used as a format string.
- Reaching it requires an attacker who can already write your policy file, and
  someone who can write your policy file already has code execution.

So the exposure is limited to a self-inflicted DoS by a policy author, which is
below the bar for a vulnerability report. It is recorded here rather than
silenced, because "Dependabot says so" is not the same as "it affects you" and
the distinction should be visible.

If OPA ever ships a runtime without this dependency, or a patched
`sprintf-js` appears, this entry should be revisited.

## Reporting a vulnerability

**Please do not open a public issue for a security report.**

Email **<fai504438@gmail.com>** with:

- what the issue is, and what an attacker gains
- the version (`npm ls -g gatewall` or `toolwall --version`)
- a minimal reproduction if you have one
- whether you have disclosed it anywhere else

You should get an acknowledgement within 72 hours. I will tell you when a fix
lands, and credit you in the changelog unless you would rather I did not.

If you prefer, GitHub's [private vulnerability reporting][pvr] is enabled on
this repository — use the *Security* tab → *Report a vulnerability*.

[pvr]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing

## Out of scope

These are not vulnerabilities in toolwall:

- An agent running a command that policy allows, and the command doing damage.
- A user writing a permissive policy and then being surprised by it.
- Credentials present in a response that does not match any known shape and are
  not visibly a credential.
- Denial of service against the local proxy itself (it binds to loopback and
  speaks to a single local agent).