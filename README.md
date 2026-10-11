# toolwall

[![CI](https://github.com/Faisal-Fayaz/toolwall/actions/workflows/ci.yml/badge.svg)](https://github.com/Faisal-Fayaz/toolwall/actions/workflows/ci.yml)

[![npm](https://img.shields.io/npm/v/toolguard.svg)](https://www.npmjs.com/package/toolguard)

A policy firewall for AI agent tool calls. Sits between an agent and its MCP
servers, gates every call against a policy, and lets you tune that policy against
your real history instead of guessing.

**The point:** most agent tooling gates on *which tool* is being called.
toolwall gates on **what the call actually does**. `read_file` is benign until
someone points it at `.env`.

```
agent ──▶ toolwall ──▶ upstream MCP server
           │
           ├─ tools/list  filter what the agent can discover   (UX)
           ├─ tools/call  gate every invocation               (security boundary)
           └─ decision log  every verdict, redacted at write
```

## Status

| | |
|---|---|
| **v0.1** | MCP stdio proxy — covers *any* agent that speaks MCP |
| **v0.2** | Argument-level Rego policy, decision log, replay |
| **v0.4** | Hook adapters for the agents' built-in tools (`Bash`, `Read`, `Write`) |
| **v0.5** | Approval queue, one-shot approvals, grants |
| **v0.6** | npm package (128 kB, precompiled policy, no build step) |

Every adapter feeds **one policy engine**, so a single ruleset governs MCP calls
and built-in calls alike.

### Supported agents

| Agent | Built-in tools | MCP tools |
|---|---|---|
| Any MCP client | via `toolwall serve` | ✅ |
| Claude Code | ✅ PreToolUse / PermissionRequest | ✅ |
| Cursor | ✅ beforeShellExecution, beforeReadFile, beforeMCPExecution, preToolUse | ✅ |
| Codex | ✅ PreToolUse / PermissionRequest | ✅ |

```bash
toolwall install-hooks --agent claude-code --cwd "$PWD"
toolwall install-hooks --agent cursor         --cwd "$PWD"   # → ~/.cursor/hooks.json
toolwall install-hooks --agent codex          --cwd "$PWD"   # → ~/.codex/hooks.json
```

Each writes to that agent's own config format and **preserves whatever you had
configured**. Cursor is auto-detected from the payload; Claude Code and Codex
must be named with `--agent` because their payloads are indistinguishable, and
guessing would risk emitting a dialect the host ignores — which fails **open**.

### Host limitations worth knowing

These are upstream bugs, not things toolwall can work around:

- **Codex ignores `permissionDecision: "ask"`.** Per its docs, an unsupported
  field makes Codex "mark the hook run as failed, report the error, and continue
  the tool call" — fail open. toolwall therefore renders every `ask` as a
  `deny` on Codex. It still tells you how to approve.
- **Codex requires persisted hook trust** on first run, and
  `[features] hooks = false` disables hooks entirely. Background/async hooks
  cannot block.
- **Cursor's CLI has partial hook support**, and there is a standing report that
  `beforeReadFile` denials are not always honoured. Read denials are therefore
  best-effort on Cursor.

## Install

```bash
npm install toolguard
```

That's the whole thing. The policy ships precompiled (~128 kB), so there is no
62MB binary to download and no build step. The OPA CLI is only needed if you
author custom `.rego`.

### Custom rules (JSON — no OPA needed)

`.firewall/policy.json` in your project, `~/.firewall/policy.json` for
user-global rules. The project file wins per rule name.

### Custom rules (Rego — needs the OPA CLI)

```bash
toolwall fetch-opa        # checksum-verified, only if you need it
toolwall build-policy ./policy.rego --output ./.toolwall
toolwall serve --policy ./.toolwall/policy.wasm -- node ./server.js
```

Your file composes with the shipped defaults, so you add rules rather than
restating the policy.

### From source

```bash
git clone … && cd toolwall
npm install
npm run fetch:opa    # vendors bin/opa, checksum-verified
npm run build        # compiles the policy + dist/
npm test
```

### As a library

```ts
import { PolicyEngine, BUNDLED_POLICY, hostBuiltins } from "toolwall";

const engine = await PolicyEngine.load(BUNDLED_POLICY);
const d = await engine.decide({
  mode: "enforce",
  agent: { id: "my-agent", cwd: process.cwd() },
  tool: { name: "Read" },
  arguments: { file_path: "./.env" },     // normalized for you
});
// → { effect: "deny", rule: "no-secret-reads", … }
```

## Use

Run any MCP server through toolwall, then point your agent at it:

```bash
toolwall serve --agent claude-code --cwd "$PWD" -- node ./my-mcp-server.js
```

To also gate the agent's built-in tools, register the hook (writes to
`~/.claude/settings.json`, preserving anything already there):

```bash
toolwall install-hooks --cwd "$PWD"
```

In Claude Code, replace the server in `.mcp.json`:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "node",
      "args": ["/path/to/toolwall/dist/cli.js", "serve",
               "--agent", "claude-code", "--cwd", "/path/to/project",
               "--", "node", "/path/to/my-mcp-server.js"]
    }
  }
}
```

Then check what would happen, without changing anything:

```bash
$ toolwall why Read --path ./.env
decision:  deny
rule:      no-secret-reads
reason:    refusing to read or write a credential path

$ node dist/cli.js why Read --path ./src/app.ts
decision:  allow
rule:      workspace-scoped
```

## Policy

Rules are **data, not code** — a JSON file is enough. Put it in
`.firewall/policy.json` (project) or `~/.firewall/policy.json` (user); the
project file wins per rule name.

```json
{
  "rules": [
    { "name": "no-deploy", "effect": "deny", "tools": ["mcp__gh__create_release"],
      "reason": "releases are cut by humans" },

    { "name": "no-outside-tree", "effect": "ask", "tools": ["*"],
      "path_outside_cwd": true, "reason": "writes outside the repo need review" },

    { "name": "ask-before-destructive", "effect": "ask", "tools": ["*"],
      "destructive": true, "reason": "tool is annotated destructiveHint" }
  ]
}
```

`effect` is `allow` | `deny` | `ask`. Precedence is **deny > ask > allow** — all
matching rules are collected and the strongest wins, so a broad `allow` can
never outvote a specific `deny`.

Constraints (all optional, combined with AND):

| Constraint | Matches when |
|---|---|
| `tools` | glob on tool name: `"Read"`, `"mcp__fs__*"`, `"mcp__*"` |
| `path_secret` | the `path` argument looks like a credential file |
| `path_within_cwd` | `path` resolves inside the agent's cwd (symlinks resolved) |
| `path_outside_cwd` | the inverse |
| `destructive` | the tool declares `annotations.destructiveHint` |
| `read_only` | the tool declares `annotations.readOnlyHint` |
| `arg_key_present` | **any** of the listed keys is present in the arguments |
| `arg_path_prefix` / `arg_path_suffix` | string match on the `path` argument |
| `command_contains` / `command_starts_with` | substring match on a shell `command` (**advisory** — see below) |

Built-in defaults deny credential paths, outbound network, and `/etc`, allow
reads inside the agent's working directory, and force-pushes; shell commands that
match nothing else resolve to `ask` so a human decides.

For anything rules can't express, write Rego against `data.toolwall.user_rules`
or add a package under `policy/`.

## Secrets

Two separate controls, and the second is the one that matters.

### Brokering — the agent never holds a credential

```bash
toolwall secrets                    # lists NAMES, never values
```

Configure either a JSON file at `~/.toolwall/secrets.json` (mode 600) or
`TOOLWALL_SECRET_<NAME>` environment variables. The agent then passes a
*reference*, and toolwall substitutes the real value at the proxy boundary:

```jsonc
{ "headers": { "Authorization": "Bearer {{secret:github_token}}" } }
```

The reference — not the credential — is what appears in your logs. An unknown
name fails **closed** rather than forwarding `{{secret:typo}}` upstream as if it
were a token.

Using a credential is itself gated. By default **no tool may spend one**; you
opt in by replacing the guard rule, so opening a credential is a visible edit:

```jsonc
{ "rules": [
  { "name": "secret-use-restricted",      // replaces the built-in guard
    "effect": "allow", "tools": ["mcp__gh__create_release"],
    "reason": "release publishing needs the credential" }
]}
```

### Scrubbing — credentials don't reach the model

This is the control that actually stops exfiltration, and it is the reason the
project exists.

A deny rule stops the agent reading `~/.aws/credentials`. It does **not** stop
a build step echoing a token into stdout, a tool returning a debug dump, or an
API response containing a live credential. And once a credential is in the
model's context it can be sent anywhere — into an issue, a commit message, a
web request — with no rule consulted at all.

So **every upstream response is scrubbed before the agent sees it**:

```
$ # upstream returns:  region=us-east-1
$ #                   token=ghp_Z1y2X3b4…   AWS=AKIAZZZZ…
$ # the agent receives:
  region=us-east-1
  token=[redacted:github_token]
  AWS=[redacted:token]
```

Two layers, because neither alone is enough:

1. **Known values** — every brokered secret, scrubbed literally. Exact, but
   only covers secrets you told toolwall about.
2. **Recognised shapes** — `ghp_…`, `sk-…`, `AKIA…`, `AIza…`, `xoxb-…`, JWTs,
   PEM blocks, `Bearer …`. Catches secrets *nobody told us about*, at the cost
   of occasionally masking something that merely looks like one. Redactions are
   visible in the output rather than silently truncating strings.

Before you paste a log into a bug report:

```bash
$ toolwall scrub "the output was: ghp_Z1y2X3b4N5m6Q7w8E9r0T1u2I3o4P5q6R7s8"
```

Redactions are recorded in the decision log (`response-scrubbed`) so you can
tell scrubbing happened without any secret reaching disk.

## Approval (`ask`)

When a rule resolves to `ask`, a human decides.

- **In Claude Code** the hook returns an `ask` decision *carrying toolwall's
  reason*, so the prompt explains why rather than looking like friction. A
  request is recorded at `<project>/.toolwall/approvals.jsonl`.
- **Through the proxy** there is no human in the transport, so `ask` fails
  closed — but the refusal tells the agent exactly how to unblock.

```bash
$ toolwall pending
1 pending approval request(s):

  5bf0f316e5c6  2026-10-10 13:13:03  Bash  [shell-needs-human]
      shell commands are reviewed by a human, not auto-approved

active grants (1):
  shell-needs-human  scope=/home/u/proj  until 2026-10-10T13:43:03.432Z
```

`approve` is not bookkeeping. It mints a **one-shot grant** keyed to that exact
request id, so the identical retry goes through — once:

```bash
$ toolwall approve 5bf0f316e5c6
approved 5bf0f316e5c6
  the next identical call (Bash) will be allowed, once,
  expiring 2026-10-10T13:39:05.901Z
```

The original call was already refused — nothing can un-refuse it. What approval
buys is the *retry*, not the past, and it is scoped tightly: the same rule, the
same tool, the same arguments, the same directory, once.

`--minutes N` grants the whole rule for a while, which is the "stop asking"
escape hatch. So is a plain grant:

```bash
$ toolwall grant shell-needs-human --minutes 30
granted 'shell-needs-human' for 30 minute(s), scope /home/u/proj
```

Grants are deliberately narrow:

- **always time-boxed** — a grant with no expiry is a permanent hole (max 7 days)
- **scoped to one rule and a directory subtree**, never to a tool or an effect
- **stored user-global** (`~/.toolwall/grants.json`), never in the repo
- **can only downgrade `ask` → `allow`.** A `deny` is a policy statement, not a
  prompt, and no grant can turn one into an `allow`. This is asserted directly
  in the test suite.

## Replay

The decision log is the point. Before tightening a policy, check what it would
break:

```bash
$ node dist/cli.js replay --against .toolwall/decisions.jsonl --policy ./tightened.wasm
replayed 412 record(s) from .toolwall/decisions.jsonl
  would-allow: 398   would-deny: 14   would-ask: 0
  changed:     14

NEWLY BLOCKED (14) — these would start failing:
  #0  read_file  (notes.md)      : allow/workspace-scoped -> deny/deny-all-writes
  #1  write_file (notes.md)      : allow/workspace-scoped -> deny/deny-all-writes
  ...
```

Exits non-zero when something newly blocks, so it can gate CI. Try
`toolwall shadow -- <server>` to record real traffic without blocking
anything first.

## Design notes

- **Filtering is not authorization.** A hidden tool is still checked on
  `tools/call`, because a client can construct that request without ever
  listing. Both gates exist deliberately.
- **Fails closed.** A policy that throws, returns nonsense, or is malformed
  denies the call and says so (`toolwall-fail-closed`). It never silently allows.
- **Deny reasons are returned to the model** as tool errors, so the agent can
  change course instead of retrying blindly.
- **Redaction happens at write time,** so credentials never reach disk.
- **Built-in tool arguments are normalized** — Claude Code's `Read`/`Write` use
  `file_path`, not `path`, and every path rule would silently stop matching
  without that mapping.
- **MCP annotations are recovered from a catalogue.** Hooks don't receive
  `readOnlyHint`/`destructiveHint` (anthropics/claude-code#83886), so the proxy
  publishes what it learns at `tools/list` and the hook adapter reads it.

## Not covered

**Shell safety is not a security boundary.** `command_contains` is substring
matching on the raw command line. It catches `git push --force`; it is defeated
by `$(...)`, `eval`, variables, aliases or a symlinked binary. It exists to
catch accidents, and it is labelled advisory in the policy for that reason. If
you need a real boundary for shell execution, use OS-level isolation — a
container with a read-only root and an egress allowlist. toolwall does not
provide one.

Also worth knowing:

- **Substitution happens in the proxy only**, never in hooks. For built-in tools
  it would paste a live secret into a shell command line — the one place a
  secret is most likely to land in a process listing, history file, or error
  message. A `{{secret:…}}` in `Bash` is treated as an ordinary string.
- **The upstream's environment is an allowlist.** The MCP SDK hands it almost
  nothing, which silently breaks servers needing API keys. Forward explicitly:

  ```bash
  toolwall serve --upstream-env GITHUB_TOKEN,SENTRY_DSN -- node ./server.js
  toolwall serve --upstream-env all -- node ./server.js   # inherit everything
  ```

  `all` also hands upstream the operator's whole environment, including
  toolwall's own secrets — prefer naming variables.

Not covered:

- **Path rules do not apply to shell commands.** `/etc/passwd` inside
  `cat /etc/passwd` is not matched by `arg_path_prefix`, because a command is
  not a path. Extracting paths from a shell string needs the AST analysis above.
- Single-node only; no shared policy service.

## Development

```bash
npm run typecheck
npm test               # engine, hooks, approval, replay, packaging, proxy e2e
npm run test:all       # adds the M0 spike suites
```

```bash
npm run test:coverage     # c8 report + HTML in coverage/
```

**328 tests, ~91% statement coverage.** `cli.ts` reads lower because it is
exercised through spawned subprocesses, which c8 cannot instrument — the paths
run, they are just not traced.

`test/packaging.test.ts` runs `npm pack`, installs the tarball into a throwaway
project with no OPA binary, and exercises it end to end. Packaging bugs are
invisible from inside the source tree — a stale `dist/` and a hardcoded `/tmp`
path both shipped looking fine until that test existed.

### Releasing

Publishing is gated on a check you can run yourself:

```bash
$ npm run prepublish:check
prepublish checks
====================================================
  ok    toolwall@0.1.0
  ok    license: MIT
  FAIL  repository.url is still a placeholder (…) — set it to the real repo
  FAIL  the name "toolwall" is ALREADY TAKEN on npm (latest 0.1.1)
  ok    precompiled policy included
  ok    vendored OPA binary excluded from the tarball
  ok    tarball size 151kB
```

The npm package is **`toolguard`**; the CLI is still just `toolwall`.

The name `toolwall` was already taken on npm by an unrelated active package,
and an npm name is the one thing you cannot take back — so the distribution name
and the project name differ. Everything else lines up: `github.com/Faisal-Fayaz/toolwall`.

Before releasing:

```bash
npm run prepublish:check   # must exit 0
npm publish
```

Or create a GitHub release and let `.github/workflows/release.yml` publish with
provenance after re-verifying everything. `npm run dry-run:release` packs
without publishing.

`docs/M0.md` records the spike that de-risked the Rego/Wasm path, including the
Rego v1 and Wasm-runtime gotchas that shaped the implementation.