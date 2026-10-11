#!/usr/bin/env node
/**
 * toolwall CLI.
 *
 *   toolwall serve  -- <upstream cmd> [args…]   run the MCP proxy (enforce)
 *   toolwall shadow -- <upstream cmd> [args…]   same, but never blocks
 *   toolwall replay --against <log.jsonl> [--policy <wasm>]
 *                                               re-evaluate history vs a
 *                                               candidate policy and diff
 *   toolwall check  [--policy <wasm>]          evaluate rules, show layering
 *   toolwall why    --tool <name> [--path p] [--annotation k=v]
 *                                               explain a single decision
 */

import { existsSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { statSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { loadUserRules, policyPaths, userData } from "./config.js";

// Approval, grants and secrets are imported lazily: `hook` runs on every tool
// call and must not pay for CLI-only code.
import { DEFAULT_KEEP, DecisionLog, readRecent } from "./decision-log/log.js";

// Adapters are imported LAZILY per command. Loading the MCP SDK costs ~150ms
// and `hook` runs on every single tool call, so it must not pay for a proxy it
// never starts.
import { PolicyEngine } from "./engine/engine.js";
import type { CallInput, Decision, DecisionEffect } from "./types.js";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));

/**
 * The precompiled policy shipped with the package. Running toolwall must never
 * require the OPA CLI — only authoring custom Rego does. We fall back to the
 * dev build directory for local development.
 */
const DEFAULT_WASM = existsSync(resolve(ROOT, "policy/default.wasm"))
	? resolve(ROOT, "policy/default.wasm")
	: resolve(ROOT, ".build/policy.wasm");
const DEFAULT_LOG = resolve(process.cwd(), ".toolwall/decisions.jsonl");

type Args = { _: string[]; flags: Record<string, string | boolean> };

/** Single-dash aliases, so `-o` is not silently dropped as a positional. */
const SHORT_FLAGS: Record<string, string> = { o: "output", h: "help", v: "verbose" };

function parseArgs(argv: string[]): Args {
	const _: string[] = [];
	const flags: Record<string, string | boolean> = {};
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i]!;
		if (a === "--") {
			_.push(...argv.slice(i + 1));
			break;
		}
		if (a.startsWith("--")) {
			const key = a.slice(2);
			const next = argv[i + 1];
			if (next && !next.startsWith("--")) {
				flags[key] = next;
				i++;
			} else {
				flags[key] = true;
			}
		} else if (a.length > 2 && a.startsWith("-") && SHORT_FLAGS[a[1]!]) {
			flags[SHORT_FLAGS[a[1]!]!] = a.slice(2) || true;
		} else if (a.startsWith("-") && a.length > 1 && SHORT_FLAGS[a.slice(1)]) {
			flags[SHORT_FLAGS[a.slice(1)]!] = argv[i + 1] ?? true;
			if (argv[i + 1]) i++;
		} else {
			_.push(a);
		}
	}
	return { _, flags };
}

function err(msg: string): never {
	process.stderr.write(`toolwall: ${msg}\n`);
	process.exit(2);
}

/**
 * User rules are resolved relative to the AGENT's working directory, not this
 * process's — toolwall typically runs as a subprocess from somewhere else, and
 * the project being protected is the one that owns `.firewall/`.
 */
function policyCwd(flags: Args["flags"]): string {
	return typeof flags.cwd === "string" ? flags.cwd : process.cwd();
}

async function makeEngine(wasmPath: string, flags: Args["flags"] = {}): Promise<PolicyEngine> {
	const cwd = policyCwd(flags);
	const { rules, sources } = loadUserRules(cwd);
	for (const s of sources) process.stderr.write(`[toolwall] loaded ${s.count} rule(s) from ${s.path}\n`);
	return PolicyEngine.load(wasmPath, userData(rules));
}

// ---------------------------------------------------------------------- serve

async function cmdServe(positional: string[], flags: Args["flags"], mode: "enforce" | "dry-run") {
	const { Gate } = await import("./adapters/mcp-proxy/gate.js");
	const { ApprovalQueue } = await import("./approval/queue.js");
	const { GrantStore } = await import("./approval/grants.js");
	const { SecretStore } = await import("./secrets/store.js");

	const wasm = typeof flags.policy === "string" ? flags.policy : DEFAULT_WASM;
	const agentCwd = policyCwd(flags);
	const secrets = new SecretStore();
	const engine = await PolicyEngine.load(wasm, userData(loadUserRules(agentCwd).rules), undefined, secrets);
	const log = new DecisionLog(logOptions(flags, typeof flags.log === "string" ? flags.log : DEFAULT_LOG));

	const gate = new Gate({
		engine,
		log,
		queue: new ApprovalQueue(`${agentCwd}/.toolwall/approvals.jsonl`),
		grants: new GrantStore(),
		secrets,
		agent: { id: typeof flags.agent === "string" ? flags.agent : "unknown", cwd: agentCwd },
		catalogueDir: agentCwd,
		mode,
		diagnostics: flags.verbose ? (m) => process.stderr.write(`[toolwall] ${m}\n`) : undefined,
	});

	const diag = flags.verbose ? (m: string) => process.stderr.write(`[toolwall] ${m}\n`) : () => {};
	process.stderr.write(`[toolwall] ${mode} via ${wasm}\n[toolwall] logging to ${log.path}\n`);

	// Remote upstream: toolwall listens locally and the agent points at us.
	const url = typeof flags.url === "string" ? flags.url : undefined;
	if (url) {
		const { createHttpProxy } = await import("./adapters/mcp-proxy/http.js");
		const handle = await createHttpProxy({
			gate,
			url,
			useSse: flags.sse === true,
			port: typeof flags.port === "string" ? Number(flags.port) : 0,
			host: typeof flags.host === "string" ? flags.host : "127.0.0.1",
			headers: parseHeaders(flags),
			secrets,
			diagnostics: diag,
		});

		process.stderr.write(
			`\n  point your agent at:\n\n    ${handle.url}\n\n` +
				`  upstream: ${url}\n`,
		);
		if ((flags.host as string) && flags.host !== "127.0.0.1" && flags.host !== "localhost") {
			process.stderr.write(
				`\n  WARNING: bound to ${flags.host}, which is reachable off-machine.\n` +
					`  A policy proxy on a public interface lets any client invoke tools\n` +
					`  through whatever policy is loaded. Loopback is the safe default.\n`,
			);
		}
		process.on("SIGINT", () => {
			void handle.close().finally(() => process.exit(0));
		});
		return;
	}

	const upstreamCmd = positional[0];
	if (!upstreamCmd) {
		err(
			"usage: toolwall serve --url <https://host/mcp>   wrap a remote MCP server\n" +
				"   or: toolwall serve -- <command> [args…]         wrap a local (stdio) MCP server",
		);
	}

	const { createProxy } = await import("./adapters/mcp-proxy/proxy.js");
	const handle = await createProxy({
		gate,
		upstream: { command: upstreamCmd, args: positional.slice(1) },
		upstreamEnv: parseUpstreamEnv(flags),
		diagnostics: diag,
	});
	// stdio server keeps the process alive
	void handle;
}

/** `--header 'Name=Value'` may be repeated; values may reference secrets. */
function parseHeaders(flags: Args["flags"]): Record<string, string> | undefined {
	const out: Record<string, string> = {};
	let any = false;
	for (const [key, value] of Object.entries(flags)) {
		if (key !== "header") continue;
		any = true;
		for (const line of String(value).split(/\n/)) {
			const idx = line.indexOf("=");
			if (idx <= 0) continue;
			out[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
		}
	}
	return any ? out : undefined;
}

interface Delta {
	record: number;
	tool: string;
	before: DecisionEffect;
	after: DecisionEffect;
	ruleBefore: string;
	ruleAfter: string;
}

interface GrantDependent {
	record: number;
	tool: string;
	recordedAs: DecisionEffect;
	policyWouldSay: DecisionEffect;
}

/**
 * Replay answers TWO questions, and conflating them was a real bug: a call
 * that was allowed by a grant looked like a policy change, so replay reported
 * false drift on exactly the calls a human had already approved.
 *
 *   1. What does this policy do on its own?       (isolated)
 *   2. What did it actually do, with grants?      (effective)
 *
 * Only (1) differing from the recorded decision counts as a policy change.
 * A recorded decision that a grant modified is reported separately, and an
 * expired grant is not treated as drift.
 */
async function cmdReplay(flags: Args["flags"]) {
	const { GrantStore, applyGrants } = await import("./approval/grants.js");
	const against = typeof flags.against === "string" ? flags.against : err("replay requires --against <log.jsonl>");
	const wasm = typeof flags.policy === "string" ? flags.policy : DEFAULT_WASM;
	const engine = await makeEngine(wasm, flags);

	// Read the rotation window newest-first rather than a single file, and
	// stream it so a large log does not have to fit in memory.
	const log = new DecisionLog({ path: against, maxBytes: 0 });
	const limit = typeof flags.limit === "string" ? Number(flags.limit) : Number.POSITIVE_INFINITY;
	const records = await readRecent(log, limit);
	if (records.length === 0) err(`no records in ${against}`);

	const useGrants = flags["no-grants"] !== true;
	const grants = useGrants ? new GrantStore() : undefined;

	const deltas: Delta[] = [];
	const grantDependent: GrantDependent[] = [];
	const tally: Record<DecisionEffect, number> = { allow: 0, deny: 0, ask: 0 };
	const effectiveTally: Record<DecisionEffect, number> = { allow: 0, deny: 0, ask: 0 };

	for (const [i, rec] of records.entries()) {
		const call: CallInput = {
			mode: "enforce",
			agent: rec.agent,
			server: rec.server,
			tool: rec.tool,
			arguments: rec.arguments ?? {},
		};

		const isolated = await engine.decide(call);
		tally[isolated.effect]++;
		effectiveTally[(grants ? applyGrants(isolated, call, grants) : isolated).effect]++;

		// A record the runtime logged as grant-modified is not evidence of a
		// policy change; the grant is what changed.
		const wasGranted = rec.rule.endsWith("(granted)");
		if (wasGranted) {
			grantDependent.push({
				record: i,
				tool: rec.tool.name,
				recordedAs: rec.effect,
				policyWouldSay: isolated.effect,
			});
			continue;
		}

		if (isolated.effect !== rec.effect || isolated.rule !== rec.rule) {
			deltas.push({
				record: i,
				tool: rec.tool.name,
				before: rec.effect,
				after: isolated.effect,
				ruleBefore: rec.rule,
				ruleAfter: isolated.rule,
			});
		}
	}

	process.stdout.write(`replayed ${records.length} record(s) from ${against}\n`);
	process.stdout.write(
		`  policy alone:   allow ${tally.allow}   ask ${tally.ask}   deny ${tally.deny}\n`,
	);
	if (useGrants) {
		process.stdout.write(
			`  with grants:    allow ${effectiveTally.allow}   ask ${effectiveTally.ask}   deny ${effectiveTally.deny}\n`,
		);
	}
	process.stdout.write(`  policy changes: ${deltas.length}\n`);

	if (grantDependent.length) {
		const differing = grantDependent.filter((g) => g.recordedAs !== g.policyWouldSay);
		process.stdout.write(
			`\nGRANT-DEPENDENT (${grantDependent.length}) — a grant was active at the time, ` +
				`these are not policy changes:\n`,
		);
		for (const g of grantDependent.slice(0, 10)) {
			process.stdout.write(`  #${g.record} ${g.tool}: recorded ${g.recordedAs}, policy alone says ${g.policyWouldSay}\n`);
		}
		if (differing.length) {
			process.stdout.write(
				`  ${differing.length} of these would now differ — the grant has expired or been removed,\n` +
					`  not because the policy changed.\n`,
			);
		}
	}

	const blocking = deltas.filter((d) => d.after === "deny" && d.before !== "deny");
	if (blocking.length) {
		process.stdout.write(`\nNEWLY BLOCKED (${blocking.length}) — these would start failing:\n`);
		for (const d of blocking.slice(0, 20)) {
			process.stdout.write(`  #${d.record} ${d.tool}: ${d.before}/${d.ruleBefore} -> deny/${d.ruleAfter}\n`);
		}
		if (blocking.length > 20) process.stdout.write(`  … and ${blocking.length - 20} more\n`);
	}

	const loosened = deltas.filter((d) => d.after === "allow" && d.before === "deny");
	if (loosened.length) {
		process.stdout.write(`\nNEWLY ALLOWED (${loosened.length}) — previously blocked:\n`);
		for (const d of loosened.slice(0, 20)) {
			process.stdout.write(`  #${d.record} ${d.tool}: deny/${d.ruleBefore} -> allow/${d.ruleAfter}\n`);
		}
		if (loosened.length > 20) process.stdout.write(`  … and ${loosened.length - 20} more\n`);
	}

	// Exit non-zero only for genuine policy changes that would break a working
	// call — an expired grant must not fail someone's build.
	process.exit(blocking.length > 0 ? 1 : 0);
}

// ---------------------------------------------------------------------- check

async function cmdCheck(flags: Args["flags"]) {
	const wasm = typeof flags.policy === "string" ? flags.policy : DEFAULT_WASM;
	const cwd = policyCwd(flags);
	const { rules, sources } = loadUserRules(cwd);
	const engine = await makeEngine(wasm, flags);

	process.stdout.write("policy files (later wins per rule name):\n");
	for (const p of policyPaths(cwd)) process.stdout.write(`  ${p}${sources.some((s) => s.path === p) ? "" : "  (not present)"}\n`);
	process.stdout.write(`\nuser rules active: ${rules.length}\n`);
	for (const r of rules) process.stdout.write(`  ${r.effect.padEnd(5)} ${r.name}\n`);

	const probe = await engine.decide({
		mode: "enforce",
		agent: { id: "check", cwd },
		tool: { name: "mcp__fs__read_file", annotations: { readOnlyHint: true } },
		arguments: { path: resolve(cwd, "src/index.ts") },
	});
	process.stdout.write(`\nsmoke test (read src/index.ts): ${probe.effect} via ${probe.rule}\n`);
	if (flags.wasm) process.stdout.write(`engine: ${wasm}\n`);
}

// ----------------------------------------------------------------------- why

async function cmdWhy(positional: string[], flags: Args["flags"]) {
	const wasm = typeof flags.policy === "string" ? flags.policy : DEFAULT_WASM;
	const engine = await makeEngine(wasm, flags);

	const tool = (positional[0] ?? (typeof flags.tool === "string" ? flags.tool : "")) || err("why requires a tool name");
	const annotations: Record<string, boolean> = {};
	if (typeof flags.destructive === "boolean" && flags.destructive) annotations.destructiveHint = true;
	if (typeof flags["read-only"] === "boolean" && flags["read-only"]) annotations.readOnlyHint = true;

	const call: CallInput = {
		mode: "enforce",
		agent: { id: "why", cwd: policyCwd(flags) },
		tool: { name: tool, annotations },
		arguments: {
			...(typeof flags.path === "string" ? { path: flags.path } : {}),
			...(typeof flags.network === "string" ? { network: flags.network } : {}),
		},
	};

	const d = await engine.decide(call);
	process.stdout.write(`tool:      ${tool}\n`);
	process.stdout.write(`arguments: ${JSON.stringify(call.arguments)}\n`);
	process.stdout.write(`decision:  ${d.effect}\n`);
	process.stdout.write(`rule:      ${d.rule}\n`);
	process.stdout.write(`reason:    ${d.reason}\n`);
}

// ---------------------------------------------------------------------- hook

// Invoked by Claude Code with the event JSON on stdin. Must be FAST and must
// print nothing but the decision — startup cost is paid on every tool call.
async function cmdHook(flags: Args["flags"]) {
	const { readStdin } = await import("./adapters/hooks/claude-code.js");
	const { detectAdapter } = await import("./adapters/hooks/index.js");
	const { runPipeline } = await import("./adapters/hooks/types.js");
	const { ApprovalQueue } = await import("./approval/queue.js");
	const { GrantStore } = await import("./approval/grants.js");
	const wasm = typeof flags.policy === "string" ? flags.policy : DEFAULT_WASM;
	const input = await readStdin();

	// A globally-installed hook must resolve the rules of the project actually
	// being worked on, not whatever cwd it was installed from. The session
	// sends its own cwd in the payload, so prefer it for BOTH the policy root
	// and the agent's working directory.
	const sessionCwd = extractPayloadCwd(input);
	const cwd = sessionCwd ?? policyCwd(flags);

	const { rules } = loadUserRules(cwd);
	const engine = await PolicyEngine.load(wasm, userData(rules));

	// --agent is the requested dialect; without it Cursor is auto-detected and
	// everything else falls back to Claude Code.
	let payload: unknown = undefined;
	try {
		payload = JSON.parse(input);
	} catch {
		// malformed payload: nothing we can gate
	}
	const adapter = detectAdapter(
		(payload ?? {}) as Record<string, unknown>,
		typeof flags.agent === "string" ? flags.agent : undefined,
	);

	const logPath = typeof flags.log === "string" ? flags.log : `${cwd}/.toolwall/decisions.jsonl`;
	const result = await runPipeline((payload ?? {}) as never, adapter, {
		engine,
		log: new DecisionLog({ path: logPath }),
		queue: new ApprovalQueue(`${cwd}/.toolwall/approvals.jsonl`),
		grants: new GrantStore(),
		agent: { id: adapter.id, cwd },
		catalogueDir: cwd,
		// silent by default: a hook that writes to stdout breaks the host, and
		// stderr noise on every call is noise the user didn't ask for.
		diagnostics: flags.verbose ? (m) => process.stderr.write(`[toolwall] ${m}\n`) : undefined,
	});

	if (result?.out) process.stdout.write(result.out);
}

/** Best-effort session cwd from the hook payload; undefined if unusable. */
function extractPayloadCwd(input: string): string | undefined {
	try {
		const cwd = (JSON.parse(input) as { cwd?: unknown }).cwd;
		return typeof cwd === "string" && cwd !== "" ? cwd : undefined;
	} catch {
		return undefined;
	}
}

// ----------------------------------------------------------------- secrets

async function cmdSecrets(_flags: Args["flags"]) {
	const { SecretStore, defaultSecretsPath } = await import("./secrets/store.js");
	const store = new SecretStore();
	process.stdout.write(`secret store: ${defaultSecretsPath()}\n`);
	process.stdout.write(`configured:    ${store.size}\n\n`);
	if (store.size === 0) {
		process.stdout.write(
			"No secrets configured. Two ways to add them:\n\n" +
				"  1. a JSON file (mode 600) at the path above:\n" +
				'       { "github_token": "ghp_…" }\n\n' +
				`  2. environment variables:  export ${"TOOLWALL_SECRET_"}<NAME>=…\n`,
		);
		return;
	}
	// names only — values are never printed
	for (const name of store.names()) process.stdout.write(`  ${name}\n`);
	process.stdout.write(`\nValues are never displayed.\n`);
}

async function cmdScrub(positional: string[]) {
	const { SecretStore } = await import("./secrets/store.js");
	const { scrubValue } = await import("./secrets/scrub.js");
	const secrets = new SecretStore();
	const input = positional[0];
	if (!input) err("usage: toolwall scrub <text>");

	process.stdout.write("Redacting your own log data before you post a bug.\n\n");
	const { value, stats } = scrubValue(input, secrets);
	process.stdout.write(`${value}\n\n`);
	process.stdout.write(`removed ${stats.count} item(s): ${stats.patterns} by shape, ${stats.names.length} by value\n`);
}

// ------------------------------------------------------------ build-policy

/** Compile a .rego to wasm. The only path that needs the OPA CLI. */
async function cmdBuildPolicy(positional: string[], flags: Args["flags"]) {
	const { execFileSync } = await import("node:child_process");
	const src = positional[0] ?? (typeof flags.policy === "string" ? flags.policy : undefined);
	if (!src || !existsSync(src)) err("usage: toolwall build-policy <policy.rego> [-o out.wasm] [--entrypoint ns/rule]");

	const script = resolve(ROOT, "scripts/build-policy.sh");
	if (!existsSync(script)) err("build-policy is unavailable in this install");

	const entrypoint = typeof flags.entrypoint === "string" ? flags.entrypoint : "firewall/decision";
	// build-policy.sh always emits <OUT_DIR>/policy.wasm
	const outDir = typeof flags.output === "string" ? resolve(flags.output) : resolve(process.cwd(), ".toolwall");
	const out = resolve(outDir, "policy.wasm");

	try {
		execFileSync("bash", [script, resolve(src), entrypoint], {
			// BASE_POLICY makes custom .rego compose with the shipped defaults,
			// so a user adds rules instead of restating the whole policy.
			env: { ...process.env, OUT_DIR: outDir, BASE_POLICY: resolve(ROOT, "policy/default.rego") },
			stdio: "inherit",
		});
	} catch {
		// The script already explained itself on stderr; a raw ENOENT/exit-code
		// stack trace on top of that is noise, not information.
		process.exit(1);
	}
	process.stdout.write(
		`\ncompiled ${resolve(src)} -> ${out}\n` +
			`use it with:  toolwall <command> --policy ${out}\n`,
	);
}

// ---------------------------------------------------------------- fetch-opa

// Only needed to author custom .rego. The bundled policy is precompiled, so
// installing and running toolwall never fetches a 62MB binary.
async function cmdFetchOpa() {
	const { execFileSync } = await import("node:child_process");
	const script = resolve(ROOT, "scripts/fetch-opa.sh");
	if (!existsSync(script)) {
		err("fetch-opa is unavailable in this install; see https://www.openpolicyagent.org/docs/latest/wasm/");
	}
	process.stdout.write("fetching the OPA CLI (checksum-verified)…\n");
	try {
		execFileSync("bash", [script], { stdio: "inherit" });
	} catch {
		err("fetch-opa failed; see the output above");
	}
}

// ------------------------------------------------------------ install-hooks

async function cmdInstallHooks(flags: Args["flags"]) {
	const { getAdapter } = await import("./adapters/hooks/index.js");
	const { readSettings, writeSettings } = await import("./adapters/hooks/claude-code.js");

	const cliPath = resolve(fileURLToPath(import.meta.url));
	const adapter = getAdapter(typeof flags.agent === "string" ? flags.agent : undefined);
	const target =
		typeof flags.settings === "string" ? flags.settings : adapter.defaultSettingsPath(process.env.HOME ?? "~");
	const cwd = policyCwd(flags);

	// Preserve whatever the host already had configured.
	const updated = adapter.install(readSettings(target), cliPath, cwd);
	writeSettings(target, updated);

	process.stdout.write(`installed toolwall hooks into ${target}\n`);
	process.stdout.write(`  agent:     ${adapter.id}\n`);
	process.stdout.write(`  events:    ${adapter.gatedEvents.join(", ")}\n`);
	process.stdout.write(`  policy:    ${typeof flags.policy === "string" ? flags.policy : DEFAULT_WASM}\n`);
	process.stdout.write(`  cwd:       ${cwd}\n`);
	process.stdout.write(`  decisions: ${cwd}/.toolwall/decisions.jsonl\n\n`);
	process.stdout.write(`Restart ${adapter.id} (or start a new session) to pick the hooks up.\n`);

	if (adapter.id === "codex") {
		process.stdout.write(
			`\nNote: Codex parses permissionDecision "ask" but does not enforce it, so toolwall\n` +
				`renders every ask as a deny. Hooks also require persisted trust on first run.\n`,
		);
	}
}

/**
 * Which environment variables to forward to the upstream MCP server.
 *
 * The SDK default is a small allowlist, so servers needing API keys break with
 * no explanation. `all` inherits everything, which is convenient but hands the
 * upstream the operator's whole environment including toolwall's own secrets.
 */
function parseUpstreamEnv(flags: Args["flags"]): Record<string, string> | "inherit" | undefined {
	const raw = flags["upstream-env"];
	if (typeof raw !== "string") return undefined;
	if (raw === "all" || raw === "inherit") return "inherit";

	const env: Record<string, string> = {};
	for (const name of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
		const value = process.env[name];
		if (value === undefined) {
			process.stderr.write(`[toolwall] --upstream-env: $${name} is not set in this process; skipping\n`);
			continue;
		}
		env[name] = value;
	}
	return env;
}

/** Log bounds from flags; keeps a runaway session from filling the disk. */
function logOptions(flags: Args["flags"], path: string) {
	return {
		path,
		maxBytes: typeof flags["log-max-bytes"] === "string" ? Number(flags["log-max-bytes"]) : undefined,
		keep: typeof flags["log-keep"] === "string" ? Number(flags["log-keep"]) : undefined,
	};
}

// --------------------------------------------------------------------- logs

/** Show which log files exist and how big they are — rotation is invisible otherwise. */
async function cmdLogs(flags: Args["flags"]) {
	const path = typeof flags.path === "string" ? flags.path : `${policyCwd(flags)}/.toolwall/decisions.jsonl`;
	const log = new DecisionLog({ path, maxBytes: 0, keep: 0 });
	const kb = (n: number) => `${(n / 1024).toFixed(1)}kB`;

	process.stdout.write(`log dir: ${dirname(path)}\n\n`);
	let total = 0;
	for (const [i, file] of log.readOrder().entries()) {
		const size = statSync(file).size;
		total += size;
		const label = i === 0 ? "live" : `rot .${i}`;
		process.stdout.write(`  ${label.padEnd(7)} ${kb(size).padStart(9)}  ${basename(file)}\n`);
	}
	if (total === 0) {
		process.stdout.write("  (no decision log yet — run the proxy or hooks first)\n");
		return;
	}
	process.stdout.write(`\n  total ${kb(total)}\n`);
	process.stdout.write(`\nRotation keeps the live file under --log-max-bytes (default 10MB)\n`);
	process.stdout.write(`and ${DEFAULT_KEEP} generations. To inspect history: toolwall replay --against ${path}\n`);
}

// ------------------------------------------------------------------ approval

function approvalsQueue(cwd: string) {
	// queue path derives from the session/project cwd so it is visible locally
	return `${cwd}/.toolwall/approvals.jsonl`;
}

async function cmdPending(flags: Args["flags"]) {
	const { ApprovalQueue, describeRequest } = await import("./approval/queue.js");
	const { GrantStore } = await import("./approval/grants.js");
	const cwd = policyCwd(flags);
	const queue = new ApprovalQueue(approvalsQueue(cwd));
	const pending = queue.pending();

	if (pending.length === 0) {
		process.stdout.write("no pending approval requests\n");
	} else {
		process.stdout.write(`${pending.length} pending approval request(s):\n\n`);
		for (const r of pending) {
			process.stdout.write(`  ${describeRequest(r)}\n`);
			process.stdout.write(`      ${r.reason}\n`);
		}
		process.stdout.write("\n  toolwall approve <id>   allow once\n");
		process.stdout.write("  toolwall deny <id>      refuse\n");
	}

	const grants = new GrantStore().active();
	process.stdout.write(`\nactive grants (${grants.length}):\n`);
	for (const g of grants) {
		process.stdout.write(`  ${g.rule}  scope=${g.scope}  until ${g.expiresAt}\n`);
	}
	if (grants.length === 0) process.stdout.write("  (none)\n");
}

/**
 * Resolve an approval request.
 *
 * `approve` is not bookkeeping: it mints a ONE-SHOT grant keyed to that exact
 * request id, so the identical retry goes through once and only once. The
 * original call was already refused — nothing can un-refuse it — so what
 * approval buys is the retry, not the past.
 *
 * `--minutes N` instead grants the whole rule for a while, which is the
 * "stop asking" escape hatch.
 */
async function cmdResolve(flags: Args["flags"], verdict: "approved" | "denied") {
	const { ApprovalQueue } = await import("./approval/queue.js");
	const { GrantStore, ONE_SHOT_TTL_MINUTES } = await import("./approval/grants.js");
	const cwd = policyCwd(flags);
	const id = typeof flags.id === "string" ? flags.id : process.argv[3];
	if (!id) err(`usage: toolwall ${verdict === "approved" ? "approve" : "deny"} <id>`);

	const queue = new ApprovalQueue(approvalsQueue(cwd));
	const request = queue.requests().find((r) => r.id === id || r.id.startsWith(id));
	if (!request) err(`no approval request matching '${id}'`);

	queue.resolve(request.id, verdict, process.env.USER);

	if (verdict === "denied") {
		process.stdout.write(`denied ${request.id} (${request.tool}, rule ${request.rule})\n`);
		process.stdout.write(
			`The refused call cannot be un-refused. To stop it being asked again, either\n` +
				`  toolwall grant ${request.rule}          silence this rule for a while\n` +
				`or add a rule to .firewall/policy.json to decide it once and for all.\n`,
		);
		return;
	}

	const minutes = typeof flags.minutes === "string" ? Number(flags.minutes) : ONE_SHOT_TTL_MINUTES;
	if (!Number.isFinite(minutes) || minutes <= 0) err("--minutes must be a positive number");

	const store = new GrantStore();
	if (flags.minutes) {
		const grant = store.add(request.rule, request.cwd ?? cwd, minutes, {
			by: process.env.USER,
			requestId: request.id,
		});
		process.stdout.write(`approved ${request.id}\n`);
		process.stdout.write(`  rule '${grant.rule}' is now allowed for ${minutes} minute(s)\n`);
		process.stdout.write(`  scope ${grant.scope}, expires ${grant.expiresAt}\n`);
	} else {
		const grant = store.approveOnce(request, minutes, process.env.USER);
		process.stdout.write(`approved ${request.id}\n`);
		process.stdout.write(
			`  the next identical call (${request.tool}) will be allowed, once,\n` +
				`  expiring ${grant.expiresAt}\n`,
		);
		process.stdout.write(`  for the whole rule instead: toolwall approve ${request.id} --minutes 30\n`);
	}
}

async function cmdGrant(flags: Args["flags"]) {
	const { GrantStore, DEFAULT_TTL_MINUTES } = await import("./approval/grants.js");
	const rule = typeof flags.rule === "string" ? flags.rule : process.argv[3];
	if (!rule) err("usage: toolwall grant <rule> [--scope <dir>] [--minutes <n>]");

	const minutes = typeof flags.minutes === "string" ? Number(flags.minutes) : DEFAULT_TTL_MINUTES;
	if (!Number.isFinite(minutes) || minutes <= 0) err("--minutes must be a positive number");
	if (minutes > 60 * 24 * 7) err("refusing a grant longer than 7 days; use a policy rule instead");

	const scope = typeof flags.scope === "string" ? flags.scope : policyCwd(flags);
	const grant = new GrantStore().add(rule, scope, minutes, { by: process.env.USER });
	process.stdout.write(`granted '${rule}' for ${minutes} minute(s), scope ${grant.scope}\n`);
	process.stdout.write(`expires ${grant.expiresAt}\n`);
}

async function cmdUngrant(flags: Args["flags"]) {
	const { GrantStore } = await import("./approval/grants.js");
	const rule = typeof flags.rule === "string" ? flags.rule : process.argv[3];
	if (!rule) err("usage: toolwall ungrant <rule> [--scope <dir>]");
	const scope = typeof flags.scope === "string" ? flags.scope : undefined;
	const removed = new GrantStore().remove(rule, scope);
	process.stdout.write(removed ? `removed ${removed} grant(s) for '${rule}'\n` : `no grant for '${rule}'\n`);
}

// ----------------------------------------------------------------------- main

async function main() {
	const { _: positional, flags } = parseArgs(process.argv.slice(2));
	const cmd = positional.shift();

	switch (cmd) {
		case "serve":
			return cmdServe(positional, flags, "enforce");
		case "shadow":
			return cmdServe(positional, flags, "dry-run");
		case "replay":
			return cmdReplay(flags);
		case "check":
			return cmdCheck(flags);
		case "why":
			return cmdWhy(positional, flags);
		case "hook":
			return cmdHook(flags);
		case "install-hooks":
			return cmdInstallHooks(flags);
		case "fetch-opa":
			return cmdFetchOpa();
		case "secrets":
			return cmdSecrets(flags);
		case "scrub":
			return cmdScrub(positional);
		case "build-policy":
			return cmdBuildPolicy(positional, flags);
		case "logs":
			return cmdLogs(flags);
		case "pending":
			return cmdPending(flags);
		case "approve":
			return cmdResolve(flags, "approved");
		case "deny":
			return cmdResolve(flags, "denied");
		case "grant":
			return cmdGrant(flags);
		case "ungrant":
			return cmdUngrant(flags);
		default: {
			// An explicitly requested --help goes to stdout (the caller asked
			// for it and may be piping it); usage on an error goes to stderr.
			const out = flags.help || flags.h ? process.stdout : process.stderr;
			out.write(
				"usage:\n" +
					"  toolwall serve  -- <command> [args…]   run the MCP proxy in enforce mode\n" +
					"                    [--upstream-env A,B|all]  env vars to forward upstream\n" +
					"  toolwall shadow -- <command> [args…]   run the proxy without blocking\n" +
					"  toolwall replay --against <log>        re-evaluate history vs a policy\n" +
					"                    [--limit N]           only the N most recent records\n" +
					"  toolwall logs [--path p]                show log files and their sizes\n" +
					"  toolwall check                         show policy layering and smoke test\n" +
					"  toolwall why <tool> --path <p>          explain one decision\n" +
					"  toolwall install-hooks                 register Claude Code hooks\n" +
					"  toolwall fetch-opa                     fetch the OPA CLI (only for custom Rego)\n" +
					"  toolwall secrets                       list brokered secret NAMES (never values)\n" +
					"  toolwall scrub <text>                  redact secrets from text before sharing it\n" +
					"  toolwall build-policy <file.rego>      compile custom Rego to wasm\n" +
					"  toolwall pending                       list approval requests + grants\n" +
					"  toolwall approve <id> | deny <id>      resolve an approval request\n" +
					"  toolwall grant <rule> [--minutes n]     stop asking about a rule for a while\n" +
					"  toolwall ungrant <rule>                remove that grant\n" +
					"  toolwall hook                          (internal) Claude Code hook entrypoint\n",
			);
			// An explicit --help is a success; a bare invocation is a usage error.
			if (flags.help || flags.h) process.exit(0);
			process.exit(cmd ? 2 : 1);
		}
	}
}

await main();