/**
 * Hook adapter tests: normalization, decisions, and the hook protocol.
 *
 * The normalization tests are the important ones — if `file_path` is not mapped
 * to `path`, every path rule silently stops matching and the agent looks
 * protected while it is not.
 *
 * Run: node --experimental-strip-types test/hooks.test.ts
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { handleHook, installHooks, type HookOptions } from "../dist/adapters/hooks/claude-code.js";
import { extractPath, mcpToolKey, normalizeArguments, resolveAnnotations } from "../dist/adapters/hooks/normalize.js";
import { DecisionLog } from "../dist/decision-log/log.js";
import { PolicyEngine } from "../dist/engine/engine.js";
import type { DecisionEffect } from "../dist/types.js";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const WASM = resolve(ROOT, ".build/policy.wasm");

let pass = 0,
	fail = 0;
const check = (label: string, got: unknown, want: unknown) => {
	const ok = JSON.stringify(got) === JSON.stringify(want);
	ok ? pass++ : fail++;
	if (!ok) console.log(`  MISS ${label}: want ${JSON.stringify(want)} got ${JSON.stringify(got)}`);
};

// ------------------------------------------------------------- normalization

console.log("normalization");

check("extract: file_path (Read/Write)", extractPath({ file_path: "/p/.env" }), "/p/.env");
check("extract: path", extractPath({ path: "/p/a" }), "/p/a");
check("extract: notebook_path", extractPath({ notebook_path: "/p/n.ipynb" }), "/p/n.ipynb");
check("extract: absent", extractPath({ command: "ls" }), undefined);
check("extract: none", extractPath(undefined), undefined);

check("normalize adds canonical path", normalizeArguments({ file_path: "/p/.env" }), {
	file_path: "/p/.env",
	path: "/p/.env",
});
check("normalize does not clobber explicit path", normalizeArguments({ file_path: "/a", path: "/b" }).path, "/b");
check("normalize keeps command key", normalizeArguments({ command: "rm -rf /" }).command, "rm -rf /");

check("mcp key: strips prefix", mcpToolKey("mcp__github__create_issue"), "github__create_issue");
check("mcp key: built-in has none", mcpToolKey("Read"), undefined);

check(
	"annotations: explicit hook payload wins",
	resolveAnnotations("mcp__x__y", { tool_annotations: { readOnlyHint: true } }, { "x__y": { destructiveHint: true } }),
	{ readOnlyHint: true },
);
check(
	"annotations: recovered from catalogue (#83886 gap)",
	resolveAnnotations("mcp__fs__write", {}, { "fs__write": { destructiveHint: true } }),
	{ destructiveHint: true },
);
check("annotations: unknown tool yields none", resolveAnnotations("mcp__fs__write", {}, undefined), undefined);

// ------------------------------------------------------------------ decisions

console.log("hook policy decisions");

const workdir = mkdtempSync(join(tmpdir(), "toolwall-hook-"));
const engine = await PolicyEngine.load(WASM);

async function decide(tool: string, toolInput: Record<string, unknown>, opts: Partial<HookOptions> = {}) {
	const hopts: HookOptions = {
		engine,
		log: new DecisionLog({ path: join(workdir, "log.jsonl") }),
		agent: { id: "claude-code", cwd: workdir },
		...opts,
	};
	const payload = { hook_event_name: "PreToolUse", tool_name: tool, tool_input: toolInput, cwd: workdir };
	const out = await handleHook(JSON.stringify(payload), hopts);
	if (out === null) return null;
	return JSON.parse(out).hookSpecificOutput as {
		permissionDecision: string;
		permissionDecisionReason: string;
	};
}

// Effect assertions go through the engine directly: the hook deliberately
// returns null for allow AND ask (both defer to the host agent's own prompt),
// so hook output alone cannot distinguish them.
const effectOf = async (tool: string, toolInput: Record<string, unknown>) => {
	const d = await engine.decide({
		mode: "enforce",
		agent: { id: "claude-code", cwd: workdir },
		tool: { name: tool },
		arguments: normalizeArguments(toolInput),
	});
	return d;
};

type D = DecisionEffect;
const cases: [string, string, Record<string, unknown>, D][] = [
	["Read inside cwd is not denied", "Read", { file_path: join(workdir, "notes.md") }, "allow"],
	["Read of .env via file_path is denied", "Read", { file_path: join(workdir, ".env") }, "deny"],
	["Write to ~/.ssh/id_rsa is denied", "Write", { file_path: "/home/u/.ssh/id_rsa" }, "deny"],
	["Edit of a secret is denied", "Edit", { file_path: join(workdir, ".env.local") }, "deny"],
	["force-push is denied", "Bash", { command: "git push --force origin main" }, "deny"],
	["force-push short flag is denied", "Bash", { command: "git push -f origin main" }, "deny"],
	["ordinary build command defers to a human", "Bash", { command: "npm run build" }, "ask"],
	// KNOWN LIMITATION: path rules match `arguments.path`, and a Bash command
	// is not a path. Extracting paths from a shell string requires the AST
	// analysis that is evadable and deliberately not implemented — so `/etc`
	// inside a command string is NOT caught by no-system-paths.
	["a path inside a shell command is not matched by path rules", "Bash", { command: "cat /etc/shadow" }, "ask"],
];

for (const [label, tool, input, want] of cases) {
	const d = await effectOf(tool, input);
	check(label, d.effect, want);

	// The hook must translate each effect into the matching host behaviour:
	//   deny -> block outright
	//   ask  -> prompt the human, WITH our reason attached
	//   allow-> stay silent and let the host run its own permission flow
	const out = await decide(tool, input);
	if (want === "deny") {
		check(`${label} (hook blocks)`, out?.permissionDecision, "deny");
	} else if (want === "ask") {
		check(`${label} (hook asks with a reason)`, out?.permissionDecision, "ask");
		check(
			`${label} (ask reason is actionable)`,
			/toolwall (approve|grant)/.test(out?.permissionDecisionReason ?? ""),
			true,
		);
	} else {
		check(`${label} (hook stays silent)`, out, null);
	}
}

// denial must carry a reason the agent can act on
{
	const denied = await decide("Read", { file_path: join(workdir, ".env") });
	check("deny returns a reason", (denied?.permissionDecisionReason ?? "").length > 10, true);
	check("deny reason names the rule", denied?.permissionDecisionReason?.includes("no-secret-reads"), true);
}

// ------------------------------------------------------------- hook protocol

console.log("hook protocol");

check("unknown event passes through", await handleHook(JSON.stringify({ hook_event_name: "SessionStart" }), {
	engine,
	log: new DecisionLog({ path: join(workdir, "log.jsonl") }),
	agent: { id: "c", cwd: workdir },
}), null);

check("malformed JSON passes through", await handleHook("{not json", {
	engine,
	log: new DecisionLog({ path: join(workdir, "log.jsonl") }),
	agent: { id: "c", cwd: workdir },
}), null);

check(
	"allow emits nothing (lets Claude Code decide)",
	await handleHook(
		JSON.stringify({
			hook_event_name: "PreToolUse",
			tool_name: "Read",
			tool_input: { file_path: join(workdir, "ok.md") },
			cwd: workdir,
		}),
		{ engine, log: new DecisionLog({ path: join(workdir, "log.jsonl") }), agent: { id: "c", cwd: workdir } },
	),
	null,
);

check(
	"PermissionRequest is gated too",
	JSON.parse(
		(await handleHook(
			JSON.stringify({
				hook_event_name: "PermissionRequest",
				tool_name: "Read",
				tool_input: { file_path: join(workdir, ".env") },
				cwd: workdir,
			}),
			{ engine, log: new DecisionLog({ path: join(workdir, "log.jsonl") }), agent: { id: "c", cwd: workdir } },
		)) ?? "{}",
	).hookSpecificOutput.permissionDecision,
	"deny",
);

// hook decisions are logged like proxy decisions
{
	const log = new DecisionLog({ path: join(workdir, "log.jsonl") });
	const contents = readFileSync(join(workdir, "log.jsonl"), "utf8").trim().split("\n");
	check("hook decisions are logged", contents.length >= cases.length, true);
	check("log is valid JSONL", contents.every((l) => l.startsWith("{")), true);
	void log;
}

// --------------------------------------------------------------- installer

console.log("installer");

const settingsPath = join(workdir, "settings.json");
installHooks(settingsPath, "/opt/toolwall/dist/cli.js", workdir);
const installed = JSON.parse(readFileSync(settingsPath, "utf8"));
check("registers PreToolUse", Array.isArray(installed.hooks?.PreToolUse), true);
check("registers PermissionRequest", Array.isArray(installed.hooks?.PermissionRequest), true);
// The matcher filters TOOL NAMES, not event names — matching on an event name
// silently matches no tools and the hook never fires.
check("PreToolUse matcher targets tool names", installed.hooks.PreToolUse[0].matcher, "*");
check("PermissionRequest matcher targets tool names", installed.hooks.PermissionRequest[0].matcher, "*");
check(
	"matcher is not an event name",
	JSON.stringify([installed.hooks.PreToolUse[0].matcher, installed.hooks.PermissionRequest[0].matcher]).includes(
		"PreToolUse",
	),
	false,
);
check("command points at the cli", JSON.stringify(installed).includes("toolwall/dist/cli.js"), true);

// idempotency: installing twice must not stack duplicates
installHooks(settingsPath, "/opt/toolwall/dist/cli.js", workdir);
const again = JSON.parse(readFileSync(settingsPath, "utf8"));
check("PreToolUse not duplicated", again.hooks.PreToolUse.length, installed.hooks.PreToolUse.length);
check("PermissionRequest not duplicated", again.hooks.PermissionRequest.length, installed.hooks.PermissionRequest.length);

// existing user hooks must survive
const mixed = { hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "my-linter" }] }] } };
writeMixed(settingsPath, mixed);
installHooks(settingsPath, "/opt/toolwall/dist/cli.js", workdir);
const merged = JSON.parse(readFileSync(settingsPath, "utf8"));
check(
	"existing user hooks preserved",
	merged.hooks.PreToolUse.some((g: any) => JSON.stringify(g).includes("my-linter")),
	true,
);

rmSync(workdir, { recursive: true, force: true });

console.log("=".repeat(52));
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);

function writeMixed(path: string, data: unknown) {
	writeFileSync(path, JSON.stringify(data, null, 2));
}