/**
 * Multi-agent hook adapter tests.
 *
 * Each agent speaks a different dialect, and the failure mode of getting one
 * wrong is FAIL OPEN — the host ignores an output it does not recognise and
 * runs the tool anyway. So these tests assert the exact wire format each agent
 * expects, not merely that "a deny happened".
 *
 * Run: node --experimental-strip-types test/multi-agent.test.ts
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { detectAdapter, getAdapter, looksLikeCursor } from "../dist/adapters/hooks/index.js";
import { runPipeline } from "../dist/adapters/hooks/types.js";
import { ApprovalQueue } from "../dist/approval/queue.js";
import { GrantStore } from "../dist/approval/grants.js";
import { DecisionLog } from "../dist/decision-log/log.js";
import { PolicyEngine } from "../dist/engine/engine.js";
import type { AdapterContext } from "../dist/adapters/hooks/types.js";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const WASM = resolve(ROOT, ".build/policy.wasm");

let pass = 0,
	fail = 0;
const check = (label: string, got: unknown, want: unknown) => {
	const ok = JSON.stringify(got) === JSON.stringify(want);
	ok ? pass++ : fail++;
	if (!ok) console.log(`  MISS ${label}: want ${JSON.stringify(want)} got ${JSON.stringify(got)}`);
};

const workdir = mkdtempSync(join(tmpdir(), "toolwall-multi-"));
const engine = await PolicyEngine.load(WASM);

function ctx(over: Partial<AdapterContext> = {}): AdapterContext {
	return {
		engine,
		log: new DecisionLog({ path: join(workdir, "log.jsonl") }),
		queue: new ApprovalQueue(join(workdir, "approvals.jsonl")),
		grants: new GrantStore(join(workdir, "grants.json")),
		agent: { id: "t", cwd: workdir },
		catalogueDir: workdir,
		...over,
	};
}

const decide = async (adapterId: string, payload: unknown) =>
	runPipeline(payload as never, getAdapter(adapterId), ctx());

// ------------------------------------------------------------------ selection

console.log("adapter selection");

check("claude-code is the default", getAdapter().id, "claude-code");
check("unknown agent is rejected", (() => {
	try {
		getAdapter("nope");
		return false;
	} catch {
		return true;
	}
})(), true);
check("cursor payload is detected", looksLikeCursor({ hook_event_name: "beforeShellExecution", command: "ls" }), true);
check("claude payload is not cursor", looksLikeCursor({ tool_name: "Read", tool_input: {} }), false);
check(
	"explicit --agent wins over detection",
	detectAdapter({ hook_event_name: "beforeShellExecution", command: "ls" }, "claude-code").id,
	"claude-code",
);
check(
	"cursor auto-detected when unspecified",
	detectAdapter({ hook_event_name: "beforeShellExecution", command: "ls" }).id,
	"cursor",
);
// Claude Code and Codex are indistinguishable by payload alone
check(
	"codex must be requested explicitly",
	detectAdapter({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: {} }).id,
	"claude-code",
);

// --------------------------------------------------------------------- cursor

console.log("cursor");

{
	// force-push: beforeShellExecution carries `command`, not tool_input.command
	const r = await decide("cursor", {
		hook_event_name: "beforeShellExecution",
		command: "git push --force origin main",
		workspace_roots: [workdir],
	});
	check("cursor gates shell", r?.decision.effect, "deny");
	const out = JSON.parse(r!.out!);
	// Cursor's envelope is `permission`, NOT hookSpecificOutput
	check("cursor uses permission field", out.permission, "deny");
	check("cursor denies via permission", out.permission === "deny", true);
	check("cursor agentMessage explains", out.agentMessage.includes("no-force-push"), true);
	check("cursor userMessage explains", out.userMessage.includes("no-force-push"), true);
	check("no Claude Code envelope leaks into cursor", "hookSpecificOutput" in out, false);
}

{
	// beforeReadFile carries file_path
	const r = await decide("cursor", {
		hook_event_name: "beforeReadFile",
		file_path: join(workdir, ".env"),
		workspace_roots: [workdir],
	});
	check("cursor gates file reads", r?.decision.effect, "deny");
	check("file_path maps to the path rules", JSON.parse(r!.out!).permission, "deny");
}

{
	// ordinary shell defers with permission "ask"
	const r = await decide("cursor", {
		hook_event_name: "beforeShellExecution",
		command: "npm test",
		workspace_roots: [workdir],
	});
	check("cursor asks for ordinary shell", JSON.parse(r!.out!).permission, "ask");
	check("cursor ask names the rule", JSON.parse(r!.out!).agentMessage.includes("shell-needs-human"), true);
}

{
	// workspace read is silent — Cursor does its own prompting
	const r = await decide("cursor", {
		hook_event_name: "beforeReadFile",
		file_path: join(workdir, "ok.md"),
		workspace_roots: [workdir],
	});
	check("cursor stays silent on allow", r?.out, null);
}

{
	// unrelated event must not be gated
	const r = await decide("cursor", { hook_event_name: "afterShellExecution", command: "ls" });
	check("cursor ignores non-gating events", r, null);
}

{
	// workspace_roots is the cwd, not process cwd
	const r = await decide("cursor", {
		hook_event_name: "beforeReadFile",
		file_path: "/somewhere/else/.env",
		workspace_roots: [workdir],
	});
	check("cursor honours workspace_roots", r?.decision.effect, "deny");
}

// ---------------------------------------------------------------------- codex

console.log("codex");

{
	const r = await decide("codex", {
		hook_event_name: "PreToolUse",
		tool_name: "Bash",
		tool_input: { command: "git push --force" },
		cwd: workdir,
	});
	check("codex gates shell", r?.decision.effect, "deny");
	const out = JSON.parse(r!.out!);
	check("codex uses the Claude-style envelope", out.hookSpecificOutput.permissionDecision, "deny");
	check("codex deny names the rule", out.hookSpecificOutput.permissionDecisionReason.includes("no-force-push"), true);
}

{
	// THE ONE THAT MATTERS: Codex parses `ask` but does not enforce it, and an
	// unsupported field makes it mark the run failed and CONTINUE the call.
	const r = await decide("codex", {
		hook_event_name: "PreToolUse",
		tool_name: "Bash",
		tool_input: { command: "npm test" },
		cwd: workdir,
	});
	const out = JSON.parse(r!.out!);
	check("codex never emits ask (it fails open)", out.hookSpecificOutput.permissionDecision, "deny");
	check("codex ask says how to approve", out.hookSpecificOutput.permissionDecisionReason.includes("toolwall approve"), true);
	check("codex ask names the rule", out.hookSpecificOutput.permissionDecisionReason.includes("shell-needs-human"), true);
}

{
	// apply_patch is Codex's edit path; rules speak `Edit`
	const r = await decide("codex", {
		hook_event_name: "PreToolUse",
		tool_name: "apply_patch",
		tool_input: { file_path: join(workdir, ".env") },
		cwd: workdir,
	});
	check("codex apply_patch is normalized to Edit", r?.decision.rule, "no-secret-reads");
}

{
	const r = await decide("codex", {
		hook_event_name: "PreToolUse",
		tool_name: "Read",
		tool_input: { file_path: join(workdir, "ok.md") },
		cwd: workdir,
	});
	check("codex stays silent on allow", r?.out, null);
}

{
	const r = await decide("codex", { hook_event_name: "SessionStart", tool_name: "Bash" });
	check("codex ignores non-gating events", r, null);
}

// ------------------------------------------------------------ claude no regress

console.log("claude-code unchanged");

{
	const r = await decide("claude-code", {
		hook_event_name: "PreToolUse",
		tool_name: "Read",
		tool_input: { file_path: join(workdir, ".env") },
		cwd: workdir,
	});
	const out = JSON.parse(r!.out!);
	check("claude-code envelope intact", out.hookSpecificOutput.permissionDecision, "deny");
	check("claude-code event name intact", out.hookSpecificOutput.hookEventName, "PreToolUse");
}

// ------------------------------------------------------------------- install

console.log("per-agent installers");

{
	const cli = join(ROOT, "dist/cli.js");
	const home = mkdtempSync(join(tmpdir(), "toolwall-home-"));

	const run = (agent: string) => {
		const out = execFileSync(
			process.execPath,
			[cli, "install-hooks", "--agent", agent, "--cwd", workdir, "--settings", join(home, `${agent}.json`)],
			{ encoding: "utf8" },
		);
		return JSON.parse(readFileSync(join(home, `${agent}.json`), "utf8"));
	};

	const cc = run("claude-code");
	check("claude-code installs PreToolUse", Array.isArray(cc.hooks.PreToolUse), true);
	check("claude-code passes its dialect", cc.hooks.PreToolUse[0].hooks[0].command.includes("--agent claude-code"), true);

	const cur = run("cursor");
	check("cursor sets version", cur.version, 1);
	check("cursor registers beforeShellExecution", Array.isArray(cur.hooks.beforeShellExecution), true);
	check("cursor registers beforeReadFile", Array.isArray(cur.hooks.beforeReadFile), true);
	check("cursor registers beforeMCPExecution", Array.isArray(cur.hooks.beforeMCPExecution), true);
	check("cursor passes its dialect", cur.hooks.beforeShellExecution[0].command.includes("--agent cursor"), true);
	check("cursor has no claude matcher key", "matcher" in cur.hooks.beforeShellExecution[0], false);

	const cdx = run("codex");
	check("codex groups by tool name", typeof cdx.hooks.PreToolUse.Bash, "object");
	check("codex PreToolUse has no array matcher", Array.isArray(cdx.hooks.PreToolUse), false);
	check("codex hook entries are typed", cdx.hooks.PreToolUse.Bash.hooks[0].type, "command");
	check("codex passes its dialect", cdx.hooks.PreToolUse.Bash.hooks[0].command.includes("--agent codex"), true);

	// idempotency per agent
	execFileSync(process.execPath, [cli, "install-hooks", "--agent", "cursor", "--cwd", workdir, "--settings", join(home, "cursor.json")], { encoding: "utf8" });
	const twice = JSON.parse(readFileSync(join(home, "cursor.json"), "utf8"));
	check("cursor reinstall does not duplicate", twice.hooks.beforeShellExecution.length, 1);

	// existing host config must survive
	const settingsFile = join(home, "cursor.json");
	const existing = JSON.parse(readFileSync(settingsFile, "utf8"));
	existing.hooks.beforeShellExecution.push({ command: "my-own-linter" });
	execFileSync("node", ["-e", `require('fs').writeFileSync(${JSON.stringify(settingsFile)}, ${JSON.stringify(JSON.stringify(existing))})`]);
	execFileSync(process.execPath, [cli, "install-hooks", "--agent", "cursor", "--cwd", workdir, "--settings", settingsFile], { encoding: "utf8" });
	const merged = JSON.parse(readFileSync(settingsFile, "utf8"));
	check(
		"existing host hooks preserved",
		merged.hooks.beforeShellExecution.some((e: any) => e.command === "my-own-linter"),
		true,
	);

	// default settings locations
	check("cursor default path", getAdapter("cursor").defaultSettingsPath("/h"), "/h/.cursor/hooks.json");
	check("codex default path", getAdapter("codex").defaultSettingsPath("/h"), "/h/.codex/hooks.json");
	check("claude default path", getAdapter("claude-code").defaultSettingsPath("/h"), "/h/.claude/settings.json");

	rmSync(home, { recursive: true, force: true });
}

rmSync(workdir, { recursive: true, force: true });

console.log("=".repeat(52));
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);