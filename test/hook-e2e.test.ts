/**
 * Subprocess-level hook verification.
 *
 * This exercises the exact path Claude Code will take: it spawns a command,
 * writes JSON to its stdin, and parses stdout. Anything written to stdout that
 * is not the decision breaks the hook, so this checks the real binary rather
 * than calling the handler in-process.
 *
 * Run: node --experimental-strip-types test/hook-e2e.test.ts
 */
import { execFileSync, execSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const CLI = resolve(ROOT, "dist/cli.js");
const WASM = resolve(ROOT, ".build/policy.wasm");

let pass = 0,
	fail = 0;
const check = (label: string, got: unknown, want: unknown) => {
	const ok = JSON.stringify(got) === JSON.stringify(want);
	ok ? pass++ : fail++;
	console.log(`${ok ? "ok  " : "MISS"} ${label}${ok ? "" : `  want=${JSON.stringify(want)} got=${JSON.stringify(got)}`}`);
};

const workdir = mkdtempSync(join(tmpdir(), "toolwall-hooke2e-"));
const settingsPath = join(workdir, "settings.json");

function runHook(payload: unknown): { stdout: string; stderr: string } {
	try {
		const stdout = execFileSync(
			process.execPath,
			[CLI, "hook", "--policy", WASM, "--cwd", workdir, "--agent", "claude-code"],
			{ input: JSON.stringify(payload), encoding: "utf8", cwd: workdir },
		);
		return { stdout, stderr: "" };
	} catch (err: any) {
		return { stdout: err.stdout ?? "", stderr: err.stderr ?? "" };
	}
}

const event = (tool: string, toolInput: Record<string, unknown>, name = "PreToolUse") => ({
	hook_event_name: name,
	tool_name: tool,
	tool_input: toolInput,
	cwd: workdir,
	session_id: "sess-1",
});

// 1. deny path — stdout must be exactly the decision JSON
{
	const r = runHook(event("Read", { file_path: join(workdir, ".env") }));
	let parsed: any = null;
	try {
		parsed = JSON.parse(r.stdout);
	} catch {
		/* handled by the assertion below */
	}
	check("deny emits parseable JSON on stdout", parsed !== null, true);
	check("deny decision is 'deny'", parsed?.hookSpecificOutput?.permissionDecision, "deny");
	check(
		"deny reason names the rule",
		parsed?.hookSpecificOutput?.permissionDecisionReason?.includes("no-secret-reads"),
		true,
	);
	check("deny carries the event name", parsed?.hookSpecificOutput?.hookEventName, "PreToolUse");
	check("stdout is only the decision (no extra output)", r.stdout.trim().startsWith("{"), true);
}

// 2. allow path — stdout must be EMPTY so the host agent's own flow proceeds
{
	const r = runHook(event("Read", { file_path: join(workdir, "notes.md") }));
	check("allow emits nothing on stdout", r.stdout, "");
}


// 3. Bash force-push denied through the real binary
{
	const r = runHook(event("Bash", { command: "git push --force origin main" }));
	const parsed = JSON.parse(r.stdout || "{}");
	check("force-push denied", parsed?.hookSpecificOutput?.permissionDecision, "deny");
	check(
		"force-push reason names the rule",
		parsed?.hookSpecificOutput?.permissionDecisionReason?.includes("no-force-push"),
		true,
	);
}

// 4. Bash ordinary command escalates to a human, with an actionable reason
{
	const r = runHook(event("Bash", { command: "npm run build" }));
	const parsed = JSON.parse(r.stdout || "{}");
	check("ordinary shell command asks", parsed?.hookSpecificOutput?.permissionDecision, "ask");
	check(
		"ask carries a reason",
		(parsed?.hookSpecificOutput?.permissionDecisionReason ?? "").length > 0,
		true,
	);
	check(
		"ask tells the user how to approve",
		/toolwall (approve|grant)/.test(parsed?.hookSpecificOutput?.permissionDecisionReason ?? ""),
		true,
	);
}

// 5. unknown event must not wedge the agent
{
	const r = runHook(event("Read", { file_path: join(workdir, ".env") }, "SessionStart"));
	check("unrelated event is ignored", r.stdout, "");
}

// 6. malformed stdin must not crash the hook
{
	let out = "";
	let threw = false;
	try {
		out = execFileSync(process.execPath, [CLI, "hook", "--policy", WASM, "--cwd", workdir], {
			input: "{ this is not json",
			encoding: "utf8",
			cwd: workdir,
		});
	} catch (err: any) {
		threw = true;
		out = err.stdout ?? "";
	}
	check("malformed stdin does not crash", threw, false);
	check("malformed stdin emits nothing", out, "");
}

// 7. installer end-to-end, then run the command it registered
{
	execFileSync(process.execPath, [CLI, "install-hooks", "--settings", settingsPath, "--cwd", workdir, "--policy", WASM], {
		encoding: "utf8",
	});
	check("settings written", existsSync(settingsPath), true);

	const settings = JSON.parse(readFileSync(settingsPath, "utf8"));
	const cmd: string = settings.hooks.PreToolUse[0].hooks[0].command;
	check("registered command invokes the cli", cmd.includes("dist/cli.js"), true);
	check("registered command passes cwd", cmd.includes(workdir), true);

	// Execute the command string exactly as written. Claude Code runs hook
	// commands through a shell, so parsing it ourselves would test our parser
	// rather than the thing that actually runs.
	const out = execSync(cmd, {
		input: JSON.stringify(event("Read", { file_path: join(workdir, ".env") })),
		encoding: "utf8",
		cwd: workdir,
	});
	check("registered command enforces policy", JSON.parse(out).hookSpecificOutput.permissionDecision, "deny");
}

// 8. hook decisions land in the log
{
	const logPath = join(workdir, ".toolwall/decisions.jsonl");
	check("hook log created", existsSync(logPath), true);
	const lines = readFileSync(logPath, "utf8").trim().split("\n").filter(Boolean);
	check("hook log is JSONL", lines.every((l) => l.startsWith("{")), true);
	check("hook log records denials", lines.some((l) => l.includes("no-secret-reads")), true);
}

mkdirSync(workdir, { recursive: true });
rmSync(workdir, { recursive: true, force: true });

console.log("=".repeat(52));
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);