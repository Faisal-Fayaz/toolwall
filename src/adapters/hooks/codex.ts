/**
 * Codex hook adapter.
 *
 * Codex hooks live in `~/.codex/hooks.json`, inline `[[hooks.PreToolUse]]` in
 * `config.toml`, or `<repo>/.codex/hooks.json`. Unlike Cursor, Codex keys each
 * event group by TOOL NAME:
 *
 *   { "hooks": { "PreToolUse": { "Bash": { "hooks": [
 *       { "type": "command", "command": "…", "statusMessage": "…" } ] } } } }
 *
 * THE CRITICAL DETAIL: Codex parses `permissionDecision: "ask"` but does not
 * enforce it. Per the docs, an unsupported field makes Codex "mark the hook run
 * as failed, report the error, and continue the tool call" — that is FAIL OPEN.
 *
 * So this adapter must never emit `ask`. An `ask` decision is rendered as a
 * DENY with instructions, which is the only outcome Codex actually honours.
 * Silently returning "ask" would look like it worked while allowing everything.
 *
 * Two further host-side limits worth knowing:
 *   - Hooks require persisted trust; `--dangerously-bypass-hook-trust` exists
 *     for automation, and `[features] hooks = false` disables them entirely.
 *   - Async/background hooks cannot block. Toolwall must stay synchronous.
 */

import { approvalText, buildCall, denialText, type AgentAdapter, type AdapterContext } from "./types.js";
import type { HookToolInput } from "./normalize.js";
import type { CallInput, Decision } from "../../types.js";

/** Codex events that gate a tool call. */
const GATED_EVENTS = ["PreToolUse", "PermissionRequest"];

function parse(payload: HookToolInput, ctx: AdapterContext): CallInput | null {
	const name = typeof payload.tool_name === "string" ? payload.tool_name : null;
	if (!name) return null;

	// Codex names the apply_patch path for edits; our rules speak `Edit`.
	const tool = name === "apply_patch" ? "Edit" : name;

	const args: Record<string, unknown> = {};
	if (payload.tool_input && typeof payload.tool_input === "object") {
		Object.assign(args, payload.tool_input as Record<string, unknown>);
	} else if (typeof (payload as any).command === "string") {
		args.command = (payload as any).command;
	}
	if (typeof (payload as any).file_path === "string") args.file_path = (payload as any).file_path;
	// Codex reports file edits by their argv (["apply_patch", "…"]).
	if (Array.isArray(args.input)) args.command = (args.input as unknown[]).map(String).join(" ");

	return buildCall(payload, ctx, { name: tool, args });
}

function render(decision: Decision, _call: CallInput, ctx: { event: string; request?: any }): string | null {
	// Codex auto-approves on `allow`; we never speak, we only object.
	if (decision.effect === "allow") return null;

	const reason = denialText(decision, decision.effect === "ask" ? approvalText(ctx.request, decision.rule) : "");

	// `ask` is rendered as deny ON PURPOSE — see the module note. Codex does
	// not enforce `ask`; emitting it would fail open.
	return JSON.stringify({
		hookSpecificOutput: {
			hookEventName: ctx.event,
			permissionDecision: "deny",
			permissionDecisionReason: reason,
		},
	});
}

export const codexAdapter: AgentAdapter = {
	id: "codex",
	gatedEvents: GATED_EVENTS,
	parse,
	render,
	defaultSettingsPath: (home) => `${home}/.codex/hooks.json`,

	install(settings, cliPath, cwd) {
		const out: Record<string, any> = { ...settings };
		const hooks: Record<string, any> = { ...(out.hooks ?? {}) };
		const pre: Record<string, any> = { ...(hooks.PreToolUse ?? {}) };

		const command = `${JSON.stringify(process.execPath)} ${JSON.stringify(cliPath)} hook --agent codex --cwd ${JSON.stringify(cwd)}`;

		// Codex groups PreToolUse by tool name rather than using a matcher.
		const TOOLS = ["Bash", "Read", "Write", "Edit", "apply_patch", "shell", "mcp"];
		for (const tool of TOOLS) {
			const group = pre[tool] ?? { hooks: [] };
			const list: any[] = Array.isArray(group.hooks) ? group.hooks : [];
			const kept = list.filter(
				(e) => !String(e?.command ?? "").includes(cliPath) && !String(e?.command ?? "").includes("toolwall"),
			);
			pre[tool] = { ...group, hooks: [{ type: "command", command, statusMessage: "toolwall policy check" }, ...kept] };
		}

		hooks.PreToolUse = pre;
		out.hooks = hooks;
		return out;
	},
};