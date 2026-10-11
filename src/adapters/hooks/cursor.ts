/**
 * Cursor hook adapter.
 *
 * Cursor's hook API (cursor.com/docs/hooks) config lives in `.cursor/hooks.json`
 * per project or `~/.cursor/hooks.json` user-global. Unlike Claude Code there is
 * no `matcher`: each event name is its own list.
 *
 * Cursor-specific facts that shaped this adapter:
 *
 *   - Permission events are `beforeShellExecution`, `beforeMCPExecution`,
 *     `beforeReadFile`, `beforeTabFileRead`, `subagentStart`, `preToolUse`.
 *   - The response is `{ permission: "allow"|"deny"|"ask", agentMessage?,
 *     userMessage? }` — a DIFFERENT envelope from Claude Code's
 *     `hookSpecificOutput.permissionDecision`.
 *   - Payload uses `command` / `file_path` / `workspace_roots`, not `tool_name`
 *     and `cwd`.
 *   - Exit code 0 with JSON on stdout. For permission hooks, output that does
 *     not match the schema BLOCKS the action.
 *
 * Known host-side gap: Cursor's CLI has partial hook support, and there is a
 * standing report that `beforeReadFile` denials are not always honoured. That is
 * a Cursor bug, not something this adapter can fix — but it does mean a read
 * denial is best-effort on Cursor, and the README says so.
 */

import { approvalText, buildCall, denialText, type AgentAdapter, type AdapterContext } from "./types.js";
import type { HookToolInput } from "./normalize.js";
import type { CallInput, Decision } from "../../types.js";

/** Cursor events that gate a tool call. */
const GATED_EVENTS = [
	"beforeShellExecution",
	"beforeMCPExecution",
	"beforeReadFile",
	"beforeTabFileRead",
	"preToolUse",
	"PermissionRequest",
];

/** Cursor event -> the tool name our policy should reason about. */
function toolNameFor(payload: HookToolInput): string | null {
	const event = payload.hook_event_name;
	const explicit = typeof payload.tool_name === "string" ? payload.tool_name : undefined;

	switch (event) {
		case "beforeShellExecution":
			return explicit ?? "Bash";
		case "beforeReadFile":
		case "beforeTabFileRead":
			return explicit ?? "Read";
		case "afterFileEdit":
			return explicit ?? "Edit";
		case "beforeMCPExecution":
		case "preToolUse":
		case "PermissionRequest":
			return explicit ?? null;
		default:
			return null;
	}
}

/** Cursor payload fields -> normalized argument object. */
function argumentsFor(payload: HookToolInput): Record<string, unknown> {
	const args: Record<string, unknown> = {};
	if (typeof payload.command === "string") args.command = payload.command;
	if (typeof payload.file_path === "string") args.file_path = payload.file_path;
	const ti = payload.tool_input;
	if (ti && typeof ti === "object") Object.assign(args, ti as Record<string, unknown>);
	// Cursor's MCP payload carries the tool name/arguments at the top level
	if (typeof payload.tool_name === "string") args.__cursor_tool = payload.tool_name;
	if (payload.arguments && typeof payload.arguments === "object") {
		Object.assign(args, payload.arguments as Record<string, unknown>);
	}
	return args;
}

function parse(payload: HookToolInput, ctx: AdapterContext): CallInput | null {
	const name = toolNameFor(payload);
	if (!name) return null;
	// Map a bare MCP tool name onto the same `server__tool` shape other agents use.
	const args = argumentsFor(payload);
	const raw = args.__cursor_tool;
	if (typeof raw === "string" && !raw.includes("__")) args.__cursor_tool = raw;
	return buildCall(payload, ctx, { name, args });
}

function render(decision: Decision, _call: CallInput, ctx: { event: string; request?: any }): string | null {
	// Cursor prompts on its own for `allow`; only objections need saying.
	if (decision.effect === "allow") return null;

	if (decision.effect === "ask") {
		return JSON.stringify({
			permission: "ask",
			userMessage: `toolwall: ${decision.rule} — ${decision.reason}`,
			agentMessage:
				`toolwall needs human approval (rule: ${decision.rule}). ` +
				approvalText(ctx.request, decision.rule),
		});
	}

	return JSON.stringify({
		permission: "deny",
		userMessage: `Blocked by toolwall (rule: ${decision.rule}). ${decision.reason}`,
		agentMessage: denialText(decision),
	});
}

export const cursorAdapter: AgentAdapter = {
	id: "cursor",
	gatedEvents: GATED_EVENTS,
	parse,
	render,
	defaultSettingsPath: (home) => `${home}/.cursor/hooks.json`,

	install(settings, cliPath, cwd) {
		const out: Record<string, any> = { ...settings };
		const version = typeof out.version === "number" ? out.version : 1;
		out.version = version;
		const hooks: Record<string, any[]> = { ...(out.hooks ?? {}) };

		const command = `${JSON.stringify(process.execPath)} ${JSON.stringify(cliPath)} hook --agent cursor --cwd ${JSON.stringify(cwd)}`;

		// Events we gate. Cursor has no matcher, so each is its own list.
		for (const event of ["beforeShellExecution", "beforeReadFile", "beforeMCPExecution", "preToolUse"]) {
			const existing: any[] = Array.isArray(hooks[event]) ? hooks[event] : [];
			// Replace our own entry on reinstall rather than stacking duplicates.
			const kept = existing.filter(
				(e) => !String(e?.command ?? "").includes(cliPath) && !String(e?.command ?? "").includes("toolwall"),
			);
			hooks[event] = [{ command }, ...kept];
		}

		out.hooks = hooks;
		return out;
	},
};

/**
 * Cursor is the one agent whose payload is unambiguous: `workspace_roots` and
 * `command`/`file_path` appear in no other dialect. Safe to auto-detect, unlike
 * Claude Code vs Codex which share `tool_name` + `hook_event_name`.
 */
export function looksLikeCursor(payload: HookToolInput): boolean {
	if (Array.isArray((payload as any).workspace_roots)) return true;
	if (typeof payload.file_path === "string" && !payload.tool_name) return true;
	return typeof payload.command === "string" && !payload.tool_name;
}