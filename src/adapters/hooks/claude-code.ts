/**
 * Claude Code hook adapter.
 *
 * Claude Code writes the event JSON to stdin and reads a hook decision from
 * stdout. stdout MUST contain only the JSON decision — every diagnostic goes to
 * stderr, or the hook fails to parse.
 *
 * Precedence caveat (documented by Anthropic): a PreToolUse hook returning
 * "allow" does NOT skip Claude Code's own deny/ask rules, so returning allow is
 * safe — it removes prompts, it does not grant permission the user never had.
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import type { AdapterContext, AgentAdapter, RenderContext } from "./types.js";
import { approvalText, buildCall, denialText, runPipeline } from "./types.js";
import {
	cataloguePath,
	resolveAnnotations,
	type Catalogue,
	type HookToolInput,
} from "./normalize.js";
import type { CallInput, Decision } from "../../types.js";

export interface HookOptions extends AdapterContext {}

export { loadCatalogue } from "./shared.js";
export type { HookToolInput } from "./normalize.js";
export { normalizeArguments, resolveAnnotations, mcpToolKey } from "./normalize.js";

/** Read all of stdin (hooks deliver one JSON document and close). */
export async function readStdin(): Promise<string> {
	const chunks: Buffer[] = [];
	for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
	return Buffer.concat(chunks).toString("utf8");
}

/** Keep these re-exports working for existing importers. */
export function loadCatalogueHere(dir: string | undefined): Catalogue | undefined {
	try {
		return dir ? (JSON.parse(readFileSync(cataloguePath(dir), "utf8")) as Catalogue) : undefined;
	} catch {
		return undefined;
	}
}
void resolveAnnotations;

const GATED_EVENTS = ["PreToolUse", "PermissionRequest"];

function parse(payload: HookToolInput, ctx: AdapterContext): CallInput | null {
	const name = typeof payload.tool_name === "string" ? payload.tool_name : null;
	if (!name) return null;
	return buildCall(payload, ctx, { name, args: payload.tool_input ?? {} });
}

function render(decision: Decision, _call: CallInput, ctx: RenderContext): string | null {
	if (decision.effect === "ask") {
		// Record the request so a human can see the backlog, then hand the
		// decision to Claude Code WITH our reason attached. Returning null here
		// would prompt the user but leave them with no idea why toolwall
		// objected — a prompt that looks like ordinary friction gets approved.
		return JSON.stringify({
			hookSpecificOutput: {
				hookEventName: ctx.event,
				permissionDecision: "ask",
				permissionDecisionReason:
					`toolwall flagged this call (rule: ${decision.rule}). ${decision.reason}\n` +
					approvalText(ctx.request, decision.rule) +
					`\nApprove once, or silence this rule for a while with: toolwall grant ${decision.rule}`,
			},
		});
	}

	// `allow` is left to Claude Code's own permission flow. Returning allow from
	// a hook auto-approves the call, and that is the host agent's decision to
	// make — toolwall removes obstacles and states objections, it does not hand
	// out permission the user never gave.
	if (decision.effect !== "deny") return null;

	return JSON.stringify({
		hookSpecificOutput: {
			hookEventName: ctx.event,
			permissionDecision: "deny",
			permissionDecisionReason: denialText(decision),
		},
	});
}

/** Matchers filter on TOOL NAME, not event names. */
const HOOK_MATCHER = "*";

/**
 * Register toolwall in a Claude Code settings file, preserving anything else
 * already there. Idempotent: re-running replaces toolwall's entry instead of
 * stacking duplicates.
 */
export function installHooks(
	settingsPath: string,
	cliPath: string,
	cwd: string,
): { changed: boolean; settings: Record<string, any> } {
	const settings = readSettings(settingsPath);
	const updated = claudeCodeAdapter.install(settings, cliPath, cwd) as Record<string, any>;
	writeSettings(settingsPath, updated);
	return { changed: true, settings: updated };
}

export function readSettings(settingsPath: string): Record<string, unknown> {
	try {
		return JSON.parse(readFileSync(settingsPath, "utf8")) as Record<string, unknown>;
	} catch {
		// missing or malformed — start from empty rather than clobber blindly
		return {};
	}
}

export function writeSettings(settingsPath: string, settings: Record<string, unknown>): void {
	const dir = dirname(settingsPath);
	if (dir && dir !== ".") mkdirSync(dir, { recursive: true });
	writeFileSync(settingsPath, `${JSON.stringify(settings, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

export const claudeCodeAdapter: AgentAdapter = {
	id: "claude-code",
	gatedEvents: GATED_EVENTS,
	parse,
	render,
	defaultSettingsPath: (home) => `${home}/.claude/settings.json`,

	install(settings, cliPath, cwd) {
		const out: Record<string, any> = { ...settings };
		const groups: Record<string, any[]> = { ...(out.hooks ?? {}) };
		const command = `${JSON.stringify(process.execPath)} ${JSON.stringify(cliPath)} hook --agent claude-code --cwd ${JSON.stringify(cwd)}`;

		const ours = (g: any): boolean =>
			((g?.hooks ?? []) as any[]).some((h) => String(h?.command ?? "").includes(cliPath) || String(h?.command ?? "").includes("toolwall"));

		for (const event of ["PreToolUse", "PermissionRequest"]) {
			const existing = groups[event] ?? [];
			groups[event] = [{ matcher: HOOK_MATCHER, hooks: [{ type: "command", command }] }, ...existing.filter((g) => !ours(g))];
		}

		out.hooks = groups;
		return out;
	},
};

/**
 * Handle one hook event for Claude Code. Returns the JSON to print on stdout,
 * or null for "no decision".
 *
 * Unknown events and malformed payloads take that path deliberately: a broken
 * hook must not wedge the agent's session.
 */
export async function handleHook(input: string, opts: HookOptions): Promise<string | null> {
	let payload: HookToolInput;
	try {
		payload = JSON.parse(input) as HookToolInput;
	} catch {
		return null;
	}
	const result = await runPipeline(payload, claudeCodeAdapter, opts);
	return result ? result.out : null;
}