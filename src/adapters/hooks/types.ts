/**
 * Shared hook-adapter core.
 *
 * Every supported agent speaks a slightly different hook dialect. What they all
 * do NOT differ on is the decision itself, so each adapter only has to answer
 * two questions — "what call is this?" and "how do I say no?" — and the engine,
 * logging, queueing, grants and fail-closed behaviour stay in one place.
 *
 * Adapters are selected EXPLICITLY (--agent). Auto-detection would be a
 * security bug in its own right: emitting the wrong dialect usually makes the
 * host ignore the hook entirely and run the tool anyway, which fails OPEN.
 */

import type { ApprovalQueue } from "../../approval/queue.js";
import { applyGrants, type GrantStore } from "../../approval/grants.js";
import type { DecisionLog } from "../../decision-log/log.js";
import type { PolicyEngine } from "../../engine/engine.js";
import type { CallInput, Decision } from "../../types.js";
import { resolveAnnotations, type HookToolInput } from "./normalize.js";
import { loadCatalogue } from "./shared.js";
import type { Catalogue } from "./normalize.js";
import { normalizeArguments } from "./normalize.js";

export interface AdapterContext {
	engine: PolicyEngine;
	log: DecisionLog;
	queue?: ApprovalQueue;
	grants?: GrantStore;
	agent: { id: string; cwd: string };
	catalogueDir?: string;
	diagnostics?: (msg: string) => void;
}

export interface RenderContext {
	event: string;
	request?: ApprovalRequestLike;
}

/** The subset of an approval request a renderer needs. */
export interface ApprovalRequestLike {
	id: string;
	rule: string;
}

/**
 * A per-agent hook dialect.
 */
export interface AgentAdapter {
	id: string;
	/** Events that carry a tool call and can therefore be gated. */
	gatedEvents: string[];
	/**
	 * Normalize a host payload into the common shape, or return null if this
	 * payload is not a gated tool call for this agent.
	 */
	parse(payload: HookToolInput, ctx: AdapterContext): CallInput | null;
	/**
	 * Render a decision as host-specific JSON, or null for "no opinion" (let the
	 * host proceed with its own permission flow).
	 */
	render(decision: Decision, call: CallInput, ctx: RenderContext): string | null;
	/** Where `install` should write the agent's hook config. */
	defaultSettingsPath(home: string): string;
	/**
	 * Merge toolwall's hooks into an existing settings object, preserving
	 * whatever the user already configured.
	 */
	install(settings: Record<string, unknown>, cliPath: string, cwd: string): Record<string, unknown>;
}

/** Canonical workspace root across agents' differing field names. */
export function sessionCwd(payload: HookToolInput, fallback: string): string {
	const roots = (payload as any).workspace_roots;
	if (Array.isArray(roots) && typeof roots[0] === "string" && roots[0]) return roots[0];
	if (typeof payload.cwd === "string" && payload.cwd) return payload.cwd;
	return fallback;
}

/** Build a CallInput from already-extracted parts. */
export function buildCall(
	payload: HookToolInput,
	ctx: AdapterContext,
	parts: { name: string; args: Record<string, unknown>; catalogue?: Catalogue },
): CallInput {
	return {
		mode: "enforce",
		agent: {
			id: ctx.agent.id,
			cwd: sessionCwd(payload, ctx.agent.cwd),
			session: payload.session_id,
		},
		tool: {
			name: parts.name,
			annotations: resolveAnnotations(parts.name, payload, parts.catalogue ?? loadCatalogue(ctx.catalogueDir)),
		},
		arguments: normalizeArguments(parts.args),
	};
}

/** Events toolwall will act on if an adapter ever reports none. */
export const DEFAULT_GATED = ["PreToolUse", "PermissionRequest"];

/**
 * The shared decision pipeline: evaluate, apply grants, log, queue, then let the
 * adapter phrase the answer. Every adapter goes through this, so fail-closed
 * and grant handling cannot drift between agents.
 */
export async function runPipeline(
	payload: HookToolInput,
	adapter: AgentAdapter,
	ctx: AdapterContext,
): Promise<{ decision: Decision; call: CallInput; out: string | null } | null> {
	const event = payload.hook_event_name;
	if (!event || !adapter.gatedEvents.includes(event)) return null;

	const call = adapter.parse(payload, ctx);
	if (!call) return null;

	let { decision } = await ctx.engine.decideTimed(call);
	if (ctx.grants) decision = applyGrants(decision, call, ctx.grants);

	ctx.log.append({
		ts: new Date().toISOString(),
		...decision,
		agent: call.agent,
		tool: call.tool,
		arguments: call.arguments,
	});
	ctx.diagnostics?.(`${decision.effect.toUpperCase()} ${call.tool.name} (${decision.rule})`);

	const request = decision.effect === "ask" ? ctx.queue?.create(call, decision, "hook") : undefined;
	return { decision, call, out: adapter.render(decision, call, { event, request }) };
}

/** Shared wording for a refusal, so every agent explains itself the same way. */
export function denialText(decision: Decision, approval?: string): string {
	return (
		`Blocked by toolwall (rule: ${decision.rule}). ${decision.reason}.` +
		(approval ?? "") +
		` Do not retry the same call — take a different approach or ask the user.`
	);
}

/** Instructions for a human who wants to unblock an `ask`. */
export function approvalText(request?: ApprovalRequestLike, rule?: string): string {
	if (!request) return "";
	return (
		` Approval request ${request.id} recorded.` +
		` Approve once with: toolwall approve ${request.id}` +
		(rule ? `, or silence the rule with: toolwall grant ${rule}.` : ".")
	);
}