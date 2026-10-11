/**
 * Core contracts shared by the engine, the log, and every adapter.
 *
 * Both adapters (MCP proxy, agent hooks) normalize into CallInput so that a
 * policy never needs to know where a call originated.
 */

export type DecisionEffect = "allow" | "deny" | "ask";

export const EFFECTS: readonly DecisionEffect[] = ["allow", "deny", "ask"] as const;

/** Strongest effect wins. Order is load-bearing: later === stronger. */
const PRECEDENCE: Record<DecisionEffect, number> = { allow: 0, ask: 1, deny: 2 };

export function stronger(a: DecisionEffect, b: DecisionEffect): DecisionEffect {
	return PRECEDENCE[a] >= PRECEDENCE[b] ? a : b;
}

export interface Decision {
	effect: DecisionEffect;
	rule: string;
	reason: string;
}

export interface AgentInfo {
	id: string;
	/** Working directory, used by path-scope rules. */
	cwd?: string;
	session?: string;
}

export interface ServerInfo {
	name?: string;
	transport?: string;
	command?: string;
}

/**
 * A tool call, normalized. `arguments` is whatever the agent supplied; for MCP
 * that is params.arguments, for a hook it is the tool input object.
 */
export interface CallInput {
	mode: "enforce" | "dry-run";
	agent: AgentInfo;
	server?: ServerInfo;
	tool: {
		name: string;
		annotations?: {
			readOnlyHint?: boolean;
			destructiveHint?: boolean;
			idempotentHint?: boolean;
		};
	};
	arguments: Record<string, unknown>;
}

/** A decision plus its provenance, as persisted to the log. */
export interface DecisionRecord extends Decision {
	ts: string;
	agent: AgentInfo;
	server?: ServerInfo;
	tool: CallInput["tool"];
	arguments: Record<string, unknown>;
	/** How long the policy evaluation took. */
	evalMs?: number;
}

/** What the caller must do next, resolved from a decision. */
export type Outcome =
	| { action: "forward" }
	| { action: "block"; decision: Decision }
	| { action: "shadow"; decision: Decision };

export function outcomeFor(decision: Decision, mode: CallInput["mode"]): Outcome {
	if (mode === "dry-run") return { action: "shadow", decision };
	return decision.effect === "allow" ? { action: "forward" } : { action: "block", decision };
}