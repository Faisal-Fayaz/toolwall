/**
 * The gate: policy enforcement, with no knowledge of any transport.
 *
 * stdio and HTTP adapters differ only in how bytes move. Everything that
 * decides anything — policy, logging, grants, secret substitution, scrubbing —
 * lives here, so a new transport cannot fork the security logic.
 *
 * Both adapters implement the same shape:
 *
 *   listTools()               -> { tools }
 *   callTool(name, args)     -> the upstream's result, or a refusal
 *
 * `callTool` never throws for a policy decision: a refusal is returned as a
 * tool error so the agent can read the reason and change course, rather than
 * seeing an opaque transport failure.
 */

import { mkdirSync, writeFileSync } from "node:fs";

import type { ApprovalQueue } from "../../approval/queue.js";
import { applyGrants, type GrantStore } from "../../approval/grants.js";
import type { DecisionLog } from "../../decision-log/log.js";
import type { PolicyEngine } from "../../engine/engine.js";
import { scrubToolResult } from "../../secrets/scrub.js";
import { substituteSecrets } from "../../secrets/reference.js";
import type { SecretStore } from "../../secrets/store.js";
import type { CallInput, Decision } from "../../types.js";

/** Rule name the policy emits when nothing matched; not a real verdict. */
export const DEFAULT_DENY_RULE = "default-deny";

export interface GateOptions {
	engine: PolicyEngine;
	log: DecisionLog;
	queue?: ApprovalQueue;
	grants?: GrantStore;
	secrets?: SecretStore;
	agent: { id: string; cwd: string };
	/** Directory the MCP adapter caches learned tool annotations in. */
	catalogueDir?: string;
	/** deny | dry-run. In dry-run nothing is ever blocked. */
	mode?: "enforce" | "dry-run";
	/** Set by the adapter: how the upstream is identified in policy input. */
	upstreamLabel?: string;
	transport?: string;
	diagnostics?: (msg: string) => void;
}

/** What the upstream is: whatever `listTools`/`callTool` is bound to. */
export interface Upstream {
	listTools(): Promise<{ tools: ToolLike[] }>;
	callTool(params: { name: string; arguments?: Record<string, unknown> }): Promise<any>;
	/** Tool annotations keyed by name, for the catalogue. */
	toolName?: string;
}

export type ToolLike = {
	name: string;
	description?: string;
	annotations?: Record<string, unknown>;
	[key: string]: unknown;
};

export class Gate {
	readonly #opts: GateOptions;

	constructor(opts: GateOptions) {
		this.#opts = opts;
	}

	get mode(): "enforce" | "dry-run" {
		return this.#opts.mode ?? "enforce";
	}

	/** Adapters identify their upstream so policy input says where it came from. */
	setUpstream(label: string, transport: string): void {
		this.#opts.upstreamLabel = label;
		this.#opts.transport = transport;
	}

	get upstreamLabel(): string {
		return this.#opts.upstreamLabel ?? "unknown";
	}

	get transport(): string {
		return this.#opts.transport ?? "stdio";
	}

	#diag(msg: string): void {
		this.#opts.diagnostics?.(msg);
	}

	#callInput(tool: string, args: Record<string, unknown>, annotations?: Record<string, unknown>, serverName?: string): CallInput {
		return {
			mode: this.mode,
			agent: this.#opts.agent,
			server: { name: serverName ?? this.upstreamLabel, transport: this.transport },
			tool: { name: tool, annotations: annotations as CallInput["tool"]["annotations"] },
			arguments: args,
		};
	}

	// ------------------------------------------------------------ discovery

	/**
	 * Filtering is UX, not enforcement. At list time there are no arguments to
	 * inspect, so only rules that deny unconditionally can hide a tool. Hiding
	 * on the policy's default-deny would hide EVERY tool, since no
	 * argument-dependent rule can match with empty arguments.
	 */
	async listTools(upstream: Upstream): Promise<{ tools: ToolLike[] }> {
		const { tools } = await upstream.listTools();

		const decisions = await Promise.all(
			tools.map(async (t: ToolLike) => {
				const decision = await this.#evaluate(this.#callInput(t.name, {}, t.annotations));
				return { tool: t, decision };
			}),
		);

		const hidden = decisions.filter((d) => d.decision.effect === "deny" && d.decision.rule !== DEFAULT_DENY_RULE);
		const visible = decisions.filter((d) => !hidden.includes(d)).map((d) => d.tool);

		this.#publishCatalogue(tools);
		this.#diag(
			`tools/list ${tools.length} -> ${visible.length}` +
				(hidden.length ? ` (hidden: ${hidden.map((h) => h.tool.name).join(", ")})` : ""),
		);
		return { tools: visible };
	}

	// ----------------------------------------------------------- invocation

	/**
	 * Gate one call, then forward it. This is the security boundary: the
	 * decision is re-checked here regardless of what `tools/list` returned,
	 * because a client can construct a `tools/call` without ever listing.
	 */
	async callTool(
		upstream: Upstream,
		name: string,
		args: Record<string, unknown>,
		annotations?: Record<string, unknown>,
	): Promise<any> {
		const call = this.#callInput(name, args, annotations);

		const decision = await this.#evaluate(call);
		this.#log(call, decision);

		if (this.mode === "dry-run") {
			this.#diag(`SHADOW ${name} (${decision.rule})`);
		} else {
			this.#diag(`${decision.effect.toUpperCase()} ${name} (${decision.rule})`);
		}

		// Substitute secret references at the boundary, so the agent passes a
		// reference and never holds a credential.
		let outbound = args;
		if (this.#opts.secrets) {
			const sub = substituteSecrets(args, this.#opts.secrets);
			if (sub.names.length) {
				this.#diag(`substituted secret(s) ${sub.names.join(", ")} for ${name}`);
				if (sub.missing.length) {
					// Fail closed: a typo'd secret name would otherwise send a
					// literal "{{secret:nope}}" upstream as if it were a token.
					this.#log(call, { effect: "deny", rule: "missing-secret", reason: `unknown secret(s): ${sub.missing.join(", ")}` });
					return this.#refusal(
						`Blocked by toolwall: unknown secret reference(s) ${sub.missing.join(", ")}.\n` +
							`Known secrets: ${this.#opts.secrets.names().join(", ") || "(none configured)"}.`,
					);
				}
				// Log the reference, never the substituted value.
				this.#log(call, { ...decision, reason: `used secret(s): ${sub.names.join(", ")}` });
			}
			outbound = sub.value;
		}

		if (this.mode === "enforce" && decision.effect === "deny") {
			return this.#denial(decision, call, name);
		}

		const result = await upstream.callTool({ name, arguments: outbound });

		// Scrub the response BEFORE the agent sees it. This is the last point
		// at which toolwall has any authority over a credential.
		if (this.#opts.secrets) {
			const { result: clean, stats } = scrubToolResult(result, this.#opts.secrets);
			if (stats.count > 0) {
				this.#diag(`scrubbed ${stats.count} secret(s) from ${name} response`);
				this.#log(
					call,
					{
						effect: decision.effect,
						rule: "response-scrubbed",
						reason:
							`scrubbed ${stats.count} item(s) (${stats.patterns} by pattern` +
							`${stats.dropped ? `, ${stats.dropped} payload(s) dropped` : ""}) from ${name}`,
					},
					{ _scrubbed: stats.count, _dropped: stats.dropped ?? 0, _secrets: stats.names },
				);
			}
			return clean;
		}
		return result;
	}

	// ------------------------------------------------------------- internals

	async #evaluate(call: CallInput): Promise<Decision> {
		const base = await this.#opts.engine.decide(call);
		if (this.#opts.grants) return applyGrants(base, call, this.#opts.grants);
		return base;
	}

	#log(
		call: CallInput,
		decision: Decision,
		extraArgs?: Record<string, unknown>,
	): void {
		this.#opts.log.append({
			ts: new Date().toISOString(),
			...decision,
			agent: call.agent,
			server: call.server,
			tool: call.tool,
			arguments: extraArgs ?? call.arguments,
		});
	}

	#refusal(text: string) {
		return { isError: true, content: [{ type: "text", text }] };
	}

	#denial(decision: Decision, call: CallInput, name: string) {
		// (no `arguments` here: class bodies are strict mode)
		// An `ask` has no human in this transport to answer it — the caller is
		// a model on a pipe — so it fails closed like a deny, but says exactly
		// how to unblock rather than just refusing.
		const approval =
			decision.effect === "ask"
				? this.#approvalBlock(call, decision)
				: "";

		return this.#refusal(
			`Blocked by toolwall policy.\n` +
				`  tool:   ${name}\n` +
				`  rule:   ${decision.rule}\n` +
				`  reason: ${decision.reason}\n` +
				approval +
				`\nDo not retry the same call. Choose another approach, or ask the user to run it manually.`,
		);
	}

	#approvalBlock(call: CallInput, decision: Decision): string {
		const request = this.#opts.queue?.create(call, decision, "proxy");
		if (!request) return `\nThis call needs human approval, but no approval channel is configured.\n`;
		return (
			`\nThis call needs human approval (request ${request.id}).\n` +
			`  approve once:     toolwall approve ${request.id}\n` +
			`  allow for a while: toolwall grant ${decision.rule}\n` +
			`  refuse:          toolwall deny ${request.id}`
		);
	}

	/**
	 * Publish annotations for the hook adapter. Hooks do not receive MCP
	 * annotations (anthropics/claude-code#83886), so without this an
	 * annotation-based rule silently stops matching once a call comes through a
	 * hook instead of the proxy.
	 */
	#publishCatalogue(tools: ToolLike[]): void {
		const dir = this.#opts.catalogueDir;
		if (!dir) return;
		try {
			const entries: Record<string, unknown> = {};
			for (const t of tools) {
				if (!t.annotations) continue;
				entries[t.name] = {
					readOnlyHint: t.annotations.readOnlyHint,
					destructiveHint: t.annotations.destructiveHint,
					idempotentHint: t.annotations.idempotentHint,
				};
			}
			mkdirSync(`${dir}/.toolwall`, { recursive: true });
			writeFileSync(`${dir}/.toolwall/tool-catalogue.json`, `${JSON.stringify(entries, null, 2)}\n`, {
				encoding: "utf8",
				mode: 0o600,
			});
		} catch {
			// A missing catalogue only costs us annotations; never fatal.
		}
	}
}