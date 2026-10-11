/**
 * MCP stdio proxy: the enforcement point.
 *
 * Two gates, and both are necessary:
 *   1. tools/list is filtered, so the agent never sees what it cannot use. This
 *      also improves model behaviour — it picks from a smaller, relevant set.
 *   2. tools/call is re-checked. Filtering the list is NOT authorization: a
 *      client can construct a tools/call directly without ever listing, so
 *      treating "hidden" as "forbidden" would be a security hole.
 *
 * stdout must stay a clean JSON-RPC channel; all diagnostics go to stderr.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

import type { ApprovalQueue } from "../../approval/queue.js";
import { scrubToolResult } from "../../secrets/scrub.js";
import { substituteSecrets } from "../../secrets/reference.js";
import type { SecretStore } from "../../secrets/store.js";
import { applyGrants, type GrantStore } from "../../approval/grants.js";
import type { DecisionLog } from "../../decision-log/log.js";
import type { PolicyEngine } from "../../engine/engine.js";
import type { CallInput, Decision } from "../../types.js";
import { outcomeFor } from "../../types.js";

/** Rule name the policy emits when nothing matched; not a real verdict. */
const DEFAULT_DENY_RULE = "default-deny";

interface CatalogueTool {
	name: string;
	annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean };
}

/**
 * Persist tool annotations so the hook adapter can apply annotation-based rules
 * to MCP tools, which hooks otherwise see blind. Keyed `server__tool` to match
 * Claude Code's `mcp__server__tool` naming once the `mcp__` prefix is stripped.
 */
function writeCatalogue(cwd: string | undefined, tools: CatalogueTool[]): void {
	if (!cwd) return;
	const entries: Record<string, unknown> = {};
	for (const t of tools) {
		if (!t.annotations) continue;
		entries[t.name] = {
			readOnlyHint: t.annotations.readOnlyHint,
			destructiveHint: t.annotations.destructiveHint,
			idempotentHint: t.annotations.idempotentHint,
		};
	}
	const dir = `${cwd}/.toolwall`;
	mkdirSync(dir, { recursive: true });
	writeFileSync(`${dir}/tool-catalogue.json`, `${JSON.stringify(entries, null, 2)}\n`, {
		encoding: "utf8",
		mode: 0o600,
	});
}

export interface ProxyOptions {
	engine: PolicyEngine;
	log: DecisionLog;
	/** Command to spawn the upstream MCP server. */
	upstream: { command: string; args: string[] };
	/**
	 * Environment for the upstream process.
	 *
	 * The MCP SDK's default is a small allowlist, which silently strips almost
	 * everything — and plenty of real MCP servers need API keys or a usable
	 * PATH. Rather than inheriting wholesale (which would hand every upstream
	 * the operator's whole environment, including toolwall's own secrets), this
	 * forwards an explicit list. Pass `inherit` to take everything.
	 */
	upstreamEnv?: Record<string, string> | "inherit";
	/** Identity reported into policy input. */
	agent: { id: string; cwd?: string };
	/** deny | dry-run. In dry-run nothing is ever blocked. */
	mode?: "enforce" | "dry-run";
	/** Records `ask` decisions; the proxy fails closed on them. */
	queue?: ApprovalQueue;
	/**
	 * Brokered secrets. `{{secret:name}}` references are substituted here, at
	 * the boundary, and upstream responses are scrubbed on the way back.
	 */
	secrets?: SecretStore;
	/** Time-boxed suppressions of `ask` rules. */
	grants?: GrantStore;
	/** Optional hook for tests / a future TUI. */
	onDecision?: (decision: Decision, call: CallInput) => void;
	/** Diagnostics stream. Defaults to stderr (never stdout). */
	diagnostics?: (msg: string) => void;
}

export async function createProxy(opts: ProxyOptions): Promise<{ server: Server; client: Client }> {
	const mode = opts.mode ?? "enforce";
	const diag = opts.diagnostics ?? ((m: string) => process.stderr.write(`[toolwall] ${m}\n`));

	const upstream = new Client(
		{ name: "toolwall-upstream", version: "0.0.1" },
		{ capabilities: {} },
	);
	const baseEnv = opts.upstreamEnv === "inherit"
		? (process.env as Record<string, string>)
		: getDefaultEnvironment();
	const upstreamEnv: Record<string, string> =
		opts.upstreamEnv && opts.upstreamEnv !== "inherit"
			? { ...baseEnv, ...opts.upstreamEnv }
			: { ...baseEnv };

	await upstream.connect(
		new StdioClientTransport({
			command: opts.upstream.command,
			args: opts.upstream.args,
			env: upstreamEnv,
		}),
	);
	const serverName = opts.upstream.args.find((a) => a.endsWith(".mjs") || a.endsWith(".js")) ?? opts.upstream.command;

	const proxy = new Server(
		{ name: "toolwall", version: "0.0.1" },
		{ capabilities: { tools: {} } },
	);

	// ---- gate 1: discovery -------------------------------------------------
	// Filtering is UX, not enforcement (gate 2 is the boundary). At list time
	// there are no arguments to inspect, so only rules that deny
	// unconditionally can hide a tool. Hiding on the policy's default-deny
	// would hide EVERY tool, since no argument-dependent rule can match here.
	proxy.setRequestHandler(ListToolsRequestSchema, async () => {
		const { tools } = await upstream.listTools();

		const decisions = await Promise.all(
			tools.map(async (t) => {
				const call: CallInput = {
					mode: "enforce",
					agent: opts.agent,
					server: { name: serverName, transport: "stdio" },
					tool: { name: t.name, annotations: t.annotations },
					arguments: {},
				};
				return { tool: t, decision: await opts.engine.decide(call) };
			}),
		);

		const hidden = decisions.filter(
			(d) => d.decision.effect === "deny" && d.decision.rule !== DEFAULT_DENY_RULE,
		);
		const visible = decisions.filter((d) => !hidden.includes(d)).map((d) => d.tool);

		// Publish what we learned for the hook adapter. Claude Code does not
		// forward MCP annotations to hooks (anthropics/claude-code#83886), so
		// without this the hook cannot see readOnlyHint/destructiveHint and
		// annotation-based rules silently stop matching.
		try {
			writeCatalogue(opts.agent.cwd, tools);
		} catch {
			// a missing catalogue only costs us annotations; never fatal
		}

		diag(
			`tools/list ${tools.length} -> ${visible.length}` +
				(hidden.length ? ` (hidden: ${hidden.map((h) => h.tool.name).join(", ")})` : ""),
		);
		return { tools: visible };
	});

	// ---- gate 2: invocation ------------------------------------------------
	proxy.setRequestHandler(CallToolRequestSchema, async (req) => {
		const name = req.params.name;
		const args = (req.params.arguments ?? {}) as Record<string, unknown>;

		// annotations are known from the upstream catalogue
		let annotations: CallInput["tool"]["annotations"];
		try {
			const { tools } = await upstream.listTools();
			annotations = tools.find((t) => t.name === name)?.annotations;
		} catch {
			// catalogue unavailable — evaluate without annotations
		}

		const call: CallInput = {
			mode,
			agent: opts.agent,
			server: { name: serverName, transport: "stdio" },
			tool: { name, annotations },
			arguments: args,
		};

		let { decision, evalMs } = await opts.engine.decideTimed(call);
		if (opts.grants) decision = applyGrants(decision, call, opts.grants);

		const request = decision.effect === "ask" ? opts.queue?.create(call, decision, "proxy") : undefined;

		opts.log.append({
			ts: new Date().toISOString(),
			...decision,
			agent: call.agent,
			server: call.server,
			tool: call.tool,
			arguments: args,
			evalMs: Math.round(evalMs * 1000) / 1000,
		});
		opts.onDecision?.(decision, call);

		const outcome = outcomeFor(decision, mode);
		diag(`${mode === "dry-run" ? "SHADOW" : decision.effect.toUpperCase()} ${name} (${decision.rule})`);

		if (outcome.action === "block") {
			// Returned as a tool error so the agent can read the reason and
			// choose a different path, rather than seeing an opaque transport
			// failure. This reason is fed back to the model.
			//
			// An `ask` has no human in this transport to answer it — the caller
			// is a model on a pipe — so it fails closed like a deny, but says
			// exactly how to unblock it rather than just refusing.
			const approval =
				decision.effect === "ask"
					? request
						? `\nThis call needs human approval (request ${request.id}).\n` +
							`  approve once:   toolwall approve ${request.id}\n` +
							`  allow for a while: toolwall grant ${decision.rule}\n` +
							`  refuse:        toolwall deny ${request.id}`
						: `\nThis call needs human approval, but no approval channel is configured.`
					: "";

			return {
				isError: true,
				content: [
					{
						type: "text",
						text:
							`Blocked by toolwall policy.\n` +
							`  tool:   ${name}\n` +
							`  rule:   ${decision.rule}\n` +
							`  reason: ${decision.reason}\n` +
							approval +
							`\nDo not retry the same call. Choose another approach, or ask the user to run it manually.`,
					},
				],
			};
		}

		// Substitute secret references at the boundary, so the agent passes a
		// reference and never holds a credential.
		let outbound = args;
		if (opts.secrets) {
			const sub = substituteSecrets(args, opts.secrets);
			if (sub.names.length) {
				diag(`substituted secret(s) ${sub.names.join(", ")} for ${name}`);
				if (sub.missing.length) {
					// Fail closed: a typo'd secret name would otherwise send a
					// literal "{{secret:nope}}" upstream as if it were a token.
					opts.log.append({
						ts: new Date().toISOString(),
						effect: "deny",
						rule: "missing-secret",
						reason: `unknown secret(s): ${sub.missing.join(", ")}`,
						agent: call.agent,
						tool: call.tool,
						arguments: args,
					});
					return {
						isError: true,
						content: [
							{
								type: "text",
								text:
									`Blocked by toolwall: unknown secret reference(s) ${sub.missing.join(", ")}.\n` +
									`Known secrets: ${opts.secrets.names().join(", ") || "(none configured)"}.`,
							},
						],
					};
				}
				// Log the reference, never the substituted value.
				opts.log.append({
					ts: new Date().toISOString(),
					effect: decision.effect,
					rule: decision.rule,
					reason: `used secret(s): ${sub.names.join(", ")}`,
					agent: call.agent,
					tool: call.tool,
					arguments: args,
				});
			}
			outbound = sub.value;
		}

		const result = await upstream.callTool({ name, arguments: outbound });

		// Scrub the response BEFORE the agent sees it. This is the last point
		// at which toolwall has any authority over the credential.
		if (opts.secrets) {
			const { result: clean, stats } = scrubToolResult(result, opts.secrets);
			if (stats.count > 0) {
				diag(`scrubbed ${stats.count} secret(s) from ${name} response`);
				opts.log.append({
					ts: new Date().toISOString(),
					effect: decision.effect,
					rule: "response-scrubbed",
					reason: `scrubbed ${stats.count} item(s) (${stats.patterns} by pattern) from ${name}`,
					agent: call.agent,
					tool: call.tool,
					arguments: { _scrubbed: stats.count, _secrets: stats.names },
				});
			}
			return clean;
		}

		return result;
	});

	await proxy.connect(new StdioServerTransport());
	return { server: proxy, client: upstream };
}