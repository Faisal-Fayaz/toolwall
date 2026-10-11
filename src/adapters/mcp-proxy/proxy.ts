/**
 * stdio adapter: toolwall wrapping an MCP server it spawns.
 *
 * All policy lives in `gate.ts`. This file's only job is moving bytes: spawn a
 * subprocess, wire a transport, hand it to the gate.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

import type { Gate } from "./gate.js";

export interface StdioProxyOptions {
	gate: Gate;
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
	diagnostics?: (msg: string) => void;
}

export async function createProxy(
	opts: StdioProxyOptions,
): Promise<{ server: Server; client: Client; close(): Promise<void> }> {
	const diag = opts.diagnostics ?? ((m: string) => process.stderr.write(`[toolwall] ${m}\n`));

	const baseEnv = opts.upstreamEnv === "inherit"
		? (process.env as Record<string, string>)
		: getDefaultEnvironment();
	const upstreamEnv: Record<string, string> =
		opts.upstreamEnv && opts.upstreamEnv !== "inherit"
			? { ...baseEnv, ...opts.upstreamEnv }
			: { ...baseEnv };

	const upstream = new Client({ name: "toolwall-upstream", version: "0.2.0" }, { capabilities: {} });
	await upstream.connect(
		new StdioClientTransport({
			command: opts.upstream.command,
			args: opts.upstream.args,
			env: upstreamEnv,
		}),
	);

	const serverName =
		opts.upstream.args.find((a) => a.endsWith(".mjs") || a.endsWith(".js")) ?? opts.upstream.command;
	opts.gate.setUpstream(serverName, "stdio");

	const server = new Server({ name: "toolwall", version: "0.2.0" }, { capabilities: { tools: {} } });

	// ---- gate 1: discovery -------------------------------------------------
	server.setRequestHandler(ListToolsRequestSchema, async () => opts.gate.listTools(upstream));

	// ---- gate 2: invocation ------------------------------------------------
	server.setRequestHandler(CallToolRequestSchema, async (req) => {
		const name = req.params.name;
		let annotations: Record<string, unknown> | undefined;
		try {
			const { tools } = await upstream.listTools();
			annotations = (tools as any[]).find((t) => t.name === name)?.annotations;
		} catch {
			// catalogue unavailable — evaluate without annotations
		}
		return opts.gate.callTool(
			upstream,
			name,
			(req.params.arguments ?? {}) as Record<string, unknown>,
			annotations,
		);
	});

	await server.connect(new StdioServerTransport());
	diag(`wrapping ${opts.upstream.command}`);

	return {
		server,
		client: upstream,
		close: async () => {
			await upstream.close();
		},
	};
}