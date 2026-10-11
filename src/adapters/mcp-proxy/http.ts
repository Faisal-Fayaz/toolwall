/**
 * HTTP adapter: toolwall listening locally in front of a REMOTE MCP server.
 *
 * This is what closes the reach gap. The stdio adapter can only wrap a server
 * it spawns, so it protects nothing when the MCP server is a hosted service —
 * which is most of them in practice.
 *
 *   agent ──▶ http://127.0.0.1:PORT/mcp ──▶ toolwall ──▶ https://remote/mcp
 *
 * The agent is pointed at the local endpoint; toolwall speaks streamable HTTP
 * upstream and gates every call on the way through.
 *
 * Bound to LOOPBACK by default. A policy proxy reachable from the network is a
 * new attack surface — a remote client could enumerate and invoke tools through
 * whatever policy happens to be loaded — so exposing it has to be a deliberate
 * flag, not a default.
 */

import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Server as McpServer } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

import type { Gate } from "./gate.js";
import type { SecretStore } from "../../secrets/store.js";
import { substituteSecrets } from "../../secrets/reference.js";

export interface HttpProxyOptions {
	gate: Gate;
	/** Upstream MCP endpoint, e.g. https://mcp.example.com/mcp */
	url: string;
	/** Force the legacy SSE transport instead of streamable HTTP. */
	useSse?: boolean;
	/** Default port; 0 asks the OS for a free one. */
	port?: number;
	host?: string;
	/**
	 * Headers for the upstream request, from the secret store.
	 * `--header Authorization=Bearer {{secret:github_token}}`
	 */
	headers?: Record<string, string>;
	secrets?: SecretStore;
	diagnostics?: (msg: string) => void;
}

export interface HttpProxyHandle {
	/** The local endpoint an agent should be pointed at. */
	url: string;
	port: number;
	close(): Promise<void>;
}

/**
 * Resolve `{{secret:…}}` references in upstream headers.
 *
 * This is credential brokering for real servers: the operator configures the
 * header once, the agent never holds the token, and the resolved value is never
 * logged.
 */
export function resolveHeaders(
	headers: Record<string, string> | undefined,
	secrets: SecretStore | undefined,
): Record<string, string> {
	if (!headers) return {};
	const out: Record<string, string> = {};
	for (const [k, v] of Object.entries(headers)) {
		if (!secrets) {
			out[k] = v;
			continue;
		}
		const sub = substituteSecrets({ [k]: v }, secrets);
		out[k] = String(sub.value[k] ?? "");
	}
	return out;
}

export async function createHttpProxy(opts: HttpProxyOptions): Promise<HttpProxyHandle> {
	const diag = opts.diagnostics ?? ((m: string) => process.stderr.write(`[toolwall] ${m}\n`));
	const headers = resolveHeaders(opts.headers, opts.secrets);

	const url = new URL(opts.url);
	const transport = opts.useSse
		? new SSEClientTransport(url, { requestInit: { headers } })
		: new StreamableHTTPClientTransport(url, { requestInit: { headers } });

	const upstream = new Client({ name: "toolwall-upstream", version: "0.2.0" }, { capabilities: {} });
	await upstream.connect(transport);
	diag(`connected upstream ${opts.url}${headers ? ` (${Object.keys(headers).length} header(s))` : ""}`);

	// One toolwall server per client session. Sessions are keyed by the
	// Mcp-Session-Id the transport hands us; an unknown id is refused rather
	// than silently creating a session, so a caller cannot acquire one by
	// guessing.
	const sessions = new Map<string, McpServer>();

	const sessionsFor = new Map<string, StreamableHTTPServerTransport>();

	async function makeSession(): Promise<{ id: string; transport: StreamableHTTPServerTransport }> {
		const gate = opts.gate;
		gate.setUpstream(url.host, opts.useSse ? "sse" : "streamable-http");

		const server = new McpServer({ name: "toolwall", version: "0.2.0" }, { capabilities: { tools: {} } });

		server.setRequestHandler(ListToolsRequestSchema, async () => gate.listTools(upstream));
		server.setRequestHandler(CallToolRequestSchema, async (req) => {
			const name = req.params.name;
			let annotations: Record<string, unknown> | undefined;
			try {
				const { tools } = await upstream.listTools();
				annotations = (tools as any[]).find((t) => t.name === name)?.annotations;
			} catch {
				// catalogue unavailable — evaluate without annotations
			}
			return gate.callTool(upstream, name, (req.params.arguments ?? {}) as Record<string, unknown>, annotations);
		});

		const transport = new StreamableHTTPServerTransport({
			sessionIdGenerator: () => randomUUID(),
			onsessioninitialized: (id: string) => {
				sessions.set(id, server);
				sessionsFor.set(id, transport);
				diag(`session ${id.slice(0, 8)} opened`);
			},
			onsessionclosed: (id: string) => {
				sessions.delete(id);
				sessionsFor.delete(id);
				diag(`session ${id.slice(0, 8)} closed`);
			},
		});

		await server.connect(transport);
		return { id: transport.sessionId ?? randomUUID(), transport };
	}

	const host = opts.host ?? "127.0.0.1";
	const httpServer: HttpServer = createServer((req, res) => {
		void handle(req, res);
	});

	async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
		try {
			// No credentials in toolwall's own logs or diagnostics.
			if (req.method === "GET" || req.method === "DELETE") {
				const id = req.headers["mcp-session-id"] as string | undefined;
				if (!id || !sessionsFor.has(id)) {
					res.writeHead(404).end();
					return;
				}
				await sessionsFor.get(id)!.handleRequest(req, res);
				return;
			}

			if (req.method === "POST") {
				const id = req.headers["mcp-session-id"] as string | undefined;

				if (id) {
					const transport = sessionsFor.get(id);
					if (!transport) {
						res.writeHead(404, { "content-type": "application/json" }).end(
							JSON.stringify({ error: "unknown session" }),
						);
						return;
					}
					await transport.handleRequest(req, res);
					return;
				}

				// No session id: a new session is being initialised.
				const { transport } = await makeSession();
				await transport.handleRequest(req, res);
				return;
			}

			res.writeHead(405, { allow: "GET, POST, DELETE" }).end();
		} catch (err) {
			diag(`request failed: ${err instanceof Error ? err.message : String(err)}`);
			if (!res.headersSent) {
				res.writeHead(500, { "content-type": "application/json" }).end(
					JSON.stringify({ error: "toolwall internal error" }),
				);
			} else {
				res.end();
			}
		}
	}

	const port = await new Promise<number>((resolve, reject) => {
		httpServer.once("error", reject);
		httpServer.listen(opts.port ?? 0, host, () => {
			const addr = httpServer.address();
			resolve(typeof addr === "object" && addr ? addr.port : 0);
		});
	});

	const local = `http://${host}:${port}/mcp`;
	diag(`listening on ${local} -> ${opts.url}`);

	return {
		url: local,
		port,
		close: async () => {
			for (const t of sessionsFor.values()) {
				try {
					await t.close();
				} catch {
					// best effort on shutdown
				}
			}
			await new Promise<void>((resolve) => httpServer.close(() => resolve()));
			await upstream.close();
		},
	};
}