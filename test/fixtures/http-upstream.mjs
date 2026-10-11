/**
 * A remote-shaped MCP upstream: streamable HTTP, not stdio.
 *
 * This is what the HTTP adapter actually faces in production. It also exposes
 * a credential through a header so header brokering can be exercised.
 */
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";

import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const REQUIRED_HEADER = process.env.FIXTURE_REQUIRED_HEADER ?? "";
const REQUIRED_VALUE = process.env.FIXTURE_REQUIRED_VALUE ?? "";
const TOKEN = process.env.FIXTURE_TOKEN ?? "";

function makeHandler() {
	const server = new Server({ name: "remote-fixture", version: "1.0.0" }, { capabilities: { tools: {} } });

	server.setRequestHandler(ListToolsRequestSchema, async () => ({
		tools: [
			{ name: "read_file", description: "Read", inputSchema: { type: "object", properties: { path: { type: "string" } } }, annotations: { readOnlyHint: true } },
			{ name: "write_file", description: "Write", inputSchema: { type: "object", properties: { path: { type: "string" } } }, annotations: { readOnlyHint: false } },
			{ name: "fetch_url", description: "Fetch", inputSchema: { type: "object", properties: { url: { type: "string" } } } },
			{ name: "dump_env", description: "Dump environment", inputSchema: { type: "object", properties: {} } },
			{ name: "nuke_everything", description: "Delete account", inputSchema: { type: "object", properties: {} }, annotations: { destructiveHint: true } },
		],
	}));

	server.setRequestHandler(CallToolRequestSchema, async (req) => {
		const name = req.params.name;
		if (name === "dump_env") {
			const lines = Object.entries(process.env)
				.filter(([k]) => k.startsWith("FIXTURE_TOKEN"))
				.map(([k, v]) => `${k}=${v}`);
			return { content: [{ type: "text", text: ["PATH=/usr/bin", ...lines].join("\n") }] };
		}
		return { content: [{ type: "text", text: `remote executed ${name}(${JSON.stringify(req.params.arguments ?? {})})` }] };
	});
	return server;
}

const transports = new Map();

const http = createServer(async (req, res) => {
	// Reject unauthenticated callers: proves toolwall actually presents the
	// brokered credential rather than the upstream just accepting anything.
	if (REQUIRED_HEADER) {
		const got = req.headers[REQUIRED_HEADER.toLowerCase()];
		if (got !== REQUIRED_VALUE) {
			res.writeHead(401, { "content-type": "application/json" }).end(JSON.stringify({ error: "unauthorized" }));
			return;
		}
	}

	try {
		const id = req.headers["mcp-session-id"];
		if (id && transports.has(id)) {
			await transports.get(id).handleRequest(req, res);
			return;
		}
		const server = makeHandler();
		const transport = new StreamableHTTPServerTransport({
			sessionIdGenerator: () => randomUUID(),
			onsessioninitialized: (sid) => transports.set(sid, transport),
			onsessionclosed: (sid) => transports.delete(sid),
		});
		await server.connect(transport);
		await transport.handleRequest(req, res);
	} catch (err) {
		if (!res.headersSent) res.writeHead(500).end(String(err));
	}
});

http.listen(Number(process.env.FIXTURE_PORT ?? 0), "127.0.0.1", () => {
	const addr = http.address();
	process.stdout.write(`${JSON.stringify({ url: `http://127.0.0.1:${addr.port}/mcp` })}\n`);
});

process.on("SIGTERM", () => process.exit(0));