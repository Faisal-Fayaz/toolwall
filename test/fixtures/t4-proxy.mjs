/**
 * T4: proving a stdio MCP proxy can intercept and gate tool calls.
 *
 * This is the transport-level go/no-go for the whole product. If a proxy can
 * sit between an agent and an MCP server, filter tools/list, and gate
 * tools/call without corrupting the stream, the design holds.
 *
 * Spoke: node test/fixtures/t4-proxy.mjs
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const HOP = { command: "node", args: [new URL("./t4-upstream.mjs", import.meta.url).pathname] };
const HIDDEN = new Set(["delete_everything"]);

const upstream = new Client({ name: "upstream-client", version: "1.0.0" }, { capabilities: {} });
await upstream.connect(new StdioClientTransport(HOP));

const proxy = new Server({ name: "toolwall", version: "0.0.1" }, { capabilities: { tools: {} } });

// GATE 1: filter what the agent can even discover
proxy.setRequestHandler(ListToolsRequestSchema, async () => {
	const { tools } = await upstream.listTools();
	const visible = tools.filter((t) => !HIDDEN.has(t.name));
	// stderr only — stdout must stay a clean JSON-RPC channel
	process.stderr.write(`[toolwall] tools/list ${tools.length} -> ${visible.length}\n`);
	return { tools: visible };
});

// GATE 2: re-check on invocation. Filtering tools/list is NOT authorization —
// a client can construct tools/call directly without ever listing.
proxy.setRequestHandler(CallToolRequestSchema, async (req) => {
	const { name } = req.params;
	if (HIDDEN.has(name)) {
		process.stderr.write(`[toolwall] DENY ${name}\n`);
		return {
			isError: true,
			content: [{ type: "text", text: `toolwall: tool '${name}' is denied by policy (hidden_dangerous_tools)` }],
		};
	}
	process.stderr.write(`[toolwall] ALLOW ${name}\n`);
	return upstream.callTool({ name, arguments: req.params.arguments ?? {} });
});

await proxy.connect(new StdioServerTransport());