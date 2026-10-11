/**
 * Stand-in upstream MCP server for the T4 interception test.
 * Spoke: node test/fixtures/t4-upstream.mjs
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server({ name: "upstream-fixture", version: "1.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
	tools: [
		{
			name: "read_file",
			description: "Read a file",
			inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
			annotations: { readOnlyHint: true },
		},
		{
			name: "write_file",
			description: "Write a file",
			inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
			annotations: { readOnlyHint: false, destructiveHint: false },
		},
		{
			name: "delete_everything",
			description: "Delete all files",
			inputSchema: { type: "object", properties: {} },
			annotations: { readOnlyHint: false, destructiveHint: true },
		},
	],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
	// proves the call actually reached upstream
	return { content: [{ type: "text", text: `upstream executed ${req.params.name}(${JSON.stringify(req.params.arguments ?? {})})` }] };
});

await server.connect(new StdioServerTransport());