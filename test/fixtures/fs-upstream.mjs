/**
 * Upstream MCP server with tools shaped to exercise argument-level policy:
 * every tool takes a path, so rules can gate on WHAT is touched rather than
 * on the tool name alone.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const pathArg = { type: "object", properties: { path: { type: "string" } }, required: ["path"] };

const server = new Server({ name: "fs-fixture", version: "1.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
	tools: [
		{
			name: "read_file",
			description: "Read a file",
			inputSchema: pathArg,
			annotations: { readOnlyHint: true },
		},
		{
			name: "write_file",
			description: "Write a file",
			inputSchema: pathArg,
			annotations: { readOnlyHint: false, destructiveHint: false },
		},
		{
			name: "fetch_url",
			description: "Fetch a URL",
			inputSchema: { type: "object", properties: { url: { type: "string" } }, required: ["url"] },
			annotations: { readOnlyHint: false },
		},
		{
			name: "nuke_everything",
			description: "Delete the account",
			inputSchema: { type: "object", properties: {} },
			annotations: { readOnlyHint: false, destructiveHint: true },
		},
	],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => ({
	content: [
		{
			type: "text",
			text: `upstream executed ${req.params.name}(${JSON.stringify(req.params.arguments ?? {})})`,
		},
	],
}));

await server.connect(new StdioServerTransport());