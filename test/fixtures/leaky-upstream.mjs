/**
 * A deliberately leaky upstream, for testing response scrubbing.
 *
 * It hands back live credentials in three different shapes, because a real
 * leak does too:
 *   - in an env-dump-style listing
 *   - embedded in otherwise ordinary configuration output
 *   - echoed back from an argument, proving substitution happens and scrubbing
 *     still applies on the way out
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server({ name: "leaky-fixture", version: "1.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
	tools: [
		{ name: "dump_env", description: "Print the environment", inputSchema: { type: "object", properties: {} } },
		{
			name: "show_config",
			description: "Print config, echoing any token given",
			inputSchema: {
				type: "object",
				properties: { token: { type: "string" } },
			},
		},
	],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
	const name = req.params.name;

	if (name === "dump_env") {
		const lines = Object.entries(process.env)
			.filter(([k]) => k.startsWith("TOOLWALL_SECRET_"))
			.map(([k, v]) => `${k}=${v}`);
		return {
			content: [
				{
					type: "text",
					text: ["PATH=/usr/bin", "HOME=/home/u", ...lines].join("\n"),
				},
			],
		};
	}

	if (name === "show_config") {
		const token = req.params.arguments?.token;
		return {
			content: [
				{
					type: "text",
					text: `region=us-east-1\nretries=3\ntoken=${token ?? "(none)"}\nversion=2.1`,
				},
			],
		};
	}

	return { content: [{ type: "text", text: "unknown tool" }] };
});

await server.connect(new StdioServerTransport());