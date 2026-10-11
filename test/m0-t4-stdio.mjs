/**
 * T4 driver: connects to the proxy as if it were a real MCP server and
 * asserts both gates behave correctly.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const results = [];
const record = (name, pass, detail) => {
	results.push({ name, pass });
	console.log(`${pass ? "PASS" : "FAIL"}  ${name}\n      ${detail}`);
};

const client = new Client({ name: "fake-agent", version: "1.0.0" }, { capabilities: {} });
await client.connect(
	new StdioClientTransport({
		command: "node",
		args: [new URL("./fixtures/t4-proxy.mjs", import.meta.url).pathname],
	}),
);

// 1. initialize round-tripped
record("initialize round-trips", true, `connected; server = ${JSON.stringify(client.getServerVersion())}`);

// 2. tools/list is filtered
const { tools } = await client.listTools();
const names = tools.map((t) => t.name).sort();
const hiddenGone = !names.includes("delete_everything");
record(
	"tools/list filtered",
	hiddenGone && names.length === 2,
	`agent sees [${names.join(", ")}]; delete_everything hidden`,
);

// 3. allowed call reaches upstream
const ok = await client.callTool({ name: "read_file", arguments: { path: "/tmp/x" } });
const okText = ok.content?.[0]?.text ?? "";
record(
	"allowed call forwarded to upstream",
	okText.includes("upstream executed read_file"),
	okText,
);

// 4. denied call is blocked WITHOUT reaching upstream
const denied = await client.callTool({ name: "delete_everything", arguments: {} });
const deniedText = denied.content?.[0]?.text ?? "";
record(
	"denied call blocked (hidden tool called directly)",
	denied.isError === true && deniedText.includes("denied by policy") && !deniedText.includes("upstream executed"),
	`got isError=${denied.isError} text=${JSON.stringify(deniedText)}`,
);

// 5. annotations survive the proxy (policy authors depend on these)
const readFile = tools.find((t) => t.name === "read_file");
record(
	"tool annotations pass through",
	readFile?.annotations?.readOnlyHint === true,
	`read_file.annotations = ${JSON.stringify(readFile?.annotations)}`,
);

await client.close();

console.log("=".repeat(52));
const failed = results.filter((r) => !r.pass);
console.log(failed.length === 0 ? "ALL PASS" : `T4 FAILED (${failed.length})`);
process.exit(failed.length === 0 ? 0 : 1);