/**
 * Interop against a REAL MCP server.
 *
 * Every other test uses a synthetic fixture. That validates our logic against
 * our own assumptions, which is exactly what a protocol compatibility problem
 * would NOT show up in. This drives toolwall in front of the official
 * `@modelcontextprotocol/server-filesystem` — real tool names, real
 * annotations, real schema shapes — so a mismatch between our assumptions and
 * reality surfaces here rather than in a bug report.
 *
 * Run: node --experimental-strip-types test/interop.test.ts
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const WASM = resolve(ROOT, ".build/policy.wasm");
const SERVER = resolve(ROOT, "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js");

let pass = 0,
	fail = 0;
const check = (label: string, got: unknown, want: unknown) => {
	const ok = JSON.stringify(got) === JSON.stringify(want);
	ok ? pass++ : fail++;
	if (!ok) console.log(`  MISS ${label}: want ${JSON.stringify(want)} got=${JSON.stringify(got)}`);
};

const workdir = mkdtempSync(join(tmpdir(), "toolwall-interop-"));
const sandbox = join(workdir, "sandbox");
mkdirSync(sandbox, { recursive: true });
writeFileSync(join(sandbox, "notes.md"), "hello from the real server\n");
writeFileSync(join(sandbox, ".env"), "SECRET=hunter2\n");

const text = (r: any): string => (r?.content ?? []).map((c: any) => c?.text ?? "").join("\n");

let client: Client | undefined;
try {
	client = new Client({ name: "interop-agent", version: "1" }, { capabilities: {} });
	await client.connect(
		new StdioClientTransport({
			command: process.execPath,
			args: [
				resolve(ROOT, "dist/cli.js"), "serve",
				"--policy", WASM,
				"--cwd", sandbox,
				"--agent", "interop",
				"--log", join(workdir, "decisions.jsonl"),
				// the real server needs PATH and HOME to start
				"--upstream-env", "ALL",
				"--", "node", SERVER, sandbox,
			],
			env: process.env as Record<string, string>,
			stderr: "ignore",
		}),
	);

	console.log("real server: discovery");

	const { tools } = await client.listTools();
	const names = (tools as any[]).map((t) => t.name);
	check("real tools discovered", names.length > 0, true);
	check("read_file present", names.includes("read_file"), true);
	check("write_file present", names.includes("write_file"), true);

	// annotations must survive our filtering — the hook catalogue depends on them
	const readFile = (tools as any[]).find((t) => t.name === "read_file");
	check("real annotations preserved", typeof readFile?.annotations, "object");

	console.log("real server: enforcement");

	// an allowed read actually reads, through the real server
	const ok = await client.callTool({ name: "read_file", arguments: { path: join(sandbox, "notes.md") } });
	check("allowed read returns real file contents", text(ok).includes("hello from the real server"), true);

	// a secret path is denied by ARGUMENT, not by tool name
	const denied = await client.callTool({ name: "read_file", arguments: { path: join(sandbox, ".env") } });
	check("secret read denied", denied.isError === true, true);
	check("denial names the rule", text(denied).includes("no-secret-reads"), true);

	// outside the agent's working directory
	const outside = await client.callTool({ name: "read_file", arguments: { path: join(workdir, "outside.md") } });
	check("read outside cwd refused", outside.isError === true, true);

	// a real server's own argument shape (directory_tree) must work
	const tree = await client.callTool({ name: "directory_tree", arguments: { path: sandbox } });
	check("directory_tree allowed inside the sandbox", tree.isError !== true, true);

	console.log("real server: side effects");

	// a real write inside the workspace is permitted and actually happens
	const wrote = await client.callTool({
		name: "write_file",
		arguments: { path: join(sandbox, "new.md"), content: "written by interop" },
	});
	check("workspace write allowed", wrote.isError !== true, true);
	check("write actually landed", readFileSync(join(sandbox, "new.md"), "utf8").includes("written by interop"), true);

	// writing a secret path is denied
	const badWrite = await client.callTool({
		name: "write_file",
		arguments: { path: join(sandbox, ".env"), content: "overwritten" },
	});
	check("writing a secret path denied", badWrite.isError === true, true);
	check(
		"the secret file was NOT modified",
		readFileSync(join(sandbox, ".env"), "utf8").includes("hunter2"),
		true,
	);

	console.log("real server: hook catalogue");

	const cat = JSON.parse(readFileSync(join(sandbox, ".toolwall/tool-catalogue.json"), "utf8"));
	check("catalogue has real tool names", Object.keys(cat).length > 0, true);
	check("catalogue captured a readOnlyHint", cat.read_file?.readOnlyHint, true);

	const logText = readFileSync(join(workdir, "decisions.jsonl"), "utf8");
	check("decisions logged from a real server", logText.includes("read_file"), true);
	check("log never contains the secret", logText.includes("hunter2"), false);
} finally {
	await client?.close().catch(() => {});
	rmSync(workdir, { recursive: true, force: true });
}

console.log("=".repeat(52));
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);