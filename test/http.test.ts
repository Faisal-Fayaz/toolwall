/**
 * HTTP adapter: toolwall in front of a REMOTE MCP server.
 *
 * This is the gap that limited reach — the stdio adapter can only wrap a
 * server it spawns, so it protected nothing when the MCP server was hosted,
 * which is most of them in practice. These tests stand up a real HTTP
 * upstream, put toolwall in front of it, and drive it as an agent would.
 *
 * Run: node --experimental-strip-types test/http.test.ts
 */
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { Gate } from "../dist/adapters/mcp-proxy/gate.js";
import { createHttpProxy, resolveHeaders } from "../dist/adapters/mcp-proxy/http.js";
import { DecisionLog } from "../dist/decision-log/log.js";
import { PolicyEngine } from "../dist/engine/engine.js";
import { SecretStore } from "../dist/secrets/store.js";
import { loadUserRules, userData } from "../dist/config.js";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const WASM = resolve(ROOT, ".build/policy.wasm");
const UPSTREAM = resolve(ROOT, "test/fixtures/http-upstream.mjs");
const TOKEN = "ghp_REMOTEUPSTREAMsecret1234567890abcd";

let pass = 0,
	fail = 0;
const check = (label: string, got: unknown, want: unknown) => {
	const ok = JSON.stringify(got) === JSON.stringify(want);
	ok ? pass++ : fail++;
	if (!ok) console.log(`  MISS ${label}: want ${JSON.stringify(want)} got=${JSON.stringify(got)}`);
};

const workdir = mkdtempSync(join(tmpdir(), "toolwall-http-"));
mkdirSync(join(workdir, ".firewall"), { recursive: true });

// Two rules, both scaffolding:
//   - deny one tool outright, so the list gate has work to do
//   - allow `dump_env`, which carries no `path` and would otherwise be
//     stopped by default-deny before it could leak anything to scrub
writeFileSync(
	join(workdir, ".firewall/policy.json"),
	JSON.stringify({
		rules: [
			{ name: "no-nuke", effect: "deny", tools: ["nuke_everything"], reason: "account deletion" },
			{ name: "allow-dump", effect: "allow", tools: ["dump_env"], reason: "test scaffolding" },
		],
	}),
);

const secrets = new SecretStore({
	path: join(workdir, "absent.json"),
	env: {} as NodeJS.ProcessEnv,
	secrets: { remote_token: TOKEN },
});

// ------------------------------------------------------- header brokering

console.log("header brokering");

{
	const resolved = resolveHeaders({ Authorization: "Bearer {{secret:remote_token}}" }, secrets);
	check("reference substituted", resolved.Authorization, `Bearer ${TOKEN}`);
	check("no other keys appear", Object.keys(resolved), ["Authorization"]);

	// without a store the reference is left literal, so it fails loudly at the
	// upstream rather than silently sending "{{secret:…}}"
	const bare = resolveHeaders({ Authorization: "Bearer {{secret:remote_token}}" }, undefined);
	check("no store leaves it literal", bare.Authorization, "Bearer {{secret:remote_token}}");

	const logText = JSON.stringify(resolved);
	check("resolved header is never logged by resolveHeaders", typeof logText, "string");
}

// ------------------------------------------------------------- fixture up

const upstream = spawn(process.execPath, [UPSTREAM], {
	env: {
		...process.env,
		// The upstream refuses anything without this credential, so a passing
		// test proves toolwall really presented the brokered secret.
		FIXTURE_REQUIRED_HEADER: "authorization",
		FIXTURE_REQUIRED_VALUE: `Bearer ${TOKEN}`,
		FIXTURE_TOKEN: TOKEN,
	} as Record<string, string>,
	stdio: ["ignore", "pipe", "pipe"],
});

const upstreamUrl = await new Promise<string>((res, rej) => {
	let buf = "";
	const t = setTimeout(() => rej(new Error("upstream did not start")), 15000);
	upstream.stdout.on("data", (d) => {
		buf += String(d);
		const i = buf.indexOf("{");
		if (i >= 0) {
			clearTimeout(t);
			res(JSON.parse(buf.slice(i)).url);
		}
	});
	upstream.stderr.on("data", (d) => process.stderr.write(`[upstream] ${d}`));
});

let handle: Awaited<ReturnType<typeof createHttpProxy>> | undefined;
let agent: Client | undefined;

try {
	const engine = await PolicyEngine.load(WASM, userData(loadUserRules(workdir).rules), undefined, secrets);
	const gate = new Gate({
		engine,
		log: new DecisionLog({ path: join(workdir, "decisions.jsonl") }),
		secrets,
		agent: { id: "http-test", cwd: workdir },
		catalogueDir: workdir,
	});

	// Without the header the upstream would 401 — this is the control.
	{
		const bare = new Client({ name: "control", version: "1" }, { capabilities: {} });
		let refused = false;
		try {
			await bare.connect(new StreamableHTTPClientTransport(new URL(upstreamUrl)));
			await bare.listTools();
		} catch {
			refused = true;
		}
		await bare.close().catch(() => {});
		check("upstream refuses an unauthenticated client (control)", refused, true);
	}

	handle = await createHttpProxy({
		gate,
		url: upstreamUrl,
		headers: { Authorization: "Bearer {{secret:remote_token}}" },
		secrets,
	});

	agent = new Client({ name: "agent", version: "1" }, { capabilities: {} });
	await agent.connect(new StreamableHTTPClientTransport(new URL(handle.url)));

	console.log("gating through the HTTP adapter");

	// ---- list gate
	const { tools } = await agent.listTools();
	const names = (tools as any[]).map((t) => t.name);
	check("tools/list hides the denied tool", names.includes("nuke_everything"), false);
	check("tools/list keeps the rest", names.includes("read_file") && names.includes("fetch_url"), true);

	// ---- allowed call reaches the REMOTE upstream
	const ok = await agent.callTool({ name: "read_file", arguments: { path: join(workdir, "a.md") } });
	check("allowed call reaches the remote upstream", (ok.content?.[0]?.text ?? "").includes("remote executed read_file"), true);

	// ---- argument-level deny against a remote server
	const denied = await agent.callTool({ name: "read_file", arguments: { path: join(workdir, ".env") } });
	check("secret path denied through HTTP", denied.isError === true, true);
	check("denial names the rule", (denied.content?.[0]?.text ?? "").includes("no-secret-reads"), true);

	const egress = await agent.callTool({ name: "fetch_url", arguments: { url: "https://example.com" } });
	check("egress denied through HTTP", egress.isError === true, true);
	check("egress names the rule", (egress.content?.[0]?.text ?? "").includes("no-egress"), true);

	// ---- hidden tool still enforced (filtering is not authorization)
	const nuke = await agent.callTool({ name: "nuke_everything", arguments: {} });
	check("hidden tool enforced on direct call", nuke.isError === true, true);
	check("hidden tool names the user rule", (nuke.content?.[0]?.text ?? "").includes("no-nuke"), true);

	// ---- response scrubbing over a real HTTP hop
	const dump = await agent.callTool({ name: "dump_env", arguments: {} });
	const dumped = dump.content?.[0]?.text ?? "";
	check("remote credential scrubbed", dumped.includes(TOKEN), false);
	check("redaction visible", dumped.includes("[redacted:"), true);
	check("rest of the response intact", dumped.includes("PATH=/usr/bin"), true);

	// ---- the brokered header must never reach the log
	const logText = readFileSync(join(workdir, "decisions.jsonl"), "utf8");
	check("decision log has no credential", logText.includes(TOKEN), false);
	check("catalogue published for hooks", readFileSync(join(workdir, ".toolwall/tool-catalogue.json"), "utf8").includes("read_file"), true);

	// ---- an unknown session id is refused, not silently created
	{
		const stray = new Client({ name: "stray", version: "1" }, { capabilities: {} });
		let refused = false;
		try {
			await stray.connect(
				new StreamableHTTPClientTransport(new URL(handle.url), {
					requestInit: { headers: { "mcp-session-id": "not-a-real-session" } },
				}),
			);
			await stray.listTools();
		} catch {
			refused = true;
		}
		await stray.close().catch(() => {});
		check("unknown session refused", refused, true);
	}
} finally {
	await agent?.close().catch(() => {});
	await handle?.close().catch(() => {});
	upstream.kill();
	rmSync(workdir, { recursive: true, force: true });
}

console.log("=".repeat(52));
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);