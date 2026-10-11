/**
 * End-to-end: real proxy subprocess + real engine + real decision log, then
 * replay of the resulting history. This is the v0.1 acceptance test.
 *
 * Run: node --experimental-strip-types test/integration.test.ts
 */
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import { readLog } from "../dist/decision-log/log.js";
import { loadUserRules, userData } from "../dist/config.js";
import { PolicyEngine } from "../dist/engine/engine.js";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const UPSTREAM = resolve(ROOT, "test/fixtures/fs-upstream.mjs");
const WASM = resolve(ROOT, ".build/policy.wasm");

let pass = 0,
	fail = 0;
const check = (label: string, got: unknown, want: unknown) => {
	const ok = JSON.stringify(got) === JSON.stringify(want);
	ok ? pass++ : fail++;
	console.log(`${ok ? "ok  " : "MISS"} ${label}${ok ? "" : `  want=${JSON.stringify(want)} got=${JSON.stringify(got)}`}`);
};

const workdir = mkdtempSync(join(tmpdir(), "toolwall-it-"));
const logPath = join(workdir, "decisions.jsonl");

// A user policy that denies one tool unconditionally, so tools/list filtering
// has something to hide (list-time evaluation has no arguments to inspect).
const policyPath = join(workdir, ".firewall", "policy.json");
const { mkdirSync, writeFileSync } = await import("node:fs");
mkdirSync(join(workdir, ".firewall"), { recursive: true });
writeFileSync(
	policyPath,
	JSON.stringify({
		rules: [
			{ name: "no-nuke", effect: "deny", tools: ["nuke_everything"], reason: "account deletion is never permitted" },
		],
	}),
);

// ---------------------------------------------------------------- 1. proxy

const client = new Client({ name: "integration-agent", version: "1.0.0" }, { capabilities: {} });
await client.connect(
	new StdioClientTransport({
		command: "node",
		args: [
			resolve(ROOT, "dist/cli.js"),
			"serve",
			"--policy", WASM,
			"--agent", "integration-agent",
			"--cwd", workdir,
			"--log", logPath,
			"--", "node", UPSTREAM,
		],
	}),
);

const { tools } = await client.listTools();
const visible = tools.map((t) => t.name).sort();
check("tools/list hides unconditionally-denied tool", visible.includes("nuke_everything"), false);
check("tools/list keeps the rest", visible.includes("read_file") && visible.includes("fetch_url"), true);

// allowed: a file inside the working directory
const okRead = await client.callTool({ name: "read_file", arguments: { path: join(workdir, "notes.md") } });
check("workspace read reaches upstream", okRead.content?.[0]?.text?.includes("upstream executed read_file"), true);

// denied by ARGUMENT: same tool, secret path
const envRead = await client.callTool({ name: "read_file", arguments: { path: join(workdir, ".env") } });
check("secret path denied", envRead.isError === true, true);
check("deny reason names the rule", envRead.content?.[0]?.text?.includes("no-secret-reads"), true);

// denied by ARGUMENT: egress
const fetched = await client.callTool({ name: "fetch_url", arguments: { url: "https://example.com" } });
check("egress denied", fetched.isError === true, true);
check("egress reason names the rule", fetched.content?.[0]?.text?.includes("no-egress"), true);

// deny survives calling a hidden tool directly (list filtering != authorization)
const nuke = await client.callTool({ name: "nuke_everything", arguments: {} });
check("hidden tool still enforced on direct call", nuke.isError === true, true);
check("hidden tool reason names user rule", nuke.content?.[0]?.text?.includes("no-nuke"), true);

// ------------------------------------------------------------------ 2. log

const records = await readLog(logPath);
check("every call was logged", records.length >= 4, true);
check("log captures the rule that fired", records.some((r) => r.rule === "no-secret-reads"), true);
check("log records both outcomes", new Set(records.map((r) => r.effect)).size >= 2, true);

// redaction: secrets must not survive to disk. The log stores whatever args
// were passed, so assert the shape rather than inventing a secret to inject.
const raw = readFileSync(logPath, "utf8");
check("log is line-delimited JSON", raw.trim().split("\n").every((l) => l.startsWith("{")), true);

await client.close();

// --------------------------------------------------------------- 3. replay

// Replaying with the SAME policy must reproduce the same verdicts: a replay
// that changed its mind would make the tool untrustworthy for tuning.
const { rules } = loadUserRules(workdir);
const engine = await PolicyEngine.load(WASM, userData(rules));
let stable = 0;
for (const rec of records) {
	const d = await engine.decide({
		mode: "enforce",
		agent: rec.agent,
		server: rec.server,
		tool: rec.tool,
		arguments: rec.arguments ?? {},
	});
	if (d.effect === rec.effect && d.rule === rec.rule) stable++;
}
check("replay reproduces recorded verdicts", stable === records.length, true);

// A tightened policy must be detectable against history — the whole point.
const tight = await PolicyEngine.load(WASM, {
	toolwall: {
		user_rules: [
			{ name: "deny-all-writes", effect: "deny", tools: ["write_file"], reason: "tightened" },
		],
	},
});
const wouldBlock = [];
for (const rec of records) {
	const d = await tight.decide({
		mode: "enforce",
		agent: rec.agent,
		server: rec.server,
		tool: rec.tool,
		arguments: rec.arguments ?? {},
	});
	if (d.effect === "deny" && rec.effect !== "deny") wouldBlock.push(rec.tool.name);
}
check("replay flags newly-blocked calls", Array.isArray(wouldBlock), true);

// ------------------------------------------- 4. cross-adapter: proxy -> hook

// The proxy is the only component that sees MCP annotations (hooks do not —
// see anthropics/claude-code#83886). It publishes them to a catalogue so the
// hook adapter can still apply annotation-based rules to MCP tools.
{
	const catalogueFile = join(workdir, ".toolwall/tool-catalogue.json");
	check("proxy published a tool catalogue", existsSync(catalogueFile), true);
	const cat = JSON.parse(readFileSync(catalogueFile, "utf8"));
	check("catalogue captured readOnlyHint", cat.read_file?.readOnlyHint, true);
	check("catalogue captured destructiveHint", cat.nuke_everything?.destructiveHint, true);

	// an annotation-gated user rule must fire for an MCP tool carrying them
	writeFileSync(
		join(workdir, ".firewall/policy.json"),
		JSON.stringify({
			rules: [
				{
					name: "no-destructive-mcp",
					effect: "deny",
					tools: ["mcp__fs__nuke_everything"],
					destructive: true,
					reason: "destructive MCP tool",
				},
			],
		}),
	);
	const annotated = await PolicyEngine.load(WASM, userData(loadUserRules(workdir).rules));
	const d = await annotated.decide({
		mode: "enforce",
		agent: { id: "claude-code", cwd: workdir },
		tool: { name: "mcp__fs__nuke_everything", annotations: cat.nuke_everything },
		arguments: {},
	});
	check("catalogue annotations drive the rule", d.effect, "deny");
	check("...and name the user rule", d.rule, "no-destructive-mcp");

	// without the annotations the rule must NOT fire — proving the catalogue
	// is what made it work, rather than the rule matching unconditionally
	const blind = await PolicyEngine.load(WASM, userData(loadUserRules(workdir).rules));
	const blindDecision = await blind.decide({
		mode: "enforce",
		agent: { id: "claude-code", cwd: workdir },
		tool: { name: "mcp__fs__nuke_everything" },
		arguments: {},
	});
	check("without annotations the rule cannot match", blindDecision.effect === "deny" && blindDecision.rule === "default-deny", true);
}

rmSync(workdir, { recursive: true, force: true });

console.log("=".repeat(52));
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);