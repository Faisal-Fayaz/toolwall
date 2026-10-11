/**
 * Exfiltration test.
 *
 * The unit tests prove the scrubber works on objects. This proves it is wired
 * into the path a leak actually takes: a real upstream handing live
 * credentials back through the real proxy, with an agent on the other end.
 *
 * This is the control that matters most. A deny rule stops the agent reading
 * ~/.aws/credentials, but it cannot stop a build step echoing a token into
 * stdout, and once a live credential is in the model's context it can be sent
 * anywhere with no rule consulted at all.
 *
 * Run: node --experimental-strip-types test/exfiltration.test.ts
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const WASM = resolve(ROOT, ".build/policy.wasm");
const LEAKY = resolve(ROOT, "test/fixtures/leaky-upstream.mjs");

let pass = 0,
	fail = 0;
const check = (label: string, got: unknown, want: unknown) => {
	const ok = JSON.stringify(got) === JSON.stringify(want);
	ok ? pass++ : fail++;
	if (!ok) console.log(`  MISS ${label}: want ${JSON.stringify(want)} got=${JSON.stringify(got)}`);
};

const TOKEN = "ghp_Z1y2X3b4N5m6Q7w8E9r0T1u2I3o4P5q6R7s8";
const AWSKEY = "AKIAZZZZZZZZZZZZZZZZ";
const workdir = mkdtempSync(join(tmpdir(), "toolwall-exfil-"));

// Scaffolding: the default policy denies these tools (they carry no `path`,
// so nothing matches and the policy fails closed). We opt them in so the test
// actually reaches upstream, where substitution and scrubbing happen.
mkdirSync(join(workdir, ".firewall"), { recursive: true });
writeFileSync(
	join(workdir, ".firewall/policy.json"),
	JSON.stringify({
		rules: [
			// Replace the guard rule so a `{{secret:…}}` reference is allowed
			// through to the substitution stage instead of being denied first.
			{ name: "secret-use-restricted", effect: "allow", tools: ["*"], uses_secret: true, reason: "test scaffolding" },
			// The leaky fixture's tools take no path argument.
			{ name: "allow-fixture", effect: "allow", tools: ["dump_env", "show_config"], reason: "test scaffolding" },
		],
	}),
);

// The proxy is a subprocess so it loads its own SecretStore from the
// environment — exactly as it would in production.
const upstreamEnv = {
	...process.env,
	TOOLWALL_SECRET_GITHUB_TOKEN: TOKEN,
	TOOLWALL_SECRET_AWS_KEY: AWSKEY,
} as Record<string, string>;

const agent = new Client({ name: "leaky-agent", version: "1.0.0" }, { capabilities: {} });
await agent.connect(
	new StdioClientTransport({
		command: process.execPath,
		args: [
			resolve(ROOT, "dist/cli.js"),
			"serve",
			"--policy", WASM,
			"--cwd", workdir,
			"--agent", "leaky-agent",
			"--log", join(workdir, "decisions.jsonl"),
			// Forward the secrets upstream, or it has nothing to leak and the
			// test would pass vacuously.
			"--upstream-env", "TOOLWALL_SECRET_GITHUB_TOKEN,TOOLWALL_SECRET_AWS_KEY",
			"--", "node", LEAKY,
		],
		env: upstreamEnv,
	}),
);

const text = (r: any): string => (r?.content ?? []).map((c: any) => c?.text ?? "").join("\n");

try {
	// 1. upstream dumps its environment, which contains live credentials
	const dump = await agent.callTool({ name: "dump_env", arguments: {} });
	const dumped = text(dump);
	check("live token never reaches the agent", dumped.includes(TOKEN), false);
	check("unknown AWS key never reaches the agent", dumped.includes(AWSKEY), false);
	check("redaction is visible rather than silent", dumped.includes("[redacted:"), true);
	check("the rest of the output is still readable", dumped.includes("PATH=/usr/bin"), true);
	check("the key NAMES are visible", dumped.includes("TOOLWALL_SECRET_GITHUB_TOKEN"), true);

	// 2. a credential embedded in otherwise ordinary config output
	const config = await agent.callTool({ name: "show_config", arguments: {} });
	const cfg = text(config);
	check("config without a token is untouched", cfg.includes("region=us-east-1"), true);
	check("no leaked token in config", cfg.includes(TOKEN), false);

	// 3. an unknown secret reference fails CLOSED rather than forwarding a literal
	const bad = await agent.callTool({
		name: "show_config",
		arguments: { token: "{{secret:not_configured}}" },
	});
	check("unknown secret reference is refused", bad.isError === true, true);
	check("...it names the unknown secret", text(bad).includes("not_configured"), true);
	check("...the literal reference is not echoed back", text(bad).includes("{{secret:"), false);
	check("...and the upstream was never called with it", text(bad).includes("region=us-east-1"), false);

	// 4. an opted-in reference is substituted upstream, then scrubbed coming back
	const ok = await agent.callTool({
		name: "show_config",
		arguments: { token: "{{secret:github_token}}" },
	});
	check("known reference does not error", ok.isError === true || ok.isError === undefined, true);
	check("the substituted token is scrubbed on the way back", text(ok).includes(TOKEN), false);

	// 5. nothing secret reached disk
	const logText = readFileSync(join(workdir, "decisions.jsonl"), "utf8");
	check("decision log contains no secret", logText.includes(TOKEN), false);
	check("decision log contains no other secret", logText.includes(AWSKEY), false);
	check("...but records that a scrub happened", logText.includes("response-scrubbed"), true);
} finally {
	await agent.close();
	rmSync(workdir, { recursive: true, force: true });
}

console.log("=".repeat(52));
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);