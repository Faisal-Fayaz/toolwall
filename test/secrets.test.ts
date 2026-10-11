/**
 * Credential brokering and response scrubbing.
 *
 * The property that matters most: once a live credential is in the model's
 * context it can be sent anywhere and no rule is consulted. Scrubbing at the
 * proxy boundary is the last place toolwall still has authority, so these
 * tests attack it from the directions a real leak would take.
 *
 * Run: node --experimental-strip-types test/secrets.test.ts
 */
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { scrubString, scrubToolResult, scrubValue } from "../dist/secrets/scrub.js";
import { findSecretRefs, substituteSecrets } from "../dist/secrets/reference.js";
import { SecretStore, ENV_PREFIX } from "../dist/secrets/store.js";
import { secretBuiltins } from "../dist/secrets/builtins.js";
import { PolicyEngine } from "../dist/engine/engine.js";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const WASM = resolve(ROOT, ".build/policy.wasm");

let pass = 0,
	fail = 0;
const check = (label: string, got: unknown, want: unknown) => {
	const ok = JSON.stringify(got) === JSON.stringify(want);
	ok ? pass++ : fail++;
	if (!ok) console.log(`  MISS ${label}: want ${JSON.stringify(want)} got=${JSON.stringify(got)}`);
};

const workdir = mkdtempSync(join(tmpdir(), "toolwall-secrets-"));
const GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
const AWS = "AKIAIOSFODNN7EXAMPLE";
const store = new SecretStore({
	path: join(workdir, "absent.json"),
	env: {} as NodeJS.ProcessEnv,
	secrets: { github_token: GH, short: "abc" },
});

// --------------------------------------------------------------------- store

console.log("secret store");

check("names only, no values", store.names().includes("github_token"), true);
check("tiny secrets are listed", store.names().includes("short"), true);
check("value accessor works", store.value("github_token"), GH);
check("unknown secret is undefined", store.value("nope"), undefined);

{
	const fromEnv = new SecretStore({
		path: join(workdir, "absent.json"),
		env: { [`${ENV_PREFIX}STRIPE_KEY`]: "sk_live_abc123xyz789" } as NodeJS.ProcessEnv,
	});
	check("env secrets are picked up", fromEnv.has("stripe_key"), true);
	check("env prefix is stripped and lowercased", fromEnv.names(), ["stripe_key"]);
}
{
	// short values must not be substring-scrubbed — collisions would mangle text
	check("short secrets are not scrubbable", store.scrubbable().includes("abc"), false);
	check("long secrets are scrubbable", store.scrubbable().includes(GH), true);
}

// ------------------------------------------------------------------- scrub

console.log("response scrubbing");

{
	// layer 1: a secret toolwall was told about
	const r = scrubString(`token is ${GH} ok`, store);
	check("known secret removed", r.text.includes(GH), false);
	check("replacement names the secret", r.text.includes("[redacted:github_token]"), true);
	check("surrounding text preserved", r.text.startsWith("token is "), true);
	check("stats report the name, not the value", r.stats.names, ["github_token"]);
}

{
	// layer 2: shapes nobody told us about
	const r = scrubString(`aws=${AWS} gh=${GH} plain=text`, store);
	check("unknown AWS key removed", r.text.includes(AWS), false);
	check("known GH token also removed", r.text.includes(GH), false);
	check("ordinary text untouched", r.text.includes("plain=text"), true);
	check("pattern hits counted", r.stats.patterns >= 1, true);
}

{
	const r = scrubString("Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345", undefined);
	check("bearer header removed", r.text.includes("abcdefghij"), false);
}
{
	const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----";
	const r = scrubString(pem, undefined);
	check("pem block removed", r.text.includes("MIIEow"), false);
}
{
	// false-positive control: ordinary text must survive
	const r = scrubString("refactor the auth middleware and update docs", undefined);
	check("ordinary prose untouched", r.text, "refactor the auth middleware and update docs");
	check("no spurious stats", r.stats.count, 0);
}

// nested structures
{
	const out = scrubValue(
		{ a: `x ${GH} y`, nested: { token: "supersecretvalue123" }, list: [`${GH}`] },
		store,
	);
	const text = JSON.stringify(out.value);
	check("nested secret removed", text.includes(GH), false);
	check("sensitive KEY redacted by name", text.includes("[redacted:field]"), true);
	check("shape preserved", Array.isArray((out.value as any).list), true);
	check("stats counted", out.stats.count > 0, true);
}

// MCP tool results specifically
{
	const { result, stats } = scrubToolResult(
		{
			isError: false,
			content: [
				{ type: "text", text: `here is your token ${GH}` },
				{ type: "text", text: "harmless" },
			],
		} as any,
		store,
	);
	const text = JSON.stringify(result);
	check("tool result scrubbed", text.includes(GH), false);
	check("envelope preserved", (result as any).isError, false);
	check("all content blocks retained", (result as any).content.length, 2);
	check("stats reported", stats.count, 1);
}
{
	// an error result must keep its shape so agent error handling still works
	const { result } = scrubToolResult({ isError: true, content: [{ type: "text", text: `fail ${GH}` }] } as any, store);
	check("error flag survives scrubbing", (result as any).isError, true);
}

// a secret embedded in a longer blob (base64-ish middle of a token)
{
	const blob = `-----BEGIN PRIVATE KEY-----\n${GH}\nmore\n-----END PRIVATE KEY-----`;
	const r = scrubString(blob, store);
	check("secret inside a block is still removed", r.text.includes(GH), false);
}

// ------------------------------------------------------------- references

console.log("secret references");

check("finds refs", findSecretRefs({ h: "Authorization: {{secret:github_token}}" }), ["github_token"]);
check("no refs in plain text", findSecretRefs({ h: "hello" }), []);

{
	const sub = substituteSecrets({ h: "Bearer {{secret:github_token}}" }, store);
	check("reference substituted", sub.value.h, `Bearer ${GH}`);
	check("name reported", sub.names, ["github_token"]);
	check("nothing missing", sub.missing, []);
}
{
	const sub = substituteSecrets({ h: "{{ secret:github_token }}" }, store);
	check("whitespace tolerated", sub.value.h, GH);
	check("case-insensitive name", sub.names, ["github_token"]);
}
{
	// an unknown name must stay visible, not become an empty string
	const sub = substituteSecrets({ h: "{{secret:nope}}" }, store);
	check("unknown ref left literal", sub.value.h, "{{secret:nope}}");
	check("unknown ref reported as missing", sub.missing, ["nope"]);
}
{
	const sub = substituteSecrets({ nested: { list: ["{{secret:github_token}}"] } }, store);
	check("nested substitution", (sub.value.nested as any).list[0], GH);
}

// the agent must never see the value; the LOG must never contain it
{
	const ref = "{{secret:github_token}}";
	check("the reference itself is not a secret", ref.includes(GH), false);
	const logged = JSON.stringify({ arguments: { h: ref } });
	check("logging the reference leaks nothing", logged.includes(GH), false);
}

// ---------------------------------------------------------------- policy

console.log("policy gating of secret use");

{
	const engine = await PolicyEngine.load(WASM, undefined, undefined, store);

	const denied = await engine.decide({
		mode: "enforce",
		agent: { id: "t", cwd: workdir },
		tool: { name: "mcp__api__post" },
		arguments: { body: "{{secret:github_token}}" },
	});
	check("secret use is denied by default", denied.effect, "deny");
	check("...and names the rule", denied.rule, "secret-use-restricted");
	check("...and never echoes the secret", denied.reason.includes(GH), false);
	check("...but shows the reference", denied.reason.includes("brokered credential"), true);

	const allowed = await engine.decide({
		mode: "enforce",
		agent: { id: "t", cwd: workdir },
		tool: { name: "mcp__api__post" },
		arguments: { body: "no secrets here" },
	});
	check("calls without secrets are unaffected", allowed.effect === "allow" || allowed.rule === "default-deny", true);

	// Regression: the secret guard must NEVER fire on a call that merely LOOKS
	// sensitive. An over-broad deny here would block ordinary traffic and train
	// people to disable the rule.
	for (const args of [
		{},
		{ command: "ls" },
		{ path: "/", network: "x" },
		{ body: "{{secret}}" },                       // malformed, not a reference
		{ body: "see docs at {{secrets:github_token}}" }, // near-miss syntax
		{ token: "{{ secret }}" },
	]) {
		const d = await engine.decide({
			mode: "enforce",
			agent: { id: "t", cwd: workdir },
			tool: { name: "mcp__api__post" },
			arguments: args,
		});
		check(`secret guard stays quiet for ${JSON.stringify(args)}`, d.rule === "secret-use-restricted", false);
	}

	// Deliberately CONSERVATIVE: reference-looking text is treated as a
	// reference even when it is not one toolwall can resolve. `${{secret:x}}`
	// is shell parameter expansion, not a reference — but allowing it would let
	// substitution paste a credential inside an expansion and mangle it, so it
	// fails closed instead. An over-broad deny is recoverable; a mangled command
	// is not.
	const shellish = await engine.decide({
		mode: "enforce",
		agent: { id: "t", cwd: workdir },
		tool: { name: "mcp__api__post" },
		arguments: { body: "${{secret:github_token}}" },
	});
	check("reference-looking shell expansion fails closed", shellish.rule, "secret-use-restricted");

	// ...but it does fire on a genuine reference
	const genuine = await engine.decide({
		mode: "enforce",
		agent: { id: "t", cwd: workdir },
		tool: { name: "mcp__api__post" },
		arguments: { body: "prefix {{secret:github_token}} suffix" },
	});
	check("genuine reference still trips the guard", genuine.rule, "secret-use-restricted");

	// A permissive rule must NOT be able to defeat the guard: deny > allow, so
	// adding an unrelated allow rule leaves the deny standing.
	const permissive = await PolicyEngine.load(WASM, {
		toolwall: {
			user_rules: [
				{
					name: "allow-github-secret",
					effect: "allow",
					tools: ["mcp__api__post"],
					secret_names: ["github_token"],
					reason: "this endpoint needs the GitHub credential",
				},
			],
		},
	}, undefined, store);
	const stillDenied = await permissive.decide({
		mode: "enforce",
		agent: { id: "t", cwd: workdir },
		tool: { name: "mcp__api__post" },
		arguments: { body: "{{secret:github_token}}" },
	});
	check("an extra allow rule cannot defeat the guard", stillDenied.effect, "deny");
	check("...the guard still names itself", stillDenied.rule, "secret-use-restricted");

	// Opting in therefore means REPLACING the guard rule by name, which is the
	// documented layering mechanism. This is deliberate: opening a credential
	// should be a visible edit to the rule, not an additive one.
	const opted = await PolicyEngine.load(WASM, {
		toolwall: {
			user_rules: [
				{
					name: "secret-use-restricted",
					effect: "allow",
					tools: ["mcp__api__post"],
					secret_names: ["github_token"],
					reason: "this endpoint needs the GitHub credential",
				},
			],
		},
	}, undefined, store);
	const d2 = await opted.decide({
		mode: "enforce",
		agent: { id: "t", cwd: workdir },
		tool: { name: "mcp__api__post" },
		arguments: { body: "{{secret:github_token}}" },
	});
	check("overriding the guard by name opts in", d2.effect, "allow");
	check("...and the reason is preserved", d2.reason.includes("needs the GitHub credential"), true);

	// the override must not leak to other tools
	const other = await opted.decide({
		mode: "enforce",
		agent: { id: "t", cwd: workdir },
		tool: { name: "mcp__other__post" },
		arguments: { body: "{{secret:github_token}}" },
	});
	check("the override is scoped to its tools", other.effect, "deny");
}

// secret builtins expose existence, never values
{
	const builtins = secretBuiltins(store);
	check("secret_exists finds a known name", builtins.secret_exists!("github_token"), true);
	check("secret_exists rejects unknown", builtins.secret_exists!("nope"), false);
	const names = builtins.secret_ref_names!({ a: "{{secret:github_token}}" });
	check("secret_ref_names returns names", names, ["github_token"]);
	check("secret_ref_names never returns values", JSON.stringify(names).includes(GH), false);
	check("contains_secret_ref detects", builtins.contains_secret_ref!({ a: "{{secret:x}}" }), true);
}

// ------------------------------------------------------------------- hygiene

console.log("hygiene");

{
	// the whole suite above must never have written a secret to a temp file we
	// then read back
	const dir = join(workdir, "logs");
	rmSync(dir, { recursive: true, force: true });
	check("no secrets file created in the test dir", existsSafe(join(workdir, "secrets.json")), false);
}

rmSync(workdir, { recursive: true, force: true });

console.log("=".repeat(52));
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);

function existsSafe(p: string): boolean {
	try {
		readFileSync(p);
		return true;
	} catch {
		return false;
	}
}