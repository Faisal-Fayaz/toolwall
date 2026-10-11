/**
 * Engine tests against the compiled default policy.
 * Run: node --experimental-strip-types test/engine.test.ts
 */
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { PolicyEngine } from "../dist/engine/engine.js";
import { pathIsWithin, pathContainsSecret } from "../dist/engine/host-builtins.js";
import type { CallInput, DecisionEffect } from "../dist/types.js";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const WASM = resolve(ROOT, ".build/policy.wasm");

let pass = 0,
	fail = 0;

function check(label: string, got: unknown, want: unknown) {
	const ok = got === want;
	ok ? pass++ : fail++;
	if (!ok) console.log(`  MISS ${label}: want ${JSON.stringify(want)} got ${JSON.stringify(got)}`);
}

function checkRule(label: string, got: { rule: string }, want: string) {
	check(`${label} [rule]`, got.rule, want);
}

// ------------------------------------------------------------ host builtins

console.log("host builtins (pure JS, testable without wasm)");

check("within: direct child", pathIsWithin("/a", "/a/b"), true);
check("within: itself", pathIsWithin("/a", "/a"), true);
check("within: nested", pathIsWithin("/a", "/a/b/c/d"), true);
check("within: sibling prefix", pathIsWithin("/a/b", "/a/bc"), false);
check("within: parent escape", pathIsWithin("/a/b", "/a"), false);
check("within: traversal escape", pathIsWithin("/a/b", "/a/b/../c"), false);
check("within: absolute traversal", pathIsWithin("/a", "/a/../../etc/passwd"), false);
check("within: relative target rejected", pathIsWithin("/a", "b/c"), false);
check("within: empty root rejected", pathIsWithin("", "/a"), false);

check("secret: .env", pathContainsSecret("/p/.env"), true);
check("secret: .env.production", pathContainsSecret("/p/.env.production"), true);
check("secret: id_rsa", pathContainsSecret("/home/u/.ssh/id_rsa"), true);
check("secret: nested .npmrc", pathContainsSecret("/home/u/.npmrc"), true);
check("secret: ordinary file", pathContainsSecret("/p/src/index.ts"), false);
check("secret: non-string", pathContainsSecret(42), false);

// ------------------------------------------------------------- policy engine

console.log("policy engine (compiled wasm)");

const engine = await PolicyEngine.load(WASM, { toolwall: { user_rules: [] } });

// Tool name, arguments and annotations are separate inputs — passing a bare
// `tool: "Read"` string would overwrite the tool object and silently match
// nothing (the policy would fail closed to default-deny for the wrong reason).
const call = (
	tool: string,
	args: Record<string, unknown> = {},
	annotations?: Record<string, boolean>,
	cwd = "/home/u/proj",
): CallInput => ({
	mode: "enforce",
	agent: { id: "test", cwd },
	tool: { name: tool, annotations },
	arguments: args,
});

type Case = [string, CallInput, DecisionEffect, string];

const cases: Case[] = [
	// default deny
	["unlisted tool with no arguments is denied", call("some_random_tool"), "deny", "default-deny"],
	// workspace allow
	["workspace path is allowed", call("Read", { path: "/home/u/proj/src/a.ts" }), "allow", "workspace-scoped"],
	// argument-level deny: the wedge
	[
		".env read denied despite being in workspace",
		call("Read", { path: "/home/u/proj/.env" }),
		"deny",
		"no-secret-reads",
	],
	[
		".env write denied too",
		call("mcp__fs__write_file", { path: "/home/u/proj/.env" }),
		"deny",
		"no-secret-reads",
	],
	// egress
	[
		"network argument denied",
		call("Bash", { command: "ls", network: "example.com" }),
		"deny",
		"no-egress",
	],
	// system paths
	["/etc denied", call("Read", { path: "/etc/shadow" }), "deny", "no-system-paths"],
	// precedence: deny must beat the workspace allow
	[
		"egress beats workspace allow",
		call("mcp__http__fetch", { path: "/home/u/proj/a", url: "https://x.com" }),
		"deny",
		"no-egress",
	],
	// path outside cwd is not "inside the workspace"
	[
		"path outside cwd is not allowed by the workspace rule",
		call("Read", { path: "/etc/hosts" }),
		"deny",
		"no-system-paths",
	],
];

for (const [label, input, wantEffect, wantRule] of cases) {
	const d = await engine.decide(input);
	check(label, d.effect, wantEffect);
	checkRule(label, d, wantRule);
}

// destructiveHint -> ask, via a user rule exercising annotations
const askEngine = await PolicyEngine.load(WASM, {
	toolwall: {
		user_rules: [
			{
				name: "ask-before-destructive",
				effect: "ask",
				tools: ["*"],
				destructive: true,
				reason: "tool is annotated destructiveHint",
			},
		],
	},
});
{
	const d = await askEngine.decide(
		call("mcp__db__drop", { path: "/home/u/proj/x" }, { destructiveHint: true }),
	);
	check("destructive annotation triggers ask", d.effect, "ask");
	checkRule("destructive annotation triggers ask", d, "ask-before-destructive");

	const safe = await askEngine.decide(
		call("Read", { path: "/home/u/proj/a.ts" }, { readOnlyHint: true }),
	);
	check("non-destructive is not asked", safe.effect, "allow");
}

// user rules can loosen a built-in rule by reusing its name
const loosenEngine = await PolicyEngine.load(WASM, {
	toolwall: {
		user_rules: [
			{ name: "workspace-scoped", effect: "allow", tools: ["*"], arg_path_prefix: "/tmp/" },
		],
	},
});
{
	const d = await loosenEngine.decide(call("Read", { path: "/tmp/x" }));
	check("user rule overrides built-in of same name", d.effect, "allow");
	checkRule("user rule overrides built-in of same name", d, "workspace-scoped");
}

// fail-closed: malformed input must deny, not throw
{
	const d = await engine.decide({ mode: "enforce", agent: {}, tool: { name: "Read" } as any, arguments: {} as any });
	check("missing fields fail closed", d.effect, "deny");
}

console.log("=".repeat(52));
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);