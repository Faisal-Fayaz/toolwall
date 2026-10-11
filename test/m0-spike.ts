/**
 * M0 spike: de-risk the Rego/Wasm path before building anything.
 *
 * Test 1 (GO/NO-GO): does a policy.wasm compiled by OPA CLI 1.21.1 load in the
 *                    opa-wasm@1.10.0 Node runtime? (version skew)
 * Test 2: per-call eval latency
 * Test 3: recompile time on policy edit
 *
 * opa-wasm@1.10 API notes (differ from older docs):
 *   - custom builtins are a map passed as 3rd arg to loadPolicy()
 *   - builtin impl receives spread positional args, returns a JSON-able value
 *   - evaluate(input) hits the baked-in entrypoint; no setInput/eval(query)
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { loadPolicy } = require("@open-policy-agent/opa-wasm");

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const SPIKE_WASM = process.env.TOOLWALL_SPIKE_WASM ?? resolve(ROOT, ".build/m0/policy.wasm");

const results: { test: string; pass: boolean; detail: string }[] = [];
const record = (test: string, pass: boolean, detail: string) => {
	results.push({ test, pass, detail });
	console.log(`${pass ? "PASS" : "FAIL"}  ${test}\n      ${detail}`);
};

// ---------- host builtins (the part we own) ----------

const SECRET_RE =
	/(^|[\\/])(\.env(\.[a-z]+)?|id_rsa|id_ed25519|\.npmrc|\.netrc|credentials|\.aws[\\/]credentials|\.git-credentials)$/i;

const norm = (p: string) => p.replace(/\/+$/, "");

const customBuiltins: Record<string, Function> = {
	path_is_within: (root: string, target: string) => {
		if (typeof root !== "string" || typeof target !== "string") return false;
		const r = norm(root);
		const t = norm(target);
		return t === r || t.startsWith(`${r}/`);
	},
	path_contains_secret: (value: unknown) =>
		typeof value === "string" ? SECRET_RE.test(value) : false,
	redact: (_value: unknown) => "[redacted]",
};

// ---------- test 1: ABI load + correctness ----------

async function testAbi() {
	const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const WASM = process.env.TOOLWALL_SPIKE_WASM ?? resolve(ROOT, ".build/m0/policy.wasm");
const bytes = readFileSync(WASM);
	let policy: any;
	try {
		policy = await loadPolicy(bytes, { initial: 10 }, customBuiltins);
	} catch (err: any) {
		record("T1 ABI: load 1.21.1-compiled wasm in runtime 1.10.0", false, String(err));
		return null;
	}

	record(
		"T1 ABI: load + host builtins",
		true,
		`wasm compiled by CLI 1.21.1 accepted by runtime 1.10.0 (wasm ABI minor ${policy.minorVersion})`,
	);

	// Assert on WHICH rule fired, not just the effect: a never-firing rule
	// still yields the right effect via `default decision`, which would mask
	// the bug entirely. This caught a real bug during the M0 spike.
	const cases: Array<[string, any, string, string]> = [
		[
			"deny .env read (argument-level)",
			{ agent: { cwd: "/home/x/proj" }, tool: { name: "mcp__fs__read_file" }, arguments: { path: "/home/x/proj/.env" } },
			"deny",
			"no-secret-reads",
		],
		[
			"allow workspace read",
			{ agent: { cwd: "/home/x/proj" }, tool: { name: "Read" }, arguments: { path: "/home/x/proj/src/index.ts" } },
			"allow",
			"workspace-reads",
		],
		[
			"deny network via argument key presence",
			{ agent: { cwd: "/home/x/proj" }, tool: { name: "Bash" }, arguments: { command: "ls", network: "api.example.com" } },
			"deny",
			"no-network",
		],
		[
			"precedence: .env under workspace denies over allow",
			{ agent: { cwd: "/home/x/proj" }, tool: { name: "Read" }, arguments: { path: "/home/x/proj/.env" } },
			"deny",
			"no-secret-reads",
		],
		[
			"default deny (no rule matched)",
			{ agent: { cwd: "/home/x/proj" }, tool: { name: "SomeUnknownTool" }, arguments: {} },
			"deny",
			"default",
		],
	];

	let ok = 0;
	for (const [label, input, expected, expectedRule] of cases) {
		try {
			// evaluate() returns an array of result-sets: [{ result: <value> }]
			const raw = await policy.evaluate(input);
			const out = Array.isArray(raw) ? raw[0]?.result : raw?.result ?? raw;
			const got = out?.effect;
			const gotRule = out?.rule;
			const pass = got === expected && gotRule === expectedRule;
			if (pass) ok++;
			console.log(
				`      ${pass ? "ok  " : "MISS"} ${label}: ` +
					`expected=${expected}/${expectedRule} got=${got}/${gotRule}`,
			);
		} catch (err: any) {
			console.log(`      ERR  ${label}: ${String(err)}`);
		}
	}
	record("T1 ABI: argument-level decisions correct", ok === cases.length, `${ok}/${cases.length} cases matched`);
	return policy;
}

// ---------- test 2: eval latency ----------

async function testLatency(policy: any) {
	const input = {
		agent: { cwd: "/home/x/proj" },
		tool: { name: "mcp__fs__read_file" },
		arguments: { path: "/home/x/proj/src/index.ts" },
	};
	await policy.evaluate(input); // warm

	const N = 1000;
	const t0 = process.hrtime.bigint();
	for (let i = 0; i < N; i++) await policy.evaluate(input);
	const perCall = Number(process.hrtime.bigint() - t0) / 1e6 / N;
	record("T2 latency", perCall < 5, `${perCall.toFixed(3)} ms/call over ${N} evals`);
}

// ---------- test 3: recompile on policy edit ----------

async function testRecompile() {
	const { execFileSync } = await import("node:child_process");
	const run = () => {
		const t0 = process.hrtime.bigint();
		execFileSync(resolve(ROOT, "bin/opa"), [
			"build", "-t", "wasm",
			"--capabilities", resolve(ROOT, "policy/capabilities.json"),
			"-e", "firewall/decision",
			"-o", resolve(ROOT, ".build/m0/recompile.tar.gz"),
			resolve(ROOT, "test/fixtures/spike.rego"),
		]);
		return Number(process.hrtime.bigint() - t0) / 1e6;
	};
	const ms = run();
	record("T3 recompile", ms < 300, `${ms.toFixed(0)} ms to recompile policy to wasm`);
}

// ---------- run ----------

console.log("M0 SPIKE — toolwall\n" + "=".repeat(52));
const policy = await testAbi();
if (policy) {
	await testLatency(policy);
	await testRecompile();
} else {
	console.log("\nT1 failed — downstream tests skipped.");
}

console.log("=".repeat(52));
const failed = results.filter((r) => !r.pass);
console.log(failed.length === 0 ? "ALL PASS" : `GO/NO-GO: NO (${failed.length} failed)`);
process.exit(failed.length === 0 ? 0 : 1);