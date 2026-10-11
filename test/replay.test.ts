/**
 * Replay tests.
 *
 * The bug these exist to prevent: replay re-evaluated without loading grants,
 * so every call that had been allowed by a grant looked like a policy change.
 * That reported false drift on exactly the calls a human had already approved,
 * which is the fastest way to make someone stop trusting the feature.
 *
 * Run: node --experimental-strip-types test/replay.test.ts
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { GrantStore, applyGrants } from "../dist/approval/grants.js";
import { DecisionLog } from "../dist/decision-log/log.js";
import { PolicyEngine } from "../dist/engine/engine.js";
import type { CallInput, DecisionRecord } from "../dist/types.js";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const CLI = resolve(ROOT, "dist/cli.js");
const WASM = resolve(ROOT, ".build/policy.wasm");

let pass = 0,
	fail = 0;
const check = (label: string, got: unknown, want: unknown) => {
	const ok = JSON.stringify(got) === JSON.stringify(want);
	ok ? pass++ : fail++;
	if (!ok) console.log(`  MISS ${label}: want ${JSON.stringify(want)} got ${JSON.stringify(got)}`);
};

const workdir = mkdtempSync(join(tmpdir(), "toolwall-replay-"));
const grantsFile = join(workdir, "grants.json");
process.env.TOOLWALL_GRANTS = grantsFile;

const engine = await PolicyEngine.load(WASM);

/** Log one call the way the adapters would, optionally through a grant. */
async function record(
	tool: string,
	args: Record<string, unknown>,
	opts: { grant?: string } = {},
): Promise<DecisionRecord> {
	const log = new DecisionLog({ path: join(workdir, "decisions.jsonl") });
	const call: CallInput = {
		mode: "enforce",
		agent: { id: "test", cwd: workdir },
		tool: { name: tool },
		arguments: args,
	};
	let decision = await engine.decide(call);
	if (opts.grant) decision = applyGrants(decision, call, new GrantStore(grantsFile));
	const rec: DecisionRecord = {
		ts: new Date().toISOString(),
		...decision,
		agent: call.agent,
		tool: call.tool,
		arguments: args,
	};
	log.append(rec);
	return rec;
}

function replay(logName: string, extra: string[] = []) {
	try {
		const stdout = execFileSync(
			process.execPath,
			[CLI, "replay", "--against", join(workdir, logName), "--policy", WASM, ...extra],
			{ encoding: "utf8", cwd: workdir },
		);
		return { stdout, code: 0 };
	} catch (err: any) {
		return { stdout: err.stdout ?? "", code: err.status ?? 1 };
	}
}

// ------------------------------------------------- granted calls are not drift

console.log("granted calls are not policy drift");

{
	const store = new GrantStore(grantsFile);
	store.add("shell-needs-human", workdir, 30, { by: "tester" });

	const granted = await record("Bash", { command: "npm test" }, { grant: "shell-needs-human" });
	check("runtime allowed it via the grant", granted.effect, "allow");
	check("granted record is labelled", granted.rule.endsWith("(granted)"), true);

	const r = replay("decisions.jsonl");
	check("replay reports no policy change", r.stdout.includes("policy changes: 0"), true);
	check("replay does not call it newly blocked", r.stdout.includes("NEWLY BLOCKED"), false);
	check("replay flags it as grant-dependent", r.stdout.includes("GRANT-DEPENDENT"), true);
	check("replay separates policy-alone tally", r.stdout.includes("policy alone:"), true);
	check("replay shows the with-grants tally", r.stdout.includes("with grants:"), true);
	check("grant drift does not fail the run", r.code, 0);
}

// ------------------------------------------------------- plain drift still seen

console.log("genuine policy changes are still reported");

{
	// no grant in play: the same call asks again
	await record("Bash", { command: "yarn build" });
	const r = replay("decisions.jsonl");
	// the granted-allow record is still grant-dependent, not drift
	check("grant-dependent still separated", r.stdout.includes("GRANT-DEPENDENT"), true);
	check("no false newly-blocked", r.stdout.includes("NEWLY BLOCKED"), false);
}

// ------------------------------------------------------ --no-grants isolation

console.log("--no-grants evaluates the policy alone");

{
	const r = replay("decisions.jsonl", ["--no-grants"]);
	check("--no-grants omits the grants tally", r.stdout.includes("with grants:"), false);
	check("--no-grants still reports policy alone", r.stdout.includes("policy alone:"), true);
}

// ------------------------------------------------------------- tighten check

console.log("tightening a policy still breaks the build");

{
	const { mkdirSync, writeFileSync } = await import("node:fs");
	const logPath = join(workdir, "tight.jsonl");
	const log = new DecisionLog({ path: logPath });
	const call: CallInput = {
		mode: "enforce",
		agent: { id: "test", cwd: workdir },
		tool: { name: "Read" },
		arguments: { path: join(workdir, "notes.md") },
	};
	// recorded as an ordinary allow, NOT via a grant
	const d = await engine.decide(call);
	check("baseline allows the read", d.effect, "allow");
	log.append({
		ts: new Date().toISOString(),
		...d,
		agent: call.agent,
		tool: call.tool,
		arguments: call.arguments,
	});

	// now tighten: deny every Bash
	mkdirSync(join(workdir, ".firewall"), { recursive: true });
	writeFileSync(
		join(workdir, ".firewall/policy.json"),
		JSON.stringify({ rules: [{ name: "deny-reads", effect: "deny", tools: ["Read"], reason: "tightened" }] }),
	);

	const r = replay("tight.jsonl");
	check("tightening is reported as newly blocked", r.stdout.includes("NEWLY BLOCKED"), true);
	check("names the tightening rule", r.stdout.includes("deny-reads"), true);
	check("a real block fails the run (CI gate)", r.code, 1);
}

rmSync(workdir, { recursive: true, force: true });

console.log("=".repeat(52));
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);