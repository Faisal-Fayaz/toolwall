/**
 * Approval flow tests: queue, grants, and how both adapters surface `ask`.
 *
 * The critical property is that a grant can only ever downgrade ask -> allow.
 * A grant that could turn a `deny` into an `allow` would be a hole in the whole
 * system, so that is asserted directly.
 *
 * Run: node --experimental-strip-types test/approval.test.ts
 */
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ApprovalQueue, requestId } from "../dist/approval/queue.js";
import { GrantStore, applyGrants, grantsPath } from "../dist/approval/grants.js";
import { homedir } from "node:os";
import { handleHook, type HookOptions } from "../dist/adapters/hooks/claude-code.js";
import { DecisionLog } from "../dist/decision-log/log.js";
import { PolicyEngine } from "../dist/engine/engine.js";
import type { CallInput, Decision } from "../dist/types.js";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const WASM = resolve(ROOT, ".build/policy.wasm");

let pass = 0,
	fail = 0;
const check = (label: string, got: unknown, want: unknown) => {
	const ok = JSON.stringify(got) === JSON.stringify(want);
	ok ? pass++ : fail++;
	if (!ok) console.log(`  MISS ${label}: want ${JSON.stringify(want)} got ${JSON.stringify(got)}`);
};

const workdir = mkdtempSync(join(tmpdir(), "toolwall-approval-"));
const call = (over: Partial<CallInput> = {}): CallInput => ({
	mode: "enforce",
	agent: { id: "test", cwd: workdir },
	tool: { name: "Bash" },
	arguments: { command: "npm test" },
	...over,
});
const askDecision: Decision = { effect: "ask", rule: "shell-needs-human", reason: "shell needs review" };
const denyDecision: Decision = { effect: "deny", rule: "no-force-push", reason: "no force push" };

// ------------------------------------------------------------------- queue

console.log("approval queue");

{
	const q = new ApprovalQueue(join(workdir, "q1.jsonl"));
	check("empty queue has no pending", q.pending().length, 0);

	const r = q.create(call(), askDecision, "proxy");
	check("create returns an id", typeof r.id === "string" && r.id.length > 0, true);
	check("create records a request", q.requests().length, 1);
	check("new request is pending", q.pending().length, 1);
	check("request captures the tool", q.requests()[0].tool, "Bash");
	check("request captures the rule", q.requests()[0].rule, "shell-needs-human");
	check("request records its source", q.requests()[0].source, "proxy");

	// idempotent: the same rule+args should not pile up duplicates
	q.create(call(), askDecision, "proxy");
	check("re-asking does not duplicate", q.requests().length, 1);

	q.resolve(r.id, "approved");
	check("resolved request is no longer pending", q.pending().length, 0);
	check("outcome is recorded", q.outcome(r.id)?.decision, "approved");

	// a denial also closes it
	const r2 = q.create(call({ arguments: { command: "ls" } }), askDecision, "hook");
	q.resolve(r2.id, "denied");
	check("denied request leaves the pending list", q.pending().length, 0);
	check("outcome survives re-read", new ApprovalQueue(join(workdir, "q1.jsonl")).outcome(r2.id)?.decision, "denied");
}

// ids are content-addressed, so the same request across machines lines up
check(
	"request id is deterministic",
	requestId(call(), "shell-needs-human"),
	requestId(call(), "shell-needs-human"),
);
check("id varies with rule", requestId(call(), "a") !== requestId(call(), "b"), true);

// ------------------------------------------------------------------ grants

console.log("grants");

{
	const store = new GrantStore(join(workdir, "g.json"));
	check("no grants initially", store.active().length, 0);

	const g = store.add("shell-needs-human", workdir, 60);
	check("grant is active", store.active().length, 1);
	check("grant has an expiry", typeof g.expiresAt === "string", true);

	// ask -> allow
	const granted = applyGrants(askDecision, call(), store);
	check("grant downgrades ask to allow", granted.effect, "allow");
	check("granted decision is labelled", granted.rule.includes("granted"), true);

	// THE invariant: a deny must survive a grant
	const stillDenied = applyGrants(denyDecision, call(), store);
	check("grant cannot downgrade a deny", stillDenied.effect, "deny");
	check("deny rule name is untouched", stillDenied.rule, "no-force-push");

	// a grant for a different rule does not apply
	const other = new GrantStore(join(workdir, "g2.json"));
	other.add("some-other-rule", workdir, 60);
	check("grant is scoped to its rule", applyGrants(askDecision, call(), other).effect, "ask");

	// scope enforcement
	const scoped = new GrantStore(join(workdir, "g3.json"));
	scoped.add("shell-needs-human", "/some/other/place", 60);
	check("grant does not leak across scopes", applyGrants(askDecision, call(), scoped).effect, "ask");

	// expiry
	const expired = new GrantStore(join(workdir, "g4.json"));
	expired.add("shell-needs-human", workdir, -1);
	check("expired grants are dropped", expired.active().length, 0);
	check("expired grant does not apply", applyGrants(askDecision, call(), expired).effect, "ask");

	check("ungrant removes", store.remove("shell-needs-human"), 1);
	check("ask returns after ungranting", applyGrants(askDecision, call(), store).effect, "ask");
}

// grants must not be silently written into a repo
{
	// separator-agnostic: this assertion must hold on Windows too
	check("grants live outside the project by default", /[\\/]\.toolwall[\\/]/.test(grantsPath()), true);
	check("default grants path is user-global", grantsPath().startsWith(homedir()), true);
}

// a grant scoped to a directory must not cover a sibling with a shared prefix
{
	const base = resolve(workdir, "proj");
	const scoped = new GrantStore(join(workdir, "g6.json"));
	scoped.add("shell-needs-human", base, 60);
	check(
		"grant does not cover a sibling with a shared prefix",
		applyGrants(askDecision, call({ agent: { id: "t", cwd: `${base}-leaked` } }), scoped).effect,
		"ask",
	);
	check(
		"grant does cover a subdirectory",
		applyGrants(askDecision, call({ agent: { id: "t", cwd: join(base, "sub") } }), scoped).effect,
		"allow",
	);
	check(
		"grant matches with a trailing separator on the call cwd",
		applyGrants(askDecision, call({ agent: { id: "t", cwd: `${join(base, "sub")}/` } }), scoped).effect,
		"allow",
	);
}

// ------------------------------------------------------- adapters and `ask`

console.log("adapters surface ask");

const engine = await PolicyEngine.load(WASM);

{
	const queue = new ApprovalQueue(join(workdir, "hook-approvals.jsonl"));
	const opts: HookOptions = {
		engine,
		log: new DecisionLog({ path: join(workdir, "hook-log.jsonl") }),
		queue,
		grants: new GrantStore(join(workdir, "hook-grants.json")),
		agent: { id: "claude-code", cwd: workdir },
	};

	// a Bash command that matches nothing escalates to `ask`
	const out = await handleHook(
		JSON.stringify({
			hook_event_name: "PreToolUse",
			tool_name: "Bash",
			tool_input: { command: "npm test" },
			cwd: workdir,
		}),
		opts,
	);
	const parsed = out ? JSON.parse(out).hookSpecificOutput : null;
	check("hook asks rather than passing through", parsed?.permissionDecision, "ask");
	check("hook reason names the rule", parsed?.permissionDecisionReason?.includes("shell-needs-human"), true);
	check("hook reason tells the user how to approve", /toolwall (approve|grant)/.test(parsed?.permissionDecisionReason ?? ""), true);
	check("hook recorded an approval request", queue.pending().length, 1);

	const req = queue.pending()[0];
	check("request id appears in the reason", parsed?.permissionDecisionReason?.includes(req.id), true);

	// deny still denies, and is not confused with ask
	const denied = JSON.parse(
		(await handleHook(
			JSON.stringify({
				hook_event_name: "PreToolUse",
				tool_name: "Bash",
				tool_input: { command: "git push --force origin main" },
				cwd: workdir,
			}),
			opts,
		)) ?? "{}",
	).hookSpecificOutput;
	check("force-push still denies", denied?.permissionDecision, "deny");

	// allow stays silent
	const allowed = await handleHook(
		JSON.stringify({
			hook_event_name: "PreToolUse",
			tool_name: "Read",
			tool_input: { file_path: join(workdir, "ok.md") },
			cwd: workdir,
		}),
		opts,
	);
	check("allow still passes through silently", allowed, null);

	// with a grant active, the ask disappears
	opts.grants!.add("shell-needs-human", workdir, 60);
	const granted = await handleHook(
		JSON.stringify({
			hook_event_name: "PreToolUse",
			tool_name: "Bash",
			tool_input: { command: "npm test" },
			cwd: workdir,
		}),
		opts,
	);
	check("granted ask no longer prompts", granted, null);
}

// ---------------------------------------------------- one-shot approval

console.log("one-shot approval");

{
	const store = new GrantStore(join(workdir, "oneshot.json"));
	const q = new ApprovalQueue(join(workdir, "oneshot-q.jsonl"));
	const req = q.create(call(), askDecision, "proxy");

	store.approveOnce(req, 10, "tester");

	// the exact call the human approved goes through
	check("approved call is allowed", applyGrants(askDecision, call(), store).effect, "allow");
	// ...and only once: a single-use grant is consumed on match
	check("approval is spent after one use", applyGrants(askDecision, call(), store).effect, "ask");

	// a different command is NOT covered, even by the same rule
	const other = call({ arguments: { command: "yarn build" } });
	check("approval does not cover a different call", applyGrants(askDecision, other, store).effect, "ask");

	// a grant from a different rule cannot unlock this one
	const q2 = new ApprovalQueue(join(workdir, "oneshot-q2.jsonl"));
	const req2 = q2.create(call(), { ...askDecision, rule: "some-other-rule" }, "proxy");
	store.approveOnce(req2, 10, "tester");
	check("approval for rule A does not unlock rule B", applyGrants(askDecision, call(), store).effect, "ask");

	// one-shot approval still cannot touch a deny
	const q3 = new ApprovalQueue(join(workdir, "oneshot-q3.jsonl"));
	const req3 = q3.create(call(), denyDecision, "proxy");
	store.approveOnce(req3, 10, "tester");
	check("one-shot approval cannot unlock a deny", applyGrants(denyDecision, call(), store).effect, "deny");

	// expiry
	const q4 = new ApprovalQueue(join(workdir, "oneshot-q4.jsonl"));
	const req4 = q4.create(call(), askDecision, "proxy");
	store.approveOnce(req4, -1, "tester");
	check("expired one-shot approval does nothing", applyGrants(askDecision, call(), store).effect, "ask");
}

// ------------------------------------------------- persistence + hygiene

console.log("persistence");

{
	check("queue file written with 0600", existsSync(join(workdir, "hook-approvals.jsonl")), true);
	const raw = readFileSync(join(workdir, "hook-approvals.jsonl"), "utf8");
	check("queue is JSONL", raw.trim().split("\n").every((l) => l.startsWith("{")), true);
}

rmSync(workdir, { recursive: true, force: true });

console.log("=".repeat(52));
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);