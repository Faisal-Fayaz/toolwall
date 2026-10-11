/**
 * Log rotation and streaming reads.
 *
 * Rotation is invisible when it works, which is exactly when it is worth
 * testing: the failure mode is an unbounded file filling the disk, and it only
 * shows up at the boundary.
 *
 * Run: node --experimental-strip-types test/log.test.ts
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { DecisionLog, readLog, readRecent, streamLog, DEFAULT_KEEP } from "../dist/decision-log/log.js";
import type { DecisionRecord } from "../dist/types.js";

let pass = 0,
	fail = 0;
const check = (label: string, got: unknown, want: unknown) => {
	const ok = JSON.stringify(got) === JSON.stringify(want);
	ok ? pass++ : fail++;
	if (!ok) console.log(`  MISS ${label}: want ${JSON.stringify(want)} got=${JSON.stringify(got)}`);
};

const workdir = mkdtempSync(join(tmpdir(), "toolwall-log-"));

const rec = (n: number): DecisionRecord => ({
	ts: new Date(1700000000000 + n).toISOString(),
	effect: "allow",
	rule: "workspace-scoped",
	reason: "",
	agent: { id: "t", cwd: workdir },
	tool: { name: "Read" },
	arguments: { n },
	evalMs: 0.1,
});

const ids = (rs: DecisionRecord[]) => rs.map((r) => (r.arguments as any).n);

// ---------------------------------------------------------------- writing

console.log("append + redact");

{
	const p = join(workdir, "basic.jsonl");
	const log = new DecisionLog({ path: p });
	log.append(rec(1));
	log.append(rec(2));

	const lines = readFileSync(p, "utf8").trim().split("\n");
	check("one line per record", lines.length, 2);
	check("valid JSONL", lines.every((l) => l.startsWith("{")), true);
	check("records read back", (await readLog(p)).length, 2);

	// redaction still happens at write time
	log.append({ ...rec(3), arguments: { password: "hunter2-hunter2", path: "/a" } });
	const raw = readFileSync(p, "utf8");
	check("secret value not on disk", raw.includes("hunter2-hunter2"), false);
	check("key preserved for rules", raw.includes("password"), true);
}

// ---------------------------------------------------------------- rotation

console.log("rotation");

{
	const p = join(workdir, "rot.jsonl");
	const log = new DecisionLog({ path: p, maxBytes: 400, keep: 2 });

	for (let i = 1; i <= 12; i++) log.append(rec(i));

	check("live file stays bounded", existsSync(p), true);
	const live = statSize(p);
	check("live file under the cap", live <= 400 + 200, true); // +slack for the record that triggered it
	check("generations exist", existsSync(`${p}.1`), true);
	check("generation count respected", existsSync(`${p}.3`), false);

	// readOrder is newest-first: live, then .1, .2
	const order = log.readOrder();
	check("read order starts with the live file", order[0], p);
	check("then the newest rotation", order[1], `${p}.1`);
	check("total bytes accounted", log.totalBytes() > 0, true);
}

{
	// rotation must not lose the most recent records
	const p = join(workdir, "recent.jsonl");
	const log = new DecisionLog({ path: p, maxBytes: 300, keep: 3 });
	for (let i = 1; i <= 15; i++) log.append(rec(i));

	const window = await readRecent(log);
	check("window is non-empty", window.length > 0, true);
	// the window is globally newest-first, across rotation boundaries
	check("newest record comes first", ids(window)[0], 15);
	const times = window.map((r) => r.ts);
	check(
		"window is in descending time order",
		times.every((t, i) => i === 0 || times[i - 1]! >= t),
		true,
	);

	// the limit must bound memory, not silently return everything
	const limited = await readRecent(log, 5);
	check("limit honoured", limited.length, 5);
	// newest-first, so the newest record is at the head of the window
	check("limit keeps the newest", ids(limited)[0], 15);
}

{
	// rotation disabled by default? no — default is 10MB, so a small log never rotates
	const p = join(workdir, "small.jsonl");
	const log = new DecisionLog({ path: p });
	for (let i = 0; i < 50; i++) log.append(rec(i));
	check("small log does not rotate", existsSync(`${p}.1`), false);
	check("all records present", (await readLog(p)).length, 50);
}

{
	// explicitly disabling rotation
	const p = join(workdir, "norot.jsonl");
	const log = new DecisionLog({ path: p, maxBytes: 0 });
	for (let i = 0; i < 200; i++) log.append(rec(i));
	check("rotation disabled by 0", existsSync(`${p}.1`), false);
	check("no truncation when disabled", (await readLog(p)).length, 200);
}

// -------------------------------------------------------------- streaming

console.log("streaming");

{
	const p = join(workdir, "stream.jsonl");
	writeFileSync(p, `${JSON.stringify(rec(1))}\nnot json at all\n\n${JSON.stringify(rec(2))}\n`);
	const seen: number[] = [];
	for await (const r of streamLog(p)) seen.push((r.arguments as any).n);
	check("malformed lines skipped, good ones kept", seen, [1, 2]);
}

{
	// a truncated final line (killed process) must not break replay
	const p = join(workdir, "trunc.jsonl");
	writeFileSync(p, `${JSON.stringify(rec(1))}\n{"ts":"2023-0`);
	const seen: number[] = [];
	for await (const r of streamLog(p)) seen.push((r.arguments as any).n);
	check("truncated tail tolerated", seen, [1]);
}

{
	// missing file is empty, not an error
	const seen: number[] = [];
	for await (const r of streamLog(join(workdir, "nope.jsonl"))) seen.push(1);
	check("missing file yields nothing", seen, []);
}

// ------------------------------------------------------------- truncation

console.log("record truncation");

{
	const p = join(workdir, "trunc2.jsonl");
	const log = new DecisionLog({ path: p, maxArgBytes: 64 });
	log.append(rec(1));
	log.append({ ...rec(2), arguments: { big: "x".repeat(500) } });

	const back = await readLog(p);
	const big = back[1]!.arguments as any;
	check("oversized record truncated", big._truncated, true);
	check("keys preserved on truncation", Array.isArray(big._keys) && big._keys.includes("big"), true);
	check("value dropped", big.big, undefined);
	check("small record untouched", (back[0]!.arguments as any).n, 1);
}

rmSync(workdir, { recursive: true, force: true });

console.log("=".repeat(52));
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);

function statSize(p: string): number {
	return statSync(p).size;
}

void DEFAULT_KEEP;