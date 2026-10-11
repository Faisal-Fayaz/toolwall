/**
 * Append-only decision log (JSONL), bounded by rotation.
 *
 * Every gated call is written here regardless of outcome — that record is what
 * makes `toolwall replay` possible, which is the point: you can evaluate a
 * candidate policy against real history instead of guessing.
 *
 * Two properties that matter:
 *
 *   - Arguments are redacted at WRITE time, not read time, so secrets never
 *     land on disk in the first place. The log is deliberately lossy.
 *   - The log is BOUNDED. `truncate` caps a single record, but without
 *     rotation an agent session produces an unbounded file and replay pulls
 *     all of it into memory.
 *
 * Rotation is size-based and keeps N previous generations, so `replay` can read
 * a recent window without touching older files.
 */

import {
	appendFileSync,
	createReadStream,
	existsSync,
	mkdirSync,
	renameSync,
	rmSync,
	statSync,
} from "node:fs";
import { dirname } from "node:path";
import { createInterface } from "node:readline";

import { redact } from "../engine/host-builtins.js";
import type { DecisionRecord } from "../types.js";

export interface LogOptions {
	/** Absolute or relative path to the .jsonl file. */
	path: string;
	/** Max arguments retained per record, to bound log growth. */
	maxArgBytes?: number;
	/** Rotate once the file exceeds this many bytes. 0 disables rotation. */
	maxBytes?: number;
	/** How many rotated generations to keep alongside the live file. */
	keep?: number;
}

const DEFAULT_MAX_ARG_BYTES = 4096;
/** 10 MB. A busy agent session makes a few hundred KB; this is generous. */
const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;
export const DEFAULT_KEEP = 3;

export class DecisionLog {
	readonly path: string;
	readonly #maxArgBytes: number;
	readonly #maxBytes: number;
	readonly #keep: number;

	constructor(opts: LogOptions) {
		this.path = opts.path;
		this.#maxArgBytes = opts.maxArgBytes ?? DEFAULT_MAX_ARG_BYTES;
		this.#maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
		this.#keep = opts.keep ?? DEFAULT_KEEP;
		const dir = dirname(this.path);
		if (dir && dir !== ".") mkdirSync(dir, { recursive: true });
	}

	/** Rotated generation N, oldest first: `path.1` is newest, `.keep` oldest. */
	rotatedPath(n: number): string {
		return `${this.path}.${n}`;
	}

	/** Append one decision. Redacts and rotates before serializing. */
	append(record: DecisionRecord): void {
		const safe: DecisionRecord = {
			...record,
			arguments: truncate(redact(record.arguments) as Record<string, unknown>, this.#maxArgBytes),
		};
		this.#rotateIfNeeded();
		appendFileSync(this.path, `${JSON.stringify(safe)}\n`, { encoding: "utf8", mode: 0o600 });
	}

	/**
	 * Shift generations down and start a fresh live file.
	 *
	 * `.1` is always the most recent rotation, so a reader wanting "recent
	 * history" reads .1, .2, ... backwards and stops at the one that does not
	 * exist. That keeps replay simple without a manifest.
	 */
	#rotateIfNeeded(): void {
		if (this.#maxBytes <= 0 || !existsSync(this.path)) return;
		let size = 0;
		try {
			size = statSync(this.path).size;
		} catch {
			return;
		}
		if (size < this.#maxBytes) return;

		try {
			// drop the oldest, then shift each generation down one slot
			rmSync(this.rotatedPath(this.#keep), { force: true });
			for (let n = this.#keep - 1; n >= 1; n--) {
				if (existsSync(this.rotatedPath(n))) renameSync(this.rotatedPath(n), this.rotatedPath(n + 1));
			}
			renameSync(this.path, this.rotatedPath(1));
		} catch {
			// A failed rotation must not block the agent's call. An unbounded
			// log is a lesser problem than a crashed proxy.
		}
	}

	/** Files to read for a window of recent history, newest first. */
	readOrder(): string[] {
		const files: string[] = [];
		if (existsSync(this.path)) files.push(this.path);
		for (let n = 1; n <= this.#keep; n++) {
			const p = this.rotatedPath(n);
			if (existsSync(p)) files.push(p);
		}
		return files;
	}

	/** Total bytes across the live file and retained rotations. */
	totalBytes(): number {
		return this.readOrder().reduce((sum, p) => {
			try {
				return sum + statSync(p).size;
			} catch {
				return sum;
			}
		}, 0);
	}
}

/** Yield records without holding the whole file in memory. */
export async function* streamLog(path: string): AsyncGenerator<DecisionRecord> {
	if (!existsSync(path)) return;
	const rl = createInterface({ input: createReadStream(path, { encoding: "utf8" }), crlfDelay: Infinity });
	try {
		for await (const line of rl) {
			const trimmed = line.trim();
			if (!trimmed) continue;
			try {
				yield JSON.parse(trimmed) as DecisionRecord;
			} catch {
				// A truncated final line from a killed process must not break
				// replay of everything else.
			}
		}
	} finally {
		rl.close();
	}
}

/** Read a log file into memory. Prefer `streamLog` for large logs. */
export async function readLog(path: string): Promise<DecisionRecord[]> {
	const out: DecisionRecord[] = [];
	for await (const rec of streamLog(path)) out.push(rec);
	return out;
}

/**
 * Read a window of recent history across rotations, newest first.
 * `limit` bounds how many records are materialised.
 *
 * Each file is appended chronologically, so it is reversed before being
 * appended to the window. Without that the result is only newest-first WITHIN
 * a file, and concatenating live + .1 + .2 produces an order that jumps
 * backwards in time at every rotation boundary.
 */
export async function readRecent(
	log: DecisionLog,
	limit = Number.POSITIVE_INFINITY,
): Promise<DecisionRecord[]> {
	const out: DecisionRecord[] = [];
	for (const path of log.readOrder()) {
		const chunk: DecisionRecord[] = [];
		for await (const rec of streamLog(path)) chunk.push(rec);
		chunk.reverse();
		for (const rec of chunk) {
			out.push(rec);
			if (out.length >= limit) return out;
		}
	}
	return out;
}

/** Keep the head of a value's JSON if it exceeds the budget. */
function truncate(value: Record<string, unknown>, maxBytes: number): Record<string, unknown> {
	let json: string;
	try {
		json = JSON.stringify(value);
	} catch {
		return { _unserializable: true };
	}
	if (json.length <= maxBytes) return value;
	// Preserve keys so rules can still see what fields existed, but drop values.
	const keys = Object.keys(value);
	return { _truncated: true, _bytes: json.length, _keys: keys };
}