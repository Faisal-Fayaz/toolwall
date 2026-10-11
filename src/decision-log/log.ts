/**
 * Append-only decision log (JSONL).
 *
 * Every gated call is written here regardless of outcome — that record is what
 * makes `toolwall replay` possible, which is the point: you can evaluate a
 * candidate policy against real history instead of guessing.
 *
 * Arguments are redacted at WRITE time, not read time, so secrets never land on
 * disk in the first place. The log is deliberately lossy.
 */

import { appendFileSync, createReadStream, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { createInterface } from "node:readline";

import { redact } from "../engine/host-builtins.js";
import type { DecisionRecord } from "../types.js";

export interface LogOptions {
	/** Absolute or relative path to the .jsonl file. */
	path: string;
	/** Max arguments retained per record, to bound log growth. */
	maxArgBytes?: number;
}

const DEFAULT_MAX_ARG_BYTES = 4096;

export class DecisionLog {
	readonly path: string;
	readonly #maxArgBytes: number;

	constructor(opts: LogOptions) {
		this.path = opts.path;
		this.#maxArgBytes = opts.maxArgBytes ?? DEFAULT_MAX_ARG_BYTES;
		const dir = dirname(this.path);
		if (dir && dir !== ".") mkdirSync(dir, { recursive: true });
	}

	/** Append one decision. Redacts before serializing. */
	append(record: DecisionRecord): void {
		const safe: DecisionRecord = {
			...record,
			arguments: truncate(redact(record.arguments) as Record<string, unknown>, this.#maxArgBytes),
		};
		appendFileSync(this.path, `${JSON.stringify(safe)}\n`, { encoding: "utf8", mode: 0o600 });
	}
}

/** Read a log file. Malformed lines are skipped, not fatal — a truncated final
 * line from a killed process should not break replay of everything else. */
export async function readLog(path: string): Promise<DecisionRecord[]> {
	if (!existsSync(path)) return [];
	const out: DecisionRecord[] = [];
	const rl = createInterface({ input: createReadStream(path, { encoding: "utf8" }), crlfDelay: Infinity });
	for await (const line of rl) {
		const trimmed = line.trim();
		if (!trimmed) continue;
		try {
			out.push(JSON.parse(trimmed) as DecisionRecord);
		} catch {
			// skip malformed
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