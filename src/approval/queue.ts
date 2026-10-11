/**
 * Approval requests for `ask` decisions.
 *
 * When a rule resolves to `ask`, toolwall records a request and lets the host
 * agent put the question to a human. The request store exists so the answer is
 * auditable and so `toolwall pending` can show what is outstanding from a
 * terminal — an agent that asks is much more useful if a human can see the
 * backlog.
 *
 * Requests are appended (JSONL) rather than mutated in place, so a crash never
 * loses history. Resolution writes a separate resolution record.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname } from "node:path";

import type { CallInput, Decision } from "../types.js";

export interface ApprovalRequest {
	id: string;
	ts: string;
	rule: string;
	reason: string;
	tool: string;
	/** Redacted arguments — the log path is the same redaction used for decisions. */
	arguments: Record<string, unknown>;
	cwd?: string;
	session?: string;
	/** Where it came from: which adapter is asking. */
	source: "hook" | "proxy";
}

export interface Resolution {
	id: string;
	ts: string;
	decision: "approved" | "denied";
	by?: string;
	note?: string;
}

export type QueueEntry =
	| { kind: "request"; request: ApprovalRequest }
	| { kind: "resolution"; resolution: Resolution };

export function queuePath(cwd: string): string {
	return `${cwd}/.toolwall/approvals.jsonl`;
}

/** Stable, short, content-addressed id — no clock or randomness needed. */
export function requestId(call: CallInput, rule: string): string {
	const material = JSON.stringify([rule, call.tool.name, call.arguments ?? {}, call.agent?.cwd ?? ""]);
	return createHash("sha256").update(material).digest("hex").slice(0, 12);
}

export class ApprovalQueue {
	readonly path: string;

	constructor(path: string) {
		this.path = path;
		const dir = dirname(path);
		if (dir && dir !== ".") mkdirSync(dir, { recursive: true });
	}

	/** Record a request. Idempotent by id: asking twice does not duplicate. */
	create(call: CallInput, decision: Decision, source: ApprovalRequest["source"]): ApprovalRequest {
		const id = requestId(call, decision.rule);
		const prior = this.requests().find((r) => r.id === id);
		if (prior) return prior;

		const request: ApprovalRequest = {
			id,
			ts: new Date().toISOString(),
			rule: decision.rule,
			reason: decision.reason,
			tool: call.tool.name,
			arguments: call.arguments ?? {},
			cwd: call.agent?.cwd,
			session: call.agent?.session,
			source,
		};
		this.#append({ kind: "request", request });
		return request;
	}

	/** Every request, oldest first. */
	requests(): ApprovalRequest[] {
		return this.entries()
			.filter((e): e is { kind: "request"; request: ApprovalRequest } => e.kind === "request")
			.map((e) => e.request);
	}

	/** Requests with no resolution after them. */
	pending(): ApprovalRequest[] {
		const done = new Set(this.resolutions().map((r) => r.id));
		return this.requests().filter((r) => !done.has(r.id));
	}

	resolutions(): Resolution[] {
		return this.entries()
			.filter((e): e is { kind: "resolution"; resolution: Resolution } => e.kind === "resolution")
			.map((e) => e.resolution);
	}

	resolve(id: string, decision: Resolution["decision"], by?: string, note?: string): Resolution {
		const resolution: Resolution = { id, ts: new Date().toISOString(), decision, by, note };
		this.#append({ kind: "resolution", resolution });
		return resolution;
	}

	/** Latest resolution for an id, if any. */
	outcome(id: string): Resolution | undefined {
		return this.resolutions()
			.filter((r) => r.id === id)
			.sort((a, b) => a.ts.localeCompare(b.ts))
			.pop();
	}

	#append(entry: QueueEntry): void {
		appendFileSync(this.path, `${JSON.stringify(entry)}\n`, { encoding: "utf8", mode: 0o600 });
	}

	private entries(): QueueEntry[] {
		if (!existsSync(this.path)) return [];
		return readFileSync(this.path, "utf8")
			.split("\n")
			.map((l) => l.trim())
			.filter(Boolean)
			.map((l) => {
				try {
					return JSON.parse(l) as QueueEntry;
				} catch {
					return null;
				}
			})
			.filter((e): e is QueueEntry => e !== null);
	}
}

/** Short one-line description for terminal output. */
export function describeRequest(r: ApprovalRequest): string {
	const when = r.ts.replace("T", " ").slice(0, 19);
	return `${r.id}  ${when}  ${r.tool}  [${r.rule}]`;
}