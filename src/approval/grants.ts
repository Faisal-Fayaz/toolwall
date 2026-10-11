/**
 * Time-boxed grants: "stop asking me about this rule for the next hour".
 *
 * Approving the same `ask` on every single call is how approval fatigue starts,
 * and an approval prompt that is always ignored is worse than none. A grant is
 * the escape hatch, and it is deliberately narrow:
 *
 *   - always time-boxed (a grant with no expiry is a permanent hole)
 *   - scoped to a rule name, never to a tool or an effect
 *   - recorded to the decision log so replay can account for it
 *
 * Grants only ever downgrade `ask` -> `allow`. They can NEVER turn a `deny`
 * into an `allow`; a deny is a policy statement, not a prompt.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

import type { CallInput, Decision } from "../types.js";

export interface Grant {
	rule: string;
	/** Directory the grant applies to; `"*"` means anywhere. */
	scope: string;
	/** ISO expiry. Always present — see the module note. */
	expiresAt: string;
	grantedAt: string;
	/** Restrict to one tool name. */
	tool?: string;
	/**
	 * Restrict to one exact call — the approval-request id, which is a hash of
	 * (rule, tool, arguments, cwd). This is what makes `toolwall approve`
	 * authorize the specific call a human actually looked at.
	 */
	fingerprint?: string;
	/** Consume on first match, so an approval lasts for exactly one retry. */
	singleUse?: boolean;
	/** The approval request this grant came from, for traceability. */
	requestId?: string;
	by?: string;
	note?: string;
}

export const DEFAULT_TTL_MINUTES = 60;
/** A one-shot approval is deliberately short-lived. */
export const ONE_SHOT_TTL_MINUTES = 10;

/** Grants are user-global; they are not committed to a repo. */
export function grantsPath(): string {
	return process.env.TOOLWALL_GRANTS ?? join(homedir(), ".toolwall", "grants.json");
}

export class GrantStore {
	readonly path: string;

	constructor(path: string = grantsPath()) {
		this.path = path;
	}

	read(): Grant[] {
		if (!existsSync(this.path)) return [];
		try {
			const parsed = JSON.parse(readFileSync(this.path, "utf8"));
			return Array.isArray(parsed) ? (parsed as Grant[]) : [];
		} catch {
			return [];
		}
	}

	write(grants: Grant[]): void {
		const dir = dirname(this.path);
		if (dir && dir !== ".") mkdirSync(dir, { recursive: true });
		writeFileSync(this.path, `${JSON.stringify(grants, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
	}

	/** Add or replace a grant for (rule, scope), or for fingerprint when given. */
	add(rule: string, scope: string, minutes: number, extra: Partial<Grant> = {}): Grant {
		const now = new Date();
		const grant: Grant = {
			rule,
			scope: scope === "*" ? "*" : normalisePath(scope),
			grantedAt: now.toISOString(),
			expiresAt: new Date(now.getTime() + minutes * 60_000).toISOString(),
			...extra,
		};
		const kept = this.read().filter((g) => !sameGrantKey(g, grant));
		this.write([...kept, grant]);
		return grant;
	}

	/** An approval the human gave for one specific pending call. */
	approveOnce(request: { id: string; rule: string; cwd?: string }, minutes: number, by?: string): Grant {
		return this.add(request.rule, request.cwd ?? process.cwd(), minutes, {
			fingerprint: request.id,
			singleUse: true,
			requestId: request.id,
			by,
			note: "one-shot approval",
		});
	}

	remove(rule: string, scope?: string): number {
		const before = this.read().length;
		const target = scope && scope !== "*" ? normalisePath(scope) : undefined;
		this.write(
			this.read().filter((g) => !(g.rule === rule && (target === undefined || g.scope === target))),
		);
		return before - this.read().length;
	}

	removeByFingerprint(fingerprint: string): number {
		const before = this.read().length;
		this.write(this.read().filter((g) => g.fingerprint !== fingerprint));
		return before - this.read().length;
	}

	/** Drop expired grants on read, so the file self-cleans. */
	active(): Grant[] {
		const now = Date.now();
		const all = this.read();
		const live = all.filter((g) => Date.parse(g.expiresAt) > now);
		if (live.length !== all.length) this.write(live);
		return live;
	}

	/** Does this grant cover this call? Pure — does not consume. */
	matches(g: Grant, rule: string, call: CallInput): boolean {
		if (g.rule !== rule) return false;
		if (g.tool && g.tool !== call.tool.name) return false;
		if (g.fingerprint && g.fingerprint !== callFingerprint(rule, call)) return false;

		if (g.scope === "*") return true;
		// Normalise both sides before comparing. A scope is stored resolved,
		// but the call's cwd arrives raw from the host — different separators,
		// trailing slashes, or casing would otherwise silently fail to match,
		// and a grant that quietly stops applying is worse than one that is
		// obviously broken.
		const cwd = normalisePath(call.agent?.cwd ?? "");
		if (!cwd) return false;
		// Prefix match on a PATH BOUNDARY, so a grant for /home/u/proj
		// does not cover /home/u/project-leaked. A plain startswith is the
		// classic sibling-directory bug.
		return cwd === g.scope || cwd.startsWith(scopePrefix(g.scope));
	}

	/** Is `rule` granted for this call? Pure — does not consume. */
	allows(rule: string, call: CallInput): boolean {
		return this.active().some((g) => this.matches(g, rule, call));
	}

	/**
	 * Find a grant and consume it if single-use. This is what `applyGrants`
	 * calls on the hot path; consuming writes the grants file, so a failure
	 * here must never throw into the enforcement path.
	 */
	consume(rule: string, call: CallInput): Grant | undefined {
		const hit = this.active().find((g) => this.matches(g, rule, call));
		if (!hit) return undefined;
		if (hit.singleUse) {
			try {
				this.write(this.read().filter((g) => g.fingerprint !== hit.fingerprint));
			} catch {
				// Best effort: an unwritable grants file must not break the call.
			}
		}
		return hit;
	}
}

/** Identity of a grant for replace-on-add purposes. */
function sameGrantKey(a: Grant, b: Grant): boolean {
	return a.rule === b.rule && a.scope === b.scope && a.fingerprint === b.fingerprint;
}

/** Path-boundary aware prefix helper. */
/**
 * Path-boundary prefix, separator-aware.
 *
 * The previous version appended "/" unconditionally, so a Windows scope never
 * matched: `C:\proj` vs `C:\proj\sub` failed the prefix test. Windows is
 * case-insensitive too, so comparisons lower-case on win32.
 */
const SEP_RE = /[\\/]+$/;

/**
 * Append the normalised separator, not the platform one.
 *
 * normalisePath rewrites everything to forward slashes, so the comparison
 * space is entirely "/". Using path.sep here produced `C:/proj\` on Windows,
 * which cannot match `C:/proj/sub`.
 */
export function scopePrefix(scope: string): string {
	return SEP_RE.test(scope) ? scope : `${scope}/`;
}

/** Normalise separators and casing for comparison; resolve if possible. */
export function normalisePath(p: string): string {
	if (!p) return "";
	let out = p.replace(/\\/g, "/");
	try {
		out = resolve(out).replace(/\\/g, "/");
	} catch {
		// keep the literal form if resolution is impossible
	}
	out = out.replace(/\/+$/, "");
	return process.platform === "win32" ? out.toLowerCase() : out;
}

/**
 * Identity of a single call: rule + tool + arguments + cwd. Matches the
 * approval-request id so an approved request and its retry line up exactly.
 */
export function callFingerprint(rule: string, call: CallInput): string {
	return createHash("sha256")
		.update(
			JSON.stringify([
				rule,
				call.tool.name,
				call.arguments ?? {},
				call.agent?.cwd ?? "",
			]),
		)
		.digest("hex")
		.slice(0, 12);
}

/**
 * Apply grants to a decision. Only `ask` is downgraded — see module note.
 */
export function applyGrants(decision: Decision, call: CallInput, store: GrantStore): Decision {
	if (decision.effect !== "ask") return decision;
	if (!store.consume(decision.rule, call)) return decision;
	return {
		...decision,
		effect: "allow",
		rule: `${decision.rule} (granted)`,
		reason: `${decision.reason} — allowed by an active grant`,
	};
}