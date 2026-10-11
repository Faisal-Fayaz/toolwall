/**
 * Builtins implemented in the host (Node) rather than in Rego.
 *
 * OPA's Wasm target implements only part of the standard library, and some of
 * what we need is not expressible in Rego at all — notably symlink-resolved
 * path containment. Every builtin here MUST have a matching declaration in
 * policy/capabilities.json or `opa build` rejects the policy.
 */

import { realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, relative, resolve } from "node:path";

/** Filenames/paths that should never be read or written by an agent. */
const SECRET_PATH_RE =
	/(^|[\\/])(\.env(\.[A-Za-z0-9_-]+)?|\.envrc|id_rsa|id_dsa|id_ecdsa|id_ed25519|\.pem|\.key|\.p12|\.pfx|\.npmrc|\.netrc|\.pypirc|\.git-credentials|\.docker[\\/]config\.json|credentials|secrets?(\.[A-Za-z0-9_-]+)?|service-account[^\\/]*\.json)$/i;

/** Value shapes that look like credentials regardless of path. */
const SECRET_VALUE_KEYS =
	/^(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|authorization|credential)s?$/i;

const norm = (p: string): string => p.replace(/[\\/]+$/, "");

/**
 * Resolve symlinks where possible so `../../etc/passwd` and symlinked escapes
 * cannot fool a path rule. For paths that do not exist yet (writes to new
 * files), resolve the deepest existing ancestor and re-append the remainder.
 */
function resolveForCompare(p: string): string {
	const abs = resolve(p);
	let probe = abs;
	const tail: string[] = [];
	for (;;) {
		try {
			const real = realpathSync.native(probe);
			return tail.length ? resolve(real, ...tail) : real;
		} catch {
			const parent = dirname(probe);
			if (parent === probe) return abs; // reached the root, give up
			tail.unshift(basename(probe));
			probe = parent;
		}
	}
}

/**
 * True when `target` is inside `root` after symlink resolution.
 * Backs the workspace-scoping rules — the single most important builtin here,
 * because a lexical-only check is trivially defeated.
 */
export function pathIsWithin(root: string, target: string): boolean {
	if (typeof root !== "string" || typeof target !== "string" || root === "" || target === "") {
		return false;
	}
	// Require absolute paths: a relative target has no stable meaning here.
	if (!isAbsolute(root) || !isAbsolute(target)) return false;

	const r = norm(resolveForCompare(root));
	const t = norm(resolveForCompare(target));
	if (t === r) return true;

	const rel = relative(r, t);
	return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
}

/** True when a path looks like a credential store. */
export function pathContainsSecret(value: unknown): boolean {
	if (typeof value !== "string" || value === "") return false;
	const base = value.split(/[\\/]/).pop() ?? value;
	return SECRET_PATH_RE.test(value) || SECRET_PATH_RE.test(base);
}

/** Recursively replace likely-secret values with a placeholder. */
export function redact(value: unknown, depth = 0): unknown {
	if (depth > 12) return "[deep]";
	if (typeof value === "string") {
		return SECRET_VALUE_KEYS.test(value) ? "[redacted]" : value;
	}
	if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
	if (value && typeof value === "object") {
		const out: Record<string, unknown> = {};
		for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
			out[k] = SECRET_VALUE_KEYS.test(k) ? "[redacted]" : redact(v, depth + 1);
		}
		return out;
	}
	return value;
}

/**
 * The map handed to opa-wasm's loadPolicy(). Implementations receive spread
 * positional args and must return a JSON-able value.
 */
export const hostBuiltins: Record<string, Function> = {
	path_is_within: pathIsWithin,
	path_contains_secret: pathContainsSecret,
	redact: (v: unknown) => redact(v),
};