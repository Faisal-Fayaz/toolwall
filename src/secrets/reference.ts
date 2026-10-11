/**
 * Secret references: `{{secret:name}}`.
 *
 * The agent writes a reference; toolwall substitutes the real value when
 * calling upstream. The agent never holds the credential, never sees it in a
 * log, and cannot exfiltrate it by echoing its own tool arguments.
 *
 * Substitution happens ONLY in the proxy path, at the boundary. It
 * deliberately does NOT happen in the hook path: for built-in tools it would
 * paste a live secret into a shell command line, which is the one place a
 * secret is most likely to end up in a process listing, a history file, or an
 * error message.
 */

import type { SecretStore } from "./store.js";

export const SECRET_REF = /\{\{\s*secret\s*:\s*([A-Za-z0-9_.-]+)\s*\}\}/g;

export interface Substitution {
	/** Arguments with real values substituted. */
	value: Record<string, unknown>;
	/** Names referenced. Safe to log and to surface to the model. */
	names: string[];
	/** References that named a secret toolwall does not have. */
	missing: string[];
}

/** Every `{{secret:…}}` name present in a value, without substituting. */
export function findSecretRefs(value: unknown): string[] {
	const names = new Set<string>();
	const walk = (v: unknown, depth = 0) => {
		if (depth > 20 || v == null) return;
		if (typeof v === "string") {
			for (const m of v.matchAll(SECRET_REF)) if (m[1]) names.add(m[1]);
			return;
		}
		if (Array.isArray(v)) {
			v.forEach((x) => walk(x, depth + 1));
			return;
		}
		if (typeof v === "object") {
			for (const x of Object.values(v as Record<string, unknown>)) walk(x, depth + 1);
		}
	};
	walk(value);
	return [...names];
}

/**
 * Replace `{{secret:name}}` with the real value.
 *
 * An unknown name is left IN PLACE rather than blanked. Emptying it would send
 * a literal `{{secret:nope}}` to an upstream API as if it were a credential,
 * producing a confusing failure far from the cause; leaving it visible keeps
 * the mistake obvious, and `missing` lets the caller fail closed deliberately.
 */
export function substituteSecrets(args: Record<string, unknown>, secrets: SecretStore): Substitution {
	const names: string[] = [];
	const missing: string[] = [];

	const substitute = (input: string): string =>
		input.replace(SECRET_REF, (whole, rawName: string) => {
			const name = rawName.toLowerCase();
			if (!names.includes(name)) names.push(name);
			const value = secrets.value(name);
			if (value === undefined) {
				if (!missing.includes(name)) missing.push(name);
				return whole;
			}
			return value;
		});

	const walk = (v: unknown, depth = 0): unknown => {
		if (depth > 20) return v;
		if (typeof v === "string") return substitute(v);
		if (Array.isArray(v)) return v.map((x) => walk(x, depth + 1));
		if (v && typeof v === "object") {
			const out: Record<string, unknown> = {};
			for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
				// Keys can carry references too, but substituting a key would
				// change the shape of the payload; treat them as literal.
				out[k] = walk(val, depth + 1);
			}
			return out;
		}
		return v;
	};

	return { value: walk(args) as Record<string, unknown>, names, missing };
}

/** True when any argument references a secret. Backs the `secret_ref` rule. */
export function usesSecret(args: unknown): boolean {
	return findSecretRefs(args).length > 0;
}