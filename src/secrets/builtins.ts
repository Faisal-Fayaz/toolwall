/**
 * Secret reference host builtins.
 *
 * The policy needs to see `{{secret:…}}` references inside arguments. Exposing
 * only the REFERENCE detection (never a value) keeps the Rego layer from ever
 * being able to print a credential into a decision reason.
 */

import { findSecretRefs, SECRET_REF } from "./reference.js";
import type { SecretStore } from "./store.js";

/** Collects secret-related builtins, bound to a store. */
export function secretBuiltins(secrets: SecretStore): Record<string, Function> {
	const refsIn = (value: unknown): string[] => {
		const names = new Set<string>();
		const walk = (v: unknown, depth = 0) => {
			if (depth > 20 || v == null) return;
			if (typeof v === "string") {
				for (const m of v.matchAll(SECRET_REF)) if (m[1]) names.add(m[1]);
				return;
			}
			if (Array.isArray(v)) return v.forEach((x) => walk(x, depth + 1));
			if (typeof v === "object") {
				for (const x of Object.values(v as Record<string, unknown>)) walk(x, depth + 1);
			}
		};
		walk(value);
		return [...names];
	};

	return {
		contains_secret_ref: (value: unknown) => refsIn(value).length > 0,
		contains_secret_ref_named: (value: unknown, name: unknown) =>
			typeof name === "string" && refsIn(value).some((n) => n.toLowerCase() === name.toLowerCase()),
		secret_ref_names: (value: unknown) => refsIn(value),
		// Existence only. A policy can ask WHICH secrets exist; it can never
		// read one, so a reason string cannot leak a credential.
		secret_exists: (name: unknown) => typeof name === "string" && secrets.has(name.toLowerCase()),
	};
}

export { findSecretRefs };