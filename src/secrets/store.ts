/**
 * Secret store.
 *
 * Two capabilities live here, and the second matters more than the first:
 *
 *   1. Brokering — the agent passes a `{{secret:name}}` reference; toolwall
 *      substitutes the real value at the proxy boundary. The agent never holds
 *      the credential.
 *
 *   2. Scrubbing — upstream RESPONSES are scrubbed before the agent sees them.
 *      This is the real prize. A deny rule stops the agent reading
 *      ~/.aws/credentials, but an agent can still be walked into running
 *      `env | grep TOKEN`, or a build step can echo a token into stdout. Once
 *      a live credential is in the model's context it can be sent anywhere,
 *      and no rule is consulted at that point. Scrubbing at the boundary is
 *      the only place that still works.
 *
 * Secrets are never logged, never written to the decision log, and never
 * returned by anything but `value()`, which the substitution path calls.
 */

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/** Env prefix for injecting secrets without a file. */
export const ENV_PREFIX = "TOOLWALL_SECRET_";

/** Values shorter than this are not substring-scrubbed: too many collisions. */
const MIN_SCRUB_LENGTH = 8;

export interface SecretStoreOptions {
	/** Explicit map, mostly for tests. */
	secrets?: Record<string, string>;
	/** Path to a JSON file of name -> value. */
	path?: string;
	/** Read TOOLWALL_SECRET_* from this environment. */
	env?: NodeJS.ProcessEnv;
}

export function defaultSecretsPath(): string {
	return process.env.TOOLWALL_SECRETS ?? join(homedir(), ".toolwall", "secrets.json");
}

export class SecretStore {
	readonly #values = new Map<string, string>();

	constructor(opts: SecretStoreOptions = {}) {
		const env = opts.env ?? process.env;

		if (opts.path ?? defaultSecretsPath()) {
			const path = opts.path ?? defaultSecretsPath()!;
			if (existsSync(path)) {
				try {
					const parsed = JSON.parse(readFileSync(path, "utf8"));
					for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
						if (typeof v === "string" && v !== "") this.#values.set(k, v);
					}
				} catch {
					// A malformed secrets file must not break the agent's session;
					// it just means no secrets are brokered.
				}
			}
		}

		for (const [k, v] of Object.entries(env)) {
			if (k.startsWith(ENV_PREFIX) && v) this.#values.set(k.slice(ENV_PREFIX.length).toLowerCase(), v);
		}

		for (const [k, v] of Object.entries(opts.secrets ?? {})) {
			if (v) this.#values.set(k, v);
		}
	}

	/** Names only. Safe to log, show in a UI, or put in the decision log. */
	names(): string[] {
		return [...this.#values.keys()].sort();
	}

	has(name: string): boolean {
		return this.#values.has(name);
	}

	/** The ONLY accessor for a raw secret value. */
	value(name: string): string | undefined {
		return this.#values.get(name);
	}

	get size(): number {
		return this.#values.size;
	}

	/** Values long enough to substring-scrub, longest first. */
	scrubbable(): string[] {
		return [...this.#values.values()].filter((v) => v.length >= MIN_SCRUB_LENGTH).sort((a, b) => b.length - a.length);
	}
}