/**
 * Loads compiled Rego policy (wasm) and evaluates tool-call decisions.
 *
 * The wasm module is compiled by `scripts/build-policy.sh`; the OPA binary is
 * only needed at build time, never at enforcement time.
 */

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

import { hostBuiltins } from "./host-builtins.js";
import { secretBuiltins } from "../secrets/builtins.js";
import { SecretStore } from "../secrets/store.js";
import type { CallInput, Decision, DecisionEffect } from "../types.js";

/** Anything loadable as a wasm module (no DOM lib in this project). */
type WasmBytes = ArrayBufferView | ArrayBuffer;

interface MemoryDescriptor {
	initial: number;
	maximum?: number;
}

const require = createRequire(import.meta.url);
const { loadPolicy } = require("@open-policy-agent/opa-wasm") as {
	loadPolicy: (
		bytes: WasmBytes,
		memory: MemoryDescriptor | number,
		customBuiltins: Record<string, Function>,
	) => Promise<LoadedPolicyLike>;
};

interface LoadedPolicyLike {
	evaluate(input: unknown, entrypoint?: number | string): Promise<unknown>;
	setData(data: unknown): void;
	entrypoints: Record<string, number>;
	minorVersion: unknown;
}

const DEFAULT_ENTRYPOINT = "firewall/decision";

/**
 * A user policy layer: rules contributed by the repo (`.firewall/`) or the
 * user (`~/.firewall/`). Lives under the `toolwall` package, separate from the
 * policy's own `firewall` package — `data.firewall.user_rules` would be a
 * self-reference and OPA rejects it as recursive.
 */
export interface UserData {
	toolwall?: { user_rules?: unknown[] };
}

/** Placeholder store so the secret builtins always resolve. */
const EMPTY_SECRETS = new SecretStore({ path: "/nonexistent/toolwall-secrets.json", secrets: {}, env: {} });

export class PolicyEngine {
	readonly #policy: LoadedPolicyLike;

	private constructor(policy: LoadedPolicyLike) {
		this.#policy = policy;
	}

	static async load(
		wasmPath: string,
		userData?: UserData,
		memory: MemoryDescriptor = { initial: 16, maximum: 128 },
		secrets?: SecretStore,
	): Promise<PolicyEngine> {
		const bytes = readFileSync(wasmPath);
		// Secret builtins are ALWAYS registered, even with an empty store. A
		// policy that references contains_secret_ref would otherwise throw at
		// evaluation time in any process that did not pass a store, and the
		// engine fails closed — so "no secrets configured" would silently deny
		// every call. Configuration must not change whether policy evaluates.
		//
		// These builtins expose reference detection and existence only — a
		// policy can ask which secrets exist, never what they are.
		const builtins = { ...hostBuiltins, ...secretBuiltins(secrets ?? EMPTY_SECRETS) };
		const policy = await loadPolicy(bytes, memory, builtins);
		if (userData) policy.setData(userData);
		return new PolicyEngine(policy);
	}

	/** Path of the wasm entrypoint baked in at compile time. */
	get entrypoint(): string {
		return Object.keys(this.#policy.entrypoints)[0] ?? DEFAULT_ENTRYPOINT;
	}

	/**
	 * Evaluate one call. Never throws: a policy that cannot be evaluated must
	 * fail closed (deny), not crash the proxy and break the agent's session.
	 */
	async decide(call: CallInput): Promise<Decision> {
		const started = process.hrtime.bigint();
		try {
			const raw = await this.#policy.evaluate(call);
			const value = unwrap(raw);
			const effect = (value as any)?.effect;
			if (effect !== "allow" && effect !== "deny" && effect !== "ask") {
				return {
					effect: "deny",
					rule: "toolwall-fail-closed",
					reason: `policy returned an unusable effect (${JSON.stringify(effect)}); failing closed`,
				};
			}
			return {
				effect: effect as DecisionEffect,
				rule: String((value as any)?.rule ?? "unknown"),
				reason: String((value as any)?.reason ?? ""),
			};
		} catch (err) {
			return {
				effect: "deny",
				rule: "toolwall-fail-closed",
				reason: `policy evaluation failed: ${err instanceof Error ? err.message : String(err)}`,
			};
		} finally {
			void started;
		}
	}

	/** Evaluate and report duration, for logging. */
	async decideTimed(call: CallInput): Promise<{ decision: Decision; evalMs: number }> {
		const t0 = process.hrtime.bigint();
		const decision = await this.decide(call);
		return { decision, evalMs: Number(process.hrtime.bigint() - t0) / 1e6 };
	}
}

/** opa-wasm returns an array of result-sets: [{ result: <value> }]. */
function unwrap(raw: unknown): unknown {
	if (Array.isArray(raw)) {
		const first = raw[0] as any;
		return first && typeof first === "object" && "result" in first ? first.result : first;
	}
	if (raw && typeof raw === "object" && "result" in (raw as any)) return (raw as any).result;
	return raw;
}