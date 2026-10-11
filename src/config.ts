/**
 * Policy layering and file discovery.
 *
 * Rules from a project `.firewall/policy.json` override same-named rules from
 * the user-global `~/.firewall/policy.json`, which in turn sit alongside the
 * compiled-in defaults. Layering is by rule NAME, so a project can weaken or
 * strengthen a single specific rule without restating the rest.
 */

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

export interface UserRule {
	name: string;
	effect: "allow" | "deny" | "ask";
	tools: string[];
	reason?: string;
	[key: string]: unknown;
}

export const PROJECT_POLICY = ".firewall/policy.json";
export const USER_POLICY = "~/.firewall/policy.json";

function expand(p: string): string {
	return p.startsWith("~/") ? join(homedir(), p.slice(2)) : p;
}

/** Candidate policy files, most specific last. */
export function policyPaths(cwd: string = process.cwd()): string[] {
	return [expand(USER_POLICY), resolve(cwd, PROJECT_POLICY)];
}

function loadFile(path: string): UserRule[] {
	if (!existsSync(path)) return [];
	let parsed: unknown;
	try {
		parsed = JSON.parse(readFileSync(path, "utf8"));
	} catch (err) {
		throw new Error(`invalid policy JSON at ${path}: ${err instanceof Error ? err.message : err}`);
	}
	const rules = (parsed as any)?.rules;
	if (!Array.isArray(rules)) {
		throw new Error(`policy at ${path} must contain a "rules" array`);
	}
	for (const [i, r] of rules.entries()) {
		if (!r || typeof r.name !== "string") throw new Error(`policy ${path}: rules[${i}] missing "name"`);
		if (!["allow", "deny", "ask"].includes((r as any).effect)) {
			throw new Error(`policy ${path}: rules[${i}] ("${(r as any).name}") needs effect allow|deny|ask`);
		}
	}
	return rules as UserRule[];
}

/**
 * Merge layered rule files. Later files win per rule name.
 * Returns the merged list plus which files contributed, for `--verbose`.
 */
export function loadUserRules(
	cwd: string = process.cwd(),
): { rules: UserRule[]; sources: { path: string; count: number }[] } {
	const byName = new Map<string, UserRule>();
	const sources: { path: string; count: number }[] = [];

	for (const path of policyPaths(cwd)) {
		const rules = loadFile(path);
		if (rules.length === 0) continue;
		sources.push({ path, count: rules.length });
		for (const rule of rules) byName.set(rule.name, rule);
	}

	return { rules: [...byName.values()], sources };
}

/** Shape handed to the policy engine as `data.toolwall`. */
export function userData(rules: UserRule[]): { toolwall: { user_rules: UserRule[] } } {
	return { toolwall: { user_rules: rules } };
}