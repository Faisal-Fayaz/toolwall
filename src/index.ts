/**
 * Programmatic API.
 *
 * Embedding toolwall in your own agent runtime: load the bundled policy, add
 * your own host builtins, and evaluate calls without going through the CLI or
 * the MCP proxy.
 *
 *   import { PolicyEngine, hostBuiltins } from "toolwall";
 *
 *   const engine = await PolicyEngine.load();          // bundled default policy
 *   const decision = await engine.decide({
 *     mode: "enforce",
 *     agent: { id: "my-agent", cwd: process.cwd() },
 *     tool: { name: "Read" },
 *     arguments: { file_path: "/repo/.env" },          // normalized for you
 *   });
 *
 * Custom host builtins require a matching declaration in
 * policy/capabilities.json before the policy will compile — the Wasm compiler
 * type-checks builtins, and an undeclared one is a build error.
 */

import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export { PolicyEngine } from "./engine/engine.js";
export type { UserData } from "./engine/engine.js";
export { hostBuiltins, pathIsWithin, pathContainsSecret, redact } from "./engine/host-builtins.js";
export { DecisionLog, readLog } from "./decision-log/log.js";
export { ApprovalQueue, requestId } from "./approval/queue.js";
export { GrantStore, applyGrants, callFingerprint } from "./approval/grants.js";
export { loadUserRules, userData, policyPaths } from "./config.js";
export { SecretStore, defaultSecretsPath, ENV_PREFIX } from "./secrets/store.js";
export { scrubString, scrubValue, scrubToolResult } from "./secrets/scrub.js";
export { substituteSecrets, findSecretRefs, usesSecret } from "./secrets/reference.js";
export { handleHook, installHooks } from "./adapters/hooks/claude-code.js";
export {
	adapters,
	getAdapter,
	detectAdapter,
	claudeCodeAdapter,
	cursorAdapter,
	codexAdapter,
} from "./adapters/hooks/index.js";
export { runPipeline } from "./adapters/hooks/types.js";
export type { AgentAdapter, AdapterContext } from "./adapters/hooks/types.js";
export { createProxy } from "./adapters/mcp-proxy/proxy.js";
export * from "./types.js";

/** Root of the installed package. */
export const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * The compiled policy shipped with the package, so ordinary use needs no OPA
 * CLI. Authoring custom `.rego` is the only thing that requires it.
 */
export const BUNDLED_POLICY = resolve(PACKAGE_ROOT, "policy/default.wasm");