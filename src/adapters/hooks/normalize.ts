/**
 * Normalizes a built-in agent tool call into the same CallInput shape the MCP
 * adapter produces, so one set of policies covers both.
 *
 * This matters more than it looks. Claude Code's built-ins do NOT use the same
 * argument names as MCP servers:
 *
 *   Read/Write/Edit   -> { file_path: "..." }     (not `path`)
 *   Bash              -> { command: "..." }
 *   Grep/Glob         -> { pattern: "...", path: "..." }
 *
 * Without normalizing `file_path` into `path`, every path-based rule silently
 * fails to match and the agent gets no protection from the rules it appears to
 * have.
 */

/** Argument keys that mean "a filesystem path" in built-in tools. */
const PATH_KEYS = ["file_path", "path", "filePath", "notebook_path"] as const;

export interface HookToolInput {
	tool_name?: string;
	tool_input?: Record<string, unknown>;
	tool_annotations?: {
		readOnlyHint?: boolean;
		destructiveHint?: boolean;
		idempotentHint?: boolean;
	};
	cwd?: string;
	session_id?: string;
	permission_mode?: string;
	hook_event_name?: string;
	[key: string]: unknown;
}

/** Canonical tool names, for readable rules. */
export const BUILTIN = {
	read: "Read",
	write: "Write",
	edit: "Edit",
	bash: "Bash",
	glob: "Glob",
	grep: "Grep",
} as const;

/**
 * Extract a canonical `path` from whichever key the tool used.
 * Returns undefined when the tool has no path notion at all.
 */
export function extractPath(toolInput: Record<string, unknown> | undefined): string | undefined {
	if (!toolInput) return undefined;
	for (const key of PATH_KEYS) {
		const v = toolInput[key];
		if (typeof v === "string" && v !== "") return v;
	}
	return undefined;
}

/**
 * Arguments as the policy sees them: original keys preserved, plus a canonical
 * `path` and, for Bash, the command under `command` (already the real key).
 *
 * Nothing is dropped — a rule may still match on the raw keys — we only ADD the
 * canonical one so path rules work across adapters.
 */
export function normalizeArguments(toolInput: Record<string, unknown> | undefined): Record<string, unknown> {
	const args: Record<string, unknown> = { ...(toolInput ?? {}) };
	const path = extractPath(toolInput);
	if (path !== undefined && args.path === undefined) args.path = path;
	return args;
}

/**
 * Claude Code does not forward MCP annotations to hooks (see
 * anthropics/claude-code#83886), so hooks that see an `mcp__*` tool have no
 * readOnly/destructive signal. The catalogue lets the MCP proxy publish what it
 * learned at tools/list time so hooks can recover the hint.
 */
export type Catalogue = Record<string, { readOnlyHint?: boolean; destructiveHint?: boolean }>;

export function resolveAnnotations(
	toolName: string,
	hookInput: HookToolInput,
	catalogue: Catalogue | undefined,
): { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean } | undefined {
	// Explicit annotations win (some Claude Code versions do forward them).
	if (hookInput.tool_annotations) return hookInput.tool_annotations;
	if (!catalogue) return undefined;

	const stripped = mcpToolKey(toolName);
	// The proxy keys the catalogue by the server's own tool name; the hook only
	// knows the client's `mcp__server__tool` naming. Try the namespaced key,
	// then fall back to the bare tool name so a server whose id we cannot see
	// still resolves.
	if (stripped) {
		if (catalogue[stripped]) return catalogue[stripped];
		const bare = stripped.split("__").pop();
		if (bare && catalogue[bare]) return catalogue[bare];
		return undefined;
	}
	return catalogue[toolName];
}

/** `mcp__github__create_issue` -> `github__create_issue`. */
export function mcpToolKey(toolName: string): string | undefined {
	return toolName.startsWith("mcp__") ? toolName.slice(5) : undefined;
}

/** Where the MCP proxy publishes what it learned from tools/list. */
export function cataloguePath(cwd: string): string {
	return `${cwd}/.toolwall/tool-catalogue.json`;
}