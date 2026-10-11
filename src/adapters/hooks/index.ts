/**
 * Hook adapter registry.
 *
 * Selection is EXPLICIT. Claude Code and Codex share `tool_name` +
 * `hook_event_name`, so guessing between them means sometimes emitting the
 * wrong dialect — which makes the host ignore the hook and run the tool
 * anyway. That is a fail-open failure, so it is not worth the convenience.
 *
 * Cursor is the exception: its payload (`workspace_roots`, `command`,
 * `file_path` with no `tool_name`) is unambiguous, so it may be auto-detected.
 */

import { claudeCodeAdapter } from "./claude-code.js";
import { codexAdapter } from "./codex.js";
import { cursorAdapter, looksLikeCursor } from "./cursor.js";
import type { AgentAdapter } from "./types.js";
import type { HookToolInput } from "./normalize.js";

export const adapters: Record<string, AgentAdapter> = {
	"claude-code": claudeCodeAdapter,
	cursor: cursorAdapter,
	codex: codexAdapter,
};

export const DEFAULT_ADAPTER = "claude-code";

export function getAdapter(id: string | undefined): AgentAdapter {
	const key = (id ?? DEFAULT_ADAPTER).toLowerCase();
	const adapter = adapters[key];
	if (!adapter) {
		throw new Error(`unknown agent '${id}'. Supported: ${Object.keys(adapters).join(", ")}`);
	}
	return adapter;
}

/**
 * Pick an adapter for a payload. Only Cursor is auto-detected, because it is
 * the only one we can identify without ambiguity.
 */
export function detectAdapter(payload: HookToolInput, requested?: string): AgentAdapter {
	if (requested) return getAdapter(requested);
	if (looksLikeCursor(payload)) return cursorAdapter;
	return getAdapter(DEFAULT_ADAPTER);
}

export { claudeCodeAdapter, cursorAdapter, codexAdapter, looksLikeCursor };
export type { AgentAdapter };