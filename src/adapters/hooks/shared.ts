/**
 * Catalogue reader shared by the hook adapters.
 *
 * The MCP proxy is the only component that sees MCP annotations — hooks don't
 * receive readOnlyHint/destructiveHint (anthropics/claude-code#83886) — so it
 * publishes what it learned and hooks read it back here.
 */

import { readFileSync } from "node:fs";

import { cataloguePath, type Catalogue } from "./normalize.js";

export function loadCatalogue(dir: string | undefined): Catalogue | undefined {
	if (!dir) return undefined;
	try {
		return JSON.parse(readFileSync(cataloguePath(dir), "utf8")) as Catalogue;
	} catch {
		return undefined; // absent or unreadable is not fatal
	}
}