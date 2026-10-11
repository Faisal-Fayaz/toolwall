#!/usr/bin/env node
/**
 * Make every entry in `bin` executable.
 *
 * tsc emits mode 664, and npm treats a non-executable bin target as invalid —
 * it SILENTLY REMOVES the entry when publishing, producing a package with no
 * working CLI and no hard error. This runs as part of every build so that
 * cannot happen quietly again.
 */

import { chmodSync, existsSync, readFileSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(resolve(ROOT, "package.json"), "utf8"));

const bins = typeof pkg.bin === "string" ? { [pkg.name.split("/").pop()]: pkg.bin } : (pkg.bin ?? {});

let changed = 0;
for (const [name, target] of Object.entries(bins)) {
	const path = resolve(ROOT, target);
	if (!existsSync(path)) {
		console.error(`  warn  bin "${name}" points at a missing file: ${target}`);
		continue;
	}
	const mode = statSync(path).mode & 0o777;
	if (mode & 0o111) continue;
	chmodSync(path, 0o755);
	changed++;
	console.error(`  chmod +x ${target}`);
}

if (changed === 0) console.error("bin scripts already executable");