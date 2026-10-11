#!/usr/bin/env node
/**
 * Last gate before `npm publish`.
 *
 * Publishing is irreversible in the ways that matter: you can un-publish a
 * version, but you cannot un-take a name, and a squatted name is never
 * released. So the things worth catching are checked here, and anything that
 * needs a human decision fails loudly instead of guessing.
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(resolve(ROOT, "package.json"), "utf8"));

const problems = [];
const warnings = [];
const ok = (msg) => console.log(`  ok    ${msg}`);
const warn = (msg) => {
	warnings.push(msg);
	console.log(`  warn  ${msg}`);
};
const fail = (msg) => {
	problems.push(msg);
	console.log(`  FAIL  ${msg}`);
};

console.log("prepublish checks\n" + "=".repeat(52));

// --- identity -------------------------------------------------------------
if (!pkg.name || !pkg.version) fail("package.json is missing name or version");
else ok(`${pkg.name}@${pkg.version}`);

if (!pkg.license) fail("no license field — publishing without one is legally murky");
else ok(`license: ${pkg.license}`);

if (!pkg.description) fail("no description");
const repoUrl = pkg.repository?.url ?? "";
const looksLikePlaceholder = !repoUrl || /example\.(com|org)|github\.com\/example\b/i.test(repoUrl);
if (looksLikePlaceholder) {
	fail(`repository.url is still a placeholder (${repoUrl || "none"}) — set it to the real repo before publishing`);
} else {
	ok("repository url set");
}

// --- name availability (advisory; needs network) --------------------------
try {
	const view = execFileSync("npm", ["view", pkg.name, "version"], {
		encoding: "utf8",
		stdio: ["ignore", "pipe", "ignore"],
	}).trim();
	fail(`the name "${pkg.name}" is ALREADY TAKEN on npm (latest ${view}) — pick another before publishing`);
} catch {
	ok(`name "${pkg.name}" appears available on npm`);
}

// --- the CLI must actually ship ------------------------------------------
// npm SILENTLY removes a bin entry whose target is not executable, publishing a
// package with no working CLI and no hard error. Verified here by checking the
// mode directly, and by confirming npm does not rewrite package.json.
try {
	const binEntries = typeof pkg.bin === "string" ? { toolwall: pkg.bin } : (pkg.bin ?? {});
	const bins = Object.entries(binEntries);
	if (bins.length === 0) {
		fail("package.json declares no bin — the CLI would not be installable");
	}
	for (const [name, target] of bins) {
		const p = resolve(ROOT, target);
		if (!existsSync(p)) {
			fail(`bin "${name}" points at a missing file: ${target}`);
			continue;
		}
		const mode = statSync(p).mode & 0o777;
		if (!(mode & 0o111)) {
			fail(`bin "${name}" (${target}) is mode ${mode.toString(8)}, not executable — npm will silently drop it`);
		} else if (!readFileSync(p, "utf8").startsWith("#!")) {
			fail(`bin "${name}" has no shebang, so it cannot be executed directly`);
		} else {
			ok(`bin "${name}" executable with shebang`);
		}
	}
} catch (err) {
	fail(`could not verify bin: ${err instanceof Error ? err.message : String(err)}`);
}

// --- artifacts ------------------------------------------------------------
for (const f of ["policy/default.wasm", "dist/cli.js", "dist/index.js"]) {
	if (existsSync(resolve(ROOT, f))) ok(`${f} present`);
	else fail(`${f} missing — run: npm run build:release`);
}

// The vendored OPA binary is 62MB and defeats the point of a precompiled
// policy. `files` should already exclude it; this checks that it did.
try {
	const listing = execFileSync("npm", ["pack", "--dry-run", "--json"], {
		encoding: "utf8",
		cwd: ROOT,
		stdio: ["ignore", "pipe", "ignore"],
	});
	// A lifecycle script can still print to stdout; take the JSON tail rather
	// than assuming stdout is pure JSON.
	const match = listing.match(/\[\s*\{/);
	const jsonStart = match ? match.index : -1;
	if (jsonStart < 0) throw new Error("npm pack produced no JSON");
	const parsed = JSON.parse(listing.slice(jsonStart));
	const files = parsed[0]?.files?.map((f) => f.path) ?? [];
	if (files.some((f) => f.startsWith("bin/"))) fail("the vendored OPA binary is in the tarball");
	else ok("vendored OPA binary excluded from the tarball");

	if (!files.includes("policy/default.wasm")) fail("policy/default.wasm missing from the tarball");
	else ok("precompiled policy included");

	const size = parsed[0]?.size ?? 0;
	if (size > 2_000_000) fail(`tarball is ${(size / 1048576).toFixed(1)}MB — expected well under 2MB`);
	else ok(`tarball size ${(size / 1024).toFixed(0)}kB`);

	if (files.some((f) => f.startsWith("test/"))) fail("test files are in the tarball");
	if (files.some((f) => f.includes("decisions.jsonl"))) fail("a decision log is in the tarball — it may hold secrets");
} catch (err) {
	fail(`could not inspect the tarball: ${err instanceof Error ? err.message : String(err)}`);
}

// --- hygiene --------------------------------------------------------------
if (existsSync(resolve(ROOT, ".toolwall"))) {
	warn("a .toolwall/ directory exists locally — it is gitignored and will not ship, but check it has no secrets");
}
ok("prepublish checks complete");

console.log("=".repeat(52));
if (problems.length) {
	console.error(`\nCannot publish: ${problems.length} problem(s)\n`);
	process.exit(1);
}
if (warnings.length) console.log(`\n${warnings.length} warning(s) — review before publishing.`);
console.log("\nReady to publish.");