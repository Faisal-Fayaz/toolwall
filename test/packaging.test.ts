/**
 * Packaging test.
 *
 * `npm pack` + install into a throwaway project, with NO OPA binary present.
 * This exists because packaging bugs are invisible from inside the source tree:
 * a stale `dist/` shipped fine, and a hardcoded /tmp path to the OPA CLI looked
 * correct right up until someone installed the tarball.
 *
 * Run: node --experimental-strip-types test/packaging.test.ts
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));

let pass = 0,
	fail = 0;
const check = (label: string, got: unknown, want: unknown) => {
	const ok = JSON.stringify(got) === JSON.stringify(want);
	ok ? pass++ : fail++;
	if (!ok) console.log(`  MISS ${label}: want ${JSON.stringify(want)} got ${JSON.stringify(got)}`);
};

const sh = (cmd: string, args: string[], cwd: string) =>
	execFileSync(cmd, args, { encoding: "utf8", cwd, stdio: ["ignore", "pipe", "pipe"] });

const workdir = mkdtempSync(join(tmpdir(), "toolwall-pkg-"));
const proj = join(workdir, "proj");
mkdirSync(proj, { recursive: true });

try {
	// ---------------------------------------------------------------- pack
	sh("npm", ["pack", "--pack-destination", workdir], ROOT);
	const tgz = readdirSync(workdir).find((f) => f.endsWith(".tgz"))!;
	const tarball = join(workdir, tgz);
	check("tarball produced", existsSync(tarball), true);

	const size = Number(execFileSync("du", ["-k", tarball], { encoding: "utf8" }).split("\t")[0]);
	// The 62MB OPA binary must never be shipped; 123kB is the expected ballpark.
	check("tarball is small (no vendored OPA)", size < 2000, true);
	console.log(`      tarball = ${size} kB`);

	// ------------------------------------------------------------- install
	sh("npm", ["init", "-y"], workdir);
	sh("npm", ["install", tarball, "--no-audit", "--no-fund"], workdir);

	// The install path depends on the package name: a scoped package lands in
	// node_modules/@scope/name, not node_modules/name.
	const pkgName = JSON.parse(readFileSync(resolve(ROOT, "package.json"), "utf8")).name as string;
	const pkg = join(workdir, "node_modules", ...pkgName.split("/"));
	const CLI = join(pkg, "dist/cli.js");

	check("policy/default.wasm ships", existsSync(join(pkg, "policy/default.wasm")), true);
	check("policy/default.rego ships (forkable)", existsSync(join(pkg, "policy/default.rego")), true);
	check("no OPA binary shipped", existsSync(join(pkg, "bin")), false);
	const installedPkg = JSON.parse(readFileSync(join(pkg, "package.json"), "utf8"));
	check("bin is declared", typeof installedPkg.bin?.toolwall === "string", true);

	// npm SILENTLY drops a bin entry whose target is not executable, publishing
	// a package with no working CLI. Run the installed binary the way a user
	// would, so this cannot regress unnoticed.
	const binLink = join(workdir, "node_modules/.bin/toolwall");
	check("npm created a .bin shim", existsSync(binLink), true);
	const binTarget = installedPkg.bin?.toolwall as string;
	const binMode = statSync(join(pkg, binTarget)).mode & 0o777;
	check("bin target is executable", (binMode & 0o111) !== 0, true);
	const viaBin = sh(binLink, ["check", "--cwd", proj], workdir);
	check("installed binary runs", viaBin.includes("workspace-scoped"), true);
	// usage text goes to stderr, so capture both streams
	const viaNode = execFileSync("node", [join(pkg, binTarget), "--help"], {
		encoding: "utf8",
		cwd: workdir,
		stdio: ["ignore", "pipe", "pipe"],
	});
	check("installed binary runs directly too", viaNode.includes("toolwall serve"), true);

	// ------------------------------------------- runs with no OPA present

	const hook = (payload: object): string => {
		try {
			return sh("node", [CLI, "hook", "--cwd", proj], workdir).trim();
		} catch {
			return "";
		}
	};
	const runHook = (tool: string, input: Record<string, unknown>): string => {
		const inputText = JSON.stringify({
			hook_event_name: "PreToolUse",
			cwd: proj,
			tool_name: tool,
			tool_input: input,
		});
		try {
			return execFileSync("node", [CLI, "hook", "--cwd", proj], {
				input: inputText,
				encoding: "utf8",
				cwd: workdir,
			}).trim();
		} catch {
			return "";
		}
	};

	check("binary runs with no OPA installed", sh("node", [CLI, "check", "--cwd", proj], workdir).includes("workspace-scoped"), true);
	check(
		"finds its OWN bundled policy",
		sh("node", [CLI, "check", "--cwd", proj], workdir).includes("policy"),
		true,
	);
	void hook;

	const denied = runHook("Read", { file_path: join(proj, ".env") });
	check("gates a secret read from a clean install", JSON.parse(denied).hookSpecificOutput.permissionDecision, "deny");
	check("names the rule", JSON.parse(denied).hookSpecificOutput.permissionDecisionReason.includes("no-secret-reads"), true);

	const forced = runHook("Bash", { command: "git push --force" });
	check("gates force-push", JSON.parse(forced).hookSpecificOutput.permissionDecision, "deny");

	check("allows a workspace read", runHook("Read", { file_path: join(proj, "ok.md") }), "");

	// -------------------------------------------------- authoring explains
	let buildErr = "";
	try {
		sh("bash", [join(pkg, "scripts/build-policy.sh"), join(proj, "x.rego")], workdir);
	} catch (err: any) {
		buildErr = `${err.stdout ?? ""}${err.stderr ?? ""}`;
	}
	check("custom Rego explains the OPA requirement", buildErr.includes("OPA CLI is required"), true);
	check("...and names the fix", buildErr.includes("fetch-opa"), true);
	check("...and says normal use does not need it", buildErr.includes("ships precompiled"), true);

	// ------------------------------------------------------- API import
	// import by the real package name, which is scope-aware
	const api = execFileSync("node", ["-e", `import(${JSON.stringify(pkgName)}).then(async m=>{const e=await m.PolicyEngine.load(m.BUNDLED_POLICY);const d=await e.decide({mode:"enforce",agent:{id:"x",cwd:"/p"},tool:{name:"Read"},arguments:{path:"/p/.env"}});console.log(d.effect+" "+d.rule)})`], {
		encoding: "utf8",
		cwd: workdir,
	}).trim();
	check("programmatic API works as a dependency", api, "deny no-secret-reads");
} finally {
	rmSync(workdir, { recursive: true, force: true });
}

console.log("=".repeat(52));
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);

/** first .tgz in the pack destination */
function require_first_tgz(): string {
	const { readdirSync } = require("node:fs") as typeof import("node:fs");
	return readdirSync(workdir).find((f) => f.endsWith(".tgz"))!;
}