/**
 * Base64 payload scrubbing.
 *
 * The hole this closes: MCP results carry data outside `text`. ImageContent
 * and AudioContent have `data`; EmbeddedResource has `resource.blob`. All
 * base64. The string walk sees them as opaque and passes them through, so a
 * credential served as base64 reached the model untouched.
 *
 * Run: node --experimental-strip-types test/base64.test.ts
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { handleBase64, looksLikeBase64 } from "../dist/secrets/base64.js";
import { scrubToolResult, scrubValue } from "../dist/secrets/scrub.js";
import { SecretStore } from "../dist/secrets/store.js";

let pass = 0,
	fail = 0;
const check = (label: string, got: unknown, want: unknown) => {
	const ok = JSON.stringify(got) === JSON.stringify(want);
	ok ? pass++ : fail++;
	if (!ok) console.log(`  MISS ${label}: want ${JSON.stringify(want)} got=${JSON.stringify(got)}`);
};

const workdir = mkdtempSync(join(tmpdir(), "toolwall-b64-"));
const TOKEN = "ghp_Z1y2X3b4N5m6Q7w8E9r0T1u2I3o4P5q6R7s8";
const store = new SecretStore({
	path: join(workdir, "absent.json"),
	env: {} as NodeJS.ProcessEnv,
	secrets: { github_token: TOKEN },
});

const b64 = (s: string) => Buffer.from(s, "utf8").toString("base64");
const unb64 = (s: string) => Buffer.from(s, "base64").toString("utf8");

// ------------------------------------------------------------- detection

console.log("base64 detection");

check("ordinary word is not base64", looksLikeBase64("hello"), false);
check("short string is not base64", looksLikeBase64("abcd"), false);
check("real base64 is detected", looksLikeBase64(b64("some longer text here")), true);
check("whitespace-wrapped base64 is detected", looksLikeBase64(`${b64("x".repeat(64))}\n`), true);
check("bad padding is rejected", looksLikeBase64("abcde"), false);
check("non-b64 chars rejected", looksLikeBase64("!!!!not base64!!!!"), false);

// ------------------------------------------------------------ text payloads

console.log("text payloads (decoded, scrubbed, re-encoded)");

{
	const config = JSON.stringify({ token: TOKEN, region: "us-east-1" });
	const result = scrubToolResult(
		{
			content: [{ type: "resource", resource: { uri: "cfg://app", mimeType: "application/json", text: config } }],
		} as any,
		store,
	);
	// plain text resource path (not base64) must already be scrubbed
	const text = JSON.stringify(result.result);
	check("resource text scrubbed", text.includes(TOKEN), false);
	check("region survives", text.includes("us-east-1"), true);
}

{
	// a base64-wrapped config: decoded, scrubbed, re-encoded so it still works
	const payload = b64(JSON.stringify({ apiKey: TOKEN, retries: 3 }));
	const verdict = handleBase64(
		payload,
		{ values: store.scrubbable(), names: store.names() },
		(t) => scrubValue(t, store).value as string,
	);
	check("verdict is text", verdict.kind, "text");
	if (verdict.kind === "text") {
		const decoded = unb64(verdict.value);
		check("decoded payload has no secret", decoded.includes(TOKEN), false);
		check("decoded payload still valid JSON", (() => {
			try {
				const o = JSON.parse(decoded);
				return o.retries === 3;
			} catch {
				return false;
			}
		})(), true);
	}
}

{
	// clean base64 must come back byte-identical
	const clean = b64("nothing sensitive in here at all");
	const verdict = handleBase64(clean, { values: store.scrubbable(), names: store.names() }, (t) => t);
	check("clean payload is clean", verdict.kind, "clean");
	if (verdict.kind === "clean") check("clean payload unchanged", verdict.value === clean, true);
}

// ---------------------------------------------------------- binary payloads

console.log("binary payloads (byte-searched, dropped when dirty)");

{
	// a real PNG header followed by the secret bytes — genuinely binary
	const png = Buffer.concat([
		Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01, 0x02, 0x03]),
		Buffer.from(TOKEN, "utf8"),
		Buffer.from([0xff, 0xfe, 0xfd]),
	]);
	const verdict = handleBase64(
		png.toString("base64"),
		{ values: store.scrubbable(), names: store.names() },
		(t) => t,
	);
	check("binary with a secret is dirty", verdict.kind, "binary-dirty");
	if (verdict.kind === "binary-dirty") check("names the secret, not its value", verdict.secretNames, ["github_token"]);
}

{
	// clean binary must pass through untouched
	const bin = Buffer.from(Array.from({ length: 64 }, (_, i) => (i * 7) % 256));
	const original = bin.toString("base64");
	const verdict = handleBase64(original, { values: store.scrubbable(), names: store.names() }, (t) => t);
	check("clean binary passes through", verdict.kind, "binary-clean");
	if (verdict.kind === "binary-clean") check("binary unchanged", verdict.value === original, true);
}

// ------------------------------------------- through the real content shapes

console.log("MCP content shapes");

{
	const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 1, 2]), Buffer.from(TOKEN)]);
	const { result, stats } = scrubToolResult(
		{
			content: [
				{ type: "text", text: "here is the artifact" },
				{ type: "image", data: png.toString("base64"), mimeType: "image/png" },
			],
		} as any,
		store,
	);
	const json = JSON.stringify(result);
	check("image payload dropped", json.includes(TOKEN), false);
	check("drop is counted", stats.dropped, 1);
	check("text block survives", json.includes("here is the artifact"), true);
	check("block count preserved", (result as any).content.length, 2);
}

{
	// EmbeddedResource carrying a base64 blob
	const blob = Buffer.concat([Buffer.from([0x00, 0xff]), Buffer.from(TOKEN)]);
	const { result, stats } = scrubToolResult(
		{
			content: [{ type: "resource", resource: { uri: "f://bin", mimeType: "application/octet-stream", blob: blob.toString("base64") } }],
		} as any,
		store,
	);
	check("embedded blob dropped", JSON.stringify(result).includes(TOKEN), false);
	check("blob drop counted", stats.dropped, 1);
}

{
	// AudioContent.data
	const audio = Buffer.concat([Buffer.from([0xff, 0xfb, 0x90]), Buffer.from(TOKEN)]);
	const { result, stats } = scrubToolResult(
		{ content: [{ type: "audio", data: audio.toString("base64"), mimeType: "audio/mpeg" }] } as any,
		store,
	);
	check("audio payload dropped", JSON.stringify(result).includes(TOKEN), false);
	check("audio drop counted", stats.dropped, 1);
}

{
	// a signed URL in a ResourceLink is plain text and must be caught
	const { result } = scrubToolResult(
		{
			content: [
				{ type: "resource_link", name: "download", uri: `https://x.dev/f?sig=${TOKEN}`, mimeType: "application/zip" },
			],
		} as any,
		store,
	);
	check("signed URL scrubbed", JSON.stringify(result).includes(TOKEN), false);
}

{
	// a clean image must NOT be dropped — over-scrubbing would break agents
	const png = Buffer.from(Array.from({ length: 128 }, (_, i) => (i * 13) % 256));
	const { result, stats } = scrubToolResult(
		{ content: [{ type: "image", data: png.toString("base64"), mimeType: "image/png" }] } as any,
		store,
	);
	check("clean image kept intact", (result as any).content[0].data, png.toString("base64"));
	check("clean image not counted as dropped", stats.dropped ?? 0, 0);
}

{
	// no secret store configured: nothing should be decoded or dropped
	const clean = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]).toString("base64");
	const { result, stats } = scrubToolResult({ content: [{ type: "image", data: clean, mimeType: "image/png" }] } as any);
	check("no store: payload untouched", (result as any).content[0].data, clean);
	check("no store: nothing dropped", stats.dropped ?? 0, 0);
}

rmSync(workdir, { recursive: true, force: true });

console.log("=".repeat(52));
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);