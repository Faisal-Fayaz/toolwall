/**
 * Base64 payload handling for response scrubbing.
 *
 * MCP tool results can carry data outside of text: ImageContent and
 * AudioContent have `data`, and EmbeddedResource has `resource.blob` — all
 * base64. The string walk in scrub.ts sees them as opaque text and leaves them
 * alone, so a credential served as base64 reaches the model untouched.
 *
 * Two shapes, handled differently:
 *
 *   - Decodes as TEXT (a config file, JSON, a signed URL, a cert). Scrub the
 *     decoded text and re-encode, so the payload still works for the agent.
 *
 *   - Genuinely BINARY (an image, audio). Byte-search it. If a secret is
 *     present, the block cannot be safely re-rendered, so it is DROPPED and
 *     replaced with a visible note.
 *
 * Known limit, stated plainly: a credential rendered as *pixels* in a
 * screenshot is invisible to byte search. That is OCR, and we do not claim it.
 * Scrubbing reduces accidental exposure; it is not a complete control.
 */

/** Keys that carry a base64 payload per the MCP content schemas. */
const BASE64_FIELDS = new Set(["data", "blob"]);

/** Below this, a base64-looking string is far more likely to be an ordinary word. */
const MIN_BASE64_LENGTH = 16;

const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

/** Share of characters that must be printable for a buffer to count as text. */
const TEXT_RATIO = 0.9;

export type Base64Verdict =
	| { kind: "not-base64" }
	| { kind: "clean"; value: string }
	/** Decodes to text; re-encoded after scrubbing. */
	| { kind: "text"; value: string }
	/** Binary and clean — pass through byte-identical. */
	| { kind: "binary-clean"; value: string }
	/** Binary containing a secret: the block must be dropped, not rewritten. */
	| { kind: "binary-dirty"; secretNames: string[] };

export function looksLikeBase64(value: string): boolean {
	if (typeof value !== "string") return false;
	const compact = value.replace(/\s+/g, "");
	if (compact.length < MIN_BASE64_LENGTH) return false;
	if (compact.length % 4 !== 0) return false;
	return B64_RE.test(compact);
}

/** Decode base64 to a Buffer, or null if it is not decodable. */
function decode(value: string): Buffer | null {
	const compact = value.replace(/\s+/g, "");
	try {
		const buf = Buffer.from(compact, "base64");
		// Buffer.from is permissive: it silently drops invalid characters, so
		// confirm a round trip before trusting the bytes.
		if (buf.length === 0) return null;
		if (buf.toString("base64").replace(/=+$/, "") !== compact.replace(/=+$/, "")) return null;
		return buf;
	} catch {
		return null;
	}
}

/** Does this buffer look like decoded text rather than an image? */
function isProbablyText(buf: Buffer): boolean {
	const decoded = buf.toString("utf8");
	if (decoded.includes("\uFFFD")) return false; // replacement char => not text
	let printable = 0;
	for (const ch of decoded) {
		const code = ch.codePointAt(0)!;
		if (code === 9 || code === 10 || code === 13 || (code >= 32 && code < 127) || code > 160) printable++;
	}
	return printable / decoded.length >= TEXT_RATIO;
}

/**
 * Classify and scrub one base64 field.
 *
 * `scrubText` is injected so this module stays independent of the scrubber
 * (and so tests can drive it without constructing a SecretStore).
 */
export function handleBase64(
	value: string,
	secrets: { values: string[]; names: string[] },
	scrubText: (text: string) => string,
): Base64Verdict {
	if (!looksLikeBase64(value)) return { kind: "not-base64" };

	const buf = decode(value);
	if (!buf) return { kind: "not-base64" };

	if (isProbablyText(buf)) {
		const original = buf.toString("utf8");
		const cleaned = scrubText(original);
		if (cleaned === original) return { kind: "clean", value };
		return { kind: "text", value: Buffer.from(cleaned, "utf8").toString("base64") };
	}

	// Binary: byte-search. Longest secret first, so an overlapping short
	// secret cannot claim credit for a longer match.
	const haystack = buf;
	const secretValues = [...secrets.values].sort((a, b) => b.length - a.length);
	for (const [i, secret] of secretValues.entries()) {
		if (haystack.includes(Buffer.from(secret, "utf8"))) {
			return { kind: "binary-dirty", secretNames: [secrets.names[i] ?? "unknown"] };
		}
	}
	return { kind: "binary-clean", value };
}

/** Is this object one of the content shapes that carries a base64 field? */
export function hasBase64Field(obj: unknown): boolean {
	if (!obj || typeof obj !== "object") return false;
	for (const key of Object.keys(obj as Record<string, unknown>)) {
		if (BASE64_FIELDS.has(key) && looksLikeBase64(String((obj as any)[key] ?? ""))) return true;
		// EmbeddedResource nests under `resource`
		if (key === "resource" && hasBase64Field((obj as any)[key])) return true;
	}
	return false;
}

export { BASE64_FIELDS };