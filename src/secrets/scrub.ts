/**
 * Response scrubbing — the exfiltration control.
 *
 * A tool's result is the last point where toolwall still has authority. Once a
 * live credential is in the model's context, nothing downstream can revoke it:
 * the model can paste it into an issue, a commit message, a web request, or
 * another tool call, and no policy is consulted for that.
 *
 * So every upstream response passes through here before the agent sees it.
 * Two layers, because neither alone is sufficient:
 *
 *   1. KNOWN values — every secret toolwall brokers, scrubbed literally. This
 *      is exact, but only covers secrets we were told about.
 *   2. SHAPED tokens — high-confidence credential shapes (ghp_, sk-, AKIA…,
 *      Bearer, PEM blocks). This catches secrets nobody told us about, at the
 *      cost of occasionally masking something that merely looks like one.
 *
 * False positives are the accepted trade-off here, and they are deliberately
 * visible in the output so the agent can tell something was removed rather
 * than silently receiving a truncated string.
 */

import { handleBase64, BASE64_FIELDS } from "./base64.js";
import type { SecretStore } from "./store.js";

/**
 * Credential shapes worth scrubbing even when toolwall was never told the
 * value. Anchored and specific — a loose pattern would redact ordinary text.
 */
const TOKEN_PATTERNS: RegExp[] = [
	// GitHub
	/\bgh[pousr]_[A-Za-z0-9]{16,}\b/g,
	// OpenAI / Anthropic style
	/\bsk-[A-Za-z0-9_-]{20,}\b/g,
	// AWS access key id
	/\bAKIA[0-9A-Z]{16}\b/g,
	// Google API key
	/\bAIza[0-9A-Za-z_-]{35}\b/g,
	// Slack
	/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
	// JWT
	/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
	// Private key blocks
	/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
	// Authorization headers
	/\b(?:Bearer|Basic|token)\s+[A-Za-z0-9._~+/=-]{16,}/gi,
];

/** Key names whose value is a credential regardless of shape. */
const SENSITIVE_KEY_RE =
	/^(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret|authorization|credential|auth|session[_-]?id|refresh[_-]?token|private[_-]?token|passphrase)$/i;

export interface ScrubStats {
	/** Total replacements, so the caller can log that something was removed. */
	count: number;
	names: string[]; // secret names (never values) that were hit
	patterns: number;
	/** Binary payloads dropped because they contained a secret. */
	dropped?: number;
}

/**
 * Scrub a string. Returns the clean text plus what was removed — callers should
 * surface the fact of removal, not the value.
 */
export function scrubString(input: string, secrets?: SecretStore): { text: string; stats: ScrubStats } {
	if (typeof input !== "string" || input === "") {
		return { text: input, stats: { count: 0, names: [], patterns: 0 } };
	}

	let text = input;
	const names = new Set<string>();
	let patterns = 0;
	let count = 0;

	// Layer 1: known brokered secrets.
	if (secrets) {
		for (const name of secrets.names()) {
			const value = secrets.value(name);
			if (!value || value.length < 8) continue;
			if (!text.includes(value)) continue;
			names.add(name);
			text = text.split(value).join(`[redacted:${name}]`);
			count++;
		}
	}

	// Layer 2: shapes we can recognise without being told the value.
	for (const pattern of TOKEN_PATTERNS) {
		text = text.replace(pattern, () => {
			patterns++;
			count++;
			return "[redacted:token]";
		});
	}

	return { text, stats: { count, names: [...names], patterns } };
}

/**
 * Scrub an arbitrary JSON-ish value. Keys are preserved so the agent can still
 * see the SHAPE of what came back; only values are replaced.
 */
export function scrubValue(value: unknown, secrets?: SecretStore, depth = 0): { value: unknown; stats: ScrubStats } {
	const stats: ScrubStats = { count: 0, names: [], patterns: 0 };
	const seen = new Set<string>();

	const merge = (s: ScrubStats) => {
		stats.count += s.count;
		stats.patterns += s.patterns;
		for (const n of s.names) seen.add(n);
	};

	// A binary payload containing a secret is DROPPED, not rewritten — the
	// bytes cannot be safely re-rendered. Recorded so the caller can say so.
	let dropped = 0;
	const dropMarker = "[redacted:toolwall dropped a binary payload containing a credential]";

	// Only THIS object's own base64 fields. Nested objects (EmbeddedResource's
	// `resource`) are handled by the recursive walk, so re-walking them here
	// would double-count every drop.
	const walkBase64 = (
		walked: Record<string, unknown>,
		raw: Record<string, unknown>,
	): Record<string, unknown> => {
		const out: Record<string, unknown> = { ...walked };
		for (const [k, val] of Object.entries(raw)) {
			if (BASE64_FIELDS.has(k) && typeof val === "string" && secrets) {
				const verdict = handleBase64(
					val,
					{ values: secrets.scrubbable(), names: secrets.names() },
					(text) => scrubString(text, secrets).text,
				);
				if (verdict.kind === "binary-dirty") {
					dropped++;
					merge({ count: 1, names: verdict.secretNames, patterns: 0 });
					out[k] = "";
					continue;
				}
				if (verdict.kind === "text") {
					merge({ count: 1, names: [], patterns: 0 });
					out[k] = verdict.value;
					continue;
				}
				out[k] = verdict.kind === "not-base64" ? scrubString(val, secrets).text : val;
				continue;
			}
			// leave everything else exactly as the ordinary walk produced it
			out[k] = walked[k];
		}
		return out;
	};

	const walk = (v: unknown, d: number): unknown => {
		if (d > 20) return "[deep]";
		if (typeof v === "string") {
			const r = scrubString(v, secrets);
			merge(r.stats);
			return r.text;
		}
		if (Array.isArray(v)) return v.map((x) => walk(x, d + 1));
		if (v && typeof v === "object" && !Array.isArray(v)) {
			const obj = v as Record<string, unknown>;
			const out: Record<string, unknown> = {};
			for (const [k, val] of Object.entries(obj)) {
				if (SENSITIVE_KEY_RE.test(k) && typeof val === "string" && val.length >= 8) {
					out[k] = "[redacted:field]";
					merge({ count: 1, names: [], patterns: 0 });
					continue;
				}
				out[k] = walk(val, d + 1);
			}
			// base64 payloads are handled after the ordinary walk so that the
			// decision to drop a block is made on the original object
			return secrets ? walkBase64(out, obj) : out;
		}
		return v;
	};

	const walked = walk(value, depth);
	stats.names = [...seen];
	if (dropped > 0) stats.dropped = dropped;
	return { value: walked, stats };
}

/**
 * Scrub an MCP tool result in place-of-copy. Only `content` is touched; the
 * envelope (isError, structuredContent, annotations) passes through so the
 * agent's error handling still works.
 */
export function scrubToolResult<T extends Record<string, unknown>>(result: T, secrets?: SecretStore): {
	result: T;
	stats: ScrubStats;
} {
	if (!result || typeof result !== "object") return { result, stats: { count: 0, names: [], patterns: 0 } };

	const total: ScrubStats = { count: 0, names: [], patterns: 0 };
	const seen = new Set<string>();
	const next: Record<string, unknown> = { ...result };

	for (const key of ["content", "structuredContent", "result"]) {
		if (!(key in next)) continue;
		const r = scrubValue(next[key], secrets);
		next[key] = r.value;
		total.count += r.stats.count;
		total.patterns += r.stats.patterns;
		total.dropped = (total.dropped ?? 0) + (r.stats.dropped ?? 0);
		for (const n of r.stats.names) seen.add(n);
	}
	total.names = [...seen];
	return { result: next as T, stats: total };
}