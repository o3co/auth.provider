/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { isLoopbackHostname } from "./loopback.mjs";

/**
 * The serialized-origin vocabulary: what a configured browser origin may be.
 *
 * Origins are matched against the `Origin` header by exact string equality, so
 * these rules stop entries that parse at boot but never match, a failure with
 * no server-side trace. An entry must equal its own serialized origin
 * (RFC 6454 §6.1, WHATWG URL): scheme, host, and a non-default port only. That
 * one comparison refuses a trailing slash, an explicit default port, an
 * uppercase host, a path / query / fragment, and userinfo.
 *
 * Stated separately:
 * - No wildcards (WHATWG accepts `*` in a host, so the comparison alone would
 *   pass it). There is no subdomain matching: a wildcard entry turns a
 *   forgotten subdomain takeover into a token endpoint the attacker can read.
 * - `https:`, or `http:` for a loopback host ({@link isLoopbackHostname}, the
 *   carve-out `checkSecureEndpoint` and the redirect checks share). Opaque
 *   origins (custom schemes, `data:`) are refused: the browser sends
 *   `Origin: null`, which every sandboxed document shares.
 */

/**
 * Reads a configured origin allowlist from either legitimate shape: an array
 * (a config file, a hand-built `AppConfig`) or a comma-separated string (the
 * only way an environment variable carries a list). Used for a composition's
 * CORS list, and by the WebAuthn package for the environment spelling of
 * `webauthn.origin` / `webauthn.topOrigin`.
 *
 * The string is split, trimmed, and empty pieces dropped (an exported-but-empty
 * variable is no list). The array keeps every string entry trimmed, empty ones
 * included so the entry check refuses them by index, and drops non-strings.
 * Anything else yields no origins; the caller decides whether to warn.
 *
 * Only the shape is normalised: every entry is still checked with
 * {@link checkSerializedOrigin} (by the schema and the CORS middleware, or by
 * `webauthnConfigSchema`), so this cannot widen an allowlist. A comma inside a
 * host (`https://a,b.example`) cannot be written in the string form: the piece
 * after it has no scheme and is refused. It lives here, not in a schema, so
 * every reader of an origin list reads it the same way.
 */
export function normalizeAllowedOrigins(raw: unknown): readonly string[] {
	if (Array.isArray(raw)) {
		return raw.flatMap((entry) => (typeof entry === "string" ? [entry.trim()] : []));
	}
	if (typeof raw !== "string") return [];
	// An exported-but-empty variable — the .env / compose / ConfigMap shape —
	// reads as "no origins", i.e. CORS off, which is what the unset key means.
	return raw
		.split(",")
		.map((entry) => entry.trim())
		.filter((entry) => entry !== "");
}

/** Why a configured origin was refused. */
export type SerializedOriginRejection =
	| { reason: "unparsable" }
	| { reason: "wildcard" }
	| { reason: "opaque-origin"; scheme: string }
	| { reason: "insecure-scheme"; scheme: string; hostname: string }
	| { reason: "not-serialized"; serialized: string };

/**
 * Checks one configured origin against the rules above: `null` when
 * acceptable, a {@link SerializedOriginRejection} otherwise. Shared by the
 * config schema and the CORS middleware, which re-applies it so a hand-built
 * `AppConfig` cannot install an entry the schema would refuse.
 */
export function checkSerializedOrigin(raw: string): SerializedOriginRejection | null {
	// Before the parse: WHATWG accepts `*` inside a host, so `URL.origin` would
	// hand it back unchanged and the identity check below would pass it.
	if (raw.includes("*")) return { reason: "wildcard" };

	let url: URL;
	try {
		url = new URL(raw);
	} catch {
		return { reason: "unparsable" };
	}

	const scheme = url.protocol.slice(0, -1); // parsed: lowercased
	// `"null"` is what WHATWG serializes for every scheme without a tuple
	// origin. Reported before the identity check, whose "did you mean" would
	// otherwise suggest the string `null`.
	if (url.origin === "null") return { reason: "opaque-origin", scheme };

	if (raw !== url.origin) return { reason: "not-serialized", serialized: url.origin };

	if (scheme === "https") return null;
	if (scheme === "http" && isLoopbackHostname(url.hostname)) return null;
	return { reason: "insecure-scheme", scheme, hostname: url.hostname };
}

/** Operator-facing wording for one {@link SerializedOriginRejection}. */
export function describeSerializedOriginRejection(rejection: SerializedOriginRejection): string {
	switch (rejection.reason) {
		case "unparsable":
			return 'must be an absolute origin, e.g. "https://app.example.com"';
		case "wildcard":
			return (
				"must not contain a wildcard — matching against the Origin header is exact string " +
				"equality, so a wildcard entry matches nothing; list each origin in full"
			);
		case "opaque-origin":
			return (
				`scheme ${JSON.stringify(rejection.scheme)} has no tuple origin — a browser sends the ` +
				"literal `Origin: null` for such documents, which every sandboxed document shares and " +
				"an allowlist therefore cannot name"
			);
		case "insecure-scheme":
			return (
				`http:// is accepted for loopback hosts only (localhost, 127.0.0.0/8, [::1]); got ` +
				`scheme ${JSON.stringify(rejection.scheme)} on host ${JSON.stringify(rejection.hostname)}`
			);
		case "not-serialized":
			return (
				"must be a bare origin — scheme, host, and a port only when it is not the scheme's " +
				`default — with no trailing slash, path, query, fragment or userinfo; did you mean ` +
				`${JSON.stringify(rejection.serialized)}?`
			);
	}
}
