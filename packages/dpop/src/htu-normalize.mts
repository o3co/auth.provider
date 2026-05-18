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

/**
 * RFC 3986 §6.2.2 unreserved character set: ALPHA / DIGIT / "-" / "." / "_" / "~".
 * Characters matching this set MUST be decoded from percent-encoded form.
 * All other percent-encoded sequences MUST be preserved (uppercased for
 * canonical form, though most WHATWG URL output is already uppercase).
 */
const UNRESERVED = /^[A-Za-z0-9\-._~]$/;

/**
 * Decode percent-encoded sequences that encode unreserved characters
 * (RFC 3986 §2.3). Sequences that encode reserved or special characters
 * are left as-is. This is required because WHATWG URL does NOT perform
 * this normalisation for the path component.
 */
const decodeUnreservedPercent = (s: string): string => {
	return s.replace(/%([0-9A-Fa-f]{2})/g, (match, hex) => {
		const code = parseInt(hex, 16);
		const ch = String.fromCharCode(code);
		return UNRESERVED.test(ch) ? ch : match.toUpperCase();
	});
};

/**
 * Remove dot segments from a URI path per RFC 3986 §5.2.4 + §6.2.2.3.
 *
 * Preserves multiple consecutive slashes (the spec only removes dot segments,
 * not double-slashes). Preserves trailing slash if the *original input* had
 * one — trailing slash produced by resolving a `..` segment (e.g. `/a/b/..`
 * → `/a/`) is stripped since the original input didn't end with `/`.
 *
 * NOTE: The WHATWG URL API resolves `.` and `..` during parsing, so
 * `url.pathname` for `https://as/a/b/..` already yields `/a/`. We operate on
 * the original raw URL path (before WHATWG parsing) to detect whether the
 * caller supplied a trailing slash.
 */
const removeDotSegments = (path: string, originalHadTrailingSlash: boolean): string => {
	// Split preserves empty strings between consecutive slashes.
	const parts = path.split("/");
	const segments: string[] = [];
	for (const seg of parts) {
		if (seg === ".") {
			// Dot segment — discard.
			continue;
		}
		if (seg === "..") {
			// Parent segment — pop last (but never pop the leading empty string
			// that corresponds to the root slash).
			if (segments.length > 1) {
				segments.pop();
			}
			continue;
		}
		segments.push(seg);
	}
	const result = segments.join("/");
	// Re-append trailing slash only when the original input had one.
	return originalHadTrailingSlash && !result.endsWith("/") ? `${result}/` : result;
};

/**
 * Normalise an `htu` URI per RFC 9449 §6 / RFC 3986 §6.2.2.
 *
 * Rules applied (in order):
 *   1. Parse via WHATWG URL — handles scheme/host lowercase + IDN ASCII.
 *   2. Strip query (`?`) and fragment (`#`).
 *   3. Remove default port (443 for https, 80 for http).
 *   4. Decode unreserved percent-encoded sequences in the path.
 *   5. Remove dot segments from the path (RFC 3986 §5.2.4).
 *   6. Normalise empty path to `/`.
 *
 * WHATWG URL (used internally) already performs:
 *   - Scheme + host lowercasing.
 *   - IDN (internationalized domain) → ASCII-compatible (Punycode) form.
 *
 * It does NOT perform:
 *   - Unreserved character decoding in the path (rule 4).
 *   - Dot-segment removal for already-parsed inputs (rule 5).
 *
 * Returns the canonical `htu` string ready for equality comparison.
 *
 * Per Wave 2 Phase 2 spec §7.
 */
export const normalizeHtu = (raw: string): string => {
	const url = new URL(raw);
	// Reject userinfo: WHATWG URL preserves `username`/`password` but the
	// canonical reconstruction below drops them, so without this check a
	// proof carrying `https://attacker:pwn@as.example/oauth/token` would
	// normalize to `https://as.example/oauth/token` and equality-match the
	// server-built URL — weakening the htu binding check. RFC 9449 §4
	// gives userinfo no meaning at the token endpoint; reject loudly so
	// the verifier surfaces a `malformed_proof` audit signal.
	if (url.username !== "" || url.password !== "") {
		throw new Error(
			`normalizeHtu: htu must not contain userinfo (got "${url.username}:***" prefix)`,
		);
	}
	// Strip query and fragment (rules from spec §7 / RFC 3986 §6.2.2).
	url.search = "";
	url.hash = "";

	// Remove default ports (RFC 3986 §6.2.3).
	if (
		(url.protocol === "https:" && url.port === "443") ||
		(url.protocol === "http:" && url.port === "80")
	) {
		url.port = "";
	}

	// Determine whether the original input had a trailing slash BEFORE the
	// WHATWG URL parser resolves dot segments (which may add `/` for `..`).
	// Strip query/fragment from the raw string first, then check the last char.
	const rawWithoutQF = raw.split("?")[0].split("#")[0];
	const originalHadTrailingSlash = rawWithoutQF.length > 1 && rawWithoutQF.endsWith("/");

	// Normalise path: unreserved decode + dot-segment removal + empty → /.
	//
	// WHATWG URL resolves `.` / `..` segments at parse time, which may
	// introduce a trailing slash (e.g. `/a/b/..` → `/a/`). Strip it when
	// the original input did not have a trailing slash, so the normalised
	// form respects the caller's intent rather than the resolver's artifact.
	let rawPath = url.pathname; // WHATWG URL always starts pathname with "/".
	if (!originalHadTrailingSlash && rawPath.length > 1 && rawPath.endsWith("/")) {
		rawPath = rawPath.slice(0, -1);
	}
	const decodedPath = decodeUnreservedPercent(rawPath);
	const normalizedPath =
		decodedPath === "" ? "/" : removeDotSegments(decodedPath, originalHadTrailingSlash);

	// Reconstruct the canonical URL string without using url.toString()
	// to avoid WHATWG URL applying its own re-encoding to our decoded characters.
	const portPart = url.port ? `:${url.port}` : "";
	return `${url.protocol}//${url.hostname}${portPart}${normalizedPath}`;
};
