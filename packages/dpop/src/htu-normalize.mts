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
 * Consecutive slashes are preserved (the spec removes only dot segments). A
 * trailing slash is kept only if the original raw input had one: WHATWG URL
 * already resolves `/a/b/..` to `/a/`, and that slash is stripped.
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
 * Normalise an `htu` URI per RFC 9449 §6 / RFC 3986 §6.2.2, returning the
 * canonical string for equality comparison.
 *
 * Rules applied (in order):
 *   1. Parse via WHATWG URL — lowercases scheme and host, IDN → Punycode.
 *   2. Strip query (`?`) and fragment (`#`).
 *   3. Remove default port (443 for https, 80 for http).
 *   4. Decode unreserved percent-encoded sequences in the path.
 *   5. Remove dot segments from the path (RFC 3986 §5.2.4).
 *   6. Normalise empty path to `/`.
 *
 * WHATWG URL does not perform rule 4, nor rule 5 for already-parsed inputs.
 */
export const normalizeHtu = (raw: string): string => {
	const url = new URL(raw);
	// Reject userinfo: the canonical reconstruction below drops it, so a proof
	// carrying `https://attacker:pwn@as.example/oauth/token` would otherwise
	// equality-match the server-built URL. RFC 9449 §4 gives userinfo no
	// meaning at the token endpoint; the verifier surfaces `malformed_proof`.
	if (url.username !== "" || url.password !== "") {
		// Not the userinfo itself: it is the client's text, and this error
		// travels on as a refusal's cause.
		throw new Error("normalizeHtu: htu must not contain userinfo");
	}
	// Strip query and fragment (RFC 3986 §6.2.2).
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
	// WHATWG URL's parse-time `..` resolution may add a trailing slash
	// (`/a/b/..` → `/a/`); strip it when the original input had none.
	let rawPath = url.pathname; // WHATWG URL always starts pathname with "/".
	if (!originalHadTrailingSlash && rawPath.length > 1 && rawPath.endsWith("/")) {
		rawPath = rawPath.slice(0, -1);
	}
	const decodedPath = decodeUnreservedPercent(rawPath);
	const normalizedPath =
		decodedPath === "" ? "/" : removeDotSegments(decodedPath, originalHadTrailingSlash);

	// Reconstruct by hand: url.toString() would re-encode the decoded
	// characters. `url.hostname` keeps IPv6 brackets (`[::1]`), so an IP
	// literal survives (pinned in `__tests__/htu-normalize.test.mts`).
	const portPart = url.port ? `:${url.port}` : "";
	return `${url.protocol}//${url.hostname}${portPart}${normalizedPath}`;
};
