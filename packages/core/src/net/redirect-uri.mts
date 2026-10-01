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
 * The registered-redirect-URI shape vocabulary. It stops misconfiguration at
 * boot, where the operator is looking; the security boundary is elsewhere
 * (registration is operator-only, matching is string equality bar the RFC 8252
 * §7.3 loopback port, see {@link matchesRegisteredRedirectUri}, and PKCE is
 * mandatory).
 *
 * - **Parse, then check; never compare raw strings.** WHATWG `new URL()`
 *   strips ASCII tab/newline and lowercases the scheme, so `java\tscript:`
 *   reaches the deny check as `javascript:`, which a raw prefix match would
 *   miss. Anything the parser refuses, this refuses.
 * - **No fragment** (RFC 6749 §3.1.2 MUST NOT) and **no userinfo**: both
 *   corrupt the redirect response and have no legitimate registration use.
 * - **`https:`; `http:` for loopback hosts only**, via {@link isLoopbackHostname}.
 * - **Custom schemes by grammar, not enumeration**: only a scheme containing a
 *   `.` (RFC 8252 §7.1 reverse-domain, `com.example.app:/callback`). Every
 *   executable/pseudo scheme is dotless and falls out structurally; a deny
 *   check on the scheme's first dot-separated label stops a dotted spelling
 *   such as `javascript.something:`.
 * - **No escape hatch, deliberately**: a dotless custom scheme (`myapp:`) is
 *   refused with no config bypass. RFC 8252 §7.1 says SHOULD reverse-domain,
 *   and a flag would be two spellings for one decision.
 * - **Query names**: only `[A-Za-z0-9_-]`, each parameter named, and no `;`
 *   anywhere in the query. The authorization response's own names (`code`,
 *   `state`, `iss`, `error`, `error_description`) are refused, compared
 *   ignoring case, `_` and `-`. Values are otherwise free. A registered
 *   parameter of the same effective name as one this provider appends would
 *   reach the client beside it, and which one a client reads is its
 *   framework's choice; an allowlist on names leaves no spelling a framework
 *   could read as another name (`iss[]`, `;iss=`, `%69ss`).
 */

/** Why a registered redirect URI was refused. */
export type RedirectUriRejection =
	| { reason: "unparsable" }
	| { reason: "control-characters" }
	| { reason: "fragment" }
	| { reason: "userinfo" }
	| { reason: "http-non-loopback"; hostname: string }
	| { reason: "executable-scheme"; scheme: string }
	| { reason: "scheme-not-reverse-domain"; scheme: string }
	| { reason: "query-name-invalid" }
	| { reason: "reserved-parameter"; parameter: string };

/**
 * First labels of executable/pseudo schemes, denied even when a dotted
 * spelling would satisfy the reverse-domain grammar. Defense in depth behind
 * the grammar rule — see the module doc.
 */
const EXECUTABLE_SCHEME_LABELS: ReadonlySet<string> = new Set([
	"javascript",
	"vbscript",
	"data",
	"blob",
	"file",
	"filesystem",
	"about",
	"intent",
]);

/** A query parameter name a redirect URI may carry: nothing a parser could read as another name. */
const QUERY_NAME = /^[A-Za-z0-9_-]+$/;

/**
 * A query name as name-normalizing middleware sees it: case folded, `_` and
 * `-` removed. Such middleware (camelCase to snake_case, a leading `_`
 * stripped) keeps a name's letters and digits and changes only these, so
 * `_state`, `errorDescription` and `error-description` all key as a response
 * parameter. Only ever applied to an allowlisted, hence ASCII, name, where
 * `toLowerCase` is exact ASCII folding.
 */
const nameKey = (name: string): string => name.toLowerCase().replace(/[_-]/g, "");

/**
 * The parameters an authorization response appends to a client's redirect
 * URI, by {@link nameKey}.
 *
 * Invariant: a response that starts appending another name onto a client
 * redirect adds it here in the same change.
 */
const RESPONSE_PARAMETERS: ReadonlyMap<string, string> = new Map(
	["code", "state", "iss", "error", "error_description"].map((name) => [nameKey(name), name]),
);

/**
 * The query's verdict, read from `url.search` UNDECODED: the WHATWG parser has
 * found where the query starts and ends, and only percent-encodes characters
 * the name allowlist refuses anyway, so a name is judged as it was written.
 * `URLSearchParams` would decode `%69ss` into `iss`, turn `+` into a space and
 * drop empty pairs, judging a different string from the one registered.
 *
 * Pairs are split on `&`; a name runs to the first `=`, or is the whole pair.
 * A `;` is refused anywhere, values included: some parsers split on it too and
 * would read `?a=x;iss=y` as carrying `iss`.
 */
function queryRejection(url: URL): RedirectUriRejection | null {
	const query = url.search.slice(1); // "" for no query and for a bare trailing `?`
	if (query === "") return null;
	if (query.includes(";")) return { reason: "query-name-invalid" };
	for (const pair of query.split("&")) {
		const equals = pair.indexOf("=");
		const name = equals === -1 ? pair : pair.slice(0, equals);
		if (!QUERY_NAME.test(name)) return { reason: "query-name-invalid" };
		const reserved = RESPONSE_PARAMETERS.get(nameKey(name));
		if (reserved !== undefined) return { reason: "reserved-parameter", parameter: reserved };
	}
	return null;
}

/**
 * Check one registered redirect URI against the shape rules above. Returns
 * `null` when acceptable, a {@link RedirectUriRejection} otherwise. Pure and
 * exported (with {@link describeRedirectUriRejection}) so a custom
 * `ClientRepository` — which bypasses `ClientEntrySchema` by design — can hold
 * its own registrations to the same vocabulary.
 */
export function checkRedirectUri(raw: string): RedirectUriRejection | null {
	let url: URL;
	try {
		url = new URL(raw);
	} catch {
		return { reason: "unparsable" };
	}
	// Checked after the parse, so a tab-smuggled `java\tscript:` reports as the
	// executable scheme it parses into. Refused either way: WHATWG strips ASCII
	// tab/newline/CR but redirect_uri matching never does, so such a
	// registration could never match a request.
	const scheme = url.protocol.slice(0, -1); // parsed: lowercased, tab/newline-stripped
	if (/[\t\n\r]/.test(raw)) {
		const firstLabel = scheme.split(".")[0] ?? scheme;
		return EXECUTABLE_SCHEME_LABELS.has(firstLabel)
			? { reason: "executable-scheme", scheme }
			: { reason: "control-characters" };
	}
	// `url.hash` is "" for both "no fragment" and a bare trailing "#"; the raw
	// string tells the two apart, and §3.1.2's MUST NOT covers both.
	if (url.hash !== "" || raw.includes("#")) return { reason: "fragment" };
	if (url.username !== "" || url.password !== "") return { reason: "userinfo" };

	const schemeRejection = checkScheme(scheme, url);
	if (schemeRejection !== null) return schemeRejection;
	// The shape is acceptable; only then is the query read.
	return queryRejection(url);
}

/** The scheme rules: `https:`, loopback `http:`, or a reverse-domain custom scheme. */
function checkScheme(scheme: string, url: URL): RedirectUriRejection | null {
	if (scheme === "https") return null;
	if (scheme === "http") {
		return isLoopbackHostname(url.hostname)
			? null
			: { reason: "http-non-loopback", hostname: url.hostname };
	}
	const firstLabel = scheme.split(".")[0] ?? scheme;
	if (EXECUTABLE_SCHEME_LABELS.has(firstLabel)) {
		return { reason: "executable-scheme", scheme };
	}
	if (!scheme.includes(".")) {
		return { reason: "scheme-not-reverse-domain", scheme };
	}
	return null;
}

/** Operator-facing wording for one {@link RedirectUriRejection}. */
export function describeRedirectUriRejection(rejection: RedirectUriRejection): string {
	switch (rejection.reason) {
		case "unparsable":
			return "must be an absolute URL";
		case "control-characters":
			return (
				"must not contain tab, newline or carriage-return characters — the URL parser strips " +
				"them, but redirect_uri matching never does, so the registration could never match a request"
			);
		case "fragment":
			return "must not carry a fragment (RFC 6749 §3.1.2)";
		case "userinfo":
			return "must not carry userinfo";
		case "http-non-loopback":
			return `http:// is accepted for loopback hosts only (localhost, 127.0.0.0/8, [::1]); got host ${JSON.stringify(rejection.hostname)}`;
		case "executable-scheme":
			return `scheme ${JSON.stringify(rejection.scheme)} is an executable/pseudo scheme and can never be a redirect target`;
		case "scheme-not-reverse-domain":
			return (
				`custom scheme ${JSON.stringify(rejection.scheme)} must use the RFC 8252 §7.1 reverse-domain shape ` +
				`(e.g. "com.example.app"); dotless legacy schemes are refused, deliberately, with no bypass`
			);
		case "query-name-invalid":
			return (
				'query parameter names may use only letters, digits, "_" and "-", each parameter must ' +
				'have a name, and the query must not contain ";": a client framework can read any other ' +
				'spelling as a different name (iss[] as iss, ";iss=" as a parameter)'
			);
		case "reserved-parameter":
			return (
				`must not carry ${JSON.stringify(rejection.parameter)} in its query (compared ignoring ` +
				'case, "_" and "-"): this provider adds that parameter when it redirects there, so the ' +
				"client would receive it twice, or read the registered value as the response's"
			);
	}
}

/**
 * Whether `url` is the shape RFC 8252 §7.3's port relaxation is written for:
 * an `http:` listener on a loopback IP literal. `localhost` is excluded: it
 * goes through name resolution, which §8.3 discourages for that reason, so it
 * keeps only the plain `http:` carve-out of {@link isLoopbackHostname}.
 */
const isLoopbackHttpListener = (url: URL): boolean =>
	url.protocol === "http:" &&
	// No userinfo (`checkRedirectUri` refuses it on registration), so the
	// authority is a plain `host[:port]` for `withoutAuthorityPort`.
	url.username === "" &&
	url.password === "" &&
	url.hostname !== "localhost" &&
	isLoopbackHostname(url.hostname);

/**
 * `raw` with the authority's `:port` removed, byte for byte, or `null` when
 * the authority cannot be located with certainty.
 *
 * It works on the ORIGINAL string, never a parsed `URL`'s serialization:
 * normalized `href`s would also ignore dot-segments (`/a/../cb` ≡ `/cb`), `\`
 * as a path separator, scheme case and an elided empty path, widening the
 * allowlist by URIs a native app controls. Only the port may differ.
 *
 * Callers must have established via {@link isLoopbackHttpListener} that the
 * value is an `http:` loopback IP literal with no userinfo. A raw spelling
 * without a literal `://` (`http:/127.0.0.1/cb`, which the parser accepts)
 * returns `null` and gets no carve-out, the safe direction.
 */
function withoutAuthorityPort(raw: string): string | null {
	const schemeEnd = raw.indexOf("://");
	if (schemeEnd === -1) return null;
	const authorityStart = schemeEnd + 3;

	// The authority runs to the first path/query/fragment delimiter. `\`
	// counts: WHATWG treats it as `/` for special schemes, so it ends the
	// authority even though it is not what a path normally starts with.
	let authorityEnd = raw.length;
	for (let i = authorityStart; i < raw.length; i++) {
		const c = raw[i];
		if (c === "/" || c === "\\" || c === "?" || c === "#") {
			authorityEnd = i;
			break;
		}
	}
	const authority = raw.slice(authorityStart, authorityEnd);

	// Where the host ends: after `]` for `[::1]`, otherwise the whole thing up
	// to the port colon (a loopback IPv4 literal contains none).
	let hostEnd = 0;
	if (authority.startsWith("[")) {
		const bracket = authority.indexOf("]");
		if (bracket === -1) return null;
		hostEnd = bracket + 1;
	}
	const colon = authority.indexOf(":", hostEnd);
	const host = colon === -1 ? authority : authority.slice(0, colon);

	return raw.slice(0, authorityStart) + host + raw.slice(authorityEnd);
}

/**
 * Whether a presented `redirect_uri` matches one registered entry, the
 * comparison `/authorize` runs against `client.allowedRedirectUris`.
 *
 * **Exact string equality, with one carve-out.** When BOTH sides are `http:`
 * on a loopback IP literal (`127.0.0.0/8`, `[::1]`), the port is dropped from
 * both and everything else is still compared exactly. Every other pair,
 * `localhost` and `https:` included, is a plain string comparison.
 *
 * Why: a native app receiving the response on a loopback interface binds an
 * ephemeral port the OS assigns at run time (RFC 8252 §7.3), so the
 * registration cannot name it. The relaxation is safe because the host is a
 * literal whose traffic never leaves the machine; a loopback *name* would move
 * that guarantee into name resolution, which is why `localhost` is out (§8.3).
 *
 * Not relaxed: the token endpoint's RFC 6749 §4.1.3 binding. Redemption
 * compares the presented `redirect_uri` with `!==` to the URI `/authorize`
 * actually redirected to, port included.
 *
 * The parse decides only whether the carve-out applies; equality runs on the
 * original strings (see {@link withoutAuthorityPort}). An unparsable value on
 * either side falls back to the string comparison rather than throwing.
 */
export function matchesRegisteredRedirectUri(registered: string, presented: string): boolean {
	// Exact equality: the only match outside the carve-out.
	if (registered === presented) return true;

	let registeredUrl: URL;
	let presentedUrl: URL;
	try {
		registeredUrl = new URL(registered);
		presentedUrl = new URL(presented);
	} catch {
		return false;
	}
	if (!isLoopbackHttpListener(registeredUrl) || !isLoopbackHttpListener(presentedUrl)) return false;

	// Port dropped from both ORIGINAL strings, then byte equality — so scheme,
	// host, path, query and fragment are all still compared exactly.
	const registeredKey = withoutAuthorityPort(registered);
	const presentedKey = withoutAuthorityPort(presented);
	return registeredKey !== null && registeredKey === presentedKey;
}
