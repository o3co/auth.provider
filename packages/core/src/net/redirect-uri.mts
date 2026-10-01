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
 * - **Query names**: only `[A-Za-z0-9_-]`, each parameter named, no `;`
 *   anywhere; the authorization response's names are refused ignoring case,
 *   `_` and `-`. Values are otherwise free. Covered: names as written and
 *   those normalizations, not a mapping a client configures.
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
 * A name as the common normalizations see it: case folded, `_` and `-`
 * removed (`_state`, `errorDescription` key as response names). Applied only
 * to allowlisted, hence ASCII, names, so `toLowerCase` is ASCII folding.
 */
const nameKey = (name: string): string => name.toLowerCase().replace(/[_-]/g, "");

/**
 * The parameters an authorization response appends, by {@link nameKey}.
 * Invariant: a response adds a name here before it starts appending it.
 */
const RESPONSE_PARAMETERS: ReadonlyMap<string, string> = new Map(
	["code", "state", "iss", "error", "error_description"].map((name) => [nameKey(name), name]),
);

/**
 * The query's names as written: `url.search` UNDECODED, split on `&`, each
 * name running to the first `=`; `[]` for none. The parser decodes nothing,
 * but trims leading and trailing C0 and spaces (`?foo ` is `?foo`), as the
 * builder does.
 */
function queryNames(url: URL): string[] {
	const query = url.search.slice(1);
	if (query === "") return [];
	return query.split("&").map((pair) => {
		const equals = pair.indexOf("=");
		return equals === -1 ? pair : pair.slice(0, equals);
	});
}

/**
 * The query's verdict. `;` is refused anywhere, values included: some parsers
 * split on it. Then the first offending name decides.
 */
function queryRejection(url: URL): RedirectUriRejection | null {
	if (url.search.includes(";")) return { reason: "query-name-invalid" };
	for (const name of queryNames(url)) {
		if (!QUERY_NAME.test(name)) return { reason: "query-name-invalid" };
		const reserved = RESPONSE_PARAMETERS.get(nameKey(name));
		if (reserved !== undefined) return { reason: "reserved-parameter", parameter: reserved };
	}
	return null;
}

/**
 * Which of `names` a URI's query carries (first match, as given in `names`),
 * compared as {@link checkRedirectUri} compares names; `undefined` for none or
 * an unparsable URI. For a module that reserves names of its own. A name the
 * grammar refuses is never matched here: call {@link checkRedirectUri} too.
 */
export function redirectUriQueryCarries(uri: string, names: readonly string[]): string | undefined {
	let url: URL;
	try {
		url = new URL(uri);
	} catch {
		return undefined;
	}
	const byKey = new Map(names.map((name) => [nameKey(name), name]));
	for (const name of queryNames(url)) {
		if (!QUERY_NAME.test(name)) continue;
		const carried = byKey.get(nameKey(name));
		if (carried !== undefined) return carried;
	}
	return undefined;
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
				'case, "_" and "-"): an authorization response carries that parameter, so a client ' +
				"redirected there could receive it twice, or read the registered value as the response's"
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
