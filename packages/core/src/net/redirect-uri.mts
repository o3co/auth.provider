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
 * The registered-redirect-URI shape vocabulary (#395, from #293 item 1).
 *
 * A registration carrying `javascript:alert(1)`, a fragment, or userinfo used
 * to boot cleanly and become a valid redirect target — while the logout
 * metadata fields in the same schema were already URL-validated. The wall this
 * checker stands on is elsewhere (registration is operator-only, matching is
 * exact string equality, PKCE is mandatory); what it stops is the misconfig
 * foot-gun, at boot, where the operator is looking.
 *
 * The rules, and why each is shaped the way it is:
 *
 * - **Parse-then-check, never raw string comparison** — the one clause the
 *   #395 falsification pass promoted to a requirement. WHATWG `new URL()`
 *   strips ASCII tab/newline and lowercases the scheme, so `java\tscript:`
 *   REACHES the deny check as `javascript:`; a raw prefix match would have
 *   missed it. Anything the parser refuses, this refuses.
 * - **No fragment** (RFC 6749 §3.1.2 MUST NOT) and **no userinfo** — both are
 *   redirect-response corruption vectors with no legitimate registration use.
 * - **`https:` allowed; `http:` for loopback hosts only** — the same carve-out
 *   `checkSecureEndpoint` and `checkRedirectShape` consume, via the shared
 *   {@link isLoopbackHostname} home (#364).
 * - **Custom schemes by grammar, not enumeration**: allowed only when the
 *   scheme contains a `.` — RFC 8252 §7.1's reverse-domain shape
 *   (`com.example.app:/callback`). Every executable/pseudo scheme
 *   (`javascript:`, `data:`, `blob:`, `file:`, `intent:`, …) is dotless and
 *   falls out structurally, with nothing to keep enumerated. A deny check on
 *   the scheme's FIRST dot-separated label backs it up, so a future
 *   `javascript.something:` spelling cannot ride the grammar in.
 * - **No legacy escape hatch, deliberately**: a dotless custom scheme
 *   (`myapp:`) is refused with no config bypass. That is a documented
 *   capability decision (#395), not an oversight — RFC 8252 §7.1 says SHOULD
 *   reverse-domain, and a quiet flag would be two spellings for one decision.
 */

/** Why a registered redirect URI was refused. */
export type RedirectUriRejection =
	| { reason: "unparsable" }
	| { reason: "control-characters" }
	| { reason: "fragment" }
	| { reason: "userinfo" }
	| { reason: "http-non-loopback"; hostname: string }
	| { reason: "executable-scheme"; scheme: string }
	| { reason: "scheme-not-reverse-domain"; scheme: string };

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
	// AFTER the parse, so a tab-smuggled `java\tscript:` still reports as the
	// executable scheme it parses into rather than as a character problem — but
	// refused regardless: WHATWG strips ASCII tab/newline/CR, while everything
	// downstream matches the registered string EXACTLY (`allowedRedirectUris
	// .includes(...)`). A registration these characters survive into can never
	// match a real request; it is a dead entry that is miserable to diagnose.
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
				"them, but redirect_uri matching is exact, so the registration could never match a request"
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
				`(e.g. "com.example.app"); dotless legacy schemes are refused, deliberately, with no bypass (#395)`
			);
	}
}
