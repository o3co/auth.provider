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
 * string equality bar the RFC 8252 §7.3 loopback port — see
 * {@link matchesRegisteredRedirectUri} — and PKCE is mandatory); what it stops
 * is the misconfig foot-gun, at boot, where the operator is looking.
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
	// refused regardless: WHATWG strips ASCII tab/newline/CR, while nothing
	// downstream ever does — {@link matchesRegisteredRedirectUri} relaxes the
	// loopback port and nothing else. A registration these characters survive
	// into can never match a real request; it is a dead entry that is
	// miserable to diagnose.
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
				`(e.g. "com.example.app"); dotless legacy schemes are refused, deliberately, with no bypass (#395)`
			);
	}
}

/**
 * Whether `url` is the shape RFC 8252 §7.3's port relaxation is written for:
 * an `http:` listener on a loopback IP literal.
 *
 * `localhost` is deliberately excluded. It is a loopback *name*, resolved
 * through the host's name resolution, and §8.3 discourages it for exactly
 * that reason — so it keeps the plain `http:` carve-out
 * {@link isLoopbackHostname} grants every consumer, and gets no second one
 * here. The predicate itself is not restated: this composes on the one home
 * (#364) rather than opening a second dialect of "loopback".
 */
const isLoopbackHttpListener = (url: URL): boolean =>
	url.protocol === "http:" && url.hostname !== "localhost" && isLoopbackHostname(url.hostname);

/**
 * Whether a presented `redirect_uri` matches one registered entry — the
 * runtime comparison `/authorize` runs against `client.allowedRedirectUris`
 * (#483).
 *
 * **Exact string equality, with one carve-out.** When BOTH sides are `http:`
 * on a loopback IP literal (`127.0.0.0/8`, `[::1]`), the port is dropped from
 * both before comparing and everything else — scheme, host, path, query — is
 * still compared exactly. Every other pair, `localhost` and `https:`
 * included, is the string comparison it has always been.
 *
 * Why: a native app receiving the authorization response on a loopback
 * interface binds an **ephemeral port** the OS assigns at run time (RFC 8252
 * §7.3), so the registration cannot name it — `http://127.0.0.1/cb` has to
 * admit `http://127.0.0.1:49152/cb`. The relaxation is safe precisely because
 * the host is a literal: traffic to it never leaves the machine, and the port
 * is the only part the client could not know in advance. A loopback *name*
 * would move that guarantee into name resolution, which is why `localhost` is
 * out (§8.3).
 *
 * What this does NOT relax: the token endpoint's RFC 6749 §4.1.3 binding.
 * `/authorize` records the URI it actually redirected to, and redemption
 * compares the presented `redirect_uri` to that record with `!==` — a
 * different question ("is this the URI this code was issued for") that stays
 * exact, port included.
 *
 * Comparison runs on WHATWG-parsed URLs, so both sides are normalized
 * identically; an unparsable value on either side falls back to the string
 * comparison rather than throwing.
 */
export function matchesRegisteredRedirectUri(registered: string, presented: string): boolean {
	// The pre-#483 behaviour, unchanged, and the answer for every pair the
	// carve-out does not cover.
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

	// Port dropped from both; `href` carries host, path, query and fragment,
	// so everything else is still compared exactly.
	registeredUrl.port = "";
	presentedUrl.port = "";
	return registeredUrl.href === presentedUrl.href;
}
