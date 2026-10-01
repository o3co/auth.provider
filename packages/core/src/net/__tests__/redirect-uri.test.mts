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
 * redirect-uri.test.mts — the registered-redirect-URI shape vocabulary.
 *
 * Two requirements are pinned by name: parse-then-check (the tab-smuggled
 * `javascript:` case) and the deliberate absence of a legacy dotless-scheme
 * escape hatch. The query-name rule is pinned over every accepted shape:
 * the allowlist on names, and the authorization response's own names.
 *
 * `matchesRegisteredRedirectUri` is the runtime half — the /authorize
 * allowlist comparison, exact everywhere except the RFC 8252 §7.3 loopback
 * port.
 */
import { describe, expect, it } from "vitest";
import {
	checkRedirectUri,
	describeRedirectUriRejection,
	matchesRegisteredRedirectUri,
	redirectUriQueryCarries,
} from "#/net/redirect-uri.mjs";

const reason = (raw: string) => checkRedirectUri(raw)?.reason;

describe("checkRedirectUri", () => {
	it("accepts https anywhere, and http on loopback only", () => {
		expect(checkRedirectUri("https://app.example/cb")).toBeNull();
		expect(checkRedirectUri("https://app.example:8443/cb?x=1")).toBeNull();
		expect(checkRedirectUri("http://localhost:3000/cb")).toBeNull();
		expect(checkRedirectUri("http://127.0.0.1/cb")).toBeNull();
		expect(checkRedirectUri("http://[::1]:8080/cb")).toBeNull();
		expect(reason("http://app.example/cb")).toBe("http-non-loopback");
	});

	it("refuses fragments and userinfo (RFC 6749 §3.1.2)", () => {
		expect(reason("https://app.example/cb#frag")).toBe("fragment");
		expect(reason("https://app.example/cb#")).toBe("fragment");
		expect(reason("https://user@app.example/cb")).toBe("userinfo");
		expect(reason("https://user:pw@app.example/cb")).toBe("userinfo");
	});

	it("refuses executable/pseudo schemes", () => {
		expect(reason("javascript:alert(1)")).toBe("executable-scheme");
		expect(reason("data:text/html,x")).toBe("executable-scheme");
		expect(reason("blob:https://x/y")).toBe("executable-scheme");
		expect(reason("file:///etc/passwd")).toBe("executable-scheme");
		expect(reason("intent://x#Intent;end")).toMatch(/executable-scheme|fragment/);
	});

	it("parse-then-check: a tab-smuggled scheme is judged by its PARSED form", () => {
		// WHATWG URL strips ASCII tab/newline, so this parses with scheme
		// `javascript` — a raw prefix match would miss it.
		expect(reason("java\tscript:alert(1)")).toBe("executable-scheme");
		expect(reason("JAVASCRIPT:alert(1)")).toBe("executable-scheme");
	});

	it("allows RFC 8252 §7.1 reverse-domain custom schemes", () => {
		expect(checkRedirectUri("com.example.app:/oauth2redirect")).toBeNull();
		expect(checkRedirectUri("com.example.app://callback")).toBeNull();
	});

	it("refuses dotless legacy custom schemes — no escape hatch, deliberately", () => {
		// A documented capability decision.
		expect(reason("myapp://callback")).toBe("scheme-not-reverse-domain");
		const rejection = checkRedirectUri("myapp://callback");
		expect(rejection && describeRedirectUriRejection(rejection)).toContain("reverse-domain");
		expect(rejection && describeRedirectUriRejection(rejection)).not.toMatch(/#\d/);
	});

	it("refuses a dotted spelling whose first label is an executable scheme", () => {
		// The deny check backs the grammar up: `javascript.evil` satisfies the
		// dot rule and must still fall.
		expect(reason("javascript.evil:x")).toBe("executable-scheme");
	});

	it("refuses raw control characters that the parser would strip", () => {
		// WHATWG strips tab/newline/CR, but runtime redirect_uri matching is
		// EXACT — a registration these survive into can never match a request.
		// Refused at boot instead of becoming a dead entry.
		expect(reason("https://app.example/\ncb")).toBe("control-characters");
		expect(reason("https://app.example/\tcb")).toBe("control-characters");
		expect(reason("https://app.example/cb\r")).toBe("control-characters");
		// The tab-smuggled executable scheme still reports as WHAT it parses
		// into — the sharper refusal wins.
		expect(reason("java\tscript:alert(1)")).toBe("executable-scheme");
	});

	it("refuses what the parser refuses", () => {
		expect(reason("not a url")).toBe("unparsable");
		expect(reason("%6aavascript:x")).toBe("unparsable");
		expect(reason("/relative/path")).toBe("unparsable");
	});
});

describe("checkRedirectUri — query names", () => {
	// Every redirect-target shape the grammar accepts: https, loopback http
	// (IPv4 and IPv6), and a reverse-domain custom scheme with a path and with
	// an opaque one.
	const BASES = [
		"https://app.example/cb",
		"http://127.0.0.1/cb",
		"http://[::1]:8080/cb",
		"com.example.app:/cb",
		"com.example.app:cb",
	];
	/** The verdict for `?query` on every base, failing with the URI that differs. */
	const verdictsOver = (query: string) => {
		for (const base of BASES) {
			const uri = `${base}?${query}`;
			expect(checkRedirectUri(uri), uri).toEqual(checkRedirectUri(`${BASES[0]}?${query}`));
		}
		return checkRedirectUri(`${BASES[0]}?${query}`);
	};
	const RESPONSE_PARAMETERS = ["code", "state", "iss", "error", "error_description"];

	it("refuses each response parameter name, with a value, an empty value or none, reporting it", () => {
		for (const name of RESPONSE_PARAMETERS) {
			for (const query of [`${name}=x`, `${name}=`, name]) {
				expect(verdictsOver(query), query).toEqual({
					reason: "reserved-parameter",
					parameter: name,
				});
			}
		}
	});

	it("refuses a response parameter name after another name, and repeated", () => {
		for (const name of RESPONSE_PARAMETERS) {
			for (const query of [`a=1&${name}=x`, `tenant=a&b=2&${name}`, `${name}=x&${name}=y`]) {
				expect(verdictsOver(query), query).toEqual({
					reason: "reserved-parameter",
					parameter: name,
				});
			}
		}
	});

	it("compares names ignoring ASCII case, reporting the canonical name", () => {
		for (const [query, parameter] of [
			["ISS=x", "iss"],
			["Code=x", "code"],
			["sTaTe=x", "state"],
			["ERROR=x", "error"],
			["Error_Description=x", "error_description"],
		] as const) {
			expect(verdictsOver(query), query).toEqual({ reason: "reserved-parameter", parameter });
		}
	});

	it("compares names ignoring `_` and `-`, reporting the canonical name", () => {
		// Name-normalizing middleware (camelCase to snake_case, leading `_`
		// stripped) reads these as the response's own names.
		for (const [query, parameter] of [
			["_state=x", "state"],
			["state_=x", "state"],
			["-iss=x", "iss"],
			["_code_=x", "code"],
			["_error=x", "error"],
			["errorDescription=x", "error_description"],
			["error-description=x", "error_description"],
			["errordescription=x", "error_description"],
			["ERROR-DESCRIPTION=x", "error_description"],
			["s_t_a_t_e=x", "state"],
		] as const) {
			expect(verdictsOver(query), query).toEqual({ reason: "reserved-parameter", parameter });
		}
	});

	it("refuses a parameter with no name, and an empty pair", () => {
		for (const query of ["=x", "=", "&", "&&", "a=1&&b=2", "a=1&", "&a=1"]) {
			expect(verdictsOver(query), query).toEqual({ reason: "query-name-invalid" });
		}
	});

	it("refuses `;` anywhere in the query, in a name or in a value", () => {
		for (const query of ["x=1;iss=a", "a=x;y", "a;b", ";", "a=1&b=;"]) {
			expect(verdictsOver(query), query).toEqual({ reason: "query-name-invalid" });
		}
	});

	it("refuses `+` and percent-encoding in a name, decoding nothing", () => {
		for (const query of ["+state=x", "a+b=1", "%69ss=x", "st%61te=x", "%41=1", "state%00x=1"]) {
			expect(verdictsOver(query), query).toEqual({ reason: "query-name-invalid" });
		}
	});

	it("refuses names a client framework can read as another name", () => {
		for (const query of [
			"iss[]=x",
			"iss[0]=x",
			"state[]=x",
			"[]error=x",
			"%20state=x",
			"error.description=x",
			"filter[x]=1",
			"a.b=1",
		]) {
			expect(verdictsOver(query), query).toEqual({ reason: "query-name-invalid" });
		}
	});

	it("refuses non-ASCII names, a space and an apostrophe", () => {
		for (const query of ["ſtate=x", "ıss=x", "ｉss=x", "a b=1", " iss=1", "a'b=1"]) {
			expect(verdictsOver(query), query).toEqual({ reason: "query-name-invalid" });
		}
	});

	it("accepts a trailing `?` with no query", () => {
		for (const base of BASES) expect(checkRedirectUri(`${base}?`), base).toBeNull();
	});

	it("accepts names whose letters differ from every response parameter's", () => {
		for (const query of [
			"x=1",
			"foo",
			"tenant=a&b-c=d_e",
			"issuer=x",
			"codes=x",
			"code_challenge=x",
			"state_id=x",
			"state-id=x",
			"error_uri=x",
			"errorUri=x",
			"A-b_9=1",
		]) {
			expect(verdictsOver(query), query).toBeNull();
		}
	});

	it("leaves values unrestricted apart from `;`", () => {
		for (const query of ["a=[1].x+y%20'", "a=x=y", "a=%26iss%3Db", "a=%3Biss=b", "a=state"]) {
			expect(verdictsOver(query), query).toBeNull();
		}
	});

	it("reports a fragment before reading the query, on every base", () => {
		for (const base of BASES) {
			for (const query of ["iss=x#f", "a=1#", "a[]=1#", "x=1;y#z"]) {
				expect(reason(`${base}?${query}`), `${base}?${query}`).toBe("fragment");
			}
		}
	});

	it("reports another shape problem before reading the query", () => {
		expect(reason("http://evil.example/cb?iss=x")).toBe("http-non-loopback");
		expect(reason("https://u@app.example/cb?state=x")).toBe("userinfo");
		expect(reason("myapp://cb?code=x")).toBe("scheme-not-reverse-domain");
	});

	it("describes both reasons for the operator", () => {
		const reserved = checkRedirectUri("https://app.example/cb?errorDescription=x");
		expect(reserved && describeRedirectUriRejection(reserved)).toMatch(
			/must not carry "error_description" in its query/,
		);
		expect(reserved && describeRedirectUriRejection(reserved)).toMatch(/case, "_" and "-"/);
		// True for every list the rule judges, post-logout and grant URIs included.
		expect(reserved && describeRedirectUriRejection(reserved)).toMatch(
			/an authorization response carries that parameter/,
		);
		const invalid = checkRedirectUri("https://app.example/cb?filter[x]=1");
		expect(invalid && describeRedirectUriRejection(invalid)).toMatch(
			/letters, digits, "_" and "-".*";"/,
		);
		for (const rejection of [reserved, invalid]) {
			expect(rejection && describeRedirectUriRejection(rejection)).not.toMatch(/#\d/);
		}
	});
});

describe("redirectUriQueryCarries", () => {
	const NAMES = ["grant_id", "state"];

	it("finds a caller's name under any case and separators, answering the name as given", () => {
		for (const query of ["grant_id=x", "GRANT_ID=x", "grantId", "_grant-id_=x", "a=1&GrantId=2"]) {
			expect(redirectUriQueryCarries(`https://app.example/cb?${query}`, NAMES), query).toBe(
				"grant_id",
			);
		}
		expect(redirectUriQueryCarries("com.example.app:cb?STATE=x", NAMES)).toBe("state");
		// The first match in query order.
		expect(redirectUriQueryCarries("https://app.example/cb?state=1&grant_id=2", NAMES)).toBe(
			"state",
		);
	});

	it("answers undefined for different letters, a value, no query and an unparsable URI", () => {
		for (const uri of [
			"https://app.example/cb?grant_ids=x",
			"https://app.example/cb?grantid1=x",
			"https://app.example/cb?a=grant_id",
			"https://app.example/cb?",
			"https://app.example/cb",
			"not a url",
		]) {
			expect(redirectUriQueryCarries(uri, NAMES), uri).toBeUndefined();
		}
	});

	it("matches only allowlisted names, leaving the rest to checkRedirectUri", () => {
		const uri = "https://app.example/cb?grant_id[]=x";
		expect(redirectUriQueryCarries(uri, NAMES)).toBeUndefined();
		expect(reason(uri)).toBe("query-name-invalid");
	});
});

describe("matchesRegisteredRedirectUri", () => {
	it("ignores the port when both sides are http on a loopback IP literal (RFC 8252 §7.3)", () => {
		// The native-app case: the client bound an ephemeral port at run time,
		// so the registration cannot name it.
		expect(matchesRegisteredRedirectUri("http://127.0.0.1/cb", "http://127.0.0.1:49152/cb")).toBe(
			true,
		);
		expect(matchesRegisteredRedirectUri("http://[::1]/cb", "http://[::1]:49152/cb")).toBe(true);
		// Whole 127.0.0.0/8, and port variance in either direction.
		expect(matchesRegisteredRedirectUri("http://127.0.0.53/cb", "http://127.0.0.53:8080/cb")).toBe(
			true,
		);
		expect(
			matchesRegisteredRedirectUri("http://127.0.0.1:1234/cb", "http://127.0.0.1:5678/cb"),
		).toBe(true);
	});

	it("still compares scheme, host, path and query exactly", () => {
		expect(
			matchesRegisteredRedirectUri("http://127.0.0.1/cb", "http://127.0.0.1:49152/other"),
		).toBe(false);
		// Both hosts are loopback; the carve-out is the port and only the port.
		expect(matchesRegisteredRedirectUri("http://127.0.0.1/cb", "http://127.0.0.2:49152/cb")).toBe(
			false,
		);
		expect(matchesRegisteredRedirectUri("http://127.0.0.1/cb", "http://[::1]:49152/cb")).toBe(
			false,
		);
		expect(
			matchesRegisteredRedirectUri("http://127.0.0.1/cb?x=1", "http://127.0.0.1:49152/cb?x=1"),
		).toBe(true);
		expect(
			matchesRegisteredRedirectUri("http://127.0.0.1/cb?x=1", "http://127.0.0.1:49152/cb?x=2"),
		).toBe(false);
	});

	it("relaxes the port and NOTHING else — no URL normalization rides along", () => {
		// The carve-out is a port comparison, not a URL-equivalence one.
		// Comparing normalized URLs would widen the allowlist by exactly the
		// URIs a native app controls: dot segments, `\` as a separator, scheme
		// case and an elided empty path all collapse into a registered entry.
		// So the equality runs on the ORIGINAL strings with only the port removed.
		const registered = "http://127.0.0.1/cb";
		expect(matchesRegisteredRedirectUri(registered, "http://127.0.0.1:8080/a/../cb")).toBe(false);
		expect(matchesRegisteredRedirectUri(registered, "http://127.0.0.1:8080/./cb")).toBe(false);
		expect(matchesRegisteredRedirectUri(registered, "http://127.0.0.1:8080/%63b")).toBe(false);
		expect(matchesRegisteredRedirectUri(registered, "http://127.0.0.1:8080/cb/")).toBe(false);
		expect(matchesRegisteredRedirectUri(registered, "http://127.0.0.1:8080\\cb")).toBe(false);
		expect(matchesRegisteredRedirectUri(registered, "HTTP://127.0.0.1:8080/cb")).toBe(false);
		expect(matchesRegisteredRedirectUri("http://127.0.0.1/", "http://127.0.0.1:8080")).toBe(false);
		// Userinfo is not a port, so it never rides in either — and a
		// registration cannot carry it (see checkRedirectUri) anyway.
		expect(matchesRegisteredRedirectUri(registered, "http://u@127.0.0.1:8080/cb")).toBe(false);
		// ...while the case the carve-out exists for is untouched.
		expect(matchesRegisteredRedirectUri(registered, "http://127.0.0.1:49152/cb")).toBe(true);
		// The default port is still a port: writing it out is a port difference.
		expect(matchesRegisteredRedirectUri(registered, "http://127.0.0.1:80/cb")).toBe(true);
	});

	it("gives `localhost` no carve-out (RFC 8252 §8.3 discourages it)", () => {
		// `localhost` resolves through the host's name resolution, which is not
		// the guarantee the IP literals carry — §7.3's relaxation is for the
		// literals, so this stays an exact match.
		expect(matchesRegisteredRedirectUri("http://localhost/cb", "http://localhost:1234/cb")).toBe(
			false,
		);
		expect(matchesRegisteredRedirectUri("http://localhost/cb", "http://localhost/cb")).toBe(true);
	});

	it("gives https no carve-out, loopback host or not", () => {
		expect(
			matchesRegisteredRedirectUri("https://app.example/cb", "https://app.example:8443/cb"),
		).toBe(false);
		expect(matchesRegisteredRedirectUri("https://127.0.0.1/cb", "https://127.0.0.1:49152/cb")).toBe(
			false,
		);
		// A scheme mismatch is a mismatch even when the rest lines up.
		expect(matchesRegisteredRedirectUri("http://127.0.0.1/cb", "https://127.0.0.1:49152/cb")).toBe(
			false,
		);
	});

	it("matches every other pair by exact string equality", () => {
		expect(
			matchesRegisteredRedirectUri(
				"com.example.app:/oauth2redirect",
				"com.example.app:/oauth2redirect",
			),
		).toBe(true);
		expect(matchesRegisteredRedirectUri("https://app.example/cb", "https://app.example/cb")).toBe(
			true,
		);
		expect(matchesRegisteredRedirectUri("https://app.example/cb", "https://evil.example/cb")).toBe(
			false,
		);
		// Unparsable on either side falls back to the string comparison rather
		// than throwing.
		expect(matchesRegisteredRedirectUri("not a url", "not a url")).toBe(true);
		expect(matchesRegisteredRedirectUri("not a url", "http://127.0.0.1:1/cb")).toBe(false);
	});
});
