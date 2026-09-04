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
 * redirect-uri.test.mts — the registered-redirect-URI shape vocabulary
 * (#395, from #293 item 1).
 *
 * The two clauses the #395 falsification pass promoted to requirements are
 * pinned here by name: parse-then-check (the tab-smuggled `javascript:` case)
 * and the deliberate absence of a legacy dotless-scheme escape hatch.
 *
 * `matchesRegisteredRedirectUri` (#483) is the runtime half — the /authorize
 * allowlist comparison, exact everywhere except the RFC 8252 §7.3 loopback
 * port.
 */
import { describe, expect, it } from "vitest";
import {
	checkRedirectUri,
	describeRedirectUriRejection,
	matchesRegisteredRedirectUri,
} from "#/net/redirect-uri.mjs";

const reason = (raw: string) => checkRedirectUri(raw)?.reason;

describe("checkRedirectUri (#395)", () => {
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
		// `javascript` — a raw prefix match would have missed it (#395's
		// falsification clause 1).
		expect(reason("java\tscript:alert(1)")).toBe("executable-scheme");
		expect(reason("JAVASCRIPT:alert(1)")).toBe("executable-scheme");
	});

	it("allows RFC 8252 §7.1 reverse-domain custom schemes", () => {
		expect(checkRedirectUri("com.example.app:/oauth2redirect")).toBeNull();
		expect(checkRedirectUri("com.example.app://callback")).toBeNull();
	});

	it("refuses dotless legacy custom schemes — no escape hatch, deliberately", () => {
		// #395's falsification clause 2: a documented capability decision.
		expect(reason("myapp://callback")).toBe("scheme-not-reverse-domain");
		const rejection = checkRedirectUri("myapp://callback");
		expect(rejection && describeRedirectUriRejection(rejection)).toContain("reverse-domain");
	});

	it("refuses a dotted spelling whose first label is an executable scheme", () => {
		// The deny check backs the grammar up: `javascript.evil` satisfies the
		// dot rule and must still fall.
		expect(reason("javascript.evil:x")).toBe("executable-scheme");
	});

	it("refuses raw control characters that the parser would strip", () => {
		// WHATWG strips tab/newline/CR, but runtime redirect_uri matching is
		// EXACT — a registration these survive into can never match a request.
		// Refused at boot instead of becoming a dead entry (Copilot on #399).
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

describe("matchesRegisteredRedirectUri (#483)", () => {
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
