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

import { afterEach, describe, expect, it, vi } from "vitest";
import {
	auditErrorList,
	auditErrorText,
	errorEnvelope,
	isWellFormedErrorCode,
	sanitizeErrorText,
} from "#/errors/envelope.mjs";

describe("AS-1/AS-2 errorEnvelope helper (RFC 6749 §5.2)", () => {
	it("includes error_description and error_uri when provided", () => {
		const e = errorEnvelope("invalid_grant", "Token expired", "https://docs.example.com");
		expect(e).toEqual({
			error: "invalid_grant",
			error_description: "Token expired",
			error_uri: "https://docs.example.com",
		});
	});

	it("omits optional fields when undefined", () => {
		const e = errorEnvelope("not_found");
		expect(e).toEqual({ error: "not_found" });
		expect(e).not.toHaveProperty("error_description");
		expect(e).not.toHaveProperty("error_uri");
	});

	it("includes error_description without error_uri", () => {
		const e = errorEnvelope("server_error", "Session regeneration failed");
		expect(e).toEqual({
			error: "server_error",
			error_description: "Session regeneration failed",
		});
		expect(e).not.toHaveProperty("error_uri");
	});

	it("treats undefined description as omission, not as a present empty value", () => {
		const e = errorEnvelope("rate_limited", undefined);
		expect(Object.keys(e).sort()).toEqual(["error"]);
	});

	it("treats empty-string description and uri as omissions", () => {
		const e = errorEnvelope("rate_limited", "", "");
		expect(e).toEqual({ error: "rate_limited" });
		expect(e).not.toHaveProperty("error_description");
		expect(e).not.toHaveProperty("error_uri");
	});

	// The rule lives in the envelope, so every writer that goes through it —
	// core's middleware, the session routes, a contributed module — conforms
	// without having to remember to.
	describe("RFC 6749 characters (Appendix A.7, A.8)", () => {
		afterEach(() => {
			vi.restoreAllMocks();
		});

		it("replaces every description character outside 1*NQSCHAR with '?'", () => {
			expect(errorEnvelope("rate_limited", 'quota "exceeded" \\ §3 — café\r\n')).toEqual({
				error: "rate_limited",
				error_description: "quota ?exceeded? ? ?3 ? caf???",
			});
		});

		it("omits a description that is not a string rather than coercing it", () => {
			// A JavaScript caller — a limiter adapter, a mechanism — can pass
			// anything; `{}` on the wire is not a description.
			const e = errorEnvelope("rate_limited", { toString: () => "x" } as unknown as string);
			expect(e).toEqual({ error: "rate_limited" });
		});

		it("answers a malformed code as server_error, and logs the code it replaced", () => {
			// The code came from server-side code, never from the client, so the
			// fault is the server's: `server_error` is the one code that is true
			// whatever status the caller answers with.
			const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
			const e = errorEnvelope('bad "code"', "refused");
			expect(e).toEqual({ error: "server_error", error_description: "refused" });
			expect(warn).toHaveBeenCalledWith({ error: "bad ?code?" }, "error_envelope_code_malformed");
		});

		it.each([
			["the empty string", ""],
			["non-ASCII", "dény"],
			["a line break", "deny\r\n"],
			["a non-string", 42 as unknown as string],
		])("answers %s as a code with server_error", (_label, code) => {
			vi.spyOn(console, "warn").mockImplementation(() => {});
			expect(errorEnvelope(code).error).toBe("server_error");
		});

		it("does not log a well-formed code", () => {
			const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
			errorEnvelope("invalid_request", "fine");
			expect(warn).not.toHaveBeenCalled();
		});
	});

	// RFC 6749 §5.2 and Appendix A.9: `error_uri` is a URI-reference, and may
	// not carry a character outside %x21 / %x23-5B / %x5D-7E.
	describe("error_uri (Appendix A.9)", () => {
		afterEach(() => {
			vi.restoreAllMocks();
		});

		it.each([
			["an absolute URI", "https://docs.example.com/errors/invalid_grant?lang=en#retry"],
			["an http URI", "http://docs.example.com/errors"],
			["an IPv6 host", "https://[2001:db8::1]:8443/errors"],
			["a relative reference", "/docs/errors/invalid_grant"],
			["a relative path", "errors/invalid_grant"],
			["a query only", "?code=invalid_grant"],
			["a fragment only", "#invalid_grant"],
			["a percent-encoded character", "https://docs.example.com/errors/caf%C3%A9"],
		])("keeps %s", (_label, uri) => {
			expect(errorEnvelope("invalid_grant", "expired", uri).error_uri).toBe(uri);
		});

		it.each([
			["a space", "https://docs.example.com/invalid grant"],
			["a double quote", 'https://docs.example.com/"quoted"'],
			["a backslash", "https://docs.example.com\\errors"],
			["a control character", "https://docs.example.com/errors\r\nX-Injected: 1"],
			["a non-ASCII character", "https://docs.example.com/caf\u00e9"],
			["a malformed percent-encoding", "https://docs.example.com/errors%zz"],
			["a character RFC 3986 does not allow", "https://docs.example.com/{errors}"],
			["a host that does not parse", "https://[docs.example.com/errors"],
			// §5.2: a human-readable web page, so an absolute reference is http(s).
			["a javascript: scheme", "javascript:alert(1)"],
			["a javascript: scheme in mixed case", "JaVaScRiPt:alert(1)"],
			["a data: scheme", "data:text/html,x"],
			["a vbscript: scheme", "vbscript:x"],
			["a file: scheme", "file:///etc/passwd"],
			// RFC 3986: brackets only around an IP literal host; a relative path's
			// first segment has no colon.
			["a bracket outside a host", "a[b"],
			["a colon in a relative path's first segment", "::"],
			// A link to a web page names no user: `https://example.com@evil.example/`
			// reads as example.com and goes to evil.example, and RFC 3986 §3.2.1
			// deprecates `user:password`.
			["a userinfo that disguises the host", "https://example.com@evil.example/"],
			["a user and password", "https://user:pw@docs.example.com/errors"],
			["a userinfo on a network-path reference", "//user@docs.example.com/errors"],
			// RFC 3986 Appendix B's split does not match a line break in a
			// fragment, so the reference has no parts at all.
			["a line break in the fragment", "https://docs.example.com/errors#a\nb"],
			// The grammar admits any digits; the WHATWG parser does not.
			["a port past 65535", "https://docs.example.com:99999/errors"],
			["an IPv6 literal with too many groups", "https://[1:2:3:4:5:6:7:8:9]/errors"],
		])("drops a uri with %s, and logs it", (_label, uri) => {
			const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
			const e = errorEnvelope("invalid_grant", "expired", uri);
			expect(e).toEqual({ error: "invalid_grant", error_description: "expired" });
			expect(warn).toHaveBeenCalledWith(
				expect.objectContaining({ error_uri: expect.any(String) }),
				"error_envelope_uri_malformed",
			);
		});

		it("drops a uri that is not a string", () => {
			vi.spyOn(console, "warn").mockImplementation(() => {});
			const e = errorEnvelope("invalid_grant", "expired", 42 as unknown as string);
			expect(e).toEqual({ error: "invalid_grant", error_description: "expired" });
		});
	});
});

// RFC 6749 Appendix A.7 and A.8: `error` and `error_description` are both
// 1*NQSCHAR, NQSCHAR = %x20-21 / %x23-5B / %x5D-7E — printable ASCII without
// `"` and `\` (§5.2, and §4.1.2.1 for the authorization endpoint).
describe("RFC 6749 error text", () => {
	const allowed = Array.from({ length: 0x7f - 0x20 }, (_, i) => String.fromCharCode(0x20 + i))
		.filter((c) => c !== '"' && c !== "\\")
		.join("");

	describe("sanitizeErrorText", () => {
		it("keeps every character the RFC allows", () => {
			expect(sanitizeErrorText(allowed)).toBe(allowed);
		});

		it.each([
			["a double quote (%x22)", 'a"b', "a?b"],
			["a backslash (%x5C)", "a\\b", "a?b"],
			["a control character", "a\u0000b\u001fc\u007fd", "a?b?c?d"],
			["a line break", "a\r\nb", "a??b"],
			["a non-ASCII character", "a\u00e9b\u2014c", "a?b?c"],
			["a character outside the BMP, as one character", "a\u{1F600}b", "a?b"],
		])("replaces %s with '?'", (_label, input, expected) => {
			expect(sanitizeErrorText(input)).toBe(expected);
		});

		// A JavaScript policy can hand back anything as a description. It is
		// not coerced: the caller falls back to its own default.
		it.each([
			["a number", 42],
			["an object", { toString: () => "x" }],
			["null", null],
			["undefined", undefined],
		])("answers undefined for %s", (_label, value) => {
			expect(sanitizeErrorText(value)).toBeUndefined();
		});
	});

	// For a log line or an audit event: sanitised, and capped at 200
	// characters with the cut marked, so a client or a policy cannot put
	// unbounded text there.
	describe("auditErrorText", () => {
		it("sanitises and keeps text within the cap", () => {
			expect(auditErrorText('bad "code"')).toBe("bad ?code?");
			expect(auditErrorText("x".repeat(200))).toBe("x".repeat(200));
		});

		it("cuts text past 200 characters, marking the cut", () => {
			expect(auditErrorText(`"${"x".repeat(300)}`)).toBe(`?${"x".repeat(196)}...`);
		});

		it("answers undefined for a non-string", () => {
			expect(auditErrorText(42)).toBeUndefined();
		});

		it("replaces the Unicode line separators and the bidi controls, which are not ASCII", () => {
			expect(auditErrorText("a\u2028b\u2029c\u202ad\u202ee\u2066f\u2069g\u0085h")).toBe(
				"a?b?c?d?e?f?g?h",
			);
		});
	});

	// A list a client chose — the scopes it asked for, the resources it named
	// — for a log line or an audit event: still a list, so a query that reads
	// it as one keeps working, but bounded in what each entry holds and in how
	// many are kept.
	describe("auditErrorList", () => {
		it("keeps a small, well-formed list exactly as it was", () => {
			expect(auditErrorList(["openid", "profile"])).toEqual(["openid", "profile"]);
			expect(auditErrorList([])).toEqual([]);
		});

		it("puts each entry through auditErrorText", () => {
			expect(auditErrorList(['a"b', `x\r\n${"y".repeat(300)}`])).toEqual([
				"a?b",
				`x??${"y".repeat(194)}...`,
			]);
		});

		it("keeps the first ten entries", () => {
			const many = Array.from({ length: 1_000 }, (_, i) => `s${i}`);
			expect(auditErrorList(many)).toEqual(many.slice(0, 10));
		});

		it("keeps the first maxItems entries when told how many", () => {
			expect(auditErrorList(["a", "b", "c"], 2)).toEqual(["a", "b"]);
		});

		it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
			"refuses maxItems %s with a RangeError",
			(maxItems) => {
				expect(() => auditErrorList(["a"], maxItems)).toThrow(RangeError);
			},
		);
	});

	describe("isWellFormedErrorCode", () => {
		it.each(["invalid_request", "access_denied", allowed])("accepts %j", (code) => {
			expect(isWellFormedErrorCode(code)).toBe(true);
		});

		it.each([
			["the empty string", ""],
			["a double quote", 'bad "code"'],
			["a backslash", "bad\\code"],
			["a control character", "bad\ncode"],
			["non-ASCII", "d\u00e9ny"],
			["a non-string", 42],
			["undefined", undefined],
		])("refuses %s", (_label, code) => {
			expect(isWellFormedErrorCode(code)).toBe(false);
		});
	});
});
