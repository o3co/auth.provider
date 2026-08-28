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
 * request-url.test.mts — the single canonical-request-URL vocabulary
 * (#292, #356).
 *
 * Two consumers share this construction and must not drift apart:
 *   - DPoP htu comparison (`@o3co/auth-provider-dpop`, #292): the expected
 *     `htu` every proof is checked against.
 *   - the /authorize login round-trip (`@o3co/auth-provider-oauth`, #356):
 *     the `redirect_to` handed to the login page.
 *
 * The properties pinned here are the ones both consumers' security arguments
 * lean on: the origin half comes only from the first argument, and no request
 * target — protocol-relative, absolute-form, or otherwise — can move it.
 */
import { describe, expect, it } from "vitest";
import { buildCanonicalRequestUrl } from "#/net/request-url.mjs";

describe("buildCanonicalRequestUrl (#292, #356)", () => {
	it("concatenates the configured origin with an origin-form target", () => {
		expect(buildCanonicalRequestUrl("https://as.example", "/oauth/authorize?client_id=x")).toBe(
			"https://as.example/oauth/authorize?client_id=x",
		);
	});

	it("keeps a protocol-relative target a path — it must not move the host", () => {
		const url = buildCanonicalRequestUrl("https://as.example", "//evil.example/x");
		expect(url).toBe("https://as.example//evil.example/x");
		// The WHATWG parser agrees: the host is still the configured one.
		expect(new URL(url).host).toBe("as.example");
	});

	it("prefixes an absolute-form target so it cannot reach the authority position", () => {
		// `GET http://evil.example/x HTTP/1.1` is legal per RFC 9112 §3.2;
		// Express would report it verbatim in `req.originalUrl`.
		const url = buildCanonicalRequestUrl("https://as.example", "http://evil.example/x");
		expect(url).toBe("https://as.example/http://evil.example/x");
		expect(new URL(url).host).toBe("as.example");
	});

	it("preserves a non-default port on the configured origin", () => {
		expect(buildCanonicalRequestUrl("http://localhost:3000", "/authorize")).toBe(
			"http://localhost:3000/authorize",
		);
	});
});
