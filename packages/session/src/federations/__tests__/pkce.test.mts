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

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { codeChallenge, generateCodeVerifier } from "../pkce.mjs";

describe("pkce", () => {
	describe("generateCodeVerifier", () => {
		it("produces a 43-character base64url string (RFC 7636 §4.1)", () => {
			const v = generateCodeVerifier();
			expect(v).toMatch(/^[A-Za-z0-9_-]+$/);
			expect(v.length).toBe(43);
		});

		it("produces a different value on each call (cryptographically random)", () => {
			const set = new Set<string>();
			for (let i = 0; i < 100; i++) set.add(generateCodeVerifier());
			expect(set.size).toBe(100);
		});
	});

	describe("codeChallenge", () => {
		it("returns BASE64URL(SHA256(verifier)) per RFC 7636 §4.2 S256", () => {
			const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
			const expected = createHash("sha256").update(verifier).digest("base64url");
			expect(codeChallenge(verifier)).toBe(expected);
		});

		it("produces a URL-safe base64 string (no padding, no + or /)", () => {
			const out = codeChallenge("some-verifier-value");
			expect(out).toMatch(/^[A-Za-z0-9_-]+$/);
			expect(out).not.toContain("=");
			expect(out).not.toContain("+");
			expect(out).not.toContain("/");
		});
	});
});
