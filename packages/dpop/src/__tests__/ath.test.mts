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
import { describe, expect, it } from "vitest";
import { athMatches, computeAth } from "#/ath.mjs";

describe("computeAth", () => {
	it("matches the worked example in RFC 9449 §4.2", async () => {
		// The RFC's own access token and the `ath` its example proof carries.
		const accessToken = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";

		expect(await computeAth(accessToken)).toBe("fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo");
	});

	it("is base64url with no padding, as a JWT claim value must be", async () => {
		const ath = await computeAth("some-access-token");

		expect(ath).toMatch(/^[A-Za-z0-9_-]+$/);
		expect(ath).not.toContain("=");
	});

	it("hashes the token's ASCII bytes, so a one-character change changes the digest", async () => {
		const a = await computeAth("token-a");
		const b = await computeAth("token-b");

		expect(a).not.toBe(b);
	});
});

describe("athMatches", () => {
	const token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";

	it("accepts the ath the RFC's example proof carries for that token", async () => {
		expect(await athMatches("fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo", token)).toBe(true);
	});

	it("rejects an ath computed over a different token", async () => {
		// This is the whole point: a proof captured alongside one request must
		// not authorise a different stolen token.
		const other = await computeAth("a-different-access-token");

		expect(await athMatches(other, token)).toBe(false);
	});

	it("rejects a truncated ath rather than throwing on the length mismatch", async () => {
		const correct = await computeAth(token);

		expect(await athMatches(correct.slice(0, 10), token)).toBe(false);
	});

	it("rejects an empty ath", async () => {
		expect(await athMatches("", token)).toBe(false);
	});
});
