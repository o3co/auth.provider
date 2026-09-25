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
import { computeAtHash, verifyAtHash } from "#/at-hash.mjs";

const unsignedJwt = (header: object): string =>
	`${Buffer.from(JSON.stringify(header)).toString("base64url")}.${Buffer.from("{}").toString("base64url")}.sig`;

describe("at_hash (OIDC Core §3.3.2.11, #524)", () => {
	it("matches the specification's worked example for RS256", () => {
		expect(computeAtHash("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y", "RS256")).toBe(
			"77QmUPtjPfzWtF2AnpK9RQ",
		);
	});

	it("uses the hash the signing algorithm names, and half of it", () => {
		expect(computeAtHash("token", "ES256")).toHaveLength(22); // 16 bytes
		expect(computeAtHash("token", "PS384")).toHaveLength(32); // 24 bytes
		expect(computeAtHash("token", "RS512")).toHaveLength(43); // 32 bytes
		expect(computeAtHash("token", "EdDSA")).toBe(computeAtHash("token", "RS512"));
		expect(computeAtHash("token", "Ed25519")).toBe(computeAtHash("token", "RS512"));
		expect(() => computeAtHash("token", "HS9")).toThrow(/at_hash/);
	});

	it("verifies against the id_token's own alg and refuses a mismatch", () => {
		const idToken = unsignedJwt({ alg: "RS256", kid: "k" });
		const accessToken = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
		expect(() =>
			verifyAtHash("test", idToken, accessToken, "77QmUPtjPfzWtF2AnpK9RQ"),
		).not.toThrow();
		expect(() => verifyAtHash("test", idToken, "another-token", "77QmUPtjPfzWtF2AnpK9RQ")).toThrow(
			/test.*at_hash/,
		);
		expect(() => verifyAtHash("test", idToken, accessToken, "77QmUPtjPfzWtF2AnpK9R")).toThrow(
			/at_hash/,
		);
		expect(() => verifyAtHash("test", idToken, accessToken, 42)).toThrow(/at_hash/);
		expect(() => verifyAtHash("test", unsignedJwt({ alg: "none" }), accessToken, "x")).toThrow(
			/at_hash/,
		);
	});

	it("refuses an alg that names no hash in its own words, wrapping no error of its own", () => {
		// The alg is checked, not caught: the one error on this path is the
		// refusal itself, so there is no library text to flatten or to carry.
		let thrown: unknown;
		try {
			verifyAtHash("test", unsignedJwt({ alg: "HS9" }), "token", "x");
		} catch (err) {
			thrown = err;
		}
		expect(thrown).toBeInstanceOf(Error);
		expect((thrown as Error).message).toBe(
			'test: at_hash cannot be verified for a JWS alg of "HS9"',
		);
		expect((thrown as Error).cause).toBeUndefined();
	});
});
