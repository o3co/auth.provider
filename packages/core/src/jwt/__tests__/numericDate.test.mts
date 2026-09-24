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
 * What a JWT's `exp`, `iat` and `nbf` must be before anything computes an
 * expiry from them: a NumericDate (RFC 7519 §2) — a finite number of seconds
 * a Date can hold. jose checks only that the claim is a number, and JSON's
 * `1e400` parses to Infinity.
 */

import { generateKeyPairSync } from "node:crypto";
import { CompactSign } from "jose";
import { describe, expect, it } from "vitest";
import { createMemoryAssertionIssuerRegistry } from "#/assertions/issuerRegistry.mjs";
import { createRegistryAssertionVerifier } from "#/assertions/registryAssertionVerifier.mjs";
import {
	isNumericDate,
	MAX_NUMERIC_DATE_SECONDS,
	malformedNumericDateClaim,
} from "#/jwt/numericDate.mjs";

describe("isNumericDate", () => {
	it("admits whole and fractional seconds, negative ones included", () => {
		for (const value of [0, 1_727_000_000, 1_727_000_000.5, -1, MAX_NUMERIC_DATE_SECONDS]) {
			expect(isNumericDate(value)).toBe(true);
		}
	});

	it("refuses what is not a finite number of seconds a Date can hold", () => {
		for (const value of [
			Number.POSITIVE_INFINITY,
			Number.NEGATIVE_INFINITY,
			Number.NaN,
			1e300,
			MAX_NUMERIC_DATE_SECONDS + 1,
			-(MAX_NUMERIC_DATE_SECONDS + 1),
			"1727000000",
			null,
			undefined,
		]) {
			expect(isNumericDate(value)).toBe(false);
		}
	});

	it("is the Date range: every admitted value is a valid Date", () => {
		expect(Number.isNaN(new Date(MAX_NUMERIC_DATE_SECONDS * 1000).getTime())).toBe(false);
		expect(Number.isNaN(new Date((MAX_NUMERIC_DATE_SECONDS + 1) * 1000).getTime())).toBe(true);
	});
});

describe("malformedNumericDateClaim", () => {
	it("names the first of exp, iat, nbf that is present and not a NumericDate", () => {
		expect(malformedNumericDateClaim({ exp: 1, iat: 1, nbf: 1 })).toBeUndefined();
		expect(malformedNumericDateClaim({})).toBeUndefined();
		expect(malformedNumericDateClaim({ exp: Number.POSITIVE_INFINITY })).toBe("exp");
		expect(malformedNumericDateClaim({ exp: 1, iat: Number.NEGATIVE_INFINITY })).toBe("iat");
		expect(malformedNumericDateClaim({ exp: 1, iat: 1, nbf: 1e300 })).toBe("nbf");
		expect(malformedNumericDateClaim({ exp: "soon" })).toBe("exp");
	});
});

describe("createRegistryAssertionVerifier — date claims that are not dates", () => {
	const authority = generateKeyPairSync("ed25519");
	const AS = "https://auth.example";
	const ISSUER = "https://devices.example";
	const verifier = createRegistryAssertionVerifier({
		registry: createMemoryAssertionIssuerRegistry([
			{ issuer: ISSUER, keys: { type: "key", key: authority.publicKey }, algorithms: ["EdDSA"] },
		]),
		audience: AS,
	});
	const now = () => Math.floor(Date.now() / 1000);
	const signRaw = (json: string) =>
		new CompactSign(new TextEncoder().encode(json))
			.setProtectedHeader({ alg: "EdDSA" })
			.sign(authority.privateKey);
	const claims = (dates: string) => `{"iss":"${ISSUER}","sub":"device:1","aud":"${AS}",${dates}}`;

	it("refuses exp: 1e400 itself, rather than verifying it with expiresAt: Infinity", async () => {
		expect(await verifier.verify(await signRaw(claims(`"exp":1e400`)))).toBeNull();
	});

	it("refuses iat: -1e400 and nbf: -1e400", async () => {
		expect(
			await verifier.verify(await signRaw(claims(`"exp":${now() + 60},"iat":-1e400`))),
		).toBeNull();
		expect(
			await verifier.verify(await signRaw(claims(`"exp":${now() + 60},"nbf":-1e400`))),
		).toBeNull();
	});

	it("still verifies a fractional exp and reports it as it is", async () => {
		const exp = now() + 60.5;
		expect(await verifier.verify(await signRaw(claims(`"exp":${exp}`)))).toMatchObject({
			expiresAt: exp,
		});
	});
});
