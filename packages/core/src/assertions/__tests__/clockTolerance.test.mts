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
 * An issuer entry's `clockToleranceSeconds` cannot switch its checks off.
 *
 * The tolerance is added to the lifetime ceiling and handed to jose for
 * `exp` / `nbf`. `NaN` and `Infinity` are numbers to both: `NaN` makes every
 * comparison false and `Infinity` makes every bound unreachable, so an entry
 * carrying either admitted an assertion that expired long ago, or one that
 * runs for a year. The string `"30s"` — a jose timespan, and what an untyped
 * store row can hold — concatenated onto the ceiling instead of adding to it.
 *
 * So an entry's tolerance is a finite number of seconds from 0 to
 * `MAX_ASSERTION_CLOCK_TOLERANCE_SECONDS`, checked where an entry is
 * validated (`checkAssertionIssuerEntry`) and again when a registry hands one
 * to the verifier — a store-backed registry's rows are not validated on the
 * way out. The lifetime comparison fails closed on anything it cannot
 * compare.
 */

import { generateKeyPairSync } from "node:crypto";
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
	type AssertionIssuerEntry,
	checkAssertionIssuerEntry,
	createMemoryAssertionIssuerRegistry,
} from "#/assertions/issuerRegistry.mjs";
import {
	assertionLifetime,
	MAX_ASSERTION_CLOCK_TOLERANCE_SECONDS,
	MAX_ASSERTION_LIFETIME_SECONDS,
} from "#/assertions/lifetime.mjs";
import { createRegistryAssertionVerifier } from "#/assertions/registryAssertionVerifier.mjs";

const AS = "https://auth.example";
const ISSUER = "https://devices.example";
const { publicKey, privateKey } = generateKeyPairSync("ed25519");

const entryWith = (clockToleranceSeconds: unknown): AssertionIssuerEntry => ({
	issuer: ISSUER,
	keys: { type: "key", key: publicKey },
	algorithms: ["EdDSA"],
	allowedSubjects: undefined,
	allowedScopes: undefined,
	allowedAudiences: undefined,
	allowedClients: undefined,
	expiresAt: undefined,
	profile: undefined,
	clockToleranceSeconds: clockToleranceSeconds as number,
});

const BAD: ReadonlyArray<readonly [string, unknown]> = [
	["NaN", Number.NaN],
	["Infinity", Number.POSITIVE_INFINITY],
	["-Infinity", Number.NEGATIVE_INFINITY],
	["negative", -1],
	["past the bound", MAX_ASSERTION_CLOCK_TOLERANCE_SECONDS + 1],
	['the string "30s"', "30s"],
];

describe("checkAssertionIssuerEntry — clockToleranceSeconds", () => {
	for (const [label, tolerance] of BAD) {
		it(`refuses ${label}`, () => {
			expect(() => checkAssertionIssuerEntry(entryWith(tolerance))).toThrow(
				/clockToleranceSeconds/,
			);
			expect(() => createMemoryAssertionIssuerRegistry([entryWith(tolerance)])).toThrow(
				/clockToleranceSeconds/,
			);
		});
	}

	it("admits none, 0, the default and the bound", () => {
		for (const tolerance of [undefined, 0, 60, MAX_ASSERTION_CLOCK_TOLERANCE_SECONDS]) {
			expect(() => checkAssertionIssuerEntry(entryWith(tolerance))).not.toThrow();
		}
	});
});

describe("assertionLifetime — fails closed on a tolerance it cannot compare", () => {
	const now = 1_800_000_000;
	for (const [label, tolerance] of [
		["NaN", Number.NaN],
		["Infinity", Number.POSITIVE_INFINITY],
		['the string "30s"', "30s"],
	] as const) {
		it(`counts even a one-minute assertion as exceeded under ${label}`, () => {
			expect(assertionLifetime(now + 60, now, tolerance as number).exceeded).toBe(true);
		});
	}
});

describe("createRegistryAssertionVerifier — a stored entry's tolerance is checked on the way out", () => {
	const expiredAnHourAgo = () => {
		const now = Math.floor(Date.now() / 1000);
		return new SignJWT({})
			.setProtectedHeader({ alg: "EdDSA" })
			.setIssuer(ISSUER)
			.setSubject("device:1")
			.setAudience(AS)
			.setExpirationTime(now - MAX_ASSERTION_LIFETIME_SECONDS)
			.sign(privateKey);
	};

	for (const [label, tolerance] of [
		["NaN", Number.NaN],
		["Infinity", Number.POSITIVE_INFINITY],
		['the string "30s"', "30s"],
	] as const) {
		it(`never admits an expired assertion under an entry whose tolerance is ${label}`, async () => {
			const verifier = createRegistryAssertionVerifier({
				// A store-backed registry: rows are not validated on the way out.
				registry: { kind: "store", findIssuer: async () => entryWith(tolerance) },
				audience: AS,
			});
			const outcome = await verifier.verify(await expiredAnHourAgo()).catch((err: unknown) => err);
			expect(outcome).toBeInstanceOf(Error);
			expect(String((outcome as Error).message)).toMatch(/clockToleranceSeconds/);
		});
	}
});
