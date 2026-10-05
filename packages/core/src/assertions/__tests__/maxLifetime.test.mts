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
 * Every assertion the registry verifier accepts that carries `iat` lives at
 * most its entry's `maxLifetimeSeconds` (`exp − iat`), so a subject's
 * revocation boundary, kept for `ASSERTION_MAX_LIFETIME_LIMIT_SECONDS` and
 * more, outlives every assertion issued before it. (Where that boundary is
 * consulted, the jwt-bearer grant requires `iat`.)
 */

import { generateKeyPairSync } from "node:crypto";
import { SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import {
	type AssertionIssuerEntry,
	type AssertionIssuerEntryInput,
	checkAssertionIssuerEntry,
	createMemoryAssertionIssuerRegistry,
} from "#/assertions/issuerRegistry.mjs";
import {
	ASSERTION_MAX_LIFETIME_LIMIT_SECONDS,
	DEFAULT_ASSERTION_MAX_LIFETIME_SECONDS,
	MAX_ASSERTION_LIFETIME_SECONDS,
} from "#/assertions/lifetime.mjs";
import { createRegistryAssertionVerifier } from "#/assertions/registryAssertionVerifier.mjs";
import { createMemoryReplaySeenSet } from "#/replay-seen-set/adapters/memory.mjs";

const AS = "https://auth.example";
const ISSUER = "https://devices.example";
const { publicKey, privateKey } = generateKeyPairSync("ed25519");

const entry = (over: Partial<AssertionIssuerEntryInput> = {}): AssertionIssuerEntryInput => ({
	issuer: ISSUER,
	keys: { type: "key", key: publicKey },
	algorithms: ["EdDSA"],
	clockToleranceSeconds: 60,
	...over,
});

const mint = async (claims: { iat?: number; exp: number; [k: string]: unknown }): Promise<string> =>
	new SignJWT({ sub: "device:1", ...claims })
		.setProtectedHeader({ alg: "EdDSA" })
		.setIssuer(ISSUER)
		.setAudience(AS)
		.sign(privateKey);

const verifierOver = (
	e: AssertionIssuerEntryInput = entry(),
	logger?: { warn: ReturnType<typeof vi.fn> },
) =>
	createRegistryAssertionVerifier({
		registry: createMemoryAssertionIssuerRegistry([e]),
		audience: AS,
		...(logger ? { logger: logger as never } : {}),
	});

const now = () => Math.floor(Date.now() / 1000);

describe("the assertion lifetime ceiling's numbers", () => {
	it("defaults to an hour, as single-use assertions are held to, and is bounded by a day", () => {
		expect(DEFAULT_ASSERTION_MAX_LIFETIME_SECONDS).toBe(3600);
		expect(DEFAULT_ASSERTION_MAX_LIFETIME_SECONDS).toBe(MAX_ASSERTION_LIFETIME_SECONDS);
		expect(ASSERTION_MAX_LIFETIME_LIMIT_SECONDS).toBe(86_400);
	});
});

describe("checkAssertionIssuerEntry — maxLifetimeSeconds", () => {
	for (const bad of [
		0,
		-1,
		1.5,
		Number.NaN,
		Number.POSITIVE_INFINITY,
		ASSERTION_MAX_LIFETIME_LIMIT_SECONDS + 1,
		"3600",
	]) {
		it(`refuses ${String(bad)} (${typeof bad})`, () => {
			const e = entry({ maxLifetimeSeconds: bad as number });
			expect(() => checkAssertionIssuerEntry(e)).toThrow(/maxLifetimeSeconds/);
			expect(() => createMemoryAssertionIssuerRegistry([e])).toThrow(/maxLifetimeSeconds/);
		});
	}

	it("admits none, one second, the default and the limit", () => {
		for (const ok of [
			undefined,
			1,
			DEFAULT_ASSERTION_MAX_LIFETIME_SECONDS,
			ASSERTION_MAX_LIFETIME_LIMIT_SECONDS,
		]) {
			expect(() => checkAssertionIssuerEntry(entry({ maxLifetimeSeconds: ok }))).not.toThrow();
		}
	});
});

describe("the registry verifier holds a plain RFC 7523 assertion to the ceiling", () => {
	it("accepts exp − iat up to the default, and refuses one second more", async () => {
		const iat = now() - 10;
		const verifier = verifierOver();
		expect(await verifier.verify(await mint({ iat, exp: iat + 3600 }))).not.toBeNull();
		expect(await verifier.verify(await mint({ iat, exp: iat + 3601 }))).toBeNull();
	});

	it("leaves an assertion without iat to its exp: it has no lifetime to measure", async () => {
		expect(await verifierOver().verify(await mint({ exp: now() + 7200 }))).not.toBeNull();
	});

	it("measures from iat, so an old assertion with little time left is still refused", async () => {
		// Issued a week ago, with a week's lifetime: an hour left, a week long.
		const iat = now() - 7 * 86_400 + 3600;
		expect(await verifierOver().verify(await mint({ iat, exp: iat + 7 * 86_400 }))).toBeNull();
	});

	it("takes the entry's own ceiling, up to the limit", async () => {
		const iat = now() - 10;
		const longer = verifierOver(
			entry({ maxLifetimeSeconds: ASSERTION_MAX_LIFETIME_LIMIT_SECONDS }),
		);
		expect(await longer.verify(await mint({ iat, exp: iat + 80_000 }))).not.toBeNull();
		const shorter = verifierOver(entry({ maxLifetimeSeconds: 300 }));
		expect(await shorter.verify(await mint({ iat, exp: iat + 600 }))).toBeNull();
	});

	it("says why at warn", async () => {
		const warn = vi.fn();
		const iat = now() - 10;
		await verifierOver(entry(), { warn }).verify(await mint({ iat, exp: iat + 7200 }));
		expect(warn).toHaveBeenCalledWith(
			expect.objectContaining({
				issuer: ISSUER,
				reason: "lifetime",
				lifetimeSeconds: 7200,
				maxLifetimeSeconds: 3600,
			}),
			"jwt_bearer_assertion_refused",
		);
	});

	it("throws for a stored entry whose ceiling cannot be compared, rather than switching it off", async () => {
		const stored: AssertionIssuerEntry = {
			issuer: ISSUER,
			keys: { type: "key", key: publicKey },
			algorithms: ["EdDSA"],
			allowedSubjects: undefined,
			allowedScopes: undefined,
			allowedAudiences: undefined,
			allowedClients: undefined,
			expiresAt: undefined,
			profile: undefined,
			clockToleranceSeconds: undefined,
			maxLifetimeSeconds: Number.NaN,
		};
		const verifier = createRegistryAssertionVerifier({
			registry: { kind: "rows", findIssuer: async () => stored },
			audience: AS,
		});
		await expect(verifier.verify(await mint({ exp: now() + 60 }))).rejects.toThrow(
			/maxLifetimeSeconds/,
		);
	});
});

describe("an ID-JAG entry keeps its own stricter limit", () => {
	it("refuses an ID-JAG over an hour ahead though the entry's ceiling is a day", async () => {
		const verifier = createRegistryAssertionVerifier({
			registry: createMemoryAssertionIssuerRegistry([
				entry({ profile: "id-jag", maxLifetimeSeconds: ASSERTION_MAX_LIFETIME_LIMIT_SECONDS }),
			]),
			audience: [AS],
			issuerIdentifier: AS,
			replaySeenSet: createMemoryReplaySeenSet(),
		});
		const idJag = (exp: number) =>
			new SignJWT({ sub: "user-1", client_id: "app", jti: `j-${Math.random()}` })
				.setProtectedHeader({ alg: "EdDSA", typ: "oauth-id-jag+jwt" })
				.setIssuer(ISSUER)
				.setAudience(AS)
				.setIssuedAt()
				.setExpirationTime(exp)
				.sign(privateKey);
		expect(await verifier.verify(await idJag(now() + 7200), { clientId: "app" })).toBeNull();
		expect(await verifier.verify(await idJag(now() + 600), { clientId: "app" })).not.toBeNull();
	});
});
