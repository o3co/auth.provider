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
 * An ID-JAG may run at most an hour past now — the ceiling the
 * `private_key_jwt` verifier already holds a client assertion to — and one
 * that runs longer is refused before its `jti` is recorded.
 *
 * Every ID-JAG `jti` is remembered until the assertion's `exp`, so an `exp`
 * with no upper bound is a replay record with none either: a year-long
 * assertion is a year-long key in the seen-set, per assertion presented.
 * RFC 7523 §3 lets the authorization server reject an `exp` "unreasonably
 * far in the future", and the ID-JAG draft (§4.4.1) applies RFC 7521 §5.2's
 * processing and sets no number of its own; this server's number is the one
 * it already uses for client assertions and for an ID-JAG's `iat` age.
 *
 * The ceiling allows the entry's clock tolerance, as every other time check
 * here does: an IdP whose clock runs a little ahead mints an hour-long
 * ID-JAG whose `exp` is a little past an hour from this server's now. A
 * refusal says why in the log (`jwt_bearer_assertion_refused`), since the
 * grant answers every refusal the same `invalid_grant`.
 */

import { generateKeyPairSync } from "node:crypto";
import { SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createMemoryAssertionIssuerRegistry } from "#/assertions/issuerRegistry.mjs";
import { MAX_ASSERTION_LIFETIME_SECONDS } from "#/assertions/lifetime.mjs";
import { createRegistryAssertionVerifier } from "#/assertions/registryAssertionVerifier.mjs";
import { consoleLogger } from "#/logging/consoleLogger.mjs";
import { createMemoryReplaySeenSet } from "#/replay-seen-set/adapters/memory.mjs";
import type { ReplaySeenSet } from "#/replay-seen-set/types.mjs";

const AS = "https://auth.example";
const IDP = "https://idp.example";
const DEVICES = "https://devices.example";
const idp = generateKeyPairSync("ed25519");
const devices = generateKeyPairSync("ed25519");

/** The memory seen-set, with every write it is asked for recorded. */
const recordingSeenSet = () => {
	const inner = createMemoryReplaySeenSet();
	const writes: string[] = [];
	const seenSet: ReplaySeenSet = {
		kind: "recording",
		markSeen: (scope, key, expiresAtMs) => {
			writes.push(key);
			return inner.markSeen(scope, key, expiresAtMs);
		},
		contains: (scope, key) => inner.contains(scope, key),
	};
	return { seenSet, writes };
};

/** The clock tolerance the ID-JAG entry below is given. */
const TOLERANCE_SECONDS = 120;

const spyLogger = () => ({
	...consoleLogger,
	warn: vi.fn(),
	info: vi.fn(),
	error: vi.fn(),
});

const verifierWith = (replaySeenSet: ReplaySeenSet, logger = spyLogger()) =>
	createRegistryAssertionVerifier({
		logger,
		registry: createMemoryAssertionIssuerRegistry([
			{
				issuer: IDP,
				keys: { type: "key", key: idp.publicKey },
				algorithms: ["EdDSA"],
				profile: "id-jag",
				clockToleranceSeconds: TOLERANCE_SECONDS,
			},
			{ issuer: DEVICES, keys: { type: "key", key: devices.publicKey }, algorithms: ["EdDSA"] },
		]),
		audience: AS,
		issuerIdentifier: AS,
		replaySeenSet,
	});

const now = () => Math.floor(Date.now() / 1000);

const idJag = (jti: string, exp: number) =>
	new SignJWT({ client_id: "app", jti })
		.setProtectedHeader({ alg: "EdDSA", typ: "oauth-id-jag+jwt" })
		.setIssuer(IDP)
		.setSubject("user-1")
		.setAudience(AS)
		.setIssuedAt()
		.setExpirationTime(exp)
		.sign(idp.privateKey);

describe("an ID-JAG's lifetime is bounded, before its jti is recorded", () => {
	it("is the hour private_key_jwt already allows", () => {
		expect(MAX_ASSERTION_LIFETIME_SECONDS).toBe(3600);
	});

	it("refuses an exp more than the ceiling and the clock tolerance past now, records nothing for it, and logs why", async () => {
		const { seenSet, writes } = recordingSeenSet();
		const logger = spyLogger();
		const assertion = await idJag(
			"jti-long",
			now() + MAX_ASSERTION_LIFETIME_SECONDS + TOLERANCE_SECONDS + 60,
		);
		expect(await verifierWith(seenSet, logger).verify(assertion, { clientId: "app" })).toBeNull();
		expect(writes).toEqual([]);
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({
				issuer: IDP,
				reason: "lifetime",
				maxLifetimeSeconds: MAX_ASSERTION_LIFETIME_SECONDS + TOLERANCE_SECONDS,
			}),
			"jwt_bearer_assertion_refused",
		);
	});

	it("allows the entry's clock tolerance past the ceiling — an IdP whose clock runs ahead", async () => {
		const { seenSet, writes } = recordingSeenSet();
		const assertion = await idJag(
			"jti-skewed",
			now() + MAX_ASSERTION_LIFETIME_SECONDS + TOLERANCE_SECONDS - 30,
		);
		expect(await verifierWith(seenSet).verify(assertion, { clientId: "app" })).not.toBeNull();
		expect(writes).toEqual(["jti-skewed"]);
	});

	it("refuses a year-long one", async () => {
		const { seenSet, writes } = recordingSeenSet();
		const assertion = await idJag("jti-year", now() + 365 * 86_400);
		expect(await verifierWith(seenSet).verify(assertion, { clientId: "app" })).toBeNull();
		expect(writes).toEqual([]);
	});

	it("accepts one inside the ceiling and records it once", async () => {
		const { seenSet, writes } = recordingSeenSet();
		const assertion = await idJag("jti-ok", now() + MAX_ASSERTION_LIFETIME_SECONDS - 60);
		const verifier = verifierWith(seenSet);
		expect(await verifier.verify(assertion, { clientId: "app" })).not.toBeNull();
		expect(writes).toEqual(["jti-ok"]);
		expect(await verifier.verify(assertion, { clientId: "app" })).toBeNull();
	});

	it("leaves a plain RFC 7523 assertion's exp to its issuer — nothing of it is recorded", async () => {
		const { seenSet } = recordingSeenSet();
		const assertion = await new SignJWT({})
			.setProtectedHeader({ alg: "EdDSA" })
			.setIssuer(DEVICES)
			.setSubject("device:1")
			.setAudience(AS)
			.setExpirationTime(now() + 7 * 86_400)
			.sign(devices.privateKey);
		expect(await verifierWith(seenSet).verify(assertion)).not.toBeNull();
	});
});
