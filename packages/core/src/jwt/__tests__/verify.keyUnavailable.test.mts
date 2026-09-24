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
 * A keystore that cannot answer is an outage, not a verdict on the token.
 *
 * `KeyStore.getVerificationKey` refuses a kid it does not hold with
 * `UnknownKidError` and a retired one with `ExpiredKidError`. Anything else it
 * throws — a remote key service that timed out, a vault that refused the
 * connection — says nothing about the token, and the verifier reported it as
 * `kid_unknown`: the "attacker-fabricated header" signal, which every caller
 * answers as the client's fault.
 */

import { createSecretKey } from "node:crypto";
import { SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import {
	isVerificationUnavailable,
	JwtVerificationError,
	type JwtVerifyOptions,
	VERIFICATION_UNAVAILABLE_DESCRIPTION,
	verifyJwt,
} from "#/jwt/verify.mjs";
import { createSymmetricKeyStore, ExpiredKidError, type KeyStore } from "#/keys/KeyStore.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import { loggableError } from "#/logging/loggableError.mjs";

const SECRET = "test-secret-32-bytes-long-string12";
const ISSUER = "https://example.com";

const options: JwtVerifyOptions = {
	type: "access_token",
	expectedIssuer: ISSUER,
	revocation: "none",
};

const mint = (kid = "v0"): Promise<string> =>
	new SignJWT({ sub: "user-1" })
		.setProtectedHeader({ alg: "HS256", kid, typ: "at+jwt" })
		.setIssuer(ISSUER)
		.setIssuedAt()
		.setExpirationTime("5m")
		.sign(createSecretKey(Buffer.from(SECRET)));

/** The real keystore, whose key lookup fails the way a remote key service does. */
const keyStoreWhoseLookupRejects = (cause: unknown): KeyStore => {
	const real = createSymmetricKeyStore(SECRET, "v0");
	return {
		algorithm: real.algorithm,
		sign: (o) => real.sign(o),
		getSigningKidFallback: () => real.getSigningKidFallback(),
		getVerificationKeys: () => real.getVerificationKeys(),
		getVerificationKey: async () => {
			throw cause;
		},
	};
};

const spyLogger = (): Logger => {
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: () => logger,
	};
	return logger as unknown as Logger;
};

describe("verifyJwt — a keystore that cannot answer", () => {
	it("refuses the token as verification_key_unavailable, not kid_unknown", async () => {
		const keyStore = keyStoreWhoseLookupRejects(new Error("connect ECONNREFUSED 10.0.0.7:8200"));
		await expect(verifyJwt(await mint(), keyStore, options)).rejects.toMatchObject({
			name: "JwtVerificationError",
			reason: "verification_key_unavailable",
		});
	});

	it("reads a thrown value that is not an Error as an outage too", async () => {
		const keyStore = keyStoreWhoseLookupRejects("timeout");
		await expect(verifyJwt(await mint(), keyStore, options)).rejects.toMatchObject({
			reason: "verification_key_unavailable",
		});
	});

	it("keeps what the keystore threw as the cause, so the caller's log names the dependency", async () => {
		const cause = Object.assign(new Error("connect ECONNREFUSED 10.0.0.7:8200"), {
			code: "ECONNREFUSED",
		});
		const err = await verifyJwt(await mint(), keyStoreWhoseLookupRejects(cause), options).catch(
			(e: unknown) => e,
		);
		expect(err).toBeInstanceOf(JwtVerificationError);
		expect((err as Error).cause).toBe(cause);
		expect(loggableError(err).cause).toMatchObject({ name: "Error", code: "ECONNREFUSED" });
	});

	it("logs jwt_verify_rejected with reason verification_key_unavailable", async () => {
		const logger = spyLogger();
		await verifyJwt(await mint(), keyStoreWhoseLookupRejects(new Error("down")), {
			...options,
			logger,
		}).catch(() => undefined);
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ reason: "verification_key_unavailable" }),
			"jwt_verify_rejected",
		);
	});

	it("still reports a kid the keystore does not hold as kid_unknown", async () => {
		// The working keystore: this is the attacker-fabricated header, and it
		// must stay the client's fault.
		const keyStore = createSymmetricKeyStore(SECRET, "v0");
		const err = await verifyJwt(await mint("fabricated"), keyStore, options).catch(
			(e: unknown) => e,
		);
		expect(err).toMatchObject({ reason: "kid_unknown" });
		expect(isVerificationUnavailable(err)).toBe(false);
	});

	it("still reports a retired kid as kid_expired", async () => {
		const keyStore = keyStoreWhoseLookupRejects(new ExpiredKidError("v0", new Date(0)));
		const err = await verifyJwt(await mint(), keyStore, options).catch((e: unknown) => e);
		expect(err).toMatchObject({ reason: "kid_expired" });
		expect(isVerificationUnavailable(err)).toBe(false);
	});
});

describe("isVerificationUnavailable — an outage, whichever dependency it was", () => {
	it("is true for a keystore that could not answer and for a revocation store that could not", () => {
		expect(
			isVerificationUnavailable(new JwtVerificationError("verification_key_unavailable", "x")),
		).toBe(true);
		expect(isVerificationUnavailable(new JwtVerificationError("revocation_unavailable", "x"))).toBe(
			true,
		);
	});

	it("is false for every finding about the token", () => {
		for (const reason of [
			"signature",
			"expired",
			"typ",
			"azp",
			"kid_unknown",
			"kid_expired",
			"revoked",
		] as const) {
			expect(isVerificationUnavailable(new JwtVerificationError(reason, "x"))).toBe(false);
		}
	});

	it("is false for something that is not a verification error", () => {
		expect(isVerificationUnavailable(new Error("verification_key_unavailable"))).toBe(false);
		expect(isVerificationUnavailable({ reason: "verification_key_unavailable" })).toBe(false);
		expect(isVerificationUnavailable(undefined)).toBe(false);
	});

	it("names the dependency in a description a caller may put on the wire", () => {
		expect(VERIFICATION_UNAVAILABLE_DESCRIPTION).toEqual({
			verification_key_unavailable: "verification key unavailable",
			revocation_unavailable: "revocation store unavailable",
		});
	});
});
