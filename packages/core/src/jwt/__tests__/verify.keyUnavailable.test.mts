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
import { auditedError } from "#/audit/auditedError.mjs";
import {
	isVerificationUnavailable,
	JwtVerificationError,
	type JwtVerifyOptions,
	VERIFICATION_UNAVAILABLE_DESCRIPTION,
	verifyJwt,
} from "#/jwt/verify.mjs";
import {
	createSymmetricKeyStore,
	ExpiredKidError,
	type KeyStore,
	UnknownKidError,
} from "#/keys/KeyStore.mjs";
import { MAX_KID_LENGTH } from "#/keys/kid.mjs";
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

	it("reads a signing-kid fallback that throws as an outage too — for a token with no kid", async () => {
		// A kid-less token asks the keystore for its current kid instead; a
		// remote store that cannot say is as unavailable as one that cannot
		// look a key up, and its error must not escape the verifier raw.
		const real = createSymmetricKeyStore(SECRET, "v0");
		const keyStore: KeyStore = {
			...keyStoreWhoseLookupRejects(new Error("unused")),
			getVerificationKey: (kid) => real.getVerificationKey(kid),
			getSigningKidFallback: () => {
				throw new Error("connect ECONNREFUSED 10.0.0.7:8200");
			},
		};
		const kidless = await new SignJWT({ sub: "user-1" })
			.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
			.setIssuer(ISSUER)
			.setIssuedAt()
			.setExpirationTime("5m")
			.sign(createSecretKey(Buffer.from(SECRET)));
		const err = await verifyJwt(kidless, keyStore, options).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(JwtVerificationError);
		expect(err).toMatchObject({ reason: "verification_key_unavailable" });
	});

	it("names itself, so an audit's details.cause.name says what failed", async () => {
		const err = await verifyJwt(
			await mint(),
			keyStoreWhoseLookupRejects(new Error("down")),
			options,
		).catch((e: unknown) => e);
		expect(auditedError(err)).toMatchObject({ name: "JwtVerificationError" });
		expect(String((err as Error).stack).split("\n")[0]).toMatch(/^JwtVerificationError: /);
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

/*
 * A header the client made up is the client's, never an outage.
 *
 * `kid` and `typ` come from the token and were used without a type check: the
 * bundled keystores build `Unknown kid: ${kid}`, so a `kid` of
 * `{"toString": null}` threw a TypeError inside `UnknownKidError`'s
 * constructor, and that TypeError — raised while handling the client's input —
 * was classified as the keystore failing to answer. An unauthenticated caller
 * could turn any verifying route into a 503 and an error-level outage line,
 * before a signature was checked. The same held for `typ`, whose message
 * interpolated the header value.
 */
describe("verifyJwt — a kid or typ the client made up", () => {
	const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
	/** A token whose protected header carries `header` as written; the signature is never reached. */
	const crafted = (header: Record<string, unknown>) => {
		const now = Math.floor(Date.now() / 1000);
		return `${b64({ alg: "HS256", typ: "at+jwt", ...header })}.${b64({ iss: ISSUER, sub: "u", iat: now, exp: now + 60 })}.AAAA`;
	};
	/** The working keystore, with its key lookups counted. */
	const countingKeyStore = () => {
		const real = createSymmetricKeyStore(SECRET, "v0");
		const lookups: unknown[] = [];
		const keyStore: KeyStore = {
			algorithm: real.algorithm,
			sign: (o) => real.sign(o),
			getSigningKidFallback: () => real.getSigningKidFallback(),
			getVerificationKeys: () => real.getVerificationKeys(),
			getVerificationKey: async (kid) => {
				lookups.push(kid);
				return real.getVerificationKey(kid);
			},
		};
		return { keyStore, lookups };
	};

	// A header is JSON, so a `toString` that throws arrives as one that is not
	// callable: `{"toString": null}` and `{"toString": 1, "valueOf": 1}` make
	// every conversion to a string throw. A `toString` that throws when called
	// can only come from code — a custom keystore — and is pinned on the
	// finding errors' constructors below.
	const MALFORMED_KIDS: ReadonlyArray<readonly [string, unknown]> = [
		["an object whose toString is null", { toString: null }],
		["an object with neither conversion", { toString: 1, valueOf: 1 }],
		["a number", 123],
		["an array", []],
		["an object", { a: 1 }],
		["a string longer than MAX_KID_LENGTH", "k".repeat(MAX_KID_LENGTH + 1)],
		// The rule a keystore is built with (`keys/kid.mts`): a kid no keystore
		// can hold is never asked for.
		["an empty string", ""],
		["a string carrying a line feed", "v0\nx"],
		["a string carrying a NUL byte", "v0\u0000"],
		// Present and null is not absent: it does not fall back to the
		// signing kid, as a missing kid does.
		["null", null],
	];

	for (const [label, kid] of MALFORMED_KIDS) {
		it(`refuses ${label} as kid_unknown, before the keystore is asked`, async () => {
			const { keyStore, lookups } = countingKeyStore();
			const err = await verifyJwt(crafted({ kid }), keyStore, options).catch((e: unknown) => e);
			expect(err).toMatchObject({ name: "JwtVerificationError", reason: "kid_unknown" });
			expect(isVerificationUnavailable(err)).toBe(false);
			expect(lookups).toEqual([]);
		});
	}

	it("still looks up a kid at the length bound", async () => {
		const { keyStore, lookups } = countingKeyStore();
		const err = await verifyJwt(
			crafted({ kid: "k".repeat(MAX_KID_LENGTH) }),
			keyStore,
			options,
		).catch((e: unknown) => e);
		expect(err).toMatchObject({ reason: "kid_unknown" });
		expect(lookups).toHaveLength(1);
	});

	for (const [label, typ] of [
		["an object whose toString is null", { toString: null }],
		["an object with neither conversion", { toString: 1, valueOf: 1 }],
		["a number", 7],
	] as const) {
		it(`refuses a typ that is ${label} as typ`, async () => {
			const { keyStore, lookups } = countingKeyStore();
			const err = await verifyJwt(crafted({ typ, kid: "v0" }), keyStore, options).catch(
				(e: unknown) => e,
			);
			expect(err).toMatchObject({ name: "JwtVerificationError", reason: "typ" });
			expect(lookups).toEqual([]);
		});
	}
});

/*
 * The keystore's own findings are recognised by name as well as by class, so
 * a composition that ends up with two copies of core — a custom keystore
 * built against one, the verifier from another — does not read "no such kid"
 * as an outage.
 */
describe("verifyJwt — a keystore's findings from another copy of core", () => {
	const named = (name: string) => Object.assign(new Error(`${name} from elsewhere`), { name });

	it("reads an error named UnknownKidError as kid_unknown", async () => {
		const err = await verifyJwt(
			await mint(),
			keyStoreWhoseLookupRejects(named("UnknownKidError")),
			options,
		).catch((e: unknown) => e);
		expect(err).toMatchObject({ reason: "kid_unknown" });
		expect(isVerificationUnavailable(err)).toBe(false);
	});

	it("reads an error named ExpiredKidError as kid_expired", async () => {
		const err = await verifyJwt(
			await mint(),
			keyStoreWhoseLookupRejects(named("ExpiredKidError")),
			options,
		).catch((e: unknown) => e);
		expect(err).toMatchObject({ reason: "kid_expired" });
	});
});

describe("the keystore's finding errors cannot fail to be built", () => {
	it("builds UnknownKidError and ExpiredKidError from any kid a custom keystore hands them", () => {
		const throwing = {
			toString() {
				throw new Error("boom");
			},
		};
		for (const kid of [{ toString: null }, throwing, 1, undefined, "k".repeat(10_000)]) {
			expect(new UnknownKidError(kid as never)).toMatchObject({ name: "UnknownKidError" });
			expect(new ExpiredKidError(kid as never, new Date(0))).toMatchObject({
				name: "ExpiredKidError",
			});
		}
		expect(new UnknownKidError("k".repeat(10_000)).message.length).toBeLessThanOrEqual(300);
	});
});
