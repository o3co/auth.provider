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
import { createSecretKey } from "node:crypto";
import { SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createMemoryAccessTokenDenylist } from "#/access-token-denylist/memory.mjs";
import type { AccessTokenDenylist } from "#/access-token-denylist/types.mjs";
import { isRevocationUnavailable, verifyJwt } from "#/jwt/verify.mjs";
import { createSymmetricKeyStore, type KeyStore } from "#/keys/KeyStore.mjs";
import type { Logger } from "#/logging/Logger.mjs";

const TEST_SECRET = "test-secret-32-bytes-long-string12";
const TEST_KID = "v0";
const TEST_ISSUER = "https://test";
const TEST_AUDIENCE = "https://rs";

function testKeyStore(): KeyStore {
	return createSymmetricKeyStore(TEST_SECRET, TEST_KID);
}

async function mintAccessToken(
	overrides: Partial<{
		expSeconds: number;
		sub: string;
		jti: string;
	}> = {},
): Promise<{ token: string; jti: string }> {
	const secretKey = createSecretKey(Buffer.from(TEST_SECRET));
	const jti = overrides.jti ?? `jti-${Math.random().toString(36).slice(2)}`;
	const nowSeconds = Math.floor(Date.now() / 1000);
	const expSeconds = overrides.expSeconds ?? nowSeconds + 300;
	const token = await new SignJWT({
		iss: TEST_ISSUER,
		aud: TEST_AUDIENCE,
		sub: overrides.sub ?? "u-1",
		jti,
	})
		.setProtectedHeader({ alg: "HS256", kid: TEST_KID, typ: "at+jwt" })
		.setIssuedAt(nowSeconds)
		.setExpirationTime(expSeconds)
		.sign(secretKey);
	return { token, jti };
}

describe("verifyJwt with AccessTokenDenylist", () => {
	it("rejects a revoked token with reason 'revoked'", async () => {
		const denylist = createMemoryAccessTokenDenylist();
		const { token, jti } = await mintAccessToken();
		await denylist.add(jti, Date.now() + 10 * 60 * 1000);

		await expect(
			verifyJwt(token, testKeyStore(), {
				type: "access_token",
				expectedIssuer: TEST_ISSUER,
				expectedAudience: TEST_AUDIENCE,
				revocation: { denylist },
			}),
		).rejects.toMatchObject({ reason: "revoked" });
	});

	it("accepts a non-revoked token (denylist returns false)", async () => {
		const denylist = createMemoryAccessTokenDenylist();
		const { token } = await mintAccessToken();
		const verified = await verifyJwt(token, testKeyStore(), {
			type: "access_token",
			expectedIssuer: TEST_ISSUER,
			expectedAudience: TEST_AUDIENCE,
			revocation: { denylist },
		});
		expect(verified.payload.sub).toBe("u-1");
	});

	it("ignoreExpiration accepts already-expired token", async () => {
		// Expire well beyond default clock skew (300 s) so the "without flag" path
		// actually rejects. clockSkewMs: 0 on that call makes the test hermetic
		// regardless of the current default skew.
		const pastExpSec = Math.floor(Date.now() / 1000) - 600;
		const { token } = await mintAccessToken({ expSeconds: pastExpSec });

		// Without flag → fails with reason "expired"
		await expect(
			verifyJwt(token, testKeyStore(), {
				type: "access_token",
				revocation: "none",
				expectedIssuer: TEST_ISSUER,
				expectedAudience: TEST_AUDIENCE,
				clockSkewMs: 0,
			}),
		).rejects.toMatchObject({ reason: "expired" });

		// With flag → passes
		const verified = await verifyJwt(token, testKeyStore(), {
			type: "access_token",
			revocation: "none",
			expectedIssuer: TEST_ISSUER,
			expectedAudience: TEST_AUDIENCE,
			ignoreExpiration: true,
		});
		expect(verified.payload.sub).toBe("u-1");
	});

	it("does NOT consult denylist when option is undefined (default)", async () => {
		// Confirms backwards-compat: existing callers (no denylist option) see no behavior change.
		const { token } = await mintAccessToken();
		const verified = await verifyJwt(token, testKeyStore(), {
			type: "access_token",
			revocation: "none",
			expectedIssuer: TEST_ISSUER,
			expectedAudience: TEST_AUDIENCE,
		});
		expect(verified.payload.sub).toBe("u-1");
	});

	it("fail-closed: denylist.has() throwing causes JwtVerificationError reason=revocation_unavailable (Copilot review #3, #459)", async () => {
		// SECURITY: if the denylist backend (e.g. Redis) is unavailable, we cannot
		// determine revocation state. Failing open would accept revoked tokens during
		// the outage; secure default is to reject. The refusal is what this pins
		// and it has not changed. The *reason* has: since #459 it is
		// `revocation_unavailable`, not `revoked` — see the outage suite below.
		const throwingDenylist = {
			kind: "throwing-test-stub",
			add: async () => {},
			has: async () => {
				throw new Error("simulated denylist backend outage");
			},
		};
		const { token } = await mintAccessToken();
		await expect(
			verifyJwt(token, testKeyStore(), {
				type: "access_token",
				expectedIssuer: TEST_ISSUER,
				expectedAudience: TEST_AUDIENCE,
				revocation: { denylist: throwingDenylist },
			}),
		).rejects.toMatchObject({
			reason: "revocation_unavailable",
			message: expect.stringContaining("denylist consult failed"),
		});
	});
});

/*
 * #459 — a denylist backend outage is not a revocation.
 *
 * Failing closed on an unreachable denylist is right, but reporting it as
 * `reason: "revoked"` made it indistinguishable from a real one. The comment
 * above the consult claimed operators could tell the two apart via the error
 * message; `emitRejection` logs the reason and not the message, so a Redis
 * blip and a genuinely revoked token produced the same
 * `jwt_verify_rejected reason=revoked` line — for every token, on every
 * replica, until the backend came back. #408 already split the outage from
 * the finding for the subject watermark and named it `revocation_unavailable`;
 * the denylist path predates that and was not brought in line.
 *
 * Nothing here lets a token through. It only stops an outage from being
 * labelled as a revocation.
 */
describe("verifyJwt — denylist backend outage (#459)", () => {
	/** A denylist whose consult always fails — a transient outage, not a revocation. */
	const outageDenylist = (): AccessTokenDenylist => ({
		kind: "outage",
		async add() {},
		async has() {
			throw new Error("ECONNREFUSED");
		},
	});

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

	const verifyWith = async (denylist: AccessTokenDenylist, logger?: Logger) => {
		const { token } = await mintAccessToken();
		return verifyJwt(token, testKeyStore(), {
			type: "access_token",
			expectedIssuer: TEST_ISSUER,
			expectedAudience: TEST_AUDIENCE,
			revocation: { denylist },
			...(logger === undefined ? {} : { logger }),
		});
	};

	/** Resolve to the rejection so the error object itself can be inspected. */
	const rejectionOf = (p: Promise<unknown>): Promise<unknown> =>
		p.then(
			() => undefined,
			(cause: unknown) => cause,
		);

	it("reports a consult failure as revocation_unavailable, not revoked", async () => {
		await expect(verifyWith(outageDenylist())).rejects.toMatchObject({
			reason: "revocation_unavailable",
		});
	});

	it("is covered by isRevocationUnavailable — one predicate for both stores", async () => {
		// A caller that answers 503 for a watermark outage (#408) must not
		// have to know which store was down to give the denylist outage the
		// same answer.
		const err = await rejectionOf(verifyWith(outageDenylist()));
		expect(isRevocationUnavailable(err)).toBe(true);
	});

	it("still fails closed — the token is refused either way", async () => {
		await expect(verifyWith(outageDenylist())).rejects.toThrow();
	});

	it("names the store in the message so an operator can tell which one is down", async () => {
		await expect(verifyWith(outageDenylist())).rejects.toMatchObject({
			message: expect.stringContaining("denylist"),
		});
	});

	it("logs jwt_verify_rejected with reason=revocation_unavailable — the field operators actually see", async () => {
		// The audit record carries the reason, not the message. This pins the
		// field a SIEM filter indexes on, which is the one the issue was about.
		const logger = spyLogger();
		await expect(verifyWith(outageDenylist(), logger)).rejects.toThrow();
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ reason: "revocation_unavailable" }),
			"jwt_verify_rejected",
		);
		expect(logger.warn).not.toHaveBeenCalledWith(
			expect.objectContaining({ reason: "revoked" }),
			"jwt_verify_rejected",
		);
	});

	it("keeps a genuine denylist hit reported as revoked, outside the predicate", async () => {
		// The two must stay distinguishable in both directions, or a caller's
		// 503 branch would start swallowing real revocations.
		const denylist = createMemoryAccessTokenDenylist();
		const { token, jti } = await mintAccessToken();
		await denylist.add(jti, Date.now() + 10 * 60 * 1000);
		const err = await rejectionOf(
			verifyJwt(token, testKeyStore(), {
				type: "access_token",
				expectedIssuer: TEST_ISSUER,
				expectedAudience: TEST_AUDIENCE,
				revocation: { denylist },
			}),
		);
		expect(err).toMatchObject({ reason: "revoked" });
		expect(isRevocationUnavailable(err)).toBe(false);
	});
});
