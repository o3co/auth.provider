/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * The subject-revocation watermark only revokes anything if `verifyJwt`
 * honours it. This is the seam between "a credential change recorded a moment" and "the
 * tokens issued before it stop working".
 */

import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
	claimCoveredByRevocationBoundary,
	isVerificationUnavailable,
	JwtVerificationError,
	verifyJwt,
} from "#/jwt/verify.mjs";
import { createSymmetricKeyStore } from "#/keys/KeyStore.mjs";
import { createInMemorySubjectRevocation } from "#/user-sessions/memory/subjectRevocation.mjs";
import type { SubjectRevocation } from "#/user-sessions/types.mjs";

const ISSUER = "https://issuer.example";
const keyStore = createSymmetricKeyStore("test-secret-at-least-32-chars!!");

const mint = async (
	opts: { sub?: string; iatSeconds?: number; omitIat?: boolean; authTime?: unknown } = {},
): Promise<string> => {
	const iat = opts.iatSeconds ?? Math.floor(Date.now() / 1000);
	let builder = new SignJWT({
		...(opts.sub === undefined ? {} : { sub: opts.sub }),
		...("authTime" in opts ? { auth_time: opts.authTime } : {}),
	})
		.setProtectedHeader({ alg: "HS256", typ: "at+jwt", kid: keyStore.getSigningKidFallback() })
		.setIssuer(ISSUER)
		.setExpirationTime(iat + 3600);
	if (!opts.omitIat) builder = builder.setIssuedAt(iat);
	return builder.sign(new TextEncoder().encode("test-secret-at-least-32-chars!!"));
};

const verify = (
	token: string,
	subjectRevocation?: SubjectRevocation,
	opts: { subjectRevocationSkewMs?: number } = {},
) =>
	verifyJwt(token, keyStore, {
		type: "access_token",
		expectedIssuer: ISSUER,
		// The bundle form even when the store may be undefined: this suite
		// plays the role of a token-accepting surface, and those always
		// forward what the composition wired.
		revocation: { subjectRevocation },
		...(opts.subjectRevocationSkewMs === undefined
			? {}
			: { subjectRevocationSkewMs: opts.subjectRevocationSkewMs }),
	});

/** A store whose consult always fails — a transient outage, not a revocation. */
const outageStore = (): SubjectRevocation => ({
	kind: "outage",
	async revokeBefore() {},
	async revokedBefore() {
		throw new Error("ECONNREFUSED");
	},
});

describe("verifyJwt — subject revocation watermark", () => {
	it("accepts a token when the subject has no watermark", async () => {
		const token = await mint({ sub: "u1" });
		await expect(verify(token, createInMemorySubjectRevocation())).resolves.toBeDefined();
	});

	it("rejects a token issued before the watermark", async () => {
		const nowSec = Math.floor(Date.now() / 1000);
		const token = await mint({ sub: "u1", iatSeconds: nowSec - 60 });
		const store = createInMemorySubjectRevocation();
		await store.revokeBefore("u1", new Date(nowSec * 1000), new Date(Date.now() + 300_000));
		await expect(verify(token, store)).rejects.toMatchObject({ reason: "revoked" });
	});

	it("rejects a token issued in the SAME second as the watermark", async () => {
		// `iat` is second-truncated and replicas do not share a clock, so a token
		// minted just before the revocation routinely lands in this second.
		// Letting it through is the vulnerability; killing one minted just after
		// costs a retry.
		const nowSec = Math.floor(Date.now() / 1000);
		const token = await mint({ sub: "u1", iatSeconds: nowSec });
		const store = createInMemorySubjectRevocation();
		await store.revokeBefore("u1", new Date(nowSec * 1000), new Date(Date.now() + 300_000));
		await expect(verify(token, store)).rejects.toMatchObject({ reason: "revoked" });
	});

	it("accepts a token issued after the watermark", async () => {
		const nowSec = Math.floor(Date.now() / 1000);
		const store = createInMemorySubjectRevocation();
		await store.revokeBefore("u1", new Date((nowSec - 60) * 1000), new Date(Date.now() + 300_000));
		const token = await mint({ sub: "u1", iatSeconds: nowSec });
		await expect(verify(token, store)).resolves.toBeDefined();
	});

	it("does not revoke a different subject's token", async () => {
		const nowSec = Math.floor(Date.now() / 1000);
		const store = createInMemorySubjectRevocation();
		await store.revokeBefore("u1", new Date(nowSec * 1000), new Date(Date.now() + 300_000));
		const token = await mint({ sub: "u2", iatSeconds: nowSec - 60 });
		await expect(verify(token, store)).resolves.toBeDefined();
	});

	it("fails closed when the store throws", async () => {
		// An unreachable backend must not read as "not revoked", the same
		// stance the jti denylist takes. The *reason* separates the outage from
		// a finding (see the outage suite below); this pins the refusal.
		const token = await mint({ sub: "u1" });
		const broken: SubjectRevocation = {
			kind: "broken",
			async revokeBefore() {},
			async revokedBefore() {
				throw new Error("redis down");
			},
		};
		await expect(verify(token, broken)).rejects.toMatchObject({
			reason: "revocation_unavailable",
		});
	});

	it("is inert when no store is wired", async () => {
		const token = await mint({ sub: "u1" });
		await expect(verify(token)).resolves.toBeDefined();
	});
});

describe("verifyJwt — the watermark needs both `sub` and `iat` to mean anything", () => {
	// The watermark is a statement about one subject at one moment. A token
	// missing either coordinate cannot be placed relative to it, so the check
	// is skipped rather than guessed at in either direction — and the token is
	// still subject to every other check the verifier makes.

	it("skips the check for a token with no sub", async () => {
		const store = createInMemorySubjectRevocation();
		await store.revokeBefore("u1", new Date(), new Date(Date.now() + 300_000));
		const token = await mint({ iatSeconds: Math.floor(Date.now() / 1000) - 60 });
		await expect(verify(token, store)).resolves.toBeDefined();
	});

	it("rejects a token with no iat while a watermark is in force", async () => {
		// A token that cannot prove it postdates the watermark must not survive
		// it: every token this provider mints carries iat, so an iat-less token
		// is exactly the legacy/foreign shape a credential change must not
		// keep honouring.
		const store = createInMemorySubjectRevocation();
		await store.revokeBefore("u1", new Date(), new Date(Date.now() + 300_000));
		const token = await mint({ sub: "u1", omitIat: true });
		await expect(verify(token, store)).rejects.toMatchObject({ reason: "revoked" });
	});

	it("still accepts a token with no iat when the subject has no watermark", async () => {
		// Absence of iat is only load-bearing while something is in force to
		// compare against — an unrevoked subject sees no behavior change.
		const token = await mint({ sub: "u1", omitIat: true });
		await expect(verify(token, createInMemorySubjectRevocation())).resolves.toBeDefined();
	});
});

/*
 * A store outage is not a revocation. Failing closed on an unreachable store
 * is right, but reporting it as `reason: "revoked"` makes it
 * indistinguishable from a real one. The refresh grant maps every
 * verification error to `400 invalid_grant`, on which a client discards its
 * refresh token (RFC 6749 §5.2), so a transient outage would log out every
 * user who refreshed during it. A distinct reason lets a caller answer `503`
 * instead.
 */
describe("verifyJwt — subject revocation store outage", () => {
	it("reports a consult failure as revocation_unavailable, not revoked", async () => {
		const token = await mint({ sub: "u1" });
		await expect(verify(token, outageStore())).rejects.toMatchObject({
			reason: "revocation_unavailable",
		});
	});

	it("still fails closed — the token is refused either way", async () => {
		const token = await mint({ sub: "u1" });
		await expect(verify(token, outageStore())).rejects.toThrow();
	});

	it("names the store in the message so an operator can tell which one is down", async () => {
		const token = await mint({ sub: "u1" });
		await expect(verify(token, outageStore())).rejects.toMatchObject({
			message: expect.stringContaining("subject revocation"),
		});
	});

	it("keeps a genuine watermark hit reported as revoked", async () => {
		// The two must stay distinguishable in both directions, or the caller's
		// 503 branch would start swallowing real revocations.
		const nowSec = Math.floor(Date.now() / 1000);
		const token = await mint({ sub: "u1", iatSeconds: nowSec - 60 });
		const store = createInMemorySubjectRevocation();
		await store.revokeBefore("u1", new Date(nowSec * 1000), new Date(Date.now() + 300_000));
		await expect(verify(token, store)).rejects.toMatchObject({ reason: "revoked" });
	});
});

/*
 * Cross-replica clock skew around the watermark. Without an allowance the
 * comparison is `iat <= floor(watermark / 1000)`: inclusive, but only to the
 * same second. A minting replica whose clock runs a second or more ahead of
 * the one that wrote the watermark stamps `iat` past it, so tokens minted
 * *just before* the credential change would survive it.
 *
 * The allowance is its own small value, not `clockSkewMs`: that defaults to
 * five minutes (RFC 7519 §4.1.4, for `exp`/`nbf`), and here it would refuse
 * every token minted in the five minutes after a reset, including the one
 * from the re-login the reset sends the user to.
 */
describe("verifyJwt — watermark clock skew", () => {
	const withWatermark = async (watermarkSec: number) => {
		const store = createInMemorySubjectRevocation();
		await store.revokeBefore("u1", new Date(watermarkSec * 1000), new Date(Date.now() + 300_000));
		return store;
	};

	it("refuses a token one second past the watermark by default", async () => {
		// A replica one second ahead must not mint survivors.
		const nowSec = Math.floor(Date.now() / 1000);
		const store = await withWatermark(nowSec - 10);
		const token = await mint({ sub: "u1", iatSeconds: nowSec - 9 });
		await expect(verify(token, store)).rejects.toMatchObject({ reason: "revoked" });
	});

	it("accepts a token past the default allowance", async () => {
		const nowSec = Math.floor(Date.now() / 1000);
		const store = await withWatermark(nowSec - 10);
		const token = await mint({ sub: "u1", iatSeconds: nowSec - 8 });
		await expect(verify(token, store)).resolves.toBeDefined();
	});

	it("keeps the same-second inclusive comparison", async () => {
		const nowSec = Math.floor(Date.now() / 1000);
		const store = await withWatermark(nowSec - 10);
		const token = await mint({ sub: "u1", iatSeconds: nowSec - 10 });
		await expect(verify(token, store)).rejects.toMatchObject({ reason: "revoked" });
	});

	it("restores the exact comparison at subjectRevocationSkewMs: 0", async () => {
		const nowSec = Math.floor(Date.now() / 1000);
		const store = await withWatermark(nowSec - 10);
		const token = await mint({ sub: "u1", iatSeconds: nowSec - 9 });
		await expect(verify(token, store, { subjectRevocationSkewMs: 0 })).resolves.toBeDefined();
	});

	it("does not borrow the five-minute clockSkewMs", async () => {
		// The failure this guards: a re-login right after the reset is refused
		// for the whole skew window, which is why the allowance is its own knob.
		const nowSec = Math.floor(Date.now() / 1000);
		const store = await withWatermark(nowSec - 10);
		const token = await mint({ sub: "u1", iatSeconds: nowSec - 5 });
		await expect(verify(token, store)).resolves.toBeDefined();
	});

	it("rounds a sub-second allowance up, never down", async () => {
		// Truncating would make the guard weaker than what the operator asked
		// for — 1500ms behaving as 1000ms — which is the wrong direction for an
		// allowance that exists to catch a replica running ahead.
		const nowSec = Math.floor(Date.now() / 1000);
		const store = await withWatermark(nowSec - 10);
		const token = await mint({ sub: "u1", iatSeconds: nowSec - 8 });
		await expect(verify(token, store, { subjectRevocationSkewMs: 1_500 })).rejects.toMatchObject({
			reason: "revoked",
		});
	});

	it("refuses to narrow the comparison below the watermark itself", async () => {
		// A negative value would move the boundary *earlier* than the watermark
		// and let pre-revocation tokens through — the opposite of the option's
		// purpose, so it is clamped rather than trusted.
		const nowSec = Math.floor(Date.now() / 1000);
		const store = await withWatermark(nowSec - 10);
		const token = await mint({ sub: "u1", iatSeconds: nowSec - 10 });
		await expect(verify(token, store, { subjectRevocationSkewMs: -60_000 })).rejects.toMatchObject({
			reason: "revoked",
		});
	});

	it("widens with an explicit allowance", async () => {
		const nowSec = Math.floor(Date.now() / 1000);
		const store = await withWatermark(nowSec - 10);
		const token = await mint({ sub: "u1", iatSeconds: nowSec - 8 });
		await expect(verify(token, store, { subjectRevocationSkewMs: 3_000 })).rejects.toMatchObject({
			reason: "revoked",
		});
	});
});

/*
 * The boundary covers a token's authentication instant as well as its
 * issuance: a token minted after the boundary from an authentication made
 * before it is revoked. `auth_time` is held to the same inclusive,
 * second-truncated rule with the same allowance as `iat`.
 */
describe("verifyJwt — the watermark covers a token's auth_time", () => {
	const withWatermark = async (watermarkSec: number) => {
		const store = createInMemorySubjectRevocation();
		await store.revokeBefore("u1", new Date(watermarkSec * 1000), new Date(Date.now() + 300_000));
		return store;
	};

	it.each([
		[0, "revoked"],
		[1, "revoked"],
	] as const)("refuses auth_time at the watermark + %ds by default", async (offset, reason) => {
		const nowSec = Math.floor(Date.now() / 1000);
		const store = await withWatermark(nowSec - 10);
		const token = await mint({ sub: "u1", iatSeconds: nowSec, authTime: nowSec - 10 + offset });
		await expect(verify(token, store)).rejects.toMatchObject({ reason });
	});

	it("accepts auth_time past the default allowance", async () => {
		const nowSec = Math.floor(Date.now() / 1000);
		const store = await withWatermark(nowSec - 10);
		const token = await mint({ sub: "u1", iatSeconds: nowSec, authTime: nowSec - 8 });
		await expect(verify(token, store)).resolves.toBeDefined();
	});

	it("refuses a token issued after the watermark from an authentication before it", async () => {
		const nowSec = Math.floor(Date.now() / 1000);
		const store = await withWatermark(nowSec - 10);
		const token = await mint({ sub: "u1", iatSeconds: nowSec, authTime: nowSec - 60 });
		await expect(verify(token, store)).rejects.toMatchObject({
			reason: "revoked",
			message: expect.stringContaining("auth_time"),
		});
	});

	it("applies the allowance to auth_time as it does to iat", async () => {
		const nowSec = Math.floor(Date.now() / 1000);
		const store = await withWatermark(nowSec - 10);
		const token = await mint({ sub: "u1", iatSeconds: nowSec, authTime: nowSec - 9 });
		await expect(verify(token, store, { subjectRevocationSkewMs: 0 })).resolves.toBeDefined();
		await expect(verify(token, store, { subjectRevocationSkewMs: 3_000 })).rejects.toMatchObject({
			reason: "revoked",
		});
	});

	it("still refuses by iat when auth_time is past the watermark", async () => {
		const nowSec = Math.floor(Date.now() / 1000);
		const store = await withWatermark(nowSec - 10);
		const token = await mint({ sub: "u1", iatSeconds: nowSec - 10, authTime: nowSec });
		await expect(verify(token, store)).rejects.toMatchObject({ reason: "revoked" });
	});

	it("applies the iat rule alone to a token with no auth_time", async () => {
		const nowSec = Math.floor(Date.now() / 1000);
		const store = await withWatermark(nowSec - 10);
		await expect(
			verify(await mint({ sub: "u1", iatSeconds: nowSec - 8 }), store),
		).resolves.toBeDefined();
		await expect(
			verify(await mint({ sub: "u1", iatSeconds: nowSec - 9 }), store),
		).rejects.toMatchObject({ reason: "revoked" });
	});

	it.each([
		["a string", "1700000000"],
		["negative", -1],
		["a fraction", 1_700_000_000.5],
		["null", null],
		["a boolean", true],
		["an object", {}],
	] as const)(
		"refuses an auth_time that is %s while a watermark is in force",
		async (_label, authTime) => {
			const nowSec = Math.floor(Date.now() / 1000);
			const store = await withWatermark(nowSec - 10);
			const token = await mint({ sub: "u1", iatSeconds: nowSec, authTime });
			await expect(verify(token, store)).rejects.toMatchObject({
				reason: "revoked",
				message: expect.stringContaining("auth_time"),
			});
		},
	);

	it.each([
		["a string", "1700000000"],
		["negative", -1],
		["null", null],
	] as const)(
		"accepts an auth_time that is %s when the subject has no watermark",
		async (_label, authTime) => {
			const token = await mint({ sub: "u1", authTime });
			await expect(verify(token, createInMemorySubjectRevocation())).resolves.toBeDefined();
			await expect(verify(token)).resolves.toBeDefined();
		},
	);

	it("reports an outage as revocation_unavailable whatever auth_time says", async () => {
		const nowSec = Math.floor(Date.now() / 1000);
		for (const authTime of [nowSec - 60, "malformed"]) {
			const token = await mint({ sub: "u1", authTime });
			await expect(verify(token, outageStore())).rejects.toMatchObject({
				reason: "revocation_unavailable",
			});
		}
	});

	it("reports a watermark that is no date as revocation_unavailable, never accepting", async () => {
		const token = await mint({ sub: "u1", authTime: Math.floor(Date.now() / 1000) - 60 });
		const invalid: SubjectRevocation = {
			kind: "invalid",
			async revokeBefore() {},
			async revokedBefore() {
				return new Date(Number.NaN);
			},
		};
		await expect(verify(token, invalid)).rejects.toMatchObject({
			reason: "revocation_unavailable",
		});
	});
});

/*
 * The seconds rule `verifyJwt` applies, for a caller that must not mint a
 * token the verifier would refuse on arrival.
 */
describe("claimCoveredByRevocationBoundary", () => {
	const at = (seconds: number) => new Date(seconds * 1000);

	it("covers nothing when no boundary is in force", () => {
		expect(claimCoveredByRevocationBoundary(0, null, 1_000)).toBe(false);
	});

	it("is inclusive to the boundary's second plus the allowance, in whole seconds", () => {
		expect(claimCoveredByRevocationBoundary(100, at(100), 1_000)).toBe(true);
		expect(claimCoveredByRevocationBoundary(101, at(100), 1_000)).toBe(true);
		expect(claimCoveredByRevocationBoundary(102, at(100), 1_000)).toBe(false);
		expect(claimCoveredByRevocationBoundary(101, at(100), 0)).toBe(false);
	});

	it("truncates the boundary to its second", () => {
		expect(claimCoveredByRevocationBoundary(101, new Date(100_900), 0)).toBe(false);
		expect(claimCoveredByRevocationBoundary(100, new Date(100_900), 0)).toBe(true);
	});

	it("rounds the allowance up and clamps a negative one to none", () => {
		expect(claimCoveredByRevocationBoundary(102, at(100), 1_500)).toBe(true);
		expect(claimCoveredByRevocationBoundary(100, at(100), -60_000)).toBe(true);
		expect(claimCoveredByRevocationBoundary(101, at(100), -60_000)).toBe(false);
	});

	it("throws a RangeError for what cannot be compared", () => {
		expect(() => claimCoveredByRevocationBoundary(100, new Date(Number.NaN), 1_000)).toThrow(
			RangeError,
		);
		expect(() =>
			claimCoveredByRevocationBoundary(100, "2026-01-01" as unknown as Date, 1_000),
		).toThrow(RangeError);
		expect(() => claimCoveredByRevocationBoundary(Number.NaN, at(100), 1_000)).toThrow(RangeError);
		expect(() => claimCoveredByRevocationBoundary(100, at(100), Number.NaN)).toThrow(RangeError);
	});
});

/*
 * The predicate callers branch on. Exported rather than left as an inline
 * `instanceof` + `reason` pair at each call site, because the answer changes
 * what a caller says on the wire — `503` versus the `400 invalid_grant` that
 * tells a client to discard its refresh token — and a wrong answer is
 * invisible in a happy-path test.
 */
describe("isVerificationUnavailable", () => {
	it("is true for the reason it names", () => {
		expect(
			isVerificationUnavailable(new JwtVerificationError("revocation_unavailable", "store down")),
		).toBe(true);
	});

	it("is false for a genuine revocation", () => {
		// The distinction the 503 branch rests on: if this were true, the
		// refresh grant would answer 503 to a real credential change and the
		// client would keep its revoked token.
		expect(isVerificationUnavailable(new JwtVerificationError("revoked", "watermark"))).toBe(false);
	});

	it("is false for every other verification failure", () => {
		for (const reason of ["signature", "expired", "typ", "azp", "kid_unknown"] as const) {
			expect(isVerificationUnavailable(new JwtVerificationError(reason, "x"))).toBe(false);
		}
	});

	it("is false for something that is not a verification error at all", () => {
		expect(isVerificationUnavailable(new Error("revocation_unavailable"))).toBe(false);
		expect(isVerificationUnavailable("revocation_unavailable")).toBe(false);
		expect(isVerificationUnavailable({ reason: "revocation_unavailable" })).toBe(false);
		expect(isVerificationUnavailable(undefined)).toBe(false);
		expect(isVerificationUnavailable(null)).toBe(false);
	});
});
