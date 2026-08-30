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
 * Issue #296 — the watermark only revokes anything if `verifyJwt` honours it.
 * This is the seam between "a credential change recorded a moment" and "the
 * tokens issued before it stop working".
 */

import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { verifyJwt } from "#/jwt/verify.mjs";
import { createSymmetricKeyStore } from "#/keys/KeyStore.mjs";
import { createInMemorySubjectRevocation } from "#/user-sessions/memory/subjectRevocation.mjs";
import type { SubjectRevocation } from "#/user-sessions/types.mjs";

const ISSUER = "https://issuer.example";
const keyStore = createSymmetricKeyStore("test-secret-at-least-32-chars!!");

const mint = async (
	opts: { sub?: string; iatSeconds?: number; omitIat?: boolean } = {},
): Promise<string> => {
	const iat = opts.iatSeconds ?? Math.floor(Date.now() / 1000);
	let builder = new SignJWT({ ...(opts.sub === undefined ? {} : { sub: opts.sub }) })
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
		// forward what the composition wired (#367).
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

describe("verifyJwt — subject revocation watermark (#296)", () => {
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
		// An unreachable backend must not read as "not revoked" — the same
		// stance the jti denylist takes. Since #408 the *reason* separates the
		// outage from a finding (see the outage suite below); the refusal
		// itself is unchanged and is what this pins.
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

	it("rejects a token with no iat while a watermark is in force (#376, fail-closed)", async () => {
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
 * #408 — a store outage is not a revocation.
 *
 * Failing closed on an unreachable store is right, but reporting it as
 * `reason: "revoked"` makes it indistinguishable from a real one. The refresh
 * grant maps every verification error to `400 invalid_grant`, and per RFC 6749
 * §5.2 a client discards its refresh token on that — so a transient outage did
 * not degrade the service, it force-logged-out every user who refreshed during
 * it. A distinct reason is what lets a caller answer `503` instead.
 *
 * Not reachable before #321, which is why it shipped: the only adapter was
 * in-process and could not fail. It became live the moment a Redis one existed.
 */
describe("verifyJwt — subject revocation store outage (#408)", () => {
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
 * #408 (related) — cross-replica clock skew around the watermark.
 *
 * The comparison is `iat <= floor(watermark / 1000)`: inclusive, but only to
 * the same second. A minting replica whose clock runs a second or more ahead
 * of the replica that wrote the watermark stamps `iat` past it, so tokens
 * minted *just before* the credential change survive it — the exact case the
 * inclusive comparison exists to catch, one second further out.
 *
 * The fix is not `clockSkewMs`. That defaults to five minutes (RFC 8725 §3.10,
 * for `exp`/`nbf`), and applying it here would refuse every token minted in
 * the five minutes after a reset — including the one from the re-login the
 * reset sends the user to. The allowance is its own small value.
 */
describe("verifyJwt — watermark clock skew (#408)", () => {
	const withWatermark = async (watermarkSec: number) => {
		const store = createInMemorySubjectRevocation();
		await store.revokeBefore("u1", new Date(watermarkSec * 1000), new Date(Date.now() + 300_000));
		return store;
	};

	it("refuses a token one second past the watermark by default", async () => {
		// The finding: a replica one second ahead used to mint survivors.
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

	it("widens with an explicit allowance", async () => {
		const nowSec = Math.floor(Date.now() / 1000);
		const store = await withWatermark(nowSec - 10);
		const token = await mint({ sub: "u1", iatSeconds: nowSec - 8 });
		await expect(verify(token, store, { subjectRevocationSkewMs: 3_000 })).rejects.toMatchObject({
			reason: "revoked",
		});
	});
});
