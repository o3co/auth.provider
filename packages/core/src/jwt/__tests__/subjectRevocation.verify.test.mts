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

const verify = (token: string, subjectRevocation?: SubjectRevocation) =>
	verifyJwt(token, keyStore, {
		type: "access_token",
		expectedIssuer: ISSUER,
		...(subjectRevocation ? { subjectRevocation } : {}),
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
		// stance the jti denylist takes.
		const token = await mint({ sub: "u1" });
		const broken: SubjectRevocation = {
			kind: "broken",
			async revokeBefore() {},
			async revokedBefore() {
				throw new Error("redis down");
			},
		};
		await expect(verify(token, broken)).rejects.toMatchObject({ reason: "revoked" });
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

	it("skips the check for a token with no iat", async () => {
		const store = createInMemorySubjectRevocation();
		await store.revokeBefore("u1", new Date(), new Date(Date.now() + 300_000));
		const token = await mint({ sub: "u1", omitIat: true });
		await expect(verify(token, store)).resolves.toBeDefined();
	});
});
