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
 * The Store owns email-verification state and its flow; auth.provider only
 * surfaces `email_verified` in what it issues. This pins the whole path, from
 * a `User` the Store returned through `claimFilter` (`emailVerified` →
 * `email_verified`) into a signed id_token, so a change at either end cannot
 * break it silently.
 */

import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { generateIdToken } from "#/grants/idToken.mjs";
import { createSymmetricKeyStore } from "#/keys/KeyStore.mjs";
import type { UserSessionClaims } from "#/user-sessions/types.mjs";

const keyStore = createSymmetricKeyStore("test-secret-at-least-32-chars!!");

const idTokenClaims = async (
	userClaims: UserSessionClaims,
	scopes: readonly string[],
): Promise<Record<string, unknown>> => {
	const { token } = await generateIdToken({
		issuer: "https://issuer.example",
		sub: "user-1",
		aud: "client-a",
		sid: "sid-1",
		authTime: new Date(),
		scopes,
		userClaims,
		keyStore,
	});
	return decodeJwt(token) as Record<string, unknown>;
};

describe("email_verified reaches the id_token", () => {
	it("carries a verified address under the email scope", async () => {
		const claims = await idTokenClaims({ email: "a@example.test", emailVerified: true }, [
			"openid",
			"email",
		]);
		expect(claims.email).toBe("a@example.test");
		expect(claims.email_verified).toBe(true);
	});

	it("carries an UNverified address as false, not as absence", async () => {
		// The difference matters: a relying party that gates on the claim must be
		// able to tell "the Store says no" from "the Store said nothing".
		const claims = await idTokenClaims({ email: "a@example.test", emailVerified: false }, [
			"openid",
			"email",
		]);
		expect(claims.email_verified).toBe(false);
	});

	it("omits it when the Store did not model verification state", async () => {
		const claims = await idTokenClaims({ email: "a@example.test" }, ["openid", "email"]);
		expect(claims.email).toBe("a@example.test");
		expect("email_verified" in claims).toBe(false);
	});

	it("omits it without the email scope, even when the Store supplied it", async () => {
		const claims = await idTokenClaims({ email: "a@example.test", emailVerified: true }, [
			"openid",
			"profile",
		]);
		expect("email_verified" in claims).toBe(false);
		expect("email" in claims).toBe(false);
	});

	it("drops a non-boolean verification value rather than forwarding it", async () => {
		// A Store reached across an untyped boundary can return anything. A
		// truthy string must not become `email_verified: "no"` in a signed token
		// that relying parties gate on.
		const claims = await idTokenClaims(
			{ email: "a@example.test", emailVerified: "no" } as unknown as UserSessionClaims,
			["openid", "email"],
		);
		expect("email_verified" in claims).toBe(false);
	});
});
