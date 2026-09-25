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

import { decodeJwt, decodeProtectedHeader } from "jose";
import { describe, expect, it } from "vitest";
import type { Confirmation } from "#/grants/confirmation.mjs";
import { generateToken, generateTokenResponse } from "#/grants/token.mjs";
import { createSymmetricKeyStore } from "#/keys/KeyStore.mjs";

const keyStore = createSymmetricKeyStore("test-secret-at-least-32-chars!!");

describe("generateToken — a caller-supplied identity (v0.13.0 audit)", () => {
	it("refuses an empty jti rather than signing a token with no identity", async () => {
		// `jti` is supplied when a token's identity is reserved before it is
		// signed (#449). An empty one would be signed as-is, and every replay
		// check keyed on it would share one key.
		await expect(generateToken({}, { keyStore, jti: "" })).rejects.toThrow(/jti/);
	});

	it("refuses an issuedAt that is not a whole number of epoch seconds", async () => {
		for (const issuedAt of [Number.NaN, 1.5, -1, Number.POSITIVE_INFINITY]) {
			await expect(generateToken({}, { keyStore, issuedAt }), String(issuedAt)).rejects.toThrow(
				/issuedAt/,
			);
		}
	});

	it("refuses an expiresIn that is not a positive whole number of seconds, before signing", async () => {
		// `exp` is `iat + expiresIn`. A fraction signs a fractional `exp` that
		// verifiers round their own way, NaN signs `"exp": null`, Infinity an
		// expiry that JSON writes as null too, and zero or less a token that is
		// dead on arrival. None of them should cost a signature.
		let signed = 0;
		const counting = {
			...keyStore,
			sign: (input: Parameters<typeof keyStore.sign>[0]) => {
				signed += 1;
				return keyStore.sign(input);
			},
		};
		for (const expiresIn of [
			1.5,
			Number.NaN,
			Number.POSITIVE_INFINITY,
			0,
			-60,
			Number.MAX_SAFE_INTEGER + 1,
		]) {
			await expect(
				generateToken({}, { keyStore: counting, expiresIn }),
				String(expiresIn),
			).rejects.toThrow(RangeError);
			await expect(generateToken({}, { keyStore: counting, expiresIn })).rejects.toThrow(
				/expiresIn/,
			);
		}
		expect(signed).toBe(0);
	});

	it("refuses an expiry past Number.MAX_SAFE_INTEGER, where iat + expiresIn stops being exact, before signing", async () => {
		// Each operand is a safe integer; their sum is not. Past 2^53 the `exp`
		// that is signed is a rounded neighbour of the one computed — the same
		// value for different lifetimes — so it is refused rather than signed.
		let signed = 0;
		const counting = {
			...keyStore,
			sign: (input: Parameters<typeof keyStore.sign>[0]) => {
				signed += 1;
				return keyStore.sign(input);
			},
		};
		const cases: Array<{ issuedAt?: number; expiresIn: number }> = [
			{ issuedAt: Number.MAX_SAFE_INTEGER - 10, expiresIn: 60 },
			{ issuedAt: Number.MAX_SAFE_INTEGER, expiresIn: 1 },
			// The clock's own iat, and the largest lifetime the check above admits.
			{ expiresIn: Number.MAX_SAFE_INTEGER },
		];
		for (const { issuedAt, expiresIn } of cases) {
			const options = {
				keyStore: counting,
				expiresIn,
				...(issuedAt === undefined ? {} : { issuedAt }),
			};
			await expect(
				generateToken({}, options),
				JSON.stringify({ issuedAt, expiresIn }),
			).rejects.toThrow(RangeError);
			await expect(generateToken({}, options)).rejects.toThrow(/exp/);
		}
		expect(signed).toBe(0);

		// The largest exact expiry is still signed.
		const edge = await generateToken(
			{},
			{ keyStore, issuedAt: Number.MAX_SAFE_INTEGER - 60, expiresIn: 60 },
		);
		expect(decodeJwt(edge.token).exp).toBe(Number.MAX_SAFE_INTEGER);
	});

	it("signs exactly the jti and issuedAt it is given", async () => {
		const token = await generateToken(
			{},
			{ keyStore, jti: "reserved-1", issuedAt: 1_700_000_000, expiresIn: 60 },
		);
		const claims = decodeJwt(token.token);
		expect(claims).toMatchObject({ jti: "reserved-1", iat: 1_700_000_000, exp: 1_700_000_060 });
	});
});

describe("generateToken", () => {
	it("returns a Token with a valid JWT string", async () => {
		const token = await generateToken(
			{},
			{
				keyStore,
				expiresIn: 3600,
				tokenType: "at+jwt",
			},
		);

		expect(token.token).toBeDefined();
		expect(typeof token.token).toBe("string");
		expect(token.token.split(".")).toHaveLength(3);
	});

	it("sets kid in JWT protected header", async () => {
		const token = await generateToken(
			{},
			{
				keyStore,
				tokenType: "at+jwt",
			},
		);

		const header = decodeProtectedHeader(token.token);
		expect(header.alg).toBe("HS256");
		expect(header.kid).toBe("v0");
	});

	it("sets custom kid from keyStore", async () => {
		const ks = createSymmetricKeyStore("test-secret-at-least-32-chars!!", "v2");
		const token = await generateToken(
			{},
			{
				keyStore: ks,
				tokenType: "at+jwt",
			},
		);

		const header = decodeProtectedHeader(token.token);
		expect(header.kid).toBe("v2");
	});

	it("sets sub claim via subject option", async () => {
		const token = await generateToken(
			{},
			{
				keyStore,
				subject: "user-123",
				tokenType: "at+jwt",
			},
		);

		const payload = decodeJwt(token.token);
		expect(payload.sub).toBe("user-123");
		expect(token.subject).toBe("user-123");
	});

	it("sets azp claim via authorizedParty option", async () => {
		const token = await generateToken(
			{},
			{
				keyStore,
				authorizedParty: "client-abc",
				tokenType: "at+jwt",
			},
		);

		const payload = decodeJwt(token.token);
		expect((payload as Record<string, unknown>).azp).toBe("client-abc");
	});

	it("sets scope claim as string in payload", async () => {
		const token = await generateToken(
			{},
			{
				keyStore,
				scope: "read write",
				tokenType: "at+jwt",
			},
		);

		const payload = decodeJwt(token.token);
		expect((payload as Record<string, unknown>).scope).toBe("read write");
		expect(token.scope).toBe("read write");
	});

	it("sets typ in protected header via tokenType option", async () => {
		const token = await generateToken(
			{},
			{
				keyStore,
				tokenType: "at+jwt",
			},
		);

		const header = decodeProtectedHeader(token.token);
		expect(header.typ).toBe("at+jwt");
		expect(token.tokenType).toBe("at+jwt");
	});

	it("sets typ to rt+jwt for refresh tokens", async () => {
		const token = await generateToken(
			{},
			{
				keyStore,
				tokenType: "rt+jwt",
			},
		);

		const header = decodeProtectedHeader(token.token);
		expect(header.typ).toBe("rt+jwt");
		expect(token.tokenType).toBe("rt+jwt");
	});

	it("does not include legacy user, client, scopes, type, ip in payload", async () => {
		const token = await generateToken(
			{},
			{
				keyStore,
				subject: "user-123",
				authorizedParty: "client-abc",
				scope: "read",
				tokenType: "at+jwt",
			},
		);

		const payload = decodeJwt(token.token) as Record<string, unknown>;
		expect(payload.user).toBeUndefined();
		expect(payload.client).toBeUndefined();
		expect(payload.scopes).toBeUndefined();
		expect(payload.type).toBeUndefined();
		expect(payload.ip).toBeUndefined();
	});

	it("includes expiresIn, audience, issuer, scope, tokenType in result", async () => {
		const token = await generateToken(
			{},
			{
				keyStore,
				expiresIn: 3600,
				issuer: "auth.provider",
				audience: "client1",
				scope: "read write",
				tokenType: "at+jwt",
			},
		);

		expect(token.expiresIn).toBe(3600);
		expect(token.issuer).toBe("auth.provider");
		expect(token.audience).toBe("client1");
		expect(token.scope).toBe("read write");
		expect(token.tokenType).toBe("at+jwt");
	});

	it("omits optional fields when not provided", async () => {
		const token = await generateToken({}, { keyStore, tokenType: "at+jwt" });

		expect(token.expiresIn).toBeUndefined();
		expect(token.issuer).toBeUndefined();
		expect(token.audience).toBeUndefined();
		expect(token.scope).toBeUndefined();
		expect(token.subject).toBeUndefined();
	});

	it("sets jti claim in JWT payload", async () => {
		const token = await generateToken({}, { keyStore, tokenType: "at+jwt" });
		const payload = decodeJwt(token.token);
		expect(typeof payload.jti).toBe("string");
		expect(payload.jti).toMatch(
			/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
		);
	});

	it("generates a unique jti per token", async () => {
		const t1 = await generateToken({}, { keyStore, tokenType: "at+jwt" });
		const t2 = await generateToken({}, { keyStore, tokenType: "at+jwt" });
		const p1 = decodeJwt(t1.token);
		const p2 = decodeJwt(t2.token);
		expect(p1.jti).not.toBe(p2.jti);
	});
});

describe("generateTokenResponse", () => {
	it("formats access token response", async () => {
		const accessToken = await generateToken(
			{},
			{
				keyStore,
				expiresIn: 3600,
				scope: "read",
				tokenType: "at+jwt",
			},
		);

		const response = generateTokenResponse({ accessToken });

		expect(response.access_token).toBe(accessToken.token);
		expect(response.token_type).toBe("Bearer");
		expect(response.expires_in).toBe(3600);
		expect(response.scope).toBe("read");
		expect(response.refresh_token).toBeUndefined();
	});

	it("includes refresh token when provided", async () => {
		const accessToken = await generateToken({}, { keyStore, tokenType: "at+jwt" });
		const refreshToken = await generateToken({}, { keyStore, tokenType: "rt+jwt" });

		const response = generateTokenResponse({ accessToken, refreshToken });

		expect(response.refresh_token).toBe(refreshToken.token);
	});
});

describe("generateTokenResponse with id_token", () => {
	it("includes id_token in the response when provided", () => {
		const resp = generateTokenResponse({
			accessToken: { token: "at", expiresIn: 3600 },
			refreshToken: { token: "rt" },
			idToken: { token: "it" },
		});
		expect(resp.id_token).toBe("it");
	});

	it("omits id_token when not provided (backward compat)", () => {
		const resp = generateTokenResponse({ accessToken: { token: "at", expiresIn: 3600 } });
		expect(resp.id_token).toBeUndefined();
	});
});

describe("generateToken cnf claim emission", () => {
	it("does NOT emit cnf when confirmation is absent", async () => {
		const keyStore = createSymmetricKeyStore("x".repeat(32));
		const token = await generateToken({}, { keyStore });
		const payload = decodeJwt(token.token);
		expect(payload).not.toHaveProperty("cnf");
	});

	it("emits cnf matching confirmation when present (jkt variant)", async () => {
		const keyStore = createSymmetricKeyStore("x".repeat(32));
		const confirmation: Confirmation = { jkt: "abc123" };
		const token = await generateToken({}, { keyStore, confirmation });
		const payload = decodeJwt(token.token);
		expect(payload.cnf).toEqual({ jkt: "abc123" });
	});

	it("emits cnf matching confirmation when present (x5t#S256 variant)", async () => {
		const keyStore = createSymmetricKeyStore("x".repeat(32));
		const confirmation: Confirmation = { "x5t#S256": "def456" };
		const token = await generateToken({}, { keyStore, confirmation });
		const payload = decodeJwt(token.token);
		expect(payload.cnf).toEqual({ "x5t#S256": "def456" });
	});

	it("echoes confirmation on the returned Token", async () => {
		const keyStore = createSymmetricKeyStore("x".repeat(32));
		const confirmation: Confirmation = { jkt: "abc123" };
		const token = await generateToken({}, { keyStore, confirmation });
		expect(token.confirmation).toEqual({ jkt: "abc123" });
	});
});

describe("generateTokenResponse token_type follows the access token's confirmation", () => {
	// RFC 9449 §5: a DPoP-bound access token is `token_type: "DPoP"`. The
	// envelope used to be whatever the grant passed, and a grant that passed
	// nothing (the device grant) advertised a `cnf.jkt` token as Bearer — which
	// a DPoP-aware client then presents as one, and a resource server refuses
	// (§7.1). Read off the confirmation the token carries, the envelope cannot
	// disagree with the claim.
	const keyStore = createSymmetricKeyStore("x".repeat(32));

	it("answers DPoP for an access token bound by cnf.jkt, without being told", async () => {
		const accessToken = await generateToken({}, { keyStore, confirmation: { jkt: "abc" } });
		expect(generateTokenResponse({ accessToken }).token_type).toBe("DPoP");
	});

	it("keeps Bearer for an mTLS-bound access token (RFC 8705 §3)", async () => {
		const accessToken = await generateToken({}, { keyStore, confirmation: { "x5t#S256": "def" } });
		expect(generateTokenResponse({ accessToken }).token_type).toBe("Bearer");
	});

	it("answers for the access token, not the refresh token beside it", async () => {
		const accessToken = await generateToken({}, { keyStore });
		const refreshToken = await generateToken({}, { keyStore, confirmation: { jkt: "abc" } });
		expect(generateTokenResponse({ accessToken, refreshToken }).token_type).toBe("Bearer");
	});
});

describe("generateTokenResponse token_type beside the other tokens", () => {
	it("returns Bearer for an unbound access token", async () => {
		const keyStore = createSymmetricKeyStore("x".repeat(32));
		const accessToken = await generateToken({}, { keyStore });
		const response = generateTokenResponse({ accessToken });
		expect(response.token_type).toBe("Bearer");
	});

	it("DPoP coexists with a refresh token in the response", async () => {
		const keyStore = createSymmetricKeyStore("x".repeat(32));
		const accessToken = await generateToken({}, { keyStore, confirmation: { jkt: "abc" } });
		const refreshToken = await generateToken({}, { keyStore });
		const response = generateTokenResponse({ accessToken, refreshToken });
		expect(response.token_type).toBe("DPoP");
		expect(response.refresh_token).toBe(refreshToken.token);
	});
});

describe("generateToken cnf coexists with other claims", () => {
	it("emits cnf alongside sub, scope, exp without interference", async () => {
		const keyStore = createSymmetricKeyStore("x".repeat(32));
		const token = await generateToken(
			{},
			{
				keyStore,
				subject: "u1",
				scope: "read",
				expiresIn: 600,
				confirmation: { jkt: "abc123" },
			},
		);
		const payload = decodeJwt(token.token);
		expect(payload.sub).toBe("u1");
		expect(payload.scope).toBe("read");
		expect(payload.exp).toBeDefined();
		expect(payload.cnf).toEqual({ jkt: "abc123" });
	});
});

describe("generateToken — a reserved identity (#449)", () => {
	const keyStore = createSymmetricKeyStore("a-test-secret-at-least-32-chars!!");
	const claimsOf = (token: string): Record<string, unknown> =>
		JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf-8")) as Record<
			string,
			unknown
		>;

	it("signs the jti and the issuing instant the caller reserved", async () => {
		// The refresh grant commits a rotation to the family store before it
		// signs anything, so the identity it reserved must be the identity the
		// token carries — the same jti, and an exp measured from the same
		// instant the reservation's expiry was.
		const issuedAt = 1_700_000_000;
		const { token } = await generateToken(
			{},
			{ keyStore, expiresIn: 3600, jti: "reserved-jti", issuedAt },
		);
		const claims = claimsOf(token);
		expect(claims.jti).toBe("reserved-jti");
		expect(claims.iat).toBe(issuedAt);
		expect(claims.exp).toBe(issuedAt + 3600);
	});

	it("still mints a fresh jti and reads the clock when neither is given", async () => {
		const before = Math.floor(Date.now() / 1000);
		const a = claimsOf((await generateToken({}, { keyStore, expiresIn: 60 })).token);
		const b = claimsOf((await generateToken({}, { keyStore, expiresIn: 60 })).token);
		expect(a.jti).not.toBe(b.jti);
		expect(a.jti as string).toMatch(
			/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
		);
		expect(a.iat as number).toBeGreaterThanOrEqual(before);
	});
});
