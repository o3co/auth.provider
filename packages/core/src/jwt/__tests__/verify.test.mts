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
import { exportPKCS8, exportSPKI, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { type JwtVerifyOptions, verifyJwt } from "#/jwt/verify.mjs";
import {
	createAsymmetricKeyStore,
	createSymmetricKeyStore,
	type KeyStore,
} from "#/keys/KeyStore.mjs";
import type { Logger } from "#/logging/Logger.mjs";

const TEST_SECRET = "test-secret-32-bytes-long-string12";
const TEST_KID = "v0";
const TEST_ISSUER = "https://example.com";
const TEST_AUDIENCE = "client1";

function makeMockLogger(): Logger {
	return {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: vi.fn(() => makeMockLogger()),
	};
}

function makeKeyStore(): KeyStore {
	return createSymmetricKeyStore(TEST_SECRET, TEST_KID);
}

async function signValidAccessToken(
	overrides: Partial<{
		iss: string;
		aud: string | string[];
		sub: string;
		typ: string | undefined;
		iat: number;
		exp: number;
		azp: string;
		nonce: string;
	}> = {},
	keyStore: KeyStore = makeKeyStore(),
): Promise<string> {
	const claims: Record<string, unknown> = {
		iss: overrides.iss ?? TEST_ISSUER,
		aud: overrides.aud ?? TEST_AUDIENCE,
		sub: overrides.sub ?? "user-1",
	};
	if (overrides.azp !== undefined) claims.azp = overrides.azp;
	if (overrides.nonce !== undefined) claims.nonce = overrides.nonce;
	const explicitTyp = "typ" in overrides ? overrides.typ : "at+jwt";
	const headerTyp = explicitTyp;
	// Use keyStore.sign so the header has correct alg + kid; we then need to
	// inject explicit iat/exp/typ overrides via jose's SignJWT directly when
	// the helper is asked for non-default values, since keyStore.sign always
	// sets iat to now and doesn't honor numeric overrides.
	if (overrides.iat !== undefined || overrides.exp !== undefined) {
		const secretKey = createSecretKey(Buffer.from(TEST_SECRET));
		const signer = new SignJWT(claims).setProtectedHeader({
			alg: "HS256",
			kid: TEST_KID,
			...(headerTyp !== undefined ? { typ: headerTyp } : {}),
		});
		if (overrides.iat !== undefined) signer.setIssuedAt(overrides.iat);
		if (overrides.exp !== undefined) signer.setExpirationTime(overrides.exp);
		return signer.sign(secretKey);
	}
	return await keyStore.sign({
		claims: { ...claims, exp: Math.floor(Date.now() / 1000) + 300 },
		header: headerTyp !== undefined ? { typ: headerTyp } : undefined,
	});
}

const baseOptions: JwtVerifyOptions = {
	type: "access_token",
	expectedIssuer: TEST_ISSUER,
	expectedAudience: TEST_AUDIENCE,
};

describe("verifyJwt", () => {
	it("Test 1 — rejects alg=none JWT with reason=alg", async () => {
		const keyStore = makeKeyStore();
		const headerB64 = Buffer.from(
			JSON.stringify({ alg: "none", typ: "at+jwt", kid: TEST_KID }),
		).toString("base64url");
		const payloadB64 = Buffer.from(
			JSON.stringify({
				iss: TEST_ISSUER,
				aud: TEST_AUDIENCE,
				sub: "user-1",
				exp: Math.floor(Date.now() / 1000) + 300,
				iat: Math.floor(Date.now() / 1000),
			}),
		).toString("base64url");
		const noneAlgJwt = `${headerB64}.${payloadB64}.`;
		await expect(verifyJwt(noneAlgJwt, keyStore, baseOptions)).rejects.toMatchObject({
			name: "JwtVerificationError",
			reason: "alg",
		});
	});

	it("Test 2 — rejects JWT signed with unexpected alg with reason=alg", async () => {
		// Asymmetric keystore expects RS256; sign with HS256 token to test
		// algorithm-confusion rejection.
		const { privateKey, publicKey } = await generateKeyPair("RS256", {
			extractable: true,
		});
		const rsKeyStore = await createAsymmetricKeyStore({
			algorithm: "RS256",
			kid: TEST_KID,
			privateKeyPem: await exportPKCS8(privateKey),
			publicKeyPem: await exportSPKI(publicKey),
		});
		const hsToken = await signValidAccessToken({}, makeKeyStore());
		await expect(verifyJwt(hsToken, rsKeyStore, baseOptions)).rejects.toMatchObject({
			name: "JwtVerificationError",
			reason: "alg",
		});
	});

	it("Test 3 — rejects JWT with wrong iss with reason=iss", async () => {
		const keyStore = makeKeyStore();
		const jwt = await signValidAccessToken({ iss: "https://wrong-issuer.example.com" }, keyStore);
		await expect(verifyJwt(jwt, keyStore, baseOptions)).rejects.toMatchObject({
			name: "JwtVerificationError",
			reason: "iss",
		});
	});

	it("Test 4 — rejects JWT with aud not containing expected with reason=aud", async () => {
		const keyStore = makeKeyStore();
		const jwt = await signValidAccessToken({ aud: "other-client" }, keyStore);
		await expect(verifyJwt(jwt, keyStore, baseOptions)).rejects.toMatchObject({
			name: "JwtVerificationError",
			reason: "aud",
		});
	});

	it("Test 5 — rejects JWT with wrong typ when legacyTypAccept=false with reason=typ", async () => {
		const keyStore = makeKeyStore();
		// Token typ=rt+jwt verified as access_token (expected at+jwt) — strict mode
		const jwt = await signValidAccessToken({ typ: "rt+jwt" }, keyStore);
		await expect(
			verifyJwt(jwt, keyStore, { ...baseOptions, legacyTypAccept: false }),
		).rejects.toMatchObject({
			name: "JwtVerificationError",
			reason: "typ",
		});
	});

	it("Test 6 — accepts JWT with undefined typ when legacyTypAccept=true and emits jwt_verify_legacy_typ warning", async () => {
		const keyStore = makeKeyStore();
		const logger = makeMockLogger();
		const jwt = await signValidAccessToken({ typ: undefined }, keyStore);
		const result = await verifyJwt(jwt, keyStore, {
			...baseOptions,
			legacyTypAccept: true,
			logger,
		});
		expect(result.type).toBe("access_token");
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ reason: "typ" }),
			"jwt_verify_legacy_typ",
		);
	});

	it("Test 7 — rejects JWT with undefined typ when legacyTypAccept=false with reason=typ", async () => {
		const keyStore = makeKeyStore();
		const jwt = await signValidAccessToken({ typ: undefined }, keyStore);
		await expect(
			verifyJwt(jwt, keyStore, { ...baseOptions, legacyTypAccept: false }),
		).rejects.toMatchObject({
			name: "JwtVerificationError",
			reason: "typ",
		});
	});

	it("Test 8 — rejects JWT with valid signature but unknown kid with reason=kid_unknown", async () => {
		const keyStore = makeKeyStore();
		// Sign with the same secret but advertise an unknown kid in the header
		const secretKey = createSecretKey(Buffer.from(TEST_SECRET));
		const jwt = await new SignJWT({
			iss: TEST_ISSUER,
			aud: TEST_AUDIENCE,
			sub: "user-1",
		})
			.setProtectedHeader({ alg: "HS256", kid: "unknown-kid", typ: "at+jwt" })
			.setIssuedAt()
			.setExpirationTime("5m")
			.sign(secretKey);
		await expect(verifyJwt(jwt, keyStore, baseOptions)).rejects.toMatchObject({
			name: "JwtVerificationError",
			reason: "kid_unknown",
		});
	});

	it("Test 8b — distinguishes expired kid from unknown kid (reason=kid_expired)", async () => {
		// Multi-agent review (Claude Important): expired and unknown kids
		// represent different operator-vs-attacker signals. The verifier must
		// surface them as separate reasons so SIEM rules can page differently.
		const SECRET = "test-secret-32-bytes-long-string12";
		const expiredKid = "v0";
		const expiredAt = new Date(Date.now() - 1000); // expired 1s ago
		// Build a keystore where v0 is "current" but a previousSecret with the
		// same secret rotates in as `vRot` already-expired. We then sign with
		// `vRot` so verification fails with kid_expired.
		const rotatingKeyStore = createSymmetricKeyStore(SECRET, "vCurrent", [
			{ kid: expiredKid, secret: SECRET, expiresAt: expiredAt },
		]);
		const secretKey = createSecretKey(Buffer.from(SECRET));
		const jwt = await new SignJWT({
			iss: TEST_ISSUER,
			aud: TEST_AUDIENCE,
			sub: "user-1",
		})
			.setProtectedHeader({ alg: "HS256", kid: expiredKid, typ: "at+jwt" })
			.setIssuedAt()
			.setExpirationTime("5m")
			.sign(secretKey);
		await expect(verifyJwt(jwt, rotatingKeyStore, baseOptions)).rejects.toMatchObject({
			name: "JwtVerificationError",
			reason: "kid_expired",
		});
	});

	it("Test 9 — rejects JWT with iat in future beyond clock skew with reason=not_yet_valid", async () => {
		const keyStore = makeKeyStore();
		const futureIat = Math.floor(Date.now() / 1000) + 400; // > 300s skew
		const futureExp = futureIat + 300;
		const jwt = await signValidAccessToken({ iat: futureIat, exp: futureExp }, keyStore);
		await expect(verifyJwt(jwt, keyStore, baseOptions)).rejects.toMatchObject({
			name: "JwtVerificationError",
			reason: "not_yet_valid",
		});
	});

	it("Test 10 — rejects expired JWT with reason=expired", async () => {
		const keyStore = makeKeyStore();
		const pastIat = Math.floor(Date.now() / 1000) - 700;
		const pastExp = Math.floor(Date.now() / 1000) - 400;
		const jwt = await signValidAccessToken({ iat: pastIat, exp: pastExp }, keyStore);
		await expect(verifyJwt(jwt, keyStore, baseOptions)).rejects.toMatchObject({
			name: "JwtVerificationError",
			reason: "expired",
		});
	});

	it("Test 11 — returns VerifiedJwt with payload, header, and type for valid JWT", async () => {
		const keyStore = makeKeyStore();
		const jwt = await signValidAccessToken({}, keyStore);
		const result = await verifyJwt(jwt, keyStore, baseOptions);
		expect(result.type).toBe("access_token");
		expect(result.payload.iss).toBe(TEST_ISSUER);
		expect(result.payload.aud).toBe(TEST_AUDIENCE);
		expect(result.payload.sub).toBe("user-1");
		expect(result.header.alg).toBe("HS256");
		expect(result.header.typ).toBe("at+jwt");
		expect(result.header.kid).toBe(TEST_KID);
	});

	it("Test 12b — when expectedIssuer is empty, accepts token regardless of iss and emits jwt_verify_iss_skipped warning", async () => {
		// Test fixtures + partial-config dev roots produce tokens without a
		// matching iss claim. Empty-string expectedIssuer is the explicit
		// opt-out. The verifier MUST log this and proceed.
		const keyStore = makeKeyStore();
		const logger = makeMockLogger();
		const jwt = await signValidAccessToken({ iss: "anything-goes" }, keyStore);
		const result = await verifyJwt(jwt, keyStore, {
			type: "access_token",
			expectedIssuer: "",
			expectedAudience: TEST_AUDIENCE,
			logger,
		});
		expect(result.type).toBe("access_token");
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ reason: "iss" }),
			"jwt_verify_iss_skipped",
		);
	});

	it("Test 12a — when expectedAudience is undefined, accepts token regardless of aud and emits jwt_verify_aud_skipped warning", async () => {
		// Bearer-as-credential routes (introspect Bearer / userinfo /
		// id_token_hint logout) cannot determine the calling client identity
		// before verification, so they explicitly omit `expectedAudience`.
		// The verifier MUST log this gap (audit-visible) and proceed.
		const keyStore = makeKeyStore();
		const logger = makeMockLogger();
		const jwt = await signValidAccessToken({ aud: "any-other-audience" }, keyStore);
		const { type } = await verifyJwt(jwt, keyStore, {
			type: "access_token",
			expectedIssuer: TEST_ISSUER,
			logger,
		});
		expect(type).toBe("access_token");
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ reason: "aud" }),
			"jwt_verify_aud_skipped",
		);
	});

	it("Test 12 — rejects azp mismatch with reason=azp", async () => {
		const keyStore = makeKeyStore();
		// Refresh-token verification path: typ=rt+jwt + azp claim binds RT to client
		const jwt = await signValidAccessToken({ typ: "rt+jwt", azp: "other-client" }, keyStore);
		await expect(
			verifyJwt(jwt, keyStore, {
				type: "refresh_token",
				expectedIssuer: TEST_ISSUER,
				expectedAudience: TEST_AUDIENCE,
				expectedAzp: TEST_AUDIENCE,
			}),
		).rejects.toMatchObject({
			name: "JwtVerificationError",
			reason: "azp",
		});
	});
});
