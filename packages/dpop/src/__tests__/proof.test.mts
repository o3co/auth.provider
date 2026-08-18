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
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { DPoPError } from "#/errors.mjs";
import { parseProof } from "#/proof.mjs";

// Shared test key for valid proof minting
let validProof: string;
let publicJwk: Record<string, unknown>;

beforeAll(async () => {
	const { privateKey, publicKey } = await generateKeyPair("ES256");
	publicJwk = await exportJWK(publicKey);
	validProof = await new SignJWT({
		htm: "POST",
		htu: "https://as.example/token",
		iat: Math.floor(Date.now() / 1000),
		jti: crypto.randomUUID(),
	})
		.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk: publicJwk })
		.sign(privateKey);
});

describe("parseProof — structural validation only (no signature check)", () => {
	it("parses a well-formed DPoP proof and returns DPoPProof (flat layout per spec §5.3)", async () => {
		const proof = await parseProof(validProof);
		expect(proof.alg).toBe("ES256");
		expect(proof.jwk).toMatchObject({ kty: "EC", crv: "P-256" });
		// jkt is the RFC 7638 SHA-256 thumbprint over the proof JWK — non-empty
		// base64url string, deterministic for the same key.
		expect(typeof proof.jkt).toBe("string");
		expect(proof.jkt.length).toBeGreaterThan(0);
		expect(proof.claims.htm).toBe("POST");
		expect(proof.claims.htu).toBe("https://as.example/token");
		expect(typeof proof.claims.iat).toBe("number");
		expect(typeof proof.claims.jti).toBe("string");
		expect(proof.raw).toBe(validProof);
	});

	// Step 3: JWT shape (3 parts)
	it("throws malformed_proof for non-string input", async () => {
		await expect(parseProof(123 as unknown as string)).rejects.toMatchObject({
			constructor: DPoPError,
			reason: "malformed_proof",
		});
	});

	it("throws malformed_proof for a non-JWT string (too few parts)", async () => {
		await expect(parseProof("not.ajwt")).rejects.toMatchObject({
			reason: "malformed_proof",
		});
	});

	it("throws malformed_proof for a non-JWT string (too many parts)", async () => {
		await expect(parseProof("a.b.c.d")).rejects.toMatchObject({
			reason: "malformed_proof",
		});
	});

	it("throws malformed_proof for unparseable header", async () => {
		await expect(parseProof("!!!.aaa.bbb")).rejects.toMatchObject({
			reason: "malformed_proof",
		});
	});

	// Step 4: typ must be dpop+jwt
	it("throws typ_mismatch when typ is not dpop+jwt", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256");
		const jwk = await exportJWK(publicKey);
		const jwt = await new SignJWT({ htm: "POST", htu: "https://as/token", iat: 1, jti: "x" })
			.setProtectedHeader({ typ: "JWT", alg: "ES256", jwk })
			.sign(privateKey);
		await expect(parseProof(jwt)).rejects.toMatchObject({ reason: "typ_mismatch" });
	});

	it("throws typ_mismatch when typ is missing", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256");
		const jwk = await exportJWK(publicKey);
		const jwt = await new SignJWT({ htm: "POST", htu: "https://as/token", iat: 1, jti: "x" })
			.setProtectedHeader({ alg: "ES256", jwk } as Parameters<SignJWT["setProtectedHeader"]>[0])
			.sign(privateKey);
		await expect(parseProof(jwt)).rejects.toMatchObject({ reason: "typ_mismatch" });
	});

	// Step 5: alg must be present and non-empty string
	it("throws malformed_proof when alg is missing from header", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256");
		const jwk = await exportJWK(publicKey);
		const jwt = await new SignJWT({ htm: "POST", htu: "https://as/token", iat: 1, jti: "x" })
			.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
			.sign(privateKey);
		const [hdrB64, payload, sig] = jwt.split(".");
		expect(hdrB64).toBeDefined();
		const hdrObj = JSON.parse(Buffer.from(hdrB64 as string, "base64url").toString());
		delete hdrObj.alg;
		const newHdr = Buffer.from(JSON.stringify(hdrObj)).toString("base64url");
		const crafted = `${newHdr}.${payload}.${sig}`;
		await expect(parseProof(crafted)).rejects.toMatchObject({ reason: "malformed_proof" });
	});

	// Step 6: jwk must be present
	it("throws missing_jwk when jwk is absent from header", async () => {
		const { privateKey } = await generateKeyPair("ES256");
		const jwt = await new SignJWT({ htm: "POST", htu: "https://as/token", iat: 1, jti: "x" })
			.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256" })
			.sign(privateKey);
		await expect(parseProof(jwt)).rejects.toMatchObject({ reason: "missing_jwk" });
	});

	// Step 7: JWK must not carry private material — parameterized for the 7 fields
	// the parser checks (d, p, q, dp, dq, qi, k).
	it.each(["d", "p", "q", "dp", "dq", "qi", "k"])(
		"throws private_jwk when JWK contains '%s' field",
		async (field) => {
			const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
			const pubJwk = await exportJWK(publicKey);
			const legitProof = await new SignJWT({
				htm: "POST",
				htu: "https://as/token",
				iat: 1,
				jti: "y",
			})
				.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk: pubJwk })
				.sign(privateKey);
			const [_hdr, payload, sig] = legitProof.split(".");
			// Surgically inject the private-key field into an otherwise-public JWK
			// so each iteration exercises exactly one private field.
			const headerObj = {
				typ: "dpop+jwt",
				alg: "ES256",
				jwk: { ...pubJwk, [field]: "REDACTED" },
			};
			const fakeHeader = Buffer.from(JSON.stringify(headerObj)).toString("base64url");
			const crafted = `${fakeHeader}.${payload}.${sig}`;
			await expect(parseProof(crafted)).rejects.toMatchObject({
				reason: "private_jwk",
				message: expect.stringContaining(field),
			});
		},
	);

	// Step 8: invalid JWK shape (passes private-field name screen, fails
	// jose's structural validation in `calculateJwkThumbprint`). Without
	// the try/catch wrapper in `parseProof`, jose's raw `JWKInvalid` would
	// leak out and break the documented `DPoPError` contract.
	it("throws malformed_proof when JWK is structurally invalid (EC missing crv)", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256");
		const pubJwk = await exportJWK(publicKey);
		const legitProof = await new SignJWT({
			htm: "POST",
			htu: "https://as/token",
			iat: 1,
			jti: "z",
		})
			.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk: pubJwk })
			.sign(privateKey);
		const [_hdr, payload, sig] = legitProof.split(".");
		// Drop `crv` so the JWK is structurally invalid for an EC key but
		// still passes the public/private-field-name screen.
		const { crv: _crv, ...badJwk } = pubJwk as Record<string, unknown> & { crv?: unknown };
		const headerObj = { typ: "dpop+jwt", alg: "ES256", jwk: badJwk };
		const fakeHeader = Buffer.from(JSON.stringify(headerObj)).toString("base64url");
		const crafted = `${fakeHeader}.${payload}.${sig}`;
		await expect(parseProof(crafted)).rejects.toMatchObject({
			constructor: DPoPError,
			reason: "malformed_proof",
		});
	});

	// Step 9: required claims
	it("throws missing_claim when htm is absent", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256");
		const jwk = await exportJWK(publicKey);
		const jwt = await new SignJWT({ htu: "https://as/token", iat: 1, jti: "x" })
			.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
			.sign(privateKey);
		await expect(parseProof(jwt)).rejects.toMatchObject({ reason: "missing_claim" });
	});

	it("throws missing_claim when htu is absent", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256");
		const jwk = await exportJWK(publicKey);
		const jwt = await new SignJWT({ htm: "POST", iat: 1, jti: "x" })
			.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
			.sign(privateKey);
		await expect(parseProof(jwt)).rejects.toMatchObject({ reason: "missing_claim" });
	});

	it("throws missing_claim when iat is absent", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256");
		const jwk = await exportJWK(publicKey);
		const jwt = await new SignJWT({ htm: "POST", htu: "https://as/token", jti: "x" })
			.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
			.sign(privateKey);
		const [hdr, payloadB64, sig] = jwt.split(".");
		expect(payloadB64).toBeDefined();
		const payloadObj = JSON.parse(Buffer.from(payloadB64 as string, "base64url").toString());
		delete payloadObj.iat;
		const newPayload = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
		const crafted = `${hdr}.${newPayload}.${sig}`;
		await expect(parseProof(crafted)).rejects.toMatchObject({ reason: "missing_claim" });
	});

	it("throws missing_claim when jti is absent", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256");
		const jwk = await exportJWK(publicKey);
		const jwt = await new SignJWT({ htm: "POST", htu: "https://as/token", iat: 1 })
			.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
			.sign(privateKey);
		await expect(parseProof(jwt)).rejects.toMatchObject({ reason: "missing_claim" });
	});

	// Step 9 continued: claim type mismatch — covers each of htm/htu/iat/jti.
	// Wrong-type claims are reported as `malformed_proof` (structural error),
	// distinct from `missing_claim` (claim absent) — operator audit triage.
	it.each([
		{ field: "htm", value: 1 },
		{ field: "htu", value: 1 },
		{ field: "iat", value: "not-a-number" },
		{ field: "jti", value: 1 },
	])("throws malformed_proof when $field has wrong type", async ({ field, value }) => {
		const { privateKey, publicKey } = await generateKeyPair("ES256");
		const jwk = await exportJWK(publicKey);
		const jwt = await new SignJWT({
			htm: "POST",
			htu: "https://as/token",
			iat: 1,
			jti: "x",
		})
			.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
			.sign(privateKey);
		const [hdr, payloadB64, sig] = jwt.split(".");
		expect(payloadB64).toBeDefined();
		const payloadObj = JSON.parse(Buffer.from(payloadB64 as string, "base64url").toString());
		payloadObj[field] = value;
		const newPayload = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
		const crafted = `${hdr}.${newPayload}.${sig}`;
		await expect(parseProof(crafted)).rejects.toMatchObject({ reason: "malformed_proof" });
	});

	it("code is always invalid_dpop_proof for all thrown DPoPErrors", async () => {
		await expect(parseProof("a.b.c.d")).rejects.toMatchObject({
			code: "invalid_dpop_proof",
		});
	});
});
