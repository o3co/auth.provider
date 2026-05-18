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
	it("parses a well-formed DPoP proof and returns DPoPProof", () => {
		const proof = parseProof(validProof);
		expect(proof.header.typ).toBe("dpop+jwt");
		expect(proof.header.alg).toBe("ES256");
		expect(proof.header.jwk).toMatchObject({ kty: "EC", crv: "P-256" });
		expect(proof.claims.htm).toBe("POST");
		expect(proof.claims.htu).toBe("https://as.example/token");
		expect(typeof proof.claims.iat).toBe("number");
		expect(typeof proof.claims.jti).toBe("string");
		expect(proof.raw).toBe(validProof);
	});

	// Step 3: JWT shape (3 parts)
	it("throws malformed_proof for non-string input", () => {
		expect(() => parseProof(123 as unknown as string)).toThrow(DPoPError);
		try {
			parseProof(123 as unknown as string);
		} catch (e) {
			expect(e).toBeInstanceOf(DPoPError);
			expect((e as DPoPError).reason).toBe("malformed_proof");
		}
	});

	it("throws malformed_proof for a non-JWT string (too few parts)", () => {
		expect(() => parseProof("not.ajwt")).toThrow(DPoPError);
		try {
			parseProof("not.ajwt");
		} catch (e) {
			expect((e as DPoPError).reason).toBe("malformed_proof");
		}
	});

	it("throws malformed_proof for a non-JWT string (too many parts)", () => {
		expect(() => parseProof("a.b.c.d")).toThrow(DPoPError);
		try {
			parseProof("a.b.c.d");
		} catch (e) {
			expect((e as DPoPError).reason).toBe("malformed_proof");
		}
	});

	it("throws malformed_proof for unparseable header", () => {
		expect(() => parseProof("!!!.aaa.bbb")).toThrow(DPoPError);
		try {
			parseProof("!!!.aaa.bbb");
		} catch (e) {
			expect((e as DPoPError).reason).toBe("malformed_proof");
		}
	});

	// Step 4: typ must be dpop+jwt
	it("throws typ_mismatch when typ is not dpop+jwt", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256");
		const jwk = await exportJWK(publicKey);
		const jwt = await new SignJWT({ htm: "POST", htu: "https://as/token", iat: 1, jti: "x" })
			.setProtectedHeader({ typ: "JWT", alg: "ES256", jwk })
			.sign(privateKey);
		expect(() => parseProof(jwt)).toThrow(DPoPError);
		try {
			parseProof(jwt);
		} catch (e) {
			expect((e as DPoPError).reason).toBe("typ_mismatch");
		}
	});

	it("throws typ_mismatch when typ is missing", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256");
		const jwk = await exportJWK(publicKey);
		const jwt = await new SignJWT({ htm: "POST", htu: "https://as/token", iat: 1, jti: "x" })
			.setProtectedHeader({ alg: "ES256", jwk } as Parameters<SignJWT["setProtectedHeader"]>[0])
			.sign(privateKey);
		expect(() => parseProof(jwt)).toThrow(DPoPError);
		try {
			parseProof(jwt);
		} catch (e) {
			expect((e as DPoPError).reason).toBe("typ_mismatch");
		}
	});

	// Step 6: jwk must be present
	it("throws missing_jwk when jwk is absent from header", async () => {
		const { privateKey } = await generateKeyPair("ES256");
		const jwt = await new SignJWT({ htm: "POST", htu: "https://as/token", iat: 1, jti: "x" })
			.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256" })
			.sign(privateKey);
		expect(() => parseProof(jwt)).toThrow(DPoPError);
		try {
			parseProof(jwt);
		} catch (e) {
			expect((e as DPoPError).reason).toBe("missing_jwk");
		}
	});

	// Step 7: JWK must not carry private material
	it("throws private_jwk when JWK contains 'd' field", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
		const fullJwk = await exportJWK(privateKey); // contains 'd'
		// Build a valid proof, then surgically inject the private JWK into the header.
		const pubJwk = await exportJWK(publicKey);
		const legitProof = await new SignJWT({ htm: "POST", htu: "https://as/token", iat: 1, jti: "y" })
			.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk: pubJwk })
			.sign(privateKey);
		// Manually reconstruct with private jwk in header
		const [_hdr, payload, sig] = legitProof.split(".");
		const headerObj = { typ: "dpop+jwt", alg: "ES256", jwk: fullJwk };
		const fakeHeader = Buffer.from(JSON.stringify(headerObj)).toString("base64url");
		const crafted = `${fakeHeader}.${payload}.${sig}`;
		expect(() => parseProof(crafted)).toThrow(DPoPError);
		try {
			parseProof(crafted);
		} catch (e) {
			expect((e as DPoPError).reason).toBe("private_jwk");
		}
	});

	// Step 9: required claims
	it("throws missing_claim when htm is absent", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256");
		const jwk = await exportJWK(publicKey);
		const jwt = await new SignJWT({ htu: "https://as/token", iat: 1, jti: "x" })
			.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
			.sign(privateKey);
		expect(() => parseProof(jwt)).toThrow(DPoPError);
		try {
			parseProof(jwt);
		} catch (e) {
			expect((e as DPoPError).reason).toBe("missing_claim");
		}
	});

	it("throws missing_claim when htu is absent", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256");
		const jwk = await exportJWK(publicKey);
		const jwt = await new SignJWT({ htm: "POST", iat: 1, jti: "x" })
			.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
			.sign(privateKey);
		expect(() => parseProof(jwt)).toThrow(DPoPError);
		try {
			parseProof(jwt);
		} catch (e) {
			expect((e as DPoPError).reason).toBe("missing_claim");
		}
	});

	it("throws missing_claim when iat is absent", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256");
		const jwk = await exportJWK(publicKey);
		// SignJWT adds iat by default; avoid using setIssuedAt
		const jwt = await new SignJWT({ htm: "POST", htu: "https://as/token", jti: "x" })
			.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
			.sign(privateKey);
		// Manually strip iat by reconstructing
		const [hdr, payloadB64, sig] = jwt.split(".");
		const payloadObj = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
		delete payloadObj.iat;
		const newPayload = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
		const crafted = `${hdr}.${newPayload}.${sig}`;
		expect(() => parseProof(crafted)).toThrow(DPoPError);
		try {
			parseProof(crafted);
		} catch (e) {
			expect((e as DPoPError).reason).toBe("missing_claim");
		}
	});

	it("throws missing_claim when jti is absent", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256");
		const jwk = await exportJWK(publicKey);
		const jwt = await new SignJWT({ htm: "POST", htu: "https://as/token", iat: 1 })
			.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
			.sign(privateKey);
		expect(() => parseProof(jwt)).toThrow(DPoPError);
		try {
			parseProof(jwt);
		} catch (e) {
			expect((e as DPoPError).reason).toBe("missing_claim");
		}
	});

	it("throws missing_claim when iat is not a number", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256");
		const jwk = await exportJWK(publicKey);
		const jwt = await new SignJWT({ htm: "POST", htu: "https://as/token", jti: "x" })
			.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
			.sign(privateKey);
		// Inject string iat
		const [hdr, payloadB64, sig] = jwt.split(".");
		const payloadObj = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
		payloadObj.iat = "not-a-number";
		const newPayload = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
		const crafted = `${hdr}.${newPayload}.${sig}`;
		expect(() => parseProof(crafted)).toThrow(DPoPError);
		try {
			parseProof(crafted);
		} catch (e) {
			expect((e as DPoPError).reason).toBe("missing_claim");
		}
	});

	it("code is always invalid_dpop_proof for all thrown DPoPErrors", () => {
		try {
			parseProof("a.b.c.d");
		} catch (e) {
			expect((e as DPoPError).code).toBe("invalid_dpop_proof");
		}
	});
});
