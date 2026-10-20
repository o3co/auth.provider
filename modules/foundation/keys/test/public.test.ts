import { createPublicKey, generateKeyPairSync, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	isCanonicalJws,
	isVerifyAlgorithm,
	type Jwk,
	publicJwk,
	publicMembers,
	publicPem,
	thumbprint,
	verifiesUnder,
	verifyAlgorithms,
} from "../src/contract.ts";

const jwkOf = (key: KeyObject, extra: Record<string, unknown> = {}): Jwk => ({
	...(key.export({ format: "jwk" }) as Jwk),
	...extra,
});
const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
const ed = generateKeyPairSync("ed25519");
const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });

describe("reading public keys", () => {
	it("takes a JWK the platform reads as a public key, keeping it as given", () => {
		for (const key of [ec.publicKey, ed.publicKey, rsa.publicKey]) {
			const jwk = jwkOf(key, { kid: "k", use: "sig" });
			const read = publicJwk(jwk);
			expect(read?.jwk).toBe(jwk);
			expect(read?.key.type).toBe("public");
		}
	});

	it("refuses a JWK with a private member, a kid that is no string, or that is no key", () => {
		const refused: Record<string, Jwk> = {
			"a private key": jwkOf(ec.privateKey),
			...Object.fromEntries(
				["d", "p", "q", "dp", "dq", "qi", "k", "oth"].map((member) => [
					`a member ${member}`,
					jwkOf(rsa.publicKey, { [member]: "AAAA" }),
				]),
			),
			"a numeric kid": jwkOf(ec.publicKey, { kid: 7 }),
			"a point off the curve": { kty: "EC", crv: "P-256", x: "AAAA", y: "AAAA" },
			"a shared secret": { kty: "oct", k: "AAAA" },
		};
		for (const [name, jwk] of Object.entries(refused)) expect(publicJwk(jwk), name).toBeUndefined();
	});

	it("takes a public PEM, and nothing else, a private PEM above all", () => {
		const spki = ec.publicKey.export({ format: "pem", type: "spki" }).toString();
		expect(publicPem(spki)?.type).toBe("public");
		for (const type of ["pkcs8", "sec1"] as const) {
			expect(
				publicPem(ec.privateKey.export({ format: "pem", type }).toString()),
				type,
			).toBeUndefined();
		}
		expect(publicPem("no pem")).toBeUndefined();
	});
});

describe("whether a key may verify", () => {
	it("knows the asymmetric algorithms alone", () => {
		expect([...verifyAlgorithms].sort()).toEqual(
			[
				"EdDSA",
				"ES256",
				"ES384",
				"ES512",
				"PS256",
				"PS384",
				"PS512",
				"RS256",
				"RS384",
				"RS512",
			].sort(),
		);
	});

	it("takes a key whose kind and curve fit the algorithm, and whose own alg is it", () => {
		expect(verifiesUnder(jwkOf(ec.publicKey), "ES256")).toBe(true);
		expect(verifiesUnder(jwkOf(ec.publicKey), "ES384")).toBe(false);
		expect(verifiesUnder(jwkOf(ed.publicKey), "EdDSA")).toBe(true);
		expect(verifiesUnder(jwkOf(rsa.publicKey), "PS256")).toBe(true);
		expect(verifiesUnder(jwkOf(rsa.publicKey, { alg: "RS256" }), "PS256")).toBe(false);
		for (const alg of ["HS256", "none", "toString"]) {
			expect(verifiesUnder(jwkOf(rsa.publicKey), alg), alg).toBe(false);
		}
	});

	it("takes, with no algorithm, a key of a kind any algorithm here verifies with", () => {
		for (const key of [ec.publicKey, ed.publicKey, rsa.publicKey]) {
			expect(verifiesUnder(jwkOf(key))).toBe(true);
		}
		expect(verifiesUnder(jwkOf(generateKeyPairSync("x25519").publicKey))).toBe(false);
		expect(verifiesUnder({ kty: "oct", k: "AAAA" })).toBe(false);
	});

	it("takes a key only for signatures where its use or operations are named", () => {
		const key = ec.publicKey;
		expect(verifiesUnder(jwkOf(key, { use: "sig", key_ops: ["verify"] }), "ES256")).toBe(true);
		for (const extra of [{ use: "enc" }, { key_ops: ["deriveKey"] }, { key_ops: "verify" }]) {
			expect(verifiesUnder(jwkOf(key, extra), "ES256"), JSON.stringify(extra)).toBe(false);
			expect(verifiesUnder(jwkOf(key, extra)), JSON.stringify(extra)).toBe(false);
		}
	});
});

describe("public members", () => {
	it("rebuilds a key from its type's public members, leaving out what describes it", () => {
		const jwk = jwkOf(ed.publicKey, { kid: "k", alg: "EdDSA", use: "sig", key_ops: ["verify"] });
		expect(publicMembers(jwk)).toEqual({ kty: "OKP", crv: "Ed25519", x: jwk.x });
		const { kty, n, e } = jwkOf(rsa.publicKey);
		expect(publicMembers({ kty, n, e })).toEqual({ kty, n, e });
	});

	it("refuses anything else: another member, a member that is no string, a type it does not know", () => {
		const refused: Record<string, unknown> = {
			"a private member": jwkOf(ec.privateKey),
			"another member": jwkOf(ec.publicKey, { oth: [] }),
			"a member that is no string": jwkOf(ec.publicKey, { x: 1 }),
			"an inherited name as its type": { kty: "constructor" },
			"a shared secret": { kty: "oct", k: "AAAA" },
			"no object": "x",
			null: null,
			"a list": [],
		};
		for (const [name, jwk] of Object.entries(refused)) {
			expect(publicMembers(jwk), name).toBeUndefined();
		}
	});
});

describe("a key in its one form", () => {
	it("refuses a JWK whose key member is not written in its one form", () => {
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
		const jwk = jwkOf(ed.publicKey);
		const x = jwk.x as string;
		// An Ed25519 x is 32 bytes in 43 characters, whose last holds bits a decoder drops.
		const variant = {
			...jwk,
			x: `${x.slice(0, -1)}${alphabet[alphabet.indexOf(x.at(-1) as string) ^ 1]}`,
		};
		expect(publicJwk(jwk)).toBeDefined();
		expect(publicJwk(variant)).toBeUndefined();
		expect(publicMembers(variant)).toBeUndefined();
	});
});

describe("a JWS in its one form", () => {
	it("takes three segments each written as its bytes encode, and nothing else", () => {
		expect(isCanonicalJws("eyJhIjoxfQ.e30.AAAA")).toBe(true);
		const refused = {
			"spare bits set": "eyJhIjoxfQ.e30.AAB",
			padding: "eyJhIjoxfQ.e30.AA==",
			"another alphabet": "eyJhIjoxfQ.e30.AA+/",
			"two segments": "eyJhIjoxfQ.e30",
			"four segments": "eyJhIjoxfQ.e30.AAAA.AAAA",
		};
		for (const [name, jws] of Object.entries(refused))
			expect(isCanonicalJws(jws), name).toBe(false);
	});
});

it("tells an algorithm it verifies under from any other name, an inherited one too", () => {
	for (const alg of verifyAlgorithms) expect(isVerifyAlgorithm(alg), alg).toBe(true);
	for (const other of ["HS256", "none", "toString", "constructor", 256]) {
		expect(isVerifyAlgorithm(other), String(other)).toBe(false);
	}
});

describe("thumbprint", () => {
	it("answers a public key's RFC 7638 SHA-256 thumbprint, as the RFC's example gives it", async () => {
		// RFC 7638, section 3.1: the example RSA key and its thumbprint.
		const n =
			"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
		const key = createPublicKey({ key: { kty: "RSA", n, e: "AQAB" }, format: "jwk" });
		expect(await thumbprint(key)).toBe("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
		// The same key written as PEM has the same thumbprint.
		const pem = publicPem(key.export({ type: "spki", format: "pem" }).toString());
		expect(pem && (await thumbprint(pem))).toBe("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
		// A JWK given is taken by its required members as written.
		expect(await thumbprint({ kty: "RSA", n, e: "AQAB", kid: "any" })).toBe(
			"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
		);
	});
});
