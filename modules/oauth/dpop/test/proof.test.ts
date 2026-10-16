import { createHash, generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import type { HttpRequest } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import type { Scene } from "@mod/sender-binding";
import { exportJWK, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { type ProofRules, readProof } from "../src/proof.ts";

const rules = { algorithms: ["EdDSA", "ES256"], windowMs: 60_000, origin: "https://as.example" };
const now = Date.now();
const iat = Math.floor(now / 1000);
const pair = generateKeyPairSync("ed25519");
const jwk = await exportJWK(pair.publicKey);
const claims = { htm: "POST", htu: "https://as.example/oauth/token", iat, jti: "j1" };

const request = (proof: string | undefined): HttpRequest =>
	testRequest({
		method: "POST",
		path: "/oauth/token",
		headers: new Map(proof === undefined ? [] : [["dpop", proof]]),
	});

const base64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/** The text with its last character's lowest bit flipped, a bit a decoder drops when it is spare. */
const spareBitFlipped = (text: string) =>
	`${text.slice(0, -1)}${base64urlAlphabet[base64urlAlphabet.indexOf(text.at(-1) as string) ^ 1]}`;

/** A JWS segment: a string as it is, anything else as JSON. */
const segment = (value: unknown) =>
	Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url");

/** A proof signed by hand, for what the library will not sign. */
const signedByHand = (header: object, payload: unknown, signWith: (input: Buffer) => Buffer) => {
	const input = `${segment(header)}.${segment(payload)}`;
	return `${input}.${signWith(Buffer.from(input)).toString("base64url")}`;
};

async function proof(
	over: Record<string, unknown> = {},
	header: Record<string, unknown> = {},
	key: KeyObject = pair.privateKey,
) {
	return new SignJWT({ ...claims, ...over })
		.setProtectedHeader({ alg: "EdDSA", typ: "dpop+jwt", jwk, ...header })
		.sign(key);
}

const check = (
	p: string | undefined,
	over: Partial<ProofRules> = {},
	scene: Scene = { kind: "issue" },
	time = now,
) => readProof(request(p), scene, { ...rules, ...over }, time);

/** Each named proof is refused for the one reason given. */
async function expectRefused(
	cases: Record<string, string>,
	description: string,
	over: Partial<ProofRules> = {},
) {
	for (const [name, p] of Object.entries(cases)) {
		expect(await check(p, over), name).toEqual({
			kind: "refused",
			error: "invalid_dpop_proof",
			description,
		});
	}
}

describe("DPoP proof", () => {
	it("binds to the RFC 7638 thumbprint of the public key and hands back the jti", async () => {
		const thumbprint = createHash("sha256")
			.update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }))
			.digest("base64url");
		expect(await check(await proof())).toEqual({ kind: "proved", jkt: thumbprint, jti: "j1" });
	});

	it("answers absent without a DPoP header", async () => {
		expect(await check(undefined)).toEqual({ kind: "absent" });
	});

	describe("header", () => {
		it("takes one DPoP header only", async () => {
			await expectRefused({ twice: `${await proof()}, ${await proof()}` }, "one DPoP header only");
		});

		it("refuses what is no JWT, or a JWT not written in its one form", async () => {
			const variant = spareBitFlipped(await proof());
			await expectRefused({ text: "not-a-jwt", "another form": variant }, "not a JWT");
		});

		it("needs typ dpop+jwt", async () => {
			await expectRefused({ jwt: await proof({}, { typ: "JWT" }) }, "typ must be dpop+jwt");
		});

		it("takes only the algorithms the rules allow", async () => {
			await expectRefused(
				{
					none: `${segment({ alg: "none", typ: "dpop+jwt", jwk })}.${segment(claims)}.`,
					"one not listed": await proof(),
				},
				"alg not allowed",
				{ algorithms: ["ES256"] },
			);
		});

		it("needs a public key of a known type, even where the rules allow a shared secret", async () => {
			const secret = new Uint8Array(32).fill(7);
			const oct = { kty: "oct", k: Buffer.from(secret).toString("base64url") };
			await expectRefused(
				{
					missing: await proof({}, { jwk: undefined }),
					null: await proof({}, { jwk: null }),
					"inherited name constructor": await proof({}, { jwk: { kty: "constructor" } }),
					"inherited name __proto__": await proof({}, { jwk: { kty: "__proto__" } }),
					"inherited name toString": await proof({}, { jwk: { kty: "toString" } }),
					private: await proof({}, { jwk: await exportJWK(pair.privateKey) }),
					"other primes": await proof({}, { jwk: { ...jwk, oth: [] } }),
					"a member not in its one form": await proof(
						{},
						{ jwk: { ...jwk, x: spareBitFlipped(jwk.x as string) } },
					),
					"a member not text": await proof({}, { jwk: { ...jwk, x: 1 } }),
					"oct under EdDSA": await proof({}, { jwk: { kty: "oct", k: "c2VjcmV0" } }),
					"oct under HS256": await new SignJWT(claims)
						.setProtectedHeader({ alg: "HS256", typ: "dpop+jwt", jwk: oct as never })
						.sign(secret),
				},
				"jwk must be a public key",
				{ algorithms: [...rules.algorithms, "HS256"] },
			);
		});

		it("takes members that only describe the key", async () => {
			const described = await proof({}, { jwk: { ...jwk, kid: "k1", use: "sig" } });
			expect((await check(described)).kind).toBe("proved");
		});
	});

	it("refuses a signature by another key, a weak key, or a key of another curve", async () => {
		const weak = generateKeyPairSync("rsa", { modulusLength: 1024 });
		const p384 = generateKeyPairSync("ec", { namedCurve: "P-384" });
		await expectRefused(
			{
				"another key": await proof({}, {}, generateKeyPairSync("ed25519").privateKey),
				// Signed by hand, since the library will not sign with a short RSA key.
				"RSA under 2048 bits": signedByHand(
					{ alg: "RS256", typ: "dpop+jwt", jwk: await exportJWK(weak.publicKey) },
					claims,
					(input) => sign("sha256", input, weak.privateKey),
				),
				"P-384 under ES256": signedByHand(
					{ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(p384.publicKey) },
					claims,
					(input) => sign("sha384", input, { key: p384.privateKey, dsaEncoding: "ieee-p1363" }),
				),
			},
			"signature does not verify",
			{ algorithms: [...rules.algorithms, "RS256"] },
		);
	});

	describe("claims", () => {
		it("needs a JSON payload", async () => {
			const noJson = signedByHand({ alg: "EdDSA", typ: "dpop+jwt", jwk }, "{not json", (input) =>
				sign(null, input, pair.privateKey),
			);
			await expectRefused({ "no JSON": noJson }, "payload is not JSON");
		});

		it("needs each claim of its type, and a jti that can be a store key", async () => {
			await expectRefused(
				{
					"no iat": await proof({ iat: undefined }),
					"iat as text": await proof({ iat: String(iat) }),
					"htu as a list": await proof({ htu: [claims.htu] }),
					"empty jti": await proof({ jti: "" }),
					"jti over 256": await proof({ jti: "x".repeat(257) }),
					"jti not well formed": await proof({ jti: "j-\udc00" }),
				},
				"missing or malformed claims",
			);
		});

		it("needs the request's method", async () => {
			await expectRefused({ GET: await proof({ htm: "GET" }) }, "htm does not match");
		});

		it("compares htu by scheme, host, port and path, ignoring query and fragment", async () => {
			const read = async (htu: string) => (await check(await proof({ htu }))).kind;
			expect(await read("https://as.example/oauth/token?x=1")).toBe("proved");
			expect(await read("https://as.example/oauth/token#part")).toBe("proved");
			expect(await read("https://AS.example:443/oauth/token")).toBe("proved");
			await expectRefused(
				{
					"another host": await proof({ htu: "https://evil.example/oauth/token" }),
					"another scheme": await proof({ htu: "http://as.example/oauth/token" }),
					"another port": await proof({ htu: "https://as.example:8443/oauth/token" }),
					"no URL": await proof({ htu: "not a url" }),
					"a user": await proof({ htu: "https://u@as.example/oauth/token" }),
					"a password": await proof({ htu: "https://:p@as.example/oauth/token" }),
				},
				"htu does not match",
			);
		});

		it("takes iat up to the window's edge on either side, and no further", async () => {
			const p = await proof();
			const at = async (time: number) => (await check(p, {}, { kind: "issue" }, time)).kind;
			expect(await at(iat * 1000 + 60_000)).toBe("proved");
			expect(await at(iat * 1000 - 60_000)).toBe("proved");
			expect(await at(iat * 1000 + 60_001)).toBe("refused");
			expect(await at(iat * 1000 - 60_001)).toBe("refused");
			await expectRefused(
				{
					"far behind": await proof({ iat: iat - 600 }),
					"far ahead": await proof({ iat: iat + 600 }),
				},
				"iat outside the window",
			);
		});

		it("needs the token's ath at a resource", async () => {
			const token = "access-token";
			const ath = createHash("sha256").update(token).digest("base64url");
			const scene = { kind: "resource", token } as const;
			expect((await check(await proof({ ath }), {}, scene)).kind).toBe("proved");
			for (const [name, p] of Object.entries({
				missing: await proof(),
				"another token's": await proof({ ath: segment("other") }),
			})) {
				expect(await check(p, {}, scene), name).toMatchObject({
					description: "ath does not match the token",
				});
			}
		});
	});
});
