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
const token = "access-token";

/** Where a proof is checked: the token endpoint at issuance, or a resource the token is presented at. */
interface Place {
	readonly scene: Scene;
	readonly method: string;
	readonly path: string;
	readonly ath?: string;
}
const endpoint: Place = { scene: { kind: "issue" }, method: "POST", path: "/oauth/token" };
const resource: Place = {
	scene: { kind: "resource", token },
	method: "GET",
	path: "/userinfo",
	ath: createHash("sha256").update(token).digest("base64url"),
};

/** The claims of a proof that passes at the place. */
const claimsAt = (at: Place) => ({
	htm: at.method,
	htu: `https://as.example${at.path}`,
	iat,
	jti: "j1",
	...(at.ath === undefined ? {} : { ath: at.ath }),
});

const request = (proof: string | undefined, at: Place): HttpRequest =>
	testRequest({
		method: at.method,
		path: at.path,
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
	at: Place = endpoint,
) {
	return new SignJWT({ ...claimsAt(at), ...over })
		.setProtectedHeader({ alg: "EdDSA", typ: "dpop+jwt", jwk, ...header })
		.sign(key);
}

const check = (
	p: string | undefined,
	over: Partial<ProofRules> = {},
	at: Place = endpoint,
	time = now,
) => readProof(request(p, at), at.scene, { ...rules, ...over }, time);

/** Each named proof, made for the place, is refused there for the one reason given, at the token endpoint and at a resource alike. */
async function expectRefused(
	cases: (at: Place) => Promise<Record<string, string>>,
	description: string,
	over: Partial<ProofRules> = {},
) {
	for (const at of [endpoint, resource]) {
		for (const [name, p] of Object.entries(await cases(at))) {
			expect(await check(p, over, at), `${name} at ${at.path}`).toEqual({
				kind: "refused",
				error: "invalid_dpop_proof",
				description,
			});
		}
	}
}

describe("DPoP proof", () => {
	it("binds to the RFC 7638 thumbprint of the public key and hands back the jti, at the token endpoint and at a resource", async () => {
		const thumbprint = createHash("sha256")
			.update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }))
			.digest("base64url");
		for (const at of [endpoint, resource]) {
			expect(await check(await proof({}, {}, pair.privateKey, at), {}, at), at.path).toEqual({
				kind: "proved",
				jkt: thumbprint,
				jti: "j1",
			});
		}
	});

	it("answers absent without a DPoP header", async () => {
		expect(await check(undefined)).toEqual({ kind: "absent" });
	});

	describe("header", () => {
		it("takes one DPoP header only [rfc9449-4.3-a] [rfc9449-4.3-m]", async () => {
			await expectRefused(async (at) => {
				const once = await proof({}, {}, pair.privateKey, at);
				return { twice: `${once}, ${once}` };
			}, "one DPoP header only");
		});

		it("refuses what is no JWT, or a JWT not written in its one form [rfc9449-4.3-b] [rfc9449-4.3-n]", async () => {
			await expectRefused(
				async (at) => ({
					text: "not-a-jwt",
					"another form": spareBitFlipped(await proof({}, {}, pair.privateKey, at)),
				}),
				"not a JWT",
			);
		});

		it("needs typ dpop+jwt [rfc9449-4.3-c] [rfc9449-4.3-o]", async () => {
			await expectRefused(
				async (at) => ({ jwt: await proof({}, { typ: "JWT" }, pair.privateKey, at) }),
				"typ must be dpop+jwt",
			);
		});

		it("needs typ, alg and jwk in the header [rfc9449-4.2-a] [rfc9449-4.2-h]", async () => {
			await expectRefused(
				async (at) => ({ "no typ": await proof({}, { typ: undefined }, pair.privateKey, at) }),
				"typ must be dpop+jwt",
			);
			await expectRefused(
				async (at) => ({
					"no alg": signedByHand({ typ: "dpop+jwt", jwk }, claimsAt(at), (input) =>
						sign(null, input, pair.privateKey),
					),
				}),
				"alg not allowed",
			);
			await expectRefused(
				async (at) => ({ "no jwk": await proof({}, { jwk: undefined }, pair.privateKey, at) }),
				"jwk must be a public key",
			);
		});

		it("takes only the algorithms the rules allow, never none [rfc9449-4.3-d] [rfc9449-4.3-p] [rfc9449-4.2-b] [rfc9449-4.2-i]", async () => {
			await expectRefused(
				async (at) => ({
					none: `${segment({ alg: "none", typ: "dpop+jwt", jwk })}.${segment(claimsAt(at))}.`,
					"one not listed": await proof({}, {}, pair.privateKey, at),
				}),
				"alg not allowed",
				{ algorithms: ["ES256"] },
			);
		});

		it("needs a public key of a known type, even where the rules allow a shared secret [rfc9449-4.2-c] [rfc9449-4.2-j] [rfc9449-4.2-b] [rfc9449-4.2-i]", async () => {
			const secret = new Uint8Array(32).fill(7);
			const oct = { kty: "oct", k: Buffer.from(secret).toString("base64url") };
			await expectRefused(
				async (at) => {
					const made = (header: Record<string, unknown>) => proof({}, header, pair.privateKey, at);
					return {
						missing: await made({ jwk: undefined }),
						null: await made({ jwk: null }),
						"inherited name constructor": await made({ jwk: { kty: "constructor" } }),
						"inherited name __proto__": await made({ jwk: { kty: "__proto__" } }),
						"inherited name toString": await made({ jwk: { kty: "toString" } }),
						private: await made({ jwk: await exportJWK(pair.privateKey) }),
						"other primes": await made({ jwk: { ...jwk, oth: [] } }),
						"a member not in its one form": await made({
							jwk: { ...jwk, x: spareBitFlipped(jwk.x as string) },
						}),
						"a member not text": await made({ jwk: { ...jwk, x: 1 } }),
						"oct under EdDSA": await made({ jwk: { kty: "oct", k: "c2VjcmV0" } }),
						"oct under HS256": await new SignJWT(claimsAt(at))
							.setProtectedHeader({ alg: "HS256", typ: "dpop+jwt", jwk: oct as never })
							.sign(secret),
					};
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

	it("refuses a signature by another key, a weak key, or a key of another curve [rfc9449-4.3-e] [rfc9449-4.3-q]", async () => {
		const weak = generateKeyPairSync("rsa", { modulusLength: 1024 });
		const p384 = generateKeyPairSync("ec", { namedCurve: "P-384" });
		await expectRefused(
			async (at) => ({
				"another key": await proof({}, {}, generateKeyPairSync("ed25519").privateKey, at),
				// Signed by hand, since the library will not sign with a short RSA key.
				"RSA under 2048 bits": signedByHand(
					{ alg: "RS256", typ: "dpop+jwt", jwk: await exportJWK(weak.publicKey) },
					claimsAt(at),
					(input) => sign("sha256", input, weak.privateKey),
				),
				"P-384 under ES256": signedByHand(
					{ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(p384.publicKey) },
					claimsAt(at),
					(input) => sign("sha384", input, { key: p384.privateKey, dsaEncoding: "ieee-p1363" }),
				),
			}),
			"signature does not verify",
			{ algorithms: [...rules.algorithms, "RS256"] },
		);
	});

	describe("claims", () => {
		it("needs a JSON payload", async () => {
			const noJson = signedByHand({ alg: "EdDSA", typ: "dpop+jwt", jwk }, "{not json", (input) =>
				sign(null, input, pair.privateKey),
			);
			await expectRefused(async () => ({ "no JSON": noJson }), "payload is not JSON");
		});

		it("needs each claim of its type, and a jti that can be a store key [rfc9449-4.2-d] [rfc9449-4.2-k]", async () => {
			await expectRefused(async (at) => {
				const made = (over: Record<string, unknown>) => proof(over, {}, pair.privateKey, at);
				return {
					"no jti": await made({ jti: undefined }),
					"no htm": await made({ htm: undefined }),
					"no htu": await made({ htu: undefined }),
					"no iat": await made({ iat: undefined }),
					"iat as text": await made({ iat: String(iat) }),
					"htu as a list": await made({ htu: [claimsAt(at).htu] }),
					"empty jti": await made({ jti: "" }),
					"jti over 256": await made({ jti: "x".repeat(257) }),
					"jti not well formed": await made({ jti: "j-\udc00" }),
				};
			}, "missing or malformed claims");
		});

		it("needs the request's method [rfc9449-4.3-f] [rfc9449-4.3-r]", async () => {
			await expectRefused(async (at) => {
				const other = at.method === "POST" ? "GET" : "POST";
				return { [other]: await proof({ htm: other }, {}, pair.privateKey, at) };
			}, "htm does not match");
		});

		it("compares htu by scheme, host, port and path, ignoring query and fragment [rfc9449-4.3-s]", async () => {
			const read = async (htu: string) => (await check(await proof({ htu }))).kind;
			expect(await read("https://as.example/oauth/token?x=1")).toBe("proved");
			expect(await read("https://as.example/oauth/token#part")).toBe("proved");
			expect(await read("https://AS.example:443/oauth/token")).toBe("proved");
			await expectRefused(async (at) => {
				const made = (htu: string) => proof({ htu }, {}, pair.privateKey, at);
				return {
					"another host": await made(`https://evil.example${at.path}`),
					"another scheme": await made(`http://as.example${at.path}`),
					"another port": await made(`https://as.example:8443${at.path}`),
					"another path": await made("https://as.example/elsewhere"),
					"no URL": await made("not a url"),
					"a user": await made(`https://u@as.example${at.path}`),
					"a password": await made(`https://:p@as.example${at.path}`),
				};
			}, "htu does not match");
		});

		it("takes iat up to the window's edge on either side, and no further [rfc9449-4.3-i] [rfc9449-4.3-u]", async () => {
			for (const place of [endpoint, resource]) {
				const p = await proof({}, {}, pair.privateKey, place);
				const at = async (time: number) => (await check(p, {}, place, time)).kind;
				expect(await at(iat * 1000 + 60_000)).toBe("proved");
				expect(await at(iat * 1000 - 60_000)).toBe("proved");
				expect(await at(iat * 1000 + 60_001)).toBe("refused");
				expect(await at(iat * 1000 - 60_001)).toBe("refused");
			}
			await expectRefused(
				async (at) => ({
					"far behind": await proof({ iat: iat - 600 }, {}, pair.privateKey, at),
					"far ahead": await proof({ iat: iat + 600 }, {}, pair.privateKey, at),
				}),
				"iat outside the window",
			);
		});

		it("needs the token's ath at a resource [rfc9449-4.2-f] [rfc9449-4.3-k]", async () => {
			expect((await check(await proof({}, {}, pair.privateKey, resource), {}, resource)).kind).toBe(
				"proved",
			);
			for (const [name, p] of Object.entries({
				missing: await proof({ ath: undefined }, {}, pair.privateKey, resource),
				"another token's": await proof({ ath: segment("other") }, {}, pair.privateKey, resource),
			})) {
				expect(await check(p, {}, resource), name).toMatchObject({
					description: "ath does not match the token",
				});
			}
		});
	});
});
