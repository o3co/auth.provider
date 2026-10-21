import { createHmac, generateKeyPairSync } from "node:crypto";
import { isUnavailable, Unavailable } from "@mod/kernel";
import { DestinationRefused, type Outbound, type OutboundResponse } from "@mod/outbound";
import { beforeEach, describe, expect, it } from "vitest";
import type { Algorithm, KeySource, Policy, Reason } from "../src/contract.ts";
import { testSigner } from "../src/testing.ts";
import { externalJwtOver } from "../src/verifier.ts";

const start = 1_800_000_000_000;
let now = start;
beforeEach(() => {
	now = start;
});
const clock = { now: () => now };
const seconds = (ms: number) => Math.floor(ms / 1000);
/** No test of written keys fetches anything. */
const unreached = {
	fetch: async () => {
		throw new Error("fetched");
	},
} as unknown as Outbound;
const invalid = (reason: Reason) => ({ kind: "invalid", reason });
const verifierOf = (keys: KeySource, rules: Policy) =>
	externalJwtOver({ clock, outbound: unreached, keySetMaxAgeMs: 86_400_000 }).verifierOf(
		keys,
		rules,
	);
const policy: Policy = { algorithms: ["ES256", "RS256", "EdDSA"], skewMs: 30_000 };
const fresh = (more: Record<string, unknown> = {}) => ({
	iss: "https://issuer.example",
	sub: "s-1",
	aud: "https://as.example",
	exp: seconds(now) + 300,
	iat: seconds(now),
	...more,
});

describe("headers and keys", () => {
	it("answers a token signed by the one key its header picks, with its header and claims", async () => {
		const signer = await testSigner("ES256", "k1");
		const verifier = verifierOf({ inline: [signer.jwk] }, policy);
		const token = await signer.sign(fresh());
		expect(await verifier.verify(token)).toEqual({
			kind: "valid",
			header: { alg: "ES256", kid: "k1" },
			claims: fresh(),
		});
	});

	it("takes only the algorithms the caller allows, never none or a shared secret", async () => {
		const signer = await testSigner("RS256");
		const strict = verifierOf({ inline: [signer.jwk] }, { ...policy, algorithms: ["ES256"] });
		expect(await strict.verify(await signer.sign(fresh()))).toEqual(invalid("algorithm"));
		const inherited = verifierOf(
			{ inline: [signer.jwk] },
			// An untyped caller can still name one outside the list; it never verifies.
			{ ...policy, algorithms: [...policy.algorithms, "toString" as Algorithm] },
		);
		expect(await inherited.verify(await signer.sign(fresh(), { alg: "toString" }))).toEqual(
			invalid("algorithm"),
		);
		// Even named by the caller, none and a shared secret never verify, whatever the token says.
		const loose = verifierOf(
			{ inline: [signer.jwk] },
			{ ...policy, algorithms: [...policy.algorithms, "HS256", "none"] as Algorithm[] },
		);
		const encoded = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
		const body = encoded(fresh());
		const hs = `${encoded({ alg: "HS256" })}.${body}`;
		const mac = createHmac("sha256", signer.pem).update(hs).digest("base64url");
		for (const token of [`${hs}.${mac}`, `${encoded({ alg: "none" })}.${body}.`]) {
			expect(await loose.verify(token), token.split(".")[0]).toEqual(invalid("algorithm"));
		}
	});

	it("refuses what is no JWS, an unencoded payload, or a critical extension", async () => {
		const signer = await testSigner("ES256");
		const verifier = verifierOf({ inline: [signer.jwk] }, policy);
		expect(await verifier.verify("nope")).toEqual(invalid("malformed"));
		for (const header of [
			{ b64: false, crit: ["b64"] },
			{ b64: false },
			{ b64: true },
			{ crit: ["x-own"], "x-own": 1 },
		]) {
			expect(
				await verifier.verify(await signer.sign(fresh(), header)),
				JSON.stringify(header),
			).toEqual(invalid("malformed"));
		}
	});

	it("refuses a token whose signature is written in a form other than its one form", async () => {
		const signer = await testSigner("ES256");
		const verifier = verifierOf({ inline: [signer.jwk] }, policy);
		const token = await signer.sign(fresh());
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
		// The last character's lowest bit is one a decoder drops: the same signature, another string.
		const variant = `${token.slice(0, -1)}${alphabet[alphabet.indexOf(token.at(-1) as string) ^ 1]}`;
		expect((await verifier.verify(token)).kind).toBe("valid");
		expect(await verifier.verify(variant)).toEqual(invalid("malformed"));
	});

	it("takes only the type the caller names, compared as RFC 7515 says", async () => {
		const signer = await testSigner("ES256");
		const verifier = verifierOf({ inline: [signer.jwk] }, { ...policy, typ: "JWT" });
		expect(await verifier.verify(await signer.sign(fresh()))).toEqual(invalid("malformed"));
		expect(await verifier.verify(await signer.sign(fresh(), { typ: "at+jwt" }))).toEqual(
			invalid("malformed"),
		);
		expect(await verifier.verify(await signer.sign(fresh(), { typ: ["JWT"] }))).toEqual(
			invalid("malformed"),
		);
		for (const typ of ["application/jwt", "jwt", "JWT"]) {
			expect((await verifier.verify(await signer.sign(fresh(), { typ }))).kind, typ).toBe("valid");
		}
	});

	it("picks a key by its kind, use, operations, algorithm and id, exactly one", async () => {
		const signer = await testSigner("ES256", "k1");
		const other = await testSigner("ES256", "k2");
		const rsa = await testSigner("RS256", "k1");
		const token = await signer.sign(fresh());
		const judged = async (keys: Record<string, unknown>[]) =>
			verifierOf({ inline: keys }, policy).verify(token);
		expect(await judged([rsa.jwk])).toEqual(invalid("no-key"));
		expect(await judged([other.jwk])).toEqual(invalid("no-key"));
		expect(await judged([{ ...signer.jwk, use: "enc" }])).toEqual(invalid("no-key"));
		expect(await judged([{ ...signer.jwk, key_ops: ["encrypt"] }])).toEqual(invalid("no-key"));
		expect(await judged([{ ...signer.jwk, key_ops: "verify" }])).toEqual(invalid("no-key"));
		expect(await judged([{ ...signer.jwk, alg: "ES384" }])).toEqual(invalid("no-key"));
		expect(
			(await judged([{ ...signer.jwk, use: "sig", key_ops: ["verify"], alg: "ES256" }])).kind,
		).toBe("valid");
		// A key written with its private part, or on another curve, never verifies.
		const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
		const exposed = { ...privateKey.export({ format: "jwk" }), kid: "k1" };
		const p384 = {
			...generateKeyPairSync("ec", { namedCurve: "P-384" }).publicKey.export({ format: "jwk" }),
			kid: "k1",
		};
		expect(await judged([exposed])).toEqual(invalid("no-key"));
		expect(await judged([p384])).toEqual(invalid("no-key"));
		const unnamed = await signer.sign(fresh(), { kid: undefined });
		const both = verifierOf({ inline: [signer.jwk, other.jwk] }, policy);
		expect(await both.verify(unnamed)).toEqual(invalid("ambiguous-key"));
	});

	it("takes a key id only as a string, in the header and in a key", async () => {
		const signer = await testSigner("ES256");
		for (const kid of [1, false, null]) {
			const verifier = verifierOf({ inline: [{ ...signer.jwk, kid }] }, policy);
			expect(await verifier.verify(await signer.sign(fresh(), { kid })), String(kid)).toEqual(
				invalid("malformed"),
			);
			expect(await verifier.verify(await signer.sign(fresh())), String(kid)).toEqual(
				invalid("no-key"),
			);
		}
	});

	it("takes a key only of the kind and curve its algorithm needs", async () => {
		const ec = await testSigner("ES256");
		const x25519 = { ...generateKeyPairSync("x25519").publicKey.export({ format: "jwk" }) };
		const all: Policy = { ...policy, algorithms: ["RS256", "ES256", "ES384", "ES512", "EdDSA"] };
		for (const [alg, jwk] of [
			["RS256", ec.jwk],
			["ES384", ec.jwk],
			["ES512", ec.jwk],
			["EdDSA", x25519],
		] as const) {
			const token = await ec.sign(fresh(), { alg });
			expect(await verifierOf({ inline: [jwk] }, all).verify(token), alg).toEqual(
				invalid("no-key"),
			);
		}
	});

	it("takes an Ed25519 key only at its length", async () => {
		const signer = await testSigner("EdDSA");
		const token = await signer.sign(fresh());
		const x = Buffer.from(signer.jwk.x as string, "base64url");
		expect((await verifierOf({ inline: [signer.jwk] }, policy).verify(token)).kind).toBe("valid");
		for (const bytes of [
			x.subarray(0, 31),
			Buffer.concat([x, Buffer.from([0])]),
			Buffer.alloc(0),
		]) {
			const jwk = { ...signer.jwk, x: bytes.toString("base64url") };
			expect(
				await verifierOf({ inline: [jwk] }, policy).verify(token),
				String(bytes.length),
			).toEqual(invalid("no-key"));
		}
	});

	it("refuses a signature that does not hold", async () => {
		const signer = await testSigner("ES256", "k1");
		const impostor = await testSigner("ES256", "k1");
		const verifier = verifierOf({ inline: [signer.jwk] }, policy);
		expect(await verifier.verify(await impostor.sign(fresh()))).toEqual(invalid("signature"));
	});

	it("takes PEM keys under the algorithm they are given for", async () => {
		const signer = await testSigner("RS256");
		const token = await signer.sign(fresh());
		const pem = (alg: Algorithm) => verifierOf({ pem: [{ alg, pem: signer.pem }] }, policy);
		expect((await pem("RS256").verify(token)).kind).toBe("valid");
		const named = await signer.sign(fresh(), { kid: "k1" });
		const withKid = (kid: string) =>
			verifierOf({ pem: [{ alg: "RS256", kid, pem: signer.pem }] }, policy).verify(named);
		expect((await withKid("k1")).kind).toBe("valid");
		expect(await withKid("k2")).toEqual(invalid("no-key"));
		expect(await pem("ES256").verify(token)).toEqual(invalid("no-key"));
	});

	it("never takes a private key written as PEM", async () => {
		const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
		const token = await (await testSigner("ES256")).sign(fresh());
		const written = (pem: string) =>
			verifierOf({ pem: [{ alg: "ES256", pem }] }, policy).verify(token);
		for (const type of ["pkcs8", "sec1"] as const) {
			const pem = privateKey.export({ format: "pem", type }).toString();
			expect(await written(pem), type).toEqual(invalid("no-key"));
		}
		expect(await written(publicKey.export({ format: "pem", type: "spki" }).toString())).toEqual(
			invalid("signature"),
		);
	});
});

describe("claims", () => {
	const signed = async (claims: Record<string, unknown>, rules: Partial<Policy> = {}) => {
		const signer = await testSigner("ES256");
		return verifierOf({ inline: [signer.jwk] }, { ...policy, ...rules }).verify(
			await signer.sign(claims),
		);
	};

	it("answers the header and claims frozen", async () => {
		const answered = await signed(fresh({ extra: { deep: [1] } }));
		if (answered.kind !== "valid") throw new Error(answered.kind);
		expect(Object.isFrozen(answered.header)).toBe(true);
		expect(Object.isFrozen((answered.claims.extra as { deep: unknown }).deep)).toBe(true);
	});

	it("needs a JSON object with an expiry", async () => {
		const { exp: _, ...lasting } = fresh();
		expect(await signed(lasting)).toEqual(invalid("malformed"));
		expect(await signed(fresh({ exp: "soon" }))).toEqual(invalid("malformed"));
		expect(await signed(fresh({ nbf: "now" }))).toEqual(invalid("malformed"));
		expect(await signed(fresh({ iat: "then" }))).toEqual(invalid("malformed"));
		for (const payload of [null, "x", [fresh()]]) {
			expect(await signed(payload as never), JSON.stringify(payload)).toEqual(invalid("malformed"));
		}
	});

	it("needs finite times", async () => {
		const signer = await testSigner("ES256");
		const verifier = verifierOf({ inline: [signer.jwk] }, policy);
		for (const claim of ["exp", "nbf", "iat"]) {
			const text = JSON.stringify(fresh()).replace("}", `,"${claim}":1e400}`);
			expect(await verifier.verify(await signer.signBytes(Buffer.from(text))), claim).toEqual(
				invalid("malformed"),
			);
		}
	});

	it("needs claims in UTF-8", async () => {
		const signer = await testSigner("ES256");
		const verifier = verifierOf({ inline: [signer.jwk] }, policy);
		const text = (sub: string) => `{"exp":${seconds(now) + 300},"sub":"${sub}"}`;
		expect((await verifier.verify(await signer.signBytes(Buffer.from(text("s-1"))))).kind).toBe(
			"valid",
		);
		const broken = Buffer.from(text("\u0000")).map((byte) => (byte === 0 ? 0xff : byte));
		expect(await verifier.verify(await signer.signBytes(broken))).toEqual(invalid("malformed"));
	});

	it("judges its times on the caller's clock, allowing the caller's skew", async () => {
		const at = seconds(now);
		expect((await signed(fresh({ exp: at - 29 }))).kind).toBe("valid");
		expect(await signed(fresh({ exp: at - 30 }))).toEqual(invalid("expired"));
		expect((await signed(fresh({ nbf: at + 30 }))).kind).toBe("valid");
		expect(await signed(fresh({ nbf: at + 31 }))).toEqual(invalid("not-yet"));
		expect((await signed(fresh({ iat: at + 30 }))).kind).toBe("valid");
		expect(await signed(fresh({ iat: at + 31 }))).toEqual(invalid("future-iat"));
	});

	it("refuses a token that lives, or was issued, longer than the caller allows", async () => {
		const at = seconds(now);
		const rules = { maxLifetimeMs: 3_600_000 };
		expect((await signed(fresh({ exp: at + 3630 }), rules)).kind).toBe("valid");
		expect(await signed(fresh({ exp: at + 3631 }), rules)).toEqual(invalid("too-long"));
		expect((await signed(fresh({ iat: at - 3630 }), rules)).kind).toBe("valid");
		expect(await signed(fresh({ iat: at - 3631 }), rules)).toEqual(invalid("too-long"));
		expect((await signed(fresh({ exp: at + 86_400 }))).kind).toBe("valid");
	});

	it("matches the issuer, any one audience and the subject the caller expects", async () => {
		const expecting = (expected: NonNullable<Policy["expect"]>) => ({ expect: expected });
		expect((await signed(fresh(), expecting({ iss: "https://issuer.example" }))).kind).toBe(
			"valid",
		);
		expect(await signed(fresh(), expecting({ iss: "https://other.example" }))).toEqual(
			invalid("issuer"),
		);
		expect((await signed(fresh(), expecting({ aud: ["https://as.example"] }))).kind).toBe("valid");
		const audiences = fresh({ aud: ["https://rs.example", "https://as.example"] });
		expect(
			(
				await signed(
					audiences,
					expecting({ aud: ["https://as.example/token", "https://as.example"] }),
				)
			).kind,
		).toBe("valid");
		expect(await signed(audiences, expecting({ aud: ["https://as.example/token"] }))).toEqual(
			invalid("audience"),
		);
		expect(
			await signed(
				fresh({ aud: [1, "https://as.example"] }),
				expecting({ aud: ["https://as.example"] }),
			),
		).toEqual(invalid("audience"));
		expect(await signed(fresh({ aud: 7 }), expecting({ aud: ["7"] }))).toEqual(invalid("audience"));
		expect((await signed(fresh(), expecting({ sub: "s-1" }))).kind).toBe("valid");
		expect(await signed(fresh(), expecting({ sub: "s-2" }))).toEqual(invalid("subject"));
		expect(await signed(fresh({ sub: 1 }), expecting({ sub: "1" }))).toEqual(invalid("subject"));
	});
});

describe("a key set at a URL", () => {
	const answer = (status: number, json: unknown): OutboundResponse => ({
		status,
		headers: new Map(),
		body: new TextEncoder().encode(JSON.stringify(json)),
	});
	function served() {
		const asked: { url: string; hosts: readonly string[] | undefined; accept?: string }[] = [];
		let next: () => Promise<OutboundResponse> = async () => answer(500, {});
		const outbound: Outbound = {
			fetch: async (url, init, narrower) => {
				const accept = init?.headers?.accept;
				asked.push({ url, hosts: narrower?.hosts, ...(accept ? { accept } : {}) });
				return next();
			},
		} as Outbound;
		return {
			outbound,
			asked,
			answer: (respond: () => Promise<OutboundResponse>) => {
				next = respond;
			},
			/** Answers a key set with these keys. */
			serve: (keys: readonly unknown[], status = 200) => {
				next = async () => answer(status, { keys });
			},
			fail: (error: unknown = new Unavailable("outbound")) => {
				next = async () => {
					throw error;
				};
			},
			/** Holds the next answer until the returned release is called. */
			hold: (keys: readonly unknown[]) => {
				let release = () => {};
				next = () =>
					new Promise((done) => {
						release = () => done(answer(200, { keys }));
					});
				return () => release();
			},
		};
	}
	const tick = () => new Promise((done) => setTimeout(done, 0));
	const fromUrl = (outbound: Outbound) =>
		externalJwtOver({ clock, outbound, keySetMaxAgeMs: 86_400_000 }).verifierOf(
			{ jwks: { url: "https://issuer.example/jwks", hosts: ["issuer.example"] } },
			policy,
		);

	it("fetches the set through outbound, narrowed to the caller's hosts, once for every waiting check", async () => {
		const signer = await testSigner("ES256", "k1");
		const s = served();
		const release = s.hold([signer.jwk]);
		const verifier = fromUrl(s.outbound);
		const token = await signer.sign(fresh());
		const waiting = [verifier.verify(token), verifier.verify(token)];
		await tick();
		release();
		expect((await Promise.all(waiting)).map((v) => v.kind)).toEqual(["valid", "valid"]);
		expect(s.asked).toEqual([
			{ url: "https://issuer.example/jwks", hosts: ["issuer.example"], accept: "application/json" },
		]);
	});

	it("fetches again for an unknown key at most once a minute, and keeps a set an hour", async () => {
		const first = await testSigner("ES256", "k1");
		const second = await testSigner("ES256", "k2");
		const s = served();
		s.serve([first.jwk]);
		const verifier = fromUrl(s.outbound);
		expect((await verifier.verify(await first.sign(fresh()))).kind).toBe("valid");
		s.serve([first.jwk, second.jwk]);
		now += 59_000;
		expect(await verifier.verify(await second.sign(fresh()))).toEqual(invalid("no-key"));
		expect(s.asked).toHaveLength(1);
		now += 1_000;
		expect((await verifier.verify(await second.sign(fresh()))).kind).toBe("valid");
		expect(s.asked).toHaveLength(2);
		now += 3_599_000;
		expect((await verifier.verify(await first.sign(fresh()))).kind).toBe("valid");
		expect(s.asked).toHaveLength(2);
		now += 1_000;
		expect((await verifier.verify(await first.sign(fresh()))).kind).toBe("valid");
		expect(s.asked).toHaveLength(3);
	});

	it("is unavailable without a set, and checks with the set it has while the next cannot be had", async () => {
		const signer = await testSigner("ES256", "k1");
		const s = served();
		s.fail();
		const verifier = fromUrl(s.outbound);
		const token = await signer.sign(fresh());
		expect(await verifier.verify(token)).toEqual({ kind: "unavailable" });
		now += 60_000;
		s.serve([signer.jwk]);
		expect((await verifier.verify(token)).kind).toBe("valid");
		now += 3_600_000;
		for (const failing of [async () => answer(503, {}), async () => answer(200, { keys: "x" })]) {
			s.answer(failing);
			expect((await verifier.verify(await signer.sign(fresh()))).kind).toBe("valid");
			now += 60_000;
		}
		expect(s.asked).toHaveLength(4);
	});

	it("is unavailable at once for an unknown key while its last fetch is under a minute old", async () => {
		const signer = await testSigner("ES256", "k1");
		const s = served();
		s.fail();
		const verifier = fromUrl(s.outbound);
		const token = await signer.sign(fresh());
		expect(await verifier.verify(token)).toEqual({ kind: "unavailable" });
		s.serve([signer.jwk]);
		now += 59_000;
		const answered = await verifier.verify(token);
		expect(answered).toEqual({ kind: "unavailable" });
		expect(isUnavailable(answered)).toBe(false);
		expect(s.asked).toHaveLength(1);
	});
	it("stops using a set it cannot renew once the set is older than the limit", async () => {
		const signer = await testSigner("ES256", "k1");
		const s = served();
		s.serve([signer.jwk]);
		const verifier = fromUrl(s.outbound);
		expect((await verifier.verify(await signer.sign(fresh()))).kind).toBe("valid");
		s.fail();
		now += 86_399_999;
		expect((await verifier.verify(await signer.sign(fresh()))).kind).toBe("valid");
		now += 1;
		expect(await verifier.verify(await signer.sign(fresh()))).toEqual({ kind: "unavailable" });
		now += 60_000;
		s.serve([signer.jwk]);
		expect((await verifier.verify(await signer.sign(fresh()))).kind).toBe("valid");
	});

	it("takes a set only from a 200 answer holding one, skipping entries that are no key", async () => {
		const signer = await testSigner("ES256", "k1");
		const s = served();
		s.serve([signer.jwk], 404);
		const verifier = fromUrl(s.outbound);
		const token = await signer.sign(fresh());
		expect(await verifier.verify(token)).toEqual({ kind: "unavailable" });
		now += 60_000;
		s.serve([null, "x", [1], signer.jwk]);
		expect((await verifier.verify(await signer.sign(fresh()))).kind).toBe("valid");
	});

	it("takes a refused destination or an answer that is no JSON as an outage, and nothing else", async () => {
		const signer = await testSigner("ES256", "k1");
		const token = await signer.sign(fresh());
		const s = served();
		s.fail(new DestinationRefused("not-allowed"));
		expect(await fromUrl(s.outbound).verify(token)).toEqual({ kind: "unavailable" });
		// A refusal a second bundled copy of outbound-policy throws: another class, the same mark.
		s.fail(
			Object.assign(new Error("outbound destination refused: not-allowed"), {
				[Symbol.for("@mod/outbound-policy.destination-refused")]: true,
				reason: "not-allowed",
			}),
		);
		expect(await fromUrl(s.outbound).verify(token)).toEqual({ kind: "unavailable" });
		s.answer(async () => ({
			status: 200,
			headers: new Map(),
			body: new TextEncoder().encode("{nope"),
		}));
		expect(await fromUrl(s.outbound).verify(token)).toEqual({ kind: "unavailable" });
		s.fail(new TypeError("a fault of the caller's"));
		await expect(fromUrl(s.outbound).verify(token)).rejects.toThrow(TypeError);
	});

	it("shares a fetch still running with a check that comes a minute later", async () => {
		const signer = await testSigner("ES256", "k1");
		const s = served();
		const release = s.hold([signer.jwk]);
		const verifier = fromUrl(s.outbound);
		const first = verifier.verify(await signer.sign(fresh()));
		await tick();
		now += 60_000;
		const second = verifier.verify(await signer.sign(fresh()));
		await tick();
		release();
		expect([(await first).kind, (await second).kind]).toEqual(["valid", "valid"]);
		expect(s.asked).toHaveLength(1);
	});
	it("fetches again only for a key the set lacks, not for one it holds twice", async () => {
		const signer = await testSigner("ES256");
		const twin = await testSigner("ES256");
		const s = served();
		s.serve([signer.jwk, twin.jwk]);
		const verifier = fromUrl(s.outbound);
		expect(await verifier.verify(await signer.sign(fresh()))).toEqual(invalid("ambiguous-key"));
		now += 60_000;
		expect(await verifier.verify(await signer.sign(fresh()))).toEqual(invalid("ambiguous-key"));
		expect(s.asked).toHaveLength(1);
	});

	it("counts a set's hour from when its fetch began", async () => {
		const signer = await testSigner("ES256", "k1");
		const s = served();
		const release = s.hold([signer.jwk]);
		const verifier = fromUrl(s.outbound);
		const first = verifier.verify(await signer.sign(fresh()));
		await tick();
		now += 30_000;
		release();
		expect((await first).kind).toBe("valid");
		s.serve([signer.jwk]);
		now += 3_569_000;
		expect((await verifier.verify(await signer.sign(fresh()))).kind).toBe("valid");
		expect(s.asked).toHaveLength(1);
		now += 1_000;
		expect((await verifier.verify(await signer.sign(fresh()))).kind).toBe("valid");
		expect(s.asked).toHaveLength(2);
	});

	it("keeps one set for a URL and its hosts, whichever verifier asks", async () => {
		const signer = await testSigner("ES256", "k1");
		const s = served();
		s.serve([signer.jwk]);
		const jwt = externalJwtOver({ clock, outbound: s.outbound, keySetMaxAgeMs: 86_400_000 });
		const source = { jwks: { url: "https://issuer.example/jwks", hosts: ["issuer.example"] } };
		const token = await signer.sign(fresh());
		expect((await jwt.verifierOf(source, policy).verify(token)).kind).toBe("valid");
		expect((await jwt.verifierOf(source, { ...policy, skewMs: 0 }).verify(token)).kind).toBe(
			"valid",
		);
		expect(s.asked).toHaveLength(1);
		const narrower = { jwks: { ...source.jwks, hosts: ["issuer.example", "other.example"] } };
		expect((await jwt.verifierOf(narrower, policy).verify(token)).kind).toBe("valid");
		expect(s.asked).toHaveLength(2);
		// The same hosts named in another order are the same set.
		const reordered = { jwks: { ...source.jwks, hosts: ["other.example", "issuer.example"] } };
		expect((await jwt.verifierOf(reordered, policy).verify(token)).kind).toBe("valid");
		expect(s.asked).toHaveLength(2);
		// So are they written in another case or with the root's trailing dot.
		const respelled = { jwks: { ...source.jwks, hosts: ["Other.Example.", "ISSUER.example"] } };
		expect((await jwt.verifierOf(respelled, policy).verify(token)).kind).toBe("valid");
		expect(s.asked).toHaveLength(2);
	});
});
