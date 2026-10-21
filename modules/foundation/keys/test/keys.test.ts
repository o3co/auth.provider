import { createPrivateKey, generateKeyPairSync, type KeyObject, randomBytes } from "node:crypto";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { assemble, BootRefused, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { CompactSign } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import { keys } from "../src/contract.ts";
import keysModule from "../src/module.ts";
import { section as keysSection } from "../src/signing/section.ts";
import { keysConfig } from "../src/testing.ts";

let now = Date.parse("2026-01-01T00:00:00Z");
const runtime = quietRuntime({
	clock: { now: () => now },
	random: { bytes: (n) => new Uint8Array(n) },
});

const ed25519Pem = () => {
	const pair = generateKeyPairSync("ed25519");
	return {
		priv: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
		pub: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
	};
};

let stop: () => Promise<void> = async () => {};
afterEach(() => stop());

async function boot(keysSection: unknown, http_: Record<string, unknown> = {}) {
	const app = await assemble({
		modules: [http, keysModule],
		config: { ...kernelConfig(), ...httpConfig(http_), keys: keysSection },
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	return { app, base: `http://127.0.0.1:${app.get(listening).port()}` };
}

async function refusedAt(keysSection: unknown): Promise<string[]> {
	try {
		await boot(keysSection);
	} catch (error) {
		if (error instanceof BootRefused) return error.refusals.map((r) => r.where);
		throw error;
	}
	throw new Error("expected a refusal");
}

/** The token with its header's kid replaced; the signature no longer matches. */
function withKid(token: string, kid: string): string {
	const [h = "", p, s] = token.split(".");
	const header = { ...JSON.parse(Buffer.from(h, "base64url").toString()), kid };
	return [Buffer.from(JSON.stringify(header)).toString("base64url"), p, s].join(".");
}

const base64url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/** The token with the signature's last character changed in a bit decoding drops: the same bytes, another string. */
function withLastBitsFlipped(token: string): string {
	const at = base64url.indexOf(token.at(-1) as string);
	return `${token.slice(0, -1)}${base64url[at ^ 1]}`;
}

/** A token signed as another holder of a key would sign it. */
const signedBy = (privatePem: string, kid: string, payload: string, typ = "JWT") =>
	new CompactSign(new TextEncoder().encode(payload))
		.setProtectedHeader({ alg: "EdDSA", typ, kid })
		.sign(createPrivateKey(privatePem));

const january = Date.parse("2026-01-01T00:00:00Z");
const july = Date.parse("2026-07-01T00:00:00Z");
afterEach(() => {
	now = january;
});

describe("keys", () => {
	const current = ed25519Pem();
	const old = ed25519Pem();
	const rotated = (previousKey = old.pub) => ({
		signing: { kid: "now", alg: "EdDSA", "private-key": current.priv },
		previous: [
			{ kid: "old", alg: "EdDSA", "public-key": previousKey, "expires-at": "2026-06-01T00:00:00Z" },
		],
	});

	it("signs and verifies with the current key, for the typ it was signed for", async () => {
		const k = (await boot(rotated())).app.get(keys);
		const token = await k.sign({ sub: "a" }, "JWT");
		const verified = await k.verify(token, "JWT");
		expect(verified).toEqual({ kind: "valid", claims: { sub: "a" } });
		expect(verified.kind === "valid" && Object.isFrozen(verified.claims)).toBe(true);
		expect(await k.verify(token, "rt+jwt")).toEqual({ kind: "invalid", reason: "typ" });
		expect(await k.verify("not a jws", "JWT")).toEqual({ kind: "invalid", reason: "malformed" });
	});

	it("verifies what the previous key signed until it expires, and tells an unknown kid", async () => {
		const k = (await boot(rotated())).app.get(keys);
		const byOld = await signedBy(old.priv, "old", JSON.stringify({ sub: "a" }));
		expect(await k.verify(byOld, "JWT")).toEqual({ kind: "valid", claims: { sub: "a" } });
		const token = await k.sign({ sub: "a" }, "JWT");
		expect(await k.verify(withKid(token, "nobody"), "JWT")).toEqual({
			kind: "invalid",
			reason: "kid_unknown",
		});
		expect(await k.verify(withKid(token, "old"), "JWT")).toEqual({
			kind: "invalid",
			reason: "signature",
		});
		now = Date.parse("2026-06-01T00:00:00Z") - 1;
		expect((await k.verify(byOld, "JWT")).kind).toBe("valid");
		now += 1;
		expect(await k.verify(byOld, "JWT")).toEqual({ kind: "invalid", reason: "kid_expired" });
	});

	it("publishes and verifies the next key, but never signs with it", async () => {
		const coming = ed25519Pem();
		const { app, base } = await boot({
			...rotated(),
			next: { kid: "next", alg: "EdDSA", "public-key": coming.priv },
		});
		const k = app.get(keys);
		const signed = await k.sign({ sub: "a" }, "JWT");
		expect(
			JSON.parse(Buffer.from(signed.split(".")[0] as string, "base64url").toString()).kid,
		).toBe("now");
		const byNext = await signedBy(coming.priv, "next", JSON.stringify({ sub: "a" }));
		expect(await k.verify(byNext, "JWT")).toEqual({ kind: "valid", claims: { sub: "a" } });
		const published = (await (await fetch(`${base}/.well-known/jwks.json`)).json()) as {
			keys: Record<string, unknown>[];
		};
		expect(published.keys.map((key) => key.kid)).toEqual(["now", "old", "next"]);
		expect(published.keys.every((key) => !("d" in key))).toBe(true);
	});

	it("takes a previous key written as a private PEM for its public half alone", async () => {
		const { app, base } = await boot(rotated(old.priv));
		const byOld = await signedBy(old.priv, "old", JSON.stringify({ sub: "a" }));
		expect((await app.get(keys).verify(byOld, "JWT")).kind).toBe("valid");
		const published = (await (await fetch(`${base}/.well-known/jwks.json`)).json()) as {
			keys: Record<string, unknown>[];
		};
		expect(published.keys.every((k) => !("d" in k))).toBe(true);
	});

	it("refuses a token whose signature is written in a form other than its one form", async () => {
		const k = (await boot(rotated())).app.get(keys);
		const token = await k.sign({ sub: "a" }, "JWT");
		const variant = withLastBitsFlipped(token);
		expect(variant).not.toBe(token);
		expect(await k.verify(variant, "JWT")).toEqual({ kind: "invalid", reason: "malformed" });
	});

	it("answers a payload the key signed that is no JSON as a bad signature", async () => {
		const k = (await boot(rotated())).app.get(keys);
		expect(await k.verify(await signedBy(current.priv, "now", "{no json"), "JWT")).toEqual({
			kind: "invalid",
			reason: "signature",
		});
	});

	it("lets a listed origin's page read the key set, and no other origin's", async () => {
		const { base } = await boot(rotated(), { "cors-origins": ["https://app.example"] });
		const read = async (origin: string) =>
			(await fetch(`${base}/.well-known/jwks.json`, { headers: { origin } })).headers.get(
				"access-control-allow-origin",
			);
		expect(await read("https://app.example")).toBe("https://app.example");
		expect(await read("https://evil.example")).toBeNull();
	});

	it("publishes only public members of unexpired keys with a strong ETag", async () => {
		const { base } = await boot(rotated());
		const res = await fetch(`${base}/.well-known/jwks.json`);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { keys: Record<string, unknown>[] };
		expect(body.keys.map((k) => k.kid)).toEqual(["now", "old"]);
		expect(body.keys.every((k) => !("d" in k))).toBe(true);
		const etag = res.headers.get("etag") ?? "";
		expect(etag).toMatch(/^"[A-Za-z0-9_-]+"$/);
		expect(res.headers.get("cache-control")).toBe("public, max-age=300");
		expect(
			(await fetch(`${base}/.well-known/jwks.json`, { headers: { "if-none-match": etag } })).status,
		).toBe(304);
		now = july;
		const later = (await (await fetch(`${base}/.well-known/jwks.json`)).json()) as {
			keys: { kid: string }[];
		};
		expect(later.keys.map((k) => k.kid)).toEqual(["now"]);
	});

	it("does not publish a key set when signing with HMAC", async () => {
		const secret = randomBytes(32).toString("hex");
		const { base } = await boot({ signing: { kid: "h", alg: "HS256", secret } });
		const res = await fetch(`${base}/.well-known/jwks.json`);
		expect(res.status).toBe(404);
		expect(res.headers.get("cache-control")).toBe("no-store");
	});

	it("refuses missing, weak, malformed, mismatched, unknown and duplicate key material", async () => {
		const signing = { kid: "k", alg: "EdDSA", "private-key": current.priv };
		const previous = { kid: "p", alg: "EdDSA", "expires-at": "2027-01-01T00:00:00Z" };
		const pkcs8 = (pair: { privateKey: KeyObject }) =>
			pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
		const p256 = pkcs8(generateKeyPairSync("ec", { namedCurve: "P-256" }));
		const rsa1024 = pkcs8(generateKeyPairSync("rsa", { modulusLength: 1024 }));
		const cases: Record<string, [section: unknown, where: string]> = {
			"no signing key": [{}, "keys.signing"],
			"HMAC secret under 32 bytes": [
				{ signing: { kid: "h", alg: "HS256", secret: randomBytes(31).toString("hex") } },
				"keys.signing.secret",
			],
			"HMAC secret left as the sample": [
				{ signing: { kid: "h", alg: "HS256", secret: "REPLACE-HMAC-SECRET-32-BYTES-OR-MORE" } },
				"keys.signing.secret",
			],
			"HMAC secret of 32 zero bytes": [
				{ signing: { kid: "h", alg: "HS256", secret: "00".repeat(32) } },
				"keys.signing.secret",
			],
			"HMAC secret of a short pattern": [
				{ signing: { kid: "h", alg: "HS256", secret: "ab".repeat(32) } },
				"keys.signing.secret",
			],
			"HMAC secret in loose base64": [
				{ signing: { kid: "h", alg: "HS256", secret: `${randomBytes(32).toString("base64")}!` } },
				"keys.signing.secret",
			],
			"kid with a space": [{ signing: { ...signing, kid: "bad kid" } }, "keys.signing.kid"],
			"kid repeated in previous": [
				{ signing, previous: [{ ...previous, kid: "k", "public-key": current.pub }] },
				"keys.previous",
			],
			"Ed25519 key named ES256": [
				{ signing: { ...signing, alg: "ES256" } },
				"keys.signing.private-key",
			],
			"P-256 key named EdDSA": [
				{ signing: { ...signing, "private-key": p256 } },
				"keys.signing.private-key",
			],
			"RSA key under 2048 bits": [
				{ signing: { ...signing, alg: "RS256", "private-key": rsa1024 } },
				"keys.signing.private-key",
			],
			"signing key that is public": [
				{ signing: { ...signing, "private-key": current.pub } },
				"keys.signing.private-key",
			],
			"kid repeated in next": [
				{ signing, next: { kid: "k", alg: "EdDSA", "public-key": old.pub } },
				"keys.next",
			],
			"next key that is no key": [
				{ signing, next: { kid: "n", alg: "EdDSA", "public-key": "x" } },
				"keys.next.public-key",
			],
			"previous key that is no key": [
				{ signing, previous: [{ ...previous, "public-key": "x" }] },
				"keys.previous.0.public-key",
			],
			"previous Ed25519 key named ES256": [
				{ signing, previous: [{ ...previous, alg: "ES256", "public-key": old.pub }] },
				"keys.previous.0.public-key",
			],
			"unknown member": [{ signing: { ...signing, extra: 1 } }, "keys.signing"],
		};
		for (const [name, [section, where]] of Object.entries(cases)) {
			expect(await refusedAt(section), name).toEqual([where]);
		}
	});

	it("refuses in its section a signing key not written as PEM, as its fragment's placeholder is, and takes the test builder's", () => {
		const signing = { kid: "k", alg: "EdDSA", "private-key": "REPLACE-PKCS8-PEM-PRIVATE-KEY" };
		const refused = keysSection.safeParse({ signing });
		expect(refused.error?.issues.map((issue) => issue.path.join("."))).toEqual([
			"signing.private-key",
		]);
		expect(keysSection.safeParse(keysConfig().keys).success).toBe(true);
	});

	it("holds no past keys and no next key when the operator writes only the signing key", () => {
		const { signing } = keysConfig().keys;
		expect(keysSection.parse({ signing })).toEqual({ signing, previous: [] });
	});

	it("signs with Ed25519 as asymmetric, and publishes its key set", async () => {
		const ed = await boot({ signing: { kid: "e", alg: "EdDSA", "private-key": current.priv } });
		expect(ed.app.get(keys).asymmetric()).toBe(true);
		expect(ed.app.get(keys).algorithm()).toBe("EdDSA");
		expect(ed.app.get(keys).keySetPath()).toBe("/.well-known/jwks.json");
		expect((await fetch(`${ed.base}${ed.app.get(keys).keySetPath()}`)).status).toBe(200);
	});

	it("signs with HMAC as needing a shared secret", async () => {
		const hs = await boot({
			signing: { kid: "h", alg: "HS256", secret: randomBytes(32).toString("base64") },
		});
		expect(hs.app.get(keys).asymmetric()).toBe(false);
		expect(hs.app.get(keys).algorithm()).toBe("HS256");
		const token = await hs.app.get(keys).sign({ sub: "a" }, "JWT");
		expect((await hs.app.get(keys).verify(token, "JWT")).kind).toBe("valid");
	});
});
