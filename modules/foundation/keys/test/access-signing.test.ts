import { createPrivateKey, generateKeyPairSync, randomBytes } from "node:crypto";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { assemble, BootRefused, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { CompactSign, decodeProtectedHeader } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import { accessTokenSigning, keys } from "../src/contract.ts";
import keysModule from "../src/module.ts";

const january = Date.parse("2026-01-01T00:00:00Z");
let now = january;
afterEach(() => {
	now = january;
});
const runtime = quietRuntime({ clock: { now: () => now } });

const ed25519Pem = () => {
	const pair = generateKeyPairSync("ed25519");
	return {
		priv: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
		pub: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
	};
};

async function open(section: unknown) {
	const app = await assemble({
		modules: [http, keysModule],
		config: { ...kernelConfig(), ...httpConfig(), keys: section },
		runtime,
	});
	return { access: app.get(accessTokenSigning), k: app.get(keys) };
}

const signedBy = (privatePem: string, kid: string, typ: string) =>
	new CompactSign(new TextEncoder().encode(JSON.stringify({ sub: "a" })))
		.setProtectedHeader({ alg: "EdDSA", typ, kid })
		.sign(createPrivateKey(privatePem));

describe("accessTokenSigning", () => {
	const current = ed25519Pem();
	const old = ed25519Pem();
	const coming = ed25519Pem();
	const rotated = {
		signing: { kid: "now", alg: "EdDSA", "private-key": current.priv },
		next: { kid: "next", alg: "EdDSA", "public-key": coming.pub },
		previous: [
			{ kid: "old", alg: "EdDSA", "public-key": old.pub, "expires-at": "2026-06-01T00:00:00Z" },
		],
	};

	it("signs the claims as they are as an at+jwt with the current key, and verifies it [oidc-core-10.1-d]", async () => {
		const { access } = await open(rotated);
		const token = await access.sign({ sub: "a", scope: "read" });
		expect(decodeProtectedHeader(token)).toEqual({ alg: "EdDSA", typ: "at+jwt", kid: "now" });
		const verified = await access.verify(token);
		expect(verified).toEqual({ kind: "valid", claims: { sub: "a", scope: "read" } });
		expect(verified.kind === "valid" && Object.isFrozen(verified.claims)).toBe(true);
	});

	it("refuses to sign claims holding a null, at any depth, by keys.sign and as an access token alike, naming the claims and not their values [oidc-core-13.3-a]", async () => {
		const { access, k } = await open(rotated);
		const claims = { sub: "a", secret: "kept-value", nonce: null, address: { region: null } };
		const refusal = /^keys: claims are null: nonce address\.region$/;
		await expect(access.sign(claims)).rejects.toThrow(refusal);
		await expect(k.sign(claims, "JWT")).rejects.toThrow(refusal);
		await expect(k.sign({ sub: "a", list: [{ item: null }] }, "JWT")).rejects.toThrow(
			/claims are null: list\[0\]\.item$/,
		);
		await expect(access.sign(claims)).rejects.not.toThrow(/kept-value/);
		expect(await access.sign({ sub: "a", scope: "read" })).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);
	});

	it("refuses a token of any other typ, and a malformed one, as keys.verify does", async () => {
		const { access, k } = await open(rotated);
		expect(await access.verify(await k.sign({ sub: "a" }, "JWT"))).toEqual({
			kind: "invalid",
			reason: "typ",
		});
		expect(await access.verify("not a jws")).toEqual({ kind: "invalid", reason: "malformed" });
	});

	it("verifies under the ring as keys.verify does: the previous key until it expires, the next key, never another kid", async () => {
		const { access } = await open(rotated);
		const byOld = await signedBy(old.priv, "old", "at+jwt");
		expect((await access.verify(byOld)).kind).toBe("valid");
		expect((await access.verify(await signedBy(coming.priv, "next", "at+jwt"))).kind).toBe("valid");
		expect(await access.verify(await signedBy(ed25519Pem().priv, "nobody", "at+jwt"))).toEqual({
			kind: "invalid",
			reason: "kid_unknown",
		});
		now = Date.parse("2026-06-01T00:00:00Z");
		expect(await access.verify(byOld)).toEqual({ kind: "invalid", reason: "kid_expired" });
	});

	it("is the only way to an access token: keys' sign and verify refuse its typ, in any case or as a media type", async () => {
		const { access, k } = await open(rotated);
		const token = await access.sign({ sub: "a" });
		for (const typ of [
			"at+jwt",
			"AT+JWT",
			"At+Jwt",
			"application/at+jwt",
			"Application/AT+JWT",
			// A media type's parameters, and the space around them, name the same type.
			"application/at+jwt; charset=UTF-8",
			"AT+JWT;x=1",
			" at+jwt ",
			"Application/At+Jwt ; q=0.5",
		]) {
			await expect(k.sign({ sub: "a" }, typ), typ).rejects.toThrow(TypeError);
			await expect(k.verify(token, typ), typ).rejects.toThrow(TypeError);
		}
		// Other types are signed and verified as before.
		for (const typ of ["JWT", "logout+jwt", "at+jwt2", "application/jwt"]) {
			expect((await k.verify(await k.sign({ sub: "a" }, typ), typ)).kind, typ).toBe("valid");
		}
	});

	it("is taken by tokens alone: another module naming it in its takes refuses boot", async () => {
		const asking = (name: string) =>
			defineModule({ name, takes: [accessTokenSigning] }, (m) => [
				m.provide(contract<object>(`${name}.asks`)).by(async (c) => {
					try {
						await c.get(accessTokenSigning);
					} catch {}
					return {};
				}),
			]);
		const boot = (name: string) =>
			assemble({
				modules: [http, keysModule, asking(name)],
				config: { ...kernelConfig(), ...httpConfig(), keys: rotated },
				runtime,
			});
		const refused = await boot("intruder").catch((error: unknown) => error);
		expect(refused).toBeInstanceOf(BootRefused);
		expect((refused as BootRefused).refusals.map((r) => r.reason).join()).toContain(
			"keys.access-signing is taken by tokens alone",
		);
		await expect(boot("tokens")).resolves.toBeDefined();
	});

	it("signs and verifies with an HMAC secret as with a key pair", async () => {
		const { access } = await open({
			signing: { kid: "s", alg: "HS256", secret: randomBytes(32).toString("base64") },
		});
		const token = await access.sign({ sub: "a" });
		expect(decodeProtectedHeader(token)).toEqual({ alg: "HS256", typ: "at+jwt", kid: "s" });
		expect(await access.verify(token)).toEqual({ kind: "valid", claims: { sub: "a" } });
	});
});
