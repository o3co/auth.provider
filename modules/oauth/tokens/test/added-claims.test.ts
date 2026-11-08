import { createPrivateKey, generateKeyPairSync, sign } from "node:crypto";
import { httpConfig } from "@mod/http/testing";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { accessTokenSigning } from "@mod/keys";
import { keysConfig } from "@mod/keys/testing";
import { describe, expect, it } from "vitest";
import {
	type AccessGrant,
	type Actor,
	type IssuancePolicy,
	type IssuanceRequest,
	issuancePolicies,
	tokens,
} from "../src/contract.ts";
import { composedModules } from "./composed.ts";
import { revokedInMemory } from "./revoked.ts";

const runtime = quietRuntime();
const privateKey = generateKeyPairSync("ed25519")
	.privateKey.export({ format: "pem", type: "pkcs8" })
	.toString();
const grant: AccessGrant = { subject: "s", issuedTo: "c", audience: ["api"], scope: [] };
const payloadOf = (token: string) =>
	JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString());

async function boot(extra: Module[] = []) {
	const app = await assemble({
		modules: [...composedModules, revokedInMemory(() => runtime.clock.now()).module, ...extra],
		config: {
			...kernelConfig(),
			...httpConfig({}),
			...keysConfig({ signing: { kid: "k", alg: "EdDSA", "private-key": privateKey } }),
			...issuerConfig({ url: "https://issuer.example" }),
			tokens: { "subject-check": "none", revocation: "unsupported" },
		},
		runtime,
	});
	return { t: app.get(tokens), signer: app.get(accessTokenSigning) };
}

/** A token signed as tokens signs one, with what a test puts in its payload. */
const signedWith = async (signer: Awaited<ReturnType<typeof boot>>["signer"], extra: object) => {
	const iat = Math.floor(runtime.clock.now() / 1000);
	const payload = {
		iss: "https://issuer.example",
		sub: "s",
		aud: "api",
		client_id: "c",
		iat,
		exp: iat + 60,
		jti: "j",
		...extra,
	};
	return signer.sign(payload);
};

/** A token as 0.18 signed one, before signing refused a null. */
const signedBefore = (extra: object) => {
	const part = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
	const iat = Math.floor(runtime.clock.now() / 1000);
	const signing = `${part({ alg: "EdDSA", typ: "at+jwt", kid: "k" })}.${part({
		iss: "https://issuer.example",
		sub: "s",
		aud: "api",
		client_id: "c",
		iat,
		exp: iat + 60,
		jti: "j",
		...extra,
	})}`;
	const signature = sign(null, Buffer.from(signing), createPrivateKey(privateKey));
	return `${signing}.${signature.toString("base64url")}`;
};

describe("claims a grant adds to its access token", () => {
	it("reads back a token an earlier release signed with a null added claim, as signed", async () => {
		const { t } = await boot();
		const claims = { "https://example.com/c": null, nested: { a: null, b: [null, 1] } };
		const checked = await t.verifyAccess(signedBefore(claims));
		if (checked.kind !== "valid") throw new Error(checked.reason);
		expect(checked.grant.claims).toEqual(claims);
	});

	it("signs them into the payload and reads them back frozen, naming them in name order", async () => {
		const { t } = await boot();
		const claims = { "https://example.com/b": [1, { c: false }], a: "x" };
		const issued = await t.issue({ grant: { ...grant, claims }, grantType: "test" });
		if (issued.kind !== "issued") throw new Error(issued.policy);
		expect(issued.access.addedClaims).toEqual(["a", "https://example.com/b"]);
		expect(payloadOf(issued.access.token)).toMatchObject(claims);
		const checked = await t.verifyAccess(issued.access.token);
		if (checked.kind !== "valid") throw new Error(checked.reason);
		expect(checked.grant.claims).toEqual(claims);
		expect(Object.isFrozen(checked.grant.claims?.["https://example.com/b"])).toBe(true);
	});

	it("takes an empty set as none, issuing and reading back as before", async () => {
		const { t } = await boot();
		const issued = await t.issue({ grant: { ...grant, claims: {} }, grantType: "test" });
		if (issued.kind !== "issued") throw new Error(issued.policy);
		expect("addedClaims" in issued.access).toBe(false);
		const checked = await t.verifyAccess(issued.access.token);
		expect(checked.kind === "valid" && "claims" in checked.grant).toBe(false);
	});

	it("signs the payload it signed before where a grant adds none or an empty set", async () => {
		const { t } = await boot();
		const membersOf = async (claims?: AccessGrant["claims"]) => {
			const issued = await t.issue({
				grant: claims ? { ...grant, claims } : grant,
				grantType: "t",
			});
			if (issued.kind !== "issued") throw new Error(issued.policy);
			return Object.keys(payloadOf(issued.access.token)).sort();
		};
		const before = ["aud", "client_id", "exp", "iat", "iss", "jti", "sub"];
		expect(await membersOf()).toEqual(before);
		expect(await membersOf({})).toEqual(before);
		expect(await membersOf({ a: 1 })).toEqual([...before, "a"].sort());
	});

	it("refuses a grant's null as a TypeError naming its path, before any policy runs, at admits as at issue", async () => {
		let judged = 0;
		const watching: IssuancePolicy = {
			name: "watching",
			judge: async () => {
				judged += 1;
				return { kind: "allowed" };
			},
		};
		const policy = defineModule({ name: "watching", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(issuancePolicies).by(() => watching),
		]);
		const { t } = await boot([policy]);
		const request = { grant: { ...grant, claims: { c: { a: null } } }, grantType: "test" };
		for (const asked of [() => t.issue(request), () => t.admits(request)]) {
			const refused = await asked().catch((error: unknown) => error);
			expect(refused).toBeInstanceOf(TypeError);
			expect((refused as TypeError).message).toContain("null at c.a");
		}
		expect(judged).toBe(0);
	});

	it("shows the policies the claims as copied, frozen, at admits as at issue", async () => {
		const seen: IssuanceRequest[] = [];
		const watching: IssuancePolicy = {
			name: "watching",
			judge: async (request) => {
				seen.push(request);
				return { kind: "allowed" };
			},
		};
		const policies = defineModule({ name: "policies", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(issuancePolicies).by(() => watching),
		]);
		const { t } = await boot([policies]);
		const claims = { a: [1] };
		expect(await t.admits({ grant: { ...grant, claims }, grantType: "test" })).toEqual({
			kind: "allowed",
		});
		expect(seen[0]?.grant.claims).toEqual(claims);
		expect(seen[0]?.grant.claims).not.toBe(claims);
		expect(Object.isFrozen(seen[0]?.grant.claims?.a)).toBe(true);
		const empty = await t.admits({ grant: { ...grant, claims: {} }, grantType: "test" });
		expect([empty.kind, "claims" in (seen[1]?.grant ?? {})]).toEqual(["allowed", false]);
	});

	it("refuses a reserved name, at issue and at admits, as the grant's maker's mistake", async () => {
		const { t } = await boot();
		for (const name of ["sub", "nbf", "scp", "email", "active", "__proto__"]) {
			const claims = JSON.parse(`{"${name}": 1}`);
			const request = { grant: { ...grant, claims }, grantType: "test" };
			await expect(t.issue(request), name).rejects.toThrow(TypeError);
			await expect(t.admits(request), name).rejects.toThrow(TypeError);
		}
		// Reserved at the top alone; an object's own names everywhere.
		const nested = { grant: { ...grant, claims: { a: { sub: 1 } } }, grantType: "test" };
		expect((await t.issue(nested)).kind).toBe("issued");
		const proto = JSON.parse('{"a": {"__proto__": 1}}');
		await expect(
			t.issue({ grant: { ...grant, claims: proto }, grantType: "test" }),
		).rejects.toThrow(TypeError);
	});

	it("shows the policies the claims as copied, frozen", async () => {
		const seen: IssuanceRequest[] = [];
		const watching: IssuancePolicy = {
			name: "watching",
			judge: async (request) => {
				seen.push(request);
				return { kind: "allowed" };
			},
		};
		const policies = defineModule({ name: "policies", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(issuancePolicies).by(() => watching),
		]);
		const { t } = await boot([policies]);
		const claims = { a: [1] };
		await t.issue({ grant: { ...grant, claims }, grantType: "test" });
		expect(seen[0]?.grant.claims).toEqual(claims);
		expect(Object.isFrozen(seen[0]?.grant.claims?.a)).toBe(true);
		expect(seen[0]?.grant.claims).not.toBe(claims);
	});

	it("reads back a member tokens does not write as an added claim, and refuses one reserved or outside the rules", async () => {
		const { t, signer } = await boot();
		const foreign = await t.verifyAccess(await signedWith(signer, { x: 1 }));
		expect(foreign.kind === "valid" && foreign.grant.claims).toEqual({ x: 1 });
		const deep = { v: [[[[[[[[1]]]]]]]] };
		for (const extra of [{ nbf: 0 }, { username: "u" }, deep, { "a b": 1 }]) {
			expect(await t.verifyAccess(await signedWith(signer, extra)), JSON.stringify(extra)).toEqual({
				kind: "invalid",
				reason: "shape",
			});
		}
	});

	it("bounds an actor chain at 16 and a compact token at 16 KiB, at both ends", async () => {
		const { t, signer } = await boot();
		const chain = (n: number): object | undefined =>
			n === 0 ? undefined : { sub: `a${n}`, ...(n > 1 ? { act: chain(n - 1) } : {}) };
		expect((await t.verifyAccess(await signedWith(signer, { act: chain(16) }))).kind).toBe("valid");
		expect(await t.verifyAccess(await signedWith(signer, { act: chain(17) }))).toEqual({
			kind: "invalid",
			reason: "shape",
		});
		expect(await t.verifyAccess(`${"a".repeat(16_385)}`)).toEqual({
			kind: "invalid",
			reason: "shape",
		});
	});

	it("refuses an issuance whose token would pass 16 KiB once signed, warning its size and the added claims' names, never a value", async () => {
		const logged = recordingLog();
		const app = await assemble({
			modules: [...composedModules, revokedInMemory(() => runtime.clock.now()).module],
			config: {
				...kernelConfig(),
				...httpConfig({}),
				...keysConfig({ signing: { kid: "k", alg: "EdDSA", "private-key": privateKey } }),
				...issuerConfig({ url: "https://issuer.example" }),
				tokens: { "subject-check": "none", revocation: "unsupported" },
			},
			runtime: { ...runtime, log: logged.log },
		});
		const wide = {
			...grant,
			scope: Array.from({ length: 2000 }, (_, i) => `scope-${i}`),
			claims: { x_secret_kept: "s3cr3t" },
		};
		expect(await app.get(tokens).issue({ grant: wide, grantType: "test" })).toEqual({
			kind: "refused",
			policy: "tokens",
			reason: "token_too_large",
			description: "too large",
		});
		const warned = logged.lines().filter((l) => l.event === "tokens.token_too_large");
		expect(warned).toMatchObject([{ fields: { limit: 16_384, claims: "x_secret_kept" } }]);
		expect(Number(warned[0]?.fields.length)).toBeGreaterThan(16_384);
		expect(JSON.stringify(logged.lines())).not.toContain("s3cr3t");
	});
});

describe("an access token at its largest", () => {
	it("fits 16 KiB with added claims at size's 8 KiB ceiling, over the standard claims this covers", async () => {
		// The maxima covered, not bounds: tokens bounds none of the standard claims' lengths, so past
		// these a token may pass 16 KiB, and issue then refuses it (`token_too_large`). Subject, client
		// and two audiences of 256 characters, 1 KiB of scope, an actor chain of four subjects of 64,
		// an acr of 64 and room for a `cnf` (a DPoP thumbprint), signed with RSA-4096.
		const rsa = generateKeyPairSync("rsa", { modulusLength: 4096 })
			.privateKey.export({ format: "pem", type: "pkcs8" })
			.toString();
		const app = await assemble({
			modules: [...composedModules, revokedInMemory(() => runtime.clock.now()).module],
			config: {
				...kernelConfig(),
				...httpConfig({}),
				...keysConfig({ signing: { kid: "k".repeat(64), alg: "RS256", "private-key": rsa } }),
				...issuerConfig({ url: "https://issuer.example" }),
				tokens: {
					"subject-check": "none",
					revocation: "unsupported",
					"added-claims": { size: "8KiB", "string-length": 8192 },
				},
			},
			runtime,
		});
		const long = (n: number) => "a".repeat(n);
		const chain = (n: number): Actor => ({
			subject: long(64),
			...(n > 1 ? { actor: chain(n - 1) } : {}),
		});
		const claims = { x_entitled: long(8100) };
		const largest: AccessGrant = {
			subject: long(256),
			issuedTo: long(256),
			audience: [long(256), `${long(255)}b`],
			scope: Array.from({ length: 128 }, (_, i) => `scope-${String(i).padStart(3, "0")}`),
			actor: chain(4),
			amr: ["pwd", "otp", "hwk"],
			acr: long(64),
			claims,
		};
		const issued = await app.get(tokens).issue({ grant: largest, grantType: "test" });
		if (issued.kind !== "issued") throw new Error(`refused: ${issued.reason}`);
		// What a DPoP binding adds, `,"cnf":{"jkt":<43 characters>}`, encoded.
		expect(issued.access.token.length).toBeLessThanOrEqual(16_384 - 80);
	});
});
