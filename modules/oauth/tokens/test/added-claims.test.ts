import { generateKeyPairSync } from "node:crypto";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { accessTokenSigning } from "@mod/keys";
import keysModule from "@mod/keys/module";
import { keysConfig } from "@mod/keys/testing";
import senderBindingModule from "@mod/sender-binding/module";
import { describe, expect, it } from "vitest";
import {
	type AccessGrant,
	type IssuancePolicy,
	type IssuanceRequest,
	issuancePolicies,
	tokens,
} from "../src/contract.ts";
import tokensModule from "../src/module.ts";
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
		modules: [
			http,
			keysModule,
			issuerModule,
			senderBindingModule,
			tokensModule,
			revokedInMemory(() => runtime.clock.now()).module,
			...extra,
		],
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

describe("claims a grant adds to its access token", () => {
	it("signs them into the payload and reads them back frozen, naming them in name order", async () => {
		const { t } = await boot();
		const claims = { "https://example.com/b": [1, { c: null }], a: "x" };
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

	it("shows the policies the claims as copied, frozen, at admits as at issue", async () => {
		const seen: IssuanceRequest[] = [];
		const watching: IssuancePolicy = {
			name: "watching",
			judge: async (request) => {
				seen.push(request);
				return { kind: "allowed" };
			},
		};
		const policies = defineModule({ name: "policies" }, (m) => [
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
		const policies = defineModule({ name: "policies" }, (m) => [
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
		const wide = { ...grant, scope: Array.from({ length: 2000 }, (_, i) => `scope-${i}`) };
		await expect(t.issue({ grant: wide, grantType: "test" })).rejects.toThrow(TypeError);
	});
});
