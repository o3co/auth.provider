import { generateKeyPairSync } from "node:crypto";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { keys } from "@mod/keys";
import keysModule from "@mod/keys/module";
import { keysConfig } from "@mod/keys/testing";
import senderBindingModule from "@mod/sender-binding/module";
import { describe, expect, it } from "vitest";
import { addedClaimsOf, limits } from "../src/added-claims/added-claims.ts";
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
	return { t: app.get(tokens), signer: app.get(keys) };
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
	return signer.sign(payload, "at+jwt");
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

describe("the added claims' copier", () => {
	const refuses = (given: unknown) => expect(() => addedClaimsOf(given)).toThrow(TypeError);

	it("copies a plain set into a new frozen one, and takes none for none or an empty set", () => {
		const given = { a: { b: [true, null, 1.5, "x"] } };
		const copied = addedClaimsOf(given);
		expect(copied).toEqual(given);
		expect(copied).not.toBe(given);
		expect(Object.isFrozen(copied?.a)).toBe(true);
		expect(addedClaimsOf(undefined)).toBeUndefined();
		expect(addedClaimsOf({})).toBeUndefined();
		expect(addedClaimsOf(Object.assign(Object.create(null), { a: 1 }))).toEqual({ a: 1 });
	});

	it("refuses what is not JSON or not plain, calling nothing it was given", () => {
		let called = false;
		const getter = Object.defineProperty({}, "a", {
			enumerable: true,
			get: () => {
				called = true;
				return 1;
			},
		});
		refuses(getter);
		refuses({ a: getter });
		const trapped = new Proxy(
			{},
			{
				ownKeys: () => {
					called = true;
					return [];
				},
			},
		);
		refuses(trapped);
		refuses({ a: trapped });
		expect(called).toBe(false);
		const cycle: Record<string, unknown> = {};
		cycle.self = cycle;
		refuses({ a: cycle });
		refuses({ a: { toJSON: () => 1 } });
		refuses({ [Symbol("a")]: 1 });
		refuses({ a: Symbol("a") });
		refuses({ a: 1n });
		refuses({ a: undefined });
		refuses({ a: Number.NaN });
		refuses({ a: Number.POSITIVE_INFINITY });
		// biome-ignore lint/suspicious/noSparseArray: the hole is what is refused
		refuses({ a: [1, , 2] });
		refuses({ a: Object.assign([1], { extra: 2 }) });
		refuses({ a: new Date(0) });
		refuses({ a: new (class Point {})() });
		refuses([1]);
		refuses("a");
		expect(Object.prototype).not.toHaveProperty("polluted");
	});

	it("takes names of 1 to 255 code points, well formed, with no control character or space", () => {
		expect(addedClaimsOf({ ["é".repeat(limits.nameCodePoints)]: 1 })).toBeDefined();
		refuses({ ["é".repeat(limits.nameCodePoints + 1)]: 1 });
		refuses({ "": 1 });
		for (const name of ["a b", "a\tb", "a\u0000", "a\uD800", "a b"]) refuses({ [name]: 1 });
	});

	it("stops at each limit: a string's code points, members, depth, values and bytes", () => {
		expect(addedClaimsOf({ a: "x".repeat(limits.stringCodePoints) })).toBeDefined();
		// Counted in code points: an astral character is one.
		expect(addedClaimsOf({ a: "😀".repeat(1000) })).toBeDefined();
		refuses({ a: "x".repeat(limits.stringCodePoints + 1) });
		refuses({ a: "a\uDC00" });
		expect(addedClaimsOf({ a: Array(limits.members).fill(0) })).toBeDefined();
		refuses({ a: Array(limits.members + 1).fill(0) });
		const nested = (depth: number): unknown => (depth === 1 ? 1 : [nested(depth - 1)]);
		expect(addedClaimsOf({ a: nested(limits.depth) })).toBeDefined();
		refuses({ a: nested(limits.depth + 1) });
		refuses({
			a: Array(200).fill([0, 0, 0, 0, 0, 0]),
		});
		// {"a":"…","b":"…"} is 15 bytes beside its two strings.
		const bytes = (n: number) => ({
			a: "x".repeat(limits.stringCodePoints),
			b: "x".repeat(n - limits.stringCodePoints - 15),
		});
		expect(addedClaimsOf(bytes(limits.bytes))).toBeDefined();
		refuses(bytes(limits.bytes + 1));
	});
});
