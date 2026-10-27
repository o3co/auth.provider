import { describe, expect, it } from "vitest";
import { claimsAsked } from "../claims-request.ts";

const scopes = new Map([
	["name", "read"],
	["email", "write"],
]);
const scopeOf = (claim: string) => scopes.get(claim);
const of = (members: Record<string, unknown>, withScopes = true) =>
	claimsAsked(JSON.stringify(members), withScopes ? scopeOf : undefined);

describe("claims-request", () => {
	it("reads no sub but for OpenID Connect, judging none it does not read, and the acr and auth_time either way", () => {
		const text = JSON.stringify({
			id_token: {
				sub: { value: 7 },
				acr: { essential: true, values: ["gold"] },
				auth_time: { essential: true },
			},
		});
		expect(claimsAsked(text)).toBe("malformed");
		expect(claimsAsked(text, undefined, false)).toEqual({
			knownTime: true,
			acr: [{ essential: true, values: ["gold"] }],
			subs: [],
			selection: {
				idToken: { names: [], constraints: [] },
				userinfo: { names: [], constraints: [] },
			},
		});
	});

	it("refuses a claim it keeps asked in a shape it does not take", () => {
		const long = "x".repeat(257);
		for (const asked of [
			{ name: 5 },
			{ name: { value: ["a"] } },
			{ name: { value: { a: 1 } } },
			{ name: { value: null } },
			{ name: { value: Number.NaN } },
			{ name: { values: [] } },
			{ name: { value: "a", values: ["b"] } },
			{ name: { values: Array.from({ length: 17 }, (_, i) => `v${i}`) } },
			{ name: { value: long } },
			{ name: { essential: "yes" } },
		]) {
			expect(of({ userinfo: asked }), JSON.stringify(asked)).toBe("malformed");
		}
		const wide = { values: Array.from({ length: 16 }, () => "y".repeat(100)) };
		expect(of({ userinfo: { name: wide, email: wide }, id_token: { name: wide } })).toBe(
			"malformed",
		);
	});

	it("reads names with their constraints by target, passing over what it does not understand [oidc-core-5.5.1-c] [oidc-core-5.5-b]", () => {
		const asked = of({
			id_token: { name: { essential: true, purpose: "x" } },
			userinfo: { email: { values: ["a@example.com", true, 3] }, nickname: [1, 2], name: null },
			other: 1,
		});
		expect(asked).toMatchObject({
			selection: {
				idToken: { names: [{ name: "name", scope: "read" }], constraints: [] },
				userinfo: {
					names: [
						{ name: "email", scope: "write" },
						{ name: "name", scope: "read" },
					],
					constraints: [{ name: "email", values: ["a@example.com", true, 3] }],
				},
			},
		});
	});

	it("reads no names without the scopes, nor a claim's shape, but still the acr and sub", () => {
		const asked = of({ userinfo: { name: 5, sub: { value: "alice" }, acr: null } }, false);
		expect(asked).toMatchObject({
			subs: [["alice"]],
			acr: [{ values: [], essential: false }],
			selection: { userinfo: { names: [], constraints: [] } },
		});
	});

	it("reads the sub values each member asks, and refuses a sub of no shape it takes", () => {
		expect(
			of({ id_token: { sub: { values: ["a", "b"] } }, userinfo: { sub: null } }),
		).toMatchObject({
			subs: [["a", "b"]],
		});
		for (const sub of [7, { value: 7 }, { values: [] }, { value: "a", values: ["b"] }]) {
			expect(of({ id_token: { sub } }), JSON.stringify(sub)).toBe("malformed");
		}
	});

	it("bounds no acr or sub values by the selection's count", () => {
		const many = Array.from({ length: 20 }, (_, i) => `urn:${i}`);
		expect(of({ id_token: { acr: { values: many }, sub: { values: many } } })).toMatchObject({
			acr: [{ values: many }],
			subs: [many],
		});
	});
});
