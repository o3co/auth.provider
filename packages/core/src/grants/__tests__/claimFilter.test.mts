// packages/core/src/grants/__tests__/claimFilter.test.mts
import { describe, expect, it } from "vitest";
import { filterClaimsByScope } from "../claimFilter.mjs";

describe("filterClaimsByScope", () => {
	const all = {
		email: "a@b.com",
		emailVerified: true,
		name: "Alice",
		picture: "https://p/p.png",
		groups: ["admins"],
		hd: "example.com", // provider-specific, not in any standard scope
	};

	it("openid scope alone returns empty claim set (sub is added by the caller)", () => {
		expect(filterClaimsByScope(all, ["openid"])).toEqual({});
	});

	it("profile scope emits name + picture", () => {
		expect(filterClaimsByScope(all, ["openid", "profile"])).toEqual({
			name: "Alice",
			picture: "https://p/p.png",
		});
	});

	it("email scope emits email + email_verified", () => {
		expect(filterClaimsByScope(all, ["openid", "email"])).toEqual({
			email: "a@b.com",
			email_verified: true,
		});
	});

	it("groups scope emits groups (non-standard, opt-in)", () => {
		expect(filterClaimsByScope(all, ["openid", "groups"])).toEqual({
			groups: ["admins"],
		});
	});

	it("combined scopes compose", () => {
		expect(filterClaimsByScope(all, ["openid", "profile", "email"])).toEqual({
			name: "Alice",
			picture: "https://p/p.png",
			email: "a@b.com",
			email_verified: true,
		});
	});

	it("absent claims are omitted (not emitted as undefined)", () => {
		expect(filterClaimsByScope({ email: "only@x.com" }, ["openid", "profile", "email"])).toEqual({
			email: "only@x.com",
		});
	});

	it("provider-specific claims are never emitted (strict whitelist)", () => {
		expect(filterClaimsByScope({ hd: "example.com" }, ["openid", "profile", "email"])).toEqual({});
	});

	it("filters non-string elements from groups array (security)", () => {
		// UserSessionClaims has an index signature, so upstream code may put
		// arbitrary values in. Ensure only strings leak through.
		const mixed = {
			groups: ["admins", 42, { nested: "obj" }, null, "editors"] as unknown[],
		};
		expect(filterClaimsByScope(mixed, ["openid", "groups"])).toEqual({
			groups: ["admins", "editors"],
		});
	});
});
