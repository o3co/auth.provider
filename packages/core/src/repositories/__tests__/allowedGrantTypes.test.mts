/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import { describe, expect, it } from "vitest";
import { isGrantTypeAllowed } from "#/repositories/allowedGrantTypes.mjs";

describe("isGrantTypeAllowed", () => {
	it("allows any grant when the client declares no allowlist", () => {
		// Absence is "unrestricted", not "denied": making it deny would revoke
		// every grant from every registration that predates the field.
		expect(isGrantTypeAllowed(undefined, "authorization_code")).toBe(true);
		expect(isGrantTypeAllowed(undefined, "refresh_token")).toBe(true);
	});

	it("allows a grant named in the allowlist", () => {
		expect(isGrantTypeAllowed(["authorization_code", "refresh_token"], "refresh_token")).toBe(true);
	});

	it("denies a grant absent from a declared allowlist", () => {
		expect(isGrantTypeAllowed(["client_credentials"], "authorization_code")).toBe(false);
	});

	it("denies every grant when the allowlist is empty", () => {
		// An empty allowlist names no grant, so no grant matches it.
		expect(isGrantTypeAllowed([], "authorization_code")).toBe(false);
		expect(isGrantTypeAllowed([], "client_credentials")).toBe(false);
	});

	/*
	 * requireAllowlist is deny-by-default for the whole deployment. Without it
	 * the secure posture is opt-in per client registration: one that omits the
	 * field silently gets every grant.
	 *
	 * RFC 7591 §2 defaults an omitted `grant_types` to `["authorization_code"]`
	 * alone. This flag denies outright instead: a deployment that turns it on
	 * has said it audits its registrations, and an implied set would be a
	 * silent decision made for it.
	 */
	describe("requireAllowlist", () => {
		it("denies a grant when the client declares no allowlist", () => {
			expect(isGrantTypeAllowed(undefined, "authorization_code", { requireAllowlist: true })).toBe(
				false,
			);
			expect(isGrantTypeAllowed(undefined, "refresh_token", { requireAllowlist: true })).toBe(
				false,
			);
		});

		it("still allows a grant named in a declared allowlist", () => {
			expect(
				isGrantTypeAllowed(["authorization_code"], "authorization_code", {
					requireAllowlist: true,
				}),
			).toBe(true);
		});

		it("still denies a grant absent from a declared allowlist", () => {
			expect(
				isGrantTypeAllowed(["client_credentials"], "authorization_code", {
					requireAllowlist: true,
				}),
			).toBe(false);
		});

		it("leaves an empty allowlist denying everything, as it already did", () => {
			expect(isGrantTypeAllowed([], "authorization_code", { requireAllowlist: true })).toBe(false);
		});

		// The default must stay allow-by-absence: denying would revoke every
		// grant from registrations that predate the field, in every deployment
		// that has not audited them.
		it("defaults to allow-by-absence when the option is omitted or false", () => {
			expect(isGrantTypeAllowed(undefined, "authorization_code")).toBe(true);
			expect(isGrantTypeAllowed(undefined, "authorization_code", {})).toBe(true);
			expect(isGrantTypeAllowed(undefined, "authorization_code", { requireAllowlist: false })).toBe(
				true,
			);
		});
	});

	it("matches the grant type exactly, without prefix or case folding", () => {
		// grant_type is a case-sensitive string (RFC 6749 §4.5 for URI-valued
		// extension grants), so a near-miss must not pass.
		expect(isGrantTypeAllowed(["authorization_code"], "authorization_cod")).toBe(false);
		expect(isGrantTypeAllowed(["authorization_code"], "Authorization_Code")).toBe(false);
		expect(
			isGrantTypeAllowed(
				["urn:ietf:params:oauth:grant-type:token-exchange"],
				"urn:ietf:params:oauth:grant-type:token-exchange",
			),
		).toBe(true);
	});
});
