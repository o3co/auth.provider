/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { describe, expect, it } from "vitest";
import { ClientEntrySchema } from "#/repositories/InMemoryClientRepository.mjs";

describe("ClientEntrySchema — allowedGrantTypes field (Wave 1 §3.4.1)", () => {
	it("accepts absent allowedGrantTypes (existing clients)", () => {
		const result = ClientEntrySchema.safeParse({
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "s",
		});
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.allowedGrantTypes).toBeUndefined();
	});

	it("accepts allowedGrantTypes as string array", () => {
		const result = ClientEntrySchema.safeParse({
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "s",
			allowedGrantTypes: ["authorization_code", "refresh_token", "client_credentials"],
		});
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.allowedGrantTypes).toEqual([
				"authorization_code",
				"refresh_token",
				"client_credentials",
			]);
		}
	});

	it("accepts empty allowedGrantTypes array", () => {
		const result = ClientEntrySchema.safeParse({
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "s",
			allowedGrantTypes: [],
		});
		expect(result.success).toBe(true);
	});

	it("rejects non-string values in allowedGrantTypes", () => {
		const result = ClientEntrySchema.safeParse({
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "s",
			allowedGrantTypes: ["client_credentials", 42],
		});
		expect(result.success).toBe(false);
	});
});

describe("ClientEntrySchema — senderConstrained field (Wave 2 §4.8)", () => {
	it("accepts absent senderConstrained (clients that have not opted in)", () => {
		const result = ClientEntrySchema.safeParse({
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "s",
		});
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.senderConstrained).toBeUndefined();
	});

	it("accepts valid senderConstrained with required + non-empty methods", () => {
		const result = ClientEntrySchema.safeParse({
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "s",
			senderConstrained: { required: true, methods: ["dpop", "mtls"] },
		});
		expect(result.success).toBe(true);
	});

	it("accepts senderConstrained.required:false with empty methods (advisory)", () => {
		// required:false → methods is advisory, empty is fine.
		const result = ClientEntrySchema.safeParse({
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "s",
			senderConstrained: { required: false, methods: [] },
		});
		expect(result.success).toBe(true);
	});

	it("rejects required:true with empty methods (would reject every binding at runtime)", () => {
		// Fail-at-boot: a config that would reject every request is almost
		// certainly operator error and should surface at load time, not
		// silently fail-closed at every /token request.
		const result = ClientEntrySchema.safeParse({
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "s",
			senderConstrained: { required: true, methods: [] },
		});
		expect(result.success).toBe(false);
	});

	it("rejects empty-string entries in methods (typo / silent-match guard)", () => {
		// An empty kind string would match a future `TokenBindingMechanism`
		// with `kind: ""` — a typo or refactor artifact — silently. Force
		// non-empty entries at schema time.
		const result = ClientEntrySchema.safeParse({
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "s",
			senderConstrained: { required: true, methods: ["dpop", ""] },
		});
		expect(result.success).toBe(false);
	});
	it("#316/#330: accepts firstParty, the marking /authorize requires", () => {
		// The `.strict()` schema had no `firstParty` key, so a YAML/static
		// registration could not carry the marking /authorize demands: writing
		// it failed boot as an unrecognized key, omitting it made every
		// /authorize return unauthorized_client. The file-backed adapters had
		// no working configuration at all.
		const result = ClientEntrySchema.safeParse({
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "s",
			firstParty: true,
		});
		expect(result.success).toBe(true);
		expect(result.success && result.data.firstParty).toBe(true);
	});

	it("#316: firstParty stays optional — absence means not first-party", () => {
		const result = ClientEntrySchema.safeParse({
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "s",
		});
		expect(result.success).toBe(true);
		expect(result.success && result.data.firstParty).toBeUndefined();
	});

	it("#316: rejects a non-boolean firstParty", () => {
		const result = ClientEntrySchema.safeParse({
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "s",
			firstParty: "true",
		});
		expect(result.success).toBe(false);
	});

	it("#273: accepts allowPlainPkce, the only route to the RFC 7636 plain method", () => {
		// The schema is `.strict()`, so without the key a registration could
		// not carry the opt-in at all — and there is deliberately no
		// server-wide setting that admits `plain` instead.
		const result = ClientEntrySchema.safeParse({
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "s",
			allowPlainPkce: true,
		});
		expect(result.success).toBe(true);
		expect(result.success && result.data.allowPlainPkce).toBe(true);
	});

	it("#273: allowPlainPkce stays optional — absence means S256 only", () => {
		const result = ClientEntrySchema.safeParse({
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "s",
		});
		expect(result.success).toBe(true);
		expect(result.success && result.data.allowPlainPkce).toBeUndefined();
	});

	it("#273: rejects a non-boolean allowPlainPkce", () => {
		// A YAML `allowPlainPkce: "true"` must fail at boot rather than reach
		// the policy site, where the strict `=== true` would silently ignore
		// it and the operator would believe the exception was in force.
		const result = ClientEntrySchema.safeParse({
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "s",
			allowPlainPkce: "true",
		});
		expect(result.success).toBe(false);
	});
});

describe("ClientEntrySchema — allowedRedirectUris shape (#395)", () => {
	const base = {
		tokenEndpointAuthMethod: "client_secret_basic",
		clientSecret: "s",
	};

	it("accepts https, loopback http, and reverse-domain custom schemes", () => {
		const result = ClientEntrySchema.safeParse({
			...base,
			allowedRedirectUris: [
				"https://app.example/cb",
				"http://localhost:3000/callback",
				"com.example.app:/oauth2redirect",
			],
		});
		expect(result.success).toBe(true);
	});

	it("refuses a javascript: registration at boot, naming the entry", () => {
		const result = ClientEntrySchema.safeParse({
			...base,
			allowedRedirectUris: ["javascript:alert(1)"],
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			const message = result.error.issues.map((issue) => issue.message).join("\n");
			expect(message).toContain("javascript:alert(1)");
			expect(message).toContain("executable");
		}
	});

	it.each([
		["a fragment", "https://app.example/cb#frag"],
		["userinfo", "https://user@app.example/cb"],
		["http off loopback", "http://app.example/cb"],
		["a dotless legacy scheme", "myapp://callback"],
		["an unparsable entry", "not a url"],
	])("refuses %s at boot", (_label, uri) => {
		const result = ClientEntrySchema.safeParse({ ...base, allowedRedirectUris: [uri] });
		expect(result.success).toBe(false);
	});

	it("reports every bad entry, not only the first", () => {
		const result = ClientEntrySchema.safeParse({
			...base,
			allowedRedirectUris: ["javascript:alert(1)", "https://ok.example/cb", "myapp://cb"],
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			const message = result.error.issues.map((issue) => issue.message).join("\n");
			expect(message).toContain("javascript:alert(1)");
			expect(message).toContain("myapp://cb");
		}
	});
});
