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
import {
	ClientEntrySchema,
	InMemoryClientRepository,
} from "#/repositories/InMemoryClientRepository.mjs";

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

	it("#527: accepts client_name and client_uri for the consent page, refusing a non-URL client_uri", () => {
		const base = { tokenEndpointAuthMethod: "client_secret_basic", clientSecret: "s" };
		expect(
			ClientEntrySchema.safeParse({
				...base,
				clientName: "Acme Chat",
				clientUri: "https://chat.example",
			}).success,
		).toBe(true);
		expect(ClientEntrySchema.safeParse({ ...base, clientName: "" }).success).toBe(false);
		expect(ClientEntrySchema.safeParse({ ...base, clientUri: "chat.example" }).success).toBe(false);
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

describe("ClientEntrySchema — defaultScopes field (#396)", () => {
	const base = {
		tokenEndpointAuthMethod: "client_secret_basic",
		clientSecret: "s",
		allowedScopes: ["read", "write"],
	};

	it("accepts defaultScopes that are a subset of allowedScopes", () => {
		const result = ClientEntrySchema.safeParse({ ...base, defaultScopes: ["read"] });
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.defaultScopes).toEqual(["read"]);
	});

	it("accepts absent defaultScopes (deny-by-absence is the runtime's job)", () => {
		const result = ClientEntrySchema.safeParse(base);
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.defaultScopes).toBeUndefined();
	});

	it("refuses defaultScopes outside allowedScopes at boot, naming them", () => {
		// A default the allowlist would refuse could never be granted to a
		// scope-carrying request; letting it ride the omitted-scope path would
		// make omission the wider grant.
		const result = ClientEntrySchema.safeParse({ ...base, defaultScopes: ["read", "admin"] });
		expect(result.success).toBe(false);
		if (!result.success) {
			const message = result.error.issues.map((issue) => issue.message).join("\n");
			expect(message).toContain("admin");
			expect(message).not.toContain('"read"');
		}
	});
});

describe("ClientEntrySchema — private_key_jwt (#484)", () => {
	const jwk = {
		kty: "EC",
		crv: "P-256",
		kid: "k1",
		x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
	};
	const issues = (input: unknown): string => {
		const result = ClientEntrySchema.safeParse(input);
		return result.success ? "" : result.error.issues.map((issue) => issue.message).join("\n");
	};

	it("accepts inline jwks and exposes it — public keys — through the repository", async () => {
		expect(issues({ tokenEndpointAuthMethod: "private_key_jwt", jwks: { keys: [jwk] } })).toBe("");
		const repo = new InMemoryClientRepository(
			new Map([
				["rp", { tokenEndpointAuthMethod: "private_key_jwt" as const, jwks: { keys: [jwk] } }],
			]),
		);
		const found = await repo.findById("rp");
		expect(found?.tokenEndpointAuthMethod).toBe("private_key_jwt");
		expect(found?.jwks).toEqual({ keys: [jwk] });
		// There is no secret to compare against: possession is proven at the
		// token endpoint by the assertion, never by this method.
		expect(await repo.authenticate("rp", "anything")).toBeNull();
	});

	it("refuses private or symmetric key material in jwks — a registration carries public keys only", () => {
		const pkj = (keys: unknown[]) =>
			issues({ tokenEndpointAuthMethod: "private_key_jwt", jwks: { keys } });
		expect(pkj([{ ...jwk, d: "AQAB-not-for-here" }])).toMatch(/private key material \(d\)/);
		expect(
			pkj([{ kty: "RSA", n: "AQAB", e: "AQAB", p: "x", q: "y", dp: "z", dq: "w", qi: "v" }]),
		).toMatch(/private key material \(p, q, dp, dq, qi\)/);
		expect(pkj([{ kty: "oct", k: "c2VjcmV0" }])).toMatch(/symmetric/);
		expect(pkj([{ crv: "P-256", x: jwk.x, y: jwk.y }])).toMatch(/kty/);
		// The public key alone is what was always accepted.
		expect(pkj([jwk])).toBe("");
	});

	it("accepts jwksUri over https, over http only on a loopback host, and exposes it", async () => {
		expect(
			issues({
				tokenEndpointAuthMethod: "private_key_jwt",
				jwksUri: "https://rp.example.com/jwks.json",
			}),
		).toBe("");
		expect(
			issues({ tokenEndpointAuthMethod: "private_key_jwt", jwksUri: "http://localhost:3000/jwks" }),
		).toBe("");
		expect(
			issues({ tokenEndpointAuthMethod: "private_key_jwt", jwksUri: "http://rp.example.com/jwks" }),
		).toMatch(/https/);
		const repo = new InMemoryClientRepository(
			new Map([
				[
					"rp",
					{
						tokenEndpointAuthMethod: "private_key_jwt" as const,
						jwksUri: "https://rp.example.com/jwks.json",
					},
				],
			]),
		);
		expect((await repo.findById("rp"))?.jwksUri).toBe("https://rp.example.com/jwks.json");
	});

	it("requires exactly one of jwks and jwksUri", () => {
		expect(issues({ tokenEndpointAuthMethod: "private_key_jwt" })).toMatch(/exactly one of jwks/);
		expect(
			issues({
				tokenEndpointAuthMethod: "private_key_jwt",
				jwks: { keys: [jwk] },
				jwksUri: "https://rp.example.com/jwks.json",
			}),
		).toMatch(/exactly one of jwks/);
	});

	it("refuses a clientSecret next to private_key_jwt — one credential, not two", () => {
		expect(
			issues({
				tokenEndpointAuthMethod: "private_key_jwt",
				jwks: { keys: [jwk] },
				clientSecret: "s",
			}),
		).toMatch(/clientSecret must not be set/);
	});

	it("refuses jwks or jwksUri on a client that authenticates with a secret", () => {
		expect(
			issues({
				tokenEndpointAuthMethod: "client_secret_basic",
				clientSecret: "s",
				jwks: { keys: [jwk] },
			}),
		).toMatch(/private_key_jwt/);
		expect(
			issues({ tokenEndpointAuthMethod: "none", jwksUri: "https://rp.example.com/jwks.json" }),
		).toMatch(/private_key_jwt/);
	});

	it("refuses an empty key set", () => {
		expect(issues({ tokenEndpointAuthMethod: "private_key_jwt", jwks: { keys: [] } })).not.toBe("");
	});
});
