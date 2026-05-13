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
import bcrypt from "bcrypt";
import { describe, expect, it } from "vitest";
import {
	ClientEntrySchema,
	InMemoryClientRepository,
} from "#/repositories/InMemoryClientRepository.mjs";

describe("InMemoryClientRepository", () => {
	describe("findById", () => {
		it("returns client when found", async () => {
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"test-app",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "test-secret",
							allowedRedirectUris: ["http://localhost:3000/callback"],
							allowedScopes: ["read", "write"],
						},
					],
				]),
			);
			const client = await repo.findById("test-app");
			expect(client).not.toBeNull();
			expect(client?.clientId).toBe("test-app");
			expect(client).not.toHaveProperty("clientSecret");
			expect(client?.allowedRedirectUris).toEqual(["http://localhost:3000/callback"]);
			expect(client?.allowedScopes).toEqual(["read", "write"]);
		});

		it("returns null when not found", async () => {
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"test-app",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "test-secret",
							allowedRedirectUris: [],
							allowedScopes: [],
						},
					],
				]),
			);
			const client = await repo.findById("nonexistent-client");
			expect(client).toBeNull();
		});

		// D-6 (v0.5.1): findById exposes the configured authentication method on
		// every PublicClient projection so downstream middleware (`clientAuthMw`)
		// and grant handlers (`refreshToken`, `authorization`) can branch on it
		// without re-fetching the client record.
		it("D-6: returns tokenEndpointAuthMethod from findById", async () => {
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"basic-client",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "s",
							allowedRedirectUris: [],
							allowedScopes: [],
						},
					],
					[
						"public-client",
						{
							tokenEndpointAuthMethod: "none",
							allowedRedirectUris: [],
							allowedScopes: [],
						},
					],
				]),
			);
			const basic = await repo.findById("basic-client");
			expect(basic?.tokenEndpointAuthMethod).toBe("client_secret_basic");
			const pub = await repo.findById("public-client");
			expect(pub?.tokenEndpointAuthMethod).toBe("none");
		});
	});

	describe("logout metadata fields round-trip", () => {
		it("preserves all logout fields when set", async () => {
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"logout-client",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "secret",
							allowedRedirectUris: ["http://localhost:3000/callback"],
							allowedScopes: ["openid"],
							postLogoutRedirectUris: [
								"http://localhost:3000/logged-out",
								"http://localhost:3000/home",
							],
							backchannelLogoutUri: "http://localhost:3000/backchannel-logout",
							backchannelLogoutSessionRequired: false,
							frontchannelLogoutUri: "http://localhost:3000/frontchannel-logout",
							frontchannelLogoutSessionRequired: false,
						},
					],
				]),
			);
			const client = await repo.findById("logout-client");
			expect(client).not.toBeNull();
			expect(client?.postLogoutRedirectUris).toEqual([
				"http://localhost:3000/logged-out",
				"http://localhost:3000/home",
			]);
			expect(client?.backchannelLogoutUri).toBe("http://localhost:3000/backchannel-logout");
			expect(client?.backchannelLogoutSessionRequired).toBe(false);
			expect(client?.frontchannelLogoutUri).toBe("http://localhost:3000/frontchannel-logout");
			expect(client?.frontchannelLogoutSessionRequired).toBe(false);
		});

		it("omits optional logout URI fields when not set, but session-required booleans default to true", async () => {
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"no-logout-client",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "secret",
							allowedRedirectUris: [],
							allowedScopes: [],
						},
					],
				]),
			);
			const client = await repo.findById("no-logout-client");
			expect(client).not.toBeNull();
			// URI fields remain absent when not configured.
			expect(client).not.toHaveProperty("postLogoutRedirectUris");
			expect(client).not.toHaveProperty("backchannelLogoutUri");
			expect(client).not.toHaveProperty("frontchannelLogoutUri");
			// Session-required booleans default to true (intentional deviation from OIDC spec default
			// of false — see ClientEntrySchema for rationale).
			expect(client?.backchannelLogoutSessionRequired).toBe(true);
			expect(client?.frontchannelLogoutSessionRequired).toBe(true);
		});

		it("explicit false is preserved (not overwritten by default)", async () => {
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"explicit-false-client",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "secret",
							allowedRedirectUris: [],
							allowedScopes: [],
							backchannelLogoutSessionRequired: false,
							frontchannelLogoutSessionRequired: false,
						},
					],
				]),
			);
			const client = await repo.findById("explicit-false-client");
			expect(client).not.toBeNull();
			expect(client?.backchannelLogoutSessionRequired).toBe(false);
			expect(client?.frontchannelLogoutSessionRequired).toBe(false);
		});
	});

	describe("federation-token opt-in field round-trip (F-6)", () => {
		it("preserves allowedAzpForFederationToken when set to true", async () => {
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"rp",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "secret",
							allowedRedirectUris: ["https://rp.example/cb"],
							allowedScopes: ["openid"],
							allowedAzpForFederationToken: true,
						},
					],
				]),
			);
			const c = await repo.findById("rp");
			expect(c?.allowedAzpForFederationToken).toBe(true);
		});

		it("defaults allowedAzpForFederationToken to false when omitted", async () => {
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"rp",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "secret",
							allowedRedirectUris: ["https://rp.example/cb"],
							allowedScopes: ["openid"],
						},
					],
				]),
			);
			const c = await repo.findById("rp");
			expect(c?.allowedAzpForFederationToken).toBe(false);
		});

		it("preserves allowedAzpForFederationToken: false when explicit", async () => {
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"rp",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "secret",
							allowedRedirectUris: ["https://rp.example/cb"],
							allowedScopes: ["openid"],
							allowedAzpForFederationToken: false,
						},
					],
				]),
			);
			const c = await repo.findById("rp");
			expect(c?.allowedAzpForFederationToken).toBe(false);
		});
	});

	describe("ClientEntrySchema URI validation", () => {
		it("rejects an invalid URL in backchannelLogoutUri", () => {
			const result = ClientEntrySchema.safeParse({
				tokenEndpointAuthMethod: "client_secret_basic",
				clientSecret: "secret",
				allowedRedirectUris: [],
				allowedScopes: [],
				backchannelLogoutUri: "not-a-url",
			});
			expect(result.success).toBe(false);
		});
	});

	describe("ClientEntrySchema URL scheme allowlist (F-5 XSS hardening)", () => {
		const baseEntry = {
			tokenEndpointAuthMethod: "client_secret_basic" as const,
			clientSecret: "secret",
			allowedRedirectUris: [],
			allowedScopes: [],
		};

		it.each([
			["postLogoutRedirectUris", { postLogoutRedirectUris: ["javascript:alert(1)"] }],
			[
				"postLogoutRedirectUris",
				{ postLogoutRedirectUris: ["data:text/html,<script>alert(1)</script>"] },
			],
			["postLogoutRedirectUris", { postLogoutRedirectUris: ["file:///etc/passwd"] }],
			["backchannelLogoutUri", { backchannelLogoutUri: "javascript:alert(1)" }],
			["frontchannelLogoutUri", { frontchannelLogoutUri: "javascript:alert(1)" }],
		])("rejects %s with scheme %s", (_field, override) => {
			const result = ClientEntrySchema.safeParse({ ...baseEntry, ...override });
			expect(result.success).toBe(false);
		});

		it("accepts https: scheme for all three logout URI fields", () => {
			const result = ClientEntrySchema.safeParse({
				...baseEntry,
				postLogoutRedirectUris: ["https://rp.example/logged-out"],
				backchannelLogoutUri: "https://rp.example/backchannel-logout",
				frontchannelLogoutUri: "https://rp.example/fc-logout",
			});
			expect(result.success).toBe(true);
		});

		it("accepts http: scheme for local/dev URIs", () => {
			const result = ClientEntrySchema.safeParse({
				...baseEntry,
				postLogoutRedirectUris: ["http://localhost:3000/logged-out"],
				backchannelLogoutUri: "http://localhost:3000/back-logout",
				frontchannelLogoutUri: "http://localhost:3000/fc-logout",
			});
			expect(result.success).toBe(true);
		});
	});

	describe("allowedAudiences field round-trip (Token Exchange RFC 8693)", () => {
		it("exposes allowedAudiences via findById (empty array when omitted)", async () => {
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"client-a",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "s",
							allowedRedirectUris: [],
							allowedScopes: [],
						},
					],
				]),
			);
			const client = await repo.findById("client-a");
			expect(client?.allowedAudiences).toEqual([]);
		});

		it("exposes allowedAudiences via findById (preserves configured values)", async () => {
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"client-b",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "s",
							allowedRedirectUris: [],
							allowedScopes: [],
							allowedAudiences: ["billing-service", "inventory-service"],
						},
					],
				]),
			);
			const client = await repo.findById("client-b");
			expect(client?.allowedAudiences).toEqual(["billing-service", "inventory-service"]);
		});

		it("exposes allowedAudiences via authenticate() (also propagates on auth path)", async () => {
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"client-c",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "correct-horse-battery-staple",
							allowedRedirectUris: [],
							allowedScopes: [],
							allowedAudiences: ["payment-service"],
						},
					],
				]),
			);
			const client = await repo.authenticate("client-c", "correct-horse-battery-staple");
			expect(client?.allowedAudiences).toEqual(["payment-service"]);
		});
	});

	describe("allowedGrantTypes field round-trip (Wave 1 §3.4.1)", () => {
		it("findById omits allowedGrantTypes when the entry has none", async () => {
			// Preserve the undefined-vs-empty distinction: when the operator did
			// not configure the field, the resolved PublicClient must surface
			// `allowedGrantTypes === undefined` so deny-by-absence-for-cc applies.
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"cc-client-a",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "s",
							allowedRedirectUris: [],
							allowedScopes: [],
						},
					],
				]),
			);
			const client = await repo.findById("cc-client-a");
			expect(client?.allowedGrantTypes).toBeUndefined();
		});

		it("findById preserves a configured allowedGrantTypes list", async () => {
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"cc-client-b",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "s",
							allowedRedirectUris: [],
							allowedScopes: [],
							allowedGrantTypes: ["client_credentials", "refresh_token"],
						},
					],
				]),
			);
			const client = await repo.findById("cc-client-b");
			expect(client?.allowedGrantTypes).toEqual(["client_credentials", "refresh_token"]);
		});

		it("authenticate() propagates allowedGrantTypes on the auth path", async () => {
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"cc-client-c",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "correct-horse-battery-staple",
							allowedRedirectUris: [],
							allowedScopes: [],
							allowedGrantTypes: ["client_credentials"],
						},
					],
				]),
			);
			const client = await repo.authenticate("cc-client-c", "correct-horse-battery-staple");
			expect(client?.allowedGrantTypes).toEqual(["client_credentials"]);
		});

		it("findById preserves an empty allowedGrantTypes list (deny-all signal)", async () => {
			// `[]` is semantically distinct from `undefined`: it explicitly denies
			// all grants for this client. The repository must NOT collapse it to
			// undefined.
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"cc-client-d",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "s",
							allowedRedirectUris: [],
							allowedScopes: [],
							allowedGrantTypes: [],
						},
					],
				]),
			);
			const client = await repo.findById("cc-client-d");
			expect(client?.allowedGrantTypes).toEqual([]);
		});
	});

	describe("authenticate", () => {
		it("returns client with correct plain text secret", async () => {
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"my-client",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "plain-secret",
							allowedRedirectUris: [],
							allowedScopes: [],
						},
					],
				]),
			);
			const client = await repo.authenticate("my-client", "plain-secret");
			expect(client).not.toBeNull();
			expect(client?.clientId).toBe("my-client");
			expect(client).not.toHaveProperty("clientSecret");
		});

		it("returns null with wrong plain text secret", async () => {
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"my-client",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "plain-secret",
							allowedRedirectUris: [],
							allowedScopes: [],
						},
					],
				]),
			);
			const client = await repo.authenticate("my-client", "wrong-secret");
			expect(client).toBeNull();
		});

		it("returns null for nonexistent client", async () => {
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"my-client",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "plain-secret",
							allowedRedirectUris: [],
							allowedScopes: [],
						},
					],
				]),
			);
			const client = await repo.authenticate("ghost-client", "plain-secret");
			expect(client).toBeNull();
		});

		it("returns client with correct bcrypt secret", async () => {
			const realHash = bcrypt.hashSync("my-secret", 10);
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"bcrypt-client",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: realHash,
							allowedRedirectUris: [],
							allowedScopes: [],
						},
					],
				]),
			);
			const client = await repo.authenticate("bcrypt-client", "my-secret");
			expect(client).not.toBeNull();
			expect(client?.clientId).toBe("bcrypt-client");
		});

		it("returns null with wrong bcrypt secret", async () => {
			const realHash = bcrypt.hashSync("my-secret", 10);
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"bcrypt-client",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: realHash,
							allowedRedirectUris: [],
							allowedScopes: [],
						},
					],
				]),
			);
			const client = await repo.authenticate("bcrypt-client", "wrong-secret");
			expect(client).toBeNull();
		});
	});

	// D-6 (v0.5.1): tokenEndpointAuthMethod discriminator + ClientEntrySchema
	// superRefine. The schema is now the single source of truth for whether a
	// client is confidential (basic/post — secret required) or public (none —
	// secret forbidden). Historically these tests would have been split between
	// ClientEntrySchema and InMemoryClientRepository, but the schema is invoked
	// from the constructor so both surfaces share the same RED tests.
	describe("D-6 tokenEndpointAuthMethod discriminator (RED Group A)", () => {
		it("A-1: client_secret_basic without clientSecret throws at construction", () => {
			expect(
				() =>
					new InMemoryClientRepository(
						new Map([
							[
								"missing-secret",
								{
									tokenEndpointAuthMethod: "client_secret_basic",
									allowedRedirectUris: [],
									allowedScopes: [],
								},
							],
						]),
					),
			).toThrow(/clientSecret is required/);
		});

		it("A-1b: client_secret_post without clientSecret throws at construction", () => {
			expect(
				() =>
					new InMemoryClientRepository(
						new Map([
							[
								"missing-secret-post",
								{
									tokenEndpointAuthMethod: "client_secret_post",
									allowedRedirectUris: [],
									allowedScopes: [],
								},
							],
						]),
					),
			).toThrow(/clientSecret is required/);
		});

		it("A-2: tokenEndpointAuthMethod=none with clientSecret throws", () => {
			expect(
				() =>
					new InMemoryClientRepository(
						new Map([
							[
								"public-with-secret",
								{
									tokenEndpointAuthMethod: "none",
									clientSecret: "secret",
									allowedRedirectUris: [],
									allowedScopes: [],
								},
							],
						]),
					),
			).toThrow(/clientSecret must not be set/);
		});

		it("A-3: tokenEndpointAuthMethod=none without clientSecret succeeds", () => {
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"public-spa",
						{
							tokenEndpointAuthMethod: "none",
							allowedRedirectUris: ["https://app.example/cb"],
							allowedScopes: ["openid"],
						},
					],
				]),
			);
			expect(repo).toBeDefined();
		});

		it("A-4: authenticate() on a public client returns null (does not throw)", async () => {
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"public-spa",
						{
							tokenEndpointAuthMethod: "none",
							allowedRedirectUris: ["https://app.example/cb"],
							allowedScopes: ["openid"],
						},
					],
				]),
			);
			// Public clients have no secret. `authenticate()` MUST return null
			// rather than throwing, so the timing surface stays uniform with the
			// "wrong secret" path (which also returns null).
			const result = await repo.authenticate("public-spa", "any-fake-secret");
			expect(result).toBeNull();
		});

		it("A-5: findById() returns tokenEndpointAuthMethod on the PublicClient projection", async () => {
			const repo = new InMemoryClientRepository(
				new Map([
					[
						"basic-rp",
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: "s",
							allowedRedirectUris: [],
							allowedScopes: [],
						},
					],
					[
						"post-rp",
						{
							tokenEndpointAuthMethod: "client_secret_post",
							clientSecret: "s",
							allowedRedirectUris: [],
							allowedScopes: [],
						},
					],
					[
						"public-rp",
						{
							tokenEndpointAuthMethod: "none",
							allowedRedirectUris: [],
							allowedScopes: [],
						},
					],
				]),
			);
			expect((await repo.findById("basic-rp"))?.tokenEndpointAuthMethod).toBe(
				"client_secret_basic",
			);
			expect((await repo.findById("post-rp"))?.tokenEndpointAuthMethod).toBe("client_secret_post");
			expect((await repo.findById("public-rp"))?.tokenEndpointAuthMethod).toBe("none");
		});

		it("A-6: omitted tokenEndpointAuthMethod throws at construction (no silent default)", () => {
			expect(
				() =>
					new InMemoryClientRepository(
						new Map([
							[
								"unspecified",
								{
									clientSecret: "secret",
									allowedRedirectUris: [],
									allowedScopes: [],
									// biome-ignore lint/suspicious/noExplicitAny: deliberately bypass the type system to verify runtime defence
								} as any,
							],
						]),
					),
			).toThrow();
		});
	});
});
