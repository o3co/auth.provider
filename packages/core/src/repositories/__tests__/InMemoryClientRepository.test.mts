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
import { clientEntries } from "#/testing/index.mjs";

describe("InMemoryClientRepository", () => {
	describe("findById", () => {
		it("returns client when found", async () => {
			const repo = new InMemoryClientRepository(
				clientEntries([
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
				clientEntries([
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

		// findById exposes the configured authentication method on every
		// PublicClient projection so downstream middleware (`clientAuthMw`) and
		// grant handlers (`refreshToken`, `authorization`) can branch on it
		// without re-fetching the client record.
		it("returns tokenEndpointAuthMethod from findById", async () => {
			const repo = new InMemoryClientRepository(
				clientEntries([
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
				clientEntries([
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
				clientEntries([
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
				clientEntries([
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

	describe("federation-token opt-in field round-trip", () => {
		it("preserves allowedAzpForFederationToken when set to true", async () => {
			const repo = new InMemoryClientRepository(
				clientEntries([
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
				clientEntries([
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
				clientEntries([
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

	describe("ClientEntrySchema URL scheme allowlist", () => {
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

	// `postLogoutRedirectUris` takes the `checkRedirectUri` grammar that
	// `allowedRedirectUris` on the same record takes, not the http/https-only
	// `httpUrlSchema`: a native app whose only redirect target is a reverse-DNS
	// custom scheme registers where it is sent after logout as well as where it
	// receives the authorization response, so RP-initiated logout ends back in
	// the app rather than in a JSON body.
	describe("postLogoutRedirectUris uses the registered-redirect-URI grammar", () => {
		const baseEntry = {
			tokenEndpointAuthMethod: "client_secret_basic" as const,
			clientSecret: "secret",
			allowedRedirectUris: [],
			allowedScopes: [],
		};

		const parse = (postLogoutRedirectUris: string[]) =>
			ClientEntrySchema.safeParse({ ...baseEntry, postLogoutRedirectUris });

		it("accepts an RFC 8252 §7.1 reverse-domain custom scheme", () => {
			expect(parse(["com.example.app:/signout"]).success).toBe(true);
		});

		it("accepts the same grammar allowedRedirectUris accepts", () => {
			// One record, one vocabulary: every shape that is a legal redirect
			// target is a legal post-logout target.
			const uris = [
				"https://rp.example/logged-out",
				"http://127.0.0.1:8080/logged-out",
				"com.example.app:/signout",
				"com.example.app:signout",
			];
			expect(parse(uris).success).toBe(true);
			expect(ClientEntrySchema.safeParse({ ...baseEntry, allowedRedirectUris: uris }).success).toBe(
				true,
			);
		});

		it.each([
			["dotless custom scheme", "myapp:/signout"],
			["executable scheme", "javascript:alert(1)"],
			["dotted executable scheme", "javascript.evil:/x"],
			["data scheme", "data:text/html,<script>alert(1)</script>"],
			["fragment", "https://rp.example/logged-out#frag"],
			["userinfo", "https://user:pass@rp.example/logged-out"],
			["http off loopback", "http://rp.example/logged-out"],
			["not absolute", "/logged-out"],
		])("refuses a %s", (_label, uri) => {
			expect(parse([uri]).success).toBe(false);
		});

		it("names the field and the offending entry's position when it refuses, never the URI", () => {
			const result = parse(["javascript:alert(1)"]);
			expect(result.success).toBe(false);
			const message = result.success ? "" : (result.error.issues[0]?.message ?? "");
			expect(message).toContain("postLogoutRedirectUris[0]: ");
			expect(message).not.toContain("alert(1)");
		});

		it("leaves backchannelLogoutUri and frontchannelLogoutUri on http/https", () => {
			// Deliberately NOT widened: one is a server-side POST target and the
			// other an iframe `src`, where a custom scheme is wrong or dangerous.
			expect(
				ClientEntrySchema.safeParse({
					...baseEntry,
					backchannelLogoutUri: "com.example.app:/backchannel",
				}).success,
			).toBe(false);
			expect(
				ClientEntrySchema.safeParse({
					...baseEntry,
					frontchannelLogoutUri: "com.example.app:/frontchannel",
				}).success,
			).toBe(false);
		});
	});

	// Front-channel logout sets `iss` and `sid` on the registered URI's query:
	// a registered one would be replaced, or read by the client as this
	// server's own when no `sid` is sent.
	describe("frontchannelLogoutUri query names", () => {
		const baseEntry = {
			tokenEndpointAuthMethod: "client_secret_basic" as const,
			clientSecret: "secret",
			allowedRedirectUris: [],
			allowedScopes: [],
		};
		const parse = (frontchannelLogoutUri: string) =>
			ClientEntrySchema.safeParse({ ...baseEntry, frontchannelLogoutUri });
		const messages = (result: ReturnType<typeof parse>) =>
			result.success ? [] : result.error.issues.map((issue) => issue.message);

		it.each([
			["iss", "https://rp.example/fc?iss=x"],
			["sid", "https://rp.example/fc?sid=x"],
			["sid", "https://rp.example/fc?a=1&SID=x"],
			["iss", "https://rp.example/fc?_Iss=x"],
			["sid", "http://localhost:3000/fc?s-id"],
		])(
			"refuses a query carrying %s, naming the field and the parameter, never the URI",
			(parameter, uri) => {
				const result = parse(uri);
				expect(result.success).toBe(false);
				const found = messages(result);
				expect(
					found.some(
						(m) => m.startsWith("frontchannelLogoutUri: ") && m.includes(`"${parameter}"`),
					),
				).toBe(true);
				for (const message of found) expect(message).not.toContain("rp.example");
			},
		);

		it.each([
			"https://rp.example/fc?%73id=x",
			"https://rp.example/fc?i%73s=x",
			"https://rp.example/fc?a=1;sid=x",
			"https://rp.example/fc?=x",
		])("refuses a query name outside [A-Za-z0-9_-]: %s", (uri) => {
			const result = parse(uri);
			expect(result.success).toBe(false);
			expect(messages(result).some((m) => m.startsWith("frontchannelLogoutUri: "))).toBe(true);
		});

		it.each([
			"https://rp.example/fc",
			"https://rp.example/fc?tenant=a&state=b&code=c",
			"https://rp.example/fc?x=iss&y=sid",
			"http://localhost:3000/fc?session_id=1",
		])("accepts %s", (uri) => {
			expect(parse(uri).success).toBe(true);
		});
	});

	describe("allowedAudiences field round-trip (Token Exchange RFC 8693)", () => {
		it("exposes allowedAudiences via findById (empty array when omitted)", async () => {
			const repo = new InMemoryClientRepository(
				clientEntries([
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
				clientEntries([
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
				clientEntries([
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

	describe("allowedGrantTypes field round-trip", () => {
		it("findById omits allowedGrantTypes when the entry has none", async () => {
			// Preserve the undefined-vs-empty distinction: when the operator did
			// not configure the field, the resolved PublicClient must surface
			// `allowedGrantTypes === undefined` so deny-by-absence-for-cc applies.
			const repo = new InMemoryClientRepository(
				clientEntries([
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
				clientEntries([
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
				clientEntries([
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
				clientEntries([
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
				clientEntries([
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
				clientEntries([
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
				clientEntries([
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
				clientEntries([
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
				clientEntries([
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

	// tokenEndpointAuthMethod discriminator + ClientEntrySchema superRefine.
	// The schema is the single source of truth for whether a client is
	// confidential (basic/post — secret required) or public (none — secret
	// forbidden). The constructor parses each entry with the schema, so these
	// tests cover ClientEntrySchema and InMemoryClientRepository alike.
	describe("tokenEndpointAuthMethod discriminator", () => {
		it("client_secret_basic without clientSecret throws at construction", () => {
			expect(
				() =>
					new InMemoryClientRepository(
						clientEntries([
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

		it("client_secret_post without clientSecret throws at construction", () => {
			expect(
				() =>
					new InMemoryClientRepository(
						clientEntries([
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

		it("tokenEndpointAuthMethod=none with clientSecret throws", () => {
			expect(
				() =>
					new InMemoryClientRepository(
						clientEntries([
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

		it("tokenEndpointAuthMethod=none without clientSecret succeeds", () => {
			const repo = new InMemoryClientRepository(
				clientEntries([
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

		it("authenticate() on a public client returns null (does not throw)", async () => {
			const repo = new InMemoryClientRepository(
				clientEntries([
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

		it("findById() returns tokenEndpointAuthMethod on the PublicClient projection", async () => {
			const repo = new InMemoryClientRepository(
				clientEntries([
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

		it("omitted tokenEndpointAuthMethod throws at construction (no silent default)", () => {
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
	describe("firstParty projection", () => {
		const entry = {
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "secret",
			allowedRedirectUris: [],
			allowedScopes: [],
			firstParty: true,
			// biome-ignore lint/suspicious/noExplicitAny: fixture shorthand, parsed by the schema at construction
		} as any;

		it("findById surfaces firstParty so /authorize can admit the client", async () => {
			// Without the projection the marking is parsed and then dropped, so
			// /authorize sees an unmarked client and rejects every request.
			const repo = new InMemoryClientRepository(new Map([["first-party-rp", entry]]));
			expect((await repo.findById("first-party-rp"))?.firstParty).toBe(true);
		});

		it("authenticate surfaces firstParty too", async () => {
			const repo = new InMemoryClientRepository(new Map([["first-party-rp", entry]]));
			expect((await repo.authenticate("first-party-rp", "secret"))?.firstParty).toBe(true);
		});

		it("omits the field entirely when unmarked", async () => {
			const repo = new InMemoryClientRepository(
				// biome-ignore lint/suspicious/noExplicitAny: fixture shorthand
				new Map([["plain-rp", { ...entry, firstParty: undefined } as any]]),
			);
			const client = await repo.findById("plain-rp");
			expect(client && "firstParty" in client).toBe(false);
		});
	});

	describe("allowPlainPkce projection", () => {
		const entry = {
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "secret",
			allowedRedirectUris: [],
			allowedScopes: [],
			allowPlainPkce: true,
			// biome-ignore lint/suspicious/noExplicitAny: fixture shorthand, parsed by the schema at construction
		} as any;

		it("findById surfaces allowPlainPkce so /authorize can admit the method", async () => {
			// Dropped in the projection, the opt-in is parsed and then lost, so
			// the client is refused for a method its registration allows.
			const repo = new InMemoryClientRepository(new Map([["legacy-rp", entry]]));
			expect((await repo.findById("legacy-rp"))?.allowPlainPkce).toBe(true);
		});

		it("authenticate surfaces allowPlainPkce too — /token reads it there", async () => {
			// `/token` projects the authenticated client, not a fresh lookup, so
			// losing it here would make a code /authorize minted unredeemable.
			const repo = new InMemoryClientRepository(new Map([["legacy-rp", entry]]));
			expect((await repo.authenticate("legacy-rp", "secret"))?.allowPlainPkce).toBe(true);
		});

		it("omits the field entirely when the client did not opt in", async () => {
			const repo = new InMemoryClientRepository(
				// biome-ignore lint/suspicious/noExplicitAny: fixture shorthand
				new Map([["s256-rp", { ...entry, allowPlainPkce: undefined } as any]]),
			);
			const client = await repo.findById("s256-rp");
			expect(client && "allowPlainPkce" in client).toBe(false);
		});
	});
});
