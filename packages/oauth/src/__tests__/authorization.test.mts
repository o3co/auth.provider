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
import crypto from "node:crypto";
import {
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantDependencies,
} from "@o3co/auth-provider-core";
import { decodeJwt } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";

const mockConfig = {
	oauth: {
		jwt: { secret: "test-secret" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {
			session: { enabled: true },
			authorization: { enabled: true },
			refresh_token: { enabled: true },
			did: { enabled: true, messageMaxAgeSec: 300 },
		},
	},
} as unknown as GrantDependencies["config"];

const mockClientRepository: ClientRepository = {
	findById: vi.fn().mockResolvedValue(null),
	authenticate: vi.fn().mockResolvedValue(null),
};

function makeDeps(
	consumeByCodeImpl: CodeRepository["consumeByCode"],
	clientRepository?: ClientRepository,
) {
	return {
		config: mockConfig,
		keyStore: createSymmetricKeyStore("test-secret"),
		codeRepository: {
			consumeByCode: consumeByCodeImpl,
			createCode: vi.fn(),
			getByCode: vi.fn(),
			removeByCode: vi.fn(),
		} as unknown as CodeRepository,
		clientRepository: clientRepository ?? mockClientRepository,
	};
}

describe("createAuthorizationGrant", () => {
	describe("handle", () => {
		it("returns 400 when code is missing", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue({ code: "abc", code_challenge: undefined }));
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { client_id: "client1" },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			expect("error" in result).toBe(true);
		});

		it("returns 400 when code does not match session code", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue(null));
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "wrong-code", client_id: "client1" },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 400 when client_id does not match session code_client_id", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue(null));
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "wrong-client" },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 400 when codeRepository.consumeByCode returns null", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue(null));
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1" },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 200 with access and refresh tokens on valid code exchange (no PKCE)", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue({ code: "abc" }));
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1" },
				session: {
					code: "abc",
					code_client_id: "client1",
					granted_scopes: ["read"],
					user: { id: "u1" },
				},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result, sessionMutation } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				expect(result.tokens.access_token).toBeDefined();
				expect(result.tokens.refresh_token).toBeDefined();
				const decoded = decodeJwt(result.tokens.access_token);
				expect(decoded.sub).toBe("u1");
				expect((decoded as Record<string, unknown>).azp).toBe("client1");
			}
			// Session must be cleared
			expect(sessionMutation).toBeDefined();
			expect(sessionMutation?.clear).toContain("code");
			expect(sessionMutation?.clear).toContain("code_client_id");
			expect(sessionMutation?.clear).toContain("granted_scopes");
		});

		it("issues an initial rt+jwt carrying a new family_id (C-3)", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue({ code: "abc" }));
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1" },
				session: {
					code: "abc",
					code_client_id: "client1",
					granted_scopes: ["read"],
					user: { id: "u1" },
				},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			if (!("tokens" in result)) throw new Error("expected tokens");
			const refreshToken = result.tokens.refresh_token;
			if (typeof refreshToken !== "string") throw new Error("expected refresh_token string");
			const decoded = decodeJwt(refreshToken) as Record<string, unknown>;
			expect(typeof decoded.family_id).toBe("string");
			// UUID v4 shape: 8-4-4-4-12 hex, version nibble = 4
			expect(decoded.family_id as string).toMatch(
				/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
			);
		});

		it("returns 400 when PKCE is required but code_verifier is missing", async () => {
			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					code_challenge: "challenge",
					code_challenge_method: "S256",
				}),
			);
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1" },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 400 when code_verifier has invalid format", async () => {
			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					code_challenge: "challenge",
					code_challenge_method: "S256",
				}),
			);
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1", code_verifier: "too-short" },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 400 when S256 code_verifier does not match challenge", async () => {
			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					code_challenge: "wrong-challenge",
					code_challenge_method: "S256",
				}),
			);
			const handler = createAuthorizationGrant(deps);
			// Valid format verifier that won't match the challenge
			const verifier = "a".repeat(43);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1", code_verifier: verifier },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 200 when S256 PKCE code_verifier is valid", async () => {
			const verifier = "a".repeat(43);
			const hash = crypto.createHash("sha256").update(verifier).digest();
			const challenge = hash.toString("base64url");

			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					code_challenge: challenge,
					code_challenge_method: "S256",
				}),
			);
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1", code_verifier: verifier },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
		});

		it("returns 200 when plain PKCE code_verifier matches challenge", async () => {
			const verifier = "b".repeat(43);
			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					code_challenge: verifier,
					code_challenge_method: "plain",
				}),
			);
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1", code_verifier: verifier },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
		});

		describe("requireS256 config option (legacy)", () => {
			const s256Config = {
				oauth: {
					jwt: { secret: "test-secret" },
					accessToken: { expiresIn: 3600 },
					refreshToken: { expiresIn: 86400 },
					grants: {
						session: { enabled: true },
						authorization: {
							enabled: true,
							pkce: { requireS256: true },
						},
						refresh_token: { enabled: true },
						did: { enabled: true, messageMaxAgeSec: 300 },
					},
				},
			} as unknown as GrantDependencies["config"];

			it("returns 400 when requireS256=true and plain method is used", async () => {
				const verifier = "b".repeat(43);
				const deps = {
					config: s256Config,
					keyStore: createSymmetricKeyStore("test-secret"),
					codeRepository: {
						consumeByCode: vi.fn().mockResolvedValue({
							code: "abc",
							code_challenge: verifier,
							code_challenge_method: "plain",
						}),
						createCode: vi.fn(),
						getByCode: vi.fn(),
						removeByCode: vi.fn(),
					} as unknown as CodeRepository,
					clientRepository: mockClientRepository,
				};
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: { code: "abc", client_id: "client1", code_verifier: verifier },
					session: { code: "abc", code_client_id: "client1" },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(400);
				expect("error" in result && result.error).toBe("invalid_request");
			});

			it("returns 200 when requireS256=true and S256 method is used", async () => {
				const verifier = "a".repeat(43);
				const hash = crypto.createHash("sha256").update(verifier).digest();
				const challenge = hash.toString("base64url");

				const deps = {
					config: s256Config,
					keyStore: createSymmetricKeyStore("test-secret"),
					codeRepository: {
						consumeByCode: vi.fn().mockResolvedValue({
							code: "abc",
							code_challenge: challenge,
							code_challenge_method: "S256",
						}),
						createCode: vi.fn(),
						getByCode: vi.fn(),
						removeByCode: vi.fn(),
					} as unknown as CodeRepository,
					clientRepository: mockClientRepository,
				};
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: { code: "abc", client_id: "client1", code_verifier: verifier },
					session: { code: "abc", code_client_id: "client1" },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(200);
			});
		});

		describe("A-2: redirect_uri binding", () => {
			it("returns invalid_grant when stored redirect_uri does not match body redirect_uri", async () => {
				const deps = makeDeps(
					vi.fn().mockResolvedValue({
						code: "abc",
						redirect_uri: "https://example.com/callback",
					}),
				);
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: { code: "abc", client_id: "client1", redirect_uri: "https://evil.com/callback" },
					session: {
						code: "abc",
						code_client_id: "client1",
						code_redirect_uri: "https://example.com/callback",
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(400);
				expect("error" in result && result.error).toBe("invalid_grant");
			});

			it("returns invalid_grant when redirect_uri was stored but omitted in token request", async () => {
				const deps = makeDeps(
					vi.fn().mockResolvedValue({
						code: "abc",
						redirect_uri: "https://example.com/callback",
					}),
				);
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: { code: "abc", client_id: "client1" },
					session: {
						code: "abc",
						code_client_id: "client1",
						code_redirect_uri: "https://example.com/callback",
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(400);
				expect("error" in result && result.error).toBe("invalid_grant");
			});

			it("returns 200 when redirect_uri matches stored value", async () => {
				const deps = makeDeps(
					vi.fn().mockResolvedValue({
						code: "abc",
						redirect_uri: "https://example.com/callback",
					}),
				);
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: { code: "abc", client_id: "client1", redirect_uri: "https://example.com/callback" },
					session: {
						code: "abc",
						code_client_id: "client1",
						code_redirect_uri: "https://example.com/callback",
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(200);
			});

			it("returns 200 when no redirect_uri was stored (redirect_uri not required in authorize)", async () => {
				const deps = makeDeps(
					vi.fn().mockResolvedValue({
						code: "abc",
					}),
				);
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: { code: "abc", client_id: "client1" },
					session: { code: "abc", code_client_id: "client1" },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(200);
			});
		});

		describe("A-3: client secret verification", () => {
			it("returns invalid_client when client_secret is wrong for a confidential client", async () => {
				const clientRepo: ClientRepository = {
					findById: vi.fn().mockResolvedValue({
						clientId: "client1",
						allowedRedirectUris: [],
						allowedScopes: [],
					}),
					authenticate: vi.fn().mockResolvedValue(null), // secret mismatch
				};
				const deps = makeDeps(vi.fn().mockResolvedValue({ code: "abc" }), clientRepo);
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: { code: "abc", client_id: "client1", client_secret: "wrong-secret" },
					session: { code: "abc", code_client_id: "client1" },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(401);
				expect("error" in result && result.error).toBe("invalid_client");
			});

			it("returns 200 when client_secret is correct", async () => {
				const clientRepo: ClientRepository = {
					findById: vi.fn().mockResolvedValue({
						clientId: "client1",
						allowedRedirectUris: [],
						allowedScopes: [],
					}),
					authenticate: vi.fn().mockResolvedValue({
						clientId: "client1",
						allowedRedirectUris: [],
						allowedScopes: [],
					}),
				};
				const deps = makeDeps(vi.fn().mockResolvedValue({ code: "abc" }), clientRepo);
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: { code: "abc", client_id: "client1", client_secret: "correct-secret" },
					session: { code: "abc", code_client_id: "client1" },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(200);
			});

			it("skips client secret check when client has no secret (public client - findById returns client but authenticate returns null with no secret provided)", async () => {
				// Public client: no client_secret in request, findById succeeds
				const clientRepo: ClientRepository = {
					findById: vi.fn().mockResolvedValue({
						clientId: "client1",
						allowedRedirectUris: [],
						allowedScopes: [],
					}),
					authenticate: vi.fn().mockResolvedValue(null),
				};
				const deps = makeDeps(vi.fn().mockResolvedValue({ code: "abc" }), clientRepo);
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: { code: "abc", client_id: "client1" }, // no client_secret
					session: { code: "abc", code_client_id: "client1" },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				};

				const { result } = await handler.handle(ctx);

				// Public client: no client_secret sent → skip verification
				expect(result.status).toBe(200);
			});
		});

		describe("B-7/B-8: pkce supportedMethods, defaultMethod, required", () => {
			function makePkceConfig(pkce: Record<string, unknown>) {
				return {
					oauth: {
						jwt: { secret: "test-secret" },
						accessToken: { expiresIn: 3600 },
						refreshToken: { expiresIn: 86400 },
						grants: {
							authorization: {
								enabled: true,
								pkce,
							},
						},
					},
				} as unknown as GrantDependencies["config"];
			}

			it("returns 400 when code_challenge_method is not in supportedMethods", async () => {
				const config = makePkceConfig({ supportedMethods: ["S256"] });
				const verifier = "b".repeat(43);
				const deps = {
					config,
					keyStore: createSymmetricKeyStore("test-secret"),
					codeRepository: {
						consumeByCode: vi.fn().mockResolvedValue({
							code: "abc",
							code_challenge: verifier,
							code_challenge_method: "plain",
						}),
						createCode: vi.fn(),
						getByCode: vi.fn(),
						removeByCode: vi.fn(),
					} as unknown as CodeRepository,
					clientRepository: mockClientRepository,
				};
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: { code: "abc", client_id: "client1", code_verifier: verifier },
					session: { code: "abc", code_client_id: "client1" },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(400);
				expect("error" in result && result.error).toBe("invalid_request");
			});

			it("returns 400 when pkce.required=true and code has no code_challenge_method", async () => {
				const config = makePkceConfig({ required: true, supportedMethods: ["S256", "plain"] });
				const deps = {
					config,
					keyStore: createSymmetricKeyStore("test-secret"),
					codeRepository: {
						consumeByCode: vi.fn().mockResolvedValue({
							code: "abc",
							// no code_challenge_method
						}),
						createCode: vi.fn(),
						getByCode: vi.fn(),
						removeByCode: vi.fn(),
					} as unknown as CodeRepository,
					clientRepository: mockClientRepository,
				};
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: { code: "abc", client_id: "client1" },
					session: { code: "abc", code_client_id: "client1" },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(400);
				expect("error" in result && result.error).toBe("invalid_request");
			});

			it("returns 200 when pkce.required=false and code has no code_challenge_method", async () => {
				const config = makePkceConfig({ required: false, supportedMethods: ["S256", "plain"] });
				const deps = {
					config,
					keyStore: createSymmetricKeyStore("test-secret"),
					codeRepository: {
						consumeByCode: vi.fn().mockResolvedValue({
							code: "abc",
							// no code_challenge_method
						}),
						createCode: vi.fn(),
						getByCode: vi.fn(),
						removeByCode: vi.fn(),
					} as unknown as CodeRepository,
					clientRepository: mockClientRepository,
				};
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: { code: "abc", client_id: "client1" },
					session: { code: "abc", code_client_id: "client1" },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(200);
			});
		});
	});
});
