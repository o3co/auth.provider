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
	type RefreshTokenFamilyRotation,
	type SessionFamilyIndex,
	type SessionRPRegistry,
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
			authorization_code: { enabled: true },
			refresh_token: { enabled: true },
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

function makeSessionFamilyIndex(override?: Partial<SessionFamilyIndex>): SessionFamilyIndex {
	return {
		kind: "memory",
		addFamilyId: vi.fn(async () => {}),
		listFamilyIds: vi.fn(async () => []),
		removeBySid: vi.fn(async () => {}),
		...override,
	} as SessionFamilyIndex;
}

function makeSessionRPRegistry(override?: Partial<SessionRPRegistry>): SessionRPRegistry {
	return {
		kind: "memory",
		registerRP: vi.fn(async () => {}),
		listRPs: vi.fn(async () => []),
		removeBySid: vi.fn(async () => {}),
		...override,
	} as SessionRPRegistry;
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
			const deps = makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "test-sid-1" }));
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

		it("registers initial rt+jwt via refreshTokenFamilyRotation.register (CP-2)", async () => {
			const registerSpy = vi.fn(async () => {});
			const refreshTokenFamilyRotation: RefreshTokenFamilyRotation = {
				register: registerSpy,
				rotate: vi.fn(async () => ({ outcome: "rotated" as const })),
			};
			const deps = {
				...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "test-sid-1" })),
				refreshTokenFamilyRotation,
			};
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
			expect(registerSpy).toHaveBeenCalledTimes(1);
			const [newJti, familyId, expiresAtMs] = registerSpy.mock.calls[0] as unknown as [
				string,
				string,
				number,
			];
			expect(typeof newJti).toBe("string");
			expect(newJti.length).toBeGreaterThan(0);
			expect(familyId).toMatch(
				/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
			);
			expect(typeof expiresAtMs).toBe("number");
			expect(expiresAtMs).toBeGreaterThan(Date.now());
		});

		it("returns 503 temporarily_unavailable when refreshTokenFamilyRotation.register throws (CP-16)", async () => {
			const throwingRotation: RefreshTokenFamilyRotation = {
				register: async () => {
					throw new Error("store down");
				},
				rotate: vi.fn(async () => ({ outcome: "rotated" as const })),
			};
			const deps = {
				...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "test-sid-1" })),
				refreshTokenFamilyRotation: throwingRotation,
			};
			const handler = createAuthorizationGrant(deps);

			const { result } = await handler.handle({
				body: { code: "abc", client_id: "client1" },
				session: {
					code: "abc",
					code_client_id: "client1",
					granted_scopes: ["read"],
					user: { id: "u1" },
				},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			});

			expect(result.status).toBe(503);
			if (!("error" in result)) throw new Error("expected error");
			expect(result.error).toBe("temporarily_unavailable");
		});

		it("skips initial-register when no refreshTokenFamilyRotation is configured (CP-2 graceful)", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "test-sid-1" }));
			const handler = createAuthorizationGrant(deps);
			const { result } = await handler.handle({
				body: { code: "abc", client_id: "client1" },
				session: {
					code: "abc",
					code_client_id: "client1",
					granted_scopes: ["read"],
					user: { id: "u1" },
				},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			});
			expect(result.status).toBe(200);
		});

		it("issues an initial rt+jwt carrying a new family_id (C-3)", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "test-sid-1" }));
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

		it("omits scope from token response when granted scopes is empty (CP-12)", async () => {
			// Code has neither grantedScope nor session.granted_scopes.
			const deps = makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "test-sid-1" }));
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1" },
				session: {
					code: "abc",
					code_client_id: "client1",
					// granted_scopes intentionally omitted
					user: { id: "u1" },
				},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			if (!("tokens" in result)) throw new Error("expected tokens");
			// Response must NOT carry scope: ""; it should be undefined / omitted
			expect(result.tokens.scope === "" ? "empty-string" : "ok").toBe("ok");
			const decoded = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
			expect(decoded.scope).toBeUndefined();
		});

		it("omits scope when Code.grantedScope is explicitly empty (CP-12)", async () => {
			// Even if persisted as [], code exchange must not emit `scope: ""`.
			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					sid: "test-sid-1",
					grantedScope: [] as readonly string[],
				}),
			);
			const handler = createAuthorizationGrant(deps);
			const { result } = await handler.handle({
				body: { code: "abc", client_id: "client1" },
				session: {
					code: "abc",
					code_client_id: "client1",
					granted_scopes: ["read"],
					user: { id: "u1" },
				},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			});
			expect(result.status).toBe(200);
			if (!("tokens" in result)) throw new Error("expected tokens");
			const decoded = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
			expect(decoded.scope).toBeUndefined();
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
					sid: "test-sid-1",
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
					sid: "test-sid-1",
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
						authorization_code: {
							enabled: true,
							pkce: { requireS256: true },
						},
						refresh_token: { enabled: true },
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
							sid: "test-sid-1",
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
						sid: "test-sid-1",
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
						sid: "test-sid-1",
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
				const deps = makeDeps(
					vi.fn().mockResolvedValue({ code: "abc", sid: "test-sid-1" }),
					clientRepo,
				);
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
				const deps = makeDeps(
					vi.fn().mockResolvedValue({ code: "abc", sid: "test-sid-1" }),
					clientRepo,
				);
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
							authorization_code: {
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
							sid: "test-sid-1",
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

		describe("TODO-F-4: id_token issuance on openid scope", () => {
			// F-4 reads config.oauth.jwt.issuer directly (not ctx.issuer) for
			// id_token issuance to avoid using the request-derived host fallback
			// as an OIDC iss claim. Tests must supply a configured issuer.
			const mockConfigWithIssuer = {
				oauth: {
					jwt: { secret: "test-secret", issuer: "https://auth.example.com" },
					accessToken: { expiresIn: 3600 },
					refreshToken: { expiresIn: 86400 },
					grants: {
						session: { enabled: true },
						authorization_code: { enabled: true },
						refresh_token: { enabled: true },
					},
				},
			} as unknown as GrantDependencies["config"];

			function makeDepsWithIssuer(
				consumeByCodeImpl: CodeRepository["consumeByCode"],
				clientRepository?: ClientRepository,
			) {
				return {
					config: mockConfigWithIssuer,
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

			function makeUserSessionStore(session: {
				sid: string;
				sub: string;
				authTime: Date;
				claims: Record<string, unknown>;
			}) {
				return {
					kind: "spy",
					async create() {},
					async get(querySid: string) {
						if (querySid !== session.sid) return null;
						return {
							sid: session.sid,
							sub: session.sub,
							authTime: session.authTime,
							createdAt: new Date(),
							expiresAt: new Date(Date.now() + 3600_000),
							claims: session.claims,
						};
					},
					async delete() {},
				};
			}

			it("includes id_token in response when scope contains 'openid' and userSessionStore is wired (F-4-1)", async () => {
				const authTime = new Date("2026-04-21T00:00:00Z");
				const userSessionStore = makeUserSessionStore({
					sid: "sid-1",
					sub: "u-1",
					authTime,
					claims: { email: "a@b.com", emailVerified: true, name: "Alice" },
				});
				const deps = {
					...makeDepsWithIssuer(
						vi.fn().mockResolvedValue({
							code: "c1",
							sid: "sid-1",
							nonce: "client-nonce",
							grantedScope: ["openid", "email"],
						}),
					),
					userSessionStore,
					sessionFamilyIndex: makeSessionFamilyIndex(),
					sessionRPRegistry: makeSessionRPRegistry(),
				};
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: { code: "c1", client_id: "client1" },
					session: { code: "c1", code_client_id: "client1" },
					issuer: "https://auth.example.com",
					metadata: { ip: "127.0.0.1" },
				});

				expect(result.status).toBe(200);
				if (!("tokens" in result)) throw new Error("expected tokens");
				const idTokenStr = result.tokens.id_token;
				if (typeof idTokenStr !== "string") throw new Error("expected id_token string");

				const idPayload = decodeJwt(idTokenStr) as Record<string, unknown>;
				expect(idPayload.iss).toBe("https://auth.example.com");
				expect(idPayload.sub).toBe("u-1");
				expect(idPayload.aud).toBe("client1");
				expect(idPayload.azp).toBe("client1");
				expect(idPayload.sid).toBe("sid-1");
				expect(idPayload.nonce).toBe("client-nonce");
				expect(idPayload.email).toBe("a@b.com");
				// profile scope not granted — name must NOT appear
				expect(idPayload.name).toBeUndefined();
			});

			it("does NOT include id_token when issuer is absent (avoids OIDC-noncompliant iss:'')", async () => {
				const authTime = new Date("2026-04-21T00:00:00Z");
				const userSessionStore = makeUserSessionStore({
					sid: "sid-noiss",
					sub: "u-noiss",
					authTime,
					claims: { email: "c@b.com", emailVerified: true },
				});
				const deps = {
					...makeDeps(
						vi.fn().mockResolvedValue({
							code: "c-noiss",
							sid: "sid-noiss",
							grantedScope: ["openid", "email"],
							nonce: "client-nonce",
						}),
					),
					userSessionStore,
					sessionFamilyIndex: makeSessionFamilyIndex(),
					sessionRPRegistry: makeSessionRPRegistry(),
				};
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: { code: "c-noiss", client_id: "client1" },
					session: { code: "c-noiss", code_client_id: "client1" },
					// issuer intentionally omitted
					metadata: { ip: "127.0.0.1" },
				});

				expect(result.status).toBe(200);
				if (!("tokens" in result)) throw new Error("expected tokens");
				expect(typeof result.tokens.access_token).toBe("string");
				expect(result.tokens.id_token).toBeUndefined();
			});

			it("does NOT include id_token when scope lacks openid (F-4-2)", async () => {
				const authTime = new Date("2026-04-21T00:00:00Z");
				const userSessionStore = makeUserSessionStore({
					sid: "sid-2",
					sub: "u-2",
					authTime,
					claims: { email: "b@b.com", emailVerified: true, name: "Bob" },
				});
				const deps = {
					...makeDepsWithIssuer(
						vi.fn().mockResolvedValue({
							code: "c2",
							sid: "sid-2",
							grantedScope: ["profile", "email"],
						}),
					),
					userSessionStore,
					sessionFamilyIndex: makeSessionFamilyIndex(),
					sessionRPRegistry: makeSessionRPRegistry(),
				};
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: { code: "c2", client_id: "client1" },
					session: { code: "c2", code_client_id: "client1" },
					issuer: "https://auth.example.com",
					metadata: { ip: "127.0.0.1" },
				});

				expect(result.status).toBe(200);
				if (!("tokens" in result)) throw new Error("expected tokens");
				expect(typeof result.tokens.access_token).toBe("string");
				expect(result.tokens.id_token).toBeUndefined();
			});

			it("does NOT include id_token when userSessionStore is not wired (backward compat, F-4-3)", async () => {
				// No userSessionStore — cannot resolve claims, so id_token is skipped.
				const deps = makeDepsWithIssuer(
					vi.fn().mockResolvedValue({
						code: "c3",
						sid: "sid-3",
						grantedScope: ["openid"],
					}),
				);
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: { code: "c3", client_id: "client1" },
					session: { code: "c3", code_client_id: "client1" },
					issuer: "https://auth.example.com",
					metadata: { ip: "127.0.0.1" },
				});

				expect(result.status).toBe(200);
				if (!("tokens" in result)) throw new Error("expected tokens");
				expect(typeof result.tokens.access_token).toBe("string");
				expect(result.tokens.id_token).toBeUndefined();
			});
		});

		describe("TODO-F-3: family_id + sid claims, RP registration", () => {
			it("happy path: access_token and refresh_token both carry family_id and sid claims (F-3-1)", async () => {
				const deps = makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "session-abc" }));
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: { code: "abc", client_id: "client1" },
					session: {
						code: "abc",
						code_client_id: "client1",
						granted_scopes: ["read"],
						user: { id: "u1" },
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				});

				expect(result.status).toBe(200);
				if (!("tokens" in result)) throw new Error("expected tokens");

				const decodedAt = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
				expect(typeof decodedAt.family_id).toBe("string");
				expect(decodedAt.family_id as string).toMatch(
					/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
				);
				expect(decodedAt.sid).toBe("session-abc");

				const refreshToken = result.tokens.refresh_token;
				if (typeof refreshToken !== "string") throw new Error("expected refresh_token string");
				const decodedRt = decodeJwt(refreshToken) as Record<string, unknown>;
				expect(decodedRt.family_id).toBe(decodedAt.family_id);
				expect(decodedRt.sid).toBe("session-abc");
			});

			it("returns 400 invalid_grant when code record has no sid and userSessionStore IS wired (F-3-2)", async () => {
				// Code was issued before Task 2 login wiring — sid missing.
				// When the store is wired, sid is required so the store can link/register.
				const userSessionStore = {
					kind: "spy",
					async create() {},
					async get() {
						return null;
					},
					async delete() {},
				};
				const deps = {
					...makeDeps(vi.fn().mockResolvedValue({ code: "abc" /* no sid */ })),
					userSessionStore,
				};
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: { code: "abc", client_id: "client1" },
					session: {
						code: "abc",
						code_client_id: "client1",
						user: { id: "u1" },
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				});

				expect(result.status).toBe(400);
				if (!("error" in result)) throw new Error("expected error");
				expect(result.error).toBe("invalid_grant");
				expect((result as { errorDescription?: string }).errorDescription).toMatch(/sid/);
			});

			it("backward compat — no userSessionStore + no sid → grant succeeds without sid claim (F-3-2-compat)", async () => {
				// Deployments that have not wired userSessionStore do not write sid at login
				// time and must continue to work. No store → sid not required.
				const deps = makeDeps(vi.fn().mockResolvedValue({ code: "abc" /* no sid */ }));
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: { code: "abc", client_id: "client1" },
					session: {
						code: "abc",
						code_client_id: "client1",
						granted_scopes: ["read"],
						user: { id: "u1" },
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				});

				expect(result.status).toBe(200);
				if (!("tokens" in result)) throw new Error("expected tokens");
				const decoded = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
				// family_id is always present; sid must NOT appear when it was never set
				expect(typeof decoded.family_id).toBe("string");
				expect(Object.hasOwn(decoded, "sid")).toBe(false);
			});

			it("calls addFamilyId and registerRP on sibling stores when userSessionStore is wired (F-3-3)", async () => {
				const sessionExpiresAt = new Date(Date.now() + 3600_000);
				const addFamilyIdSpy = vi.fn(async (_sid: string, _fam: string, _exp: Date) => {});
				const registerRPSpy = vi.fn(async (_sid: string, _rp: unknown, _exp: Date) => {});
				const userSessionStore = {
					kind: "spy",
					async create() {},
					async get() {
						// Return a minimal session so the existence check passes.
						// expiresAt is captured as sessionExpiresAt for assertion below.
						return {
							sid: "session-xyz",
							sub: "u1",
							authTime: new Date(),
							createdAt: new Date(),
							expiresAt: sessionExpiresAt,
							claims: {},
						};
					},
					async delete() {},
				};
				const sessionFamilyIndex = makeSessionFamilyIndex({ addFamilyId: addFamilyIdSpy });
				const sessionRPRegistry = makeSessionRPRegistry({ registerRP: registerRPSpy });
				const deps = {
					...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "session-xyz" })),
					userSessionStore,
					sessionFamilyIndex,
					sessionRPRegistry,
				};
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: { code: "abc", client_id: "client1" },
					session: {
						code: "abc",
						code_client_id: "client1",
						granted_scopes: ["read"],
						user: { id: "u1" },
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				});

				expect(result.status).toBe(200);
				expect(addFamilyIdSpy).toHaveBeenCalledTimes(1);
				const [sidArg, familyIdArg, expiresAtArg] = addFamilyIdSpy.mock.calls[0] as [
					string,
					string,
					Date,
				];
				expect(sidArg).toBe("session-xyz");
				expect(familyIdArg).toMatch(
					/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
				);
				// Per A4 §5.3 TTL contract: expiresAt MUST be passed from session.expiresAt
				expect(expiresAtArg).toBe(sessionExpiresAt);
				expect(registerRPSpy).toHaveBeenCalledTimes(1);
				const [rpSid, rpData, rpExpiresAt] = registerRPSpy.mock.calls[0] as [
					string,
					Record<string, unknown>,
					Date,
				];
				expect(rpSid).toBe("session-xyz");
				expect(rpData.clientId).toBe("client1");
				expect(rpData.registeredAt).toBeInstanceOf(Date);
				// Per A4 §5.2 TTL contract: expiresAt MUST match session.expiresAt
				expect(rpExpiresAt).toBe(sessionExpiresAt);
			});

			it("backward compat: issues tokens without userSessionStore (F-3-4)", async () => {
				// No userSessionStore in deps — grant must succeed without linkFamily/registerRP.
				const deps = makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "session-abc" }));
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: { code: "abc", client_id: "client1" },
					session: {
						code: "abc",
						code_client_id: "client1",
						granted_scopes: ["read"],
						user: { id: "u1" },
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				});

				expect(result.status).toBe(200);
				if (!("tokens" in result)) throw new Error("expected tokens");
				// Tokens must still carry family_id and sid even without a session store.
				const decoded = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
				expect(typeof decoded.family_id).toBe("string");
				expect(decoded.sid).toBe("session-abc");
			});

			it("returns 400 invalid_grant session_invalid when session was deleted between /authorize and /token (F-3-I1)", async () => {
				// Session deleted after /authorize was issued — get(sid) returns null.
				const userSessionStore = {
					kind: "spy",
					async create() {},
					async get() {
						return null; // session gone
					},
					async delete() {},
				};
				const deps = {
					...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "session-gone" })),
					userSessionStore,
				};
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: { code: "abc", client_id: "client1" },
					session: {
						code: "abc",
						code_client_id: "client1",
						granted_scopes: ["read"],
						user: { id: "u1" },
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				});

				expect(result.status).toBe(400);
				if (!("error" in result)) throw new Error("expected error");
				expect(result.error).toBe("invalid_grant");
				expect((result as { errorDescription?: string }).errorDescription).toMatch(/session/i);
			});

			it("returns 503 temporarily_unavailable when userSessionStore.get throws (F-3-I1-503)", async () => {
				// Store is wired but unavailable when get() is called.
				const userSessionStore = {
					kind: "broken",
					async create() {},
					async get() {
						throw new Error("store down");
					},
					async delete() {},
				};
				const deps = {
					...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "session-abc" })),
					userSessionStore,
				};
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: { code: "abc", client_id: "client1" },
					session: {
						code: "abc",
						code_client_id: "client1",
						granted_scopes: ["read"],
						user: { id: "u1" },
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				});

				expect(result.status).toBe(503);
				if (!("error" in result)) throw new Error("expected error");
				expect(result.error).toBe("temporarily_unavailable");
			});

			it("returns 503 temporarily_unavailable when clientRepository.findById throws (F-3-I2)", async () => {
				// findById is now inside the try/catch — a throw must produce a controlled 503.
				const throwingClientRepo: ClientRepository = {
					findById: vi.fn().mockRejectedValue(new Error("db down")),
					authenticate: vi.fn().mockResolvedValue(null),
				};
				const userSessionStore = {
					kind: "spy",
					async create() {},
					async get() {
						return {
							sid: "session-abc",
							sub: "u1",
							authTime: new Date(),
							createdAt: new Date(),
							expiresAt: new Date(Date.now() + 3600_000),
							claims: {},
						};
					},
					async delete() {},
				};
				const deps = {
					...makeDeps(
						vi.fn().mockResolvedValue({ code: "abc", sid: "session-abc" }),
						throwingClientRepo,
					),
					userSessionStore,
					sessionFamilyIndex: makeSessionFamilyIndex(),
					sessionRPRegistry: makeSessionRPRegistry(),
				};
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: { code: "abc", client_id: "client1" },
					session: {
						code: "abc",
						code_client_id: "client1",
						granted_scopes: ["read"],
						user: { id: "u1" },
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				});

				expect(result.status).toBe(503);
				if (!("error" in result)) throw new Error("expected error");
				expect(result.error).toBe("temporarily_unavailable");
			});
		});
	});
});
