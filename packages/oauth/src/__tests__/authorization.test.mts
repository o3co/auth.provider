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
import { pkceMethodsForClient, resolvePkceOptions } from "#/grants/pkce.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";

// D-1 / v0.5.1: codeData must carry client_id and redirect_uri (required fields).
// `body.redirect_uri` must match codeData.redirect_uri or /token rejects.
const RP_URI = "https://rp.example/cb";

// #273: PKCE is mandatory for every authorization-code client, so a redeemable
// code record always carries an S256 challenge and every token request that is
// meant to reach a non-PKCE branch has to present the matching verifier.
const CODE_VERIFIER = "pkce-verifier".padEnd(43, "x");
const S256_CHALLENGE = crypto.createHash("sha256").update(CODE_VERIFIER).digest("base64url");

const validCode = {
	client_id: "client1",
	redirect_uri: RP_URI,
	code_challenge: S256_CHALLENGE,
	code_challenge_method: "S256",
};

// D-6 (v0.5.1): the authorization grant requires `ctx.authenticatedClient` to
// be present and match `codeData.client_id`. Tests default to "client1" — the
// same client_id baked into validCode — so existing scope/PKCE/policy tests
// pass through the binding gate unchanged.
const DEFAULT_AUTH_CLIENT = {
	clientId: "client1",
	tokenEndpointAuthMethod: "client_secret_basic" as const,
};

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
			findByCode: vi.fn(),
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
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			expect("error" in result).toBe(true);
		});

		it("returns 400 when code does not match session code", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue(null));
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "wrong-code", client_id: "client1", code_verifier: CODE_VERIFIER },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 400 when client_id does not match session code_client_id", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue(null));
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "wrong-client", code_verifier: CODE_VERIFIER },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 400 when codeRepository.consumeByCode returns null", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue(null));
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: {
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
					code_verifier: CODE_VERIFIER,
				},
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 200 with access and refresh tokens on valid code exchange (no PKCE)", async () => {
			const deps = makeDeps(
				vi.fn().mockResolvedValue({ code: "abc", sid: "test-sid-1", ...validCode }),
			);
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: {
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
					code_verifier: CODE_VERIFIER,
				},
				session: {
					code: "abc",
					code_client_id: "client1",
					granted_scopes: ["read"],
					user: { id: "u1" },
				},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
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
			// D-1: only `code` remains in clear list. `code_client_id` and
			// `granted_scopes` are no longer written by /authorize, so the
			// /token grant no longer needs to clear them.
			expect(sessionMutation).toBeDefined();
			expect(sessionMutation?.clear).toContain("code");
			expect(sessionMutation?.clear).not.toContain("code_client_id");
			expect(sessionMutation?.clear).not.toContain("code_redirect_uri");
			expect(sessionMutation?.clear).not.toContain("granted_scopes");
		});

		it("registers initial rt+jwt via refreshTokenFamilyRotation.register (CP-2)", async () => {
			const registerSpy = vi.fn(async () => {});
			const refreshTokenFamilyRotation: RefreshTokenFamilyRotation = {
				register: registerSpy,
				rotate: vi.fn(async () => ({ outcome: "rotated" as const })),
			};
			const deps = {
				...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "test-sid-1", ...validCode })),
				refreshTokenFamilyRotation,
			};
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: {
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
					code_verifier: CODE_VERIFIER,
				},
				session: {
					code: "abc",
					code_client_id: "client1",
					granted_scopes: ["read"],
					user: { id: "u1" },
				},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
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
				...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "test-sid-1", ...validCode })),
				refreshTokenFamilyRotation: throwingRotation,
			};
			const handler = createAuthorizationGrant(deps);

			const { result } = await handler.handle({
				body: {
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
					code_verifier: CODE_VERIFIER,
				},
				session: {
					code: "abc",
					code_client_id: "client1",
					granted_scopes: ["read"],
					user: { id: "u1" },
				},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});

			expect(result.status).toBe(503);
			if (!("error" in result)) throw new Error("expected error");
			expect(result.error).toBe("temporarily_unavailable");
		});

		it("skips initial-register when no refreshTokenFamilyRotation is configured (CP-2 graceful)", async () => {
			const deps = makeDeps(
				vi.fn().mockResolvedValue({ code: "abc", sid: "test-sid-1", ...validCode }),
			);
			const handler = createAuthorizationGrant(deps);
			const { result } = await handler.handle({
				body: {
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
					code_verifier: CODE_VERIFIER,
				},
				session: {
					code: "abc",
					code_client_id: "client1",
					granted_scopes: ["read"],
					user: { id: "u1" },
				},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});
			expect(result.status).toBe(200);
		});

		it("issues an initial rt+jwt carrying a new family_id (C-3)", async () => {
			const deps = makeDeps(
				vi.fn().mockResolvedValue({ code: "abc", sid: "test-sid-1", ...validCode }),
			);
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: {
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
					code_verifier: CODE_VERIFIER,
				},
				session: {
					code: "abc",
					code_client_id: "client1",
					granted_scopes: ["read"],
					user: { id: "u1" },
				},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
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
			const deps = makeDeps(
				vi.fn().mockResolvedValue({ code: "abc", sid: "test-sid-1", ...validCode }),
			);
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: {
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
					code_verifier: CODE_VERIFIER,
				},
				session: {
					code: "abc",
					code_client_id: "client1",
					// granted_scopes intentionally omitted
					user: { id: "u1" },
				},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
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
					client_id: "client1",
					redirect_uri: RP_URI,
					code_challenge: S256_CHALLENGE,
					code_challenge_method: "S256",
					sid: "test-sid-1",
					grantedScope: [] as readonly string[],
				}),
			);
			const handler = createAuthorizationGrant(deps);
			const { result } = await handler.handle({
				body: {
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
					code_verifier: CODE_VERIFIER,
				},
				session: {
					code: "abc",
					code_client_id: "client1",
					granted_scopes: ["read"],
					user: { id: "u1" },
				},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});
			expect(result.status).toBe(200);
			if (!("tokens" in result)) throw new Error("expected tokens");
			const decoded = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
			expect(decoded.scope).toBeUndefined();
		});

		it("returns 400 when the code carries a challenge but no code_verifier is sent", async () => {
			// The body deliberately omits `code_verifier` — that is the whole
			// point of this case, and asserting the errorDescription is what
			// keeps it honest: a bare `status === 400` also passes when the
			// request fails for an unrelated reason (a verifier that simply
			// does not match, say), which is how this test briefly stopped
			// testing anything at all.
			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
					code_challenge: S256_CHALLENGE,
					code_challenge_method: "S256",
				}),
			);
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1", redirect_uri: RP_URI },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			expect("error" in result && result.error).toBe("invalid_request");
			expect("errorDescription" in result && result.errorDescription).toBe(
				"code_verifier required",
			);
		});

		it("returns 400 when code_verifier is an empty string", async () => {
			// `!code_verifier` covers empty-string as well as absent; an empty
			// verifier must not reach the comparison.
			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
					code_challenge: S256_CHALLENGE,
					code_challenge_method: "S256",
				}),
			);
			const handler = createAuthorizationGrant(deps);
			const { result } = await handler.handle({
				body: { code: "abc", client_id: "client1", redirect_uri: RP_URI, code_verifier: "" },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});

			expect(result.status).toBe(400);
			expect("errorDescription" in result && result.errorDescription).toBe(
				"code_verifier required",
			);
		});

		it("returns 400 when code_verifier has invalid format", async () => {
			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
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
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 400 when S256 code_verifier does not match challenge", async () => {
			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
					code_challenge: "wrong-challenge",
					code_challenge_method: "S256",
				}),
			);
			const handler = createAuthorizationGrant(deps);
			// Valid format verifier that won't match the challenge
			const verifier = "a".repeat(43);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1", redirect_uri: RP_URI, code_verifier: verifier },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
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
					client_id: "client1",
					redirect_uri: RP_URI,
					sid: "test-sid-1",
					code_challenge: challenge,
					code_challenge_method: "S256",
				}),
			);
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1", redirect_uri: RP_URI, code_verifier: verifier },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
		});

		it("returns 200 when plain PKCE code_verifier matches challenge — opted-in client only", async () => {
			// #273: `plain` is reachable ONLY through the client registration's
			// `allowPlainPkce: true`. The grant reads it off the authenticated
			// client, which is the same record /authorize consulted.
			const verifier = "b".repeat(43);
			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
					sid: "test-sid-1",
					code_challenge: verifier,
					code_challenge_method: "plain",
				}),
			);
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1", redirect_uri: RP_URI, code_verifier: verifier },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: { ...DEFAULT_AUTH_CLIENT, allowPlainPkce: true },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
		});

		it("returns 400 for the same plain code when the client has no opt-in (#273)", async () => {
			const verifier = "b".repeat(43);
			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
					sid: "test-sid-1",
					code_challenge: verifier,
					code_challenge_method: "plain",
				}),
			);
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1", redirect_uri: RP_URI, code_verifier: verifier },
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			expect("error" in result && result.error).toBe("invalid_request");
		});

		// #273: the legacy `pkce.requireS256` boolean is gone. It was the only
		// knob the TOKEN endpoint honoured, and /authorize ignored it — the
		// divergence that could mint a code doomed at redemption. These tests
		// pin that a config still setting it changes nothing in either
		// direction: S256 is mandatory whatever it says.
		describe("legacy pkce.requireS256 is inert (#273)", () => {
			const legacyConfig = (requireS256: boolean) =>
				({
					oauth: {
						jwt: { secret: "test-secret" },
						accessToken: { expiresIn: 3600 },
						refreshToken: { expiresIn: 86400 },
						grants: {
							session: { enabled: true },
							authorization_code: { enabled: true, pkce: { requireS256 } },
							refresh_token: { enabled: true },
						},
					},
				}) as unknown as GrantDependencies["config"];

			const makeLegacyDeps = (requireS256: boolean, codeData: Record<string, unknown>) => ({
				config: legacyConfig(requireS256),
				keyStore: createSymmetricKeyStore("test-secret"),
				codeRepository: {
					consumeByCode: vi.fn().mockResolvedValue({ code: "abc", ...codeData }),
					createCode: vi.fn(),
					findByCode: vi.fn(),
					removeByCode: vi.fn(),
				} as unknown as CodeRepository,
				clientRepository: mockClientRepository,
			});

			const legacyCtx = (verifier: string): GrantContext => ({
				body: {
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
					code_verifier: verifier,
				},
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});

			it.each([true, false])(
				"rejects a plain code with requireS256=%s — the client has no opt-in",
				async (requireS256) => {
					const verifier = "b".repeat(43);
					const handler = createAuthorizationGrant(
						makeLegacyDeps(requireS256, {
							client_id: "client1",
							redirect_uri: RP_URI,
							code_challenge: verifier,
							code_challenge_method: "plain",
						}),
					);

					const { result } = await handler.handle(legacyCtx(verifier));

					expect(result.status).toBe(400);
					expect("error" in result && result.error).toBe("invalid_request");
				},
			);

			it.each([true, false])("accepts an S256 code with requireS256=%s", async (requireS256) => {
				const handler = createAuthorizationGrant(
					makeLegacyDeps(requireS256, {
						client_id: "client1",
						redirect_uri: RP_URI,
						sid: "test-sid-1",
						code_challenge: S256_CHALLENGE,
						code_challenge_method: "S256",
					}),
				);

				const { result } = await handler.handle(legacyCtx(CODE_VERIFIER));

				expect(result.status).toBe(200);
			});

			it.each([true, false])(
				"rejects a PKCE-less code with requireS256=%s (was: redeemable)",
				async (requireS256) => {
					const handler = createAuthorizationGrant(
						makeLegacyDeps(requireS256, {
							client_id: "client1",
							redirect_uri: RP_URI,
							sid: "test-sid-1",
						}),
					);

					const { result } = await handler.handle(legacyCtx(CODE_VERIFIER));

					expect(result.status).toBe(400);
					expect("error" in result && result.error).toBe("invalid_request");
				},
			);
		});

		// A-2 redirect_uri binding — D-1 made redirect_uri a required field on
		// CodeData; the previous "vacuous-pass when not stored" behavior (IH-4)
		// is closed. session.code_redirect_uri fallback is removed.
		describe("A-2: redirect_uri binding", () => {
			it("returns invalid_grant when stored redirect_uri does not match body redirect_uri", async () => {
				const deps = makeDeps(
					vi.fn().mockResolvedValue({
						code: "abc",
						client_id: "client1",
						redirect_uri: "https://example.com/callback",
						code_challenge: S256_CHALLENGE,
						code_challenge_method: "S256",
					}),
				);
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: {
						code: "abc",
						client_id: "client1",
						redirect_uri: "https://evil.com/callback",
						code_verifier: CODE_VERIFIER,
					},
					session: {
						code: "abc",
						code_client_id: "client1",
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(400);
				expect("error" in result && result.error).toBe("invalid_grant");
			});

			it("returns invalid_grant when redirect_uri was stored but omitted in token request", async () => {
				const deps = makeDeps(
					vi.fn().mockResolvedValue({
						code: "abc",
						client_id: "client1",
						redirect_uri: "https://example.com/callback",
						code_challenge: S256_CHALLENGE,
						code_challenge_method: "S256",
					}),
				);
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: {
						code: "abc",
						client_id: "client1" /* no redirect_uri */,
						code_verifier: CODE_VERIFIER,
					},
					session: {
						code: "abc",
						code_client_id: "client1",
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
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
						client_id: "client1",
						redirect_uri: "https://example.com/callback",
						code_challenge: S256_CHALLENGE,
						code_challenge_method: "S256",
					}),
				);
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: {
						code: "abc",
						client_id: "client1",
						redirect_uri: "https://example.com/callback",
						code_verifier: CODE_VERIFIER,
					},
					session: {
						code: "abc",
						code_client_id: "client1",
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(200);
			});

			it("D-1 / IH-4: rejects when codeData has no redirect_uri (was: vacuous-pass returns 200)", async () => {
				// Pre-v0.5.1 this returned 200 because the redirect_uri binding
				// check was guarded by `if (storedRedirectUri)`. Post-D-1
				// codeData.redirect_uri is required and the check is unconditional.
				const deps = makeDeps(
					vi.fn().mockResolvedValue({
						code: "abc",
						sid: "test-sid-1",
						client_id: "client1",
						// redirect_uri intentionally omitted to model legacy/corrupt records.
					}),
				);
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: {
						code: "abc",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_verifier: CODE_VERIFIER,
					},
					session: { code: "abc", code_client_id: "client1" },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(400);
				expect("error" in result && result.error).toBe("invalid_grant");
			});
		});

		// D-6 (v0.5.1): the in-grant `client_secret` check that lived here pre-
		// v0.5.1 is removed. RFC 6749 §2.3 client authentication is now the
		// responsibility of `clientAuthMw` at the route level — the grant
		// handler trusts `ctx.authenticatedClient` and only verifies the
		// canonical binding `codeData.client_id === authenticatedClient.clientId`.
		// The integration-level coverage for credential validity lives in
		// `clientAuth.test.mts` (Group B + Codex M1/M4) and the route-level
		// `routes.test.mts` (Group C). The grant-level invariant tested here is
		// just the binding gate.
		describe("D-6 binding gate: codeData.client_id vs ctx.authenticatedClient.clientId", () => {
			it("returns 401 invalid_client when ctx.authenticatedClient is null", async () => {
				const deps = makeDeps(vi.fn().mockResolvedValue({ code: "abc", ...validCode }));
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: { code: "abc", redirect_uri: RP_URI, code_verifier: CODE_VERIFIER },
					session: {},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: null,
				});

				expect(result.status).toBe(401);
				if (!("error" in result)) expect.fail("Expected error in result");
				expect(result.error).toBe("invalid_client");
			});

			it("returns 400 invalid_grant when authenticatedClient.clientId differs from codeData.client_id", async () => {
				// codeData binds the code to "client1" (validCode); the authenticated
				// client at /token is a different client. The binding gate must
				// reject — accepting it would let any authenticated client redeem
				// any code, which is the spoof vector PB-2 closes.
				const deps = makeDeps(vi.fn().mockResolvedValue({ code: "abc", ...validCode }));
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: { code: "abc", redirect_uri: RP_URI, code_verifier: CODE_VERIFIER },
					session: {},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: {
						clientId: "different-client",
						tokenEndpointAuthMethod: "client_secret_basic",
					},
				});

				expect(result.status).toBe(400);
				if (!("error" in result)) expect.fail("Expected error in result");
				expect(result.error).toBe("invalid_grant");
				expect(result.errorDescription).toBe("code was not issued to this client");
			});

			it("returns 200 when authenticatedClient matches codeData.client_id (canonical happy path)", async () => {
				const deps = makeDeps(
					vi.fn().mockResolvedValue({ code: "abc", sid: "test-sid", ...validCode }),
				);
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: { code: "abc", redirect_uri: RP_URI, code_verifier: CODE_VERIFIER },
					session: { user: { id: "u1" } },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				});

				expect(result.status).toBe(200);
			});
		});

		// #273 replaced the B-7/B-8 knobs (supportedMethods / defaultMethod /
		// required) with one fixed policy plus a per-client `plain` opt-in.
		// What is pinned here is that no server-wide config can widen it.
		describe("#273: PKCE policy is fixed, not configurable", () => {
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

			const makeConfiguredDeps = (
				pkce: Record<string, unknown>,
				codeData: Record<string, unknown>,
			) => ({
				config: makePkceConfig(pkce),
				keyStore: createSymmetricKeyStore("test-secret"),
				codeRepository: {
					consumeByCode: vi.fn().mockResolvedValue({ code: "abc", ...codeData }),
					createCode: vi.fn(),
					findByCode: vi.fn(),
					removeByCode: vi.fn(),
				} as unknown as CodeRepository,
				clientRepository: mockClientRepository,
			});

			const ctxFor = (
				verifier: string,
				authenticatedClient: GrantContext["authenticatedClient"] = DEFAULT_AUTH_CLIENT,
			): GrantContext => ({
				body: {
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
					code_verifier: verifier,
				},
				session: { code: "abc", code_client_id: "client1" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient,
			});

			it("refuses plain even when supportedMethods lists it", async () => {
				const verifier = "b".repeat(43);
				const handler = createAuthorizationGrant(
					makeConfiguredDeps(
						{ supportedMethods: ["S256", "plain"], defaultMethod: "plain" },
						{
							client_id: "client1",
							redirect_uri: RP_URI,
							code_challenge: verifier,
							code_challenge_method: "plain",
						},
					),
				);

				const { result } = await handler.handle(ctxFor(verifier));

				expect(result.status).toBe(400);
				expect("error" in result && result.error).toBe("invalid_request");
			});

			it("still admits plain for a client that opted in, whatever the config says", async () => {
				const verifier = "b".repeat(43);
				const handler = createAuthorizationGrant(
					makeConfiguredDeps(
						{ supportedMethods: ["S256"] },
						{
							client_id: "client1",
							redirect_uri: RP_URI,
							sid: "test-sid-1",
							code_challenge: verifier,
							code_challenge_method: "plain",
						},
					),
				);

				const { result } = await handler.handle(
					ctxFor(verifier, { ...DEFAULT_AUTH_CLIENT, allowPlainPkce: true }),
				);

				expect(result.status).toBe(200);
			});

			it("refuses a code with no code_challenge_method whatever `required` says", async () => {
				// Pre-#273 `required: false` (the default!) made this a 200 for a
				// confidential client — PKCE was effectively optional.
				for (const required of [true, false]) {
					const handler = createAuthorizationGrant(
						makeConfiguredDeps(
							{ required, supportedMethods: ["S256", "plain"] },
							{
								client_id: "client1",
								redirect_uri: RP_URI,
								sid: "test-sid-1",
							},
						),
					);

					const { result } = await handler.handle(ctxFor(CODE_VERIFIER));

					expect(result.status).toBe(400);
					expect("error" in result && result.error).toBe("invalid_request");
					expect("errorDescription" in result && result.errorDescription).toBe(
						"PKCE is required but code was issued without code_challenge",
					);
				}
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
						findByCode: vi.fn(),
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
							client_id: "client1",
							redirect_uri: RP_URI,
							code_challenge: S256_CHALLENGE,
							code_challenge_method: "S256",
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
					body: {
						code: "c1",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_verifier: CODE_VERIFIER,
					},
					session: { code: "c1", code_client_id: "client1" },
					issuer: "https://auth.example.com",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
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
							client_id: "client1",
							redirect_uri: RP_URI,
							code_challenge: S256_CHALLENGE,
							code_challenge_method: "S256",
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
					body: {
						code: "c-noiss",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_verifier: CODE_VERIFIER,
					},
					session: { code: "c-noiss", code_client_id: "client1" },
					// issuer intentionally omitted
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
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
							client_id: "client1",
							redirect_uri: RP_URI,
							code_challenge: S256_CHALLENGE,
							code_challenge_method: "S256",
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
					body: {
						code: "c2",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_verifier: CODE_VERIFIER,
					},
					session: { code: "c2", code_client_id: "client1" },
					issuer: "https://auth.example.com",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
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
						client_id: "client1",
						redirect_uri: RP_URI,
						code_challenge: S256_CHALLENGE,
						code_challenge_method: "S256",
						sid: "sid-3",
						grantedScope: ["openid"],
					}),
				);
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: {
						code: "c3",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_verifier: CODE_VERIFIER,
					},
					session: { code: "c3", code_client_id: "client1" },
					issuer: "https://auth.example.com",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				});

				expect(result.status).toBe(200);
				if (!("tokens" in result)) throw new Error("expected tokens");
				expect(typeof result.tokens.access_token).toBe("string");
				expect(result.tokens.id_token).toBeUndefined();
			});
		});

		// D-1 / IH-4 / IH-2: identity gates move from the Express session to the
		// code record. consumeByCode (atomic getDel on a single Redis node)
		// becomes the sole authenticity gate; client_id and redirect_uri are
		// verified against codeData fields populated at /authorize time.
		describe("D-1: identity gates derive from codeData not session", () => {
			it("IH-4: rejects when both body.redirect_uri AND codeData.redirect_uri are missing (vacuous-pass closure)", async () => {
				// Per Codex calibration: include session.code / session.code_client_id
				// matching the body so the early session gates would otherwise let
				// this through, and exercise the new strict redirect_uri check directly.
				const deps = makeDeps(
					vi.fn().mockResolvedValue({
						code: "abc",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_challenge: S256_CHALLENGE,
						code_challenge_method: "S256",
						sid: "test-sid-1",
						// redirect_uri intentionally absent — pre-fix this is the Redis
						// drop scenario where IH-4 vacuous-pass would skip the check.
					}),
				);
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: {
						code: "abc",
						client_id: "client1" /* no redirect_uri */,
						code_verifier: CODE_VERIFIER,
					},
					session: { code: "abc", code_client_id: "client1", user: { id: "u1" } },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(400);
				expect("error" in result && result.error).toBe("invalid_grant");
			});

			it("IH-4: rejects when body.redirect_uri is supplied but codeData.redirect_uri is missing", async () => {
				const deps = makeDeps(
					vi.fn().mockResolvedValue({
						code: "abc",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_challenge: S256_CHALLENGE,
						code_challenge_method: "S256",
						sid: "test-sid-1",
						// redirect_uri intentionally absent on the codeData side.
					}),
				);
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: {
						code: "abc",
						client_id: "client1",
						redirect_uri: "https://attacker.example/steal",
					},
					session: { code: "abc", code_client_id: "client1", user: { id: "u1" } },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(400);
				expect("error" in result && result.error).toBe("invalid_grant");
			});

			it("IH-2: client_id check derives from codeData.client_id, not session.code_client_id", async () => {
				// Per Codex calibration: set session.code_client_id to MATCH the body
				// so the pre-fix session-based gate (`client_id !== session.code_client_id`)
				// would let the request through. The new gate must reject because
				// codeData.client_id differs from the body's client_id.
				const deps = makeDeps(
					vi.fn().mockResolvedValue({
						code: "abc",
						sid: "test-sid-1",
						client_id: "real-client",
						redirect_uri: "https://rp.example/cb",
						code_challenge: S256_CHALLENGE,
						code_challenge_method: "S256",
					}),
				);
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: {
						code: "abc",
						client_id: "spoofed-client",
						redirect_uri: "https://rp.example/cb",
					},
					session: {
						code: "abc",
						// matches body.client_id — pre-fix session gate passes.
						code_client_id: "spoofed-client",
						user: { id: "u1" },
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(400);
				expect("error" in result && result.error).toBe("invalid_grant");
			});
		});

		describe("TODO-F-3: family_id + sid claims, RP registration", () => {
			it("happy path: access_token and refresh_token both carry family_id and sid claims (F-3-1)", async () => {
				const deps = makeDeps(
					vi.fn().mockResolvedValue({ code: "abc", sid: "session-abc", ...validCode }),
				);
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: {
						code: "abc",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_verifier: CODE_VERIFIER,
					},
					session: {
						code: "abc",
						code_client_id: "client1",
						granted_scopes: ["read"],
						user: { id: "u1" },
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
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
					...makeDeps(vi.fn().mockResolvedValue({ code: "abc", ...validCode } /* no sid */)),
					userSessionStore,
				};
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: {
						code: "abc",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_verifier: CODE_VERIFIER,
					},
					session: {
						code: "abc",
						code_client_id: "client1",
						user: { id: "u1" },
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				});

				expect(result.status).toBe(400);
				if (!("error" in result)) throw new Error("expected error");
				expect(result.error).toBe("invalid_grant");
				expect((result as { errorDescription?: string }).errorDescription).toMatch(/sid/);
			});

			it("backward compat — no userSessionStore + no sid → grant succeeds without sid claim (F-3-2-compat)", async () => {
				// Deployments that have not wired userSessionStore do not write sid at login
				// time and must continue to work. No store → sid not required.
				const deps = makeDeps(
					vi.fn().mockResolvedValue({ code: "abc", ...validCode } /* no sid */),
				);
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: {
						code: "abc",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_verifier: CODE_VERIFIER,
					},
					session: {
						code: "abc",
						code_client_id: "client1",
						granted_scopes: ["read"],
						user: { id: "u1" },
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
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
					...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "session-xyz", ...validCode })),
					userSessionStore,
					sessionFamilyIndex,
					sessionRPRegistry,
				};
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: {
						code: "abc",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_verifier: CODE_VERIFIER,
					},
					session: {
						code: "abc",
						code_client_id: "client1",
						granted_scopes: ["read"],
						user: { id: "u1" },
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
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
				const deps = makeDeps(
					vi.fn().mockResolvedValue({ code: "abc", sid: "session-abc", ...validCode }),
				);
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: {
						code: "abc",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_verifier: CODE_VERIFIER,
					},
					session: {
						code: "abc",
						code_client_id: "client1",
						granted_scopes: ["read"],
						user: { id: "u1" },
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
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
					...makeDeps(
						vi.fn().mockResolvedValue({ code: "abc", sid: "session-gone", ...validCode }),
					),
					userSessionStore,
				};
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: {
						code: "abc",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_verifier: CODE_VERIFIER,
					},
					session: {
						code: "abc",
						code_client_id: "client1",
						granted_scopes: ["read"],
						user: { id: "u1" },
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
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
					...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "session-abc", ...validCode })),
					userSessionStore,
				};
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: {
						code: "abc",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_verifier: CODE_VERIFIER,
					},
					session: {
						code: "abc",
						code_client_id: "client1",
						granted_scopes: ["read"],
						user: { id: "u1" },
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
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
						vi.fn().mockResolvedValue({ code: "abc", sid: "session-abc", ...validCode }),
						throwingClientRepo,
					),
					userSessionStore,
					sessionFamilyIndex: makeSessionFamilyIndex(),
					sessionRPRegistry: makeSessionRPRegistry(),
				};
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: {
						code: "abc",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_verifier: CODE_VERIFIER,
					},
					session: {
						code: "abc",
						code_client_id: "client1",
						granted_scopes: ["read"],
						user: { id: "u1" },
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				});

				expect(result.status).toBe(503);
				if (!("error" in result)) throw new Error("expected error");
				expect(result.error).toBe("temporarily_unavailable");
			});
		});
	});
});

// ---------------------------------------------------------------------------
// CR-4 — TOCTOU: re-validate session before returning tokens
//
// Background: between the first `userSessionStore.get(sid)` and the call to
// `sessionFamilyIndex.addFamilyId`, the handler awaits `clientRepository.findById`.
// If `cascadeLogout` runs during that await window, the session is gone and
// the just-issued tokens become orphaned from logout orchestration. CR-4 closes
// the common case (logout fully completes before the second check) by adding a
// second `userSessionStore.get(sid)` immediately before `addFamilyId`. Per
// Codex Delta 1, this REDUCES the window — it does not eliminate it. Phase F
// follow-up is the atomic Lua EVAL `addFamilyIdIfSessionActive`.
// ---------------------------------------------------------------------------

describe("CR-4 — TOCTOU re-check session before returning tokens", () => {
	it("returns 400 invalid_grant / session_invalidated when session is deleted between findById and addFamilyId", async () => {
		// Mock: first get returns session (initial check at line ~439), second get
		// returns null (the new CR-4 re-check immediately before addFamilyId).
		let getCallCount = 0;
		const userSessionStore = {
			kind: "spy",
			async create() {},
			async get() {
				getCallCount++;
				if (getCallCount === 1) {
					return {
						sid: "sid-toctou",
						sub: "u1",
						authTime: new Date(),
						createdAt: new Date(),
						expiresAt: new Date(Date.now() + 3600_000),
						claims: {},
					};
				}
				return null;
			},
			async delete() {},
		};
		const sessionFamilyIndex = makeSessionFamilyIndex();
		const sessionRPRegistry = makeSessionRPRegistry();
		const logger = createMockLogger();

		const deps = {
			...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "sid-toctou", ...validCode })),
			userSessionStore,
			sessionFamilyIndex,
			sessionRPRegistry,
			logger,
		};

		const handler = createAuthorizationGrant(deps);
		const { result } = await handler.handle({
			body: {
				code: "abc",
				client_id: "client1",
				redirect_uri: RP_URI,
				code_verifier: CODE_VERIFIER,
			},
			session: {
				code: "abc",
				code_client_id: "client1",
				granted_scopes: ["read"],
				user: { id: "u1" },
			},
			issuer: "localhost",
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		});

		// Behavioral: 400 invalid_grant / session_invalidated (distinct from the
		// existing first-check rejection which returns "session_invalid").
		expect(result.status).toBe(400);
		if (!("error" in result)) throw new Error("expected error");
		expect(result.error).toBe("invalid_grant");
		expect((result as { errorDescription?: string }).errorDescription).toBe("session_invalidated");

		// Proof of re-check: get was called twice (first + CR-4 second).
		expect(getCallCount).toBe(2);

		// Negative invariants: token-linking ops MUST NOT run when second check fails.
		expect(sessionFamilyIndex.addFamilyId).not.toHaveBeenCalled();
		expect(sessionRPRegistry.registerRP).not.toHaveBeenCalled();

		// Codex Delta 3: audit log MUST fire on session_invalidated rejection.
		expect(logger.warn).toHaveBeenCalledTimes(1);
		const [warnPayload, warnMsg] = logger.warn.mock.calls[0] as [Record<string, unknown>, string];
		expect(warnPayload).toMatchObject({
			sid: "sid-toctou",
			clientId: "client1",
		});
		expect(warnMsg).toBe("authorization_grant_rejected_session_invalidated_during_token_issuance");
	});

	it("returns 503 temporarily_unavailable when the second userSessionStore.get throws", async () => {
		// First get succeeds; second get throws (e.g. Redis blip mid-grant).
		// The CR-4 second `get` has its own dedicated try/catch — store-availability
		// failures here surface as `503 / "session store unavailable"`, matching the
		// first-get path and not the broader outer catch that wraps findById /
		// addFamilyId / registerRP (which surfaces as `503 / "session linking
		// unavailable"`).
		let getCallCount = 0;
		const userSessionStore = {
			kind: "spy",
			async create() {},
			async get() {
				getCallCount++;
				if (getCallCount === 1) {
					return {
						sid: "sid-blip",
						sub: "u1",
						authTime: new Date(),
						createdAt: new Date(),
						expiresAt: new Date(Date.now() + 3600_000),
						claims: {},
					};
				}
				throw new Error("store down on second check");
			},
			async delete() {},
		};
		const sessionFamilyIndex = makeSessionFamilyIndex();
		const deps = {
			...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "sid-blip", ...validCode })),
			userSessionStore,
			sessionFamilyIndex,
			sessionRPRegistry: makeSessionRPRegistry(),
		};
		const handler = createAuthorizationGrant(deps);
		const { result } = await handler.handle({
			body: {
				code: "abc",
				client_id: "client1",
				redirect_uri: RP_URI,
				code_verifier: CODE_VERIFIER,
			},
			session: {
				code: "abc",
				code_client_id: "client1",
				granted_scopes: ["read"],
				user: { id: "u1" },
			},
			issuer: "localhost",
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		});

		expect(result.status).toBe(503);
		if (!("error" in result)) throw new Error("expected error");
		expect(result.error).toBe("temporarily_unavailable");
		// errorDescription matches the first-get's wording — the second `get` has its
		// own try/catch (not the outer findById/addFamilyId catch) so operators see a
		// store-availability error description, not a misleading "session linking" one.
		expect((result as { errorDescription?: string }).errorDescription).toBe(
			"session store unavailable",
		);
		expect(getCallCount).toBe(2);
		expect(sessionFamilyIndex.addFamilyId).not.toHaveBeenCalled();
	});
});

// ---------------------------------------------------------------------------
// #259 — access/refresh token `sub` binds to the code's UserSession
//
// The token endpoint is a back-channel call for confidential clients: it
// carries no end-user cookie, so `ctx.session.user` is undefined there. The
// subject therefore has to come from the `UserSession` the code points at via
// `sid` — the same source the id_token already uses — with `ctx.session.user`
// left as the fallback only for deployments that wire no session store.
// ---------------------------------------------------------------------------

describe("#259 — AT/RT subject derives from the code-bound UserSession", () => {
	const ISSUER = "https://auth.example.com";
	const configWithIssuer = {
		oauth: {
			jwt: { secret: "test-secret", issuer: ISSUER },
			accessToken: { expiresIn: 3600 },
			refreshToken: { expiresIn: 86400 },
			grants: {
				session: { enabled: true },
				authorization_code: { enabled: true },
				refresh_token: { enabled: true },
			},
		},
	} as unknown as GrantDependencies["config"];

	function makeStore(sid: string, sub: string) {
		return {
			kind: "spy",
			async create() {},
			async get(querySid: string) {
				if (querySid !== sid) return null;
				return {
					sid,
					sub,
					authTime: new Date("2026-04-21T00:00:00Z"),
					createdAt: new Date(),
					expiresAt: new Date(Date.now() + 3600_000),
					claims: {},
				};
			},
			async delete() {},
		};
	}

	it("issues a sub on a cookie-less back-channel code exchange", async () => {
		const deps = {
			...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "sid-259", ...validCode })),
			config: configWithIssuer,
			userSessionStore: makeStore("sid-259", "u-259"),
			sessionFamilyIndex: makeSessionFamilyIndex(),
			sessionRPRegistry: makeSessionRPRegistry(),
		};
		const handler = createAuthorizationGrant(deps);

		// No `user` key: the confidential-client /token request carries no cookie.
		const { result } = await handler.handle({
			body: {
				code: "abc",
				client_id: "client1",
				redirect_uri: RP_URI,
				code_verifier: CODE_VERIFIER,
			},
			session: { code: "abc", code_client_id: "client1" },
			issuer: ISSUER,
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		});

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens");
		expect(decodeJwt(result.tokens.access_token).sub).toBe("u-259");
		expect(decodeJwt(result.tokens.refresh_token as string).sub).toBe("u-259");
	});

	it("prefers the code-bound session when the request session names another user", async () => {
		const deps = {
			...makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					sid: "sid-259",
					grantedScope: ["openid"],
					...validCode,
				}),
			),
			config: configWithIssuer,
			userSessionStore: makeStore("sid-259", "u-259"),
			sessionFamilyIndex: makeSessionFamilyIndex(),
			sessionRPRegistry: makeSessionRPRegistry(),
		};
		const handler = createAuthorizationGrant(deps);

		// Same-origin/BFF topology where /token does carry a cookie, and the
		// browser session moved to a different user between /authorize and /token.
		const { result } = await handler.handle({
			body: {
				code: "abc",
				client_id: "client1",
				redirect_uri: RP_URI,
				code_verifier: CODE_VERIFIER,
			},
			session: { code: "abc", code_client_id: "client1", user: { id: "other-user" } },
			issuer: ISSUER,
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		});

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens");
		const idToken = result.tokens.id_token;
		if (typeof idToken !== "string") throw new Error("expected id_token");

		// All three tokens agree, and none of them names the request session's user.
		expect(decodeJwt(result.tokens.access_token).sub).toBe("u-259");
		expect(decodeJwt(result.tokens.refresh_token as string).sub).toBe("u-259");
		expect(decodeJwt(idToken).sub).toBe("u-259");
	});

	it("refuses when the session's subject changes between the two store reads", async () => {
		// The AT/RT are signed from the first read and the id_token from the
		// re-check. A store that answered with a different subject for the same
		// sid would hand back tokens that disagree about who the user is — which
		// is the confusion this whole subject handling exists to prevent.
		let call = 0;
		const store = {
			kind: "spy",
			async create() {},
			async get() {
				call++;
				return {
					sid: "sid-259",
					sub: call === 1 ? "u-259" : "someone-else",
					authTime: new Date("2026-04-21T00:00:00Z"),
					createdAt: new Date(),
					expiresAt: new Date(Date.now() + 3600_000),
					claims: {},
				};
			},
			async delete() {},
		};
		const sessionFamilyIndex = makeSessionFamilyIndex();
		const deps = {
			...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "sid-259", ...validCode })),
			config: configWithIssuer,
			userSessionStore: store,
			sessionFamilyIndex,
			sessionRPRegistry: makeSessionRPRegistry(),
		};

		const { result } = await createAuthorizationGrant(deps).handle({
			body: {
				code: "abc",
				client_id: "client1",
				redirect_uri: RP_URI,
				code_verifier: CODE_VERIFIER,
			},
			session: { code: "abc", code_client_id: "client1" },
			issuer: ISSUER,
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		});

		expect(result.status).toBe(400);
		if (!("error" in result)) throw new Error("expected error");
		expect(result.error).toBe("invalid_grant");
		// Nothing is linked to a session whose identity we could not agree on.
		expect(sessionFamilyIndex.addFamilyId).not.toHaveBeenCalled();
	});

	it("refuses when a wired store returns a record with no usable sub", async () => {
		// Gating the request-session fallback on `sub` being nullish rather than
		// on the store being absent would silently revert to the cookie-derived
		// identity here — the cross-user mismatch this fix removes.
		const store = {
			kind: "spy",
			async create() {},
			async get() {
				return {
					sid: "sid-259",
					sub: undefined as unknown as string,
					authTime: new Date("2026-04-21T00:00:00Z"),
					createdAt: new Date(),
					expiresAt: new Date(Date.now() + 3600_000),
					claims: {},
				};
			},
			async delete() {},
		};
		const deps = {
			...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "sid-259", ...validCode })),
			config: configWithIssuer,
			userSessionStore: store,
			sessionFamilyIndex: makeSessionFamilyIndex(),
			sessionRPRegistry: makeSessionRPRegistry(),
		};

		const { result } = await createAuthorizationGrant(deps).handle({
			body: {
				code: "abc",
				client_id: "client1",
				redirect_uri: RP_URI,
				code_verifier: CODE_VERIFIER,
			},
			// A cookie IS present and names a different user — the BFF topology.
			session: { code: "abc", code_client_id: "client1", user: { id: "cookie-user" } },
			issuer: ISSUER,
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		});

		expect(result.status).toBe(400);
		if (!("error" in result)) throw new Error("expected error");
		expect(result.error).toBe("invalid_grant");
	});

	it("falls back to the request session when no session store is wired", async () => {
		const deps = makeDeps(vi.fn().mockResolvedValue({ code: "abc", ...validCode }));
		const handler = createAuthorizationGrant(deps);

		const { result } = await handler.handle({
			body: {
				code: "abc",
				client_id: "client1",
				redirect_uri: RP_URI,
				code_verifier: CODE_VERIFIER,
			},
			session: { code: "abc", code_client_id: "client1", user: { id: "u-legacy" } },
			issuer: "localhost",
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		});

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens");
		expect(decodeJwt(result.tokens.access_token).sub).toBe("u-legacy");
	});
});

// F6 coverage boost — patch lines for PR #126 (IH-13 + SF-3 + IH-16 + TS-4)
// that are reachable but were not exercised by the original test suite.
// Each test pins both status code AND errorDescription so a future refactor
// that shifts an error to a different branch is caught.
describe("F6 PR2 patch coverage — SF-3 corrupt code records + PKCE branches", () => {
	it("returns 400 invalid_grant when code record has code_challenge without code_challenge_method (SF-3 corrupt code A)", async () => {
		const deps = makeDeps(
			vi.fn().mockResolvedValue({
				code: "abc",
				client_id: "client1",
				redirect_uri: RP_URI,
				// SF-3 corrupt shape: challenge persisted but method missing.
				// /authorize never writes this pairing — only a misbehaving
				// CodeRepository implementation could produce it.
				code_challenge: "challenge",
				// code_challenge_method intentionally omitted
			}),
		);
		const handler = createAuthorizationGrant(deps);
		const ctx: GrantContext = {
			body: {
				code: "abc",
				client_id: "client1",
				redirect_uri: RP_URI,
				code_verifier: CODE_VERIFIER,
			},
			session: { code: "abc", code_client_id: "client1" },
			issuer: "localhost",
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		};

		const { result } = await handler.handle(ctx);

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
		expect((result as { errorDescription?: string }).errorDescription).toBe("invalid code");
	});

	it("returns 400 invalid_request when code_challenge_method is set but code_challenge is non-string (SF-3 corrupt code B)", async () => {
		const deps = makeDeps(
			vi.fn().mockResolvedValue({
				code: "abc",
				client_id: "client1",
				redirect_uri: RP_URI,
				// code_challenge typed as `unknown` from a corrupt store record.
				// Pre-SF-3 this passed silently because `verifier !== undefined`
				// is true; constantTimeStringEqual now rejects non-string args.
				code_challenge: 12345 as unknown as string,
				code_challenge_method: "S256",
			}),
		);
		const handler = createAuthorizationGrant(deps);
		const verifier = "a".repeat(43);
		const ctx: GrantContext = {
			body: { code: "abc", client_id: "client1", redirect_uri: RP_URI, code_verifier: verifier },
			session: { code: "abc", code_client_id: "client1" },
			issuer: "localhost",
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		};

		const { result } = await handler.handle(ctx);

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_request");
		expect((result as { errorDescription?: string }).errorDescription).toBe(
			"code_challenge missing on code record",
		);
	});

	it("returns 400 invalid_request when code_verifier fails RFC 7636 format check", async () => {
		// RFC 7636 §4.1: code_verifier is 43-128 chars from the unreserved set.
		// "too-short" is 9 chars → must reject. The pre-existing test for this
		// branch omitted body.redirect_uri and so was returning early at the
		// redirect_uri *presence* gate (authorization.mts:125, after D-1
		// hoisted the absence check ahead of consumeByCode). The error string
		// happened to be `"redirect_uri mismatch"` either way, but it was
		// firing at presence-check, not at the equality-check at L168, and
		// never reached the regex at L263. This test pins redirect_uri so
		// the regex check is the actual cause and errorDescription is asserted.
		const deps = makeDeps(
			vi.fn().mockResolvedValue({
				code: "abc",
				client_id: "client1",
				redirect_uri: RP_URI,
				code_challenge: "challenge",
				code_challenge_method: "S256",
			}),
		);
		const handler = createAuthorizationGrant(deps);
		const ctx: GrantContext = {
			body: {
				code: "abc",
				client_id: "client1",
				redirect_uri: RP_URI,
				code_verifier: "too-short",
			},
			session: { code: "abc", code_client_id: "client1" },
			issuer: "localhost",
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		};

		const { result } = await handler.handle(ctx);

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_request");
		expect((result as { errorDescription?: string }).errorDescription).toBe(
			"invalid code_verifier format",
		);
	});

	it("returns 400 invalid_grant when plain method code_verifier does not match challenge (SF-3 + MIN-4 timing-safe)", async () => {
		// Both verifier and challenge are valid 43-char RFC 7636 strings, but
		// they differ. Pre-SF-3+MIN-4 the comparison was a short-circuit `!==`
		// whose per-byte timing leaked progress against the stored challenge;
		// constantTimeStringEqual replaces it on both S256 and plain branches.
		// #273: reaching the plain branch at all now requires the client's
		// `allowPlainPkce` opt-in — without it the method allowlist rejects
		// first and this branch is never exercised.
		const verifier = "a".repeat(43);
		const challenge = "b".repeat(43);
		const deps = makeDeps(
			vi.fn().mockResolvedValue({
				code: "abc",
				client_id: "client1",
				redirect_uri: RP_URI,
				code_challenge: challenge,
				code_challenge_method: "plain",
			}),
		);
		const handler = createAuthorizationGrant(deps);
		const ctx: GrantContext = {
			body: { code: "abc", client_id: "client1", redirect_uri: RP_URI, code_verifier: verifier },
			session: { code: "abc", code_client_id: "client1" },
			issuer: "localhost",
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: { ...DEFAULT_AUTH_CLIENT, allowPlainPkce: true },
		};

		const { result } = await handler.handle(ctx);

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
		expect((result as { errorDescription?: string }).errorDescription).toBe(
			"invalid code_verifier",
		);
	});

	it("admits exactly the two methods the verifier comparison handles", () => {
		// The comparison in `authorization.mts` is a two-way choice: digest the
		// verifier for `S256`, compare it verbatim for `plain`. It used to be a
		// `switch` with a `default` guarding against the operator-configured
		// `supportedMethods` and the switch diverging — #273 removed that knob,
		// so the guard became unreachable and the runtime test that drove it
		// (by widening `supportedMethods` to include a bogus method) could no
		// longer exist.
		//
		// The invariant it protected is still worth pinning, so it is asserted
		// where it actually lives: grow the admissible set without revisiting
		// that comparison and this fails.
		const policy = resolvePkceOptions(undefined);
		const admissible = new Set([
			...pkceMethodsForClient(policy, null),
			...pkceMethodsForClient(policy, { allowPlainPkce: true }),
		]);
		expect([...admissible].sort()).toEqual(["S256", "plain"]);
	});
});
