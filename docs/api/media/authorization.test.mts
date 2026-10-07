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
	type GrantHandler,
	InMemoryCodeRepository,
	type RefreshTokenFamilyRotation,
	type SessionAuthentication,
	type SessionJoinOutcome,
	type SessionLifecycle,
	type SessionLifecycleStore,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createTestOAuthTokenSettings, resolverForTests } from "@o3co/auth-provider-core/testing";
import { decodeJwt } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";
import { pkceMethodsForClient, resolvePkceOptions } from "#/grants/pkce.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { registeredGrants } from "./_helpers/grantRegistry.mjs";
import { grantSettingsFrom } from "./_helpers/grantSettings.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";
import { expectUriNotLogged } from "./_helpers/projectedLog.mjs";
import {
	joiningLifecycle,
	lifecycleStoreOver,
	openingLifecycleStore,
	outsideAnswer,
} from "./_helpers/sessionLifecycle.mjs";

afterEach(() => {
	vi.useRealTimers();
});

// codeData must carry client_id and redirect_uri (required fields), and
// `body.redirect_uri` must match codeData.redirect_uri or /token rejects.
const RP_URI = "https://rp.example/cb";

// PKCE is mandatory for every authorization-code client, so a redeemable
// code record always carries an S256 challenge and every token request that is
// meant to reach a non-PKCE branch has to present the matching verifier.
const CODE_VERIFIER = "pkce-verifier".padEnd(43, "x");
const S256_CHALLENGE = crypto.createHash("sha256").update(CODE_VERIFIER).digest("base64url");

/**
 * What `/authorize` records of how the session had authenticated over a
 * record whose primary cannot be told: one that carries no `authentication`
 * and an `amr` that names no primary, as most records stubbed here do. A
 * code over a record that names one carries it as `/authorize` records it.
 */
const UNTOLD = { primary: undefined, mfaAt: undefined };

const validCode = {
	client_id: "client1",
	redirect_uri: RP_URI,
	code_challenge: S256_CHALLENGE,
	code_challenge_method: "S256",
	authentication: UNTOLD,
};

// The authorization grant requires `ctx.authenticatedClient` to be present and
// match `codeData.client_id`. Tests default to "client1", validCode's
// client_id, so they pass the binding gate.
const DEFAULT_AUTH_CLIENT = {
	clientId: "client1",
	tokenEndpointAuthMethod: "client_secret_basic" as const,
};

const mockConfig = {
	oauth: {
		jwt: { secret: "test-secret" },
		accessToken: { defaultExpiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {
			session: { enabled: true },
			authorization_code: { enabled: true },
			refresh_token: { enabled: true },
		},
	},
};

const mockClientRepository: ClientRepository = {
	findById: vi.fn().mockResolvedValue(null),
	authenticate: vi.fn().mockResolvedValue(null),
};

function makeDeps(
	consumeByCodeImpl: CodeRepository["consumeByCode"],
	clientRepository?: ClientRepository,
) {
	return {
		sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
		grantHandlerResolver: registeredGrants("refresh_token"),
		...grantSettingsFrom(mockConfig),
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

describe("createAuthorizationGrant — where a user-session store is wired, core's session lifecycle is required", () => {
	const withSessions = (sessionLifecycleStore?: SessionLifecycleStore) =>
		({
			...makeDeps(vi.fn()),
			userSessionStore: {} as UserSessionStore,
			sessionLifecycle: {} as SessionLifecycle,
			...(sessionLifecycleStore === undefined ? {} : { sessionLifecycleStore }),
		}) as Parameters<typeof createAuthorizationGrant>[0];

	it("refuses to build with userSessionStore and sessionLifecycle wired and no sessionLifecycleStore, naming the slot", () => {
		expect(() => createAuthorizationGrant(withSessions())).toThrow(
			/^The authorization_code grant: userSessionStore is wired, but sessionLifecycleStore is not\.[\s\S]*sessionLifecycleModule\.$/,
		);
	});

	it("builds with all three wired", () => {
		expect(() => createAuthorizationGrant(withSessions({} as SessionLifecycleStore))).not.toThrow();
	});
});

describe("createAuthorizationGrant — the lifetimes it mints with", () => {
	// A slot filled by hand never met boot's check. Read when the grant is
	// built, a bad lifetime is a composition fault that never reaches a code;
	// read per request, it would be refused only after `consumeByCode` had spent
	// the code: a 500, and a code the client can never redeem.
	const settings = createTestOAuthTokenSettings();
	const broken: Array<[string, Record<string, unknown>]> = [
		["refreshTokenExpiresIn = 1.5", { ...settings, refreshTokenExpiresIn: 1.5 }],
		["refreshTokenExpiresIn = NaN", { ...settings, refreshTokenExpiresIn: Number.NaN }],
		["refreshTokenExpiresIn = 0", { ...settings, refreshTokenExpiresIn: 0 }],
		["no refreshTokenExpiresIn", { ...settings, refreshTokenExpiresIn: undefined }],
		[
			"accessTokenLifetime.defaultExpiresIn = 1.5",
			{ ...settings, accessTokenLifetime: { defaultExpiresIn: 1.5, maxExpiresIn: 3600 } },
		],
	];
	for (const [label, over] of broken) {
		it(`is refused when it is built with an oauthTokenSettings slot whose ${label}, and no code is spent`, async () => {
			const codes = new InMemoryCodeRepository();
			try {
				const { code } = await codes.createCode({
					client_id: "client1",
					redirect_uri: RP_URI,
					code_challenge: S256_CHALLENGE,
					code_challenge_method: "S256",
					grantedScope: ["read"],
					grantedAudience: undefined,
					nonce: undefined,
					sid: undefined,
					acr: undefined,
					amr: undefined,
					authentication: undefined,
				});
				const deps = {
					...makeDeps(vi.fn()),
					codeRepository: codes,
					oauthTokenSettings: over as never,
				};

				let refused: unknown;
				let handler: GrantHandler | undefined;
				try {
					handler = createAuthorizationGrant(deps);
				} catch (err) {
					refused = err;
				}
				// Were it built, this is the redemption that would spend the code.
				await handler
					?.handle({
						body: {
							code,
							client_id: "client1",
							redirect_uri: RP_URI,
							code_verifier: CODE_VERIFIER,
						},
						session: { user: { id: "u1" } },
						issuer: "localhost",
						metadata: {},
						authenticatedClient: DEFAULT_AUTH_CLIENT,
					})
					.catch(() => undefined);

				expect(await codes.findByCode(code)).not.toBeNull();
				expect(refused).toBeInstanceOf(RangeError);
				expect((refused as Error).message).toMatch(
					/oauthTokenSettings\.(refreshTokenExpiresIn|accessTokenLifetime)/,
				);
			} finally {
				codes.dispose();
			}
		});
	}
});

describe("createAuthorizationGrant — the lifetimes come from the oauthTokenSettings slot", () => {
	it("mints the slot's lifetimes, read once when it is built", async () => {
		// Read once, in the factory, from the slot boot hands it frozen: a
		// change to `oauth.*` takes a restart. The README says so; this pins
		// that the slot, not the configuration, decides.
		const handler = createAuthorizationGrant({
			...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "sid-1", ...validCode })),
			oauthTokenSettings: createTestOAuthTokenSettings({
				accessTokenLifetime: { defaultExpiresIn: 600, maxExpiresIn: 600 },
				refreshTokenExpiresIn: 7200,
			}),
		});

		const { result } = await handler.handle({
			body: {
				code: "abc",
				client_id: "client1",
				redirect_uri: RP_URI,
				code_verifier: CODE_VERIFIER,
			},
			session: { user: { id: "u1" } },
			issuer: "localhost",
			metadata: {},
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		});
		if (!("tokens" in result)) throw new Error(`expected tokens, got ${result.status}`);
		const at = decodeJwt(result.tokens.access_token);
		const rt = decodeJwt(result.tokens.refresh_token as string);
		expect((at.exp as number) - (at.iat as number)).toBe(600);
		expect((rt.exp as number) - (rt.iat as number)).toBe(7200);
	});
});

describe("createAuthorizationGrant", () => {
	describe("handle", () => {
		it("returns 400 when code is missing", async () => {
			const deps = makeDeps(vi.fn().mockResolvedValue({ code: "abc", code_challenge: undefined }));
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { client_id: "client1" },
				session: { code: "abc" },
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
				session: { code: "abc" },
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
				session: { code: "abc" },
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
			// Only `code` is in the clear list: /authorize does not write
			// `code_client_id` or `granted_scopes`, so the grant has nothing of theirs
			// to clear.
			expect(sessionMutation).toBeDefined();
			expect(sessionMutation?.clear).toContain("code");
			expect(sessionMutation?.clear).not.toContain("code_client_id");
			expect(sessionMutation?.clear).not.toContain("code_redirect_uri");
			expect(sessionMutation?.clear).not.toContain("granted_scopes");
		});

		it("mints the configured default lifetime and ignores an expires_in request parameter", async () => {
			// `expires_in` is the time left when answered: read on a frozen clock.
			vi.useFakeTimers({ toFake: ["Date"], now: Date.now() });
			// The lifetime is read through `resolveAccessTokenLifetime`. Only token
			// exchange honours `expires_in`.
			const deps = {
				...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "test-sid-1", ...validCode })),
				...grantSettingsFrom({
					oauth: {
						...mockConfig.oauth,
						accessToken: { defaultExpiresIn: 600, maxExpiresIn: 7200 },
					},
				}),
			};
			const handler = createAuthorizationGrant(deps);
			const { result } = await handler.handle({
				body: {
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
					code_verifier: CODE_VERIFIER,
					expires_in: "7200",
				},
				session: { code: "abc", user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});

			if (!("tokens" in result)) throw new Error(`expected tokens, got ${result.status}`);
			expect(result.tokens.expires_in).toBe(600);
			const decoded = decodeJwt(result.tokens.access_token);
			expect((decoded.exp as number) - (decoded.iat as number)).toBe(600);
		});

		it("registers initial rt+jwt via refreshTokenFamilyRotation.register", async () => {
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

		it("returns 503 temporarily_unavailable when refreshTokenFamilyRotation.register throws", async () => {
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

		it("returns 200 when no refreshTokenFamilyRotation is configured", async () => {
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
					user: { id: "u1" },
				},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});
			expect(result.status).toBe(200);
		});

		it("issues an initial rt+jwt carrying a new family_id", async () => {
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

		it("answers no empty-string scope, and mints no scope claim, when granted scopes is empty", async () => {
			// The code carries no grantedScope.
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

		it("echoes the code's granted scope in the token response (RFC 6749 §3.3)", async () => {
			// The honesty half of keeping silent narrowing at /authorize: the
			// grant the client actually received is visible on the wire. The
			// narrowing half (request "read bogus" → code carries ["read"]) is
			// pinned in authorizeEndpoint.test.mts.
			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
					code_challenge: S256_CHALLENGE,
					code_challenge_method: "S256",
					sid: "test-sid-1",
					authentication: UNTOLD,
					grantedScope: ["read"] as readonly string[],
				}),
			);
			const handler = createAuthorizationGrant(deps);
			const { result } = await handler.handle({
				body: {
					code: "abc",
					redirect_uri: RP_URI,
					code_verifier: CODE_VERIFIER,
				},
				session: {},
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});

			expect(result.status).toBe(200);
			if (!("tokens" in result)) throw new Error("expected tokens");
			expect(result.tokens.scope).toBe("read");
		});

		it("mints no scope claim when Code.grantedScope is explicitly empty", async () => {
			// Even if persisted as [], code exchange must not emit `scope: ""`.
			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
					code_challenge: S256_CHALLENGE,
					code_challenge_method: "S256",
					sid: "test-sid-1",
					authentication: UNTOLD,
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
			// The body deliberately omits `code_verifier`. Asserting the
			// errorDescription keeps the case honest: a bare `status === 400` also
			// passes when the request fails for an unrelated reason (a verifier that
			// simply does not match, say).
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
				session: { code: "abc" },
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
				session: { code: "abc" },
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
				session: { code: "abc" },
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
				session: { code: "abc" },
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
					authentication: UNTOLD,
					code_challenge: challenge,
					code_challenge_method: "S256",
				}),
			);
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1", redirect_uri: RP_URI, code_verifier: verifier },
				session: { code: "abc" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
		});

		it("returns 200 when plain PKCE code_verifier matches challenge — opted-in client only", async () => {
			// `plain` is reachable ONLY through the client registration's
			// `allowPlainPkce: true`. The grant reads it off the authenticated
			// client, which is the same record /authorize consulted.
			const verifier = "b".repeat(43);
			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
					sid: "test-sid-1",
					authentication: UNTOLD,
					code_challenge: verifier,
					code_challenge_method: "plain",
				}),
			);
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1", redirect_uri: RP_URI, code_verifier: verifier },
				session: { code: "abc" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: { ...DEFAULT_AUTH_CLIENT, allowPlainPkce: true },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
		});

		it("returns 400 for the same plain code when the client has no opt-in", async () => {
			const verifier = "b".repeat(43);
			const deps = makeDeps(
				vi.fn().mockResolvedValue({
					code: "abc",
					client_id: "client1",
					redirect_uri: RP_URI,
					sid: "test-sid-1",
					authentication: UNTOLD,
					code_challenge: verifier,
					code_challenge_method: "plain",
				}),
			);
			const handler = createAuthorizationGrant(deps);
			const ctx: GrantContext = {
				body: { code: "abc", client_id: "client1", redirect_uri: RP_URI, code_verifier: verifier },
				session: { code: "abc" },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			expect("error" in result && result.error).toBe("invalid_request");
		});

		// A config still setting the legacy `pkce.requireS256` changes nothing in
		// either direction: S256 is mandatory whatever it says.
		describe("legacy pkce.requireS256 is inert", () => {
			const legacyConfig = (requireS256: boolean) => ({
				oauth: {
					jwt: { secret: "test-secret" },
					accessToken: { defaultExpiresIn: 3600 },
					refreshToken: { expiresIn: 86400 },
					grants: {
						session: { enabled: true },
						authorization_code: { enabled: true, pkce: { requireS256 } },
						refresh_token: { enabled: true },
					},
				},
			});

			const makeLegacyDeps = (requireS256: boolean, codeData: Record<string, unknown>) => ({
				sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
				grantHandlerResolver: registeredGrants("refresh_token"),
				...grantSettingsFrom(legacyConfig(requireS256)),
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
				session: { code: "abc" },
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
				"rejects a PKCE-less code as invalid_request with requireS256=%s",
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

		// redirect_uri is a required field on CodeData and the binding check is
		// unconditional: no pass when none is stored, and no fallback to
		// session.code_redirect_uri.
		describe("redirect_uri binding", () => {
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
						authentication: UNTOLD,
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
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(200);
			});

			it("returns invalid_grant for a loopback redirect_uri on another port than the stored one — the equality stays exact", async () => {
				// /authorize may admit a presented `redirect_uri` whose loopback
				// port differs from the registration (RFC 8252 §7.3), and it
				// binds the URI it actually used to the code record. RFC 6749
				// §4.1.3 is a different question — "is this the URI this code
				// was issued for" — so it is answered by exact equality, port
				// included, and a second listener on another port cannot redeem
				// the first one's code.
				const deps = makeDeps(
					vi.fn().mockResolvedValue({
						code: "abc",
						sid: "test-sid-1",
						authentication: UNTOLD,
						client_id: "client1",
						redirect_uri: "http://127.0.0.1:49152/cb",
						code_challenge: S256_CHALLENGE,
						code_challenge_method: "S256",
					}),
				);
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: {
						code: "abc",
						client_id: "client1",
						redirect_uri: "http://127.0.0.1:51000/cb",
						code_verifier: CODE_VERIFIER,
					},
					session: { code: "abc" },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(400);
				expect("error" in result && result.error).toBe("invalid_grant");
			});

			it("rejects when codeData has no redirect_uri", async () => {
				// codeData.redirect_uri is required and the binding check is
				// unconditional, so a record without one is refused.
				const deps = makeDeps(
					vi.fn().mockResolvedValue({
						code: "abc",
						sid: "test-sid-1",
						authentication: UNTOLD,
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
					session: { code: "abc" },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(400);
				expect("error" in result && result.error).toBe("invalid_grant");
			});
		});

		// RFC 6749 §2.3 client authentication is `clientAuthMw`'s, at the route
		// (covered in `clientAuth.test.mts` and `routes.test.mts`). The grant trusts
		// `ctx.authenticatedClient` and verifies only the binding
		// `codeData.client_id === authenticatedClient.clientId`, pinned here.
		describe("binding gate: codeData.client_id vs ctx.authenticatedClient.clientId", () => {
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
				// reject, or any authenticated client could redeem any code.
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

		// PKCE is one fixed policy plus a per-client `plain` opt-in. No server-wide
		// config (the legacy `supportedMethods` / `defaultMethod` / `required`
		// keys) can widen it.
		describe("PKCE policy is fixed, not configurable", () => {
			function makePkceConfig(pkce: Record<string, unknown>) {
				return {
					oauth: {
						jwt: { secret: "test-secret" },
						accessToken: { defaultExpiresIn: 3600 },
						refreshToken: { expiresIn: 86400 },
						grants: {
							authorization_code: {
								enabled: true,
								pkce,
							},
						},
					},
				};
			}

			const makeConfiguredDeps = (
				pkce: Record<string, unknown>,
				codeData: Record<string, unknown>,
			) => ({
				sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
				grantHandlerResolver: registeredGrants("refresh_token"),
				...grantSettingsFrom(makePkceConfig(pkce)),
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
				session: { code: "abc" },
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
				// Not even `required: false` makes PKCE optional for a confidential
				// client.
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

		describe("id_token issuance on openid scope", () => {
			// id_token issuance reads the issuer from the oauthTokenSettings slot
			// (not ctx.issuer), so the request-derived host fallback never becomes
			// an OIDC iss claim.
			const mockConfigWithIssuer = {
				oauth: {
					jwt: { secret: "test-secret", issuer: "https://auth.example.com" },
					accessToken: { defaultExpiresIn: 3600 },
					refreshToken: { expiresIn: 86400 },
					grants: {
						session: { enabled: true },
						authorization_code: { enabled: true },
						refresh_token: { enabled: true },
					},
				},
			};

			function makeDepsWithIssuer(
				consumeByCodeImpl: CodeRepository["consumeByCode"],
				clientRepository?: ClientRepository,
			) {
				return {
					sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
					grantHandlerResolver: registeredGrants("refresh_token"),
					...grantSettingsFrom(mockConfigWithIssuer),
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
				amr?: readonly string[];
				/** Absent: a session written before the key existed (see the MFA ADR). */
				authentication?: SessionAuthentication;
			}) {
				return {
					kind: "spy",
					async create() {},
					async get(querySid: string): Promise<UserSession | null> {
						if (querySid !== session.sid) return null;
						return {
							sid: session.sid,
							sub: session.sub,
							authTime: session.authTime,
							createdAt: new Date(),
							expiresAt: new Date(Date.now() + 3600_000),
							claims: session.claims,
							amr: session.amr,
							authentication: session.authentication,
						};
					},
					async delete() {},
				};
			}

			it("includes id_token in response when scope contains 'openid' and userSessionStore is wired", async () => {
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
							authentication: UNTOLD,
							nonce: "client-nonce",
							grantedScope: ["openid", "email"],
						}),
					),
					userSessionStore,
					sessionLifecycleStore: lifecycleStoreOver(userSessionStore),
					sessionLifecycle: joiningLifecycle().lifecycle,
				};
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: {
						code: "c1",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_verifier: CODE_VERIFIER,
					},
					session: { code: "c1" },
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

			it("carries amr and acr from the code record, not the session's, and mirrors both into the access and refresh tokens", async () => {
				const authTime = new Date("2026-04-21T00:00:00Z");
				const userSessionStore = makeUserSessionStore({
					sid: "sid-1",
					sub: "u-1",
					authTime,
					claims: {},
					amr: ["pwd"],
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
							// What /authorize recorded of a password session it admitted
							// with a second factor: more than the record holds now.
							authentication: { primary: "pwd", mfaAt: new Date("2026-04-21T00:10:00Z") },
							grantedScope: ["openid"],
							acr: "urn:example:mfa",
							amr: ["pwd", "otp", "mfa"],
						}),
					),
					userSessionStore,
					sessionLifecycleStore: lifecycleStoreOver(userSessionStore),
					sessionLifecycle: joiningLifecycle().lifecycle,
				};
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: {
						code: "c1",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_verifier: CODE_VERIFIER,
					},
					session: { code: "c1" },
					issuer: "https://auth.example.com",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				});
				expect(result.status).toBe(200);
				if (!("tokens" in result)) throw new Error("expected tokens");
				const id = decodeJwt(result.tokens.id_token as string) as Record<string, unknown>;
				expect(id.amr).toEqual(["pwd", "otp", "mfa"]);
				expect(id.acr).toBe("urn:example:mfa");
				expect(id.auth_time).toBe(Math.floor(authTime.getTime() / 1000));
				const at = decodeJwt(result.tokens.access_token as string) as Record<string, unknown>;
				expect(at.amr).toEqual(["pwd", "otp", "mfa"]);
				expect(at.acr).toBe("urn:example:mfa");
				// The refresh token carries them too: `amr` and `acr` live on the code,
				// which is spent here, so the refresh grant has nowhere else to read
				// them from, and a resource server gating on `amr` must not see it
				// vanish at the first refresh.
				const rt = decodeJwt(result.tokens.refresh_token as string) as Record<string, unknown>;
				expect(rt.amr).toEqual(["pwd", "otp", "mfa"]);
				expect(rt.acr).toBe("urn:example:mfa");
			});

			it.each([
				["an empty amr", []],
				["an amr with an empty element", ["pwd", ""]],
			])("stamps no amr on any token for a code carrying %s", async (_label, amr) => {
				// Every grant reads `amr` through one predicate, so the first refresh
				// token cannot carry an `amr: []` the refresh grant then drops.
				const userSessionStore = makeUserSessionStore({
					sid: "sid-1",
					sub: "u-1",
					authTime: new Date("2026-04-21T00:00:00Z"),
					claims: {},
					amr: ["pwd"],
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
							authentication: { primary: "pwd", mfaAt: undefined },
							grantedScope: ["openid"],
							amr,
						}),
					),
					userSessionStore,
					sessionLifecycleStore: lifecycleStoreOver(userSessionStore),
					sessionLifecycle: joiningLifecycle().lifecycle,
				};
				const { result } = await createAuthorizationGrant(deps).handle({
					body: {
						code: "c1",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_verifier: CODE_VERIFIER,
					},
					session: { code: "c1" },
					issuer: "https://auth.example.com",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				});
				if (!("tokens" in result)) throw new Error("expected tokens");
				for (const token of ["id_token", "access_token", "refresh_token"] as const) {
					expect(decodeJwt(result.tokens[token] as string), token).not.toHaveProperty("amr");
				}
			});

			/**
			 * Redeems the code "c1" bound to "sid-1" against `userSessionStore`, when
			 * one is given, the code carrying `authentication` as `/authorize`
			 * recorded it over that record.
			 */
			const redeemSessionCode = async (
				userSessionStore?: ReturnType<typeof makeUserSessionStore>,
				authentication: unknown = UNTOLD,
			) => {
				const deps = {
					...makeDepsWithIssuer(
						vi.fn().mockResolvedValue({
							code: "c1",
							client_id: "client1",
							redirect_uri: RP_URI,
							code_challenge: S256_CHALLENGE,
							code_challenge_method: "S256",
							sid: "sid-1",
							authentication,
							grantedScope: ["openid"],
						}),
					),
					...(userSessionStore
						? {
								userSessionStore,
								sessionLifecycleStore: lifecycleStoreOver(userSessionStore),
								sessionLifecycle: joiningLifecycle().lifecycle,
							}
						: {}),
				};
				const { result } = await createAuthorizationGrant(deps).handle({
					body: {
						code: "c1",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_verifier: CODE_VERIFIER,
					},
					session: { code: "c1", user: { id: "u-1" } },
					issuer: "https://auth.example.com",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				});
				if (!("tokens" in result))
					throw new Error(`expected tokens, got ${JSON.stringify(result)}`);
				return result.tokens;
			};

			it("stamps the session's auth_time on the access and refresh tokens, as on the id_token", async () => {
				const authTime = new Date("2026-04-21T00:00:00.750Z");
				const tokens = await redeemSessionCode(
					makeUserSessionStore({ sid: "sid-1", sub: "u-1", authTime, claims: {}, amr: ["pwd"] }),
					{ primary: "pwd", mfaAt: undefined },
				);
				const seconds = Math.floor(authTime.getTime() / 1000);
				expect(decodeJwt(tokens.id_token as string).auth_time).toBe(seconds);
				expect(decodeJwt(tokens.access_token).auth_time).toBe(seconds);
				expect(decodeJwt(tokens.refresh_token as string).auth_time).toBe(seconds);
			});

			it("stamps the primary authentication's time, not when a second factor was verified", async () => {
				const authTime = new Date("2026-04-21T00:00:00Z");
				const tokens = await redeemSessionCode(
					makeUserSessionStore({
						sid: "sid-1",
						sub: "u-1",
						authTime,
						claims: {},
						amr: ["pwd", "otp", "mfa"],
						authentication: {
							primary: "pwd",
							federation: undefined,
							upstreamAmr: undefined,
							mfaAt: new Date("2026-04-21T00:10:00Z"),
						},
					}),
					{ primary: "pwd", mfaAt: new Date("2026-04-21T00:10:00Z") },
				);
				const seconds = Math.floor(authTime.getTime() / 1000);
				expect(decodeJwt(tokens.access_token).auth_time).toBe(seconds);
				expect(decodeJwt(tokens.refresh_token as string).auth_time).toBe(seconds);
			});

			it("stamps when this provider established the session, not when a federation's upstream last authenticated the user", async () => {
				const authTime = new Date("2026-04-21T00:00:00Z");
				const tokens = await redeemSessionCode(
					makeUserSessionStore({
						sid: "sid-1",
						sub: "u-1",
						authTime,
						claims: {},
						amr: ["fed"],
						authentication: {
							primary: "fed",
							federation: "google",
							upstreamAmr: undefined,
							mfaAt: undefined,
							upstreamAuthTime: new Date("2026-04-20T00:00:00Z"),
						},
					}),
					{ primary: "fed", mfaAt: undefined },
				);
				const seconds = Math.floor(authTime.getTime() / 1000);
				expect(decodeJwt(tokens.id_token as string).auth_time).toBe(seconds);
				expect(decodeJwt(tokens.access_token).auth_time).toBe(seconds);
			});

			it("stamps no auth_time without a userSessionStore, which records no authentication", async () => {
				const tokens = await redeemSessionCode();
				expect(decodeJwt(tokens.access_token)).not.toHaveProperty("auth_time");
				expect(decodeJwt(tokens.refresh_token as string)).not.toHaveProperty("auth_time");
			});

			it("stamps the slot's issuer on the id_token when the request carries none (never an OIDC-noncompliant iss:'')", async () => {
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
							authentication: UNTOLD,
							grantedScope: ["openid", "email"],
							nonce: "client-nonce",
						}),
					),
					userSessionStore,
					sessionLifecycleStore: lifecycleStoreOver(userSessionStore),
					sessionLifecycle: joiningLifecycle().lifecycle,
				};
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: {
						code: "c-noiss",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_verifier: CODE_VERIFIER,
					},
					session: { code: "c-noiss" },
					// issuer intentionally omitted
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				});

				expect(result.status).toBe(200);
				if (!("tokens" in result)) throw new Error("expected tokens");
				expect(typeof result.tokens.access_token).toBe("string");
				expect(decodeJwt(result.tokens.id_token as string).iss).toBe(
					grantSettingsFrom(mockConfig).oauthTokenSettings.issuer,
				);
			});

			it("does NOT include id_token when scope lacks openid", async () => {
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
							authentication: UNTOLD,
							grantedScope: ["profile", "email"],
						}),
					),
					userSessionStore,
					sessionLifecycleStore: lifecycleStoreOver(userSessionStore),
					sessionLifecycle: joiningLifecycle().lifecycle,
				};
				const handler = createAuthorizationGrant(deps);
				const { result } = await handler.handle({
					body: {
						code: "c2",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_verifier: CODE_VERIFIER,
					},
					session: { code: "c2" },
					issuer: "https://auth.example.com",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				});

				expect(result.status).toBe(200);
				if (!("tokens" in result)) throw new Error("expected tokens");
				expect(typeof result.tokens.access_token).toBe("string");
				expect(result.tokens.id_token).toBeUndefined();
			});

			it("does NOT include id_token when userSessionStore is not wired", async () => {
				// No userSessionStore — cannot resolve claims, so id_token is skipped.
				const deps = makeDepsWithIssuer(
					vi.fn().mockResolvedValue({
						code: "c3",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_challenge: S256_CHALLENGE,
						code_challenge_method: "S256",
						sid: "sid-3",
						authentication: UNTOLD,
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
					session: { code: "c3" },
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

		// Identity gates read the code record, not the Express session:
		// consumeByCode (atomic getDel on a single Redis node) is the sole
		// authenticity gate, and client_id and redirect_uri are verified against
		// codeData fields populated at /authorize time.
		describe("identity gates derive from codeData, not session", () => {
			/** A session carrying `code_client_id`, a key no writer sets: no gate may read it. */
			const withCodeClientId = (
				session: GrantContext["session"] & { readonly code_client_id: string },
			): GrantContext["session"] => session;

			it("rejects when body.redirect_uri is missing, though the session matches the body", async () => {
				// session.code / session.code_client_id match the body, so a
				// session-based gate would let this through; only the redirect_uri
				// check can refuse it.
				const deps = makeDeps(
					vi.fn().mockResolvedValue({
						code: "abc",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_challenge: S256_CHALLENGE,
						code_challenge_method: "S256",
						sid: "test-sid-1",
						authentication: UNTOLD,
					}),
				);
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: {
						code: "abc",
						client_id: "client1" /* no redirect_uri */,
						code_verifier: CODE_VERIFIER,
					},
					session: withCodeClientId({ code: "abc", code_client_id: "client1", user: { id: "u1" } }),
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(400);
				expect("error" in result && result.error).toBe("invalid_grant");
			});

			it("rejects a body.redirect_uri that differs from codeData.redirect_uri, though the session matches the body", async () => {
				const deps = makeDeps(
					vi.fn().mockResolvedValue({
						code: "abc",
						client_id: "client1",
						redirect_uri: RP_URI,
						code_challenge: S256_CHALLENGE,
						code_challenge_method: "S256",
						sid: "test-sid-1",
						authentication: UNTOLD,
					}),
				);
				const handler = createAuthorizationGrant(deps);
				const ctx: GrantContext = {
					body: {
						code: "abc",
						client_id: "client1",
						redirect_uri: "https://attacker.example/steal",
					},
					session: withCodeClientId({ code: "abc", code_client_id: "client1", user: { id: "u1" } }),
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(400);
				expect("error" in result && result.error).toBe("invalid_grant");
			});

			it("rejects when codeData.client_id differs from the body's, though session.code_client_id matches it", async () => {
				// session.code_client_id MATCHES the body, so a session-based gate
				// (`client_id !== session.code_client_id`) would let the request through.
				// The gate must reject because codeData.client_id differs from the body's.
				const deps = makeDeps(
					vi.fn().mockResolvedValue({
						code: "abc",
						sid: "test-sid-1",
						authentication: UNTOLD,
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
					session: withCodeClientId({
						code: "abc",
						// matches body.client_id: a session-based gate would pass.
						code_client_id: "spoofed-client",
						user: { id: "u1" },
					}),
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				};

				const { result } = await handler.handle(ctx);

				expect(result.status).toBe(400);
				expect("error" in result && result.error).toBe("invalid_grant");
			});
		});

		describe("family_id + sid claims, RP registration", () => {
			it("happy path: access_token and refresh_token both carry family_id and sid claims", async () => {
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

			it("returns 400 invalid_grant when code record has no sid and userSessionStore IS wired", async () => {
				// A code record without sid. When the store is wired, sid is required so
				// the store can link/register.
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
					sessionLifecycleStore: lifecycleStoreOver(userSessionStore),
					sessionLifecycle: joiningLifecycle().lifecycle,
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

			it("no userSessionStore + no sid → grant succeeds without sid claim", async () => {
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

			it("joins the family and the RP to the session through the lifecycle when userSessionStore is wired", async () => {
				const { lifecycle, join } = joiningLifecycle();
				const userSessionStore = {
					kind: "spy",
					async create() {},
					async get() {
						// Return a minimal session so the existence check passes.
						return {
							sid: "session-xyz",
							sub: "u1",
							authTime: new Date(),
							createdAt: new Date(),
							expiresAt: new Date(Date.now() + 3600_000),
							claims: {},
							amr: undefined,
							authentication: undefined,
						};
					},
					async delete() {},
				};
				const deps = {
					...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "session-xyz", ...validCode })),
					userSessionStore,
					sessionLifecycleStore: lifecycleStoreOver(userSessionStore),
					sessionLifecycle: lifecycle,
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
						user: { id: "u1" },
					},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				});

				expect(result.status).toBe(200);
				expect(join).toHaveBeenCalledTimes(1);
				expect(join).toHaveBeenCalledWith("session-xyz", {
					rp: expect.objectContaining({ clientId: "client1", registeredAt: expect.any(Date) }),
					familyId: expect.stringMatching(
						/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
					),
				});
				// The family joined is the one the tokens carry.
				if (!("tokens" in result)) throw new Error("expected tokens");
				expect(join.mock.calls[0]?.[1].familyId).toBe(
					decodeJwt(result.tokens.access_token).family_id,
				);
			});

			it.each([
				["sid wanted on neither channel", false, false],
				["sid wanted on the back-channel only", true, false],
				["sid wanted on the front-channel only", false, true],
			])(
				"joins the RP with every logout field the client record carries — %s",
				async (_label, backchannelSessionRequired, frontchannelSessionRequired) => {
					// Each of the four fields is asserted with its own value: the types catch
					// a field forgotten, not two same-typed fields swapped.
					const { lifecycle, join } = joiningLifecycle();
					const clientRepository: ClientRepository = {
						...mockClientRepository,
						findById: vi.fn().mockResolvedValue({
							clientId: "client1",
							tokenEndpointAuthMethod: "client_secret_basic",
							allowedRedirectUris: [RP_URI],
							allowedScopes: ["read"],
							backchannelLogoutUri: "https://rp.example/back",
							backchannelLogoutSessionRequired: backchannelSessionRequired,
							frontchannelLogoutUri: "https://rp.example/front",
							frontchannelLogoutSessionRequired: frontchannelSessionRequired,
						}),
					};
					const deps = {
						...makeDeps(
							vi.fn().mockResolvedValue({ code: "abc", sid: "session-xyz", ...validCode }),
							clientRepository,
						),
						userSessionStore: {
							kind: "spy",
							async create() {},
							async get() {
								return {
									sid: "session-xyz",
									sub: "u1",
									authTime: new Date(),
									createdAt: new Date(),
									expiresAt: new Date(Date.now() + 3600_000),
									claims: {},
									amr: undefined,
									authentication: undefined,
								};
							},
							async delete() {},
						},
						sessionLifecycleStore: openingLifecycleStore("u1"),
						sessionLifecycle: lifecycle,
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
							user: { id: "u1" },
						},
						issuer: "localhost",
						metadata: { ip: "127.0.0.1" },
						authenticatedClient: DEFAULT_AUTH_CLIENT,
					});

					expect(result.status).toBe(200);
					expect(join).toHaveBeenCalledTimes(1);
					expect(join).toHaveBeenCalledWith("session-xyz", {
						rp: expect.objectContaining({
							clientId: "client1",
							backchannelLogoutUri: "https://rp.example/back",
							backchannelLogoutSessionRequired: backchannelSessionRequired,
							frontchannelLogoutUri: "https://rp.example/front",
							frontchannelLogoutSessionRequired: frontchannelSessionRequired,
						}),
						familyId: expect.any(String),
					});
				},
			);

			describe("a frontchannelLogoutUri must be http(s)", () => {
				/** One code exchange against `record`; the RP it joined to the session and the logger. */
				const exchangeWith = async (record: object, warn?: () => void, wired = true) => {
					const { result, join, logger } = await attempt(record, warn, wired);
					expect(join).toHaveBeenCalledTimes(1);
					const rpData = join.mock.calls[0]?.[1].rp;
					if (rpData === undefined) throw new Error("expected the exchange to join an RP");
					return { result, rpData, logger };
				};

				/** One code exchange against `record`: its result, the lifecycle's `join` spy and the logger. */
				const attempt = async (record: object, warn?: () => void, wired = true) => {
					const { lifecycle, join } = joiningLifecycle();
					const logger = createMockLogger();
					if (warn !== undefined) logger.warn.mockImplementation(warn);
					const clientRepository: ClientRepository = {
						...mockClientRepository,
						findById: vi.fn().mockResolvedValue(record),
					};
					const handler = createAuthorizationGrant({
						...makeDeps(
							vi.fn().mockResolvedValue({ code: "abc", sid: "session-xyz", ...validCode }),
							clientRepository,
						),
						userSessionStore: {
							kind: "spy",
							async create() {},
							async get() {
								return {
									sid: "session-xyz",
									sub: "u1",
									authTime: new Date(),
									createdAt: new Date(),
									expiresAt: new Date(Date.now() + 3600_000),
									claims: {},
									amr: undefined,
									authentication: undefined,
								};
							},
							async delete() {},
						},
						sessionLifecycleStore: openingLifecycleStore("u1"),
						sessionLifecycle: lifecycle,
						...(wired ? { logger } : {}),
					});
					const { result } = await handler.handle({
						body: {
							code: "abc",
							client_id: "client1",
							redirect_uri: RP_URI,
							code_verifier: CODE_VERIFIER,
						},
						session: { code: "abc", user: { id: "u1" } },
						issuer: "localhost",
						metadata: { ip: "127.0.0.1" },
						authenticatedClient: DEFAULT_AUTH_CLIENT,
					});
					return { result, join, logger };
				};

				/**
				 * What a refused record leaves: one `client_record_refused` warn and
				 * one `client_repository_unavailable` line naming the refusal as its
				 * cause, both naming the authenticated id.
				 */
				const expectRecordRefused = (logger: ReturnType<typeof createMockLogger>) => {
					const refused = logger.warn.mock.calls.filter(
						([, event]) => event === "client_record_refused",
					);
					expect(refused).toHaveLength(1);
					expect(refused[0]?.[0]).toMatchObject({ step: "find", clientId: "client1" });
					expect(logger.error.mock.calls).toHaveLength(1);
					expect(logger.error.mock.calls[0]).toEqual([
						expect.objectContaining({
							site: "authorization_code",
							step: "find",
							clientId: "client1",
							err: expect.objectContaining({ reason: "client_record_refused" }),
						}),
						"client_repository_unavailable",
					]);
				};

				/** The answer to a refused record: 503, as for the store's outage. */
				const SESSION_LINKING_UNAVAILABLE = {
					status: 503,
					error: "temporarily_unavailable",
					errorDescription: "session linking unavailable",
				};

				const baseRecord = {
					clientId: "client1",
					tokenEndpointAuthMethod: "client_secret_basic",
					allowedRedirectUris: [RP_URI],
					allowedScopes: ["read"],
					backchannelLogoutUri: "https://rp.example/back",
				};

				it.each([
					["a non-http(s) scheme (lower case)", "javascript:void(0)"],
					["a non-http(s) scheme (upper case)", "JAVASCRIPT:void(0)"],
					// The URL parser strips the tab, so this parses as the scheme above.
					["a non-http(s) scheme (a tab inside the scheme)", "java\tscript:void(0)"],
					["a non-http(s) scheme (a data URL)", "data:text/plain,signed-out"],
					["a non-http(s) scheme (a blob URL)", "blob:https://rp.example/x"],
					["a non-http(s) scheme (a custom scheme)", "com.example.app:/x"],
					["a non-http(s) scheme (an ftp URL)", "ftp://rp.example/front"],
					["a value that is not a URL", "not-a-url"],
					["a value that is not a string", 42],
				])(
					"refuses a record with %s from a custom repository whole: 503, no RP joined, and neither the warn nor the outage line names the URI",
					async (_label, uri) => {
						const { result, join, logger } = await attempt({
							...baseRecord,
							frontchannelLogoutUri: uri,
						});

						expect(result).toMatchObject(SESSION_LINKING_UNAVAILABLE);
						expect(join).not.toHaveBeenCalled();
						expect(logger.warn).toHaveBeenCalledTimes(1);
						expectRecordRefused(logger);
						expectUriNotLogged(logger, String(uri));
					},
				);

				it.each([
					["null", null],
					["an empty string", ""],
				])(
					"refuses a record whose frontchannelLogoutUri is %s whole: 503, and no RP joined",
					async (_label, uri) => {
						const { result, join, logger } = await attempt({
							...baseRecord,
							frontchannelLogoutUri: uri,
						});

						expect(result).toMatchObject(SESSION_LINKING_UNAVAILABLE);
						expect(join).not.toHaveBeenCalled();
						expectRecordRefused(logger);
					},
				);

				it("warns through the console fallback when the grant has no logger", async () => {
					const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
					try {
						const { result, join } = await attempt(
							{ ...baseRecord, frontchannelLogoutUri: "ftp://rp.example/front" },
							undefined,
							false,
						);
						expect(result).toMatchObject(SESSION_LINKING_UNAVAILABLE);
						expect(join).not.toHaveBeenCalled();
						const refused = warn.mock.calls.filter(([, name]) => name === "client_record_refused");
						expect(refused).toHaveLength(1);
						expect(refused[0]?.[0]).toMatchObject({ step: "find", clientId: "client1" });
					} finally {
						warn.mockRestore();
					}
				});

				it("names the authenticated client in the warn and the outage line, not the record's clientId", async () => {
					const { result, logger } = await attempt({
						...baseRecord,
						clientId: "record-client",
						frontchannelLogoutUri: "ftp://rp.example/front",
					});

					expect(result).toMatchObject(SESSION_LINKING_UNAVAILABLE);
					expectRecordRefused(logger);
				});

				it("answers 503 and joins no RP when the refusal's warn throws", async () => {
					const { result, join, logger } = await attempt(
						{ ...baseRecord, frontchannelLogoutUri: "ftp://rp.example/front" },
						() => {
							throw new Error("logger unavailable");
						},
					);

					expect(result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
					expect(join).not.toHaveBeenCalled();
					expect(logger.warn).toHaveBeenCalledTimes(1);
				});

				it("answers a frontchannelLogoutUri whose read throws as a client repository outage: 503, no RP joined", async () => {
					const record = {
						...baseRecord,
						get frontchannelLogoutUri(): string {
							throw new Error("field unavailable");
						},
					};
					const { result, join, logger } = await attempt(record);

					expect(result).toMatchObject({
						status: 503,
						error: "temporarily_unavailable",
						errorDescription: "session linking unavailable",
					});
					expect(join).not.toHaveBeenCalled();
					expect(logger.error.mock.calls.map(([, event]) => event)).toEqual([
						"client_repository_unavailable",
					]);
				});

				it("joins an http(s) frontchannelLogoutUri on any host, with a query or a fragment, without a warn", async () => {
					for (const uri of [
						"https://rp.example/front?state=a",
						"https://rp.example/front#section",
						"http://rp.example/front",
						"http://127.0.0.1:8080/front",
					]) {
						const { rpData, logger } = await exchangeWith({
							...baseRecord,
							frontchannelLogoutUri: uri,
						});
						expect(rpData.frontchannelLogoutUri).toBe(uri);
						expect(logger.warn).not.toHaveBeenCalled();
					}
				});

				it("joins no front-channel entry, silently, for a record without one", async () => {
					const { rpData, logger } = await exchangeWith({
						...baseRecord,
						frontchannelLogoutUri: undefined,
					});
					expect(rpData.frontchannelLogoutUri).toBeUndefined();
					expect(rpData.backchannelLogoutUri).toBe("https://rp.example/back");
					expect(logger.warn).not.toHaveBeenCalled();
				});
			});

			it("issues tokens carrying family_id and sid without userSessionStore", async () => {
				// No userSessionStore in deps — grant must succeed without joining a session.
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

			it("returns 400 invalid_grant naming the session when session was deleted between /authorize and /token", async () => {
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
					sessionLifecycleStore: lifecycleStoreOver(userSessionStore),
					sessionLifecycle: joiningLifecycle().lifecycle,
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

			it("returns 503 temporarily_unavailable when userSessionStore.get throws", async () => {
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
					sessionLifecycleStore: lifecycleStoreOver(userSessionStore),
					sessionLifecycle: joiningLifecycle().lifecycle,
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

			it("returns 503 temporarily_unavailable when clientRepository.findById throws", async () => {
				// findById is inside the try/catch: a throw must produce a controlled 503.
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
							amr: undefined,
							authentication: undefined,
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
					sessionLifecycleStore: lifecycleStoreOver(userSessionStore),
					sessionLifecycle: joiningLifecycle().lifecycle,
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
// TOCTOU: re-validate the session before returning tokens
//
// Between the first `userSessionStore.get(sid)` and the family's add the
// handler awaits `clientRepository.findById`; a logout in that
// window would orphan the just-issued tokens from logout orchestration. A
// second `userSessionStore.get(sid)` immediately before the add refuses a
// session a logout has already deleted. A logout between that read and the
// add is the guarded add's to refuse (`logoutCodeExchange.race.test.mts`).
// ---------------------------------------------------------------------------

describe("TOCTOU re-check of the session before returning tokens", () => {
	it("returns 400 invalid_grant / session_invalidated when session is deleted between findById and the lifecycle join", async () => {
		// First get returns the session (the initial check), second returns null
		// (the re-check immediately before the join).
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
						amr: undefined,
						authentication: undefined,
					};
				}
				return null;
			},
			async delete() {},
		};
		const { lifecycle, join } = joiningLifecycle();
		const logger = createMockLogger();

		const deps = {
			...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "sid-toctou", ...validCode })),
			userSessionStore,
			sessionLifecycleStore: openingLifecycleStore("u1"),
			sessionLifecycle: lifecycle,
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

		// Proof of re-check: get was called twice (first + re-check).
		expect(getCallCount).toBe(2);

		// Negative invariant: nothing joins the session when the second check fails.
		expect(join).not.toHaveBeenCalled();

		// The audit log MUST fire on the session_invalidated rejection.
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
		// The second `get` has its own dedicated try/catch: store-availability
		// failures here surface as `503 / "session store unavailable"`, matching the
		// first-get path and not the lifecycle join's outage (which surfaces as
		// `503 / "session linking unavailable"`).
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
						amr: undefined,
						authentication: undefined,
					};
				}
				throw new Error("store down on second check");
			},
			async delete() {},
		};
		const { lifecycle, join } = joiningLifecycle();
		const deps = {
			...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "sid-blip", ...validCode })),
			userSessionStore,
			sessionLifecycleStore: openingLifecycleStore("u1"),
			sessionLifecycle: lifecycle,
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
		// own try/catch (not the lifecycle join's outage) so operators see a
		// store-availability error description, not a misleading "session linking" one.
		expect((result as { errorDescription?: string }).errorDescription).toBe(
			"session store unavailable",
		);
		expect(getCallCount).toBe(2);
		expect(join).not.toHaveBeenCalled();
	});
});

// ---------------------------------------------------------------------------
// Access/refresh token `sub` binds to the code's UserSession
//
// The token endpoint is a back-channel call for confidential clients: it
// carries no end-user cookie, so `ctx.session.user` is undefined there. The
// subject therefore has to come from the `UserSession` the code points at via
// `sid` — the same source the id_token already uses — with `ctx.session.user`
// left as the fallback only for deployments that wire no session store.
// ---------------------------------------------------------------------------

describe("AT/RT subject derives from the code-bound UserSession", () => {
	const ISSUER = "https://auth.example.com";
	const configWithIssuer = {
		oauth: {
			jwt: { secret: "test-secret", issuer: ISSUER },
			accessToken: { defaultExpiresIn: 3600 },
			refreshToken: { expiresIn: 86400 },
			grants: {
				session: { enabled: true },
				authorization_code: { enabled: true },
				refresh_token: { enabled: true },
			},
		},
	};

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
					amr: undefined,
					authentication: undefined,
				};
			},
			async delete() {},
		};
	}

	it("issues a sub on a cookie-less back-channel code exchange", async () => {
		const deps = {
			...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "sid-259", ...validCode })),
			...grantSettingsFrom(configWithIssuer),
			userSessionStore: makeStore("sid-259", "u-259"),
			sessionLifecycleStore: openingLifecycleStore("u-259"),
			sessionLifecycle: joiningLifecycle().lifecycle,
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
			session: { code: "abc" },
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
			...grantSettingsFrom(configWithIssuer),
			userSessionStore: makeStore("sid-259", "u-259"),
			sessionLifecycleStore: openingLifecycleStore("u-259"),
			sessionLifecycle: joiningLifecycle().lifecycle,
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
			session: { code: "abc", user: { id: "other-user" } },
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
					amr: undefined,
					authentication: undefined,
				};
			},
			async delete() {},
		};
		const { lifecycle, join } = joiningLifecycle();
		const deps = {
			...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "sid-259", ...validCode })),
			...grantSettingsFrom(configWithIssuer),
			userSessionStore: store,
			sessionLifecycleStore: openingLifecycleStore("u-259"),
			sessionLifecycle: lifecycle,
		};

		const { result } = await createAuthorizationGrant(deps).handle({
			body: {
				code: "abc",
				client_id: "client1",
				redirect_uri: RP_URI,
				code_verifier: CODE_VERIFIER,
			},
			session: { code: "abc" },
			issuer: ISSUER,
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		});

		expect(result.status).toBe(400);
		if (!("error" in result)) throw new Error("expected error");
		expect(result.error).toBe("invalid_grant");
		// Nothing is linked to a session whose identity we could not agree on.
		expect(join).not.toHaveBeenCalled();
	});

	it("refuses when a wired store returns a record with no usable sub", async () => {
		// Gating the request-session fallback on `sub` being nullish rather than
		// on the store being absent would silently revert to the cookie-derived
		// identity here: the cross-user mismatch this handling prevents.
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
					amr: undefined,
					authentication: undefined,
				};
			},
			async delete() {},
		};
		const deps = {
			...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "sid-259", ...validCode })),
			...grantSettingsFrom(configWithIssuer),
			userSessionStore: store,
			sessionLifecycleStore: openingLifecycleStore("u-259"),
			sessionLifecycle: joiningLifecycle().lifecycle,
		};

		const { result } = await createAuthorizationGrant(deps).handle({
			body: {
				code: "abc",
				client_id: "client1",
				redirect_uri: RP_URI,
				code_verifier: CODE_VERIFIER,
			},
			// A cookie IS present and names a different user — the BFF topology.
			session: { code: "abc", user: { id: "cookie-user" } },
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
			session: { code: "abc", user: { id: "u-legacy" } },
			issuer: "localhost",
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		});

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens");
		expect(decodeJwt(result.tokens.access_token).sub).toBe("u-legacy");
	});
});

// Corrupt code records and PKCE error branches. Each test pins both status
// code AND errorDescription so a refactor that shifts an error to a different
// branch is caught.
describe("corrupt code records + PKCE branches", () => {
	it("returns 400 invalid_grant when code record has code_challenge without code_challenge_method", async () => {
		const deps = makeDeps(
			vi.fn().mockResolvedValue({
				code: "abc",
				client_id: "client1",
				redirect_uri: RP_URI,
				// Corrupt shape: challenge persisted but method missing.
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
			session: { code: "abc" },
			issuer: "localhost",
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		};

		const { result } = await handler.handle(ctx);

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
		expect((result as { errorDescription?: string }).errorDescription).toBe("invalid code");
	});

	it("returns 400 invalid_request when code_challenge_method is set but code_challenge is non-string", async () => {
		const deps = makeDeps(
			vi.fn().mockResolvedValue({
				code: "abc",
				client_id: "client1",
				redirect_uri: RP_URI,
				// code_challenge typed as `unknown` from a corrupt store record;
				// constantTimeStringEqual rejects non-string args.
				code_challenge: 12345 as unknown as string,
				code_challenge_method: "S256",
			}),
		);
		const handler = createAuthorizationGrant(deps);
		const verifier = "a".repeat(43);
		const ctx: GrantContext = {
			body: { code: "abc", client_id: "client1", redirect_uri: RP_URI, code_verifier: verifier },
			session: { code: "abc" },
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
		// RFC 7636 §4.1: code_verifier is 43-128 chars from the unreserved set;
		// "too-short" is 9 chars. The body carries the matching redirect_uri so
		// the redirect_uri gates pass and the format check is what refuses it.
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
			session: { code: "abc" },
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

	it("returns 400 invalid_grant when plain method code_verifier does not match challenge", async () => {
		// Both verifier and challenge are valid 43-char RFC 7636 strings, but
		// they differ. constantTimeStringEqual compares them on both S256 and
		// plain branches, so a short-circuit `!==`'s per-byte timing cannot leak
		// progress against the stored challenge. Reaching the plain branch needs
		// the client's `allowPlainPkce` opt-in, or the method allowlist rejects
		// first.
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
			session: { code: "abc" },
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
		// verifier for `S256`, compare it verbatim for `plain`. Grow the
		// admissible method set without revisiting that comparison and this
		// fails.
		const policy = resolvePkceOptions();
		const admissible = new Set([
			...pkceMethodsForClient(policy, null),
			...pkceMethodsForClient(policy, { allowPlainPkce: true }),
		]);
		expect([...admissible].sort()).toEqual(["S256", "plain"]);
	});
});

// ---------------------------------------------------------------------------
// Every store outage the grant answers 503 is logged once, at error level.
// ---------------------------------------------------------------------------

describe("createAuthorizationGrant — a store that cannot answer is logged, not only answered 503", () => {
	const liveSession = (sid: string) => ({
		sid,
		sub: "u1",
		authTime: new Date(),
		createdAt: new Date(),
		expiresAt: new Date(Date.now() + 3600_000),
		claims: {},
		amr: undefined,
		authentication: undefined,
	});
	const outage = (): Error =>
		Object.assign(new Error("READONLY You can't write against a read only replica."), {
			name: "ReplyError",
			command: { name: "set", args: ["key", "refused-command-marker"] },
		});
	const exchange = (handler: ReturnType<typeof createAuthorizationGrant>) =>
		handler.handle({
			body: {
				code: "abc",
				client_id: "client1",
				redirect_uri: RP_URI,
				code_verifier: CODE_VERIFIER,
			},
			session: {
				code: "abc",
				user: { id: "u1" },
			},
			issuer: "localhost",
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		});
	const expectOutageLine = (
		logger: ReturnType<typeof createMockLogger>,
		event: string,
		fields: Record<string, unknown>,
	) => {
		expect(logger.warn).not.toHaveBeenCalled();
		expect(logger.error).toHaveBeenCalledTimes(1);
		const [line, name] = logger.error.mock.calls[0] as [Record<string, unknown>, string];
		expect(name).toBe(event);
		expect(line).toMatchObject(fields);
		expect(line.err).toMatchObject({ name: "ReplyError" });
		expect(line.err).not.toBeInstanceOf(Error);
		expect(JSON.stringify(logger.error.mock.calls)).not.toContain("refused-command-marker");
	};
	const sessionStore = (get: () => Promise<unknown>) => ({
		kind: "spy",
		async create() {},
		get,
		async delete() {},
	});

	it("the code store's consume: 503, not the terminal handler's 500", async () => {
		const logger = createMockLogger();
		const handler = createAuthorizationGrant({
			...makeDeps(vi.fn().mockRejectedValue(outage())),
			logger,
		} as Parameters<typeof createAuthorizationGrant>[0]);
		const { result } = await exchange(handler);
		expect(result).toMatchObject({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "authorization code store unavailable",
		});
		expectOutageLine(logger, "authorization_grant_store_unavailable", {
			store: "authorization_code",
			step: "consume",
			clientId: "client1",
		});
	});

	it("the session read before any token is signed: admission's line, the grant's own is not written", async () => {
		const logger = createMockLogger();
		const handler = createAuthorizationGrant({
			...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "sid-1", ...validCode })),
			userSessionStore: sessionStore(async () => {
				throw outage();
			}),
			sessionLifecycleStore: openingLifecycleStore("u1"),
			sessionLifecycle: joiningLifecycle().lifecycle,
			logger,
		} as Parameters<typeof createAuthorizationGrant>[0]);
		const { result } = await exchange(handler);
		expect(result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
		expectOutageLine(logger, "session_admission_unavailable", {
			store: "user_session",
			action: "oauth.code_exchange",
		});
	});

	it("records the client id capped at 200 characters, as every client-id field is", async () => {
		const logger = createMockLogger();
		const longId = "c".repeat(256);
		const handler = createAuthorizationGrant({
			// The grant's own line: the code store's consume. A session store's
			// outage is admission's line, which names no client.
			...makeDeps(vi.fn().mockRejectedValue(outage())),
			logger,
		} as Parameters<typeof createAuthorizationGrant>[0]);
		const { result } = await handler.handle({
			body: { code: "abc", client_id: longId, redirect_uri: RP_URI, code_verifier: CODE_VERIFIER },
			session: {
				code: "abc",
				user: { id: "u1" },
			},
			issuer: "localhost",
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: { ...DEFAULT_AUTH_CLIENT, clientId: longId },
		});
		expect(result).toMatchObject({ status: 503 });
		const [line] = logger.error.mock.calls[0] as [Record<string, unknown>, string];
		expect(typeof line.clientId).toBe("string");
		expect(String(line.clientId).length).toBeLessThanOrEqual(200);
	});

	it("the refresh-token family registration", async () => {
		const logger = createMockLogger();
		const handler = createAuthorizationGrant({
			...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "sid-1", ...validCode })),
			refreshTokenFamilyRotation: {
				register: async () => {
					throw outage();
				},
				rotate: vi.fn(async () => ({ outcome: "rotated" as const })),
			},
			logger,
		} as Parameters<typeof createAuthorizationGrant>[0]);
		const { result } = await exchange(handler);
		expect(result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
		expectOutageLine(logger, "authorization_grant_store_unavailable", {
			store: "refresh_token_family",
			step: "register",
			clientId: "client1",
		});
	});

	it("the session re-read before the family is linked: admission's line", async () => {
		const logger = createMockLogger();
		let reads = 0;
		const handler = createAuthorizationGrant({
			...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "sid-1", ...validCode })),
			userSessionStore: sessionStore(async () => {
				reads++;
				if (reads === 1) return liveSession("sid-1");
				throw outage();
			}),
			sessionLifecycleStore: openingLifecycleStore("u1"),
			sessionLifecycle: joiningLifecycle().lifecycle,
			logger,
		} as Parameters<typeof createAuthorizationGrant>[0]);
		const { result } = await exchange(handler);
		expect(result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
		expectOutageLine(logger, "session_admission_unavailable", {
			store: "user_session",
			action: "oauth.code_exchange",
		});
	});

	it("the client lookup for logout metadata, as client_repository_unavailable", async () => {
		const logger = createMockLogger();
		const handler = createAuthorizationGrant({
			...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "sid-1", ...validCode }), {
				findById: vi.fn().mockRejectedValue(outage()),
				authenticate: vi.fn(),
			}),
			userSessionStore: sessionStore(async () => liveSession("sid-1")),
			sessionLifecycleStore: openingLifecycleStore("u1"),
			sessionLifecycle: joiningLifecycle().lifecycle,
			logger,
		} as Parameters<typeof createAuthorizationGrant>[0]);
		const { result } = await exchange(handler);
		expect(result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
		expectOutageLine(logger, "client_repository_unavailable", {
			site: "authorization_code",
			step: "find",
			clientId: "client1",
		});
	});

	it("joining the session: the lifecycle's outage, on the grant's line without an error projection", async () => {
		const logger = createMockLogger();
		const revokeFamily = vi.fn(async () => {});
		const register = vi.fn(async () => {});
		const handler = createAuthorizationGrant({
			...makeDeps(vi.fn().mockResolvedValue({ code: "abc", sid: "sid-1", ...validCode })),
			userSessionStore: sessionStore(async () => liveSession("sid-1")),
			sessionLifecycleStore: openingLifecycleStore("u1"),
			sessionLifecycle: joiningLifecycle(outsideAnswer<SessionJoinOutcome>()).lifecycle,
			refreshTokenFamilyRotation: {
				register,
				rotate: vi.fn(async () => ({ outcome: "rotated" as const })),
			},
			refreshTokenFamilyRevocation: { revokeFamily, isFamilyRevoked: vi.fn(async () => false) },
			logger,
		} as Parameters<typeof createAuthorizationGrant>[0]);
		const { result } = await exchange(handler);
		expect(result).toMatchObject({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "session linking unavailable",
		});
		expect(logger.warn).not.toHaveBeenCalled();
		// The defensive fallback has no error to project: the grant's line names the step only.
		expect(logger.error.mock.calls).toEqual([
			[
				{ store: "session_lifecycle", step: "join", clientId: "client1" },
				"authorization_grant_store_unavailable",
			],
		]);
		// The family registered for tokens never served is revoked by the grant.
		expect(revokeFamily).toHaveBeenCalledTimes(1);
		expect(revokeFamily).toHaveBeenCalledWith((register.mock.calls[0] as unknown[])[1]);
	});
});
