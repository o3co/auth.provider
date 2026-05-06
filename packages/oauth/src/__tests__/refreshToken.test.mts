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
import { createSecretKey } from "node:crypto";
import {
	createSymmetricKeyStore,
	type GrantContext,
	type GrantDependencies,
	type GrantPolicyHookBase,
	type RefreshTokenFamilyRotation,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { createRefreshTokenGrant } from "#/grants/refreshToken.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

const mockConfig = {
	oauth: {
		jwt: { secret: SECRET },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {
			session: { enabled: true },
			authorization_code: { enabled: true },
			refresh_token: { enabled: true },
		},
	},
} as unknown as GrantDependencies["config"];

const mockDeps: GrantDependencies = {
	config: mockConfig,
	keyStore,
};

// D-6 (v0.5.1): every test that hits the binding gate must supply both an
// `aud` (or `azp`) on the signed RT and a matching `authenticatedClient` on
// the GrantContext. We default both to "client1" so existing tests continue
// to exercise the same scope/policy/family code paths without per-test
// boilerplate; tests that need an explicit identity mismatch override the
// `body.refresh_token` aud or the ctx authenticatedClient.
const DEFAULT_CLIENT_ID = "client1";

async function makeRefreshToken(overrides: Record<string, unknown> = {}): Promise<string> {
	return new SignJWT({ sub: "u1", scope: "read write", ...overrides })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
		.setAudience(DEFAULT_CLIENT_ID)
		.setExpirationTime("24h")
		.sign(secretKey);
}

const DEFAULT_AUTH_CLIENT = {
	clientId: DEFAULT_CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic" as const,
};

describe("createRefreshTokenGrant", () => {
	describe("handle", () => {
		it("returns 400 when refresh_token is missing", async () => {
			const handler = createRefreshTokenGrant(mockDeps);
			const ctx: GrantContext = {
				body: {},
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			expect("error" in result).toBe(true);
		});

		it("returns 400 when refresh_token is invalid JWT", async () => {
			const handler = createRefreshTokenGrant(mockDeps);
			const ctx: GrantContext = {
				body: { refresh_token: "not-a-valid-jwt" },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 400 when JWT typ header is not rt+jwt", async () => {
			const accessToken = await new SignJWT({ sub: "u1" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
				.setExpirationTime("1h")
				.sign(secretKey);
			const handler = createRefreshTokenGrant(mockDeps);
			const ctx: GrantContext = {
				body: { refresh_token: accessToken },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("D-6: returns 400 invalid_grant when authenticatedClient does not match RT azp/aud", async () => {
			// Token is bound to "client1" via aud; authenticatedClient is a
			// different client. The binding gate must reject — accepting it
			// would let any authenticated client redeem any RT, defeating PB-2.
			const token = await new SignJWT({ sub: "u1" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setAudience("client1")
				.setExpirationTime("24h")
				.sign(secretKey);
			const handler = createRefreshTokenGrant(mockDeps);
			const ctx: GrantContext = {
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: {
					clientId: "different-client",
					tokenEndpointAuthMethod: "client_secret_basic",
				},
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			if (!("error" in result)) expect.fail("Expected error in result");
			expect(result.error).toBe("invalid_grant");
			expect(result.errorDescription).toBe("refresh_token was not issued to this client");
		});

		it("D-6: returns 401 invalid_client when ctx.authenticatedClient is null", async () => {
			// Direct grant invocation with no client auth — must be refused
			// regardless of the RT contents.
			const token = await makeRefreshToken();
			const handler = createRefreshTokenGrant(mockDeps);
			const { result } = await handler.handle({
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: null,
			});

			expect(result.status).toBe(401);
			if (!("error" in result)) expect.fail("Expected error in result");
			expect(result.error).toBe("invalid_client");
		});

		it("D-6 R-legacy-azp: legacy RT (aud only, no azp) + matching authenticatedClient → 200, new RT emits azp", async () => {
			// Pre-D-6 tokens carry only `aud`; the binding gate falls back to
			// `aud === authenticatedClient.clientId`. The newly minted RT must
			// emit `azp = authenticatedClient.clientId` so subsequent rotations
			// no longer rely on the `aud` fallback.
			const legacyToken = await new SignJWT({ sub: "u1", scope: "read" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setAudience("client1")
				// note: no .azp claim (legacy)
				.setExpirationTime("24h")
				.sign(secretKey);
			const handler = createRefreshTokenGrant(mockDeps);
			const { result } = await handler.handle({
				body: { refresh_token: legacyToken },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});

			expect(result.status).toBe(200);
			if (!("tokens" in result)) expect.fail("Expected tokens in result");
			const newRt = result.tokens.refresh_token as string;
			const payload = JSON.parse(
				Buffer.from(newRt.split(".")[1] ?? "", "base64url").toString("utf-8"),
			) as Record<string, unknown>;
			expect(payload.azp).toBe(DEFAULT_CLIENT_ID);
			expect(payload.aud).toBe(DEFAULT_CLIENT_ID);
		});

		it("returns 200 with new access and refresh tokens on valid refresh token", async () => {
			const token = await makeRefreshToken();
			const handler = createRefreshTokenGrant(mockDeps);
			const ctx: GrantContext = {
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				expect(result.tokens.access_token).toBeDefined();
				expect(result.tokens.refresh_token).toBeDefined();
			}
		});

		it("returns 200 when client_id matches token audience", async () => {
			const token = await new SignJWT({ sub: "u1" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setAudience("client1")
				.setExpirationTime("24h")
				.sign(secretKey);
			const handler = createRefreshTokenGrant(mockDeps);
			const ctx: GrantContext = {
				body: { refresh_token: token, client_id: "client1" },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
		});

		it("allows scope reduction via scope parameter", async () => {
			const token = await makeRefreshToken({ scope: "read write" });
			const handler = createRefreshTokenGrant(mockDeps);
			const ctx: GrantContext = {
				body: { refresh_token: token, scope: "read" },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				expect(result.tokens.scope).toBe("read");
			}
		});

		it("rejects scope that exceeds original grant", async () => {
			const token = await makeRefreshToken({ scope: "read" });
			const handler = createRefreshTokenGrant(mockDeps);
			const ctx: GrantContext = {
				body: { refresh_token: token, scope: "read write" },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			if ("error" in result) {
				expect(result.error).toBe("invalid_scope");
			}
		});

		it("deduplicates requested scope values", async () => {
			const token = await makeRefreshToken({ scope: "read write" });
			const handler = createRefreshTokenGrant(mockDeps);
			const ctx: GrantContext = {
				body: { refresh_token: token, scope: "read read" },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				expect(result.tokens.scope).toBe("read");
			}
		});

		it("treats empty scope string as no scope change", async () => {
			const token = await makeRefreshToken({ scope: "read write" });
			const handler = createRefreshTokenGrant(mockDeps);
			const ctx: GrantContext = {
				body: { refresh_token: token, scope: "" },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				expect(result.tokens.scope).toBe("read write");
			}
		});

		it("accepts legacy tokens with type payload instead of typ header", async () => {
			// Tokens issued before claims standardization use type: "refresh" in payload
			// instead of typ: "rt+jwt" in the protected header.
			const legacyToken = await new SignJWT({ type: "refresh", sub: "u1" })
				.setProtectedHeader({ alg: "HS256", kid: "v0" })
				.setAudience(DEFAULT_CLIENT_ID)
				.setExpirationTime("24h")
				.sign(secretKey);
			const handler = createRefreshTokenGrant(mockDeps);
			const ctx: GrantContext = {
				body: { refresh_token: legacyToken },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
		});

		it("accepts legacy tokens without kid header", async () => {
			const legacyToken = await new SignJWT({ sub: "u1" })
				.setProtectedHeader({ alg: "HS256", typ: "rt+jwt" })
				.setAudience(DEFAULT_CLIENT_ID)
				.setExpirationTime("24h")
				.sign(secretKey);
			const handler = createRefreshTokenGrant(mockDeps);
			const ctx: GrantContext = {
				body: { refresh_token: legacyToken },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
		});

		it("does not return sessionMutation", async () => {
			const token = await makeRefreshToken();
			const handler = createRefreshTokenGrant(mockDeps);
			const ctx: GrantContext = {
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { sessionMutation } = await handler.handle(ctx);

			expect(sessionMutation).toBeUndefined();
		});
	});

	describe("family_id and refreshTokenFamilyRotation integration", () => {
		function createStubRotation(
			outcome: "rotated" | "replayed" | "revoked" | "unknown_family",
		): RefreshTokenFamilyRotation {
			return {
				async register() {},
				async rotate() {
					return { outcome };
				},
			};
		}

		it("emits family_id in the new rt+jwt (generated when absent from input)", async () => {
			// Input token has no family_id claim — the grant should generate a fresh UUID
			const token = await makeRefreshToken();
			const handler = createRefreshTokenGrant(mockDeps);
			const ctx: GrantContext = {
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			if ("tokens" in result) {
				const rtToken = result.tokens.refresh_token as string;
				// Decode the payload from the returned rt+jwt
				const parts = rtToken.split(".");
				const payload = JSON.parse(
					Buffer.from(parts[1] ?? "", "base64url").toString("utf-8"),
				) as Record<string, unknown>;
				expect(typeof payload.family_id).toBe("string");
				// Should be a UUID-shaped string (8-4-4-4-12)
				expect(payload.family_id as string).toMatch(
					/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
				);
			} else {
				expect.fail("Expected tokens in result");
			}
		});

		it("returns invalid_grant/replay_detected when the rotation reports 'replayed'", async () => {
			const stub = createStubRotation("replayed");
			const depsWithStore: GrantDependencies = { ...mockDeps, refreshTokenFamilyRotation: stub };
			// Token must include a jti so that previousJti !== null and rotate() is called
			const token = await new SignJWT({ sub: "u1", scope: "read write" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setAudience(DEFAULT_CLIENT_ID)
				.setExpirationTime("24h")
				.setJti("prev-jti-replay")
				.sign(secretKey);
			const handler = createRefreshTokenGrant(depsWithStore);
			const ctx: GrantContext = {
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			if ("error" in result) {
				expect(result.error).toBe("invalid_grant");
				expect(result.errorDescription).toBe("replay_detected");
			} else {
				expect.fail("Expected error in result");
			}
		});

		it("returns 503 temporarily_unavailable when refreshTokenFamilyRotation.rotate throws (CP-17)", async () => {
			const throwingRotation: RefreshTokenFamilyRotation = {
				async register() {},
				async rotate() {
					throw new Error("redis down");
				},
			};
			const depsWithStore: GrantDependencies = {
				...mockDeps,
				refreshTokenFamilyRotation: throwingRotation,
			};
			const token = await new SignJWT({ sub: "u1", scope: "read write" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setAudience(DEFAULT_CLIENT_ID)
				.setExpirationTime("24h")
				.setJti("prev-jti-503")
				.sign(secretKey);
			const handler = createRefreshTokenGrant(depsWithStore);

			const { result } = await handler.handle({
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});

			expect(result.status).toBe(503);
			if (!("error" in result)) expect.fail("Expected error in result");
			expect(result.error).toBe("temporarily_unavailable");
		});

		it("returns invalid_grant/family_revoked when the rotation reports 'revoked'", async () => {
			const stub = createStubRotation("revoked");
			const depsWithStore: GrantDependencies = { ...mockDeps, refreshTokenFamilyRotation: stub };
			// Token must include a jti so that previousJti !== null and rotate() is called
			const token = await new SignJWT({ sub: "u1", scope: "read write" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setAudience(DEFAULT_CLIENT_ID)
				.setExpirationTime("24h")
				.setJti("prev-jti-revoked")
				.sign(secretKey);
			const handler = createRefreshTokenGrant(depsWithStore);
			const ctx: GrantContext = {
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			if ("error" in result) {
				expect(result.error).toBe("invalid_grant");
				expect(result.errorDescription).toBe("family_revoked");
			} else {
				expect.fail("Expected error in result");
			}
		});
	});

	describe("refresh_token grant — grantPolicy hook", () => {
		function createStubPolicy(evaluate: GrantPolicyHookBase["evaluate"]): GrantPolicyHookBase {
			return { kind: "stub", evaluate };
		}

		it("narrows scope when policy returns allow with grantedScope", async () => {
			const token = await makeRefreshToken({ scope: "read write" });
			const policy = createStubPolicy(async () => ({
				outcome: "allow",
				grantedScope: ["read"],
			}));
			const depsWithPolicy: GrantDependencies = { ...mockDeps, grantPolicy: policy };
			const handler = createRefreshTokenGrant(depsWithPolicy);
			const ctx: GrantContext = {
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			if ("tokens" in result) {
				expect(result.tokens.scope).toBe("read");
			} else {
				expect.fail("Expected tokens in result");
			}
		});

		it("forwards ctx.ip and ctx.userAgent to grantPolicy.evaluate (CP-1)", async () => {
			const token = await makeRefreshToken({ scope: "read write" });
			let observedIp: string | undefined;
			let observedUa: string | undefined;
			const policy = createStubPolicy(async (_req, ctxArg) => {
				observedIp = ctxArg.ip;
				observedUa = ctxArg.userAgent;
				return { outcome: "allow" };
			});
			const depsWithPolicy: GrantDependencies = { ...mockDeps, grantPolicy: policy };
			const handler = createRefreshTokenGrant(depsWithPolicy);
			const ctx: GrantContext = {
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: { ip: "10.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
				ip: "10.0.0.1",
				userAgent: "test-agent/1.0",
			};

			await handler.handle(ctx);

			expect(observedIp).toBe("10.0.0.1");
			expect(observedUa).toBe("test-agent/1.0");
		});

		it("denies with policy-provided error", async () => {
			const token = await makeRefreshToken({ scope: "read write" });
			const policy = createStubPolicy(async () => ({
				outcome: "deny",
				error: "access_denied",
				errorDescription: "policy",
			}));
			const depsWithPolicy: GrantDependencies = { ...mockDeps, grantPolicy: policy };
			const handler = createRefreshTokenGrant(depsWithPolicy);
			const ctx: GrantContext = {
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			if ("error" in result) {
				expect(result.error).toBe("access_denied");
				expect(result.errorDescription).toBe("policy");
			} else {
				expect.fail("Expected error in result");
			}
		});

		it("rejects invalid_scope when policy grantedScope exceeds original (CP-15 RFC 6749 §6)", async () => {
			const token = await makeRefreshToken({ scope: "read" });
			const policy = createStubPolicy(async () => ({
				outcome: "allow",
				grantedScope: ["read", "admin"], // admin is NOT in the original "read"
			}));
			const depsWithPolicy: GrantDependencies = { ...mockDeps, grantPolicy: policy };
			const handler = createRefreshTokenGrant(depsWithPolicy);
			const ctx: GrantContext = {
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			if (!("error" in result)) expect.fail("Expected error in result");
			expect(result.error).toBe("invalid_scope");
			expect(result.errorDescription).toContain("admin");
		});

		it("returns 503 temporarily_unavailable when grantPolicy.evaluate throws (CP-18)", async () => {
			const token = await makeRefreshToken({ scope: "read" });
			const policy = createStubPolicy(async () => {
				throw new Error("policy backend 502");
			});
			const depsWithPolicy: GrantDependencies = { ...mockDeps, grantPolicy: policy };
			const handler = createRefreshTokenGrant(depsWithPolicy);

			const { result } = await handler.handle({
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});

			expect(result.status).toBe(503);
			if (!("error" in result)) expect.fail("Expected error in result");
			expect(result.error).toBe("temporarily_unavailable");
			expect(result.errorDescription).toContain("policy");
		});

		it("omits scope from token response when policy narrows to empty array (CP-15)", async () => {
			const token = await makeRefreshToken({ scope: "read write" });
			const policy = createStubPolicy(async () => ({
				outcome: "allow",
				grantedScope: [],
			}));
			const depsWithPolicy: GrantDependencies = { ...mockDeps, grantPolicy: policy };
			const handler = createRefreshTokenGrant(depsWithPolicy);

			const { result } = await handler.handle({
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});

			expect(result.status).toBe(200);
			if (!("tokens" in result)) expect.fail("expected tokens");
			// Response MUST NOT include scope: "". decodeJwt scope field is also absent.
			expect(result.tokens.scope).toBeUndefined();
		});
	});

	describe("sid claim propagation and userSessionStore integration (TODO-F-3 task 4)", () => {
		function decodeTokenPayload(token: string): Record<string, unknown> {
			const parts = token.split(".");
			return JSON.parse(Buffer.from(parts[1] ?? "", "base64url").toString("utf-8")) as Record<
				string,
				unknown
			>;
		}

		function createStubUserSessionStore(
			get: (sid: string) => Promise<import("@o3co/auth-provider-core").UserSession | null>,
		): UserSessionStore {
			return {
				kind: "stub",
				get,
				async create() {},
				async delete() {},
			};
		}

		it("preserves family_id and sid on both minted tokens (F-3-4-1)", async () => {
			const token = await makeRefreshToken({ family_id: "fam-1", sid: "sid-1" });
			const store = createStubUserSessionStore(async (_sid) => ({
				sid: "sid-1",
				sub: "u1",
				authTime: new Date(),
				createdAt: new Date(),
				expiresAt: new Date(Date.now() + 3600_000),
				claims: {},
			}));
			const deps: GrantDependencies = { ...mockDeps, userSessionStore: store };
			const handler = createRefreshTokenGrant(deps);

			const { result } = await handler.handle({
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});

			expect(result.status).toBe(200);
			if (!("tokens" in result)) expect.fail("Expected tokens in result");

			const atPayload = decodeTokenPayload(result.tokens.access_token as string);
			expect(atPayload.family_id).toBe("fam-1");
			expect(atPayload.sid).toBe("sid-1");

			const rtPayload = decodeTokenPayload(result.tokens.refresh_token as string);
			expect(rtPayload.family_id).toBe("fam-1");
			expect(rtPayload.sid).toBe("sid-1");
		});

		it("returns 400 invalid_grant when userSessionStore.get returns null (F-3-4-2)", async () => {
			const token = await makeRefreshToken({ sid: "sid-dead" });
			const store = createStubUserSessionStore(async (_sid) => null);
			const deps: GrantDependencies = { ...mockDeps, userSessionStore: store };
			const handler = createRefreshTokenGrant(deps);

			const { result } = await handler.handle({
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});

			expect(result.status).toBe(400);
			if (!("error" in result)) expect.fail("Expected error in result");
			expect(result.error).toBe("invalid_grant");
			expect(result.errorDescription).toMatch(/session/i);
		});

		it("returns 503 temporarily_unavailable when userSessionStore.get throws (F-3-4-3)", async () => {
			const token = await makeRefreshToken({ sid: "sid-boom" });
			const store = createStubUserSessionStore(async (_sid) => {
				throw new Error("redis down");
			});
			const deps: GrantDependencies = { ...mockDeps, userSessionStore: store };
			const handler = createRefreshTokenGrant(deps);

			const { result } = await handler.handle({
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});

			expect(result.status).toBe(503);
			if (!("error" in result)) expect.fail("Expected error in result");
			expect(result.error).toBe("temporarily_unavailable");
		});

		it("succeeds without sid on minted tokens when legacy token has no sid claim (F-3-4-4)", async () => {
			// Token minted before F-3: only family_id, no sid
			const token = await makeRefreshToken({ family_id: "fam-legacy" });
			const handler = createRefreshTokenGrant(mockDeps);

			const { result } = await handler.handle({
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});

			expect(result.status).toBe(200);
			if (!("tokens" in result)) expect.fail("Expected tokens in result");

			const atPayload = decodeTokenPayload(result.tokens.access_token as string);
			expect(atPayload.family_id).toBe("fam-legacy");
			expect(Object.hasOwn(atPayload, "sid")).toBe(false);

			const rtPayload = decodeTokenPayload(result.tokens.refresh_token as string);
			expect(rtPayload.family_id).toBe("fam-legacy");
			expect(Object.hasOwn(rtPayload, "sid")).toBe(false);
		});
	});
});
