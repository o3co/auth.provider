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
	type GrantPolicyHook,
	type Logger,
	type RefreshTokenFamilyRotation,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createRefreshTokenGrant } from "#/grants/refreshToken.mjs";

// Vitest mock-shaped Logger that satisfies the interface; tests pass a fresh
// `vi.fn()` for `warn` and inspect its calls. Other levels are vi.fn() so
// unrelated calls don't crash on undefined.
function makeStubLogger(warn: ReturnType<typeof vi.fn>): Logger {
	const stub = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn,
		error: vi.fn(),
		fatal: vi.fn(),
	};
	// `child()` returns the same stub so child loggers are observable too.
	return { ...stub, child: () => stub as unknown as Logger } as unknown as Logger;
}

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

const mockConfig = {
	oauth: {
		jwt: { secret: SECRET },
		accessToken: { expiresIn: 3600 },
		refreshToken: {
			expiresIn: 86400,
			// CC-2 (v0.5.1): default policy for unknown_family is "reject".
			unknownFamilyPolicy: "reject",
			// SF-6 (v0.5.1): default policy for tokens lacking jti or family_id
			// when rotation is wired is "reject".
			legacyRtPolicy: "reject",
		},
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
		.setIssuer("localhost")
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
				.setIssuer("localhost")
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
				.setIssuer("localhost")
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
				.setIssuer("localhost")
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

		it("accepts tokens without kid header (kid is optional)", async () => {
			const legacyToken = await new SignJWT({ sub: "u1" })
				.setProtectedHeader({ alg: "HS256", typ: "rt+jwt" })
				.setIssuer("localhost")
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

		describe("refresh-token strict gate (header.typ === rt+jwt required)", () => {
			it("RT-1: rejects payload.type=refresh as a typ substitute", async () => {
				const legacyToken = await new SignJWT({ type: "refresh", sub: "u1" })
					.setProtectedHeader({ alg: "HS256", kid: "v0" })
					.setIssuer("localhost")
					.setAudience(DEFAULT_CLIENT_ID)
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

				expect(result.status).toBe(400);
				if (!("error" in result)) expect.fail("Expected error in result");
				expect(result.error).toBe("invalid_grant");
				expect(result.errorDescription).toBe("invalid refresh_token");
			});

			it("RT-2: accepts header.typ rt+jwt with standard claims", async () => {
				const modernToken = await makeRefreshToken({ sub: "u1", azp: DEFAULT_CLIENT_ID });
				const handler = createRefreshTokenGrant(mockDeps);

				const { result } = await handler.handle({
					body: { refresh_token: modernToken },
					session: {},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				});

				expect(result.status).toBe(200);
				expect("tokens" in result).toBe(true);
			});

			it("RT-3: ignores claims.user.id fallback for sub", async () => {
				const legacyClaimsToken = await new SignJWT({
					type: "refresh",
					user: { id: "u1" },
					scope: "read",
				})
					.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
					.setIssuer("localhost")
					.setAudience(DEFAULT_CLIENT_ID)
					.setExpirationTime("24h")
					.sign(secretKey);
				const handler = createRefreshTokenGrant(mockDeps);

				const { result } = await handler.handle({
					body: { refresh_token: legacyClaimsToken },
					session: {},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				});

				expect(result.status).toBe(400);
				if (!("error" in result)) expect.fail("Expected error in result");
				expect(result.error).toBe("invalid_grant");
				expect(result.errorDescription).toBe("refresh token has no subject");
			});

			it("RT-OC: typ-less JWT is rejected even when legacyTypAccept=true (AT-as-RT defended)", async () => {
				// SF-1's legacyTypAccept=true allows a typ-less JWT through the
				// central verifier. This grant-level gate must STILL reject it
				// because the token declares no refresh marker (header.typ is
				// the only accepted marker after M4). Without this guard, any
				// AT or non-refresh JWT signed with the same key could pass as
				// a refresh token — that is the AT-as-RT confusion vector the
				// strict marker check defends against.
				const typLessUnmarkedToken = await new SignJWT({
					sub: "u1",
					azp: DEFAULT_CLIENT_ID,
					scope: "read",
				})
					.setProtectedHeader({ alg: "HS256", kid: "v0" })
					.setIssuer("localhost")
					.setAudience(DEFAULT_CLIENT_ID)
					.setExpirationTime("24h")
					.sign(secretKey);
				const handler = createRefreshTokenGrant(mockDeps);

				const { result } = await handler.handle({
					body: { refresh_token: typLessUnmarkedToken },
					session: {},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				});

				expect(result.status).toBe(400);
				if (!("error" in result)) expect.fail("Expected error in result");
				expect(result.error).toBe("invalid_grant");
				expect(result.errorDescription).toBe("invalid refresh_token");
			});
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
			// PB-1 (v0.5.1): rotation wired without revocation must fail-closed
			// to 503. Existing tests that only assert the "replayed" path supply
			// a noop revocation stub so the request reaches the replay branch.
			const noopRevocation = {
				async revokeFamily() {},
				async isFamilyRevoked() {
					return false;
				},
			};
			const depsWithStore: GrantDependencies = {
				...mockDeps,
				refreshTokenFamilyRotation: stub,
				refreshTokenFamilyRevocation: noopRevocation,
			};
			// SF-6 (v0.5.1): when rotation is wired the token MUST carry both
			// jti AND family_id, otherwise the legacy gate fires before rotation.
			const token = await new SignJWT({ sub: "u1", scope: "read write", family_id: "fam-1" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setIssuer("localhost")
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
			// SF-6 (v0.5.1): token must carry family_id when rotation is wired.
			const token = await new SignJWT({ sub: "u1", scope: "read write", family_id: "fam-1" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setIssuer("localhost")
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
			// SF-6 (v0.5.1): token must carry family_id when rotation is wired.
			const token = await new SignJWT({ sub: "u1", scope: "read write", family_id: "fam-1" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setIssuer("localhost")
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

	describe("F6 PR3 — PB-1 RT reuse → family revoke", () => {
		// Stub rotation that always reports "replayed" (jti mismatch).
		const replayedRotation: RefreshTokenFamilyRotation = {
			async register() {},
			async rotate() {
				return { outcome: "replayed" };
			},
		};

		// Helper: a refresh token with both jti and family_id present so SF-6
		// gate doesn't fire. The replayed outcome is decided by the rotation
		// stub regardless of the actual jti — the stub is unconditional.
		async function makeReplayedRt(familyId = "fam-1"): Promise<string> {
			return new SignJWT({ sub: "u1", scope: "read write", family_id: familyId })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setIssuer("localhost")
				.setAudience(DEFAULT_CLIENT_ID)
				.setExpirationTime("24h")
				.setJti("jti-A")
				.sign(secretKey);
		}

		const baseCtx: GrantContext = {
			body: {},
			session: {},
			issuer: "localhost",
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		};

		it("revokes the RT family with the exact family_id when replay is detected (RED 1)", async () => {
			const revokeFamily = vi.fn().mockResolvedValue(undefined);
			const revocation = {
				revokeFamily,
				async isFamilyRevoked() {
					return false;
				},
			};
			const deps: GrantDependencies = {
				...mockDeps,
				refreshTokenFamilyRotation: replayedRotation,
				refreshTokenFamilyRevocation: revocation,
			};
			const rt = await makeReplayedRt("fam-1");

			const { result } = await createRefreshTokenGrant(deps).handle({
				...baseCtx,
				body: { refresh_token: rt },
			});

			expect(result.status).toBe(400);
			if (!("error" in result)) expect.fail("Expected error in result");
			expect(result.error).toBe("invalid_grant");
			expect(result.errorDescription).toBe("replay_detected");
			// PB-1 Codex Delta 3: assert exact family_id, not expect.any(String).
			expect(revokeFamily).toHaveBeenCalledWith("fam-1");
			expect(revokeFamily).toHaveBeenCalledTimes(1);
		});

		it("returns 503 when revocation dep is missing (PB-1 Codex Delta 1, fail-closed)", async () => {
			// Rotation wired but no revocation dep — fail-closed per Delta 1
			// (silent skip would violate RFC 6819 §5.2.2 compliance guarantee).
			const deps: GrantDependencies = {
				...mockDeps,
				refreshTokenFamilyRotation: replayedRotation,
			};
			const rt = await makeReplayedRt("fam-1");

			const { result } = await createRefreshTokenGrant(deps).handle({
				...baseCtx,
				body: { refresh_token: rt },
			});

			expect(result.status).toBe(503);
			if (!("error" in result)) expect.fail("Expected error in result");
			expect(result.error).toBe("temporarily_unavailable");
		});

		it("returns 503 when revokeFamily throws during replay handling (RED 5)", async () => {
			const revocation = {
				async revokeFamily() {
					throw new Error("Redis down");
				},
				async isFamilyRevoked() {
					return false;
				},
			};
			const deps: GrantDependencies = {
				...mockDeps,
				refreshTokenFamilyRotation: replayedRotation,
				refreshTokenFamilyRevocation: revocation,
			};
			const rt = await makeReplayedRt("fam-1");

			const { result } = await createRefreshTokenGrant(deps).handle({
				...baseCtx,
				body: { refresh_token: rt },
			});

			expect(result.status).toBe(503);
			if (!("error" in result)) expect.fail("Expected error in result");
			expect(result.error).toBe("temporarily_unavailable");
		});

		it("emits rt_reuse_detected_family_revoked audit log on replay (RED 3)", async () => {
			const warn = vi.fn();
			const logger = makeStubLogger(warn);
			const revocation = {
				async revokeFamily() {},
				async isFamilyRevoked() {
					return false;
				},
			};
			const deps: GrantDependencies = {
				...mockDeps,
				refreshTokenFamilyRotation: replayedRotation,
				refreshTokenFamilyRevocation: revocation,
				logger,
			};
			const rt = await makeReplayedRt("fam-1");

			await createRefreshTokenGrant(deps).handle({
				...baseCtx,
				body: { refresh_token: rt },
			});

			expect(warn).toHaveBeenCalledWith(
				expect.objectContaining({ familyId: "fam-1", clientId: DEFAULT_CLIENT_ID }),
				"rt_reuse_detected_family_revoked",
			);
		});

		it("concurrent replay calls revoke twice idempotently (PB-1 Codex Delta 2)", async () => {
			const revokeFamily = vi.fn().mockResolvedValue(undefined);
			const revocation = {
				revokeFamily,
				async isFamilyRevoked() {
					return false;
				},
			};
			const deps: GrantDependencies = {
				...mockDeps,
				refreshTokenFamilyRotation: replayedRotation,
				refreshTokenFamilyRevocation: revocation,
			};
			const rt = await makeReplayedRt("fam-race");
			const handler = createRefreshTokenGrant(deps);

			const [r1, r2] = await Promise.all([
				handler.handle({ ...baseCtx, body: { refresh_token: rt } }),
				handler.handle({ ...baseCtx, body: { refresh_token: rt } }),
			]);

			expect(r1.result.status).toBe(400);
			expect(r2.result.status).toBe(400);
			expect(revokeFamily).toHaveBeenCalledTimes(2);
			expect(revokeFamily).toHaveBeenCalledWith("fam-race");
		});

		it("a fresh family after revocation is independent (RED 4 — orthogonality smoke)", async () => {
			// "rotated" outcome on a different family — issuance succeeds, no
			// revocation invoked. Demonstrates the replay branch is targeted
			// only at the matching family_id.
			const rotated: RefreshTokenFamilyRotation = {
				async register() {},
				async rotate() {
					return { outcome: "rotated" };
				},
			};
			const revokeFamily = vi.fn().mockResolvedValue(undefined);
			const revocation = {
				revokeFamily,
				async isFamilyRevoked() {
					return false;
				},
			};
			const deps: GrantDependencies = {
				...mockDeps,
				refreshTokenFamilyRotation: rotated,
				refreshTokenFamilyRevocation: revocation,
			};
			const rt = await new SignJWT({ sub: "u1", scope: "read", family_id: "fam-2" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setIssuer("localhost")
				.setAudience(DEFAULT_CLIENT_ID)
				.setExpirationTime("24h")
				.setJti("jti-fresh")
				.sign(secretKey);

			const { result } = await createRefreshTokenGrant(deps).handle({
				...baseCtx,
				body: { refresh_token: rt },
			});

			expect(result.status).toBe(200);
			expect(revokeFamily).not.toHaveBeenCalled();
		});
	});

	describe("F6 PR3 — CC-2 unknown_family policy", () => {
		const unknownFamilyRotation: RefreshTokenFamilyRotation = {
			async register() {},
			async rotate() {
				return { outcome: "unknown_family" };
			},
		};

		const baseCtx: GrantContext = {
			body: {},
			session: {},
			issuer: "localhost",
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		};

		async function makeRtWithFamily(familyId = "fam-unknown"): Promise<string> {
			return new SignJWT({ sub: "u1", scope: "read write", family_id: familyId })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setIssuer("localhost")
				.setAudience(DEFAULT_CLIENT_ID)
				.setExpirationTime("24h")
				.setJti("jti-X")
				.sign(secretKey);
		}

		function configWithUnknownPolicy(policy: "accept" | "reject"): GrantDependencies["config"] {
			return {
				...mockConfig,
				oauth: {
					...mockConfig.oauth,
					refreshToken: {
						...mockConfig.oauth.refreshToken,
						unknownFamilyPolicy: policy,
					},
				},
			} as unknown as GrantDependencies["config"];
		}

		it("returns 400 invalid_grant for unknown_family with default policy (RED 1)", async () => {
			const deps: GrantDependencies = {
				...mockDeps,
				refreshTokenFamilyRotation: unknownFamilyRotation,
			};
			const rt = await makeRtWithFamily();

			const { result } = await createRefreshTokenGrant(deps).handle({
				...baseCtx,
				body: { refresh_token: rt },
			});

			expect(result.status).toBe(400);
			if (!("error" in result)) expect.fail("Expected error in result");
			expect(result.error).toBe("invalid_grant");
			expect(result.errorDescription).toBe("unknown_family");
		});

		it("issues tokens with unknownFamilyPolicy=accept (RED 2 — legacy mode)", async () => {
			const warn = vi.fn();
			const logger = makeStubLogger(warn);
			const deps: GrantDependencies = {
				config: configWithUnknownPolicy("accept"),
				keyStore: mockDeps.keyStore,
				refreshTokenFamilyRotation: unknownFamilyRotation,
				logger,
			};
			const rt = await makeRtWithFamily("fam-legacy");

			const { result } = await createRefreshTokenGrant(deps).handle({
				...baseCtx,
				body: { refresh_token: rt },
			});

			expect(result.status).toBe(200);
			expect(warn).toHaveBeenCalledWith(
				expect.objectContaining({ familyId: "fam-legacy" }),
				"unknown_family_accepted_legacy_mode",
			);
		});

		it("returns 400 with explicit unknownFamilyPolicy=reject (RED 3)", async () => {
			const warn = vi.fn();
			const logger = makeStubLogger(warn);
			const deps: GrantDependencies = {
				config: configWithUnknownPolicy("reject"),
				keyStore: mockDeps.keyStore,
				refreshTokenFamilyRotation: unknownFamilyRotation,
				logger,
			};
			const rt = await makeRtWithFamily("fam-unknown");

			const { result } = await createRefreshTokenGrant(deps).handle({
				...baseCtx,
				body: { refresh_token: rt },
			});

			expect(result.status).toBe(400);
			if (!("error" in result)) expect.fail("Expected error in result");
			expect(result.errorDescription).toBe("unknown_family");
			expect(warn).toHaveBeenCalledWith(
				expect.objectContaining({ familyId: "fam-unknown" }),
				"unknown_family_rejected",
			);
		});

		it("still handles replayed outcome correctly (RED 4 — orthogonality)", async () => {
			const replayedRotation: RefreshTokenFamilyRotation = {
				async register() {},
				async rotate() {
					return { outcome: "replayed" };
				},
			};
			const revocation = {
				async revokeFamily() {},
				async isFamilyRevoked() {
					return false;
				},
			};
			const deps: GrantDependencies = {
				...mockDeps,
				refreshTokenFamilyRotation: replayedRotation,
				refreshTokenFamilyRevocation: revocation,
			};
			const rt = await makeRtWithFamily("fam-replay");

			const { result } = await createRefreshTokenGrant(deps).handle({
				...baseCtx,
				body: { refresh_token: rt },
			});

			expect(result.status).toBe(400);
			if (!("error" in result)) expect.fail("Expected error in result");
			// MUST be "replay_detected", NOT "unknown_family"
			expect(result.errorDescription).toBe("replay_detected");
		});
	});

	describe("F6 PR3 — SF-6 RT without jti/family_id rejection", () => {
		const rotatedRotation: RefreshTokenFamilyRotation = {
			async register() {},
			async rotate() {
				return { outcome: "rotated" };
			},
		};

		const baseCtx: GrantContext = {
			body: {},
			session: {},
			issuer: "localhost",
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		};

		it("returns 400 invalid_grant for RT without jti when rotation is wired (RED 1)", async () => {
			const deps: GrantDependencies = {
				...mockDeps,
				refreshTokenFamilyRotation: rotatedRotation,
			};
			// Token has family_id but no jti — legacy gate must fire
			const rt = await new SignJWT({ sub: "u1", scope: "read", family_id: "fam-1" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setIssuer("localhost")
				.setAudience(DEFAULT_CLIENT_ID)
				.setExpirationTime("24h")
				.sign(secretKey);

			const { result } = await createRefreshTokenGrant(deps).handle({
				...baseCtx,
				body: { refresh_token: rt },
			});

			expect(result.status).toBe(400);
			if (!("error" in result)) expect.fail("Expected error in result");
			expect(result.error).toBe("invalid_grant");
			expect(result.errorDescription).toBe("missing_jti_or_family_id");
		});

		it("returns 400 invalid_grant for RT without family_id when rotation is wired (RED 2)", async () => {
			const deps: GrantDependencies = {
				...mockDeps,
				refreshTokenFamilyRotation: rotatedRotation,
			};
			// Token has jti but no family_id
			const rt = await new SignJWT({ sub: "u1", scope: "read" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setIssuer("localhost")
				.setAudience(DEFAULT_CLIENT_ID)
				.setExpirationTime("24h")
				.setJti("jti-only")
				.sign(secretKey);

			const { result } = await createRefreshTokenGrant(deps).handle({
				...baseCtx,
				body: { refresh_token: rt },
			});

			expect(result.status).toBe(400);
			if (!("error" in result)) expect.fail("Expected error in result");
			expect(result.errorDescription).toBe("missing_jti_or_family_id");
		});

		it("proceeds with normal rotation when RT has both jti and family_id (RED 4)", async () => {
			const rotateSpy = vi.fn().mockResolvedValue({ outcome: "rotated" });
			const rotation: RefreshTokenFamilyRotation = {
				async register() {},
				rotate: rotateSpy,
			};
			const deps: GrantDependencies = {
				...mockDeps,
				refreshTokenFamilyRotation: rotation,
			};
			const rt = await new SignJWT({ sub: "u1", scope: "read", family_id: "fam-1" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setIssuer("localhost")
				.setAudience(DEFAULT_CLIENT_ID)
				.setExpirationTime("24h")
				.setJti("jti-1")
				.sign(secretKey);

			const { result } = await createRefreshTokenGrant(deps).handle({
				...baseCtx,
				body: { refresh_token: rt },
			});

			expect(result.status).toBe(200);
			// SF-6 Codex Delta 3: rotation called with original family_id
			expect(rotateSpy).toHaveBeenCalledWith(
				"jti-1",
				expect.any(String),
				"fam-1",
				expect.any(Number),
			);
		});
	});

	describe("refresh_token grant — grantPolicy hook", () => {
		function createStubPolicy(evaluate: GrantPolicyHook["evaluate"]): GrantPolicyHook {
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

	// F6 coverage boost — patch line for PR #127 (PB-1 + CC-2 + SF-6) that is
	// reachable only via runtime-cast to a future outcome value not yet in the
	// `RefreshTokenFamilyRotationOutcome` union. The `default` arm exists as a
	// runtime invariant so a future outcome added without updating the switch
	// is rejected with a stable error rather than silently falling through to
	// token issuance. We exercise it deliberately to pin that contract.
	describe("F6 PR3 patch coverage — exhaustive switch defense-in-depth", () => {
		it("throws 'unhandled rotation outcome' when rotation returns an unknown outcome variant", async () => {
			const rotation = {
				async register() {},
				async rotate() {
					// Simulates a future outcome added to the union without
					// updating the consumer switch — the type cast is the
					// whole point: TypeScript would otherwise prevent this
					// and only the runtime guard catches the divergence.
					return { outcome: "future_outcome_xx" } as unknown as Awaited<
						ReturnType<RefreshTokenFamilyRotation["rotate"]>
					>;
				},
			} satisfies RefreshTokenFamilyRotation;
			const depsWithStore: GrantDependencies = {
				...mockDeps,
				refreshTokenFamilyRotation: rotation,
			};
			// SF-6: token must carry both jti AND family_id so the legacy
			// gate doesn't fire before rotation runs.
			const token = await new SignJWT({
				sub: "u1",
				scope: "read write",
				family_id: "fam-future",
			})
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setIssuer("localhost")
				.setAudience(DEFAULT_CLIENT_ID)
				.setExpirationTime("24h")
				.setJti("prev-jti-future")
				.sign(secretKey);
			const handler = createRefreshTokenGrant(depsWithStore);
			const ctx: GrantContext = {
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			await expect(handler.handle(ctx)).rejects.toThrow(/unhandled rotation outcome/);
		});
	});
});
