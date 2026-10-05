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
	createMemoryRefreshTokenFamilyStore,
	createRefreshTokenFamilyRevocation,
	createRefreshTokenFamilyRotation,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantDependencies,
	type GrantPolicyHook,
	type Logger,
	type RefreshTokenFamilyRotation,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import { decodeJwt, SignJWT } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createRefreshTokenGrant, type RefreshTokenGrantDeps } from "#/grants/refreshToken.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";

afterEach(() => {
	vi.useRealTimers();
});

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
			// Default policy for unknown_family is "reject".
			unknownFamilyPolicy: "reject",
			// Default policy for tokens lacking jti or family_id when rotation
			// is wired is "reject".
			legacyRtPolicy: "reject",
		},
		grants: {
			session: { enabled: true },
			authorization_code: { enabled: true },
			refresh_token: { enabled: true },
		},
	},
} as unknown as GrantDependencies["config"];

const mockDeps: RefreshTokenGrantDeps = {
	config: mockConfig,
	keyStore,
	sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
};

// Every test that hits the client-binding gate must supply both an `aud`
// (or `azp`) on the signed RT and a matching `authenticatedClient` on the
// GrantContext. Both default to "client1"; a test that needs a mismatch
// overrides the `body.refresh_token` aud or the ctx authenticatedClient.
const DEFAULT_CLIENT_ID = "client1";

async function makeRefreshToken(overrides: Record<string, unknown> = {}): Promise<string> {
	return (
		new SignJWT({ sub: "u1", scope: "read write", ...overrides })
			.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
			// Real RTs carry iat (generateToken sets it), and the subject
			// watermark compares against it — a fixture without one would skip
			// the backstop and never exercise it.
			.setIssuedAt()
			.setIssuer("localhost")
			.setAudience(DEFAULT_CLIENT_ID)
			.setExpirationTime("24h")
			.sign(secretKey)
	);
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

		it("returns 400 invalid_grant when authenticatedClient does not match RT azp/aud", async () => {
			// Token is bound to "client1" via aud; authenticatedClient is a
			// different client. The binding gate must reject: accepting it
			// would let any authenticated client redeem any RT.
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

		it("returns 401 invalid_client when ctx.authenticatedClient is null", async () => {
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

		it("RT with aud only, no azp + matching authenticatedClient → 200, new RT emits azp", async () => {
			// For a token carrying only `aud`, the binding gate falls back to
			// `aud === authenticatedClient.clientId`. The newly minted RT must
			// emit `azp = authenticatedClient.clientId` so later rotations do
			// not rely on the `aud` fallback.
			const legacyToken = await new SignJWT({ sub: "u1", scope: "read" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setIssuer("localhost")
				.setAudience("client1")
				// no azp claim
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

		it("mints the configured default lifetime and ignores an expires_in request parameter", async () => {
			// `expires_in` is the time left when answered: read on a frozen clock.
			vi.useFakeTimers({ toFake: ["Date"], now: Date.now() });
			// Only the current keys are configured, so a grant reading the
			// deprecated `expiresIn` would mint a token with no `exp` at all.
			const handler = createRefreshTokenGrant({
				...mockDeps,
				config: {
					oauth: {
						...mockConfig.oauth,
						accessToken: { defaultExpiresIn: 600, maxExpiresIn: 7200 },
					},
				} as unknown as GrantDependencies["config"],
			});
			const { result } = await handler.handle({
				body: { refresh_token: await makeRefreshToken(), expires_in: "7200" },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});

			if (!("tokens" in result)) throw new Error(`expected tokens, got ${result.status}`);
			expect(result.tokens.expires_in).toBe(600);
			const decoded = decodeJwt(result.tokens.access_token);
			expect((decoded.exp as number) - (decoded.iat as number)).toBe(600);
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

		it("refuses a requested scope that is not RFC 6749 §3.3's space-delimited list as malformed", async () => {
			const token = await makeRefreshToken();
			const handler = createRefreshTokenGrant(mockDeps);
			for (const scope of ["read\twrite", 'read "write"', "\t"]) {
				const { result } = await handler.handle({
					body: { refresh_token: token, scope },
					session: {},
					issuer: "localhost",
					metadata: {},
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				});
				expect(result.status, JSON.stringify(scope)).toBe(400);
				expect("error" in result && result.error).toBe("invalid_scope");
				expect("errorDescription" in result && result.errorDescription).toBe(
					"scope is not a space-delimited list of scope-tokens",
				);
			}
		});

		it("reads scope: null as no change of scope, and refuses any other value that is not a string", async () => {
			// RFC 6749 §3.2: a parameter sent without a value is treated as
			// omitted. A JSON body's `null` is that, as `scope=""` is for a form
			// body — the same reading token exchange gives `expires_in: null`. Any
			// other value that is not a string is `invalid_request`.
			const handler = createRefreshTokenGrant(mockDeps);
			const token = await makeRefreshToken({ scope: "read write" });
			const ctx = (body: Record<string, unknown>): GrantContext => ({
				body: { refresh_token: token, ...body },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});
			const nulled = (await handler.handle(ctx({ scope: null }))).result;
			if (!("tokens" in nulled)) expect.fail("expected tokens");
			expect(nulled.tokens.scope).toBe("read write");

			for (const scope of [42, {}, true]) {
				const { result } = await handler.handle(ctx({ scope }));
				expect(result, JSON.stringify(scope)).toMatchObject({
					status: 400,
					error: "invalid_request",
				});
			}
		});

		it("refuses a repeated scope parameter as invalid_request rather than throwing", async () => {
			// Express reads `scope=a&scope=b` as an array; calling `.split` on
			// it would make the request a 500.
			const { result } = await createRefreshTokenGrant(mockDeps).handle({
				body: { refresh_token: await makeRefreshToken(), scope: ["read", "write"] },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});
			expect(result).toEqual({
				status: 400,
				error: "invalid_request",
				errorDescription: "scope must be a space-delimited string",
			});
		});

		it("never carries a scope wider than the refresh token was minted with, and carries it on canonical", async () => {
			// A token minted before requests were read strictly can carry
			// `openid\temail` as one entry, which named no scope. Split on the tab
			// it would put `email` into the next pair of tokens, so the entry is
			// dropped: a narrowing request cannot find `email` in it, and the
			// refreshed tokens carry no scope at all.
			const ctx = (token: string, body: Record<string, unknown> = {}): GrantContext => ({
				body: { refresh_token: token, ...body },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});
			const handler = createRefreshTokenGrant(mockDeps);
			const legacy = await makeRefreshToken({ scope: "openid\temail" });

			const narrowed = (await handler.handle(ctx(legacy, { scope: "email" }))).result;
			expect(narrowed.status).toBe(400);
			expect("error" in narrowed && narrowed.error).toBe("invalid_scope");

			const carried = (await handler.handle(ctx(legacy))).result;
			if (!("tokens" in carried)) expect.fail("expected tokens");
			expect(carried.tokens.scope).toBeUndefined();
			expect(decodeJwt(carried.tokens.refresh_token as string).scope).toBeUndefined();
			expect(decodeJwt(carried.tokens.access_token).scope).toBeUndefined();

			// Runs of spaces name the same scopes, carried on in canonical form.
			const spaced = await makeRefreshToken({ scope: "read  write" });
			const canonical = (await handler.handle(ctx(spaced))).result;
			if (!("tokens" in canonical)) expect.fail("expected tokens");
			expect(canonical.tokens.scope).toBe("read write");
			expect(decodeJwt(canonical.tokens.refresh_token as string).scope).toBe("read write");
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
			it("rejects payload.type=refresh as a typ substitute", async () => {
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

			it("accepts header.typ rt+jwt with standard claims", async () => {
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

			it("ignores claims.user.id fallback for sub", async () => {
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

			it("rejects a typ-less JWT as invalid_grant, with legacyTypAccept off", async () => {
				// With `legacyTypAccept` off (the default), the verifier refuses
				// the typ-less token; the grant's own `rt+jwt` gate is not reached.
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
			// Rotation wired without revocation fails closed to 503, so a test
			// asserting only the "replayed" path supplies a noop revocation
			// stub to reach the replay branch.
			const noopRevocation = {
				async revokeFamily() {},
				async isFamilyRevoked() {
					return false;
				},
			};
			const depsWithStore: RefreshTokenGrantDeps = {
				...mockDeps,
				refreshTokenFamilyRotation: stub,
				refreshTokenFamilyRevocation: noopRevocation,
			};
			// When rotation is wired the token MUST carry both jti AND
			// family_id, otherwise the legacy gate fires before rotation.
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

		it("returns 503 temporarily_unavailable when refreshTokenFamilyRotation.rotate throws", async () => {
			const throwingRotation: RefreshTokenFamilyRotation = {
				async register() {},
				async rotate() {
					throw new Error("redis down");
				},
			};
			const depsWithStore: RefreshTokenGrantDeps = {
				...mockDeps,
				refreshTokenFamilyRotation: throwingRotation,
			};
			// The token must carry family_id when rotation is wired.
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

		it("is refused when it is built with a lifetime that is not a positive whole number of seconds, and no token is spent", async () => {
			// The schema refuses such a value at boot; a configuration built by
			// hand never meets it. `generateToken` refuses it too, but only after
			// the rotation has committed — the presented token spent and no token
			// issued in its place — and read per request, even a check
			// ahead of the rotation answers every request with a 500. The grant
			// reads both lifetimes when it is built instead.
			const refreshTokenFamilyStore = createMemoryRefreshTokenFamilyStore();
			// A revoked family is kept for as long as the access tokens it could
			// have minted are accepted: the store wrappers take that horizon.
			const accessTokenHorizonMs = 3_600_000;
			const rotation = createRefreshTokenFamilyRotation({
				refreshTokenFamilyStore,
				accessTokenHorizonMs,
			});
			const revocation = createRefreshTokenFamilyRevocation({
				refreshTokenFamilyStore,
				accessTokenHorizonMs,
			});
			await rotation.register("prev-jti-lifetime", "fam-lifetime", Date.now() + 86_400_000);
			const token = await new SignJWT({ sub: "u1", scope: "read write", family_id: "fam-lifetime" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setIssuedAt()
				.setIssuer("localhost")
				.setAudience(DEFAULT_CLIENT_ID)
				.setExpirationTime("24h")
				.setJti("prev-jti-lifetime")
				.sign(secretKey);
			const ctx: GrantContext = {
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};
			const withOAuth = (over: Record<string, unknown>): RefreshTokenGrantDeps => ({
				...mockDeps,
				config: {
					...mockConfig,
					oauth: { ...mockConfig.oauth, ...over },
				} as GrantDependencies["config"],
				refreshTokenFamilyRotation: rotation,
				refreshTokenFamilyRevocation: revocation,
			});

			const broken: Record<string, unknown>[] = [
				{ refreshToken: { ...mockConfig.oauth.refreshToken, expiresIn: 1.5 } },
				{ refreshToken: { ...mockConfig.oauth.refreshToken, expiresIn: Number.NaN } },
				{ refreshToken: { ...mockConfig.oauth.refreshToken, expiresIn: 0 } },
				{ accessToken: { expiresIn: 1.5 } },
			];
			for (const over of broken) {
				let refused: unknown;
				let handler: ReturnType<typeof createRefreshTokenGrant> | undefined;
				try {
					handler = createRefreshTokenGrant(withOAuth(over));
				} catch (err) {
					refused = err;
				}
				await handler?.handle(ctx).catch(() => undefined);
				expect(refused, JSON.stringify(over)).toBeInstanceOf(RangeError);
				expect((refused as Error).message).toMatch(/oauth\.(refreshToken|accessToken)\.expiresIn/);
			}

			// Nothing was spent: the same token still refreshes under a sound
			// configuration, rather than reading as a replay.
			const { result } = await createRefreshTokenGrant(withOAuth({})).handle(ctx);
			expect(result.status).toBe(200);
		});

		it("returns invalid_grant/family_revoked when the rotation reports 'revoked'", async () => {
			const stub = createStubRotation("revoked");
			const depsWithStore: RefreshTokenGrantDeps = {
				...mockDeps,
				refreshTokenFamilyRotation: stub,
			};
			// The token must carry family_id when rotation is wired.
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

	describe("RT reuse → family revoke", () => {
		// Stub rotation that always reports "replayed" (jti mismatch).
		const replayedRotation: RefreshTokenFamilyRotation = {
			async register() {},
			async rotate() {
				return { outcome: "replayed" };
			},
		};

		// Helper: a refresh token with both jti and family_id present so the
		// legacy-token gate doesn't fire. The replayed outcome is decided by the rotation
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

		it("revokes the RT family with the exact family_id when replay is detected", async () => {
			const revokeFamily = vi.fn().mockResolvedValue(undefined);
			const revocation = {
				revokeFamily,
				async isFamilyRevoked() {
					return false;
				},
			};
			const deps: RefreshTokenGrantDeps = {
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
			// Exact family_id, not expect.any(String).
			expect(revokeFamily).toHaveBeenCalledWith("fam-1");
			expect(revokeFamily).toHaveBeenCalledTimes(1);
		});

		// -------------------------------------------------------------------
		// The shipped rotation revokes the family inside the same
		// compare-and-swap that detected the replay, and reports
		// `familyRevoked: true`. The handler must then not write again: there
		// must be no second operation for a sibling to slip past.
		//
		// The `replayedRotation` stub above reports a bare
		// `{ outcome: "replayed" }`, so the tests around these two cover the
		// fallback path of a custom rotation that does not revoke atomically.
		// -------------------------------------------------------------------
		const atomicallyRevokedRotation: RefreshTokenFamilyRotation = {
			async register() {},
			async rotate() {
				return { outcome: "replayed", familyRevoked: true };
			},
		};

		it("does not revoke again when the rotation already revoked the family atomically", async () => {
			const revokeFamily = vi.fn().mockResolvedValue(undefined);
			const revocation = {
				revokeFamily,
				async isFamilyRevoked() {
					return false;
				},
			};
			const deps: RefreshTokenGrantDeps = {
				...mockDeps,
				refreshTokenFamilyRotation: atomicallyRevokedRotation,
				refreshTokenFamilyRevocation: revocation,
			};
			const rt = await makeReplayedRt("fam-1");

			const { result } = await createRefreshTokenGrant(deps).handle({
				...baseCtx,
				body: { refresh_token: rt },
			});

			// The wire response is the same either way: this is internal
			// ordering, not protocol.
			expect(result.status).toBe(400);
			if (!("error" in result)) expect.fail("Expected error in result");
			expect(result.error).toBe("invalid_grant");
			expect(result.errorDescription).toBe("replay_detected");
			expect(revokeFamily).not.toHaveBeenCalled();
		});

		it("still audits the revocation when the rotation revoked atomically", async () => {
			// The audit signal belongs to the replay, not to which component
			// performed the write. A SIEM watching for this event must not go
			// quiet because the revocation happened in the store.
			const warn = vi.fn();
			const logger = makeStubLogger(warn);
			const deps: RefreshTokenGrantDeps = {
				...mockDeps,
				refreshTokenFamilyRotation: atomicallyRevokedRotation,
				refreshTokenFamilyRevocation: {
					async revokeFamily() {},
					async isFamilyRevoked() {
						return false;
					},
				},
				logger,
			};
			const rt = await makeReplayedRt("fam-1");

			await createRefreshTokenGrant(deps).handle({ ...baseCtx, body: { refresh_token: rt } });

			expect(warn).toHaveBeenCalledWith(
				expect.objectContaining({ familyId: "fam-1", clientId: DEFAULT_CLIENT_ID }),
				"rt_reuse_detected_family_revoked",
			);
		});

		it("rejects with 400, not 503, when the rotation revoked atomically and no revocation dep is wired", async () => {
			// The 503 exists to avoid answering "just this request is refused"
			// while sibling RTs stay live. Once the family is already revoked
			// there is nothing left to fail closed about, and returning 503
			// would tell a client to retry a replay.
			const deps: RefreshTokenGrantDeps = {
				...mockDeps,
				refreshTokenFamilyRotation: atomicallyRevokedRotation,
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
		});

		it("returns 503 when revocation dep is missing (fail-closed)", async () => {
			// Rotation wired but no revocation dep: fail closed, since a silent
			// skip would break the RFC 6819 §5.2.2 guarantee.
			const deps: RefreshTokenGrantDeps = {
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

		it("returns 503 when revokeFamily throws during replay handling", async () => {
			const revocation = {
				async revokeFamily() {
					throw new Error("Redis down");
				},
				async isFamilyRevoked() {
					return false;
				},
			};
			const deps: RefreshTokenGrantDeps = {
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

		it("emits rt_reuse_detected_family_revoked audit log on replay", async () => {
			const warn = vi.fn();
			const logger = makeStubLogger(warn);
			const revocation = {
				async revokeFamily() {},
				async isFamilyRevoked() {
					return false;
				},
			};
			const deps: RefreshTokenGrantDeps = {
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

		it("concurrent replay calls revoke twice idempotently", async () => {
			const revokeFamily = vi.fn().mockResolvedValue(undefined);
			const revocation = {
				revokeFamily,
				async isFamilyRevoked() {
					return false;
				},
			};
			const deps: RefreshTokenGrantDeps = {
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

		it("issues tokens and revokes nothing when the rotation reports 'rotated'", async () => {
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
			const deps: RefreshTokenGrantDeps = {
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

	describe("unknown_family policy", () => {
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

		it("returns 400 invalid_grant for unknown_family with default policy", async () => {
			const deps: RefreshTokenGrantDeps = {
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

		it("issues tokens with unknownFamilyPolicy=accept, and warns that it did", async () => {
			const warn = vi.fn();
			const logger = makeStubLogger(warn);
			const deps: RefreshTokenGrantDeps = {
				sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
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

		it("returns 400 with explicit unknownFamilyPolicy=reject", async () => {
			const warn = vi.fn();
			const logger = makeStubLogger(warn);
			const deps: RefreshTokenGrantDeps = {
				sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
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

		it("still answers replay_detected, not unknown_family, for a replayed outcome", async () => {
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
			const deps: RefreshTokenGrantDeps = {
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

	describe("RT without jti/family_id rejection", () => {
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

		it("returns 400 invalid_grant for RT without jti when rotation is wired", async () => {
			const deps: RefreshTokenGrantDeps = {
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

		it("returns 400 missing_jti_or_family_id for RT without family_id when rotation is wired", async () => {
			const deps: RefreshTokenGrantDeps = {
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

		it("proceeds with normal rotation when RT has both jti and family_id", async () => {
			const rotateSpy = vi.fn().mockResolvedValue({ outcome: "rotated" });
			const rotation: RefreshTokenFamilyRotation = {
				async register() {},
				rotate: rotateSpy,
			};
			const deps: RefreshTokenGrantDeps = {
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
			// Rotation called with the original family_id
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
			const depsWithPolicy: RefreshTokenGrantDeps = { ...mockDeps, grantPolicy: policy };
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

		it("lets a policy grant within the original grant beyond a narrowed refresh request (RFC 6749 §6 ceiling)", async () => {
			// The ceiling is the original grant, not the request: this pins the
			// `scopeCeiling` the refresh grant hands the home, so passing the
			// request as the ceiling (or the grant as the default) fails here.
			const token = await makeRefreshToken({ scope: "read write" });
			const policy = createStubPolicy(async () => ({
				outcome: "allow",
				grantedScope: ["read", "write"],
			}));
			const handler = createRefreshTokenGrant({ ...mockDeps, grantPolicy: policy });
			const { result } = await handler.handle({
				body: { refresh_token: token, scope: "read" },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});
			if (!("tokens" in result)) expect.fail("Expected tokens in result");
			expect(result.tokens.scope).toBe("read write");

			// And a silent policy leaves the narrowed request, not the grant.
			const silent = createRefreshTokenGrant({
				...mockDeps,
				grantPolicy: createStubPolicy(async () => ({ outcome: "allow" })),
			});
			const narrowed = await silent.handle({
				body: { refresh_token: await makeRefreshToken({ scope: "read write" }), scope: "read" },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});
			if (!("tokens" in narrowed.result)) expect.fail("Expected tokens in result");
			expect(narrowed.result.tokens.scope).toBe("read");
		});

		it("issues no scope when the refresh token carried none and the policy says nothing", async () => {
			const handler = createRefreshTokenGrant({
				...mockDeps,
				grantPolicy: createStubPolicy(async () => ({ outcome: "allow" })),
			});
			const { result } = await handler.handle({
				body: { refresh_token: await makeRefreshToken({ scope: undefined }) },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});
			if (!("tokens" in result)) expect.fail("Expected tokens in result");
			expect(result.tokens.scope ?? null).toBeNull();
		});

		it("refuses a policy that returns a non-array grantedScope", async () => {
			const token = await makeRefreshToken({ scope: "read write" });
			const policy = createStubPolicy(
				async () =>
					({ outcome: "allow", grantedScope: "read" }) as unknown as Awaited<
						ReturnType<GrantPolicyHook["evaluate"]>
					>,
			);
			const handler = createRefreshTokenGrant({ ...mockDeps, grantPolicy: policy });
			const { result } = await handler.handle({
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			});
			expect(result.status).toBe(500);
			if ("error" in result) {
				expect(result.error).toBe("server_error");
				expect(result.errorDescription).toMatch(/non-array grantedScope/);
			} else {
				expect.fail("Expected an error result");
			}

			// Falsy but present: still malformed, not "no opinion".
			for (const malformed of ["", null]) {
				const falsy = createStubPolicy(
					async () =>
						({ outcome: "allow", grantedScope: malformed }) as unknown as Awaited<
							ReturnType<GrantPolicyHook["evaluate"]>
						>,
				);
				const out = await createRefreshTokenGrant({ ...mockDeps, grantPolicy: falsy }).handle({
					body: { refresh_token: await makeRefreshToken({ scope: "read write" }) },
					session: {},
					issuer: "localhost",
					metadata: {},
					authenticatedClient: DEFAULT_AUTH_CLIENT,
				});
				expect(out.result.status).toBe(500);
			}
		});

		it("forwards ctx.ip and ctx.userAgent to grantPolicy.evaluate", async () => {
			const token = await makeRefreshToken({ scope: "read write" });
			let observedIp: string | undefined;
			let observedUa: string | undefined;
			const policy = createStubPolicy(async (_req, ctxArg) => {
				observedIp = ctxArg.ip;
				observedUa = ctxArg.userAgent;
				return { outcome: "allow" };
			});
			const depsWithPolicy: RefreshTokenGrantDeps = { ...mockDeps, grantPolicy: policy };
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

		it("answers a policy's access_denied deny invalid_request, never invalid_grant, which would kill the refresh token", async () => {
			const token = await makeRefreshToken({ scope: "read write" });
			const policy = createStubPolicy(async () => ({
				outcome: "deny",
				error: "access_denied",
				errorDescription: "policy",
			}));
			const depsWithPolicy: RefreshTokenGrantDeps = { ...mockDeps, grantPolicy: policy };
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
				expect(result.error).toBe("invalid_request");
				expect(result.errorDescription).toBe("policy");
			} else {
				expect.fail("Expected error in result");
			}
		});

		it("leaves the refresh token usable after a policy deny: the same token refreshes once the policy allows", async () => {
			const refreshTokenFamilyStore = createMemoryRefreshTokenFamilyStore();
			const accessTokenHorizonMs = 3_600_000;
			const rotation = createRefreshTokenFamilyRotation({
				refreshTokenFamilyStore,
				accessTokenHorizonMs,
			});
			const revocation = createRefreshTokenFamilyRevocation({
				refreshTokenFamilyStore,
				accessTokenHorizonMs,
			});
			await rotation.register("prev-jti-policy", "fam-policy", Date.now() + 86_400_000);
			const token = await new SignJWT({ sub: "u1", scope: "read write", family_id: "fam-policy" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setIssuedAt()
				.setIssuer("localhost")
				.setAudience(DEFAULT_CLIENT_ID)
				.setExpirationTime("24h")
				.setJti("prev-jti-policy")
				.sign(secretKey);
			let denying = true;
			const handler = createRefreshTokenGrant({
				...mockDeps,
				refreshTokenFamilyRotation: rotation,
				refreshTokenFamilyRevocation: revocation,
				grantPolicy: createStubPolicy(async () =>
					denying ? { outcome: "deny", error: "access_denied" } : { outcome: "allow" },
				),
			});
			const ctx: GrantContext = {
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const denied = await handler.handle(ctx);
			expect(denied.result).toMatchObject({ status: 400, error: "invalid_request" });

			denying = false;
			const refreshed = await handler.handle(ctx);
			expect(refreshed.result.status).toBe(200);
			expect("tokens" in refreshed.result && refreshed.result.tokens.refresh_token).toEqual(
				expect.any(String),
			);
		});

		it("answers 500 server_error when policy grantedScope exceeds the original grant (RFC 6749 §6)", async () => {
			const token = await makeRefreshToken({ scope: "read" });
			const policy = createStubPolicy(async () => ({
				outcome: "allow",
				grantedScope: ["read", "admin"], // admin is NOT in the original "read"
			}));
			const depsWithPolicy: RefreshTokenGrantDeps = { ...mockDeps, grantPolicy: policy };
			const handler = createRefreshTokenGrant(depsWithPolicy);
			const ctx: GrantContext = {
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(500);
			if (!("error" in result)) expect.fail("Expected error in result");
			expect(result.error).toBe("server_error");
			expect(result.errorDescription).toContain("admin");
		});

		it("returns 503 temporarily_unavailable when grantPolicy.evaluate throws", async () => {
			const token = await makeRefreshToken({ scope: "read" });
			const policy = createStubPolicy(async () => {
				throw new Error("policy backend 502");
			});
			const depsWithPolicy: RefreshTokenGrantDeps = { ...mockDeps, grantPolicy: policy };
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
			expect(result.errorDescription ?? "").not.toContain("policy backend 502");
		});

		it("omits scope from token response when policy narrows to empty array", async () => {
			const token = await makeRefreshToken({ scope: "read write" });
			const policy = createStubPolicy(async () => ({
				outcome: "allow",
				grantedScope: [],
			}));
			const depsWithPolicy: RefreshTokenGrantDeps = { ...mockDeps, grantPolicy: policy };
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

	describe("refresh_token grant — grantPolicy audience validation", () => {
		function createStubPolicy(evaluate: GrantPolicyHook["evaluate"]): GrantPolicyHook {
			return { kind: "stub", evaluate };
		}

		function depsWithAudiencePolicy(evaluate: GrantPolicyHook["evaluate"]): RefreshTokenGrantDeps {
			return {
				...mockDeps,
				config: {
					oauth: {
						...mockDeps.config.oauth,
						resourceIndicator: { enabled: true },
					},
				} as unknown as GrantDependencies["config"],
				grantPolicy: createStubPolicy(evaluate),
				// allowedAudiences lives on the authenticatedClient in the ctx — set per-test.
			};
		}

		it("answers 500 server_error when policy grantedAudience is outside client.allowedAudiences", async () => {
			// Policy returns an audience not in client.allowedAudiences → fail-closed.
			const token = await makeRefreshToken({ scope: "read" });
			const deps = depsWithAudiencePolicy(async () => ({
				outcome: "allow",
				grantedAudience: ["https://other.example"],
			}));
			const handler = createRefreshTokenGrant(deps);

			const { result } = await handler.handle({
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: {
					...DEFAULT_AUTH_CLIENT,
					allowedAudiences: ["https://api.example"],
				},
			});

			expect(result.status).toBe(500);
			if (!("error" in result)) expect.fail("Expected error in result");
			expect(result.error).toBe("server_error");
			expect(result.errorDescription).toContain("https://other.example");
		});

		it("uses policy grantedAudience when within client.allowedAudiences", async () => {
			// Policy narrows to ["https://api.example"] ∈ allowedAudiences → 200, token aud is https://api.example.
			const token = await makeRefreshToken({ scope: "read" });
			const deps = depsWithAudiencePolicy(async () => ({
				outcome: "allow",
				grantedAudience: ["https://api.example"],
			}));
			const handler = createRefreshTokenGrant(deps);

			const { result } = await handler.handle({
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: {
					...DEFAULT_AUTH_CLIENT,
					allowedAudiences: ["https://api.example", "https://other.example"],
				},
			});

			expect(result.status).toBe(200);
			if (!("tokens" in result)) expect.fail("Expected tokens in result");
			const parts = result.tokens.access_token.split(".");
			const payload = JSON.parse(
				Buffer.from(parts[1] ?? "", "base64url").toString("utf-8"),
			) as Record<string, unknown>;
			expect(payload.aud).toBe("https://api.example");
		});
	});

	describe("sid claim propagation and userSessionStore integration", () => {
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

		it("preserves family_id and sid on both minted tokens", async () => {
			const token = await makeRefreshToken({ family_id: "fam-1", sid: "sid-1" });
			const store = createStubUserSessionStore(async (_sid) => ({
				sid: "sid-1",
				sub: "u1",
				authTime: new Date(),
				createdAt: new Date(),
				expiresAt: new Date(Date.now() + 3600_000),
				claims: {},
				amr: undefined,
				authentication: undefined,
			}));
			const deps: RefreshTokenGrantDeps = { ...mockDeps, userSessionStore: store };
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

		it("returns 400 invalid_grant when userSessionStore.get returns null", async () => {
			const token = await makeRefreshToken({ sid: "sid-dead" });
			const store = createStubUserSessionStore(async (_sid) => null);
			const deps: RefreshTokenGrantDeps = { ...mockDeps, userSessionStore: store };
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

		it("returns 503 temporarily_unavailable when userSessionStore.get throws", async () => {
			const token = await makeRefreshToken({ sid: "sid-boom" });
			const store = createStubUserSessionStore(async (_sid) => {
				throw new Error("redis down");
			});
			const deps: RefreshTokenGrantDeps = { ...mockDeps, userSessionStore: store };
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

		it("succeeds without sid on minted tokens when the presented token has no sid claim", async () => {
			// A token with only family_id, no sid
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

	// The switch's `default` arm is reachable only by casting to an outcome
	// not in the `RefreshTokenFamilyRotationOutcome` union. It exists so an
	// outcome added without updating the switch is rejected with a stable
	// error rather than silently falling through to token issuance.
	describe("exhaustive rotation-outcome switch (defense-in-depth)", () => {
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
			const depsWithStore: RefreshTokenGrantDeps = {
				...mockDeps,
				refreshTokenFamilyRotation: rotation,
			};
			// The token must carry both jti AND family_id so the legacy
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

	describe("subject-revocation watermark backstop", () => {
		const makeSubjectRevocation = (revokedSubject: string) => ({
			kind: "stub",
			revokeBefore: async () => {},
			// Watermark far in the future: every RT this subject already holds
			// was minted before it.
			revokedBefore: async (sub: string) =>
				sub === revokedSubject ? new Date(Date.now() + 86_400_000) : null,
		});

		it("refuses an RT minted before the subject's watermark with invalid_grant", async () => {
			// The subject-revocation cascade revokes RT families directly; the
			// watermark is the backstop for a partial cascade failure. An RT
			// whose iat is at or before the watermark must not redeem, forcing
			// re-authentication.
			const handler = createRefreshTokenGrant({
				...mockDeps,
				subjectRevocation: makeSubjectRevocation("u1"),
			});
			const ctx: GrantContext = {
				body: { refresh_token: await makeRefreshToken() },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			expect("error" in result && result.error).toBe("invalid_grant");
		});

		it("does not touch an RT whose subject has no watermark in force", async () => {
			const handler = createRefreshTokenGrant({
				...mockDeps,
				subjectRevocation: makeSubjectRevocation("someone-else"),
			});
			const ctx: GrantContext = {
				body: { refresh_token: await makeRefreshToken() },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			// The token passes verification (no watermark rejection); whatever
			// happens downstream, it is NOT the verifier's invalid_grant.
			const description = "errorDescription" in result ? result.errorDescription : undefined;
			expect(description).not.toBe("invalid refresh_token");
		});
	});

	/*
	 * A watermark store outage is not a revocation. The verifier fails closed
	 * on an unreachable store, and the handler answers it as it answers a
	 * family-store outage, `503 temporarily_unavailable`, not
	 * `400 invalid_grant`: per RFC 6749 §5.2 a client discards its refresh
	 * token on `invalid_grant`, so a transient outage would log out every
	 * user who refreshed during it.
	 */
	describe("subject-revocation store outage", () => {
		const outageStore = {
			kind: "outage",
			revokeBefore: async () => {},
			revokedBefore: async () => {
				throw new Error("ECONNREFUSED");
			},
		};

		const refreshWith = async (subjectRevocation: unknown) => {
			const handler = createRefreshTokenGrant({
				...mockDeps,
				subjectRevocation,
			} as never);
			const ctx: GrantContext = {
				body: { refresh_token: await makeRefreshToken() },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			};
			return (await handler.handle(ctx)).result;
		};

		it("answers 503 temporarily_unavailable, not invalid_grant", async () => {
			const result = await refreshWith(outageStore);
			expect(result.status).toBe(503);
			expect("error" in result && result.error).toBe("temporarily_unavailable");
		});

		it("matches what a family-store outage already answered", async () => {
			// The two outages are the same event class on the same endpoint and
			// are answered the same way.
			const result = await refreshWith(outageStore);
			expect(result.status).toBe(503);
		});

		it("does not tell the client to discard its refresh token", async () => {
			// The whole point: RFC 6749 §5.2 makes `invalid_grant` the signal to
			// throw the credential away.
			const result = await refreshWith(outageStore);
			expect("error" in result && result.error).not.toBe("invalid_grant");
		});

		it("still refuses the request — the outage is not fail-open", async () => {
			const result = await refreshWith(outageStore);
			expect("tokens" in result).toBe(false);
		});

		it("keeps a genuine watermark hit on invalid_grant", async () => {
			// The 503 branch must not start swallowing real revocations.
			const result = await refreshWith({
				kind: "stub",
				revokeBefore: async () => {},
				revokedBefore: async () => new Date(Date.now() + 86_400_000),
			});
			expect(result.status).toBe(400);
			expect("error" in result && result.error).toBe("invalid_grant");
		});

		it("keeps a malformed token on invalid_grant", async () => {
			// Every other verification failure is still the client's problem.
			const handler = createRefreshTokenGrant({ ...mockDeps } as never);
			const { result } = await handler.handle({
				body: { refresh_token: "not-a-jwt" },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			} as GrantContext);
			expect(result.status).toBe(400);
			expect("error" in result && result.error).toBe("invalid_grant");
		});
	});
});

describe("refresh rotation reserves before it signs", () => {
	/** The key store, with every signature counted. */
	const countingKeyStore = () => {
		const signed: unknown[] = [];
		return {
			signed,
			keyStore: {
				...keyStore,
				sign: async (args: Parameters<typeof keyStore.sign>[0]) => {
					signed.push(args);
					return keyStore.sign(args);
				},
			} as typeof keyStore,
		};
	};

	const presented = async () =>
		new SignJWT({ sub: "u1", scope: "read write", family_id: "fam-1" })
			.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
			.setIssuer("localhost")
			.setAudience(DEFAULT_CLIENT_ID)
			.setIssuedAt()
			.setExpirationTime("24h")
			.setJti("old-jti")
			.sign(new TextEncoder().encode(SECRET));

	const run = async (
		rotation: RefreshTokenFamilyRotation,
		store: ReturnType<typeof countingKeyStore>,
	) => {
		const handler = createRefreshTokenGrant({
			...mockDeps,
			keyStore: store.keyStore,
			refreshTokenFamilyRotation: rotation,
			refreshTokenFamilyRevocation: {
				async revokeFamily() {},
				async isFamilyRevoked() {
					return false;
				},
			},
		});
		return handler.handle({
			body: { refresh_token: await presented() },
			session: {},
			issuer: "localhost",
			metadata: {},
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		});
	};

	it("spends no signature when the family store refuses the rotation", async () => {
		// A lost race (a replay, a revoked family) must not cost signatures
		// for tokens that are never issued: with a KMS-backed signing key each
		// is a billable remote call.
		for (const outcome of ["replayed", "revoked", "unknown_family"] as const) {
			const store = countingKeyStore();
			const { result } = await run(
				{
					async register() {},
					async rotate() {
						return { outcome };
					},
				},
				store,
			);
			expect(result.status).toBe(400);
			expect(store.signed).toHaveLength(0);
		}
	});

	it("spends no signature when the family store is unreachable", async () => {
		const store = countingKeyStore();
		const { result } = await run(
			{
				async register() {},
				async rotate() {
					throw new Error("redis down");
				},
			},
			store,
		);
		expect(result.status).toBe(503);
		expect(store.signed).toHaveLength(0);
	});

	it("signs no longer than the family ceiling the rotation actually committed", async () => {
		// The family TTL is set once at creation and never extended,
		// so a rotation late in a family's life commits a shorter expiry than
		// it was asked for and reports it as `cappedExpiresAtMs`. A token
		// signed past that outlives the record that would catch its replay.
		const store = countingKeyStore();
		const cappedAt = Date.now() + 42_000;
		const { result } = await run(
			{
				async register() {},
				async rotate() {
					return { outcome: "rotated" as const, cappedExpiresAtMs: cappedAt };
				},
			},
			store,
		);
		expect(result.status).toBe(200);
		if (!("tokens" in result)) return expect.fail("expected tokens");
		const claims = JSON.parse(
			Buffer.from(
				(result.tokens.refresh_token as string).split(".")[1] ?? "",
				"base64url",
			).toString("utf-8"),
		) as Record<string, unknown>;
		// At or inside the committed ceiling — never past it. The adapter's
		// reported value drifts forward by milliseconds, so a one-second margin
		// comes off before flooring.
		expect((claims.exp as number) * 1000).toBeLessThanOrEqual(cappedAt);
		expect(claims.exp as number).toBe(Math.floor((cappedAt - 1_000) / 1000));
	});

	it("keeps a margin for the forward drift, which flooring alone does not", async () => {
		// The contract (`RefreshTokenFamilyRotationOutcome.cappedExpiresAtMs`)
		// says the reported ceiling drifts FORWARD and asks for a subtracted
		// margin. Flooring truncates: a true ceiling at …10.998 s reported as
		// …11.002 s floors to 11 s, two milliseconds past the record.
		const store = countingKeyStore();
		const reported = (Math.floor(Date.now() / 1000) + 42) * 1000 + 2; // just past a second
		const { result } = await run(
			{
				async register() {},
				async rotate() {
					return { outcome: "rotated" as const, cappedExpiresAtMs: reported };
				},
			},
			store,
		);
		if (!("tokens" in result)) return expect.fail("expected tokens");
		const exp = decodeJwt(result.tokens.refresh_token as string).exp as number;
		// The true ceiling may be up to the drift earlier than reported.
		expect(exp * 1000).toBeLessThanOrEqual(reported - 1_000);
	});

	it("refuses rather than issue a refresh token the family ceiling leaves no lifetime for", async () => {
		// An exhausted family must not become `expiresIn: 0`, a 200 carrying
		// an already-expired refresh token after the presented one was spent.
		// The family reached its lifetime; say so.
		const store = countingKeyStore();
		const { result } = await run(
			{
				async register() {},
				async rotate() {
					return { outcome: "rotated" as const, cappedExpiresAtMs: Date.now() + 400 };
				},
			},
			store,
		);
		expect(result.status).toBe(400);
		if (!("error" in result)) return expect.fail("expected an error");
		expect(result.error).toBe("invalid_grant");
		expect(result.errorDescription).toMatch(/lifetime/);
		expect(store.signed).toHaveLength(0);
	});

	it("ignores a cap that is not shorter than what it asked for", async () => {
		const store = countingKeyStore();
		const { result } = await run(
			{
				async register() {},
				async rotate(_previousJti: string, _newJti: string, _family: string, expiresAt: number) {
					return { outcome: "rotated" as const, cappedExpiresAtMs: expiresAt + 60_000 };
				},
			},
			store,
		);
		expect(result.status).toBe(200);
		if (!("tokens" in result)) return expect.fail("expected tokens");
		const claims = JSON.parse(
			Buffer.from(
				(result.tokens.refresh_token as string).split(".")[1] ?? "",
				"base64url",
			).toString("utf-8"),
		) as Record<string, unknown>;
		expect((claims.exp as number) - (claims.iat as number)).toBe(
			mockConfig.oauth.refreshToken.expiresIn,
		);
	});

	it("does not shorten a rotation the family did not cap", async () => {
		// The store reports the committed ceiling on every rotation; when the
		// family is younger than the requested lifetime that is exactly the
		// expiry asked for. The drift margin is for a cap that fired; applied
		// here it would take a second off every refresh token, and refuse a
		// one-second lifetime as exhausted.
		const store = countingKeyStore();
		const { result } = await run(
			{
				async register() {},
				async rotate(_previousJti: string, _newJti: string, _family: string, expiresAt: number) {
					return { outcome: "rotated" as const, cappedExpiresAtMs: expiresAt };
				},
			},
			store,
		);
		if (!("tokens" in result)) return expect.fail("expected tokens");
		const claims = decodeJwt(result.tokens.refresh_token as string);
		expect((claims.exp as number) - (claims.iat as number)).toBe(
			mockConfig.oauth.refreshToken.expiresIn,
		);
	});

	it("refuses when the store took longer than the capped lifetime it left", async () => {
		// `issuedAt` is reserved before the rotation; a slow store can use up
		// what the cap left, and the token would be signed already expired.
		vi.useFakeTimers({ toFake: ["Date"] });
		try {
			const start = 1_800_000_000_000;
			vi.setSystemTime(start);
			const store = countingKeyStore();
			const { result } = await run(
				{
					async register() {},
					async rotate() {
						vi.setSystemTime(start + 4_000); // the CAS round trip took four seconds
						return { outcome: "rotated" as const, cappedExpiresAtMs: start + 3_500 };
					},
				},
				store,
			);
			expect(result.status).toBe(400);
			expect(store.signed).toHaveLength(0);
		} finally {
			vi.useRealTimers();
		}
	});

	it("signs the jti and expiry it reserved, once the reservation holds", async () => {
		const reserved: { jti?: string; expiresAt?: number } = {};
		const store = countingKeyStore();
		const { result } = await run(
			{
				async register() {},
				async rotate(_previousJti: string, newJti: string, _family: string, expiresAt: number) {
					reserved.jti = newJti;
					reserved.expiresAt = expiresAt;
					return { outcome: "rotated" as const };
				},
			},
			store,
		);
		expect(result.status).toBe(200);
		if (!("tokens" in result)) return expect.fail("expected tokens");
		const claims = JSON.parse(
			Buffer.from(
				(result.tokens.refresh_token as string).split(".")[1] ?? "",
				"base64url",
			).toString("utf-8"),
		) as Record<string, unknown>;
		expect(claims.jti).toBe(reserved.jti);
		expect((claims.exp as number) * 1000).toBe(reserved.expiresAt);
		// The access token and the refresh token, and nothing before them.
		expect(store.signed).toHaveLength(2);
	});
});

describe("a signing failure after the rotation commits", () => {
	const presented = async () =>
		new SignJWT({ sub: "u1", scope: "read write", family_id: "fam-1" })
			.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
			.setIssuer("localhost")
			.setAudience(DEFAULT_CLIENT_ID)
			.setIssuedAt()
			.setExpirationTime("24h")
			.setJti("old-jti")
			.sign(new TextEncoder().encode(SECRET));

	/** A key store that signs `ok` times and then fails, as a KMS outage would. */
	const failingAfter = (ok: number) => {
		let signed = 0;
		return {
			...keyStore,
			sign: async (args: Parameters<typeof keyStore.sign>[0]) => {
				signed += 1;
				if (signed > ok) throw new Error("KMS unavailable");
				return keyStore.sign(args);
			},
		} as typeof keyStore;
	};

	const run = async (ok: number, logger?: unknown) => {
		const rotated: string[] = [];
		const handler = createRefreshTokenGrant({
			...mockDeps,
			keyStore: failingAfter(ok),
			...(logger === undefined ? {} : { logger: logger as never }),
			refreshTokenFamilyRotation: {
				async register() {},
				async rotate(previousJti: string) {
					rotated.push(previousJti);
					return { outcome: "rotated" as const };
				},
			},
			refreshTokenFamilyRevocation: {
				async revokeFamily() {},
				async isFamilyRevoked() {
					return false;
				},
			},
		});
		const out = await handler.handle({
			body: { refresh_token: await presented() },
			session: {},
			issuer: "localhost",
			metadata: {},
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		} as GrantContext);
		return { ...out, rotated };
	};

	it("answers temporarily_unavailable rather than an unhandled error", async () => {
		// Reserve-before-sign means the old jti is already consumed when the
		// signer fails: the client gets nothing, and its retry with the old
		// token reads as a replay, which revokes the whole family. An
		// unhandled throw would make that an express 500 with no log naming
		// the family, the one case an operator most needs to find.
		const { result } = await run(0);
		expect(result.status).toBe(503);
		expect("error" in result && result.error).toBe("temporarily_unavailable");
	});

	it("fails the same way when only the refresh token cannot be signed", async () => {
		// The access token signs, the refresh token does not: the rotation is
		// still committed, so this is the same orphan.
		const { result } = await run(1);
		expect(result.status).toBe(503);
	});

	it("does not call a rotation-less signer failure an orphan", async () => {
		// No rotation is wired, so nothing was reserved and the presented token
		// is still valid: this is the ordinary signer outage every other mint
		// has, and it surfaces the way the runbook says they all do.
		const error = vi.fn();
		const handler = createRefreshTokenGrant({
			...mockDeps,
			keyStore: failingAfter(0),
			logger: { error, warn: vi.fn(), info: vi.fn(), debug: vi.fn() } as never,
			refreshTokenFamilyRotation: undefined,
		});
		await expect(
			handler.handle({
				body: { refresh_token: await presented() },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			} as GrantContext),
		).rejects.toThrow(/KMS unavailable/);
		expect(error).not.toHaveBeenCalledWith(expect.anything(), "refresh_token_rotation_orphaned");
	});

	it("logs the orphaned rotation, naming what an operator has to look for", async () => {
		const error = vi.fn();
		const logger = { error, warn: vi.fn(), info: vi.fn(), debug: vi.fn() };
		await run(0, logger);
		expect(error).toHaveBeenCalledWith(
			expect.objectContaining({
				familyId: expect.any(String),
				previousJti: "old-jti",
				newRefreshJti: expect.any(String),
			}),
			"refresh_token_rotation_orphaned",
		);
	});
});

describe("refresh carries how the user authenticated", () => {
	// `amr` and `acr` describe the authentication event, which a refresh does
	// not repeat. The access token mirrors them so auth.policy-verifier or a
	// resource server can gate on them without an id_token (README); a
	// refresh that dropped them would pass a policy requiring `mfa` in `amr`
	// on the first access token and fail it on the first refresh.
	const presentedWith = async (extra: Record<string, unknown>) =>
		new SignJWT({ sub: "u1", scope: "read write", family_id: "fam-1", ...extra })
			.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
			.setIssuer("localhost")
			.setAudience(DEFAULT_CLIENT_ID)
			.setIssuedAt()
			.setExpirationTime("24h")
			.setJti("old-jti")
			.sign(new TextEncoder().encode(SECRET));

	const refresh = async (refreshToken: string, deps: Partial<RefreshTokenGrantDeps> = {}) => {
		const handler = createRefreshTokenGrant({
			...mockDeps,
			...deps,
			refreshTokenFamilyRotation: {
				async register() {},
				async rotate() {
					return { outcome: "rotated" as const };
				},
			},
			refreshTokenFamilyRevocation: {
				async revokeFamily() {},
				async isFamilyRevoked() {
					return false;
				},
			},
		});
		const { result } = await handler.handle({
			body: { refresh_token: refreshToken },
			session: {},
			issuer: "localhost",
			metadata: {},
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		} as GrantContext);
		if (!("tokens" in result)) throw new Error(`expected tokens, got ${JSON.stringify(result)}`);
		return {
			at: decodeJwt(result.tokens.access_token as string) as Record<string, unknown>,
			rt: decodeJwt(result.tokens.refresh_token as string) as Record<string, unknown>,
		};
	};

	it("carries amr and acr from the presented refresh token onto both new tokens", async () => {
		const { at, rt } = await refresh(
			await presentedWith({ amr: ["pwd", "mfa"], acr: "urn:example:mfa" }),
		);
		expect(at.amr).toEqual(["pwd", "mfa"]);
		expect(at.acr).toBe("urn:example:mfa");
		// Onto the new refresh token too, or the second refresh drops them.
		expect(rt.amr).toEqual(["pwd", "mfa"]);
		expect(rt.acr).toBe("urn:example:mfa");
	});

	it("carries nothing when the presented token has none", async () => {
		const { at, rt } = await refresh(await presentedWith({}));
		expect(at).not.toHaveProperty("amr");
		expect(at).not.toHaveProperty("acr");
		expect(rt).not.toHaveProperty("amr");
	});

	it("carries auth_time from the presented refresh token onto both new tokens", async () => {
		// RFC 9470 §6.1: the authentication event's values do not change when
		// the access token is renewed.
		const { at, rt } = await refresh(await presentedWith({ auth_time: 1_776_729_600 }));
		expect(at.auth_time).toBe(1_776_729_600);
		expect(rt.auth_time).toBe(1_776_729_600);
	});

	it("caps a carried auth_time later than its own issuance at that issuance, on both new tokens", async () => {
		const ahead = Math.floor(Date.now() / 1000) + 3600;
		const { at, rt } = await refresh(await presentedWith({ auth_time: ahead }));
		expect(rt.auth_time).toBe(rt.iat);
		expect(at.auth_time).toBe(rt.iat);
		expect(at.auth_time as number).toBeLessThanOrEqual(at.iat as number);
	});

	it("a clock that steps back between the refresh's issuance and the signing still gives auth_time <= iat on both tokens", async () => {
		const presented = await presentedWith({ auth_time: Math.floor(Date.now() / 1000) });
		let t = Date.now();
		const clock = vi.spyOn(Date, "now").mockImplementation(() => {
			t -= 2_000;
			return t;
		});
		try {
			const { at, rt } = await refresh(presented);
			expect(at.auth_time as number).toBeLessThanOrEqual(at.iat as number);
			expect(rt.auth_time as number).toBeLessThanOrEqual(rt.iat as number);
		} finally {
			clock.mockRestore();
		}
	});

	it("caps a carried auth_time later than the presented token's own iat at that iat", async () => {
		const presentedIat = Math.floor(Date.now() / 1000) - 3600;
		const presented = await new SignJWT({
			sub: "u1",
			scope: "read write",
			family_id: "fam-1",
			auth_time: presentedIat + 600,
		})
			.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
			.setIssuer("localhost")
			.setAudience(DEFAULT_CLIENT_ID)
			.setIssuedAt(presentedIat)
			.setExpirationTime("24h")
			.setJti("old-jti")
			.sign(new TextEncoder().encode(SECRET));
		const { at, rt } = await refresh(presented);
		expect(at.auth_time).toBe(presentedIat);
		expect(rt.auth_time).toBe(presentedIat);
	});

	it("refreshes a refresh token that carries no auth_time, and takes none from its live session", async () => {
		const session: UserSession = {
			sid: "sid-1",
			sub: "u1",
			authTime: new Date("2026-04-21T00:00:00Z"),
			createdAt: new Date("2026-04-21T00:00:00Z"),
			expiresAt: new Date(Date.now() + 3_600_000),
			claims: {},
			amr: ["pwd"],
			authentication: undefined,
		};
		const userSessionStore: UserSessionStore = {
			kind: "stub",
			async get(sid) {
				return sid === session.sid ? session : null;
			},
			async create() {},
			async delete() {},
		};
		const { at, rt } = await refresh(await presentedWith({ sid: "sid-1", amr: ["pwd"] }), {
			userSessionStore,
		});
		expect(at.sub).toBe("u1");
		expect(at).not.toHaveProperty("auth_time");
		expect(rt).not.toHaveProperty("auth_time");
	});

	it("does not carry a malformed auth_time forward", async () => {
		for (const bad of ["1776729600", -1, 1_776_729_600.5, null, true]) {
			const { at, rt } = await refresh(await presentedWith({ auth_time: bad }));
			expect(at, JSON.stringify(bad)).not.toHaveProperty("auth_time");
			expect(rt, JSON.stringify(bad)).not.toHaveProperty("auth_time");
		}
	});

	it("keeps auth_time, amr and acr through a chain of rotations", async () => {
		const refreshTokenFamilyStore = createMemoryRefreshTokenFamilyStore();
		const accessTokenHorizonMs = 3_600_000;
		const rotation = createRefreshTokenFamilyRotation({
			refreshTokenFamilyStore,
			accessTokenHorizonMs,
		});
		const handler = createRefreshTokenGrant({
			...mockDeps,
			refreshTokenFamilyRotation: rotation,
			refreshTokenFamilyRevocation: createRefreshTokenFamilyRevocation({
				refreshTokenFamilyStore,
				accessTokenHorizonMs,
			}),
		});
		await rotation.register("old-jti", "fam-1", Date.now() + 86_400_000);
		const authentication = {
			auth_time: 1_776_729_600,
			amr: ["pwd", "otp", "mfa"],
			acr: "urn:example:mfa",
		};
		let presented = await presentedWith(authentication);
		for (const round of [1, 2, 3]) {
			const { result } = await handler.handle({
				body: { refresh_token: presented },
				session: {},
				issuer: "localhost",
				metadata: {},
				authenticatedClient: DEFAULT_AUTH_CLIENT,
			} as GrantContext);
			if (!("tokens" in result)) throw new Error(`round ${round}: ${JSON.stringify(result)}`);
			expect(decodeJwt(result.tokens.access_token), `round ${round}`).toMatchObject(authentication);
			presented = result.tokens.refresh_token as string;
			expect(decodeJwt(presented), `round ${round}`).toMatchObject(authentication);
		}
	});

	it("does not carry a malformed amr or acr forward", async () => {
		// This server minted the presented token, so these shapes should never
		// occur — but a claim copied forward is a claim vouched for again, and
		// a resource server reads `amr` as a list of strings.
		for (const bad of [
			{ amr: "pwd", acr: 42 },
			{ amr: ["pwd", 7], acr: "" },
			{ amr: [], acr: null },
		]) {
			const { at } = await refresh(await presentedWith(bad));
			expect(at, JSON.stringify(bad)).not.toHaveProperty("amr");
			expect(at, JSON.stringify(bad)).not.toHaveProperty("acr");
		}
	});
});
