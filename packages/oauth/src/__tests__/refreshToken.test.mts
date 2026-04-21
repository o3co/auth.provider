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
	type RefreshTokenRotateOutcome,
	type RefreshTokenStoreBase,
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
			authorization: { enabled: true },
			refresh_token: { enabled: true },
			did: { enabled: true, messageMaxAgeSec: 300 },
		},
	},
} as unknown as GrantDependencies["config"];

const mockDeps: GrantDependencies = {
	config: mockConfig,
	keyStore,
};

async function makeRefreshToken(overrides: Record<string, unknown> = {}): Promise<string> {
	return new SignJWT({ sub: "u1", scope: "read write", ...overrides })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
		.setExpirationTime("24h")
		.sign(secretKey);
}

describe("createRefreshTokenGrant", () => {
	describe("handle", () => {
		it("returns 400 when refresh_token is missing", async () => {
			const handler = createRefreshTokenGrant(mockDeps);
			const ctx: GrantContext = {
				body: {},
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
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
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 400 when client_id does not match token audience", async () => {
			const token = await new SignJWT({ sub: "u1" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setAudience("client1")
				.setExpirationTime("24h")
				.sign(secretKey);
			const handler = createRefreshTokenGrant(mockDeps);
			const ctx: GrantContext = {
				body: { refresh_token: token, client_id: "wrong-client" },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 200 with new access and refresh tokens on valid refresh token", async () => {
			const token = await makeRefreshToken();
			const handler = createRefreshTokenGrant(mockDeps);
			const ctx: GrantContext = {
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
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
				.setExpirationTime("24h")
				.sign(secretKey);
			const handler = createRefreshTokenGrant(mockDeps);
			const ctx: GrantContext = {
				body: { refresh_token: legacyToken },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
		});

		it("accepts legacy tokens without kid header", async () => {
			const legacyToken = await new SignJWT({ sub: "u1" })
				.setProtectedHeader({ alg: "HS256", typ: "rt+jwt" })
				.setExpirationTime("24h")
				.sign(secretKey);
			const handler = createRefreshTokenGrant(mockDeps);
			const ctx: GrantContext = {
				body: { refresh_token: legacyToken },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
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
			};

			const { sessionMutation } = await handler.handle(ctx);

			expect(sessionMutation).toBeUndefined();
		});
	});

	describe("family_id and refreshTokenStore integration", () => {
		function createStubRefreshTokenStore(
			onRotate: (previousJti: string | null) => RefreshTokenRotateOutcome,
		): RefreshTokenStoreBase {
			return {
				kind: "stub",
				async rotate(previousJti) {
					return onRotate(previousJti);
				},
				async isFamilyRevoked() {
					return false;
				},
				async revokeFamily() {},
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

		it("returns invalid_grant/replay_detected when the store reports 'replayed'", async () => {
			const stub = createStubRefreshTokenStore((_prev) => ({
				outcome: "replayed",
				familyId: "test-family",
			}));
			const depsWithStore: GrantDependencies = { ...mockDeps, refreshTokenStore: stub };
			// Token must include a jti so that previousJti !== null and rotate() is called
			const token = await new SignJWT({ sub: "u1", scope: "read write" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setExpirationTime("24h")
				.setJti("prev-jti-replay")
				.sign(secretKey);
			const handler = createRefreshTokenGrant(depsWithStore);
			const ctx: GrantContext = {
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
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

		it("returns invalid_grant/family_revoked when the store reports 'revoked'", async () => {
			const stub = createStubRefreshTokenStore((_prev) => ({ outcome: "revoked" }));
			const depsWithStore: GrantDependencies = { ...mockDeps, refreshTokenStore: stub };
			// Token must include a jti so that previousJti !== null and rotate() is called
			const token = await new SignJWT({ sub: "u1", scope: "read write" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setExpirationTime("24h")
				.setJti("prev-jti-revoked")
				.sign(secretKey);
			const handler = createRefreshTokenGrant(depsWithStore);
			const ctx: GrantContext = {
				body: { refresh_token: token },
				session: {},
				issuer: "localhost",
				metadata: {},
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
	});
});
