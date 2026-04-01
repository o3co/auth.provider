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
import jwt from "jsonwebtoken";
import { describe, expect, it } from "vitest";

import { createRefreshTokenGrant } from "../refreshToken.mjs";
import type { GrantContext, GrantDependencies } from "../types.mjs";

const SECRET = "test-secret";

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
	clientRepository: {} as GrantDependencies["clientRepository"],
	codeRepository: {} as GrantDependencies["codeRepository"],
};

function makeRefreshToken(overrides: object = {}): string {
	return jwt.sign({ type: "refresh", user: { id: "u1" }, ...overrides }, SECRET, {
		expiresIn: 86400,
	});
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

		it("returns 400 when JWT type is not refresh", async () => {
			const accessToken = jwt.sign({ type: "access", user: { id: "u1" } }, SECRET);
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
			const token = jwt.sign({ type: "refresh", user: { id: "u1" } }, SECRET, {
				audience: "client1",
			});
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
			const token = makeRefreshToken();
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
			const token = jwt.sign({ type: "refresh", user: { id: "u1" } }, SECRET, {
				audience: "client1",
				expiresIn: 86400,
			});
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
			const token = makeRefreshToken({ scopes: ["read", "write"] });
			const handler = createRefreshTokenGrant(mockDeps);
			const ctx: GrantContext = {
				body: { refresh_token: token, scope: "read" },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			if ("tokens" in result) {
				expect(result.tokens.scope).toBe("read");
			}
		});

		it("rejects scope that exceeds original grant", async () => {
			const token = makeRefreshToken({ scopes: ["read"] });
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

		it("does not return sessionMutation", async () => {
			const token = makeRefreshToken();
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
});
