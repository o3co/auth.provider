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
import { describe, expect, it } from "vitest";

import { createSessionGrant } from "../session.mjs";
import type { GrantContext, GrantDependencies } from "../types.mjs";

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

const mockDeps: GrantDependencies = {
	config: mockConfig,
	clientRepository: {} as GrantDependencies["clientRepository"],
	codeRepository: {} as GrantDependencies["codeRepository"],
};

describe("createSessionGrant", () => {
	describe("handle", () => {
		it("returns 401 when session is not authenticated", async () => {
			const handler = createSessionGrant(mockDeps);
			const ctx: GrantContext = {
				body: {},
				session: { isAuthenticated: false },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(401);
			expect("error" in result).toBe(true);
			if ("error" in result) {
				expect(result.error).toBe("unauthorized");
			}
		});

		it("returns 401 when session has no isAuthenticated field", async () => {
			const handler = createSessionGrant(mockDeps);
			const ctx: GrantContext = {
				body: {},
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(401);
		});

		it("returns 200 with access token when session is authenticated", async () => {
			const handler = createSessionGrant(mockDeps);
			const ctx: GrantContext = {
				body: {},
				session: {
					isAuthenticated: true,
					user: { id: "user1", name: "Alice" },
					client: { id: "client1" },
				},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				expect(result.tokens.access_token).toBeDefined();
				expect(result.tokens.token_type).toBe("Bearer");
				expect(result.tokens.refresh_token).toBeUndefined();
			}
		});

		it("includes metadata in token payload instead of req.ip", async () => {
			const handler = createSessionGrant(mockDeps);
			const ctx: GrantContext = {
				body: {},
				session: {
					isAuthenticated: true,
					user: { id: "user1" },
				},
				issuer: "localhost",
				metadata: { ip: "192.168.1.1", customField: "value" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
		});

		it("does not return sessionMutation", async () => {
			const handler = createSessionGrant(mockDeps);
			const ctx: GrantContext = {
				body: {},
				session: { isAuthenticated: true },
				issuer: "localhost",
				metadata: {},
			};

			const { sessionMutation } = await handler.handle(ctx);

			expect(sessionMutation).toBeUndefined();
		});
	});
});
