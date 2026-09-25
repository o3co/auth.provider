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

import { createSymmetricKeyStore, defineModule, type GrantHandler } from "@o3co/auth-provider-core";
import { createTestApp, makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { describe, expect, it, vi } from "vitest";
import { oauthSessionModule } from "#/oauthSession.mjs";

// ---------------------------------------------------------------------------
// Shared test-only stubs
// ---------------------------------------------------------------------------

/** Inline module that satisfies `requires: ["keyStore"]`. */
const keyStoreModule = defineModule({
	name: "test:key-store",
	provides: {
		keyStore: () => createSymmetricKeyStore("test-secret-for-session-grant"),
	},
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("oauthSessionModule", () => {
	it("wires session liveness into the registered grant", async () => {
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: { ...base.oauth, grants: { ...base.oauth.grants, session: { enabled: true } } },
		};
		const get = vi.fn(async () => null);
		const handle = await createTestApp({
			modules: [
				oauthSessionModule({ config }),
				keyStoreModule,
				defineModule({
					name: "test:session-store",
					provides: {
						userSessionStore: () => ({
							kind: "memory" as const,
							get,
							create: async () => {},
							delete: async () => {},
						}),
					},
				}),
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		try {
			const grant = handle.inspect.grants.get("session") as GrantHandler;
			const { result } = await grant.handle({
				body: {},
				session: { isAuthenticated: true, sid: "revoked", user: { id: "user" } },
				issuer: "https://issuer.test",
				metadata: {},
				authenticatedClient: { clientId: "app", tokenEndpointAuthMethod: "none" },
			});
			expect(result.status).toBe(400);
			expect(get).toHaveBeenCalledWith("revoked");
		} finally {
			await handle.dispose();
		}
	});
	it("logs a session-store outage on the composition's logger, once, at error", async () => {
		// The grant writes the outage's one line through `deps.logger`, and the
		// boot planner hands a module only the slots its manifest names: a
		// manifest without `logger` answered the 503 and logged nothing.
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: { ...base.oauth, grants: { ...base.oauth.grants, session: { enabled: true } } },
		};
		const logger = {
			trace: vi.fn(),
			debug: vi.fn(),
			info: vi.fn(),
			warn: vi.fn(),
			error: vi.fn(),
			fatal: vi.fn(),
			child: vi.fn(),
		};
		const handle = await createTestApp({
			modules: [
				oauthSessionModule({ config }),
				keyStoreModule,
				defineModule({
					name: "test:session-store",
					provides: {
						userSessionStore: () => ({
							kind: "memory" as const,
							get: async () => {
								throw new Error("connect ECONNREFUSED 127.0.0.1:6379");
							},
							create: async () => {},
							delete: async () => {},
						}),
					},
				}),
			],
			bootstrapComponents: { config, pathResolver: (s) => s, logger },
		});
		try {
			const grant = handle.inspect.grants.get("session") as GrantHandler;
			const { result } = await grant.handle({
				body: {},
				session: { isAuthenticated: true, sid: "sid-1", user: { id: "user" } },
				issuer: "https://issuer.test",
				metadata: {},
				authenticatedClient: { clientId: "app", tokenEndpointAuthMethod: "none" },
			});
			expect(result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
			expect(logger.error).toHaveBeenCalledTimes(1);
			expect(logger.error).toHaveBeenCalledWith(
				expect.objectContaining({
					store: "user_session",
					step: "get",
					err: expect.objectContaining({ name: "Error" }),
				}),
				"session_grant_store_unavailable",
			);
			expect(logger.error.mock.calls[0]?.[0].err).not.toBeInstanceOf(Error);
			expect(logger.warn).not.toHaveBeenCalled();
		} finally {
			await handle.dispose();
		}
	});

	it("has name 'oauth-session'", () => {
		const config = makeValidAppConfig();
		const module = oauthSessionModule({ config });
		expect(module.name).toBe("oauth-session");
	});

	it("registers the session grant when config.oauth.grants.session.enabled is explicitly true", async () => {
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: { ...base.oauth, grants: { ...base.oauth.grants, session: { enabled: true } } },
		};
		const handle = await createTestApp({
			modules: [oauthSessionModule({ config }), keyStoreModule],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		expect(handle.inspect.grants.has("session")).toBe(true);
		await handle.dispose();
	});

	it("contributes no grant when config.oauth.grants.session.enabled === false", async () => {
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: { ...base.oauth, grants: { ...base.oauth.grants, session: { enabled: false } } },
		};
		const handle = await createTestApp({
			modules: [oauthSessionModule({ config }), keyStoreModule],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		expect(handle.inspect.grants.has("session")).toBe(false);
		await handle.dispose();
	});

	it("contributes no grant when config.oauth.grants.session is the string 'false' (HOCON env-substitution outcome)", async () => {
		// Mirrors the corresponding oauthAuthorization test: HOCON env-var
		// substitution resolves env values as strings (no schema coercion on
		// the `grants` passthrough sub-tree). Under the strict opt-in check,
		// a resolved `enabled: "false"` correctly evaluates to not-enabled,
		// restoring the env-disable invariant.
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				grants: {
					...base.oauth.grants,
					session: { enabled: "false" as unknown as boolean },
				},
			},
		};
		const handle = await createTestApp({
			modules: [oauthSessionModule({ config }), keyStoreModule],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		expect(handle.inspect.grants.has("session")).toBe(false);
		await handle.dispose();
	});

	it("registers the session grant when config.oauth.grants.session.enabled is the string 'true' (env-enable)", async () => {
		// An operator setting `OAUTH_GRANTS_SESSION_ENABLED=true` produces a
		// resolved `enabled: "true"` (string) on the passthrough `grants`
		// sub-tree. The opt-in check accepts both boolean `true` and string
		// `"true"` so the documented env-enable pattern works at runtime,
		// matching the CHANGELOG's operator-facing guidance.
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				grants: {
					...base.oauth.grants,
					session: { enabled: "true" as unknown as boolean },
				},
			},
		};
		const handle = await createTestApp({
			modules: [oauthSessionModule({ config }), keyStoreModule],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		expect(handle.inspect.grants.has("session")).toBe(true);
		await handle.dispose();
	});

	it("registered handler returns 401 unauthorized for an unauthenticated session", async () => {
		const config = makeValidAppConfig();
		const handle = await createTestApp({
			modules: [oauthSessionModule({ config }), keyStoreModule],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		// TestInspect.grants is ReadonlyMap<string, unknown> because contributes-map.mts
		// uses a structural placeholder for GrantHandler until Phase 9 substitutes the
		// concrete type. Cast to the concrete GrantHandler from grants/types.mts here.
		const handler = handle.inspect.grants.get("session") as GrantHandler | undefined;
		if (!handler) throw new Error("expected session grant to be registered");
		// A real client, because the grant answers `401 invalid_client` for a
		// missing one BEFORE it looks at the session (#626): with
		// `authenticatedClient: null` this test used to pass on the client
		// branch under the session's name. `session.test.mts` covers
		// `invalid_client`; this asserts the branch it is named after.
		const { result } = await handler.handle({
			body: {},
			session: { isAuthenticated: false },
			issuer: "localhost",
			metadata: {},
			authenticatedClient: {
				clientId: "my-app",
				tokenEndpointAuthMethod: "client_secret_basic",
				allowedScopes: ["read"],
			},
		});
		expect(result.status).toBe(401);
		expect(result).toMatchObject({ error: "unauthorized" });
		await handle.dispose();
	});
});
