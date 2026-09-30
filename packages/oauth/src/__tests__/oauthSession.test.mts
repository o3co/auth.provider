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
import { capturing, withGrants } from "./_helpers/sections.mjs";

/** `config` with the captures of the renames the module declares, as a resolution under an empty environment makes them. */
const captured = <C extends object>(config: C): C =>
	capturing(config, [oauthSessionModule({ config: config as never })]);

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
		const config = withGrants(makeValidAppConfig(), { session: true });
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
			bootstrapComponents: { config: captured(config), pathResolver: (s) => s },
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
		// Admission writes the outage's one line through the grant's
		// `deps.logger`, and the boot planner hands a module only the slots its
		// manifest names: a manifest without `logger` answered the 503 and logged
		// nothing.
		const config = withGrants(makeValidAppConfig(), { session: true });
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
			bootstrapComponents: { config: captured(config), pathResolver: (s) => s, logger },
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
					action: "oauth.session_grant",
					err: expect.objectContaining({ name: "Error" }),
				}),
				"session_admission_unavailable",
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

	it("registers the session grant when oauth-session.enabled is explicitly true", async () => {
		const config = withGrants(makeValidAppConfig(), { session: true });
		const handle = await createTestApp({
			modules: [oauthSessionModule({ config }), keyStoreModule],
			bootstrapComponents: { config: captured(config), pathResolver: (s) => s },
		});
		expect(handle.inspect.grants.has("session")).toBe(true);
		await handle.dispose();
	});

	it("contributes no grant when oauth-session.enabled === false", async () => {
		const config = withGrants(makeValidAppConfig(), { session: false });
		const handle = await createTestApp({
			modules: [oauthSessionModule({ config }), keyStoreModule],
			bootstrapComponents: { config: captured(config), pathResolver: (s) => s },
		});
		expect(handle.inspect.grants.has("session")).toBe(false);
		await handle.dispose();
	});

	it("contributes no grant when oauth-session.enabled is the string 'false' (HOCON env-substitution outcome)", async () => {
		// HOCON env-var substitution resolves env values as strings, which the
		// switch reads as the section's schema does: `"false"` is off.
		const config = withGrants(makeValidAppConfig(), { session: "false" });
		const handle = await createTestApp({
			modules: [oauthSessionModule({ config }), keyStoreModule],
			bootstrapComponents: { config: captured(config), pathResolver: (s) => s },
		});
		expect(handle.inspect.grants.has("session")).toBe(false);
		await handle.dispose();
	});

	it("registers the session grant when oauth-session.enabled is the string 'true' (env-enable)", async () => {
		// An operator setting `OAUTH_SESSION_ENABLED=true` produces a resolved
		// `enabled: "true"` (string), which reads as on so the documented
		// env-enable pattern works at runtime.
		const config = withGrants(makeValidAppConfig(), { session: "true" });
		const handle = await createTestApp({
			modules: [oauthSessionModule({ config }), keyStoreModule],
			bootstrapComponents: { config: captured(config), pathResolver: (s) => s },
		});
		expect(handle.inspect.grants.has("session")).toBe(true);
		await handle.dispose();
	});

	it("registered handler returns 401 unauthorized for an unauthenticated session", async () => {
		const config = makeValidAppConfig();
		const handle = await createTestApp({
			modules: [oauthSessionModule({ config }), keyStoreModule],
			bootstrapComponents: { config: captured(config), pathResolver: (s) => s },
		});
		const handler = handle.inspect.grants.get("session") as GrantHandler | undefined;
		if (!handler) throw new Error("expected session grant to be registered");
		// A real client, because the grant answers `401 invalid_client` for a
		// missing one BEFORE it looks at the session: with
		// `authenticatedClient: null` this test would pass on the client
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
