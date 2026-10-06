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

import {
	BootError,
	createSymmetricKeyStore,
	defineModule,
	type GrantHandler,
} from "@o3co/auth-provider-core";
import {
	createTestApp,
	createTestOAuthTokenSettings,
	makeValidAppConfig,
} from "@o3co/auth-provider-core/testing";
import { decodeJwt } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { oauthSessionGrantModule } from "#/oauthSession.mjs";
import { capturing, withGrants } from "./_helpers/sections.mjs";

afterEach(() => {
	vi.useRealTimers();
});

/** `config` with the captures of the renames the module declares, as a resolution under an empty environment makes them. */
const captured = <C extends object>(config: C): C => capturing(config, [oauthSessionGrantModule]);

/**
 * The `oauthTokenSettings` slot a composition without the oauth module fills
 * itself: what the grant reads of `oauth {}`.
 */
const oauthTokenSettings = createTestOAuthTokenSettings();

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

describe("oauthSessionGrantModule", () => {
	it("wires session liveness into the registered grant", async () => {
		const config = withGrants(makeValidAppConfig(), { session: true });
		const get = vi.fn(async () => null);
		const handle = await createTestApp({
			modules: [
				oauthSessionGrantModule,
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
			bootstrapComponents: { config: captured(config), pathResolver: (s) => s, oauthTokenSettings },
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
				oauthSessionGrantModule,
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
			bootstrapComponents: {
				config: captured(config),
				pathResolver: (s) => s,
				oauthTokenSettings,
				logger,
			},
		});
		// What boot logged of the configuration is not this test's: the outage alone is.
		logger.warn.mockClear();
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

	it("refuses a mint the composition's grantPolicy denies", async () => {
		// Boot hands a module only the slots its manifest names: without the
		// declaration the grant reads no policy and mints.
		const config = withGrants(makeValidAppConfig(), { session: true });
		const evaluate = vi.fn(async () => ({
			outcome: "deny" as const,
			error: "access_denied",
			errorDescription: "browser tokens are closed",
		}));
		const handle = await createTestApp({
			modules: [
				oauthSessionGrantModule,
				keyStoreModule,
				defineModule({
					name: "test:grant-policy",
					provides: { grantPolicy: () => ({ kind: "deny-all", evaluate }) },
				}),
			],
			bootstrapComponents: { config: captured(config), pathResolver: (s) => s, oauthTokenSettings },
		});
		try {
			const grant = handle.inspect.grants.get("session") as GrantHandler;
			const { result } = await grant.handle({
				body: {},
				session: { isAuthenticated: true, user: { id: "user" } },
				issuer: "https://issuer.test",
				metadata: {},
				authenticatedClient: { clientId: "app", tokenEndpointAuthMethod: "none" },
			});
			expect(result).toEqual({
				status: 400,
				error: "invalid_request",
				errorDescription: "browser tokens are closed",
				policyDenial: { error: "access_denied" },
			});
			expect(evaluate).toHaveBeenCalledTimes(1);
		} finally {
			await handle.dispose();
		}
	});

	it("declares grantPolicy among the slots it reads", () => {
		expect(oauthSessionGrantModule.optional).toContain("grantPolicy");
	});

	it("has name 'oauth-session'", () => {
		expect(oauthSessionGrantModule.name).toBe("oauth-session");
	});

	it("is one module, switched by its own section", () => {
		expect(typeof oauthSessionGrantModule.section?.isEnabled).toBe("function");
	});

	it("reads no whole configuration: it requires oauthTokenSettings, and neither requires nor reads config", () => {
		expect(oauthSessionGrantModule.requires).toContain("oauthTokenSettings");
		expect(oauthSessionGrantModule.requires).not.toContain("config");
		expect(oauthSessionGrantModule.optional).not.toContain("config");
		expect(oauthSessionGrantModule.optional).not.toContain("oauthTokenSettings");
	});

	it("mints with the lifetime the oauthTokenSettings slot holds, not one of the configuration's", async () => {
		// `expires_in` is the time left when answered: read on a frozen clock.
		vi.useFakeTimers({ toFake: ["Date"], now: Date.now() });
		// The configuration's access-token lifetime is 3600 s; the slot's is
		// shorter, which boot accepts. The grant reads the slot alone.
		const config = withGrants(makeValidAppConfig(), { session: true });
		const handle = await createTestApp({
			modules: [oauthSessionGrantModule, keyStoreModule],
			bootstrapComponents: {
				config: captured(config),
				pathResolver: (s) => s,
				oauthTokenSettings: createTestOAuthTokenSettings({
					accessTokenLifetime: { defaultExpiresIn: 600, maxExpiresIn: 600 },
				}),
			},
		});
		try {
			const grant = handle.inspect.grants.get("session") as GrantHandler;
			const { result } = await grant.handle({
				body: {},
				session: { isAuthenticated: true, user: { id: "user" } },
				issuer: "https://auth.test",
				metadata: {},
				authenticatedClient: { clientId: "app", tokenEndpointAuthMethod: "none" },
			});
			if (!("tokens" in result)) throw new Error(`expected tokens, got ${result.status}`);
			expect(result.tokens.expires_in).toBe(600);
			const claims = decodeJwt(result.tokens.access_token);
			expect((claims.exp as number) - (claims.iat as number)).toBe(600);
		} finally {
			await handle.dispose();
		}
	});

	it("refuses boot with the grant on and no oauthTokenSettings, naming the slot", async () => {
		const config = withGrants(makeValidAppConfig(), { session: true });
		const err = await createTestApp({
			modules: [oauthSessionGrantModule, keyStoreModule],
			bootstrapComponents: { config: captured(config), pathResolver: (s) => s },
		}).then(
			async (handle) => {
				await handle.dispose();
				return undefined;
			},
			(caught: unknown) => caught,
		);
		expect(err).toBeInstanceOf(BootError);
		expect(String((err as BootError).message)).toContain("oauthTokenSettings");
	});

	it("requires nothing with the grant off: it boots without oauthTokenSettings or a key store", async () => {
		const config = withGrants(makeValidAppConfig(), { session: false });
		const handle = await createTestApp({
			modules: [oauthSessionGrantModule],
			bootstrapComponents: { config: captured(config), pathResolver: (s) => s },
		});
		expect(handle.inspect.grants.has("session")).toBe(false);
		await handle.dispose();
	});

	it("reads an absent oauth-session section as off", async () => {
		const { "oauth-session": _section, ...config } = makeValidAppConfig();
		const handle = await createTestApp({
			modules: [oauthSessionGrantModule, keyStoreModule],
			bootstrapComponents: { config: captured(config), pathResolver: (s) => s, oauthTokenSettings },
		});
		expect(handle.inspect.grants.has("session")).toBe(false);
		await handle.dispose();
	});

	it("registers the session grant when oauth-session.enabled is explicitly true", async () => {
		const config = withGrants(makeValidAppConfig(), { session: true });
		const handle = await createTestApp({
			modules: [oauthSessionGrantModule, keyStoreModule],
			bootstrapComponents: { config: captured(config), pathResolver: (s) => s, oauthTokenSettings },
		});
		expect(handle.inspect.grants.has("session")).toBe(true);
		await handle.dispose();
	});

	it("contributes no grant when oauth-session.enabled === false", async () => {
		const config = withGrants(makeValidAppConfig(), { session: false });
		const handle = await createTestApp({
			modules: [oauthSessionGrantModule, keyStoreModule],
			bootstrapComponents: { config: captured(config), pathResolver: (s) => s, oauthTokenSettings },
		});
		expect(handle.inspect.grants.has("session")).toBe(false);
		await handle.dispose();
	});

	it("contributes no grant when oauth-session.enabled is the string 'false' (HOCON env-substitution outcome)", async () => {
		// HOCON env-var substitution resolves env values as strings, which the
		// switch reads as the section's schema does: `"false"` is off.
		const config = withGrants(makeValidAppConfig(), { session: "false" });
		const handle = await createTestApp({
			modules: [oauthSessionGrantModule, keyStoreModule],
			bootstrapComponents: { config: captured(config), pathResolver: (s) => s, oauthTokenSettings },
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
			modules: [oauthSessionGrantModule, keyStoreModule],
			bootstrapComponents: { config: captured(config), pathResolver: (s) => s, oauthTokenSettings },
		});
		expect(handle.inspect.grants.has("session")).toBe(true);
		await handle.dispose();
	});

	it("registered handler returns 401 unauthorized for an unauthenticated session", async () => {
		const config = makeValidAppConfig();
		const handle = await createTestApp({
			modules: [oauthSessionGrantModule, keyStoreModule],
			bootstrapComponents: { config: captured(config), pathResolver: (s) => s, oauthTokenSettings },
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
