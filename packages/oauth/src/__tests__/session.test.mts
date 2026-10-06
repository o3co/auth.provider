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
	createInMemorySessionLifecycleStore,
	createInMemoryUserSessionStore,
	createSymmetricKeyStore,
	type GrantContext,
} from "@o3co/auth-provider-core";
import { createTestOAuthTokenSettings, resolverForTests } from "@o3co/auth-provider-core/testing";
import { decodeJwt } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createSessionGrant } from "#/grants/session.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";

afterEach(() => {
	vi.useRealTimers();
});

type SessionGrantDeps = Parameters<typeof createSessionGrant>[0];

const makeDeps = (overrides?: Partial<SessionGrantDeps>): SessionGrantDeps => ({
	sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
	oauthTokenSettings: createTestOAuthTokenSettings(),
	keyStore: createSymmetricKeyStore("test-secret"),
	...overrides,
});

const mockDeps = makeDeps();

// Every /token request reaches a grant through `clientAuthMw`, so
// `ctx.authenticatedClient` is always populated in production. Tests that are
// not about client authentication itself supply this default so they exercise
// the same shape the route does.
const AUTH_CLIENT = {
	clientId: "my-app",
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	allowedScopes: ["read", "write"],
};

describe("createSessionGrant — the token settings it mints with, read when it is built", () => {
	it("is refused when it is built without the oauthTokenSettings slot, naming it", () => {
		// Read per request, a missing slot would fail every token request with
		// a 500, after client authentication had spent whatever it spends.
		const { oauthTokenSettings: _settings, ...withoutSlot } = makeDeps();
		expect(() => createSessionGrant(withoutSlot as SessionGrantDeps)).toThrow(/oauthTokenSettings/);
	});

	it("is refused when it is built with an access-token lifetime the slot's contract refuses", () => {
		for (const accessTokenLifetime of [
			{ defaultExpiresIn: 1.5, maxExpiresIn: 3600 },
			{ defaultExpiresIn: 0, maxExpiresIn: 3600 },
			{ defaultExpiresIn: 600, maxExpiresIn: 60 },
			{},
		]) {
			const oauthTokenSettings = {
				...createTestOAuthTokenSettings(),
				accessTokenLifetime,
			} as unknown as SessionGrantDeps["oauthTokenSettings"];
			expect(
				() => createSessionGrant(makeDeps({ oauthTokenSettings })),
				JSON.stringify(accessTokenLifetime),
			).toThrow(/oauthTokenSettings\.accessTokenLifetime/);
		}
	});

	it("reads nothing of a whole configuration it is handed", async () => {
		// `expires_in` is the time left when answered: read on a frozen clock.
		vi.useFakeTimers({ toFake: ["Date"], now: Date.now() });
		// Settings at a configuration's paths that the slot contradicts: only
		// the slot's are read.
		const config = {
			oauth: {
				accessToken: { defaultExpiresIn: 60, maxExpiresIn: 60 },
				requireEmailVerified: true,
			},
		};
		const handler = createSessionGrant({ ...makeDeps(), config } as SessionGrantDeps);
		const { result } = await handler.handle({
			body: {},
			session: { isAuthenticated: true, user: { id: "user1" } },
			issuer: "localhost",
			metadata: {},
			authenticatedClient: AUTH_CLIENT,
		});

		if (!("tokens" in result)) throw new Error(`expected tokens, got ${result.status}`);
		expect(result.tokens.expires_in).toBe(3600);
	});
});

describe("createSessionGrant — where a user-session store is wired, core's session lifecycle is required", () => {
	it("refuses to build with userSessionStore wired and no sessionLifecycleStore, naming both slots", () => {
		expect(() =>
			createSessionGrant(makeDeps({ userSessionStore: createInMemoryUserSessionStore() })),
		).toThrow(
			/^oauth-session: userSessionStore is wired, but sessionLifecycleStore is not\.[\s\S]*Install sessionLifecycleModule/,
		);
	});

	it("builds sessionless, with neither wired, and with both wired", () => {
		expect(() => createSessionGrant(makeDeps())).not.toThrow();
		expect(() =>
			createSessionGrant(
				makeDeps({
					userSessionStore: createInMemoryUserSessionStore(),
					sessionLifecycleStore: createInMemorySessionLifecycleStore(),
				}),
			),
		).not.toThrow();
	});
});

describe("createSessionGrant", () => {
	describe("handle", () => {
		it("returns 401 when session is not authenticated", async () => {
			const handler = createSessionGrant(mockDeps);
			const ctx: GrantContext = {
				body: {},
				session: { isAuthenticated: false },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: AUTH_CLIENT,
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
				authenticatedClient: AUTH_CLIENT,
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
				authenticatedClient: AUTH_CLIENT,
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
				authenticatedClient: AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
		});

		it("mints the configured default lifetime and ignores an expires_in request parameter", async () => {
			// `expires_in` is the time left when answered: read on a frozen clock.
			vi.useFakeTimers({ toFake: ["Date"], now: Date.now() });
			const handler = createSessionGrant(
				makeDeps({
					oauthTokenSettings: createTestOAuthTokenSettings({
						accessTokenLifetime: { defaultExpiresIn: 600, maxExpiresIn: 7200 },
					}),
				}),
			);
			const { result } = await handler.handle({
				body: { expires_in: "7200" },
				session: { isAuthenticated: true, user: { id: "user1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: AUTH_CLIENT,
			});

			if (!("tokens" in result)) throw new Error(`expected tokens, got ${result.status}`);
			expect(result.tokens.expires_in).toBe(600);
			const decoded = decodeJwt(result.tokens.access_token);
			expect((decoded.exp as number) - (decoded.iat as number)).toBe(600);
		});

		it("binds audience and azp to the authenticated client", async () => {
			const handler = createSessionGrant(makeDeps());
			const ctx: GrantContext = {
				body: {},
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				const decoded = decodeJwt(result.tokens.access_token);
				expect(decoded.aud).toBe("my-app");
				expect(decoded.sub).toBe("u1");
				expect((decoded as Record<string, unknown>).azp).toBe("my-app");
			}
		});

		it("validates scope against the authenticated client's allowedScopes", async () => {
			const handler = createSessionGrant(makeDeps());
			const ctx: GrantContext = {
				body: { scope: "read" },
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				expect(result.tokens.scope).toBe("read");
			}
		});

		it("rejects scope exceeding client allowedScopes", async () => {
			const handler = createSessionGrant(makeDeps());
			const ctx: GrantContext = {
				body: { scope: "read admin" },
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			expect("error" in result).toBe(true);
			if ("error" in result) {
				expect(result.error).toBe("invalid_scope");
			}
		});

		it("ignores a body client_id naming a different client", async () => {
			// clientAuthMw rejects a body client_id that contradicts Basic
			// credentials, so this shape cannot reach the grant through /token.
			// The assertion pins that identity is read from the authenticated
			// slot regardless, rather than relying on that upstream check alone.
			const handler = createSessionGrant(makeDeps());
			const ctx: GrantContext = {
				body: { client_id: "other-app", scope: "read" },
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				const decoded = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
				expect(decoded.aud).toBe("my-app");
				expect(decoded.azp).toBe("my-app");
			}
		});

		it("refuses a scope that is not RFC 6749 §3.3's space-delimited list as malformed", async () => {
			const handler = createSessionGrant(makeDeps());
			for (const scope of ["read\twrite", 'read "write"', "\t"]) {
				const { result } = await handler.handle({
					body: { scope },
					session: { isAuthenticated: true, user: { id: "u1" } },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: AUTH_CLIENT,
				});
				expect(result.status, JSON.stringify(scope)).toBe(400);
				expect("error" in result && result.error).toBe("invalid_scope");
				expect("errorDescription" in result && result.errorDescription).toBe(
					"scope is not a space-delimited list of scope-tokens",
				);
			}
		});

		it("reads scope: null as an omitted scope, and refuses any other value that is not a string", async () => {
			// RFC 6749 §3.2: a parameter sent without a value is treated as
			// omitted. A JSON body's `null` is that, as `scope=""` is for a form
			// body — the same reading token exchange gives `expires_in: null`. Any
			// other value that is not a string is `invalid_request`.
			const handler = createSessionGrant(makeDeps());
			const ctx = (body: Record<string, unknown>): GrantContext => ({
				body,
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: AUTH_CLIENT,
			});
			const nulled = (await handler.handle(ctx({ scope: null }))).result;
			expect(nulled.status).toBe(200);
			if ("tokens" in nulled) expect(nulled.tokens.scope).toBeUndefined();

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
			const handler = createSessionGrant(makeDeps());
			const { result } = await handler.handle({
				body: { scope: ["read", "write"] },
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: AUTH_CLIENT,
			});
			expect(result).toEqual({
				status: 400,
				error: "invalid_request",
				errorDescription: "scope must be a space-delimited string",
			});
		});

		it("grants the requested scope when it is within the allowlist", async () => {
			const handler = createSessionGrant(makeDeps());
			const ctx: GrantContext = {
				body: { scope: "read write" },
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				expect(result.tokens.scope).toBe("read write");
			}
		});

		it("deduplicates scope values", async () => {
			const handler = createSessionGrant(makeDeps());
			const ctx: GrantContext = {
				body: { scope: "read read write" },
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				expect(result.tokens.scope).toBe("read write");
			}
		});

		it("treats empty scope string as no scope", async () => {
			const handler = createSessionGrant(makeDeps());
			const ctx: GrantContext = {
				body: { scope: "" },
				session: { isAuthenticated: true, user: { id: "u1" } },
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
				authenticatedClient: AUTH_CLIENT,
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				expect(result.tokens.scope).toBeUndefined();
			}
		});

		// -------------------------------------------------------------------
		// The grant must authorize against the *authenticated* client:
		// `clientAuthMw` runs before every grant on /token and populates
		// `ctx.authenticatedClient`. A client authenticating with HTTP Basic
		// (the canonical transport for a confidential client) has its
		// `client_id` in the Authorization header, never in the body, so a
		// grant reading `body.client_id` would skip its allowlist entirely.
		// -------------------------------------------------------------------
		describe("authorization binds to ctx.authenticatedClient", () => {
			const basicAuthClient = {
				clientId: "first-party-app",
				tokenEndpointAuthMethod: "client_secret_basic" as const,
				allowedScopes: ["read"],
			};

			it("enforces allowedScopes for a Basic-authenticated client that sends no body client_id", async () => {
				const handler = createSessionGrant(makeDeps());
				const { result } = await handler.handle({
					// Basic credentials are consumed by clientAuthMw; the body carries
					// only the grant parameters.
					body: { scope: "admin:*" },
					session: { isAuthenticated: true, user: { id: "u1" } },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: basicAuthClient,
				});

				expect(result.status).toBe(400);
				if (!("error" in result)) throw new Error("expected error");
				expect(result.error).toBe("invalid_scope");
			});

			it("binds aud and azp to the authenticated client rather than the body", async () => {
				const handler = createSessionGrant(makeDeps());
				const { result } = await handler.handle({
					body: { scope: "read" },
					session: { isAuthenticated: true, user: { id: "u1" } },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: basicAuthClient,
				});

				expect(result.status).toBe(200);
				if (!("tokens" in result)) throw new Error("expected tokens");
				const decoded = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
				expect(decoded.aud).toBe("first-party-app");
				expect(decoded.azp).toBe("first-party-app");
			});

			it("uses the client's configured audience when one is registered", async () => {
				// Forcing `aud` to the client id would mint tokens the operator's own
				// API rejects, since its audience check never names the client.
				const handler = createSessionGrant(makeDeps());
				const { result } = await handler.handle({
					body: { scope: "read" },
					session: { isAuthenticated: true, user: { id: "u1" } },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: {
						...basicAuthClient,
						allowedAudiences: ["https://api.example.com"],
					},
				});

				expect(result.status).toBe(200);
				if (!("tokens" in result)) throw new Error("expected tokens");
				const decoded = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
				expect(decoded.aud).toBe("https://api.example.com");
				// azp still names who asked, not what the token is for.
				expect(decoded.azp).toBe("first-party-app");
			});

			it("returns 401 when the request was not client-authenticated", async () => {
				const handler = createSessionGrant(makeDeps());
				const { result } = await handler.handle({
					body: { scope: "admin:*" },
					session: { isAuthenticated: true, user: { id: "u1" } },
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
					authenticatedClient: null,
				});

				expect(result.status).toBe(401);
				if (!("error" in result)) throw new Error("expected error");
				expect(result.error).toBe("invalid_client");
			});

			// The factory takes no client repository, so the type system
			// enforces that none is consulted.
		});

		it("does not return sessionMutation", async () => {
			const handler = createSessionGrant(mockDeps);
			const ctx: GrantContext = {
				body: {},
				session: { isAuthenticated: true },
				issuer: "localhost",
				metadata: {},
				authenticatedClient: AUTH_CLIENT,
			};

			const { sessionMutation } = await handler.handle(ctx);

			expect(sessionMutation).toBeUndefined();
		});
	});
});

// ---------------------------------------------------------------------------
// The email-verified gate on the session grant
// ---------------------------------------------------------------------------

describe("createSessionGrant — email-verified gate", () => {
	const gated = createTestOAuthTokenSettings({ requireEmailVerified: true });

	const runWith = async (
		oauthTokenSettings: SessionGrantDeps["oauthTokenSettings"],
		user: Record<string, unknown> | undefined,
	) => {
		const handler = createSessionGrant(makeDeps({ oauthTokenSettings }));
		const { result } = await handler.handle({
			body: {},
			session: { isAuthenticated: true, ...(user ? { user } : {}) },
			issuer: "localhost",
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: AUTH_CLIENT,
		} as GrantContext);
		return result;
	};

	it("refuses when the gate is on and the Store published no verification", async () => {
		// This grant mints straight from the browser session, so gating only
		// /authorize would leave a deployment believing it had a gate.
		const result = await runWith(gated, { id: "u1" });
		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
	});

	it("refuses on an explicit false", async () => {
		const result = await runWith(gated, { id: "u1", emailVerified: false });
		expect("error" in result && result.error).toBe("invalid_grant");
	});

	it("admits when the Store published true", async () => {
		const result = await runWith(gated, { id: "u1", emailVerified: true });
		expect(result.status).toBe(200);
	});

	it("is inert when the gate is off", async () => {
		const result = await runWith(createTestOAuthTokenSettings(), { id: "u1" });
		expect(result.status).toBe(200);
	});
});

/**
 * The `session` grant's access token must be covered by logout: it carries
 * the browser session's `sid`, which every downstream liveness check
 * (`/userinfo`, `/introspect`) keys on. Without it the token would stay valid
 * after logout for the whole access-token lifetime, in exactly the BFF /
 * proxy topology this grant exists to serve.
 */
describe("createSessionGrant — sid binds the token to the browser session", () => {
	const runWith = async (session: Record<string, unknown>) => {
		const handler = createSessionGrant(makeDeps());
		const { result } = await handler.handle({
			body: {},
			session,
			issuer: "https://auth.example",
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: AUTH_CLIENT,
		} as unknown as GrantContext);
		return result;
	};

	it("stamps the session's sid onto the access token", async () => {
		const result = await runWith({
			isAuthenticated: true,
			user: { id: "u1" },
			sid: "sid-abc",
		});

		expect(result.status).toBe(200);
		expect("tokens" in result).toBe(true);
		if ("tokens" in result) {
			const claims = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
			expect(claims.sid).toBe("sid-abc");
		}
	});

	it("issues no family_id — this grant mints no refresh token", async () => {
		// A `family_id` would name a refresh-token family that does not exist,
		// so the cascade would consult a family nothing ever revokes. `sid` is
		// the whole binding here.
		const result = await runWith({
			isAuthenticated: true,
			user: { id: "u1" },
			sid: "sid-abc",
		});

		expect("tokens" in result).toBe(true);
		if ("tokens" in result) {
			const claims = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
			expect(claims.family_id).toBeUndefined();
			expect(result.tokens.refresh_token).toBeUndefined();
		}
	});

	it("omits sid when the session recorded none", async () => {
		// A deployment whose login wiring records no `sid` still mints; the claim
		// is absent rather than present-and-empty, which is what keeps the
		// liveness checks' "no sid to check" branch distinguishable.
		const result = await runWith({ isAuthenticated: true, user: { id: "u1" } });

		expect(result.status).toBe(200);
		expect("tokens" in result).toBe(true);
		if ("tokens" in result) {
			const claims = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
			expect("sid" in claims).toBe(false);
		}
	});
});

describe("createSessionGrant — a session store that cannot answer is logged, not only answered 503", () => {
	it("logs no client id at all", async () => {
		const error = vi.fn();
		const longId = "c".repeat(256);
		const handler = createSessionGrant({
			...makeDeps(),
			sessionLifecycleStore: createInMemorySessionLifecycleStore(),
			userSessionStore: {
				kind: "broken",
				create: async () => {},
				get: async () => {
					throw new Error("down");
				},
				delete: async () => {},
			},
			logger: {
				trace: vi.fn(),
				debug: vi.fn(),
				info: vi.fn(),
				warn: vi.fn(),
				error,
				fatal: vi.fn(),
				child: vi.fn(),
			},
		} as Parameters<typeof createSessionGrant>[0]);
		await handler.handle({
			body: {},
			session: { isAuthenticated: true, sid: "sid-1", user: { id: "u1" } },
			issuer: "https://auth.example",
			metadata: {},
			authenticatedClient: { ...AUTH_CLIENT, clientId: longId },
		} as unknown as GrantContext);
		expect(error).toHaveBeenCalledTimes(1);
		expect(error.mock.calls[0]?.[0]).not.toHaveProperty("clientId");
		expect(JSON.stringify(error.mock.calls)).not.toContain(longId);
	});

	it("logs it once, at error level, as admission's session_admission_unavailable — the grant's own line is gone", async () => {
		const warn = vi.fn();
		const error = vi.fn();
		const outage = Object.assign(
			new Error("READONLY You can't write against a read only replica."),
			{
				name: "ReplyError",
				command: { name: "get", args: ["ss:us:sid-1", "refused-command-marker"] },
			},
		);
		const handler = createSessionGrant({
			...makeDeps(),
			sessionLifecycleStore: createInMemorySessionLifecycleStore(),
			userSessionStore: {
				kind: "broken",
				create: async () => {},
				get: async () => {
					throw outage;
				},
				delete: async () => {},
			},
			logger: {
				trace: vi.fn(),
				debug: vi.fn(),
				info: vi.fn(),
				warn,
				error,
				fatal: vi.fn(),
				child: vi.fn(),
			},
		} as Parameters<typeof createSessionGrant>[0]);
		const { result } = await handler.handle({
			body: {},
			session: { isAuthenticated: true, sid: "sid-1", user: { id: "u1" } },
			issuer: "https://auth.example",
			metadata: {},
			authenticatedClient: AUTH_CLIENT,
		} as unknown as GrantContext);
		expect(result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
		expect(warn).not.toHaveBeenCalled();
		expect(error).toHaveBeenCalledTimes(1);
		expect(error).toHaveBeenCalledWith(
			{
				store: "user_session",
				action: "oauth.session_grant",
				err: expect.objectContaining({ name: "ReplyError" }),
			},
			"session_admission_unavailable",
		);
		expect(error.mock.calls[0]?.[0].err).not.toBeInstanceOf(Error);
		expect(JSON.stringify(error.mock.calls)).not.toContain("refused-command-marker");
	});
});
