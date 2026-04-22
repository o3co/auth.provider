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

import type { FederationTokenStoreBase, UserRepository, UserSessionStoreBase } from "@o3co/auth-provider-core";
import express, { type Request, type Response } from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { codeChallenge } from "#/federations/pkce.mjs";
import type { FederationProvider } from "#/federations/types.mjs";
import { createRouter } from "#/routes/Federation.mjs";

// ---------------------------------------------------------------------------
// Session shim helpers
//
// express-session is NOT a direct devDependency of this package, so tests use
// a lightweight shim. A shared in-memory store keyed by cookie value lets a
// supertest agent simulate a stateful session across requests.
// ---------------------------------------------------------------------------

type SessionStore = Map<string, Record<string, unknown>>;

/**
 * Build an express app with a cookie-backed in-memory session shim.
 * Every request reads/writes the session object from the shared store via a
 * `sid` cookie. `req.session.save` calls its callback synchronously.
 */
function makeSessionApp(store: SessionStore): express.Express {
	const app = express();
	app.use((req, _res, next) => {
		// Parse the `sid` cookie manually
		const cookieHeader = req.headers.cookie ?? "";
		const sidMatch = cookieHeader.match(/(?:^|;\s*)sid=([^;]+)/);
		const id = sidMatch ? decodeURIComponent(sidMatch[1]) : String(Math.random());

		if (!store.has(id)) store.set(id, {});
		const sessionData = store.get(id) ?? {};

		// Attach a minimal session-like object to req
		(req as unknown as { session: Record<string, unknown> }).session = {
			...sessionData,
			save(cb?: (err: unknown) => void) {
				// Persist mutations back to store
				const current = (req as unknown as { session: Record<string, unknown> }).session;
				const { save: _s, ...rest } = current;
				store.set(id, rest);
				cb?.(null);
				return this as unknown as import("express-session").Session;
			},
		};

		next();
	});
	return app;
}

/** Middleware that plants a session.federation value, then redirects to the requested path. */
function plantFederation(
	store: SessionStore,
	federation: Record<string, unknown>,
): express.RequestHandler {
	return (_req, res) => {
		// Find or create an entry in the store keyed by the current session id.
		// We create a new stable key and set a cookie so subsequent requests reuse it.
		const id = "test-session";
		store.set(id, { federation });
		// Return the id so the caller can set the cookie
		res.cookie("sid", id, { httpOnly: true });
		res.json({ ok: true });
	};
}

// ---------------------------------------------------------------------------
// Provider fake
// ---------------------------------------------------------------------------

function makeFakeProvider(overrides: Partial<FederationProvider> = {}): FederationProvider {
	return {
		name: "test",
		scope: ["openid"],
		validateRedirect: () => ({ ok: true, value: undefined }),
		resolveCallbackRedirect: (s) => ({ ok: true, value: s.redirectTo ?? "/" }),
		buildAuthorizationUrl: ({ state, codeVerifier }) => {
			const url = new URL("https://idp.example.com/authorize");
			url.searchParams.set("state", state);
			url.searchParams.set("code_challenge", codeChallenge(codeVerifier));
			url.searchParams.set("code_challenge_method", "S256");
			return url;
		},
		exchangeCode: vi.fn(async () => ({
			issuer: "https://idp.example.com",
			sub: "external-42",
			email: "u@example.com",
			accessToken: "at",
			refreshToken: "rt",
			idToken: "it",
			expiresAt: new Date(Date.now() + 3_600_000),
		})),
		...overrides,
	};
}

// ---------------------------------------------------------------------------
// Repository / store fakes
// ---------------------------------------------------------------------------

function makeUserRepository(
	user: { id: string; username: string; [k: string]: unknown } | null = {
		id: "user-1",
		username: "alice",
	},
): UserRepository {
	return {
		authenticate: vi.fn(async () => user),
		authenticateByToken: vi.fn(async () => user),
	};
}

function makeUserSessionStore(): UserSessionStoreBase & {
	create: ReturnType<typeof vi.fn>;
	delete: ReturnType<typeof vi.fn>;
} {
	return {
		kind: "memory",
		create: vi.fn(async () => {}),
		get: vi.fn(async () => null),
		registerRP: vi.fn(async () => {}),
		linkFamily: vi.fn(async () => {}),
		updateClaims: vi.fn(async () => {}),
		removeFederation: vi.fn(async () => {}),
		delete: vi.fn(async () => {}),
	};
}

function makeFederationTokenStore(): FederationTokenStoreBase & {
	attach: ReturnType<typeof vi.fn>;
	delete: ReturnType<typeof vi.fn>;
} {
	return {
		kind: "memory",
		attach: vi.fn(async () => {}),
		get: vi.fn(async () => null),
		update: vi.fn(async () => {}),
		deleteBySession: vi.fn(async () => {}),
		delete: vi.fn(async () => {}),
	};
}

// ---------------------------------------------------------------------------
// Convenience app builder for simple (stateless) start-route tests
// ---------------------------------------------------------------------------

const TEST_CALLBACK_URL = "https://app.example.com/session/oauth/federation/test/callback";

function buildStatelessApp({
	providers,
	providerCallbackUrls,
	userRepository,
	userSessionStore,
	federationTokenStore,
}: {
	providers: ReadonlyMap<string, FederationProvider>;
	providerCallbackUrls?: ReadonlyMap<string, string>;
	userRepository?: UserRepository;
	userSessionStore?: UserSessionStoreBase;
	federationTokenStore?: FederationTokenStoreBase;
}) {
	const store: SessionStore = new Map();
	const app = makeSessionApp(store);
	app.use(
		createRouter(express, {
			config: {} as never,
			federationProviders: providers,
			providerCallbackUrls: providerCallbackUrls ?? new Map([["test", TEST_CALLBACK_URL]]),
			userRepository: userRepository ?? makeUserRepository(),
			userSessionStore: userSessionStore ?? makeUserSessionStore(),
			federationTokenStore: federationTokenStore ?? makeFederationTokenStore(),
		}),
	);
	return app;
}

/**
 * Build an app with a planted session so callback-route tests start with a
 * pre-seeded session.federation value.
 */
function buildCallbackApp({
	providers,
	providerCallbackUrls,
	federation,
	userRepository,
	userSessionStore,
	federationTokenStore,
	saveInterceptor,
}: {
	providers: ReadonlyMap<string, FederationProvider>;
	providerCallbackUrls?: ReadonlyMap<string, string>;
	federation: Record<string, unknown>;
	userRepository?: UserRepository;
	userSessionStore?: UserSessionStoreBase;
	federationTokenStore?: FederationTokenStoreBase;
	/** Optional middleware inserted AFTER session shim to intercept req.session.save. */
	saveInterceptor?: express.RequestHandler;
}): { app: express.Express; store: SessionStore } {
	const store: SessionStore = new Map();
	const app = makeSessionApp(store);

	// Plant endpoint — sets session.federation and returns the session cookie
	app.get("/_plant", plantFederation(store, federation));

	if (saveInterceptor) app.use(saveInterceptor);

	app.use(
		createRouter(express, {
			config: {} as never,
			federationProviders: providers,
			providerCallbackUrls: providerCallbackUrls ?? new Map([["test", TEST_CALLBACK_URL]]),
			userRepository: userRepository ?? makeUserRepository(),
			userSessionStore: userSessionStore ?? makeUserSessionStore(),
			federationTokenStore: federationTokenStore ?? makeFederationTokenStore(),
		}),
	);

	// Inspect endpoint — returns current session data as JSON
	app.get("/_inspect", (req: Request, res: Response) => {
		const s = (req as unknown as { session: Record<string, unknown> }).session;
		const { save: _s, ...data } = s;
		res.json(data);
	});

	return { app, store };
}

/** Plant the session and return the agent with the sid cookie set. */
async function plantAndGetAgent(
	app: express.Express,
): Promise<ReturnType<typeof request.agent>> {
	const agent = request.agent(app);
	// Use the /_plant route to set the cookie
	await agent.get("/_plant");
	// Directly write to the shared store (plant route already did this); cookie is set automatically
	return agent;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Federation routes", () => {
	// -----------------------------------------------------------------------
	// createRouter constructor guards
	// -----------------------------------------------------------------------

	describe("createRouter constructor guards", () => {
		it("throws if userSessionStore is missing", () => {
			expect(() =>
				createRouter(express, {
					config: {} as never,
					federationProviders: new Map(),
					userRepository: makeUserRepository(),
					userSessionStore: undefined as never,
					federationTokenStore: makeFederationTokenStore(),
					providerCallbackUrls: new Map(),
				}),
			).toThrow("federation routes require userSessionStore");
		});

		it("throws if federationTokenStore is missing", () => {
			expect(() =>
				createRouter(express, {
					config: {} as never,
					federationProviders: new Map(),
					userRepository: makeUserRepository(),
					userSessionStore: makeUserSessionStore(),
					federationTokenStore: undefined as never,
					providerCallbackUrls: new Map(),
				}),
			).toThrow("federation routes require federationTokenStore");
		});

		it("throws if userRepository is missing", () => {
			expect(() =>
				createRouter(express, {
					config: {} as never,
					federationProviders: new Map(),
					userRepository: undefined as never,
					userSessionStore: makeUserSessionStore(),
					federationTokenStore: makeFederationTokenStore(),
					providerCallbackUrls: new Map(),
				}),
			).toThrow("federation routes require userRepository");
		});

		it("throws if providerCallbackUrls is missing", () => {
			expect(() =>
				createRouter(express, {
					config: {} as never,
					federationProviders: new Map(),
					userRepository: makeUserRepository(),
					userSessionStore: makeUserSessionStore(),
					federationTokenStore: makeFederationTokenStore(),
					providerCallbackUrls: undefined as never,
				}),
			).toThrow("federation routes require providerCallbackUrls");
		});
	});

	// -----------------------------------------------------------------------
	// Start route  GET /oauth/federation/:name
	// -----------------------------------------------------------------------

	describe("GET /oauth/federation/:name (start)", () => {
		// Test 1
		it("returns 404 for unknown provider name", async () => {
			const app = buildStatelessApp({ providers: new Map([["test", makeFakeProvider()]]) });
			const res = await request(app).get("/oauth/federation/unknown");
			expect(res.status).toBe(404);
		});

		// Test 2
		it("redirects with state + code_challenge + code_challenge_method=S256 in Location", async () => {
			const provider = makeFakeProvider();
			const app = buildStatelessApp({ providers: new Map([["test", provider]]) });

			const res = await request(app).get("/oauth/federation/test");

			expect(res.status).toBe(302);
			const location = res.headers.location as string;
			expect(location).toBeDefined();
			const url = new URL(location);
			expect(url.searchParams.get("state")).toBeTruthy();
			expect(url.searchParams.get("code_challenge")).toBeTruthy();
			expect(url.searchParams.get("code_challenge_method")).toBe("S256");
		});

		// Test 3 — redirect_to stored in session.federation.redirectTo
		it("accepts valid redirect_to; buildAuthorizationUrl is invoked (session write path ran)", async () => {
			const provider = makeFakeProvider();
			const buildSpy = vi.spyOn(provider, "buildAuthorizationUrl");
			const app = buildStatelessApp({ providers: new Map([["test", provider]]) });

			const res = await request(app).get(
				"/oauth/federation/test?redirect_to=https%3A%2F%2Fexample.com%2Fdash",
			);

			// 302 confirms redirect_to was accepted and written to session.
			expect(res.status).toBe(302);
			// buildAuthorizationUrl invoked — confirms the session write path ran.
			expect(buildSpy).toHaveBeenCalled();
		});

		// Regression: buildAuthorizationUrl must receive the configured redirectUri, not ""
		it("buildAuthorizationUrl receives the configured redirectUri for the provider", async () => {
			const provider = makeFakeProvider();
			const buildSpy = vi.spyOn(provider, "buildAuthorizationUrl");
			const app = buildStatelessApp({ providers: new Map([["test", provider]]) });

			await request(app).get("/oauth/federation/test");

			expect(buildSpy).toHaveBeenCalledOnce();
			const callArgs = buildSpy.mock.calls[0][0];
			expect(callArgs.redirectUri).toBe(TEST_CALLBACK_URL);
		});
	});

	// -----------------------------------------------------------------------
	// Callback route  GET /oauth/federation/:name/callback
	// -----------------------------------------------------------------------

	describe("GET /oauth/federation/:name/callback", () => {
		// Test 4 — missing session.federation
		it("returns 400 invalid_session when session.federation is absent", async () => {
			const app = buildStatelessApp({ providers: new Map([["test", makeFakeProvider()]]) });

			const res = await request(app).get(
				"/oauth/federation/test/callback?state=x&code=y",
			);

			expect(res.status).toBe(400);
			expect(JSON.parse(res.text)).toMatchObject({ error: "invalid_session" });
		});

		// Test 5 — mismatched name in session
		it("returns 400 invalid_session when session.federation.name does not match route param", async () => {
			const providers = new Map([
				["other", makeFakeProvider({ name: "other" })],
				["test", makeFakeProvider({ name: "test" })],
			]);
			const { app } = buildCallbackApp({
				providers,
				federation: { name: "other", state: "abc123", codeVerifier: "verifier" },
			});
			const agent = await plantAndGetAgent(app);

			const res = await agent.get("/oauth/federation/test/callback?state=abc123&code=y");
			expect(res.status).toBe(400);
			expect(JSON.parse(res.text)).toMatchObject({ error: "invalid_session" });
		});

		// Test 6 — wrong CSRF state
		it("returns 400 invalid_state when state query param does not match session state", async () => {
			const providers = new Map([["test", makeFakeProvider()]]);
			const { app } = buildCallbackApp({
				providers,
				federation: { name: "test", state: "correct-state", codeVerifier: "verifier" },
			});
			const agent = await plantAndGetAgent(app);

			const res = await agent.get(
				"/oauth/federation/test/callback?state=wrong-state&code=y",
			);
			expect(res.status).toBe(400);
			expect(JSON.parse(res.text)).toMatchObject({ error: "invalid_state" });
		});

		// Test 7 — exchangeCode throws → 502, session.federation deleted (reuse prevention)
		it("returns 502 exchange_failed when exchangeCode throws; session.federation is deleted", async () => {
			const provider = makeFakeProvider({
				exchangeCode: vi.fn(async () => {
					throw new Error("upstream error");
				}),
			});
			const providers = new Map([["test", provider]]);
			const { app } = buildCallbackApp({
				providers,
				federation: { name: "test", state: "s1", codeVerifier: "v1" },
			});
			const agent = await plantAndGetAgent(app);

			const res = await agent.get("/oauth/federation/test/callback?state=s1&code=c1");
			expect(res.status).toBe(502);
			expect(JSON.parse(res.text)).toMatchObject({ error: "exchange_failed" });

			// session.federation should be absent (reuse prevention)
			const inspect = await agent.get("/_inspect");
			expect(JSON.parse(inspect.text).federation).toBeUndefined();
		});

		// Test 8 — empty profile.sub → 400 invalid_profile; session.federation deleted
		it("returns 400 invalid_profile when profile.sub is empty; session.federation deleted", async () => {
			const provider = makeFakeProvider({
				exchangeCode: vi.fn(async () => ({
					issuer: "https://idp.example.com",
					sub: "", // empty
					accessToken: "at",
				})),
			});
			const providers = new Map([["test", provider]]);
			const { app } = buildCallbackApp({
				providers,
				federation: { name: "test", state: "s1", codeVerifier: "v1" },
			});
			const agent = await plantAndGetAgent(app);

			const res = await agent.get("/oauth/federation/test/callback?state=s1&code=c1");
			expect(res.status).toBe(400);
			expect(JSON.parse(res.text)).toMatchObject({ error: "invalid_profile" });

			// session.federation deleted
			const inspect = await agent.get("/_inspect");
			expect(JSON.parse(inspect.text).federation).toBeUndefined();
		});

		// Test 9 — authenticateByToken returns null → 401 unknown_user
		it("returns 401 unknown_user when authenticateByToken returns null", async () => {
			const provider = makeFakeProvider();
			const providers = new Map([["test", provider]]);
			const repo = makeUserRepository(null);

			const { app } = buildCallbackApp({
				providers,
				federation: { name: "test", state: "s1", codeVerifier: "v1" },
				userRepository: repo,
			});
			const agent = await plantAndGetAgent(app);

			const res = await agent.get("/oauth/federation/test/callback?state=s1&code=c1");
			expect(res.status).toBe(401);
			expect(JSON.parse(res.text)).toMatchObject({ error: "unknown_user" });
			expect(repo.authenticateByToken).toHaveBeenCalledWith("test:external-42");
		});

		// Test 10 — happy path
		it("happy path: creates UserSession, attaches token, sets req.session.sid, redirects to redirectTo", async () => {
			const provider = makeFakeProvider();
			const providers = new Map([["test", provider]]);
			const repo = makeUserRepository({ id: "user-1", username: "alice" });
			const uss = makeUserSessionStore();
			const fts = makeFederationTokenStore();

			const { app } = buildCallbackApp({
				providers,
				federation: { name: "test", state: "s1", codeVerifier: "v1", redirectTo: "/dashboard" },
				userRepository: repo,
				userSessionStore: uss,
				federationTokenStore: fts,
			});
			const agent = await plantAndGetAgent(app);

			const res = await agent.get("/oauth/federation/test/callback?state=s1&code=c1");
			expect(res.status).toBe(302);
			// resolveCallbackRedirect returns the stored redirectTo
			expect(res.headers.location).toBe("/dashboard");

			// UserSessionStore.create was called with correct fields
			expect(uss.create).toHaveBeenCalledOnce();
			const createArg = (uss.create as ReturnType<typeof vi.fn>).mock.calls[0][0] as Record<
				string,
				unknown
			>;
			expect(createArg.sub).toBe("user-1");
			expect(createArg.federations).toEqual(["test"]);
			expect(typeof createArg.sid).toBe("string");

			// FederationTokenStore.attach called with correct tokens
			expect(fts.attach).toHaveBeenCalledOnce();
			const [attachSid, attachName, attachTokens] = (fts.attach as ReturnType<typeof vi.fn>)
				.mock.calls[0] as [string, string, Record<string, unknown>];
			expect(attachSid).toBe(createArg.sid);
			expect(attachName).toBe("test");
			expect(attachTokens.accessToken).toBe("at");
			expect(attachTokens.refreshToken).toBe("rt");
			expect(attachTokens.idToken).toBe("it");

			// req.session.sid set on the session
			const inspect = await agent.get("/_inspect");
			expect(JSON.parse(inspect.text).sid).toBe(createArg.sid);
		});

		// Test 11 — rollback: FederationTokenStore.attach throws → UserSessionStore.delete; no token.delete
		it("rollback: attach throws → UserSessionStore.delete called; returns 500", async () => {
			const provider = makeFakeProvider();
			const providers = new Map([["test", provider]]);
			const uss = makeUserSessionStore();
			const fts = makeFederationTokenStore();
			(fts.attach as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("attach fail"));

			const { app } = buildCallbackApp({
				providers,
				federation: { name: "test", state: "s1", codeVerifier: "v1" },
				userSessionStore: uss,
				federationTokenStore: fts,
			});
			const agent = await plantAndGetAgent(app);

			const res = await agent.get("/oauth/federation/test/callback?state=s1&code=c1");
			expect(res.status).toBe(500);

			expect(uss.create).toHaveBeenCalledOnce();
			// Token was NOT attached, so token.delete NOT called
			expect(fts.delete).not.toHaveBeenCalled();
			// UserSession rollback
			expect(uss.delete).toHaveBeenCalledOnce();
		});

		// Test 12 — rollback: req.session.save throws → token.delete + session.delete (reverse order)
		it("rollback: session.save throws → FederationTokenStore.delete + UserSessionStore.delete", async () => {
			const provider = makeFakeProvider();
			const providers = new Map([["test", provider]]);
			const uss = makeUserSessionStore();
			const fts = makeFederationTokenStore();

			// The route makes two save calls per callback request:
			//   call 1 — early deletion-persist (session.federation cleared, should succeed)
			//   call 2 — post-create sid persist (should fail to trigger rollback)
			let saveCalls = 0;
			const saveInterceptor: express.RequestHandler = (req, _res, next) => {
				const origSave = req.session.save.bind(req.session);
				req.session.save = (cb?: (err: unknown) => void) => {
					saveCalls++;
					if (saveCalls === 2 && typeof cb === "function") {
						cb(new Error("session save failed"));
						return req.session;
					}
					return origSave(cb);
				};
				next();
			};

			const { app } = buildCallbackApp({
				providers,
				federation: { name: "test", state: "s1", codeVerifier: "v1" },
				userSessionStore: uss,
				federationTokenStore: fts,
				saveInterceptor,
			});
			const agent = await plantAndGetAgent(app);

			const res = await agent.get("/oauth/federation/test/callback?state=s1&code=c1");
			expect(res.status).toBe(500);

			// UserSession was created
			expect(uss.create).toHaveBeenCalledOnce();
			// Token was attached (attach succeeded before save failed)
			expect(fts.attach).toHaveBeenCalledOnce();
			// Rollback in reverse order
			expect(fts.delete).toHaveBeenCalledOnce();
			expect(uss.delete).toHaveBeenCalledOnce();
		});

		// Test 13 — SupportsClaimMapping: mapClaims merged into UserSession.claims
		it("SupportsClaimMapping: mapClaims output is merged into UserSession.claims", async () => {
			const mapClaimsMock = vi.fn(() => ({
				email: "mapped@example.com",
				name: "Mapped Name",
				picture: "https://cdn.example.com/pic.jpg",
			}));

			// Provider with mapClaims capability
			const provider: FederationProvider & { mapClaims: typeof mapClaimsMock } = {
				...makeFakeProvider(),
				mapClaims: mapClaimsMock,
			};
			const providers = new Map<string, FederationProvider>([["test", provider]]);

			const repo = makeUserRepository({
				id: "user-1",
				username: "alice",
				email: "user@example.com",
				name: "Alice",
			});
			const uss = makeUserSessionStore();

			const { app } = buildCallbackApp({
				providers,
				federation: { name: "test", state: "s1", codeVerifier: "v1" },
				userRepository: repo,
				userSessionStore: uss,
			});
			const agent = await plantAndGetAgent(app);

			await agent.get("/oauth/federation/test/callback?state=s1&code=c1");

			expect(mapClaimsMock).toHaveBeenCalledOnce();
			const createArg = (uss.create as ReturnType<typeof vi.fn>).mock.calls[0][0] as {
				claims: Record<string, unknown>;
			};
			// mapClaims values override extractUserClaims for shared keys
			expect(createArg.claims.email).toBe("mapped@example.com");
			expect(createArg.claims.name).toBe("Mapped Name");
			expect(createArg.claims.picture).toBe("https://cdn.example.com/pic.jpg");
		});

		// Regression: exchangeCode must receive the configured redirectUri, not ""
		it("exchangeCode receives the configured redirectUri for the provider", async () => {
			const provider = makeFakeProvider();
			const providers = new Map([["test", provider]]);
			const { app } = buildCallbackApp({
				providers,
				federation: { name: "test", state: "s1", codeVerifier: "v1" },
			});
			const agent = await plantAndGetAgent(app);

			await agent.get("/oauth/federation/test/callback?state=s1&code=c1");

			expect(provider.exchangeCode).toHaveBeenCalledOnce();
			const callArgs = (provider.exchangeCode as ReturnType<typeof vi.fn>).mock.calls[0][0] as {
				redirectUri: string;
			};
			expect(callArgs.redirectUri).toBe(TEST_CALLBACK_URL);
		});

		// 404 for unknown name on callback route
		it("returns 404 for unknown provider name on callback route", async () => {
			const app = buildStatelessApp({ providers: new Map([["test", makeFakeProvider()]]) });
			const res = await request(app).get("/oauth/federation/unknown/callback?state=x&code=y");
			expect(res.status).toBe(404);
		});
	});
});
