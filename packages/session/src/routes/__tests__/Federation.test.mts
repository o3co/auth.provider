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

import type {
	FederationTokenStore,
	SessionFederationIndex,
	UserRepository,
	UserSessionStore,
} from "@o3co/auth-provider-core";
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
/**
 * Build a minimal session-like object backed by `store` under `persistKey`.
 *
 * `persistKey` is the store key used for both reads and writes.  For the initial
 * session it equals the cookie id.  For regenerated sessions it is still the
 * original cookie id — simulating the browser receiving a `Set-Cookie` with the
 * new session id, which in tests cannot actually change the agent's cookie.
 * This keeps `/_inspect` requests (which arrive with the original cookie) able
 * to read the regenerated session's data.
 */
function makeSessionObject(
	store: SessionStore,
	persistKey: string,
	req: express.Request,
): Record<string, unknown> {
	const sessionData = store.get(persistKey) ?? {};
	const session: Record<string, unknown> = {
		...sessionData,
		save(cb?: (err: unknown) => void) {
			const current = (req as unknown as { session: Record<string, unknown> }).session;
			const { save: _s, regenerate: _r, ...rest } = current;
			store.set(persistKey, rest);
			cb?.(null);
			return this as unknown as import("express-session").Session;
		},
		regenerate(cb?: (err: unknown) => void) {
			// Simulate session ID rotation: clear the store entry (old data gone) and
			// install a fresh empty session.  We reuse the same `persistKey` so that
			// subsequent supertest requests with the same cookie still reach the data.
			store.set(persistKey, {});
			const newSession = makeSessionObject(store, persistKey, req);
			(req as unknown as { session: Record<string, unknown> }).session = newSession;
			cb?.(null);
			return this as unknown as import("express-session").Session;
		},
		destroy(cb?: (err: unknown) => void) {
			// Best-effort destroy: remove the session from the store.
			store.delete(persistKey);
			cb?.(null);
			return this as unknown as import("express-session").Session;
		},
	};
	return session;
}

function makeSessionApp(store: SessionStore): express.Express {
	const app = express();
	app.use((req, res, next) => {
		// Parse the `sid` cookie manually
		const cookieHeader = req.headers.cookie ?? "";
		const sidMatch = cookieHeader.match(/(?:^|;\s*)sid=([^;]+)/);
		const id = sidMatch ? decodeURIComponent(sidMatch[1]) : String(Math.random());

		if (!store.has(id)) store.set(id, {});

		// Attach a minimal session-like object to req
		(req as unknown as { session: Record<string, unknown> }).session = makeSessionObject(
			store,
			id,
			req,
		);

		// Persist the session cookie so a supertest agent can carry it across requests.
		// Real express-session does this on response writeHead — we mimic it idempotently
		// here so end-to-end inspection (start handler → /_inspect) sees the same session.
		res.cookie("sid", id, { httpOnly: true });

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

function makeUserSessionStore(): UserSessionStore & {
	create: ReturnType<typeof vi.fn>;
	delete: ReturnType<typeof vi.fn>;
} {
	return {
		kind: "memory",
		create: vi.fn(async () => {}),
		get: vi.fn(async () => null),
		delete: vi.fn(async () => {}),
	};
}

function makeSessionFederationIndex(
	override?: Partial<SessionFederationIndex>,
): SessionFederationIndex {
	return {
		kind: "memory",
		addFederation: vi.fn(async () => {}),
		listFederations: vi.fn(async () => []),
		removeFederation: vi.fn(async () => {}),
		removeBySid: vi.fn(async () => {}),
		...override,
	} as SessionFederationIndex;
}

function makeFederationTokenStore(): FederationTokenStore & {
	attach: ReturnType<typeof vi.fn>;
	delete: ReturnType<typeof vi.fn>;
} {
	return {
		kind: "memory",
		attach: vi.fn(async () => {}),
		get: vi.fn(async () => null),
		update: vi.fn(async () => {}),
		removeBySid: vi.fn(async () => {}),
		delete: vi.fn(async () => {}),
	};
}

// ---------------------------------------------------------------------------
// Convenience app builder for simple (stateless) start-route tests
// ---------------------------------------------------------------------------

const TEST_CALLBACK_URL = "https://app.example.com/session/oauth/federation/test/callback";

/** Default permissive redirect policy for test providers. */
function makePermissivePolicy() {
	return {
		validateRedirect: () => ({ ok: true as const, value: undefined }),
		resolveCallbackRedirect: (s: { redirectTo?: string }) => ({
			ok: true as const,
			value: s.redirectTo ?? "/",
		}),
	};
}

function buildStatelessApp({
	providers,
	providerCallbackUrls,
	federationRedirectPolicyResolver,
	userRepository,
	userSessionStore,
	sessionFederationIndex,
	federationTokenStore,
}: {
	providers: ReadonlyMap<string, FederationProvider>;
	providerCallbackUrls?: ReadonlyMap<string, string>;
	federationRedirectPolicyResolver?: ReadonlyMap<string, ReturnType<typeof makePermissivePolicy>>;
	userRepository?: UserRepository;
	userSessionStore?: UserSessionStore;
	sessionFederationIndex?: SessionFederationIndex;
	federationTokenStore?: FederationTokenStore;
}) {
	const store: SessionStore = new Map();
	const app = makeSessionApp(store);
	// Default: permissive policy for every registered provider name
	const defaultResolver = new Map(
		[...providers.keys()].map((name) => [name, makePermissivePolicy()]),
	);
	app.use(
		createRouter(express, {
			config: {} as never,
			federationProviders: providers,
			federationRedirectPolicyResolver: federationRedirectPolicyResolver ?? defaultResolver,
			providerCallbackUrls: providerCallbackUrls ?? new Map([["test", TEST_CALLBACK_URL]]),
			userRepository: userRepository ?? makeUserRepository(),
			userSessionStore: userSessionStore ?? makeUserSessionStore(),
			sessionFederationIndex: sessionFederationIndex ?? makeSessionFederationIndex(),
			federationTokenStore: federationTokenStore ?? makeFederationTokenStore(),
		}),
	);

	// Inspect endpoint — exposes the cookie-bound session as JSON. Used by tests that
	// need to verify a route wrote (or cleared) session fields end-to-end.
	app.get("/_inspect", (req: Request, res: Response) => {
		const s = (req as unknown as { session: Record<string, unknown> }).session;
		const { save: _s, regenerate: _r, destroy: _d, ...data } = s;
		res.json(data);
	});

	return app;
}

/**
 * Build an app with a planted session so callback-route tests start with a
 * pre-seeded session.federation value.
 */
function buildCallbackApp({
	providers,
	providerCallbackUrls,
	federationRedirectPolicyResolver,
	federation,
	userRepository,
	userSessionStore,
	sessionFederationIndex,
	federationTokenStore,
	saveInterceptor,
}: {
	providers: ReadonlyMap<string, FederationProvider>;
	providerCallbackUrls?: ReadonlyMap<string, string>;
	federationRedirectPolicyResolver?: ReadonlyMap<string, ReturnType<typeof makePermissivePolicy>>;
	federation: Record<string, unknown>;
	userRepository?: UserRepository;
	userSessionStore?: UserSessionStore;
	sessionFederationIndex?: SessionFederationIndex;
	federationTokenStore?: FederationTokenStore;
	/** Optional middleware inserted AFTER session shim to intercept req.session.save. */
	saveInterceptor?: express.RequestHandler;
}): { app: express.Express; store: SessionStore } {
	const store: SessionStore = new Map();
	const app = makeSessionApp(store);

	// Plant endpoint — sets session.federation and returns the session cookie
	app.get("/_plant", plantFederation(store, federation));

	if (saveInterceptor) app.use(saveInterceptor);

	// Default: permissive policy for every registered provider name
	const defaultResolver = new Map(
		[...providers.keys()].map((name) => [name, makePermissivePolicy()]),
	);
	app.use(
		createRouter(express, {
			config: {} as never,
			federationProviders: providers,
			federationRedirectPolicyResolver: federationRedirectPolicyResolver ?? defaultResolver,
			providerCallbackUrls: providerCallbackUrls ?? new Map([["test", TEST_CALLBACK_URL]]),
			userRepository: userRepository ?? makeUserRepository(),
			userSessionStore: userSessionStore ?? makeUserSessionStore(),
			sessionFederationIndex: sessionFederationIndex ?? makeSessionFederationIndex(),
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
async function plantAndGetAgent(app: express.Express): Promise<ReturnType<typeof request.agent>> {
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
					federationRedirectPolicyResolver: new Map(),
					userRepository: makeUserRepository(),
					userSessionStore: undefined as never,
					sessionFederationIndex: makeSessionFederationIndex(),
					federationTokenStore: makeFederationTokenStore(),
					providerCallbackUrls: new Map(),
				}),
			).toThrow("federation routes require userSessionStore");
		});

		it("throws if sessionFederationIndex is missing", () => {
			expect(() =>
				createRouter(express, {
					config: {} as never,
					federationProviders: new Map(),
					federationRedirectPolicyResolver: new Map(),
					userRepository: makeUserRepository(),
					userSessionStore: makeUserSessionStore(),
					sessionFederationIndex: undefined as never,
					federationTokenStore: makeFederationTokenStore(),
					providerCallbackUrls: new Map(),
				}),
			).toThrow("federation routes require sessionFederationIndex");
		});

		it("throws if federationTokenStore is missing", () => {
			expect(() =>
				createRouter(express, {
					config: {} as never,
					federationProviders: new Map(),
					federationRedirectPolicyResolver: new Map(),
					userRepository: makeUserRepository(),
					userSessionStore: makeUserSessionStore(),
					sessionFederationIndex: makeSessionFederationIndex(),
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
					federationRedirectPolicyResolver: new Map(),
					userRepository: undefined as never,
					userSessionStore: makeUserSessionStore(),
					sessionFederationIndex: makeSessionFederationIndex(),
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
					federationRedirectPolicyResolver: new Map(),
					userRepository: makeUserRepository(),
					userSessionStore: makeUserSessionStore(),
					sessionFederationIndex: makeSessionFederationIndex(),
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

		// AS-1 RFC 6749 §5.2 envelope: 404 body shape migrates from {message:"NotFound"}
		// to {error:"not_found", error_description}.
		it("AS-1: 404 unknown provider returns RFC 6749 envelope (no `message`)", async () => {
			const app = buildStatelessApp({ providers: new Map([["test", makeFakeProvider()]]) });
			const res = await request(app).get("/oauth/federation/unknown");
			expect(res.status).toBe(404);
			expect(res.body).toMatchObject({
				error: "not_found",
				error_description: expect.any(String),
			});
			expect(res.body).not.toHaveProperty("message");
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

			const res = await request(app).get("/oauth/federation/test/callback?state=x&code=y");

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

			const res = await agent.get("/oauth/federation/test/callback?state=wrong-state&code=y");
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
					expiresAt: null,
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
		it("happy path: creates UserSession, addFederation, attaches token, sets req.session.sid, redirects to redirectTo", async () => {
			const provider = makeFakeProvider();
			const providers = new Map([["test", provider]]);
			const repo = makeUserRepository({ id: "user-1", username: "alice" });
			const uss = makeUserSessionStore();
			const sfi = makeSessionFederationIndex();
			const fts = makeFederationTokenStore();

			const { app } = buildCallbackApp({
				providers,
				federation: { name: "test", state: "s1", codeVerifier: "v1", redirectTo: "/dashboard" },
				userRepository: repo,
				userSessionStore: uss,
				sessionFederationIndex: sfi,
				federationTokenStore: fts,
			});
			const agent = await plantAndGetAgent(app);

			const res = await agent.get("/oauth/federation/test/callback?state=s1&code=c1");
			expect(res.status).toBe(302);
			// resolveCallbackRedirect returns the stored redirectTo
			expect(res.headers.location).toBe("/dashboard");

			// UserSessionStore.create was called with correct fields — NO federations field
			expect(uss.create).toHaveBeenCalledOnce();
			const createArg = (uss.create as ReturnType<typeof vi.fn>).mock.calls[0][0] as Record<
				string,
				unknown
			>;
			expect(createArg.sub).toBe("user-1");
			expect(createArg.federations).toBeUndefined();
			expect(typeof createArg.sid).toBe("string");

			// sessionFederationIndex.addFederation called with (sid, "test", expiresAt)
			expect(sfi.addFederation).toHaveBeenCalledOnce();
			const [addSid, addName, addExpiresAt] = (sfi.addFederation as ReturnType<typeof vi.fn>).mock
				.calls[0] as [string, string, Date];
			expect(addSid).toBe(createArg.sid);
			expect(addName).toBe("test");
			expect(addExpiresAt).toBeInstanceOf(Date);

			// FederationTokenStore.attach called with correct tokens
			expect(fts.attach).toHaveBeenCalledOnce();
			const [attachSid, attachName, attachTokens] = (fts.attach as ReturnType<typeof vi.fn>).mock
				.calls[0] as [string, string, Record<string, unknown>];
			expect(attachSid).toBe(createArg.sid);
			expect(attachName).toBe("test");
			expect(attachTokens.accessToken).toBe("at");
			expect(attachTokens.refreshToken).toBe("rt");
			expect(attachTokens.idToken).toBe("it");
			// profile.expiresAt is a Date → attached as-is, no 1h fallback re-invented
			expect(attachTokens.expiresAt).toBeInstanceOf(Date);

			// req.session.sid set on the session
			const inspect = await agent.get("/_inspect");
			expect(JSON.parse(inspect.text).sid).toBe(createArg.sid);
		});

		// Regression: route must propagate profile.expiresAt === null verbatim
		// (no legacy "now + 1h" fallback). null signals "no finite expiry; don't
		// refresh" — a fallback would trigger spurious refresh attempts for
		// GitHub OAuth Apps classic tokens.
		it("expiresAt=null on profile propagates to FederationTokenStore.attach as null", async () => {
			const provider = makeFakeProvider({
				exchangeCode: vi.fn(async () => ({
					issuer: "https://idp.example.com",
					sub: "external-42",
					accessToken: "at",
					expiresAt: null as Date | null,
				})),
			});
			const providers = new Map([["test", provider]]);
			const repo = makeUserRepository();
			const uss = makeUserSessionStore();
			const fts = makeFederationTokenStore();

			const { app } = buildCallbackApp({
				providers,
				federation: { name: "test", state: "s1", codeVerifier: "v1" },
				userRepository: repo,
				userSessionStore: uss,
				federationTokenStore: fts,
			});
			const agent = await plantAndGetAgent(app);

			const res = await agent.get("/oauth/federation/test/callback?state=s1&code=c1");
			expect(res.status).toBe(302);

			expect(fts.attach).toHaveBeenCalledOnce();
			const [, , attachTokens] = (fts.attach as ReturnType<typeof vi.fn>).mock.calls[0] as [
				string,
				string,
				Record<string, unknown>,
			];
			expect(attachTokens.expiresAt).toBeNull();
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

			// The route makes the following calls per callback request:
			//   save 1 — reuse-prevention persist (session.federation cleared, should succeed)
			//   regenerate() — replaces req.session with a new object
			//   save 2 (on new session) — post-regenerate sid persist (should fail → rollback)
			//
			// The saveInterceptor patches both the initial save AND wraps regenerate so that
			// the new session's save is also intercepted.
			const saveInterceptor: express.RequestHandler = (req, _res, next) => {
				let saveCalls = 0;

				function patchSave(session: import("express-session").Session) {
					const orig = session.save.bind(session);
					session.save = (cb?: (err: unknown) => void) => {
						saveCalls++;
						// save 2 (on the regenerated session) should fail to trigger rollback
						if (saveCalls === 2 && typeof cb === "function") {
							cb(new Error("session save failed"));
							return session;
						}
						return orig(cb);
					};
				}

				patchSave(req.session);

				// Also wrap regenerate to patch save on the newly created session.
				const origRegenerate = req.session.regenerate.bind(req.session);
				req.session.regenerate = (cb?: (err: unknown) => void) => {
					return origRegenerate((err: unknown) => {
						// req.session is now the new session — patch its save too.
						patchSave(req.session);
						cb?.(err);
					});
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

		// AS-1 RFC 6749 §5.2 envelope: callback 404 body shape migrates same as start.
		it("AS-1: 404 unknown provider on callback returns RFC 6749 envelope (no `message`)", async () => {
			const app = buildStatelessApp({ providers: new Map([["test", makeFakeProvider()]]) });
			const res = await request(app).get("/oauth/federation/unknown/callback?state=x&code=y");
			expect(res.status).toBe(404);
			expect(res.body).toMatchObject({
				error: "not_found",
				error_description: expect.any(String),
			});
			expect(res.body).not.toHaveProperty("message");
		});

		// Fix 1 — session fixation: regenerate is called; new session has correct sid/isAuthenticated/user
		it("Fix 1: regenerates session after successful auth; new session has sid/isAuthenticated/user", async () => {
			const provider = makeFakeProvider();
			const providers = new Map([["test", provider]]);
			const repo = makeUserRepository({ id: "user-1", username: "alice" });
			const uss = makeUserSessionStore();
			const fts = makeFederationTokenStore();

			// Spy on regenerate to verify it was called
			let regenerateCalled = false;
			const regenerateInterceptor: express.RequestHandler = (req, _res, next) => {
				const origRegenerate = req.session.regenerate.bind(req.session);
				req.session.regenerate = (cb: (err: unknown) => void) => {
					regenerateCalled = true;
					return origRegenerate(cb);
				};
				next();
			};

			const { app } = buildCallbackApp({
				providers,
				federation: { name: "test", state: "s1", codeVerifier: "v1", redirectTo: "/dashboard" },
				userRepository: repo,
				userSessionStore: uss,
				federationTokenStore: fts,
				saveInterceptor: regenerateInterceptor,
			});
			const agent = await plantAndGetAgent(app);

			const res = await agent.get("/oauth/federation/test/callback?state=s1&code=c1");
			expect(res.status).toBe(302);
			expect(res.headers.location).toBe("/dashboard");

			// regenerate was called
			expect(regenerateCalled).toBe(true);

			// New session must have the correct auth fields
			const inspect = await agent.get("/_inspect");
			const sessionData = JSON.parse(inspect.text) as Record<string, unknown>;
			expect(sessionData.isAuthenticated).toBe(true);
			expect(typeof sessionData.sid).toBe("string");
			expect((sessionData.user as Record<string, unknown>).id).toBe("user-1");
		});

		// Fix 1: if regenerate fails, userSessionStore.delete is called (rollback) and 500 returned
		it("Fix 1: regenerate failure → UserSessionStore.delete rollback + 500", async () => {
			const provider = makeFakeProvider();
			const providers = new Map([["test", provider]]);
			const uss = makeUserSessionStore();
			const fts = makeFederationTokenStore();

			const regenerateFailInterceptor: express.RequestHandler = (req, _res, next) => {
				req.session.regenerate = (cb?: (err: unknown) => void) => {
					cb?.(new Error("regenerate failed"));
					return req.session;
				};
				next();
			};

			const { app } = buildCallbackApp({
				providers,
				federation: { name: "test", state: "s1", codeVerifier: "v1" },
				userSessionStore: uss,
				federationTokenStore: fts,
				saveInterceptor: regenerateFailInterceptor,
			});
			const agent = await plantAndGetAgent(app);

			const res = await agent.get("/oauth/federation/test/callback?state=s1&code=c1");
			expect(res.status).toBe(500);
			expect(JSON.parse(res.text)).toMatchObject({ error: "session_create_failed" });

			// UserSession was created then rolled back
			expect(uss.create).toHaveBeenCalledOnce();
			expect(uss.delete).toHaveBeenCalledOnce();
			// No token was attached (regenerate failed before attach)
			expect(fts.attach).not.toHaveBeenCalled();
			expect(fts.delete).not.toHaveBeenCalled();
		});

		// Fix 2 — fail-closed reuse-prevention: save failure returns 500, does NOT call exchangeCode
		it("Fix 2: reuse-prevention save failure returns 500 and does NOT call exchangeCode", async () => {
			const provider = makeFakeProvider();
			const providers = new Map([["test", provider]]);

			// Intercept the first save (reuse-prevention) to fail
			const saveFailInterceptor: express.RequestHandler = (req, _res, next) => {
				const origSave = req.session.save.bind(req.session);
				let saveCount = 0;
				req.session.save = (cb?: (err: unknown) => void) => {
					saveCount++;
					if (saveCount === 1 && typeof cb === "function") {
						cb(new Error("store unavailable"));
						return req.session;
					}
					return origSave(cb);
				};
				next();
			};

			const { app } = buildCallbackApp({
				providers,
				federation: { name: "test", state: "s1", codeVerifier: "v1" },
				saveInterceptor: saveFailInterceptor,
			});
			const agent = await plantAndGetAgent(app);

			const res = await agent.get("/oauth/federation/test/callback?state=s1&code=c1");
			expect(res.status).toBe(500);
			expect(JSON.parse(res.text)).toMatchObject({
				error: "server_error",
				error_description: "Session store unavailable",
			});

			// exchangeCode must NOT have been called (fail-closed gate)
			expect(provider.exchangeCode).not.toHaveBeenCalled();
		});

		// Fix 3 — authenticateByToken throws → 503 temporarily_unavailable
		it("Fix 3: authenticateByToken throws → 503 temporarily_unavailable", async () => {
			const provider = makeFakeProvider();
			const providers = new Map([["test", provider]]);
			const repo: UserRepository = {
				authenticate: vi.fn(async () => null),
				authenticateByToken: vi.fn(async () => {
					throw new Error("db outage");
				}),
			};

			const { app } = buildCallbackApp({
				providers,
				federation: { name: "test", state: "s1", codeVerifier: "v1" },
				userRepository: repo,
			});
			const agent = await plantAndGetAgent(app);

			const res = await agent.get("/oauth/federation/test/callback?state=s1&code=c1");
			expect(res.status).toBe(503);
			expect(JSON.parse(res.text)).toMatchObject({ error: "temporarily_unavailable" });
		});

		// C-1 Claude: userSessionStore.create throws → 503 temporarily_unavailable (no rollback needed)
		it("C-1: userSessionStore.create throws → 503 temporarily_unavailable; exchangeCode was called", async () => {
			const provider = makeFakeProvider();
			const providers = new Map([["test", provider]]);
			const uss = makeUserSessionStore();
			(uss.create as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("db outage"));
			const fts = makeFederationTokenStore();

			const { app } = buildCallbackApp({
				providers,
				federation: { name: "test", state: "s1", codeVerifier: "v1" },
				userSessionStore: uss,
				federationTokenStore: fts,
			});
			const agent = await plantAndGetAgent(app);

			const res = await agent.get("/oauth/federation/test/callback?state=s1&code=c1");
			expect(res.status).toBe(503);
			expect(JSON.parse(res.text)).toMatchObject({ error: "temporarily_unavailable" });

			// exchangeCode was called (failure happens at persist step, not exchange step)
			expect(provider.exchangeCode).toHaveBeenCalledOnce();
			// No token was attached (create failed before attach)
			expect(fts.attach).not.toHaveBeenCalled();
		});

		// Fix 4 — missing code query param → 400 invalid_request (not 502 exchange_failed)
		it("Fix 4: missing code query param returns 400 invalid_request", async () => {
			const provider = makeFakeProvider();
			const providers = new Map([["test", provider]]);

			const { app } = buildCallbackApp({
				providers,
				federation: { name: "test", state: "s1", codeVerifier: "v1" },
			});
			const agent = await plantAndGetAgent(app);

			// No code param
			const res = await agent.get("/oauth/federation/test/callback?state=s1");
			expect(res.status).toBe(400);
			expect(JSON.parse(res.text)).toMatchObject({
				error: "invalid_request",
				error_description: "Missing authorization code",
			});

			// exchangeCode must NOT be called
			expect(provider.exchangeCode).not.toHaveBeenCalled();
		});

		// Fix 4: empty string code param → 400 invalid_request
		it("Fix 4: empty string code query param returns 400 invalid_request", async () => {
			const provider = makeFakeProvider();
			const providers = new Map([["test", provider]]);

			const { app } = buildCallbackApp({
				providers,
				federation: { name: "test", state: "s1", codeVerifier: "v1" },
			});
			const agent = await plantAndGetAgent(app);

			const res = await agent.get("/oauth/federation/test/callback?state=s1&code=");
			expect(res.status).toBe(400);
			expect(JSON.parse(res.text)).toMatchObject({ error: "invalid_request" });
			expect(provider.exchangeCode).not.toHaveBeenCalled();
		});

		// -----------------------------------------------------------------------
		// A4 sibling-store invariants (§6.1 + §13.5)
		// -----------------------------------------------------------------------

		describe("federation login: A4 sibling-store invariants", () => {
			// A4-1: Both stores populated on success
			it("create succeeds + addFederation succeeds → both stores called, no federations in create input", async () => {
				const provider = makeFakeProvider();
				const providers = new Map([["test", provider]]);
				const uss = makeUserSessionStore();
				const sfi = makeSessionFederationIndex();

				const { app } = buildCallbackApp({
					providers,
					federation: { name: "test", state: "s1", codeVerifier: "v1" },
					userSessionStore: uss,
					sessionFederationIndex: sfi,
				});
				const agent = await plantAndGetAgent(app);

				const res = await agent.get("/oauth/federation/test/callback?state=s1&code=c1");
				expect(res.status).toBe(302);

				// userSessionStore.create called once with no federations field
				expect(uss.create).toHaveBeenCalledOnce();
				const createArg = (uss.create as ReturnType<typeof vi.fn>).mock.calls[0][0] as Record<
					string,
					unknown
				>;
				expect(createArg.federations).toBeUndefined();

				// sessionFederationIndex.addFederation called with (sid, "test", expiresAt)
				expect(sfi.addFederation).toHaveBeenCalledOnce();
				const [addSid, addName, addExpiresAt] = (sfi.addFederation as ReturnType<typeof vi.fn>).mock
					.calls[0] as [string, string, Date];
				expect(addSid).toBe(createArg.sid);
				expect(addName).toBe("test");
				expect(addExpiresAt).toBeInstanceOf(Date);
			});

			// A4-2: addFederation failure rolls back orphan UserSession → 503
			it("addFederation failure after create → orphan session rolled back, 503 returned", async () => {
				const provider = makeFakeProvider();
				const providers = new Map([["test", provider]]);
				const uss = makeUserSessionStore();
				const sfi = makeSessionFederationIndex({
					addFederation: vi.fn(async () => {
						throw new Error("redis blip");
					}),
				});

				const { app } = buildCallbackApp({
					providers,
					federation: { name: "test", state: "s1", codeVerifier: "v1" },
					userSessionStore: uss,
					sessionFederationIndex: sfi,
				});
				const agent = await plantAndGetAgent(app);

				const res = await agent.get("/oauth/federation/test/callback?state=s1&code=c1");
				expect(res.status).toBe(503);
				expect(JSON.parse(res.text)).toMatchObject({ error: "temporarily_unavailable" });

				// userSessionStore.create was called
				expect(uss.create).toHaveBeenCalledOnce();
				// Orphan UserSession rolled back
				expect(uss.delete).toHaveBeenCalledOnce();
				const deleteSid = (uss.delete as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
				const createSid = (
					(uss.create as ReturnType<typeof vi.fn>).mock.calls[0][0] as Record<string, unknown>
				).sid as string;
				expect(deleteSid).toBe(createSid);
				// No federation token attached
				expect(sfi.addFederation).toHaveBeenCalledOnce();
			});

			// A4-3: regenerate failure rolls back BOTH stores in reverse order (federation index first)
			it("regenerate failure after addFederation rolls back BOTH stores in reverse order (fed first)", async () => {
				const provider = makeFakeProvider();
				const providers = new Map([["test", provider]]);
				const uss = makeUserSessionStore();
				const sfi = makeSessionFederationIndex();

				const regenerateFailInterceptor: express.RequestHandler = (req, _res, next) => {
					req.session.regenerate = (cb?: (err: unknown) => void) => {
						cb?.(new Error("regenerate failed"));
						return req.session;
					};
					next();
				};

				const { app } = buildCallbackApp({
					providers,
					federation: { name: "test", state: "s1", codeVerifier: "v1" },
					userSessionStore: uss,
					sessionFederationIndex: sfi,
					saveInterceptor: regenerateFailInterceptor,
				});
				const agent = await plantAndGetAgent(app);

				const res = await agent.get("/oauth/federation/test/callback?state=s1&code=c1");
				expect(res.status).toBe(500);
				expect(JSON.parse(res.text)).toMatchObject({ error: "session_create_failed" });

				// Both stores were rolled back
				expect(sfi.removeBySid).toHaveBeenCalledOnce();
				expect(uss.delete).toHaveBeenCalledOnce();

				// Verify reverse order: removeBySid (fed index, created last) before delete (session, created first)
				const removeFedOrder = (sfi.removeBySid as ReturnType<typeof vi.fn>).mock
					.invocationCallOrder[0];
				const deleteSessionOrder = (uss.delete as ReturnType<typeof vi.fn>).mock
					.invocationCallOrder[0];
				expect(removeFedOrder).toBeLessThan(deleteSessionOrder);
			});

			// A4-4: post-regenerate failure unwinds federation index before session (REVERSE order)
			it("post-regenerate rollback also unwinds federation index before session (REVERSE order)", async () => {
				const provider = makeFakeProvider();
				const providers = new Map([["test", provider]]);
				const uss = makeUserSessionStore();
				const sfi = makeSessionFederationIndex();
				const fts = makeFederationTokenStore();
				// Make session.save fail on the post-regenerate save (save 2) to trigger the catch block
				const saveFailInterceptor: express.RequestHandler = (req, _res, next) => {
					let saveCalls = 0;

					function patchSave(session: import("express-session").Session) {
						const orig = session.save.bind(session);
						session.save = (cb?: (err: unknown) => void) => {
							saveCalls++;
							if (saveCalls === 2 && typeof cb === "function") {
								cb(new Error("session save failed"));
								return session;
							}
							return orig(cb);
						};
					}

					patchSave(req.session);

					const origRegenerate = req.session.regenerate.bind(req.session);
					req.session.regenerate = (cb?: (err: unknown) => void) => {
						return origRegenerate((err: unknown) => {
							patchSave(req.session);
							cb?.(err);
						});
					};

					next();
				};

				const { app } = buildCallbackApp({
					providers,
					federation: { name: "test", state: "s1", codeVerifier: "v1" },
					userSessionStore: uss,
					sessionFederationIndex: sfi,
					federationTokenStore: fts,
					saveInterceptor: saveFailInterceptor,
				});
				const agent = await plantAndGetAgent(app);

				const res = await agent.get("/oauth/federation/test/callback?state=s1&code=c1");
				expect(res.status).toBe(500);

				// federationTokenStore.delete called (token was attached before save failed)
				expect(fts.delete).toHaveBeenCalledOnce();
				// sessionFederationIndex.removeBySid called
				expect(sfi.removeBySid).toHaveBeenCalledOnce();
				// userSessionStore.delete called
				expect(uss.delete).toHaveBeenCalledOnce();

				// Verify reverse order: fts.delete → sfi.removeBySid → uss.delete
				const deleteFtsOrder = (fts.delete as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0];
				const removeFedOrder = (sfi.removeBySid as ReturnType<typeof vi.fn>).mock
					.invocationCallOrder[0];
				const deleteSessionOrder = (uss.delete as ReturnType<typeof vi.fn>).mock
					.invocationCallOrder[0];
				expect(deleteFtsOrder).toBeLessThan(removeFedOrder);
				expect(removeFedOrder).toBeLessThan(deleteSessionOrder);
			});
		});

		// -----------------------------------------------------------------------
		// PB-4 — Federation OIDC nonce wiring (start + callback)
		// -----------------------------------------------------------------------

		describe("PB-4: federation nonce generation + thread-through", () => {
			// PB-4 RED-1: start handler generates a nonce, persists it on session.federation,
			// AND passes it to buildAuthorizationUrl. The session-side assertion catches the
			// regression class where nonce reaches the provider but never lands in the session
			// (so the callback can't bind id_token via expectedNonce).
			it("start handler persists nonce on session.federation and forwards it to buildAuthorizationUrl", async () => {
				const provider = makeFakeProvider();
				const buildSpy = vi.spyOn(provider, "buildAuthorizationUrl");
				const app = buildStatelessApp({ providers: new Map([["test", provider]]) });
				const agent = request.agent(app);

				const res = await agent.get("/oauth/federation/test");
				expect(res.status).toBe(302);

				expect(buildSpy).toHaveBeenCalledOnce();
				const callArg = buildSpy.mock.calls[0][0] as { nonce?: unknown };
				expect(typeof callArg.nonce).toBe("string");
				expect((callArg.nonce as string).length).toBeGreaterThanOrEqual(16);

				// Cross-check: the same nonce must be persisted on session.federation so the
				// callback handler can thread it back into provider.exchangeCode.
				const inspect = await agent.get("/_inspect");
				const sessionData = JSON.parse(inspect.text) as Record<string, unknown>;
				const fed = sessionData.federation as { nonce?: unknown } | undefined;
				expect(fed).toBeDefined();
				expect(fed?.nonce).toBe(callArg.nonce);
			});

			// PB-4 RED-2: callback handler threads session.federation.nonce into provider.exchangeCode.
			it("callback handler threads session-stored nonce into provider.exchangeCode", async () => {
				const provider = makeFakeProvider();
				const providers = new Map([["test", provider]]);

				const { app } = buildCallbackApp({
					providers,
					federation: {
						name: "test",
						state: "s1",
						codeVerifier: "v1",
						nonce: "stored-nonce-9f3d",
					},
				});
				const agent = await plantAndGetAgent(app);

				const res = await agent.get("/oauth/federation/test/callback?state=s1&code=c1");
				expect(res.status).toBe(302);

				expect(provider.exchangeCode).toHaveBeenCalledOnce();
				const callArg = (provider.exchangeCode as ReturnType<typeof vi.fn>).mock.calls[0][0] as {
					nonce?: unknown;
				};
				expect(callArg.nonce).toBe("stored-nonce-9f3d");
			});

			// PB-4 RED-3: callback handler still works when planted federation has no nonce
			// (defence-in-depth — adapters that ignore nonce must remain backward-compat).
			it("callback handler tolerates absent session.federation.nonce (passes undefined)", async () => {
				const provider = makeFakeProvider();
				const providers = new Map([["test", provider]]);

				const { app } = buildCallbackApp({
					providers,
					// No nonce field — pre-PB-4 sessions or non-OIDC providers.
					federation: { name: "test", state: "s1", codeVerifier: "v1" },
				});
				const agent = await plantAndGetAgent(app);

				const res = await agent.get("/oauth/federation/test/callback?state=s1&code=c1");
				expect(res.status).toBe(302);

				expect(provider.exchangeCode).toHaveBeenCalledOnce();
				const callArg = (provider.exchangeCode as ReturnType<typeof vi.fn>).mock.calls[0][0] as {
					nonce?: unknown;
				};
				expect(callArg.nonce).toBeUndefined();
			});
		});

		// -----------------------------------------------------------------------
		// TD-6 — Reuse / replay-prevention assertions
		// -----------------------------------------------------------------------

		describe("TD-6: session.federation cleanup on success path", () => {
			// TD-6 RED-1: happy path must clear session.federation as part of reuse prevention.
			// Pre-fix Test 10 only inspected sid, so a regression that re-introduced the
			// pre-cleared federation envelope (e.g. by re-saving fed back onto the session)
			// would silently slip through.
			it("happy-path callback clears session.federation as part of reuse prevention", async () => {
				const provider = makeFakeProvider();
				const providers = new Map([["test", provider]]);

				const { app } = buildCallbackApp({
					providers,
					federation: { name: "test", state: "s1", codeVerifier: "v1", nonce: "n1" },
				});
				const agent = await plantAndGetAgent(app);

				const res = await agent.get("/oauth/federation/test/callback?state=s1&code=c1");
				expect(res.status).toBe(302);

				const inspect = await agent.get("/_inspect");
				const sessionData = JSON.parse(inspect.text) as Record<string, unknown>;
				expect(sessionData.federation).toBeUndefined();
			});

			// TD-6 RED-2: replay prevention — re-using the same state after a successful
			// callback must fail because the planted federation envelope is gone. The 400
			// invalid_session response is the same one that protects against pre-completion
			// CSRF state replay; we just assert it activates after the auth-grant has been
			// consumed.
			it("replay prevention: second callback with same state returns 400 invalid_session", async () => {
				const provider = makeFakeProvider();
				const providers = new Map([["test", provider]]);
				const { app } = buildCallbackApp({
					providers,
					federation: { name: "test", state: "replay-state", codeVerifier: "v1", nonce: "n1" },
				});
				const agent = await plantAndGetAgent(app);

				const first = await agent.get("/oauth/federation/test/callback?state=replay-state&code=c1");
				expect(first.status).toBe(302);

				// Second attempt — agent retains the cookie but session.federation is gone.
				const second = await agent.get(
					"/oauth/federation/test/callback?state=replay-state&code=c2",
				);
				expect(second.status).toBe(400);
				expect(JSON.parse(second.text)).toMatchObject({ error: "invalid_session" });
				// exchangeCode must NOT fire on the replay — the gate is the absent envelope.
				expect(provider.exchangeCode).toHaveBeenCalledOnce();
			});
		});
	});
});
