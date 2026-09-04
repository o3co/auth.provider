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
	type AuditSink,
	type ClientRepository,
	createSymmetricKeyStore,
	type FederationProviderHandle,
	type FederationTokenStore,
	type Logger,
	type RefreshTokenFamilyRevocation,
	type SessionFamilyIndex,
	type SessionFederationIndex,
	type SessionRPRegistry,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createRouter } from "#/routes/logout.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

/** Mint an id_token with the given claims. */
// #394: mints carry typ JWT. `typ` stays overridable so the suite can present
// a wrong spelling — including the pre-#394 `id+jwt`, which #402 made one more
// wrong spelling rather than a special case.
async function mintIdToken(extra: Record<string, unknown> = {}, typ = "JWT"): Promise<string> {
	return new SignJWT({
		sub: "u-1",
		aud: "client-1",
		sid: "sid-1",
		...extra,
	})
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ })
		.setExpirationTime("1h")
		.setIssuedAt()
		.setIssuer("https://auth.example.com")
		.sign(secretKey);
}

async function mintOldIdToken(): Promise<string> {
	const oldIat = Math.floor((Date.now() - 25 * 60 * 60 * 1000) / 1000);
	return new SignJWT({
		sub: "u-1",
		aud: "client-1",
		sid: "sid-1",
	})
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "JWT" })
		.setExpirationTime("1h")
		.setIssuedAt(oldIat)
		.setIssuer("https://auth.example.com")
		.sign(secretKey);
}

/**
 * Mint an access token (typ: at+jwt) for use with POST /oauth/federation/:name/logout.
 * Includes sid, sub, and family_id by default.
 */
async function mintAccessToken(extra: Record<string, unknown> = {}): Promise<string> {
	return new SignJWT({
		sub: "u-1",
		sid: "sid-1",
		family_id: "fam-1",
		...extra,
	})
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
		.setExpirationTime("1h")
		.setIssuedAt()
		.setIssuer("https://auth.example.com")
		.sign(secretKey);
}

// A minimal valid UserSession (v0.5.0 shape — no derived fields)
const baseSession: UserSession = {
	sid: "sid-1",
	sub: "u-1",
	authTime: new Date(),
	createdAt: new Date(),
	expiresAt: new Date(Date.now() + 3_600_000),
	claims: { email: "alice@example.com" },
};

function makeSessionStore(override?: Partial<UserSessionStore>): UserSessionStore {
	return {
		kind: "memory",
		create: vi.fn(),
		get: vi.fn().mockResolvedValue(baseSession),
		delete: vi.fn(),
		...override,
	};
}

function makeSessionRPRegistry(override?: Partial<SessionRPRegistry>): SessionRPRegistry {
	return {
		kind: "memory",
		registerRP: vi.fn(async () => {}),
		listRPs: vi.fn(async () => []),
		removeBySid: vi.fn(async () => {}),
		...override,
	} as SessionRPRegistry;
}

function makeSessionFamilyIndex(override?: Partial<SessionFamilyIndex>): SessionFamilyIndex {
	return {
		kind: "memory",
		addFamilyId: vi.fn(async () => {}),
		listFamilyIds: vi.fn(async () => ["fam-1"]),
		removeBySid: vi.fn(async () => {}),
		...override,
	} as SessionFamilyIndex;
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

function makeFamilyRevocation(
	override?: Partial<RefreshTokenFamilyRevocation>,
): RefreshTokenFamilyRevocation {
	return {
		isFamilyRevoked: vi.fn().mockResolvedValue(false),
		revokeFamily: vi.fn().mockResolvedValue(undefined),
		...override,
	};
}

function makeFedTokenStore(override?: Partial<FederationTokenStore>): FederationTokenStore {
	return {
		kind: "memory",
		attach: vi.fn(),
		get: vi.fn().mockResolvedValue(null),
		update: vi.fn(),
		removeBySid: vi.fn().mockResolvedValue(undefined),
		delete: vi.fn(),
		...override,
	};
}

function makeClientRepo(override?: Partial<ClientRepository>): ClientRepository {
	return {
		findById: vi.fn().mockResolvedValue(null),
		authenticate: vi.fn(),
		...override,
	};
}

interface BuildAppOpts {
	sessionStore?: UserSessionStore;
	sessionRPRegistry?: SessionRPRegistry;
	sessionFamilyIndex?: SessionFamilyIndex;
	sessionFederationIndex?: SessionFederationIndex;
	refreshFamilyRevocation?: RefreshTokenFamilyRevocation;
	fedTokenStore?: FederationTokenStore;
	clientRepo?: ClientRepository;
	/** Getter for federation providers — evaluated at request time. */
	getFederationProviders?: () => ReadonlyMap<string, FederationProviderHandle> | undefined;
	/** Override fetch for broadcast testing. Defaults to a no-op stub. */
	fetchImpl?: typeof fetch;
	logger?: Logger;
	auditSink?: AuditSink;
	/**
	 * The express-session bag the request carries. Absent by default, which is
	 * the shape the rest of this suite runs in (no session middleware mounted)
	 * and the one R1a must not throw on.
	 */
	browserSession?: FakeBrowserSession;
}

/**
 * The slice of `express-session`'s request session R1a touches: the `sid` it
 * recorded at login and the `destroy` callback. `destroyed` records whether
 * the route actually ended it, so a test can assert on scoping rather than on
 * a spy's call count alone.
 */
interface FakeBrowserSession extends Record<string, unknown> {
	destroy: (cb: (err: Error | null) => void) => void;
	destroyed?: boolean;
}

/**
 * Builds the session bag a logged-in browser carries. `sid` names the
 * UserSession this browser belongs to; `destroyFails` makes the store's
 * destroy reject the way a Redis outage would, and `destroyThrows` makes it
 * throw synchronously the way an adapter that validates its arguments before
 * reaching its own callback does — the path that never calls back at all.
 */
function makeBrowserSession(
	opts: { sid?: string; destroyFails?: boolean; destroyThrows?: boolean } = {},
): FakeBrowserSession {
	const session: FakeBrowserSession = {
		isAuthenticated: true,
		user: { id: "u-1" },
		destroyed: false,
		destroy(cb: (err: Error | null) => void) {
			if (opts.destroyThrows) {
				throw new Error("session store threw synchronously");
			}
			if (opts.destroyFails) {
				cb(new Error("session store down"));
				return;
			}
			session.destroyed = true;
			session.isAuthenticated = false;
			cb(null);
		},
	};
	if (opts.sid !== undefined) session.sid = opts.sid;
	return session;
}

function buildApp(opts: BuildAppOpts = {}) {
	const app = express();
	if (opts.browserSession) {
		app.use((req, _res, next) => {
			(req as unknown as { session: FakeBrowserSession }).session =
				opts.browserSession as FakeBrowserSession;
			next();
		});
	}
	const router = createRouter(express, {
		keyStore,
		issuer: "https://auth.example.com",
		userSessionStore: opts.sessionStore ?? makeSessionStore(),
		sessionRPRegistry: opts.sessionRPRegistry ?? makeSessionRPRegistry(),
		sessionFamilyIndex: opts.sessionFamilyIndex ?? makeSessionFamilyIndex(),
		sessionFederationIndex: opts.sessionFederationIndex ?? makeSessionFederationIndex(),
		refreshTokenFamilyRevocation: opts.refreshFamilyRevocation ?? makeFamilyRevocation(),
		federationTokenStore: opts.fedTokenStore ?? makeFedTokenStore(),
		clientRepository: opts.clientRepo ?? makeClientRepo(),
		getFederationProviders: opts.getFederationProviders ?? (() => undefined),
		// Stub fetchImpl so broadcast never makes real network calls
		fetchImpl: opts.fetchImpl ?? vi.fn().mockResolvedValue({ ok: true }),
		logger: opts.logger,
		auditSink: opts.auditSink,
	});
	app.use("/oauth", router);
	return app;
}

async function postLogout(
	app: ReturnType<typeof express>,
	body: Record<string, string | undefined>,
	headers: Record<string, string> = {},
) {
	const req = request(app).post("/oauth/logout").type("form");
	for (const [k, v] of Object.entries(headers)) {
		req.set(k, v);
	}
	// Only send defined values
	const filteredBody = Object.fromEntries(
		Object.entries(body).filter(([, v]) => v !== undefined),
	) as Record<string, string>;
	return req.send(filteredBody);
}

function getLogout(app: ReturnType<typeof express>, query: Record<string, string | undefined>) {
	const filteredQuery = Object.fromEntries(
		Object.entries(query).filter(([, v]) => v !== undefined),
	) as Record<string, string>;
	return request(app).get("/oauth/logout").query(filteredQuery);
}

function expectLogoutConfirmation(res: Awaited<ReturnType<typeof getLogout>>) {
	expect(res.status).toBe(200);
	expect(res.headers["content-type"]).toMatch(/^text\/html/);
	expect(res.text).toContain("<form");
	expect(res.text).toContain('method="POST"');
	// action="" submits to the current URL — avoids the relative-URL trap
	// where action="logout" on /oauth/logout/ resolves to /oauth/logout/logout.
	expect(res.text).toContain('action=""');
}

describe("POST /oauth/logout", () => {
	describe("happy path", () => {
		it("valid id_token_hint + session → cascadeLogout called, returns JSON { logged_out: true }", async () => {
			const sessionStore = makeSessionStore();
			const refreshFamilyRevocation = makeFamilyRevocation();
			const fedTokenStore = makeFedTokenStore();
			const app = buildApp({ sessionStore, refreshFamilyRevocation, fedTokenStore });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ logged_out: true });
			// cascadeLogout step 1: revokeFamily called for each familyId
			expect(refreshFamilyRevocation.revokeFamily).toHaveBeenCalledWith("fam-1");
			// cascadeLogout step 3: session deleted
			expect(sessionStore.delete).toHaveBeenCalledWith("sid-1");
			// cascadeLogout step 2: federation tokens cleared
			expect(fedTokenStore.removeBySid).toHaveBeenCalledWith("sid-1");
		});

		it("confirmed=1 form-submission shape (hint + confirmed + state) completes hint-based logout, not 400", async () => {
			// Regression: the GET confirmation page submits a POST whose body
			// includes `confirmed=1` plus the id_token_hint passed through as
			// a hidden input. Previously the form did not include the hint,
			// so the "Sign out" button always hit a 400 invalid_request. This
			// asserts the same shape the form submits today reaches the
			// hint-based logout path and returns 200.
			const sessionStore = makeSessionStore();
			const refreshFamilyRevocation = makeFamilyRevocation();
			const app = buildApp({ sessionStore, refreshFamilyRevocation });
			const token = await mintIdToken();

			const res = await postLogout(app, {
				id_token_hint: token,
				confirmed: "1",
				state: "round-trip",
			});

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ logged_out: true });
			expect(refreshFamilyRevocation.revokeFamily).toHaveBeenCalledWith("fam-1");
			expect(sessionStore.delete).toHaveBeenCalledWith("sid-1");
		});
	});

	describe("#394 dual-accept window, closed (#402)", () => {
		it("refuses a pre-#394 id_token_hint carrying typ id+jwt", async () => {
			// This is the endpoint the window existed for: an id_token already
			// in the wild loses its logout-hint value the moment the spelling
			// stops being accepted. #402's own conditions gate that — one
			// refresh-token lifetime after the release, and the legacy log line
			// gone quiet — and neither means anything for a provider with no
			// deployment behind it. There are no such id_tokens.
			const sessionStore = makeSessionStore();
			const app = buildApp({ sessionStore });
			const token = await mintIdToken({}, "id+jwt");

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(400);
			expect(sessionStore.delete).not.toHaveBeenCalled();
		});

		it("accepts the standard spelling", async () => {
			const sessionStore = makeSessionStore();
			const app = buildApp({ sessionStore });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ logged_out: true });
		});

		it("refuses at+jwt, as it always did", async () => {
			// The accepted set is back to exactly one value, and cross-type
			// confusion is refused the same way it was through the window.
			const app = buildApp({});
			const token = await mintIdToken({}, "at+jwt");

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(400);
		});
	});

	describe("session missing (defensive no-op)", () => {
		it("userSessionStore.get → null → 200 JSON, cascadeLogout NOT called", async () => {
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(null) });
			const refreshFamilyRevocation = makeFamilyRevocation();
			const app = buildApp({ sessionStore, refreshFamilyRevocation });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ logged_out: true });
			expect(refreshFamilyRevocation.revokeFamily).not.toHaveBeenCalled();
			expect(sessionStore.delete).not.toHaveBeenCalled();
		});
	});

	describe("id_token_hint invalid signature", () => {
		it("returns 400 invalid_token", async () => {
			const app = buildApp();

			const res = await postLogout(app, { id_token_hint: "not.a.valid.jwt" });

			expect(res.status).toBe(400);
			expect(res.body.error).toBe("invalid_token");
		});
	});

	describe("id_token_hint missing sid claim", () => {
		it("returns 400 invalid_request", async () => {
			const app = buildApp();
			// Mint a token without sid
			const token = await new SignJWT({ sub: "u-1", aud: "client-1" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "JWT" })
				.setIssuer("https://auth.example.com")
				.setExpirationTime("1h")
				.setIssuedAt()
				.sign(secretKey);

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(400);
			expect(res.body.error).toBe("invalid_request");
			expect(res.body.error_description).toMatch(/sid/);
		});
	});

	describe("cascadeLogout returns failed (step 1: revokeFamily throws)", () => {
		it("returns 503 temporarily_unavailable", async () => {
			const refreshFamilyRevocation = makeFamilyRevocation({
				revokeFamily: vi.fn().mockRejectedValue(new Error("redis down")),
			});
			const app = buildApp({ refreshFamilyRevocation });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(503);
			expect(res.body.error).toBe("temporarily_unavailable");
		});
	});

	describe("backchannelLogoutSessionRequired:false omits sid from logout_token", () => {
		it("RP with backchannelLogoutSessionRequired:false → fetch called without sid in logout_token", async () => {
			const capturedBodies: string[] = [];
			const fetchSpy = vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
				if (init?.body) capturedBodies.push(String(init.body));
				return { ok: true };
			});
			const rpData = [
				{
					clientId: "rp-no-sid",
					backchannelLogoutUri: "https://rp.example.com/back-logout",
					backchannelLogoutSessionRequired: false,
					registeredAt: new Date(),
				},
			];
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const sessionRPRegistry = makeSessionRPRegistry({ listRPs: vi.fn(async () => rpData) });
			const app = buildApp({ sessionStore, sessionRPRegistry, fetchImpl: fetchSpy });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(200);
			expect(fetchSpy).toHaveBeenCalledOnce();
			// The logout_token body is URL-encoded; extract and decode it
			expect(capturedBodies).toHaveLength(1);
			const params = new URLSearchParams(capturedBodies[0]);
			const logoutToken = params.get("logout_token");
			expect(logoutToken).toBeTruthy();
			if (!logoutToken) throw new Error("logout_token missing from broadcast request body");
			// Decode JWT payload (no signature verification needed — we minted it)
			const payloadBase64 = logoutToken.split(".")[1];
			const payload = JSON.parse(Buffer.from(payloadBase64, "base64url").toString("utf8"));
			// backchannelLogoutSessionRequired:false → sid MUST be absent
			expect(payload.sid).toBeUndefined();
		});
	});

	describe("front-channel HTML response", () => {
		it("Accept: text/html + session has frontchannelLogoutUri RP → 200 text/html with <iframe>", async () => {
			const rpData = [
				{
					clientId: "rp-1",
					frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
					registeredAt: new Date(),
				},
			];
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const sessionRPRegistry = makeSessionRPRegistry({ listRPs: vi.fn(async () => rpData) });
			const app = buildApp({ sessionStore, sessionRPRegistry });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token }, { Accept: "text/html" });

			expect(res.status).toBe(200);
			expect(res.headers["content-type"]).toMatch(/text\/html/);
			expect(res.text).toContain("<iframe");
			expect(res.text).toContain("rp1.example.com");
		});
	});

	describe("HTML branch open-redirect defense", () => {
		it("unregistered post_logout_redirect_uri is NOT embedded in redirect script (open redirect defense)", async () => {
			const rpData = [
				{
					clientId: "client-1",
					frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
					registeredAt: new Date(),
				},
			];
			// Client does NOT include evil.example in postLogoutRedirectUris
			const clientRepo = makeClientRepo({
				findById: vi.fn().mockResolvedValue({
					clientId: "client-1",
					allowedRedirectUris: [],
					allowedScopes: [],
					postLogoutRedirectUris: ["https://trusted.example.com/logged-out"],
				}),
			});
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const sessionRPRegistry = makeSessionRPRegistry({ listRPs: vi.fn(async () => rpData) });
			const app = buildApp({ sessionStore, sessionRPRegistry, clientRepo });
			const token = await mintIdToken();

			const res = await postLogout(
				app,
				{
					id_token_hint: token,
					post_logout_redirect_uri: "https://evil.example/steal",
				},
				{ Accept: "text/html" },
			);

			expect(res.status).toBe(200);
			expect(res.headers["content-type"]).toMatch(/text\/html/);
			// Body MUST NOT contain the attacker-controlled URL
			expect(res.text).not.toContain("evil.example");
		});

		it("registered post_logout_redirect_uri IS embedded in HTML redirect script", async () => {
			const rpData = [
				{
					clientId: "client-1",
					frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
					registeredAt: new Date(),
				},
			];
			const clientRepo = makeClientRepo({
				findById: vi.fn().mockResolvedValue({
					clientId: "client-1",
					allowedRedirectUris: [],
					allowedScopes: [],
					postLogoutRedirectUris: ["https://trusted.example.com/logged-out"],
				}),
			});
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const sessionRPRegistry = makeSessionRPRegistry({ listRPs: vi.fn(async () => rpData) });
			const app = buildApp({ sessionStore, sessionRPRegistry, clientRepo });
			const token = await mintIdToken();

			const res = await postLogout(
				app,
				{
					id_token_hint: token,
					post_logout_redirect_uri: "https://trusted.example.com/logged-out",
				},
				{ Accept: "text/html" },
			);

			expect(res.status).toBe(200);
			expect(res.headers["content-type"]).toMatch(/text\/html/);
			// The validated URI MUST appear in the page
			expect(res.text).toContain("trusted.example.com");
		});
	});

	describe("post_logout_redirect_uri in allowlist", () => {
		it("returns 303 redirect to post_logout_redirect_uri with state appended", async () => {
			const clientRepo = makeClientRepo({
				findById: vi.fn().mockResolvedValue({
					clientId: "client-1",
					allowedRedirectUris: [],
					allowedScopes: [],
					postLogoutRedirectUris: ["https://app.example.com/logged-out"],
				}),
			});
			const app = buildApp({ clientRepo });
			const token = await mintIdToken();

			const res = await postLogout(app, {
				id_token_hint: token,
				post_logout_redirect_uri: "https://app.example.com/logged-out",
				state: "csrf-abc",
			});

			expect(res.status).toBe(303);
			expect(res.headers.location).toContain("https://app.example.com/logged-out");
			expect(res.headers.location).toContain("state=csrf-abc");
		});
	});

	describe("post_logout_redirect_uri NOT in allowlist", () => {
		it("falls back to 200 JSON (no redirect)", async () => {
			const clientRepo = makeClientRepo({
				findById: vi.fn().mockResolvedValue({
					clientId: "client-1",
					allowedRedirectUris: [],
					allowedScopes: [],
					postLogoutRedirectUris: ["https://trusted.example.com/logged-out"],
				}),
			});
			const app = buildApp({ clientRepo });
			const token = await mintIdToken();

			const res = await postLogout(app, {
				id_token_hint: token,
				post_logout_redirect_uri: "https://evil.example.com/steal",
			});

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ logged_out: true });
		});
	});

	describe("federation end-session redirect", () => {
		it("session.federations has provider with endSession → 303 to mock endSession URL", async () => {
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const sessionFederationIndex = makeSessionFederationIndex({
				listFederations: vi.fn(async () => ["google"]),
			});

			const mockEndSessionUrl = new URL("https://accounts.google.com/logout?id_token_hint=x");
			const mockProvider: FederationProviderHandle & {
				endSession: (req: unknown) => Promise<{ url: URL; method: "GET" }>;
			} = {
				name: "google",
				endSession: vi.fn().mockResolvedValue({ url: mockEndSessionUrl, method: "GET" }),
			};
			const federationProviders = new Map<string, FederationProviderHandle>([
				["google", mockProvider],
			]);

			const app = buildApp({
				sessionStore,
				sessionFederationIndex,
				getFederationProviders: () => federationProviders,
			});
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(303);
			expect(res.headers.location).toContain("accounts.google.com");
			expect(mockProvider.endSession).toHaveBeenCalledOnce();
		});
	});

	describe("id_token_hint missing entirely", () => {
		it("returns 400 invalid_request", async () => {
			const app = buildApp();

			const res = await postLogout(app, {});

			expect(res.status).toBe(400);
			expect(res.body.error).toBe("invalid_request");
		});
	});

	describe("userSessionStore.get throws (fail-closed)", () => {
		it("returns 503 temporarily_unavailable when userSessionStore.get throws", async () => {
			const throwingStore = makeSessionStore({
				get: vi.fn().mockRejectedValue(new Error("redis down")),
			});
			const app = buildApp({ sessionStore: throwingStore });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(503);
			expect(res.body.error).toBe("temporarily_unavailable");
		});
	});

	describe("reverse-index pre-fetch throws (fail-closed)", () => {
		it("POST /logout returns 503 when reverse-index pre-fetch fails", async () => {
			const sessionRPRegistry = makeSessionRPRegistry({
				listRPs: vi.fn(async () => {
					throw new Error("redis down");
				}),
			});
			const app = buildApp({ sessionRPRegistry });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(503);
			expect(res.body.error).toBe("temporarily_unavailable");
		});
	});

	describe("Cache-Control / Pragma headers", () => {
		it("200 JSON success path sets Cache-Control: no-store and Pragma: no-cache", async () => {
			const app = buildApp();
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(200);
			expect(res.headers["cache-control"]).toBe("no-store");
			expect(res.headers.pragma).toBe("no-cache");
		});

		it("503 cascade failure sets Cache-Control: no-store and Pragma: no-cache", async () => {
			const refreshFamilyRevocation = makeFamilyRevocation({
				revokeFamily: vi.fn().mockRejectedValue(new Error("redis down")),
			});
			const app = buildApp({ refreshFamilyRevocation });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(503);
			expect(res.headers["cache-control"]).toBe("no-store");
			expect(res.headers.pragma).toBe("no-cache");
		});

		it("400 invalid id_token_hint sets Cache-Control: no-store and Pragma: no-cache", async () => {
			const app = buildApp();

			const res = await postLogout(app, { id_token_hint: "not.a.valid.jwt" });

			expect(res.status).toBe(400);
			expect(res.headers["cache-control"]).toBe("no-store");
			expect(res.headers.pragma).toBe("no-cache");
		});

		it("200 HTML front-channel response sets Cache-Control: no-store and Pragma: no-cache", async () => {
			const rpData = [
				{
					clientId: "rp-1",
					frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
					registeredAt: new Date(),
				},
			];
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const sessionRPRegistry = makeSessionRPRegistry({ listRPs: vi.fn(async () => rpData) });
			const app = buildApp({ sessionStore, sessionRPRegistry });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token }, { Accept: "text/html" });

			expect(res.status).toBe(200);
			expect(res.headers["cache-control"]).toBe("no-store");
			expect(res.headers.pragma).toBe("no-cache");
		});
	});

	describe("q-weighted Accept header content negotiation", () => {
		it("application/json > text/html returns JSON (not HTML)", async () => {
			const rpData = [
				{
					clientId: "rp-1",
					frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
					registeredAt: new Date(),
				},
			];
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const sessionRPRegistry = makeSessionRPRegistry({ listRPs: vi.fn(async () => rpData) });
			const app = buildApp({ sessionStore, sessionRPRegistry });
			const token = await mintIdToken();

			const res = await postLogout(
				app,
				{ id_token_hint: token },
				{ Accept: "application/json, text/html;q=0.1" },
			);

			expect(res.headers["content-type"]).toMatch(/json/);
			expect(res.body.logged_out).toBe(true);
		});

		it("Accept: */* falls back to JSON (not HTML)", async () => {
			const rpData = [
				{
					clientId: "rp-1",
					frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
					registeredAt: new Date(),
				},
			];
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const sessionRPRegistry = makeSessionRPRegistry({ listRPs: vi.fn(async () => rpData) });
			const app = buildApp({ sessionStore, sessionRPRegistry });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token }, { Accept: "*/*" });

			expect(res.headers["content-type"]).toMatch(/json/);
			expect(res.body.logged_out).toBe(true);
		});
	});

	describe("logger routing for handler-level warnings", () => {
		it("routes federation endSession failure warning to opts.logger (not console)", async () => {
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const sessionFederationIndex = makeSessionFederationIndex({
				listFederations: vi.fn(async () => ["google"]),
			});
			const throwingProvider: FederationProviderHandle & {
				endSession: () => Promise<never>;
			} = {
				name: "google",
				endSession: vi.fn().mockRejectedValue(new Error("IdP down")),
			};
			const logger = createMockLogger();
			const warnSpy = logger.warn;
			const app = buildApp({
				sessionStore,
				sessionFederationIndex,
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", throwingProvider]]),
				logger,
			});
			const token = await mintIdToken();

			const consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
			try {
				const res = await postLogout(app, { id_token_hint: token });
				// Logout still succeeds (best-effort federation end-session)
				expect(res.status).toBe(200);
				expect(warnSpy).toHaveBeenCalled();
				expect(consoleWarnSpy).not.toHaveBeenCalled();
			} finally {
				consoleWarnSpy.mockRestore();
			}
		});
	});
});

describe("GET /oauth/logout", () => {
	it("logs out and redirects to a registered post_logout_redirect_uri with state", async () => {
		const sessionStore = makeSessionStore();
		const refreshFamilyRevocation = makeFamilyRevocation();
		const fedTokenStore = makeFedTokenStore();
		const app = buildApp({
			sessionStore,
			refreshFamilyRevocation,
			fedTokenStore,
			clientRepo: makeClientRepo({
				findById: vi.fn().mockResolvedValue({
					clientId: "client-1",
					tokenEndpointAuthMethod: "client_secret_basic",
					allowedRedirectUris: ["https://example.test/cb"],
					allowedScopes: ["openid"],
					postLogoutRedirectUris: ["https://rp.example/logged-out"],
				}),
			}),
		});
		const token = await mintIdToken();

		const res = await getLogout(app, {
			id_token_hint: token,
			post_logout_redirect_uri: "https://rp.example/logged-out",
			state: "bye",
		});

		expect(res.status).toBe(303);
		expect(res.headers.location).toBe("https://rp.example/logged-out?state=bye");
		expect(refreshFamilyRevocation.revokeFamily).toHaveBeenCalledWith("fam-1");
		expect(sessionStore.delete).toHaveBeenCalledWith("sid-1");
		expect(fedTokenStore.removeBySid).toHaveBeenCalledWith("sid-1");
	});

	it("returns 400 invalid_request when id_token_hint is missing (no hint to pass through)", async () => {
		// With no id_token_hint, a confirmation page would render a "Sign out"
		// button whose POST cannot satisfy the hint requirement, so reject
		// directly rather than show a confirmation that always fails.
		const sessionStore = makeSessionStore();
		const refreshFamilyRevocation = makeFamilyRevocation();
		const app = buildApp({ sessionStore, refreshFamilyRevocation });

		const res = await getLogout(app, {
			post_logout_redirect_uri: "https://rp.example/logged-out",
		});

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_request");
		expect(refreshFamilyRevocation.revokeFamily).not.toHaveBeenCalled();
		expect(sessionStore.delete).not.toHaveBeenCalled();
	});

	it("returns 400 invalid_token when id_token_hint signature is invalid (no confirm page)", async () => {
		// Invalid-signature / iss / typ id_token_hint: the POST verifier uses
		// identical options to GET, so passing the same hint through hidden
		// inputs would render a "Sign out" button that the confirmed POST
		// can only re-fail with 400 invalid_token. Reject directly for GET
		// as well as POST.
		const sessionStore = makeSessionStore();
		const refreshFamilyRevocation = makeFamilyRevocation();
		const app = buildApp({ sessionStore, refreshFamilyRevocation });

		const res = await getLogout(app, { id_token_hint: "not.a.valid.jwt" });

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_token");
		expect(refreshFamilyRevocation.revokeFamily).not.toHaveBeenCalled();
		expect(sessionStore.delete).not.toHaveBeenCalled();
	});

	it("renders confirmation HTML and does not log out when id_token_hint iat is stale", async () => {
		const sessionStore = makeSessionStore();
		const refreshFamilyRevocation = makeFamilyRevocation();
		// Allowlist the redirect URI we will pass — exercises the round-trip
		// path and confirms the value reaches the hidden input.
		const clientRepo = makeClientRepo({
			findById: vi.fn().mockResolvedValue({
				clientId: "client-1",
				allowedRedirectUris: [],
				allowedScopes: [],
				postLogoutRedirectUris: ["https://rp.example/logged-out"],
			}),
		});
		const app = buildApp({ sessionStore, refreshFamilyRevocation, clientRepo });
		const token = await mintOldIdToken();

		const res = await getLogout(app, {
			id_token_hint: token,
			post_logout_redirect_uri: "https://rp.example/logged-out",
			state: "xyz",
		});

		expectLogoutConfirmation(res);
		// All three params must round-trip into the form so a confirmed POST
		// completes the standard hint-based logout (verification on POST has
		// no staleness check, so the same hint will succeed there).
		expect(res.text).toContain(`value="${token}"`);
		expect(res.text).toContain('name="id_token_hint"');
		expect(res.text).toContain('name="post_logout_redirect_uri"');
		expect(res.text).toContain('value="https://rp.example/logged-out"');
		expect(res.text).toContain('name="state"');
		expect(res.text).toContain('value="xyz"');
		expect(refreshFamilyRevocation.revokeFamily).not.toHaveBeenCalled();
		expect(sessionStore.delete).not.toHaveBeenCalled();
	});

	it("drops post_logout_redirect_uri from the stale-iat confirm page when not allowlisted", async () => {
		// Even though the post-cascade allowlist gate prevents an actual
		// redirect to an attacker URL, reflecting the URL into the confirm
		// page on the auth-provider origin weakens the invariant. Only
		// allowlisted URIs round-trip into the form.
		const sessionStore = makeSessionStore();
		const refreshFamilyRevocation = makeFamilyRevocation();
		const clientRepo = makeClientRepo({
			findById: vi.fn().mockResolvedValue({
				clientId: "client-1",
				allowedRedirectUris: [],
				allowedScopes: [],
				postLogoutRedirectUris: ["https://rp.example/logged-out"],
			}),
		});
		const app = buildApp({ sessionStore, refreshFamilyRevocation, clientRepo });
		const token = await mintOldIdToken();

		const res = await getLogout(app, {
			id_token_hint: token,
			post_logout_redirect_uri: "https://attacker.example/steal",
			state: "xyz",
		});

		expectLogoutConfirmation(res);
		expect(res.text).not.toContain("attacker.example");
		expect(res.text).not.toContain('name="post_logout_redirect_uri"');
		// The hint and state must still round-trip — only the redirect URI
		// is dropped.
		expect(res.text).toContain('name="id_token_hint"');
		expect(res.text).toContain('name="state"');
	});

	it("HTML-escapes hidden input values to prevent attribute injection", async () => {
		// state may carry attacker-influenced characters in the worst case;
		// the GET-confirm path echoes it into an HTML attribute so it must
		// be escaped (regression: `"` would break out of the value attr).
		const sessionStore = makeSessionStore();
		const refreshFamilyRevocation = makeFamilyRevocation();
		const app = buildApp({ sessionStore, refreshFamilyRevocation });
		const token = await mintOldIdToken();

		const res = await getLogout(app, {
			id_token_hint: token,
			state: 'evil"><script>alert(1)</script>',
		});

		expectLogoutConfirmation(res);
		expect(res.text).not.toContain('"><script>');
		expect(res.text).toContain("&quot;");
	});

	it("HTML-escapes ampersands in hidden input values (& → &amp;)", async () => {
		// Regression: the previous test only exercised the `"` escape via
		// quoted-attribute injection. State values commonly contain `&` in
		// query-encoded round-tripping, so the entity escape needs an
		// independent regression guard.
		const sessionStore = makeSessionStore();
		const refreshFamilyRevocation = makeFamilyRevocation();
		const app = buildApp({ sessionStore, refreshFamilyRevocation });
		const token = await mintOldIdToken();

		const res = await getLogout(app, {
			id_token_hint: token,
			state: "a&b=1",
		});

		expectLogoutConfirmation(res);
		expect(res.text).toContain("a&amp;b=1");
		// Raw `a&b=1` must NOT appear unescaped — a regex-bounded check
		// avoids matching the escaped form's substring.
		expect(res.text).not.toMatch(/value="a&b=1"/);
	});
});

// ---------------------------------------------------------------------------
// POST /oauth/federation/:name/logout
// ---------------------------------------------------------------------------

/** Session that has google linked (v0.5.0 shape — no derived fields) */
const sessionWithGoogle: UserSession = { ...baseSession };
const googleFederations = ["google"];

function buildFedLogoutApp(opts: BuildAppOpts = {}) {
	return buildApp({
		sessionStore: makeSessionStore({ get: vi.fn().mockResolvedValue(sessionWithGoogle) }),
		sessionFederationIndex: makeSessionFederationIndex({
			listFederations: vi.fn(async () => googleFederations),
		}),
		...opts,
	});
}

async function postFedLogout(
	app: ReturnType<typeof express>,
	name: string,
	token: string,
	body: Record<string, string> = {},
	headers: Record<string, string> = {},
) {
	const req = request(app)
		.post(`/oauth/federation/${name}/logout`)
		.type("form")
		.set("Authorization", `Bearer ${token}`);
	for (const [k, v] of Object.entries(headers)) {
		req.set(k, v);
	}
	return req.send(body);
}

describe("POST /oauth/federation/:name/logout", () => {
	describe("happy path WITH endSession capability", () => {
		it("returns 303 redirect to provider end-session URL", async () => {
			const endSessionUrl = new URL("https://accounts.google.com/o/oauth2/revoke?token=id-hint");
			const mockProvider: FederationProviderHandle & {
				endSession: (req: unknown) => Promise<{ url: URL; method: "GET" }>;
			} = {
				name: "google",
				endSession: vi.fn().mockResolvedValue({ url: endSessionUrl, method: "GET" }),
			};
			const app = buildFedLogoutApp({
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", mockProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(303);
			expect(res.headers.location).toContain("accounts.google.com");
			expect(mockProvider.endSession).toHaveBeenCalledOnce();
			expect(res.headers["cache-control"]).toBe("no-store");
		});
	});

	describe("happy path WITHOUT endSession capability", () => {
		it("returns 200 JSON { disconnected: true } when provider has no endSession method", async () => {
			const bareProvider: FederationProviderHandle = { name: "github" };
			const app = buildApp({
				sessionStore: makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) }),
				sessionFederationIndex: makeSessionFederationIndex({
					listFederations: vi.fn(async () => ["github"]),
				}),
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["github", bareProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "github", token);

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ disconnected: true });
			expect(res.headers["cache-control"]).toBe("no-store");
		});
	});

	describe("missing Authorization header", () => {
		it("returns 401 invalid_token", async () => {
			const app = buildFedLogoutApp();
			const res = await request(app).post("/oauth/federation/google/logout").type("form").send({});

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
		});
	});

	describe("wrong token type (rt+jwt)", () => {
		it("returns 401 invalid_token when typ is not at+jwt", async () => {
			const refreshToken = await new SignJWT({ sub: "u-1", sid: "sid-1", family_id: "fam-1" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setExpirationTime("1h")
				.setIssuedAt()
				.sign(secretKey);
			const app = buildFedLogoutApp();

			const res = await postFedLogout(app, "google", refreshToken);

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
		});
	});

	describe("invalid signature", () => {
		it("returns 401 invalid_token", async () => {
			const app = buildFedLogoutApp();

			const res = await postFedLogout(app, "google", "not.a.valid.jwt");

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
		});
	});

	describe("family revoked", () => {
		it("returns 401 invalid_token when isFamilyRevoked returns true", async () => {
			const refreshFamilyRevocation = makeFamilyRevocation({
				isFamilyRevoked: vi.fn().mockResolvedValue(true),
			});
			const app = buildFedLogoutApp({ refreshFamilyRevocation });
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
		});
	});

	describe("session null", () => {
		it("returns 401 invalid_token when session is not found", async () => {
			const app = buildApp({
				sessionStore: makeSessionStore({ get: vi.fn().mockResolvedValue(null) }),
			});
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
		});
	});

	describe("federation not linked", () => {
		it("returns 404 federation_not_linked when federation is absent from session", async () => {
			// sessionWithGoogle only has google, so 'github' is not linked
			const app = buildFedLogoutApp();
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "github", token);

			expect(res.status).toBe(404);
			expect(res.body.error).toBe("federation_not_linked");
		});
	});

	describe("federationTokenStore.delete throws", () => {
		it("returns 503 when delete fails after local state was partially cleared", async () => {
			const fedTokenStore = makeFedTokenStore({
				delete: vi.fn().mockRejectedValue(new Error("redis down")),
			});
			const app = buildFedLogoutApp({ fedTokenStore });
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(503);
			expect(res.body.error).toBe("temporarily_unavailable");
			expect(res.headers["cache-control"]).toBe("no-store");
		});
	});

	describe("provider.endSession throws (soft-fail)", () => {
		it("returns 200 { disconnected: true } when endSession throws (local state already cleared)", async () => {
			const throwingProvider: FederationProviderHandle & {
				endSession: () => Promise<never>;
			} = {
				name: "google",
				endSession: vi.fn().mockRejectedValue(new Error("IdP unreachable")),
			};
			const app = buildFedLogoutApp({
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", throwingProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			// Local state cleared before endSession call; soft-fail returns 200
			expect(res.status).toBe(200);
			expect(res.body).toEqual({ disconnected: true });
			expect(res.headers["cache-control"]).toBe("no-store");
		});
	});

	describe("getFederationProviders returns undefined (no federation configured)", () => {
		it("returns 200 { disconnected: true } when providers map is undefined", async () => {
			const app = buildFedLogoutApp({ getFederationProviders: () => undefined });
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ disconnected: true });
		});
	});

	describe("WWW-Authenticate header on 401 paths", () => {
		it("missing Authorization header returns WWW-Authenticate: Bearer error=invalid_token", async () => {
			const app = buildFedLogoutApp();
			const res = await request(app).post("/oauth/federation/google/logout").type("form").send({});

			expect(res.status).toBe(401);
			expect(res.headers["www-authenticate"]).toMatch(/Bearer/);
			expect(res.headers["www-authenticate"]).toMatch(/error="invalid_token"/);
		});

		it("invalid signature returns WWW-Authenticate: Bearer error=invalid_token", async () => {
			const app = buildFedLogoutApp();
			const res = await postFedLogout(app, "google", "not.a.valid.jwt");

			expect(res.status).toBe(401);
			expect(res.headers["www-authenticate"]).toMatch(/Bearer/);
			expect(res.headers["www-authenticate"]).toMatch(/error="invalid_token"/);
		});

		it("family revoked returns WWW-Authenticate: Bearer error=invalid_token", async () => {
			const refreshFamilyRevocation = makeFamilyRevocation({
				isFamilyRevoked: vi.fn().mockResolvedValue(true),
			});
			const app = buildFedLogoutApp({ refreshFamilyRevocation });
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(401);
			expect(res.headers["www-authenticate"]).toMatch(/Bearer/);
			expect(res.headers["www-authenticate"]).toMatch(/error="invalid_token"/);
		});

		it("session not found returns WWW-Authenticate: Bearer error=invalid_token", async () => {
			const app = buildApp({
				sessionStore: makeSessionStore({ get: vi.fn().mockResolvedValue(null) }),
			});
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(401);
			expect(res.headers["www-authenticate"]).toMatch(/Bearer/);
			expect(res.headers["www-authenticate"]).toMatch(/error="invalid_token"/);
		});
	});

	describe("Cache-Control / Pragma headers", () => {
		it("401 missing Bearer sets both Cache-Control: no-store and Pragma: no-cache", async () => {
			const app = buildFedLogoutApp();
			const res = await request(app).post("/oauth/federation/google/logout").type("form").send({});

			expect(res.status).toBe(401);
			expect(res.headers["cache-control"]).toBe("no-store");
			expect(res.headers.pragma).toBe("no-cache");
		});

		it("503 federationTokenStore.delete throw sets both Cache-Control: no-store and Pragma: no-cache", async () => {
			const fedTokenStore = makeFedTokenStore({
				delete: vi.fn().mockRejectedValue(new Error("redis down")),
			});
			const app = buildFedLogoutApp({ fedTokenStore });
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(503);
			expect(res.headers["cache-control"]).toBe("no-store");
			expect(res.headers.pragma).toBe("no-cache");
		});
	});

	describe("logger routing", () => {
		it("routes /federation/:name/logout failures to opts.logger (not console)", async () => {
			const logger = createMockLogger();
			const warnSpy = logger.warn;
			const fedTokenStore = makeFedTokenStore({
				delete: vi.fn().mockRejectedValue(new Error("boom")),
			});
			const app = buildFedLogoutApp({ fedTokenStore, logger });
			const token = await mintAccessToken();

			const consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
			try {
				const res = await postFedLogout(app, "google", token);
				expect(res.status).toBe(503);
				expect(warnSpy).toHaveBeenCalled();
				expect(consoleWarnSpy).not.toHaveBeenCalled();
			} finally {
				consoleWarnSpy.mockRestore();
			}
		});
	});
});

// ---------------------------------------------------------------------------
// Audit event observability
// ---------------------------------------------------------------------------

describe("audit events", () => {
	describe("federation.logout.idp_unreachable", () => {
		it("emits when provider.endSession throws (orphan IdP session)", async () => {
			const auditSink: AuditSink = {
				kind: "mock",
				record: vi.fn().mockResolvedValue(undefined),
			};
			const throwingProvider: FederationProviderHandle & { endSession: () => Promise<never> } = {
				name: "google",
				endSession: vi.fn().mockRejectedValue(new Error("IdP down")),
			};
			const app = buildFedLogoutApp({
				auditSink,
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", throwingProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(200);
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "federation.logout.idp_unreachable",
					details: expect.objectContaining({ federation: "google", error: "IdP down" }),
				}),
			);
		});
	});

	describe("federation.logout.success", () => {
		it("emits with redirected_to_idp: true when endSession succeeds (303 path)", async () => {
			const auditSink: AuditSink = {
				kind: "mock",
				record: vi.fn().mockResolvedValue(undefined),
			};
			const endSessionUrl = new URL("https://accounts.google.com/logout");
			const mockProvider: FederationProviderHandle & {
				endSession: (req: unknown) => Promise<{ url: URL; method: "GET" }>;
			} = {
				name: "google",
				endSession: vi.fn().mockResolvedValue({ url: endSessionUrl, method: "GET" }),
			};
			const app = buildFedLogoutApp({
				auditSink,
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", mockProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(303);
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "federation.logout.success",
					details: expect.objectContaining({ federation: "google", redirected_to_idp: true }),
				}),
			);
		});

		it("emits with redirected_to_idp: false when provider has no endSession (200 path)", async () => {
			const auditSink: AuditSink = {
				kind: "mock",
				record: vi.fn().mockResolvedValue(undefined),
			};
			const bareProvider: FederationProviderHandle = { name: "github" };
			const app = buildApp({
				auditSink,
				sessionStore: makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) }),
				sessionFederationIndex: makeSessionFederationIndex({
					listFederations: vi.fn(async () => ["github"]),
				}),
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["github", bareProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "github", token);

			expect(res.status).toBe(200);
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "federation.logout.success",
					details: expect.objectContaining({ federation: "github", redirected_to_idp: false }),
				}),
			);
		});
	});

	describe("logout.success", () => {
		it("emits on POST /oauth/logout happy path", async () => {
			const auditSink: AuditSink = {
				kind: "mock",
				record: vi.fn().mockResolvedValue(undefined),
			};
			const app = buildApp({ auditSink });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(200);
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "logout.success",
					details: expect.objectContaining({ sid: "sid-1" }),
				}),
			);
		});
	});

	describe("logout.cascade_failed", () => {
		it("emits on 503 cascade failure", async () => {
			const auditSink: AuditSink = {
				kind: "mock",
				record: vi.fn().mockResolvedValue(undefined),
			};
			const refreshFamilyRevocation = makeFamilyRevocation({
				revokeFamily: vi.fn().mockRejectedValue(new Error("redis down")),
			});
			const app = buildApp({ auditSink, refreshFamilyRevocation });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(503);
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "logout.cascade_failed",
					details: expect.objectContaining({ sid: "sid-1", step: 2 }),
				}),
			);
		});
	});
});

/**
 * R1a — `/oauth/logout` must end the browser session too.
 *
 * The cascade deletes the `UserSession` record, but until this fix nothing
 * touched the express-session, so the same cookie kept satisfying
 * `req.session.isAuthenticated` at `/authorize`: the browser went on minting
 * authorization codes carrying the dead `sid`, `/token` refused them with
 * `invalid_grant`, and the user sat in a login loop with no login page for up
 * to `session.maxAge`.
 *
 * Scoping is the substance of these tests: the destroy is owed to the browser
 * that OWNS the session being logged out, and to no other. An RP-initiated
 * logout arriving on some third party's cookie must leave that cookie alone.
 */
describe("POST /oauth/logout — browser session (R1a)", () => {
	it("destroys the express-session whose sid is the one being logged out", async () => {
		const browserSession = makeBrowserSession({ sid: "sid-1" });
		const sessionStore = makeSessionStore();
		const app = buildApp({ browserSession, sessionStore });
		const token = await mintIdToken();

		const res = await postLogout(app, { id_token_hint: token });

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ logged_out: true });
		expect(sessionStore.delete).toHaveBeenCalledWith("sid-1");
		expect(browserSession.destroyed).toBe(true);
		expect(browserSession.isAuthenticated).toBe(false);
	});

	it("leaves a browser session belonging to a DIFFERENT sid untouched", async () => {
		// RP-initiated logout for someone else's session, arriving on this
		// browser's cookie. Destroying it would log out an unrelated user.
		const browserSession = makeBrowserSession({ sid: "sid-other" });
		const app = buildApp({ browserSession });
		const token = await mintIdToken();

		const res = await postLogout(app, { id_token_hint: token });

		expect(res.status).toBe(200);
		expect(browserSession.destroyed).toBe(false);
		expect(browserSession.isAuthenticated).toBe(true);
	});

	it("leaves a browser session that recorded no sid untouched", async () => {
		// Without a recorded `sid` there is no evidence this cookie belongs to
		// the session being logged out, so the conservative read wins.
		const browserSession = makeBrowserSession();
		const app = buildApp({ browserSession });
		const token = await mintIdToken();

		const res = await postLogout(app, { id_token_hint: token });

		expect(res.status).toBe(200);
		expect(browserSession.destroyed).toBe(false);
	});

	it("completes normally when no session middleware is mounted at all", async () => {
		// A back-channel-only deployment carries no cookie; the destroy must be
		// a no-op rather than a TypeError on `req.session`.
		const app = buildApp();
		const token = await mintIdToken();

		const res = await postLogout(app, { id_token_hint: token });

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ logged_out: true });
	});

	it("destroys on the front-channel HTML response branch", async () => {
		const browserSession = makeBrowserSession({ sid: "sid-1" });
		const sessionRPRegistry = makeSessionRPRegistry({
			listRPs: vi.fn(async () => [
				{
					clientId: "client-1",
					frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
					registeredAt: new Date(),
				},
			]),
		});
		const app = buildApp({ browserSession, sessionRPRegistry });
		const token = await mintIdToken();

		const res = await postLogout(app, { id_token_hint: token }, { Accept: "text/html" });

		expect(res.status).toBe(200);
		expect(res.headers["content-type"]).toMatch(/text\/html/);
		expect(browserSession.destroyed).toBe(true);
	});

	it("destroys on the IdP end-session 303 branch", async () => {
		const browserSession = makeBrowserSession({ sid: "sid-1" });
		const mockProvider = {
			kind: "oidc",
			endSession: vi
				.fn()
				.mockResolvedValue({ url: new URL("https://idp.example/end"), method: "GET" }),
		} as unknown as FederationProviderHandle;
		const sessionFederationIndex = makeSessionFederationIndex({
			listFederations: vi.fn(async () => ["google"]),
		});
		const app = buildApp({
			browserSession,
			sessionFederationIndex,
			getFederationProviders: () => new Map([["google", mockProvider]]),
		});
		const token = await mintIdToken();

		const res = await postLogout(app, { id_token_hint: token });

		expect(res.status).toBe(303);
		expect(browserSession.destroyed).toBe(true);
	});

	it("destroys on the post_logout_redirect_uri 303 branch", async () => {
		const browserSession = makeBrowserSession({ sid: "sid-1" });
		const clientRepo = makeClientRepo({
			findById: vi.fn().mockResolvedValue({
				clientId: "client-1",
				allowedRedirectUris: [],
				allowedScopes: [],
				postLogoutRedirectUris: ["https://app.example.com/logged-out"],
			}),
		});
		const app = buildApp({ browserSession, clientRepo });
		const token = await mintIdToken();

		const res = await postLogout(app, {
			id_token_hint: token,
			post_logout_redirect_uri: "https://app.example.com/logged-out",
		});

		expect(res.status).toBe(303);
		expect(browserSession.destroyed).toBe(true);
	});

	it("destroys the browser session when the UserSession record is already gone", async () => {
		// The no-op branch is exactly the broken-loop state: the store entry has
		// expired or was deleted out of band while the cookie still claims to be
		// authenticated. Ending the cookie here is what unsticks the browser.
		const browserSession = makeBrowserSession({ sid: "sid-1" });
		const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(null) });
		const app = buildApp({ browserSession, sessionStore });
		const token = await mintIdToken();

		const res = await postLogout(app, { id_token_hint: token });

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ logged_out: true });
		expect(browserSession.destroyed).toBe(true);
	});

	it("a failing destroy is logged, and does not turn a successful cascade into a 5xx", async () => {
		const logger = createMockLogger();
		const browserSession = makeBrowserSession({ sid: "sid-1", destroyFails: true });
		const sessionStore = makeSessionStore();
		const app = buildApp({ browserSession, sessionStore, logger });
		const token = await mintIdToken();

		const res = await postLogout(app, { id_token_hint: token });

		// The cascade succeeded — the stores are clean and the RPs were told.
		// A cookie the store could not delete is a weaker failure than
		// reporting the whole logout as failed, which would invite a retry of
		// a cascade that already ran.
		expect(res.status).toBe(200);
		expect(res.body).toEqual({ logged_out: true });
		expect(sessionStore.delete).toHaveBeenCalledWith("sid-1");
		expect(logger.warn).toHaveBeenCalled();
	});

	it("a destroy that throws synchronously is logged, and the request still answers", async () => {
		// An adapter that validates before reaching its own callback throws
		// instead of calling back, so the promise the route awaits would never
		// settle and the request would hang. The synchronous guard is what
		// turns that into the same logged, non-fatal outcome as a callback
		// error.
		const logger = createMockLogger();
		const browserSession = makeBrowserSession({ sid: "sid-1", destroyThrows: true });
		const sessionStore = makeSessionStore();
		const app = buildApp({ browserSession, sessionStore, logger });
		const token = await mintIdToken();

		const res = await postLogout(app, { id_token_hint: token });

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ logged_out: true });
		expect(sessionStore.delete).toHaveBeenCalledWith("sid-1");
		expect(logger.warn).toHaveBeenCalled();
		expect(browserSession.destroyed).toBe(false);
	});

	it("does NOT destroy the browser session when the cascade failed", async () => {
		// A 503 invites a retry; leaving the cookie in place is what lets the
		// retry identify the same session.
		const browserSession = makeBrowserSession({ sid: "sid-1" });
		const refreshFamilyRevocation = makeFamilyRevocation({
			revokeFamily: vi.fn().mockRejectedValue(new Error("redis down")),
		});
		const app = buildApp({ browserSession, refreshFamilyRevocation });
		const token = await mintIdToken();

		const res = await postLogout(app, { id_token_hint: token });

		expect(res.status).toBe(503);
		expect(browserSession.destroyed).toBe(false);
	});
});
