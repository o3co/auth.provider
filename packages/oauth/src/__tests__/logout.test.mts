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
	type ClientRepository,
	createSymmetricKeyStore,
	type FederationProviderHandle,
	type FederationTokenStoreBase,
	type Logger,
	type RefreshTokenStoreBase,
	type UserSession,
	type UserSessionStoreBase,
} from "@o3co/auth-provider-core";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createRouter } from "#/routes/logout.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

/** Mint an id_token with the given claims. */
async function mintIdToken(extra: Record<string, unknown> = {}): Promise<string> {
	return new SignJWT({
		sub: "u-1",
		aud: "client-1",
		sid: "sid-1",
		...extra,
	})
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "JWT" })
		.setExpirationTime("1h")
		.setIssuedAt()
		.setIssuer("https://auth.example.com")
		.sign(secretKey);
}

// A minimal valid UserSession with no federations (simplifies most test cases)
const baseSession: UserSession = {
	sid: "sid-1",
	sub: "u-1",
	authTime: new Date(),
	createdAt: new Date(),
	expiresAt: new Date(Date.now() + 3_600_000),
	federations: [],
	activeRPs: [],
	familyIds: ["fam-1"],
	claims: { email: "alice@example.com" },
};

function makeSessionStore(override?: Partial<UserSessionStoreBase>): UserSessionStoreBase {
	return {
		kind: "memory",
		create: vi.fn(),
		get: vi.fn().mockResolvedValue(baseSession),
		registerRP: vi.fn(),
		linkFamily: vi.fn(),
		updateClaims: vi.fn(),
		removeFederation: vi.fn(),
		delete: vi.fn(),
		...override,
	};
}

function makeRefreshStore(override?: Partial<RefreshTokenStoreBase>): RefreshTokenStoreBase {
	return {
		kind: "memory",
		isFamilyRevoked: vi.fn().mockResolvedValue(false),
		rotate: vi.fn(),
		revokeFamily: vi.fn().mockResolvedValue(undefined),
		...override,
	};
}

function makeFedTokenStore(override?: Partial<FederationTokenStoreBase>): FederationTokenStoreBase {
	return {
		kind: "memory",
		attach: vi.fn(),
		get: vi.fn().mockResolvedValue(null),
		update: vi.fn(),
		deleteBySession: vi.fn().mockResolvedValue(undefined),
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
	sessionStore?: UserSessionStoreBase;
	refreshStore?: RefreshTokenStoreBase;
	fedTokenStore?: FederationTokenStoreBase;
	clientRepo?: ClientRepository;
	/** Getter for federation providers — evaluated at request time. */
	getFederationProviders?: () => ReadonlyMap<string, FederationProviderHandle> | undefined;
	logger?: Logger;
}

function buildApp(opts: BuildAppOpts = {}) {
	const app = express();
	const router = createRouter(express, {
		keyStore,
		issuer: "https://auth.example.com",
		userSessionStore: opts.sessionStore ?? makeSessionStore(),
		refreshTokenStore: opts.refreshStore ?? makeRefreshStore(),
		federationTokenStore: opts.fedTokenStore ?? makeFedTokenStore(),
		clientRepository: opts.clientRepo ?? makeClientRepo(),
		getFederationProviders: opts.getFederationProviders ?? (() => undefined),
		// Stub fetchImpl so broadcast never makes real network calls
		fetchImpl: vi.fn().mockResolvedValue({ ok: true }),
		logger: opts.logger,
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

describe("POST /oauth/logout", () => {
	describe("happy path", () => {
		it("valid id_token_hint + session → cascadeLogout called, returns JSON { logged_out: true }", async () => {
			const sessionStore = makeSessionStore();
			const refreshStore = makeRefreshStore();
			const fedTokenStore = makeFedTokenStore();
			const app = buildApp({ sessionStore, refreshStore, fedTokenStore });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ logged_out: true });
			// cascadeLogout step 1: revokeFamily called for each familyId
			expect(refreshStore.revokeFamily).toHaveBeenCalledWith("fam-1");
			// cascadeLogout step 3: session deleted
			expect(sessionStore.delete).toHaveBeenCalledWith("sid-1");
			// cascadeLogout step 2: federation tokens cleared
			expect(fedTokenStore.deleteBySession).toHaveBeenCalledWith("sid-1");
		});
	});

	describe("session missing (defensive no-op)", () => {
		it("userSessionStore.get → null → 200 JSON, cascadeLogout NOT called", async () => {
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(null) });
			const refreshStore = makeRefreshStore();
			const app = buildApp({ sessionStore, refreshStore });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ logged_out: true });
			expect(refreshStore.revokeFamily).not.toHaveBeenCalled();
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
			const refreshStore = makeRefreshStore({
				revokeFamily: vi.fn().mockRejectedValue(new Error("redis down")),
			});
			const app = buildApp({ refreshStore });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(503);
			expect(res.body.error).toBe("temporarily_unavailable");
		});
	});

	describe("front-channel HTML response", () => {
		it("Accept: text/html + session has frontchannelLogoutUri RP → 200 text/html with <iframe>", async () => {
			const sessionWithRP: UserSession = {
				...baseSession,
				activeRPs: [
					{
						clientId: "rp-1",
						frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
						registeredAt: new Date(),
					},
				],
			};
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(sessionWithRP) });
			const app = buildApp({ sessionStore });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token }, { Accept: "text/html" });

			expect(res.status).toBe(200);
			expect(res.headers["content-type"]).toMatch(/text\/html/);
			expect(res.text).toContain("<iframe");
			expect(res.text).toContain("rp1.example.com");
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
			const sessionWithFed: UserSession = {
				...baseSession,
				federations: ["google"],
			};
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(sessionWithFed) });

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

			const app = buildApp({ sessionStore, getFederationProviders: () => federationProviders });
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

	describe("q-weighted Accept header content negotiation", () => {
		it("application/json > text/html returns JSON (not HTML)", async () => {
			const sessionWithRP: UserSession = {
				...baseSession,
				activeRPs: [
					{
						clientId: "rp-1",
						frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
						registeredAt: new Date(),
					},
				],
			};
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(sessionWithRP) });
			const app = buildApp({ sessionStore });
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
			const sessionWithRP: UserSession = {
				...baseSession,
				activeRPs: [
					{
						clientId: "rp-1",
						frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
						registeredAt: new Date(),
					},
				],
			};
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(sessionWithRP) });
			const app = buildApp({ sessionStore });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token }, { Accept: "*/*" });

			expect(res.headers["content-type"]).toMatch(/json/);
			expect(res.body.logged_out).toBe(true);
		});
	});

	describe("logger routing for handler-level warnings", () => {
		it("routes federation endSession failure warning to opts.logger (not console)", async () => {
			const sessionWithFed: UserSession = {
				...baseSession,
				federations: ["google"],
			};
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(sessionWithFed) });
			const throwingProvider: FederationProviderHandle & {
				endSession: () => Promise<never>;
			} = {
				name: "google",
				endSession: vi.fn().mockRejectedValue(new Error("IdP down")),
			};
			const warnSpy = vi.fn<(message: string, ...args: unknown[]) => void>();
			const logger: Logger = { warn: warnSpy };
			const app = buildApp({
				sessionStore,
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
