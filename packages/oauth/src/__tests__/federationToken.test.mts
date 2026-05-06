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
	type AuditSinkBase,
	type ClientRepository,
	createSymmetricKeyStore,
	type FederationProviderHandle,
	type FederationTokenStoreBase,
	type Logger,
	type RefreshTokenFamilyRevocation,
	type SessionFederationIndex,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createRouter } from "#/routes/federationToken.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

/** Mint an at+jwt access token with the given extra claims. */
async function mintAccessToken(extra: Record<string, unknown> = {}): Promise<string> {
	return new SignJWT({
		sub: "u-1",
		sid: "sid-1",
		azp: "client-1",
		family_id: "fam-1",
		...extra,
	})
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
		.setExpirationTime("1h")
		.setIssuedAt()
		.setIssuer("https://auth.example.com")
		.sign(secretKey);
}

// Base session — identity fields only (federation data lives in SessionFederationIndex)
const baseSession: UserSession = {
	sid: "sid-1",
	sub: "u-1",
	authTime: new Date(),
	createdAt: new Date(),
	expiresAt: new Date(Date.now() + 3_600_000),
	claims: { email: "alice@example.com" },
};

// Base federation tokens — not expired
const baseFedTokens = {
	accessToken: "upstream-at-xyz",
	refreshToken: "upstream-rt-xyz",
	expiresAt: new Date(Date.now() + 3_600_000),
	tokenType: "Bearer",
	scope: "openid email",
};

// Client with allowedAzpForFederationToken: true
const allowedClient = {
	clientId: "client-1",
	allowedRedirectUris: [],
	allowedScopes: [],
	allowedAzpForFederationToken: true as const,
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

function makeSessionFederationIndex(
	override?: Partial<SessionFederationIndex>,
): SessionFederationIndex {
	return {
		kind: "memory",
		addFederation: vi.fn(async () => {}),
		listFederations: vi.fn(async () => ["google"]),
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

function makeFedTokenStore(override?: Partial<FederationTokenStoreBase>): FederationTokenStoreBase {
	return {
		kind: "memory",
		attach: vi.fn(),
		get: vi.fn().mockResolvedValue(baseFedTokens),
		update: vi.fn().mockResolvedValue(undefined),
		deleteBySession: vi.fn().mockResolvedValue(undefined),
		delete: vi.fn().mockResolvedValue(undefined),
		...override,
	};
}

function makeClientRepo(override?: Partial<ClientRepository>): ClientRepository {
	return {
		findById: vi.fn().mockResolvedValue(allowedClient),
		authenticate: vi.fn(),
		...override,
	};
}

interface BuildAppOpts {
	sessionStore?: UserSessionStore;
	sessionFederationIndex?: SessionFederationIndex;
	refreshFamilyRevocation?: RefreshTokenFamilyRevocation;
	fedTokenStore?: FederationTokenStoreBase;
	clientRepo?: ClientRepository;
	getFederationProviders?: () => ReadonlyMap<string, FederationProviderHandle> | undefined;
	logger?: Logger;
	auditSink?: AuditSinkBase;
	refreshBufferMs?: number;
}

function buildApp(opts: BuildAppOpts = {}) {
	const app = express();
	const router = createRouter(express, {
		keyStore,
		userSessionStore: opts.sessionStore ?? makeSessionStore(),
		sessionFederationIndex: opts.sessionFederationIndex ?? makeSessionFederationIndex(),
		refreshTokenFamilyRevocation: opts.refreshFamilyRevocation ?? makeFamilyRevocation(),
		federationTokenStore: opts.fedTokenStore ?? makeFedTokenStore(),
		clientRepository: opts.clientRepo ?? makeClientRepo(),
		getFederationProviders: opts.getFederationProviders ?? (() => undefined),
		logger: opts.logger,
		auditSink: opts.auditSink,
		refreshBufferMs: opts.refreshBufferMs,
	});
	app.use("/oauth", router);
	return app;
}

async function postFedToken(
	app: ReturnType<typeof express>,
	name: string,
	token: string,
	headers: Record<string, string> = {},
) {
	const req = request(app)
		.post(`/oauth/federation/${name}/token`)
		.set("Authorization", `Bearer ${token}`);
	for (const [k, v] of Object.entries(headers)) {
		req.set(k, v);
	}
	return req.send();
}

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

describe("POST /oauth/federation/:name/token", () => {
	describe("happy path: valid token, not expired", () => {
		it("returns 200 with upstream access_token without calling provider refresh", async () => {
			const fedTokenStore = makeFedTokenStore();
			const app = buildApp({ fedTokenStore });
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(200);
			expect(res.body.access_token).toBe("upstream-at-xyz");
			expect(res.body.token_type).toBe("Bearer");
			expect(res.body.expires_in).toBeGreaterThan(0);
			expect(res.body.scope).toBe("openid email");
			expect(res.headers["cache-control"]).toBe("no-store");
			// No provider needed — refresh should not be called
			expect(fedTokenStore.update).not.toHaveBeenCalled();
		});
	});

	describe("happy path refresh: expired token + provider supportsRefresh", () => {
		it("calls provider.refreshFederationToken, updates store, returns 200 with new token", async () => {
			// Tokens expired just now (well within the buffer)
			const expiredTokens = {
				...baseFedTokens,
				accessToken: "old-upstream-at",
				refreshToken: "upstream-rt-xyz",
				expiresAt: new Date(Date.now() - 1000),
			};
			const newExpiresAt = new Date(Date.now() + 3_600_000);
			const refreshFn = vi.fn().mockResolvedValue({
				accessToken: "new-upstream-at",
				refreshToken: "new-upstream-rt",
				expiresAt: newExpiresAt,
			});
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(expiredTokens),
			});
			const mockProvider: FederationProviderHandle & {
				refreshFederationToken: (rt: string) => Promise<{
					accessToken: string;
					refreshToken?: string;
					expiresAt: Date;
				}>;
			} = {
				name: "google",
				refreshFederationToken: refreshFn,
			};
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", mockProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(200);
			expect(res.body.access_token).toBe("new-upstream-at");
			expect(res.body.token_type).toBe("Bearer");
			expect(refreshFn).toHaveBeenCalledWith("upstream-rt-xyz");
			expect(fedTokenStore.update).toHaveBeenCalledWith(
				"sid-1",
				"google",
				expect.objectContaining({
					accessToken: "new-upstream-at",
					refreshToken: "new-upstream-rt",
				}),
			);
		});
	});

	// ---------------------------------------------------------------------------
	// 401 error paths
	// ---------------------------------------------------------------------------

	describe("missing Authorization header", () => {
		it("returns 401 invalid_token with WWW-Authenticate, Cache-Control: no-store", async () => {
			const app = buildApp();
			const res = await request(app).post("/oauth/federation/google/token").send();

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
			expect(res.headers["www-authenticate"]).toMatch(/Bearer/);
			expect(res.headers["www-authenticate"]).toMatch(/error="invalid_token"/);
			expect(res.headers["cache-control"]).toBe("no-store");
			expect(res.headers.pragma).toBe("no-cache");
		});
	});

	describe("wrong token type: rt+jwt", () => {
		it("returns 401 invalid_token", async () => {
			const rtToken = await new SignJWT({
				sub: "u-1",
				sid: "sid-1",
				azp: "client-1",
				family_id: "fam-1",
			})
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setExpirationTime("1h")
				.setIssuedAt()
				.sign(secretKey);
			const app = buildApp();

			const res = await postFedToken(app, "google", rtToken);

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
			expect(res.headers["www-authenticate"]).toMatch(/error="invalid_token"/);
		});
	});

	describe("wrong token type: id+jwt", () => {
		it("returns 401 invalid_token", async () => {
			const idToken = await new SignJWT({
				sub: "u-1",
				sid: "sid-1",
				azp: "client-1",
				family_id: "fam-1",
			})
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "id+jwt" })
				.setExpirationTime("1h")
				.setIssuedAt()
				.sign(secretKey);
			const app = buildApp();

			const res = await postFedToken(app, "google", idToken);

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
		});
	});

	describe("invalid signature", () => {
		it("returns 401 invalid_token", async () => {
			const app = buildApp();
			const res = await postFedToken(app, "google", "not.a.valid.jwt");

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
			expect(res.headers["www-authenticate"]).toMatch(/error="invalid_token"/);
		});
	});

	describe("missing family_id claim", () => {
		it("returns 401 invalid_token", async () => {
			const tokenNoFamily = await mintAccessToken({ family_id: undefined });
			const app = buildApp();
			const res = await postFedToken(app, "google", tokenNoFamily);

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
			expect(res.body.error_description).toMatch(/family_id/);
		});
	});

	describe("missing sid claim", () => {
		it("returns 401 invalid_token", async () => {
			const tokenNoSid = await mintAccessToken({ sid: undefined });
			const app = buildApp();
			const res = await postFedToken(app, "google", tokenNoSid);

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
			expect(res.body.error_description).toMatch(/sid/);
		});
	});

	describe("missing azp claim", () => {
		it("returns 401 invalid_token", async () => {
			const tokenNoAzp = await mintAccessToken({ azp: undefined });
			const app = buildApp();
			const res = await postFedToken(app, "google", tokenNoAzp);

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
			expect(res.body.error_description).toMatch(/azp/);
		});
	});

	describe("isFamilyRevoked returns true", () => {
		it("returns 401 + emits federation.token.family_revoked audit event", async () => {
			const auditSink: AuditSinkBase = {
				kind: "mock",
				record: vi.fn().mockResolvedValue(undefined),
			};
			const refreshFamilyRevocation = makeFamilyRevocation({
				isFamilyRevoked: vi.fn().mockResolvedValue(true),
			});
			const app = buildApp({ refreshFamilyRevocation, auditSink });
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
			expect(res.headers["www-authenticate"]).toMatch(/error="invalid_token"/);
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "federation.token.family_revoked",
					details: expect.objectContaining({ sid: "sid-1" }),
				}),
			);
		});
	});

	describe("isFamilyRevoked throws (fail-closed)", () => {
		it("returns 401 when revocation check throws", async () => {
			const refreshFamilyRevocation = makeFamilyRevocation({
				isFamilyRevoked: vi.fn().mockRejectedValue(new Error("redis down")),
			});
			const app = buildApp({ refreshFamilyRevocation });
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
			expect(res.body.error_description).toMatch(/revocation/);
		});
	});

	describe("userSessionStore.get → null", () => {
		it("returns 401 invalid_token", async () => {
			const sessionStore = makeSessionStore({
				get: vi.fn().mockResolvedValue(null),
			});
			const app = buildApp({ sessionStore });
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
			expect(res.body.error_description).toMatch(/session/);
		});
	});

	describe("userSessionStore.get throws", () => {
		it("returns 503 temporarily_unavailable", async () => {
			const sessionStore = makeSessionStore({
				get: vi.fn().mockRejectedValue(new Error("redis down")),
			});
			const app = buildApp({ sessionStore });
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(503);
			expect(res.body.error).toBe("temporarily_unavailable");
		});
	});

	// ---------------------------------------------------------------------------
	// 403 — client not opted in
	// ---------------------------------------------------------------------------

	describe("client.allowedAzpForFederationToken !== true", () => {
		it("returns 403 forbidden + emits federation.token.forbidden audit event", async () => {
			const auditSink: AuditSinkBase = {
				kind: "mock",
				record: vi.fn().mockResolvedValue(undefined),
			};
			const clientRepo = makeClientRepo({
				findById: vi.fn().mockResolvedValue({
					clientId: "client-1",
					allowedRedirectUris: [],
					allowedScopes: [],
					allowedAzpForFederationToken: false,
				}),
			});
			const app = buildApp({ clientRepo, auditSink });
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(403);
			expect(res.body.error).toBe("forbidden");
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "federation.token.forbidden",
					details: expect.objectContaining({ federation: "google", azp: "client-1" }),
				}),
			);
		});

		it("returns 403 when client is null (not found)", async () => {
			const clientRepo = makeClientRepo({
				findById: vi.fn().mockResolvedValue(null),
			});
			const app = buildApp({ clientRepo });
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(403);
			expect(res.body.error).toBe("forbidden");
		});
	});

	// ---------------------------------------------------------------------------
	// 404 — federation not linked / tokens missing
	// ---------------------------------------------------------------------------

	describe("federation not in sessionFederationIndex", () => {
		it("returns 404 federation_not_linked", async () => {
			// sessionFederationIndex only has 'google'; asking for 'github'
			const app = buildApp();
			const token = await mintAccessToken();

			const res = await postFedToken(app, "github", token);

			expect(res.status).toBe(404);
			expect(res.body.error).toBe("federation_not_linked");
		});
	});

	describe("federationTokenStore.get returns null (dangling link)", () => {
		it("returns 404 + calls sessionFederationIndex.removeFederation self-heal", async () => {
			const removeFederationSpy = vi.fn(async () => {});
			const sessionFederationIndex = makeSessionFederationIndex({
				listFederations: vi.fn(async () => ["google"]),
				removeFederation: removeFederationSpy,
			});
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(null),
			});
			const app = buildApp({ sessionFederationIndex, fedTokenStore });
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(404);
			expect(res.body.error).toBe("federation_not_linked");
			expect(removeFederationSpy).toHaveBeenCalledWith("sid-1", "google");
		});
	});

	// ---------------------------------------------------------------------------
	// Refresh error paths
	// ---------------------------------------------------------------------------

	describe("refresh: no refreshToken in stored federation tokens", () => {
		it("returns 410 refresh_token_absent", async () => {
			const expiredNoRt = {
				...baseFedTokens,
				refreshToken: undefined,
				expiresAt: new Date(Date.now() - 1000),
			};
			const refreshProvider: FederationProviderHandle & {
				refreshFederationToken: (rt: string) => Promise<{ accessToken: string; expiresAt: Date }>;
			} = {
				name: "google",
				refreshFederationToken: vi.fn(),
			};
			const app = buildApp({
				fedTokenStore: makeFedTokenStore({ get: vi.fn().mockResolvedValue(expiredNoRt) }),
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", refreshProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(410);
			expect(res.body.error).toBe("refresh_token_absent");
		});
	});

	describe("refresh: provider does not support refresh", () => {
		it("returns 503 refresh_not_supported", async () => {
			const expiredTokens = {
				...baseFedTokens,
				expiresAt: new Date(Date.now() - 1000),
			};
			// Provider without refreshFederationToken method
			const bareProvider: FederationProviderHandle = { name: "google" };
			const app = buildApp({
				fedTokenStore: makeFedTokenStore({ get: vi.fn().mockResolvedValue(expiredTokens) }),
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", bareProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(503);
			expect(res.body.error).toBe("refresh_not_supported");
		});
	});

	describe("refresh: provider.refreshFederationToken throws invalid_grant", () => {
		it("returns 410 re_authentication_required + cleans up + emits audit event", async () => {
			const auditSink: AuditSinkBase = {
				kind: "mock",
				record: vi.fn().mockResolvedValue(undefined),
			};
			const expiredTokens = { ...baseFedTokens, expiresAt: new Date(Date.now() - 1000) };
			const removeFederationSpy = vi.fn(async () => {});
			const sessionFederationIndex = makeSessionFederationIndex({
				listFederations: vi.fn(async () => ["google"]),
				removeFederation: removeFederationSpy,
			});
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(expiredTokens),
			});
			const failingProvider: FederationProviderHandle & {
				refreshFederationToken: (rt: string) => Promise<never>;
			} = {
				name: "google",
				refreshFederationToken: vi
					.fn()
					.mockRejectedValue(new Error("invalid_grant: token revoked")),
			};
			const app = buildApp({
				sessionFederationIndex,
				fedTokenStore,
				auditSink,
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", failingProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(410);
			expect(res.body.error).toBe("re_authentication_required");
			expect(fedTokenStore.delete).toHaveBeenCalledWith("sid-1", "google");
			expect(removeFederationSpy).toHaveBeenCalledWith("sid-1", "google");
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "federation.token.reauthentication_required",
					details: expect.objectContaining({ federation: "google" }),
				}),
			);
		});
	});

	describe("refresh: provider throws 5xx-ish error", () => {
		it("returns 503 temporarily_unavailable", async () => {
			const expiredTokens = { ...baseFedTokens, expiresAt: new Date(Date.now() - 1000) };
			const failingProvider: FederationProviderHandle & {
				refreshFederationToken: (rt: string) => Promise<never>;
			} = {
				name: "google",
				refreshFederationToken: vi
					.fn()
					.mockRejectedValue(new Error("temporarily_unavailable: provider 503")),
			};
			const app = buildApp({
				fedTokenStore: makeFedTokenStore({ get: vi.fn().mockResolvedValue(expiredTokens) }),
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", failingProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(503);
			expect(res.body.error).toBe("temporarily_unavailable");
		});
	});

	describe("refresh: provider throws generic error", () => {
		it("returns 500 refresh_failed + emits federation.token.refresh_failed audit event", async () => {
			const auditSink: AuditSinkBase = {
				kind: "mock",
				record: vi.fn().mockResolvedValue(undefined),
			};
			const expiredTokens = { ...baseFedTokens, expiresAt: new Date(Date.now() - 1000) };
			const failingProvider: FederationProviderHandle & {
				refreshFederationToken: (rt: string) => Promise<never>;
			} = {
				name: "google",
				refreshFederationToken: vi.fn().mockRejectedValue(new Error("unexpected provider error")),
			};
			const app = buildApp({
				fedTokenStore: makeFedTokenStore({ get: vi.fn().mockResolvedValue(expiredTokens) }),
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", failingProvider]]),
				auditSink,
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(500);
			expect(res.body.error).toBe("refresh_failed");
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "federation.token.refresh_failed",
					details: expect.objectContaining({
						federation: "google",
						error: "unexpected provider error",
					}),
				}),
			);
		});
	});

	// ---------------------------------------------------------------------------
	// Lock paths
	// ---------------------------------------------------------------------------

	describe("lock timeout", () => {
		it("returns 503 lock_timeout when acquireLock returns acquired: false", async () => {
			const expiredTokens = { ...baseFedTokens, expiresAt: new Date(Date.now() - 1000) };
			const lockingStore = {
				...makeFedTokenStore({ get: vi.fn().mockResolvedValue(expiredTokens) }),
				acquireLock: vi.fn().mockResolvedValue({ acquired: false, reason: "timeout" }),
			};
			const refreshProvider: FederationProviderHandle & {
				refreshFederationToken: (rt: string) => Promise<{ accessToken: string; expiresAt: Date }>;
			} = {
				name: "google",
				refreshFederationToken: vi.fn(),
			};
			const app = buildApp({
				fedTokenStore: lockingStore,
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", refreshProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(503);
			expect(res.body.error).toBe("lock_timeout");
		});
	});

	describe("concurrent refresh: second caller re-reads after lock, sees fresh token", () => {
		it("skips IdP call and returns already-refreshed token", async () => {
			const expiredTokens = { ...baseFedTokens, expiresAt: new Date(Date.now() - 1000) };
			const freshTokens = {
				...baseFedTokens,
				accessToken: "already-refreshed-at",
				expiresAt: new Date(Date.now() + 3_600_000),
			};
			const release = vi.fn().mockResolvedValue(undefined);
			// First get returns expired, second (post-lock re-read) returns fresh
			const getFn = vi.fn().mockResolvedValueOnce(expiredTokens).mockResolvedValueOnce(freshTokens);
			const lockingStore = {
				...makeFedTokenStore({ get: getFn }),
				acquireLock: vi.fn().mockResolvedValue({ acquired: true, release }),
			};
			const refreshProvider: FederationProviderHandle & {
				refreshFederationToken: (rt: string) => Promise<{ accessToken: string; expiresAt: Date }>;
			} = {
				name: "google",
				refreshFederationToken: vi.fn(),
			};
			const app = buildApp({
				fedTokenStore: lockingStore,
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", refreshProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(200);
			expect(res.body.access_token).toBe("already-refreshed-at");
			// Provider refresh must NOT be called
			expect(refreshProvider.refreshFederationToken).not.toHaveBeenCalled();
			// Lock must be released
			expect(release).toHaveBeenCalled();
		});
	});

	// ---------------------------------------------------------------------------
	// Refresh-token preservation
	// ---------------------------------------------------------------------------

	describe("preserves refresh_token when IdP doesn't rotate it", () => {
		it("stores original refreshToken when provider returns no refreshToken", async () => {
			const expiredTokens = {
				...baseFedTokens,
				expiresAt: new Date(Date.now() - 1000),
				refreshToken: "original-rt",
			};
			const newExpiresAt = new Date(Date.now() + 3_600_000);
			const refreshProvider: FederationProviderHandle & {
				refreshFederationToken: (rt: string) => Promise<{ accessToken: string; expiresAt: Date }>;
			} = {
				name: "google",
				refreshFederationToken: vi.fn().mockResolvedValue({
					accessToken: "new-at",
					// No refreshToken returned — IdP did NOT rotate
					expiresAt: newExpiresAt,
				}),
			};
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(expiredTokens),
			});
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", refreshProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(200);
			// Verify that update was called with the original refreshToken preserved
			expect(fedTokenStore.update).toHaveBeenCalledWith(
				"sid-1",
				"google",
				expect.objectContaining({
					accessToken: "new-at",
					refreshToken: "original-rt", // preserved from original
				}),
			);
		});
	});

	// ---------------------------------------------------------------------------
	// Audit event: federation.token.success
	// ---------------------------------------------------------------------------

	describe("audit event: federation.token.success on happy path", () => {
		it("emits with refreshed: false on valid non-expired token", async () => {
			const auditSink: AuditSinkBase = {
				kind: "mock",
				record: vi.fn().mockResolvedValue(undefined),
			};
			const app = buildApp({ auditSink });
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(200);
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "federation.token.success",
					details: expect.objectContaining({ federation: "google", refreshed: false }),
				}),
			);
		});

		it("emits with refreshed: true after successful provider refresh", async () => {
			const auditSink: AuditSinkBase = {
				kind: "mock",
				record: vi.fn().mockResolvedValue(undefined),
			};
			const expiredTokens = { ...baseFedTokens, expiresAt: new Date(Date.now() - 1000) };
			const refreshProvider: FederationProviderHandle & {
				refreshFederationToken: (rt: string) => Promise<{
					accessToken: string;
					refreshToken?: string;
					expiresAt: Date;
				}>;
			} = {
				name: "google",
				refreshFederationToken: vi.fn().mockResolvedValue({
					accessToken: "new-at",
					expiresAt: new Date(Date.now() + 3_600_000),
				}),
			};
			const app = buildApp({
				fedTokenStore: makeFedTokenStore({ get: vi.fn().mockResolvedValue(expiredTokens) }),
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", refreshProvider]]),
				auditSink,
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(200);
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "federation.token.success",
					details: expect.objectContaining({ federation: "google", refreshed: true }),
				}),
			);
		});
	});

	// ---------------------------------------------------------------------------
	// Fix 1 regression: post-lock re-read currentTokens.refreshToken used (Codex P2)
	// ---------------------------------------------------------------------------

	describe("post-lock refresh uses currentTokens.refreshToken (Codex P2 regression)", () => {
		it("calls refreshFederationToken with the FRESH refresh_token read after lock, not the pre-lock stale one", async () => {
			const staleRefreshToken = "stale-rt-pre-lock";
			const freshRefreshToken = "fresh-rt-post-lock";

			// Pre-lock get: stale tokens with expired access_token
			const staleTokens = {
				...baseFedTokens,
				refreshToken: staleRefreshToken,
				expiresAt: new Date(Date.now() - 1000),
			};
			// Post-lock re-read: fresh tokens that are still within the 30s buffer
			// (expiresAt is 10s from now — less than the default 30s buffer)
			// so code still falls into the refresh branch
			const freshTokensWithinBuffer = {
				...baseFedTokens,
				accessToken: "fresh-at-still-expiring",
				refreshToken: freshRefreshToken,
				expiresAt: new Date(Date.now() + 10_000), // 10s — inside the 30s buffer
			};

			const release = vi.fn().mockResolvedValue(undefined);
			const getFn = vi
				.fn()
				.mockResolvedValueOnce(staleTokens) // pre-lock read
				.mockResolvedValueOnce(freshTokensWithinBuffer); // post-lock re-read

			const lockingStore = {
				...makeFedTokenStore({ get: getFn }),
				acquireLock: vi.fn().mockResolvedValue({ acquired: true, release }),
			};

			const newExpiresAt = new Date(Date.now() + 3_600_000);
			const refreshFn = vi.fn().mockResolvedValue({
				accessToken: "brand-new-at",
				refreshToken: "brand-new-rt",
				expiresAt: newExpiresAt,
			});
			const refreshProvider: FederationProviderHandle & {
				refreshFederationToken: (rt: string) => Promise<{
					accessToken: string;
					refreshToken?: string;
					expiresAt: Date;
				}>;
			} = {
				name: "google",
				refreshFederationToken: refreshFn,
			};

			const app = buildApp({
				fedTokenStore: lockingStore,
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", refreshProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(200);
			// The critical assertion: must use the FRESH refresh_token from post-lock re-read
			expect(refreshFn).toHaveBeenCalledWith(freshRefreshToken);
			expect(refreshFn).not.toHaveBeenCalledWith(staleRefreshToken);
			expect(release).toHaveBeenCalled();
		});
	});

	// ---------------------------------------------------------------------------
	// Fix 2: preserve stored id_token when IdP omits it on refresh (Claude I1)
	// ---------------------------------------------------------------------------

	describe("preserves stored id_token when IdP omits it on refresh (Claude I1)", () => {
		it("stores original idToken when provider.refreshFederationToken returns no idToken", async () => {
			const storedIdToken = "stored-id-token-for-logout-hint";
			const expiredTokens = {
				...baseFedTokens,
				expiresAt: new Date(Date.now() - 1000),
				idToken: storedIdToken,
			};
			const newExpiresAt = new Date(Date.now() + 3_600_000);
			const refreshProvider: FederationProviderHandle & {
				refreshFederationToken: (rt: string) => Promise<{
					accessToken: string;
					refreshToken?: string;
					expiresAt: Date;
				}>;
			} = {
				name: "google",
				refreshFederationToken: vi.fn().mockResolvedValue({
					accessToken: "new-at",
					refreshToken: "new-rt",
					// idToken deliberately absent — Google-style refresh
					expiresAt: newExpiresAt,
				}),
			};
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(expiredTokens),
			});
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", refreshProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(200);
			// Stored idToken must be preserved, not overwritten with undefined
			expect(fedTokenStore.update).toHaveBeenCalledWith(
				"sid-1",
				"google",
				expect.objectContaining({
					accessToken: "new-at",
					idToken: storedIdToken,
				}),
			);
		});
	});

	// ---------------------------------------------------------------------------
	// Logger routing
	// ---------------------------------------------------------------------------

	describe("logger routing", () => {
		it("routes failures to opts.logger, not console", async () => {
			const logger = createMockLogger();
			const warnSpy = logger.warn;
			const sessionStore = makeSessionStore({
				get: vi.fn().mockRejectedValue(new Error("redis down")),
			});
			const app = buildApp({ sessionStore, logger });
			const token = await mintAccessToken();

			const consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
			try {
				const res = await postFedToken(app, "google", token);
				expect(res.status).toBe(503);
				expect(warnSpy).toHaveBeenCalled();
				expect(consoleWarnSpy).not.toHaveBeenCalled();
			} finally {
				consoleWarnSpy.mockRestore();
			}
		});
	});

	// ---------------------------------------------------------------------------
	// A4 §6.2 Step 1: sessionFederationIndex.listFederations failure → 503
	// ---------------------------------------------------------------------------

	describe("sessionFederationIndex.listFederations throws (fail-closed)", () => {
		it("returns 503 temporarily_unavailable when federation index read fails", async () => {
			const sessionFederationIndex = makeSessionFederationIndex({
				listFederations: vi.fn().mockRejectedValue(new Error("redis down")),
			});
			const app = buildApp({ sessionFederationIndex });
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(503);
			expect(res.body.error).toBe("temporarily_unavailable");
		});
	});
});
