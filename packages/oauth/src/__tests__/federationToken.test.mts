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

function makeFedTokenStore(override?: Partial<FederationTokenStore>): FederationTokenStore {
	return {
		kind: "memory",
		attach: vi.fn(),
		get: vi.fn().mockResolvedValue(baseFedTokens),
		update: vi.fn().mockResolvedValue(undefined),
		removeBySid: vi.fn().mockResolvedValue(undefined),
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
	fedTokenStore?: FederationTokenStore;
	clientRepo?: ClientRepository;
	getFederationProviders?: () => ReadonlyMap<string, FederationProviderHandle> | undefined;
	logger?: Logger;
	auditSink?: AuditSink;
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
		it("calls provider.refreshToken, updates store, returns 200 with new token", async () => {
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
				refreshToken: (rt: string) => Promise<{
					accessToken: string;
					refreshToken?: string;
					expiresAt: Date;
				}>;
			} = {
				name: "google",
				refreshToken: refreshFn,
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
			const auditSink: AuditSink = {
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
			const auditSink: AuditSink = {
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
				refreshToken: (rt: string) => Promise<{ accessToken: string; expiresAt: Date }>;
			} = {
				name: "google",
				refreshToken: vi.fn(),
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
			// Provider without refreshToken method
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

	describe("refresh: provider.refreshToken throws invalid_grant", () => {
		it("returns 410 re_authentication_required + cleans up + emits audit event", async () => {
			const auditSink: AuditSink = {
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
				refreshToken: (rt: string) => Promise<never>;
			} = {
				name: "google",
				refreshToken: vi.fn().mockRejectedValue(new Error("invalid_grant: token revoked")),
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
				refreshToken: (rt: string) => Promise<never>;
			} = {
				name: "google",
				refreshToken: vi.fn().mockRejectedValue(new Error("temporarily_unavailable: provider 503")),
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
			const auditSink: AuditSink = {
				kind: "mock",
				record: vi.fn().mockResolvedValue(undefined),
			};
			const expiredTokens = { ...baseFedTokens, expiresAt: new Date(Date.now() - 1000) };
			const failingProvider: FederationProviderHandle & {
				refreshToken: (rt: string) => Promise<never>;
			} = {
				name: "google",
				refreshToken: vi.fn().mockRejectedValue(new Error("unexpected provider error")),
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
			// SF-13: audit details now carry the classifier reason (not the raw message)
			// so SIEM rules can group on a stable enum. `"unexpected provider error"` is
			// neither an OAuth-defined error code nor a 5xx-shaped string, so the helper
			// classifies it as "unknown".
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "federation.token.refresh_failed",
					details: expect.objectContaining({
						federation: "google",
						reason: "unknown",
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
				refreshToken: (rt: string) => Promise<{ accessToken: string; expiresAt: Date }>;
			} = {
				name: "google",
				refreshToken: vi.fn(),
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
				refreshToken: (rt: string) => Promise<{ accessToken: string; expiresAt: Date }>;
			} = {
				name: "google",
				refreshToken: vi.fn(),
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
			expect(refreshProvider.refreshToken).not.toHaveBeenCalled();
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
				refreshToken: (rt: string) => Promise<{ accessToken: string; expiresAt: Date }>;
			} = {
				name: "google",
				refreshToken: vi.fn().mockResolvedValue({
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
			const auditSink: AuditSink = {
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
			const auditSink: AuditSink = {
				kind: "mock",
				record: vi.fn().mockResolvedValue(undefined),
			};
			const expiredTokens = { ...baseFedTokens, expiresAt: new Date(Date.now() - 1000) };
			const refreshProvider: FederationProviderHandle & {
				refreshToken: (rt: string) => Promise<{
					accessToken: string;
					refreshToken?: string;
					expiresAt: Date;
				}>;
			} = {
				name: "google",
				refreshToken: vi.fn().mockResolvedValue({
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
		it("calls refreshToken with the FRESH refresh_token read after lock, not the pre-lock stale one", async () => {
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
				refreshToken: (rt: string) => Promise<{
					accessToken: string;
					refreshToken?: string;
					expiresAt: Date;
				}>;
			} = {
				name: "google",
				refreshToken: refreshFn,
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
		it("stores original idToken when provider.refreshToken returns no idToken", async () => {
			const storedIdToken = "stored-id-token-for-logout-hint";
			const expiredTokens = {
				...baseFedTokens,
				expiresAt: new Date(Date.now() - 1000),
				idToken: storedIdToken,
			};
			const newExpiresAt = new Date(Date.now() + 3_600_000);
			const refreshProvider: FederationProviderHandle & {
				refreshToken: (rt: string) => Promise<{
					accessToken: string;
					refreshToken?: string;
					expiresAt: Date;
				}>;
			} = {
				name: "google",
				refreshToken: vi.fn().mockResolvedValue({
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

	// ---------------------------------------------------------------------------
	// D-8 regression marker: published SupportsRefresh interface uses
	// `refreshToken` (NOT `refreshFederationToken` — the broken name pre-rename
	// at v0.5.0). Real providers (e.g. federation-google) follow the published
	// name. Pre-rename the route's duck-type guard probed the wrong identifier
	// and every refresh request returned 503 `refresh_not_supported` in
	// production.
	//
	// This is a sanity-check regression marker, not a full structural lock.
	// The mock provider's shape mirrors whatever method name the route probes,
	// so a future "wrong-rename" of the route would fail this test only via
	// the same mechanism as the pre-existing happy-path test above. A stronger
	// anchor (a compile-time type assertion that the route's local
	// `SupportsRefreshShape` is structurally compatible with the published
	// `@o3co/auth-provider-session` `SupportsRefresh`) would require importing
	// session in oauth tests, crossing the package independence boundary
	// stated at federationToken.mts:40-41. Deferred to a follow-up spec.
	// ---------------------------------------------------------------------------

	describe("D-8 regression: route detects provider.refreshToken (published interface name)", () => {
		it("succeeds with 200 when provider exposes refreshToken (real-provider shape)", async () => {
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
			// Mock provider exposes `refreshToken` per the published SupportsRefresh
			// interface — exactly what `federation-google/src/google.mts` ships.
			const realShapeProvider: FederationProviderHandle & {
				refreshToken: (rt: string) => Promise<{
					accessToken: string;
					refreshToken?: string;
					expiresAt: Date;
				}>;
			} = {
				name: "google",
				refreshToken: refreshFn,
			};
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", realShapeProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(200);
			expect(res.body.access_token).toBe("new-upstream-at");
			expect(refreshFn).toHaveBeenCalledWith("upstream-rt-xyz");
		});
	});

	// ---------------------------------------------------------------------------
	// SF-12 — post-lock RT guard (replaces ??"" fallback)
	// ---------------------------------------------------------------------------

	describe("SF-12: post-lock refresh-token guard", () => {
		// SF-12 characterization test (NOT a true RED — pre-fix `?? ""` fallback is not
		// triggered when currentTokens.refreshToken is truthy, so this assertion passes
		// both pre- and post-fix). Kept as a regression guard against a future refactor
		// that drops `currentTokens` and reaches for `freshTokens.refreshToken ?? ""`. The
		// next two tests are the actual RED guards for SF-12.
		it('passes the real refresh_token to provider.refreshToken (no ?? "" fallback)', async () => {
			const expiredTokens = { ...baseFedTokens, expiresAt: new Date(Date.now() - 1000) };
			const refreshFn = vi.fn().mockResolvedValue({
				accessToken: "new-at",
				refreshToken: "new-rt",
				expiresAt: new Date(Date.now() + 3_600_000),
			});
			const refreshProvider: FederationProviderHandle & {
				refreshToken: typeof refreshFn;
			} = { name: "google", refreshToken: refreshFn };
			const app = buildApp({
				fedTokenStore: makeFedTokenStore({ get: vi.fn().mockResolvedValue(expiredTokens) }),
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", refreshProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(200);
			expect(refreshFn).toHaveBeenCalledOnce();
			expect(refreshFn).toHaveBeenCalledWith("upstream-rt-xyz");
			expect(refreshFn).not.toHaveBeenCalledWith("");
		});

		// SF-12 RED-2: post-lock re-read returns FederationTokens record with refreshToken: undefined.
		// Pre-fix: the code falls through to `provider.refreshToken("")` which the IdP rejects with
		// some 4xx → mapped via SF-13 string-match to 500 refresh_failed. Post-fix: a dedicated guard
		// fires BEFORE the IdP call and returns 410 refresh_token_absent.
		it("returns 410 refresh_token_absent when post-lock re-read has no refreshToken", async () => {
			const expiredTokens = { ...baseFedTokens, expiresAt: new Date(Date.now() - 1000) };
			// Post-lock re-read is still expired but missing refreshToken (e.g. concurrent revoke
			// stripped it; or the IdP issued a token set without RT and the store records that).
			const postLockTokens = {
				...baseFedTokens,
				refreshToken: undefined as string | undefined,
				expiresAt: new Date(Date.now() - 1000),
			};
			const release = vi.fn().mockResolvedValue(undefined);
			const getFn = vi
				.fn()
				.mockResolvedValueOnce(expiredTokens) // pre-lock read
				.mockResolvedValueOnce(postLockTokens); // post-lock re-read
			const lockingStore = {
				...makeFedTokenStore({ get: getFn }),
				acquireLock: vi.fn().mockResolvedValue({ acquired: true, release }),
			};
			const refreshFn = vi.fn();
			const refreshProvider: FederationProviderHandle & {
				refreshToken: typeof refreshFn;
			} = { name: "google", refreshToken: refreshFn };
			const app = buildApp({
				fedTokenStore: lockingStore,
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", refreshProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(410);
			expect(res.body.error).toBe("refresh_token_absent");
		});

		// SF-12 RED-3: with the post-lock guard firing, the provider must NOT be called.
		// Spy assertion catches the regression where the guard exists but the IdP call still
		// happens (e.g. the guard branches on `tokens.refreshToken` instead of `currentTokens.refreshToken`).
		it("does not call provider.refreshToken when post-lock guard fires", async () => {
			const expiredTokens = { ...baseFedTokens, expiresAt: new Date(Date.now() - 1000) };
			const postLockTokens = {
				...baseFedTokens,
				refreshToken: undefined as string | undefined,
				expiresAt: new Date(Date.now() - 1000),
			};
			const release = vi.fn().mockResolvedValue(undefined);
			const getFn = vi
				.fn()
				.mockResolvedValueOnce(expiredTokens)
				.mockResolvedValueOnce(postLockTokens);
			const lockingStore = {
				...makeFedTokenStore({ get: getFn }),
				acquireLock: vi.fn().mockResolvedValue({ acquired: true, release }),
			};
			const refreshFn = vi.fn();
			const refreshProvider: FederationProviderHandle & {
				refreshToken: typeof refreshFn;
			} = { name: "google", refreshToken: refreshFn };
			const app = buildApp({
				fedTokenStore: lockingStore,
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", refreshProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(410);
			expect(refreshFn).not.toHaveBeenCalled();
		});
	});

	// ---------------------------------------------------------------------------
	// SF-13 — Structured error classification (replaces fragile string match)
	// ---------------------------------------------------------------------------

	describe("SF-13: structured error classification", () => {
		// Helper: build a refresh-failure path with a custom error object the helper must classify.
		function buildRefreshFailure(error: unknown, opts: { auditSink?: AuditSink } = {}) {
			const expiredTokens = { ...baseFedTokens, expiresAt: new Date(Date.now() - 1000) };
			const refreshFn = vi.fn().mockRejectedValue(error);
			const refreshProvider: FederationProviderHandle & {
				refreshToken: typeof refreshFn;
			} = { name: "google", refreshToken: refreshFn };
			return buildApp({
				fedTokenStore: makeFedTokenStore({ get: vi.fn().mockResolvedValue(expiredTokens) }),
				getFederationProviders: () =>
					new Map<string, FederationProviderHandle>([["google", refreshProvider]]),
				auditSink: opts.auditSink,
			});
		}

		// SF-13 RED-1: openid-client v6 throws errors with structured `{ error: "invalid_grant" }`
		// — the message may be a generic OAuth wrapper without "invalid_grant" substring. Pre-fix
		// the string match misses this and falls through to 500. Post-fix the helper inspects
		// `.error` and classifies as invalid_grant → 410.
		it("returns 410 when provider throws structured { error: 'invalid_grant' } without message match", async () => {
			const providerError = Object.assign(new Error("OAuth provider rejected refresh"), {
				error: "invalid_grant",
			});
			const app = buildRefreshFailure(providerError);
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(410);
			expect(res.body.error).toBe("re_authentication_required");
		});

		// SF-13 RED-2: OIDC §5.2.2 error code "invalid_token" — RFC 6750 §3.1 also defines this for
		// resource access. When an upstream returns invalid_token on refresh (treat-as-revoked
		// signal from some IdPs), map to invalid_grant cleanup path so the user re-authenticates.
		it("returns 410 when provider throws structured { error: 'invalid_token' }", async () => {
			const providerError = Object.assign(new Error("token rejected"), {
				error: "invalid_token",
			});
			const app = buildRefreshFailure(providerError);
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(410);
			expect(res.body.error).toBe("re_authentication_required");
		});

		// SF-13 RED-3: rate-limited (429). Pre-fix: 500 generic. Post-fix: 429 rate_limited so
		// callers can implement Retry-After / exponential backoff at a higher tier.
		it("returns 429 rate_limited when provider throws { status: 429 }", async () => {
			const providerError = Object.assign(new Error("rate limit hit"), { status: 429 });
			const app = buildRefreshFailure(providerError);
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(429);
			expect(res.body.error).toBe("rate_limited");
		});

		// SF-13 RED-3b (Round 1 Claude Minor): the helper also classifies on `.error ===
		// "too_many_requests"` (RFC 6585 §4 status name echoed back by some IdPs in the
		// OAuth `error` field). Without this branch the only path to `rate_limited` is
		// the HTTP status — IdPs that surface the rate-limit signal only on `.error`
		// would fall through to `unknown` → 500.
		it("returns 429 rate_limited when provider throws { error: 'too_many_requests' }", async () => {
			const providerError = Object.assign(new Error("rate limit hit"), {
				error: "too_many_requests",
			});
			const app = buildRefreshFailure(providerError);
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(429);
			expect(res.body.error).toBe("rate_limited");
		});

		// SF-13 RED-4: structured 5xx via `.status` (openid-client surfaces upstream HTTP code
		// here even when the message doesn't contain it). Pre-fix: 500 generic (no /5\d\d/ match
		// when the message is just "service down"). Post-fix: 503 temporarily_unavailable.
		it("returns 503 temporarily_unavailable when provider throws { status: 503 } without message match", async () => {
			const providerError = Object.assign(new Error("service down"), { status: 503 });
			const app = buildRefreshFailure(providerError);
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(503);
			expect(res.body.error).toBe("temporarily_unavailable");
		});

		// SF-13 RED-5: Node's network error codes propagate as `.code` (ECONNREFUSED / ENOTFOUND
		// / ETIMEDOUT) — these are upstream-network failures, not OAuth grant rejections. Pre-fix:
		// 500. Post-fix: 503.
		it("returns 503 when provider throws { code: 'ECONNREFUSED' }", async () => {
			const providerError = Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:443"), {
				code: "ECONNREFUSED",
			});
			const app = buildRefreshFailure(providerError);
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(503);
			expect(res.body.error).toBe("temporarily_unavailable");
		});

		// SF-13 RED-5b (Round 1 Codex Important): Node/undici fetch failures are thrown as
		// `TypeError("fetch failed")` with the actual network code on `.cause.code`, not on
		// `.code`. openid-client v6 rethrows these as-is. Without walking the cause chain
		// the helper would classify these as `unknown` → 500, defeating SF-13's intent that
		// network failures return 503.
		it("returns 503 when provider throws TypeError with cause.code = 'ENOTFOUND'", async () => {
			const providerError = Object.assign(new TypeError("fetch failed"), {
				cause: { code: "ENOTFOUND" },
			});
			const app = buildRefreshFailure(providerError);
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(503);
			expect(res.body.error).toBe("temporarily_unavailable");
		});

		// SF-13 RED-6: defense-in-depth string fallback still works for legacy / non-openid-client
		// errors that only carry the OAuth code in the message. Confirms we did not regress the
		// existing behavior when removing the fragile path.
		it("returns 410 from string fallback when error.message contains invalid_grant", async () => {
			const providerError = new Error("400 invalid_grant: token revoked");
			const app = buildRefreshFailure(providerError);
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(410);
			expect(res.body.error).toBe("re_authentication_required");
		});

		// SF-13 RED-7: unknown / non-OAuth error → 500 + audit emit with reason in details. Pre-fix
		// the audit details capture the message string; post-fix they capture the helper's
		// classification reason ("unknown") so SIEM can group.
		it("returns 500 refresh_failed and emits audit event with reason='unknown' for unrecognized errors", async () => {
			const auditSink: AuditSink = {
				kind: "mock",
				record: vi.fn().mockResolvedValue(undefined),
			};
			const providerError = new Error("internal-bug-stack-trace");
			const app = buildRefreshFailure(providerError, { auditSink });
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(500);
			expect(res.body.error).toBe("refresh_failed");
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "federation.token.refresh_failed",
					details: expect.objectContaining({
						federation: "google",
						reason: "unknown",
					}),
				}),
			);
		});
	});
});
