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
	type FederationProvider,
	type FederationTokenStore,
	type FederationTokens,
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
import {
	expectBestEffortWarn,
	expectOutageLine,
	REFUSED_COMMAND_MARKER,
	serialisedCalls,
	storeReplyError,
} from "./_helpers/projectedLog.mjs";

/**
 * A federation that satisfies the contract, with whatever capability the case
 * under test adds. Since #626 P1 `federationProviders` carries
 * `FederationProvider` rather than a one-field stand-in, so a mock has to be
 * one — which is the point: these routes read a provider the boot planner
 * could actually have handed them.
 */
const federationBase = (name: string) => ({
	name,
	scope: ["openid"] as readonly string[],
	buildAuthorizationUrl: () => new URL(`https://${name}.example/auth`),
	exchangeCode: async () => ({
		issuer: `https://${name}.example`,
		sub: "sub-1",
		expiresAt: null,
	}),
});

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
	amr: undefined,
};

// Base federation tokens — not expired. A stored record, so every key is named.
const baseFedTokens: FederationTokens = {
	accessToken: "upstream-at-xyz",
	refreshToken: "upstream-rt-xyz",
	idToken: undefined,
	expiresAt: new Date(Date.now() + 3_600_000),
	tokenType: "Bearer",
	scope: "openid email",
	grantedScope: undefined,
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
	getFederationProviders?: () => ReadonlyMap<string, FederationProvider> | undefined;
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
			const mockProvider: FederationProvider & {
				refreshToken: (rt: string) => Promise<{
					accessToken: string;
					refreshToken?: string;
					expiresAt: Date;
				}>;
			} = {
				...federationBase("google"),
				refreshToken: refreshFn,
			};
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", mockProvider]]),
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
		it("returns 503 temporarily_unavailable — an outage, not an invalid token", async () => {
			const refreshFamilyRevocation = makeFamilyRevocation({
				isFamilyRevoked: vi.fn().mockRejectedValue(new Error("redis down")),
			});
			const app = buildApp({ refreshFamilyRevocation });
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(503);
			expect(res.body).toEqual({
				error: "temporarily_unavailable",
				error_description: "refresh token store unavailable",
			});
			expect(res.headers["www-authenticate"]).toBeUndefined();
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

		for (const [label, raw] of [
			["a control character", "goo\u0007gle"],
			["more than 200 characters", "g".repeat(300)],
		] as const) {
			it(`audits a federation name carrying ${label} sanitised and capped`, async () => {
				// `federation.token.forbidden` fires before the linked-federation
				// check, so the name is whatever the caller put in the path. An
				// audit event is kept longer than a log line and read by more
				// systems: it carries the name as the log lines do.
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
				const res = await postFedToken(
					buildApp({ clientRepo, auditSink }),
					encodeURIComponent(raw),
					await mintAccessToken(),
				);
				expect(res.status).toBe(403);
				const event = vi
					.mocked(auditSink.record)
					.mock.calls.map(([recorded]) => recorded)
					.find((recorded) => recorded.type === "federation.token.forbidden");
				const audited = String(event?.details?.federation);
				expect(audited.length).toBeLessThanOrEqual(200);
				// biome-ignore lint/suspicious/noControlCharactersInRegex: a control character is what must not be audited.
				expect(audited).not.toMatch(/[\u0000-\u001f\u007f]/);
			});
		}

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
			expect(res.body.error_description).toBe("federation 'github' is not linked to this session");
		});

		it("quotes the requested name within RFC 6749's characters", async () => {
			// The name is the client's path segment. Appendix A.8 allows no `"`,
			// `\` or non-ASCII in error_description, so the description quotes
			// with `'` and sends any other character as `?`.
			const app = buildApp();
			const token = await mintAccessToken();

			const res = await postFedToken(app, encodeURIComponent('git"h\\ub\u00e9'), token);

			expect(res.status).toBe(404);
			expect(res.body.error_description).toBe(
				"federation 'git?h?ub?' is not linked to this session",
			);
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
			expect(res.body.error_description).toBe("federation 'google' tokens not found");
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
			const refreshProvider: FederationProvider & {
				refreshToken: (rt: string) => Promise<{ accessToken: string; expiresAt: Date }>;
			} = {
				...federationBase("google"),
				refreshToken: vi.fn(),
			};
			const app = buildApp({
				fedTokenStore: makeFedTokenStore({ get: vi.fn().mockResolvedValue(expiredNoRt) }),
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
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
			const bareProvider = federationBase("google");
			const app = buildApp({
				fedTokenStore: makeFedTokenStore({ get: vi.fn().mockResolvedValue(expiredTokens) }),
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", bareProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(503);
			expect(res.body.error).toBe("refresh_not_supported");
			expect(res.body.error_description).toBe("federation 'google' does not support token refresh");
		});
	});

	describe("refresh: the upstream rejects the refresh token (a structured 400 invalid_grant)", () => {
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
			const failingProvider: FederationProvider & {
				refreshToken: (rt: string) => Promise<never>;
			} = {
				...federationBase("google"),
				// What openid-client raises for a 400 whose body names the code.
				refreshToken: vi.fn().mockRejectedValue(
					Object.assign(new Error("server responded with an error in the response body"), {
						error: "invalid_grant",
						status: 400,
					}),
				),
			};
			const app = buildApp({
				sessionFederationIndex,
				fedTokenStore,
				auditSink,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", failingProvider]]),
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
			const failingProvider: FederationProvider & {
				refreshToken: (rt: string) => Promise<never>;
			} = {
				...federationBase("google"),
				refreshToken: vi.fn().mockRejectedValue(new Error("temporarily_unavailable: provider 503")),
			};
			const app = buildApp({
				fedTokenStore: makeFedTokenStore({ get: vi.fn().mockResolvedValue(expiredTokens) }),
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", failingProvider]]),
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
			const failingProvider: FederationProvider & {
				refreshToken: (rt: string) => Promise<never>;
			} = {
				...federationBase("google"),
				refreshToken: vi.fn().mockRejectedValue(new Error("unexpected provider error")),
			};
			const app = buildApp({
				fedTokenStore: makeFedTokenStore({ get: vi.fn().mockResolvedValue(expiredTokens) }),
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", failingProvider]]),
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

	describe("refresh: the token store refuses to write the refreshed record", () => {
		/**
		 * What ioredis rejects a store write with: a ReplyError carrying the
		 * command it refused as `command: { name, args }`. Under
		 * `encryption.mode = "allow-plaintext"` the SET's arguments are the
		 * refreshed token record.
		 */
		const storeWriteError = (): Error =>
			Object.assign(new Error("OOM command not allowed when used memory > 'maxmemory'."), {
				name: "ReplyError",
				command: {
					name: "set",
					args: [
						"federation-token:sid-1:google",
						JSON.stringify({
							accessToken: "at-must-never-reach-a-log",
							refreshToken: "rt-must-never-reach-a-log",
						}),
					],
				},
			});

		const recordingLogger = () => {
			const lines: string[] = [];
			const walk = (value: unknown, seen = new WeakSet<object>()): unknown => {
				if (typeof value !== "object" || value === null) return value;
				if (seen.has(value)) return "[circular]";
				seen.add(value);
				const out: Record<string, unknown> = {};
				for (const key of Object.getOwnPropertyNames(value)) {
					out[key] = walk((value as Record<string, unknown>)[key], seen);
				}
				return out;
			};
			const record =
				(level: string) =>
				(...args: unknown[]): void => {
					lines.push(JSON.stringify({ level, args: walk(args) }));
				};
			const logger: Logger = {
				trace: record("trace"),
				debug: record("debug"),
				info: record("info"),
				warn: record("warn"),
				error: record("error"),
				fatal: record("fatal"),
				child: () => logger,
			};
			return { logger, lines };
		};

		const expired = { ...baseFedTokens, expiresAt: new Date(Date.now() - 1000) };

		it("logs a failed update of a refreshed record without the store's command", async () => {
			const { logger, lines } = recordingLogger();
			const provider: FederationProvider & {
				refreshToken: (rt: string) => Promise<{ accessToken: string; expiresAt: Date }>;
			} = {
				...federationBase("google"),
				refreshToken: vi.fn().mockResolvedValue({
					accessToken: "at-must-never-reach-a-log",
					refreshToken: "rt-must-never-reach-a-log",
					expiresAt: new Date(Date.now() + 3_600_000),
				}),
			};
			const app = buildApp({
				fedTokenStore: makeFedTokenStore({
					get: vi.fn().mockResolvedValue(expired),
					update: vi.fn().mockRejectedValue(storeWriteError()),
				}),
				getFederationProviders: () => new Map<string, FederationProvider>([["google", provider]]),
				logger,
			});
			const res = await postFedToken(app, "google", await mintAccessToken());
			expect(res.status).toBe(503);
			const failure = lines.find((line) => line.includes('"federation_token_store_unavailable"'));
			expect(failure).toContain('"level":"error"');
			expect(failure).toContain("ReplyError");
			for (const line of lines) {
				expect(line).not.toContain("at-must-never-reach-a-log");
				expect(line).not.toContain("rt-must-never-reach-a-log");
			}
		});

		it("logs a failed update that was keeping a rotated refresh token without the store's command", async () => {
			const { logger, lines } = recordingLogger();
			// A refresh that answers no usable access token but rotates the
			// refresh token: the route keeps the rotated one, and that write fails.
			const provider: FederationProvider & {
				refreshToken: (rt: string) => Promise<{ refreshToken: string }>;
			} = {
				...federationBase("google"),
				refreshToken: vi.fn().mockResolvedValue({ refreshToken: "rt-must-never-reach-a-log" }),
			};
			const app = buildApp({
				fedTokenStore: makeFedTokenStore({
					get: vi.fn().mockResolvedValue(expired),
					update: vi.fn().mockRejectedValue(storeWriteError()),
				}),
				getFederationProviders: () => new Map<string, FederationProvider>([["google", provider]]),
				logger,
			});
			await postFedToken(app, "google", await mintAccessToken());
			const failure = lines.find((line) => line.includes('"federation_token_keep_rotated_failed"'));
			expect(failure).toContain('"step":"update"');
			expect(failure).toContain("ReplyError");
			for (const line of lines) {
				expect(line).not.toContain("at-must-never-reach-a-log");
				expect(line).not.toContain("rt-must-never-reach-a-log");
			}
		});
	});

	describe("refresh: the adapter's library refuses the refresh answer", () => {
		it("logs the failure without the refresh answer the library carries on the error", async () => {
			// What openid-client 6 throws for a token response it cannot parse:
			// a ClientError ("invalid response encountered") whose cause is
			// oauth4webapi's OperationProcessingError, whose own cause is
			// `{ body }` — the refresh answer itself, rotated refresh token
			// included (openid-client's `errorHandler`, oauth4webapi's
			// `processGenericAccessTokenResponse`). Built by hand because this
			// package does not depend on the library; the adapters' tests drive
			// the real one to the same shape.
			const body = {
				access_token: "at-must-never-reach-a-log",
				refresh_token: "rt-must-never-reach-a-log",
				token_type: "bearer",
				scope: 42,
			};
			const refused = Object.assign(
				new Error("invalid response encountered", {
					cause: Object.assign(
						new Error('"response" body "scope" property must be a string', {
							cause: { body },
						}),
						{ name: "OperationProcessingError", code: "OAUTH_INVALID_RESPONSE" },
					),
				}),
				{ name: "ClientError", code: "OAUTH_INVALID_RESPONSE" },
			);

			// A logger that serialises every own property, `cause` included — a
			// deployment is free to install one.
			const lines: string[] = [];
			const serialiseEverything = (value: unknown, seen = new WeakSet<object>()): unknown => {
				if (typeof value !== "object" || value === null) return value;
				if (seen.has(value)) return "[circular]";
				seen.add(value);
				const out: Record<string, unknown> = {};
				for (const key of Object.getOwnPropertyNames(value)) {
					out[key] = serialiseEverything((value as Record<string, unknown>)[key], seen);
				}
				return out;
			};
			const record =
				(level: string) =>
				(...args: unknown[]): void => {
					lines.push(JSON.stringify({ level, args: serialiseEverything(args) }));
				};
			const logger: Logger = {
				trace: record("trace"),
				debug: record("debug"),
				info: record("info"),
				warn: record("warn"),
				error: record("error"),
				fatal: record("fatal"),
				child: () => logger,
			};

			const expiredTokens = { ...baseFedTokens, expiresAt: new Date(Date.now() - 1000) };
			const failingProvider: FederationProvider & {
				refreshToken: (rt: string) => Promise<never>;
			} = {
				...federationBase("google"),
				refreshToken: vi.fn().mockRejectedValue(refused),
			};
			const app = buildApp({
				fedTokenStore: makeFedTokenStore({ get: vi.fn().mockResolvedValue(expiredTokens) }),
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", failingProvider]]),
				logger,
			});

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(500);
			expect(res.body.error).toBe("refresh_failed");
			const failure = lines.find((line) => line.includes('"federation_token_refresh_failed"'));
			expect(failure).toBeDefined();
			// What an operator needs is still there: the library's code and reason.
			expect(failure).toContain("OAUTH_INVALID_RESPONSE");
			expect(failure).toContain('\\"scope\\" property must be a string');
			for (const line of lines) {
				expect(line).not.toContain("at-must-never-reach-a-log");
				expect(line).not.toContain("rt-must-never-reach-a-log");
			}
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
			const refreshProvider: FederationProvider & {
				refreshToken: (rt: string) => Promise<{ accessToken: string; expiresAt: Date }>;
			} = {
				...federationBase("google"),
				refreshToken: vi.fn(),
			};
			const logger = createMockLogger();
			const app = buildApp({
				fedTokenStore: lockingStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
				logger,
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(503);
			expect(res.body.error).toBe("lock_timeout");
			// Contention, not an outage: warn, structured, once — so contention
			// that persists is visible. Who waited, never a token or a secret.
			expect(logger.error).not.toHaveBeenCalled();
			const lines = logger.warn.mock.calls.filter(
				([, event]) => event === "federation_token_lock_timeout",
			);
			expect(lines).toEqual([
				[
					{ federation: "google", clientId: "client-1", sid: "sid-1" },
					"federation_token_lock_timeout",
				],
			]);
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
			const refreshProvider: FederationProvider & {
				refreshToken: (rt: string) => Promise<{ accessToken: string; expiresAt: Date }>;
			} = {
				...federationBase("google"),
				refreshToken: vi.fn(),
			};
			const app = buildApp({
				fedTokenStore: lockingStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
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
		it("answers 500 and keeps a rotated refresh token when the provider returns no access token (#626 P1)", async () => {
			// `RefreshedTokens.accessToken` is optional. A refresh without one is a
			// failed refresh — but a refresh token the upstream rotated is now the
			// only usable one (RFC 6749 §6), so it is stored before the refusal.
			const expiredTokens = {
				...baseFedTokens,
				expiresAt: new Date(Date.now() - 1000),
				refreshToken: "original-rt",
			};
			const refreshProvider: FederationProvider & {
				refreshToken: (rt: string) => Promise<{ refreshToken: string }>;
			} = {
				...federationBase("google"),
				refreshToken: vi.fn().mockResolvedValue({ refreshToken: "rotated-rt" }),
			};
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(expiredTokens),
			});
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(500);
			expect(res.body.error).toBe("refresh_failed");
			expect(fedTokenStore.update).toHaveBeenCalledWith(
				expect.any(String),
				"google",
				expect.objectContaining({ refreshToken: "rotated-rt" }),
			);
		});

		it("derives the new token's expiry from expiresIn when the provider names no expiresAt (#626 P1)", async () => {
			// The stored expiry belongs to the token just replaced — expired, which
			// is why this ran — so it is not carried forward.
			const expiredTokens = { ...baseFedTokens, expiresAt: new Date(Date.now() - 1000) };
			const refreshProvider: FederationProvider & {
				refreshToken: (rt: string) => Promise<{ accessToken: string; expiresIn: number }>;
			} = {
				...federationBase("google"),
				refreshToken: vi.fn().mockResolvedValue({ accessToken: "new-at", expiresIn: 3600 }),
			};
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(expiredTokens),
			});
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(200);
			expect(res.body.expires_in).toBeGreaterThan(3500);
			const stored = (fedTokenStore.update as ReturnType<typeof vi.fn>).mock.calls[0][2] as {
				expiresAt: Date | null;
			};
			expect(stored.expiresAt).not.toBeNull();
			expect((stored.expiresAt as Date).getTime()).toBeGreaterThan(Date.now());
		});

		it("stores no expiry and omits expires_in when the provider names neither (#626 P1)", async () => {
			const expiredTokens = { ...baseFedTokens, expiresAt: new Date(Date.now() - 1000) };
			const refreshProvider: FederationProvider & {
				refreshToken: (rt: string) => Promise<{ accessToken: string }>;
			} = {
				...federationBase("google"),
				refreshToken: vi.fn().mockResolvedValue({ accessToken: "new-at" }),
			};
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(expiredTokens),
			});
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(200);
			expect("expires_in" in res.body).toBe(false);
			const stored = (fedTokenStore.update as ReturnType<typeof vi.fn>).mock.calls[0][2] as {
				expiresAt: Date | null;
			};
			expect(stored.expiresAt).toBeNull();
		});

		// -------------------------------------------------------------------------
		// What the adapter answers is unverified data (D5). An adapter is a
		// third-party extension point, and `core/federation-grants/retrieve.mts`
		// holds the same contract to the same bar — `retrieve.hostile.test.mts`
		// pins it there. These pin it here.
		// -------------------------------------------------------------------------

		describe("refuses to believe an unusable reading from the adapter (#626 P1 review)", () => {
			const refreshingApp = (
				answer: unknown,
				stored: Partial<FederationTokens> = baseFedTokens,
			) => {
				const expiredTokens = { ...stored, expiresAt: new Date(Date.now() - 1000) };
				const refreshProvider = {
					...federationBase("google"),
					refreshToken: vi.fn().mockResolvedValue(answer),
				} as unknown as FederationProvider;
				const fedTokenStore = makeFedTokenStore({
					get: vi.fn().mockResolvedValue(expiredTokens),
				});
				const app = buildApp({
					fedTokenStore,
					getFederationProviders: () =>
						new Map<string, FederationProvider>([["google", refreshProvider]]),
				});
				return { app, fedTokenStore };
			};
			const storedExpiry = (fedTokenStore: ReturnType<typeof makeFedTokenStore>) =>
				(
					(fedTokenStore.update as ReturnType<typeof vi.fn>).mock.calls[0][2] as {
						expiresAt: Date | null;
					}
				).expiresAt;

			it.each([
				["NaN", Number.NaN],
				["a negative lifetime", -5],
				["zero", 0],
				["Infinity", Number.POSITIVE_INFINITY],
			])(
				"refuses the refresh for a stated but unusable lifetime: %s",
				async (_label, expiresIn) => {
					// Storing `null` here would be worse than storing a past instant.
					// `expiresAt: null` is this route's "no finite expiry", and its fast
					// path answers a stored token carrying one WITHOUT refreshing - so a
					// lifetime the upstream stated and got wrong would put the access
					// token into indefinite, unchecked use. A stated-and-broken lifetime
					// is malformed data, and the refresh fails.
					const { app, fedTokenStore } = refreshingApp({ accessToken: "new-at", expiresIn });
					const res = await postFedToken(app, "google", await mintAccessToken());

					expect(res.status).toBe(500);
					expect(res.body.error).toBe("refresh_failed");
					expect(fedTokenStore.update).not.toHaveBeenCalled();
				},
			);

			it("refuses the refresh for a lifetime that overflows the Date range", async () => {
				// `1e13` seconds is finite and positive, so it passes the lifetime
				// check, and still puts the instant past the 8.64e15 ms maximum. The
				// Invalid Date that results serialises to `null` in the store, which
				// is the never-expires sentinel again by a different route, so the
				// DERIVED instant is judged and not only the reading it came from.
				const { app, fedTokenStore } = refreshingApp({ accessToken: "new-at", expiresIn: 1e13 });
				const res = await postFedToken(app, "google", await mintAccessToken());

				expect(res.status).toBe(500);
				expect(res.body.error).toBe("refresh_failed");
				expect(fedTokenStore.update).not.toHaveBeenCalled();
			});

			it("refuses the refresh for an Invalid Date", async () => {
				const { app, fedTokenStore } = refreshingApp({
					accessToken: "new-at",
					expiresAt: new Date(Number.NaN),
				});
				const res = await postFedToken(app, "google", await mintAccessToken());

				expect(res.status).toBe(500);
				expect(fedTokenStore.update).not.toHaveBeenCalled();
			});

			it("salvages a rotated refresh token from a refusal over a broken lifetime", async () => {
				// The rotation rule does not care why the refresh failed: the old
				// token is dead either way (RFC 6749 section 6).
				const { app, fedTokenStore } = refreshingApp(
					{ accessToken: "new-at", expiresIn: Number.NaN, refreshToken: "rotated-rt" },
					{ ...baseFedTokens, refreshToken: "original-rt" },
				);
				const res = await postFedToken(app, "google", await mintAccessToken());

				expect(res.status).toBe(500);
				expect(fedTokenStore.update).toHaveBeenCalledWith(
					expect.any(String),
					"google",
					expect.objectContaining({ refreshToken: "rotated-rt" }),
				);
			});

			it("returns the token it stored, not a second read of the adapter's field", async () => {
				// The answer is read once. A getter read again may answer
				// differently, and handing the client a token the store does not
				// hold leaves the two disagreeing about what was issued.
				let reads = 0;
				const drifting = {
					get accessToken(): string {
						reads += 1;
						return reads === 1 ? "first-at" : "second-at";
					},
					expiresIn: 3600,
				};
				const { app, fedTokenStore } = refreshingApp(drifting);
				const res = await postFedToken(app, "google", await mintAccessToken());

				expect(res.status).toBe(200);
				expect(res.body.access_token).toBe("first-at");
				expect(fedTokenStore.update).toHaveBeenCalledWith(
					expect.any(String),
					"google",
					expect.objectContaining({ accessToken: "first-at" }),
				);
			});

			it.each([
				["expiresAt: null beside a finite expiresIn", { expiresAt: null, expiresIn: 3600 }],
				[
					"expiresIn: null beside a finite expiresAt",
					{ expiresIn: null, expiresAt: new Date(Date.now() + 3_600_000) },
				],
			])(
				"refuses an adapter that contradicts itself about the lifetime (%s)",
				async (_l, lifetime) => {
					// One field naming a lifetime while the other denies there is one
					// cannot both be true. The precedence would resolve it toward
					// `null`, which is the never-refresh sentinel, so neither is
					// believed.
					const { app, fedTokenStore } = refreshingApp({ accessToken: "new-at", ...lifetime });
					const res = await postFedToken(app, "google", await mintAccessToken());

					expect(res.status).toBe(500);
					expect(res.body.error).toBe("refresh_failed");
					expect(fedTokenStore.update).not.toHaveBeenCalled();
				},
			);

			it("does not recreate a record a concurrent logout deleted", async () => {
				// Salvaging a rotated token must not put credentials back after the
				// user asked for them to be dropped. Losing the token on a refresh
				// that already failed is the lesser harm.
				const expiredTokens = {
					...baseFedTokens,
					expiresAt: new Date(Date.now() - 1000),
					refreshToken: "original-rt",
				};
				const get = vi.fn().mockResolvedValueOnce(expiredTokens).mockResolvedValue(null);
				const refreshProvider = {
					...federationBase("google"),
					refreshToken: vi.fn().mockResolvedValue({ refreshToken: "rotated-rt" }),
				} as unknown as FederationProvider;
				const fedTokenStore = makeFedTokenStore({ get });
				const app = buildApp({
					fedTokenStore,
					getFederationProviders: () =>
						new Map<string, FederationProvider>([["google", refreshProvider]]),
				});

				const res = await postFedToken(app, "google", await mintAccessToken());

				expect(res.status).toBe(500);
				expect(fedTokenStore.update).not.toHaveBeenCalled();
			});

			it("refuses rather than storing no-expiry when a lifetime getter throws", async () => {
				// `readField` answers `undefined` for a field it cannot read, and
				// `undefined` on a lifetime field otherwise means "the upstream
				// stated nothing", which is stored as `null` and read as never
				// refresh again. An unreadable lifetime must not collapse into that
				// sentinel.
				const hostile = {
					accessToken: "new-at",
					get expiresAt(): Date {
						throw new Error("hostile getter");
					},
				};
				const { app, fedTokenStore } = refreshingApp(hostile);
				const res = await postFedToken(app, "google", await mintAccessToken());

				expect(res.status).toBe(500);
				expect(res.body.error).toBe("refresh_failed");
				expect(fedTokenStore.update).not.toHaveBeenCalled();
			});

			it("does not overwrite a concurrent refresh when salvaging a rotated token", async () => {
				// The lock TTL may expire during the upstream call, and this route
				// allows another request to refresh in that window. Writing the
				// pre-call snapshot back would replace that success with an expired
				// access token.
				const expiredTokens = {
					...baseFedTokens,
					expiresAt: new Date(Date.now() - 1000),
					refreshToken: "original-rt",
				};
				const concurrent = {
					...baseFedTokens,
					accessToken: "concurrent-at",
					expiresAt: new Date(Date.now() + 3_600_000),
					refreshToken: "concurrent-rt",
				};
				// The first read is the route's own; the next is the salvage's
				// re-read, by which point another request has rotated the chain.
				const get = vi.fn().mockResolvedValueOnce(expiredTokens).mockResolvedValue(concurrent);
				const refreshProvider = {
					...federationBase("google"),
					refreshToken: vi.fn().mockResolvedValue({ refreshToken: "rotated-rt" }),
				} as unknown as FederationProvider;
				const fedTokenStore = makeFedTokenStore({ get });
				const app = buildApp({
					fedTokenStore,
					getFederationProviders: () =>
						new Map<string, FederationProvider>([["google", refreshProvider]]),
				});

				const res = await postFedToken(app, "google", await mintAccessToken());

				expect(res.status).toBe(500);
				expect(fedTokenStore.update).not.toHaveBeenCalled();
			});

			it("merges the rotated token onto the record as it stands now", async () => {
				// No concurrent rotation, so the salvage still happens - but onto
				// what the store holds at write time, not onto the pre-call snapshot.
				const expiredTokens = {
					...baseFedTokens,
					expiresAt: new Date(Date.now() - 1000),
					refreshToken: "original-rt",
					idToken: "original-idt",
				};
				const refreshProvider = {
					...federationBase("google"),
					refreshToken: vi.fn().mockResolvedValue({ refreshToken: "rotated-rt" }),
				} as unknown as FederationProvider;
				const fedTokenStore = makeFedTokenStore({
					get: vi.fn().mockResolvedValue(expiredTokens),
				});
				const app = buildApp({
					fedTokenStore,
					getFederationProviders: () =>
						new Map<string, FederationProvider>([["google", refreshProvider]]),
				});

				const res = await postFedToken(app, "google", await mintAccessToken());

				expect(res.status).toBe(500);
				expect(fedTokenStore.update).toHaveBeenCalledWith(
					expect.any(String),
					"google",
					expect.objectContaining({ refreshToken: "rotated-rt", idToken: "original-idt" }),
				);
			});

			it("answers refresh_failed when a field getter throws, and still salvages the rotated token", async () => {
				// An object is not the same as a readable one. A getter that throws
				// would escape the refusal and take the rotated refresh token with
				// it, so each field is read behind a guard and an unreadable one is
				// simply absent.
				const hostile = {
					get accessToken(): string {
						throw new Error("hostile getter");
					},
					refreshToken: "rotated-rt",
					get expiresIn(): number {
						throw new Error("hostile getter");
					},
				};
				const { app, fedTokenStore } = refreshingApp(hostile, {
					...baseFedTokens,
					refreshToken: "original-rt",
				});
				const res = await postFedToken(app, "google", await mintAccessToken());

				expect(res.status).toBe(500);
				expect(res.body.error).toBe("refresh_failed");
				// The readable field survives the unreadable ones beside it.
				expect(fedTokenStore.update).toHaveBeenCalledWith(
					expect.any(String),
					"google",
					expect.objectContaining({ refreshToken: "rotated-rt" }),
				);
			});

			it.each([
				["null", null],
				["undefined", undefined],
				["a string", "not an object"],
			])(
				"answers refresh_failed rather than throwing when the adapter resolves %s",
				async (_l, answer) => {
					// A third-party adapter may resolve with no object at all. Reading
					// a field off it would throw past the refusal and lose both the
					// structured answer and the rotated-token salvage.
					const { app } = refreshingApp(answer);
					const res = await postFedToken(app, "google", await mintAccessToken());

					expect(res.status).toBe(500);
					expect(res.body.error).toBe("refresh_failed");
				},
			);

			it("keeps `null` meaning the upstream named no lifetime", async () => {
				// `null` is a statement and `undefined` is silence. Stated alone it
				// is believed, and the token is stored with no finite expiry. Paired
				// with a finite `expiresIn` it would be a contradiction, which is
				// refused instead - see the cases above.
				const { app, fedTokenStore } = refreshingApp({
					accessToken: "new-at",
					expiresAt: null,
				});
				const res = await postFedToken(app, "google", await mintAccessToken());

				expect(res.status).toBe(200);
				expect("expires_in" in res.body).toBe(false);
				expect(storedExpiry(fedTokenStore)).toBeNull();
			});

			it("treats an empty access token as no access token", async () => {
				// `access_token: ""` is not a credential, and answering 200 with one
				// is a malformed RFC 6749 §5.1 response.
				const { app } = refreshingApp({ accessToken: "" });
				const res = await postFedToken(app, "google", await mintAccessToken());

				expect(res.status).toBe(500);
				expect(res.body.error).toBe("refresh_failed");
			});

			it("keeps a rotated id_token alongside the rotated refresh token", async () => {
				// The stored `id_token` is what logout sends as `id_token_hint`, so
				// an upstream that rotated both should not leave the session holding
				// the old one against the new refresh token.
				const { app, fedTokenStore } = refreshingApp(
					{ refreshToken: "rotated-rt", idToken: "rotated-idt" },
					{ ...baseFedTokens, refreshToken: "original-rt", idToken: "original-idt" },
				);
				const res = await postFedToken(app, "google", await mintAccessToken());

				expect(res.status).toBe(500);
				expect(fedTokenStore.update).toHaveBeenCalledWith(
					expect.any(String),
					"google",
					expect.objectContaining({ refreshToken: "rotated-rt", idToken: "rotated-idt" }),
				);
			});

			it("keeps the stored id_token when the refusal carries no usable one", async () => {
				const { app, fedTokenStore } = refreshingApp(
					{ refreshToken: "rotated-rt", idToken: "" },
					{ ...baseFedTokens, refreshToken: "original-rt", idToken: "original-idt" },
				);
				const res = await postFedToken(app, "google", await mintAccessToken());

				expect(res.status).toBe(500);
				expect(fedTokenStore.update).toHaveBeenCalledWith(
					expect.any(String),
					"google",
					expect.objectContaining({ idToken: "original-idt" }),
				);
			});

			it("still answers 500 when the best-effort write of the rotated token fails", async () => {
				// Best effort means the refusal is unchanged: the refresh had already
				// failed, and a store that cannot take the rotated token is one more
				// thing wrong rather than a different answer.
				const expiredTokens = {
					...baseFedTokens,
					expiresAt: new Date(Date.now() - 1000),
					refreshToken: "original-rt",
				};
				const refreshProvider = {
					...federationBase("google"),
					refreshToken: vi.fn().mockResolvedValue({ refreshToken: "rotated-rt" }),
				} as unknown as FederationProvider;
				const fedTokenStore = makeFedTokenStore({
					get: vi.fn().mockResolvedValue(expiredTokens),
					update: vi.fn().mockRejectedValue(new Error("store down")),
				});
				const app = buildApp({
					fedTokenStore,
					getFederationProviders: () =>
						new Map<string, FederationProvider>([["google", refreshProvider]]),
				});

				const res = await postFedToken(app, "google", await mintAccessToken());

				expect(res.status).toBe(500);
				expect(res.body.error).toBe("refresh_failed");
			});

			it("keeps the stored refresh token when the rotated one is empty", async () => {
				// Overwriting a good refresh token with `""` strands the connection:
				// the next request finds no usable token and answers 410, which is
				// exactly what the rotation-preserving branch exists to prevent.
				const { app, fedTokenStore } = refreshingApp(
					{ refreshToken: "" },
					{ ...baseFedTokens, refreshToken: "original-rt" },
				);
				const res = await postFedToken(app, "google", await mintAccessToken());

				expect(res.status).toBe(500);
				expect(fedTokenStore.update).not.toHaveBeenCalled();
			});
		});

		it.each([
			["a getter that throws", "throws"],
			["a non-string", 42],
			["whitespace only", "   "],
		])(
			"keeps the narrowed scope when the answer names one this route cannot use: %s",
			async (_l, value) => {
				// Named-but-unusable is not silence. The upstream said something about
				// the scope and this route could not read it, so it learned nothing —
				// and nothing is a reason to keep what is stored, never to widen it back
				// to the grant.
				const narrowed = {
					...baseFedTokens,
					expiresAt: new Date(Date.now() - 1000),
					scope: "openid",
					grantedScope: "openid email",
				};
				const answer =
					value === "throws"
						? {
								accessToken: "new-at",
								expiresIn: 3600,
								get scope(): string {
									throw new Error("hostile getter");
								},
							}
						: { accessToken: "new-at", expiresIn: 3600, scope: value };
				const refreshProvider = {
					...federationBase("google"),
					refreshToken: vi.fn().mockResolvedValue(answer),
				} as unknown as FederationProvider;
				const fedTokenStore = makeFedTokenStore({
					get: vi.fn().mockResolvedValue(narrowed),
				});
				const app = buildApp({
					fedTokenStore,
					getFederationProviders: () =>
						new Map<string, FederationProvider>([["google", refreshProvider]]),
				});

				const res = await postFedToken(app, "google", await mintAccessToken());

				expect(res.status).toBe(200);
				expect(res.body.scope).toBe("openid");
				expect(fedTokenStore.update).toHaveBeenCalledWith(
					expect.any(String),
					"google",
					expect.objectContaining({ scope: "openid" }),
				);
			},
		);

		it("reads a refresh that names no scope as the grant, not as the last narrowing (#647)", async () => {
			// `refreshToken(refreshToken)` sends no `scope` upstream, so RFC 6749
			// section 6 makes the request one for the original grant, and section
			// 5.1 makes the answer's scope optional ONLY when it matches the
			// request. A conforming upstream that has narrowed must say so every
			// time; silence therefore means the grant. Reading silence as "whatever
			// the last narrowing left" is the permanent narrowing again.
			const narrowed = {
				...baseFedTokens,
				expiresAt: new Date(Date.now() - 1000),
				scope: "openid",
				grantedScope: "openid email",
			};
			const refreshProvider = {
				...federationBase("google"),
				refreshToken: vi.fn().mockResolvedValue({ accessToken: "new-at", expiresIn: 3600 }),
			} as unknown as FederationProvider;
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(narrowed),
			});
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
			});

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(200);
			expect(res.body.scope).toBe("openid email");
		});

		it("falls through to the current scope when the stored ceiling names nothing (#647)", async () => {
			// A ceiling has to satisfy the same rule as an answer. Whitespace names
			// no scope, and standing as an empty bound would refuse every answer
			// forever.
			const odd = {
				...baseFedTokens,
				expiresAt: new Date(Date.now() - 1000),
				scope: "openid email",
				grantedScope: "   ",
			};
			const refreshProvider = {
				...federationBase("google"),
				refreshToken: vi
					.fn()
					.mockResolvedValue({ accessToken: "new-at", expiresIn: 3600, scope: "openid" }),
			} as unknown as FederationProvider;
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(odd),
			});
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
			});

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(200);
			expect(res.body.scope).toBe("openid");
			// `objectContaining({ grantedScope: undefined })` would also pass if the
			// key were never written, so the whole record is read instead.
			const written = (fedTokenStore.update as ReturnType<typeof vi.fn>).mock.calls[0][2] as {
				grantedScope?: string;
				scope?: string;
			};
			expect("grantedScope" in written).toBe(true);
			expect(written.grantedScope).toBeUndefined();
			expect(written.scope).toBe("openid");
		});

		it.each([
			["a tab", "\t"],
			["a newline", "\n"],
			["three spaces", "   "],
		])("reads %s as an answer it cannot use, not as a scope by that name", async (_l, scope) => {
			// RFC 6749 section 3.3's scope-token excludes whitespace, so a tab is
			// not a scope named tab. Read as one it would be stored as the token's
			// scope and then fail every later comparison.
			const narrowed = {
				...baseFedTokens,
				expiresAt: new Date(Date.now() - 1000),
				scope: "openid",
				grantedScope: "openid email",
			};
			const refreshProvider = {
				...federationBase("google"),
				refreshToken: vi.fn().mockResolvedValue({ accessToken: "new-at", expiresIn: 3600, scope }),
			} as unknown as FederationProvider;
			const fedTokenStore = makeFedTokenStore({ get: vi.fn().mockResolvedValue(narrowed) });
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
			});

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(200);
			expect(res.body.scope).toBe("openid");
		});

		it("reads scopes separated by a tab as separate scopes (#647)", async () => {
			const narrowed = {
				...baseFedTokens,
				expiresAt: new Date(Date.now() - 1000),
				scope: "openid",
				grantedScope: "openid email",
			};
			const refreshProvider = {
				...federationBase("google"),
				refreshToken: vi
					.fn()
					.mockResolvedValue({ accessToken: "new-at", expiresIn: 3600, scope: "openid\temail" }),
			} as unknown as FederationProvider;
			const fedTokenStore = makeFedTokenStore({ get: vi.fn().mockResolvedValue(narrowed) });
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
			});

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(200);
			// Two scopes, both within the grant — not one scope with a tab in its name.
			expect(res.body.scope).toBe("openid email");
		});

		it("stores a repeated entry once (#647)", async () => {
			const narrowed = {
				...baseFedTokens,
				expiresAt: new Date(Date.now() - 1000),
				scope: "openid",
				grantedScope: "openid email",
			};
			const refreshProvider = {
				...federationBase("google"),
				refreshToken: vi.fn().mockResolvedValue({
					accessToken: "new-at",
					expiresIn: 3600,
					scope: "openid openid email",
				}),
			} as unknown as FederationProvider;
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(narrowed),
			});
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
			});

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(200);
			expect(res.body.scope).toBe("openid email");
		});

		it("accepts a refresh back up to the granted scope after an earlier narrowing (#647)", async () => {
			// RFC 6749 section 6 bounds a refresh by the ORIGINAL grant, not by the
			// scope of the token it replaces. An upstream that narrowed once and
			// then answers with the full grant again is within its rights, and
			// judging that against the narrowed value would make the first
			// narrowing permanent.
			const narrowed = {
				...baseFedTokens,
				expiresAt: new Date(Date.now() - 1000),
				scope: "openid",
				grantedScope: "openid email",
			};
			const refreshProvider = {
				...federationBase("google"),
				refreshToken: vi
					.fn()
					.mockResolvedValue({ accessToken: "new-at", expiresIn: 3600, scope: "openid email" }),
			} as unknown as FederationProvider;
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(narrowed),
			});
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
			});

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(200);
			expect(res.body.scope).toBe("openid email");
			expect(fedTokenStore.update).toHaveBeenCalledWith(
				expect.any(String),
				"google",
				// The ceiling itself never moves.
				expect.objectContaining({ scope: "openid email", grantedScope: "openid email" }),
			);
		});

		it("still refuses a refresh beyond the granted scope, not merely beyond the current one (#647)", async () => {
			const narrowed = {
				...baseFedTokens,
				expiresAt: new Date(Date.now() - 1000),
				scope: "openid",
				grantedScope: "openid email",
			};
			const refreshProvider = {
				...federationBase("google"),
				refreshToken: vi.fn().mockResolvedValue({
					accessToken: "new-at",
					expiresIn: 3600,
					scope: "openid email admin",
				}),
			} as unknown as FederationProvider;
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(narrowed),
			});
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
			});

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(200);
			expect(res.body.scope).toBe("openid");
		});

		it("falls back to the current scope as the ceiling for a record written before #647", async () => {
			// Existing records carry no `grantedScope`. They keep the behaviour they
			// had: the current scope is the only ceiling available, which is
			// conservative rather than wrong.
			const legacy = {
				...baseFedTokens,
				expiresAt: new Date(Date.now() - 1000),
				scope: "openid email",
			};
			const refreshProvider = {
				...federationBase("google"),
				refreshToken: vi
					.fn()
					.mockResolvedValue({ accessToken: "new-at", expiresIn: 3600, scope: "openid" }),
			} as unknown as FederationProvider;
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(legacy),
			});
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
			});

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(200);
			expect(res.body.scope).toBe("openid");
		});

		it("refuses a refresh that widens the scope, keeping what was granted", async () => {
			// RFC 6749 section 6: the refreshed token's scope "MUST NOT include any
			// scope not originally granted". An answer that adds one is the upstream
			// or the adapter misbehaving, and recording it would leave the store
			// claiming a consent the user never gave.
			const expiredTokens = {
				...baseFedTokens,
				expiresAt: new Date(Date.now() - 1000),
				scope: "openid email",
			};
			const refreshProvider = {
				...federationBase("google"),
				refreshToken: vi.fn().mockResolvedValue({
					accessToken: "new-at",
					expiresIn: 3600,
					scope: "openid email admin",
				}),
			} as unknown as FederationProvider;
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(expiredTokens),
			});
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
			});

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(200);
			expect(res.body.scope).toBe("openid email");
			expect(fedTokenStore.update).toHaveBeenCalledWith(
				expect.any(String),
				"google",
				expect.objectContaining({ scope: "openid email" }),
			);
		});

		it("keeps the stored refresh token when a successful refresh answers an empty one", async () => {
			// The no-access-token branch refused an empty string already; the success
			// path used `??`, which lets one through and strands the connection at
			// the next request.
			const expiredTokens = {
				...baseFedTokens,
				expiresAt: new Date(Date.now() - 1000),
				refreshToken: "original-rt",
			};
			const refreshProvider = {
				...federationBase("google"),
				refreshToken: vi
					.fn()
					.mockResolvedValue({ accessToken: "new-at", expiresIn: 3600, refreshToken: "" }),
			} as unknown as FederationProvider;
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(expiredTokens),
			});
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
			});

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(200);
			expect(fedTokenStore.update).toHaveBeenCalledWith(
				expect.any(String),
				"google",
				expect.objectContaining({ refreshToken: "original-rt" }),
			);
		});

		it("narrows the stored and reported scope to what the refresh answered (RFC 6749 §6)", async () => {
			// §6 lets a refresh return a narrower scope, and §5.1 makes the answer
			// authoritative when it differs from the request. Keeping the old value
			// would leave the record claiming access the upstream just withdrew.
			const expiredTokens = {
				...baseFedTokens,
				expiresAt: new Date(Date.now() - 1000),
				scope: "openid email calendar.write",
			};
			const refreshProvider = {
				...federationBase("google"),
				refreshToken: vi
					.fn()
					.mockResolvedValue({ accessToken: "new-at", expiresIn: 3600, scope: "openid email" }),
			} as unknown as FederationProvider;
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(expiredTokens),
			});
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
			});

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(200);
			expect(res.body.scope).toBe("openid email");
			expect(fedTokenStore.update).toHaveBeenCalledWith(
				expect.any(String),
				"google",
				expect.objectContaining({ scope: "openid email" }),
			);
		});

		it.each([
			["whitespace only", "   "],
			["an empty string", ""],
		])("keeps the stored scope when the refresh names one it cannot use: %s", async (_l, scope) => {
			// RFC 6749 section 3.3 makes a scope a space-delimited list, so neither
			// of these names one. Parsed, both are the empty list - which would
			// satisfy the subset check vacuously and store the whitespace, leaving
			// every later answer failing against an empty granted set. Absent,
			// empty and whitespace-only are one case.
			const expiredTokens = {
				...baseFedTokens,
				expiresAt: new Date(Date.now() - 1000),
				scope: "openid email",
			};
			const refreshProvider = {
				...federationBase("google"),
				refreshToken: vi.fn().mockResolvedValue({ accessToken: "new-at", expiresIn: 3600, scope }),
			} as unknown as FederationProvider;
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(expiredTokens),
			});
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
			});

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(200);
			expect(res.body.scope).toBe("openid email");
			expect(fedTokenStore.update).toHaveBeenCalledWith(
				expect.any(String),
				"google",
				expect.objectContaining({ scope: "openid email" }),
			);
		});

		it("stores the canonical form of an accepted narrowing", async () => {
			// Re-joined from the parsed list, so a ragged answer does not become the
			// stored value that later answers are judged against.
			const expiredTokens = {
				...baseFedTokens,
				expiresAt: new Date(Date.now() - 1000),
				scope: "openid email calendar",
			};
			const refreshProvider = {
				...federationBase("google"),
				refreshToken: vi.fn().mockResolvedValue({
					accessToken: "new-at",
					expiresIn: 3600,
					scope: "  openid   email ",
				}),
			} as unknown as FederationProvider;
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(expiredTokens),
			});
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
			});

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(200);
			expect(res.body.scope).toBe("openid email");
		});

		it("reads a refresh that names none as the stored scope when the record has no ceiling", async () => {
			const expiredTokens = {
				...baseFedTokens,
				expiresAt: new Date(Date.now() - 1000),
				scope: "openid email",
			};
			const refreshProvider = {
				...federationBase("google"),
				refreshToken: vi.fn().mockResolvedValue({ accessToken: "new-at", expiresIn: 3600 }),
			} as unknown as FederationProvider;
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(expiredTokens),
			});
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
			});

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(200);
			expect(res.body.scope).toBe("openid email");
		});

		it("stores original refreshToken when provider returns no refreshToken", async () => {
			const expiredTokens = {
				...baseFedTokens,
				expiresAt: new Date(Date.now() - 1000),
				refreshToken: "original-rt",
			};
			const newExpiresAt = new Date(Date.now() + 3_600_000);
			const refreshProvider: FederationProvider & {
				refreshToken: (rt: string) => Promise<{ accessToken: string; expiresAt: Date }>;
			} = {
				...federationBase("google"),
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
					new Map<string, FederationProvider>([["google", refreshProvider]]),
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
			const refreshProvider: FederationProvider & {
				refreshToken: (rt: string) => Promise<{
					accessToken: string;
					refreshToken?: string;
					expiresAt: Date;
				}>;
			} = {
				...federationBase("google"),
				refreshToken: vi.fn().mockResolvedValue({
					accessToken: "new-at",
					expiresAt: new Date(Date.now() + 3_600_000),
				}),
			};
			const app = buildApp({
				fedTokenStore: makeFedTokenStore({ get: vi.fn().mockResolvedValue(expiredTokens) }),
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
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
			const refreshProvider: FederationProvider & {
				refreshToken: (rt: string) => Promise<{
					accessToken: string;
					refreshToken?: string;
					expiresAt: Date;
				}>;
			} = {
				...federationBase("google"),
				refreshToken: refreshFn,
			};

			const app = buildApp({
				fedTokenStore: lockingStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
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
			const refreshProvider: FederationProvider & {
				refreshToken: (rt: string) => Promise<{
					accessToken: string;
					refreshToken?: string;
					expiresAt: Date;
				}>;
			} = {
				...federationBase("google"),
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
					new Map<string, FederationProvider>([["google", refreshProvider]]),
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

	describe("every store failure it logs reaches the logger as a projection, never as the error", () => {
		const expired = (): FederationTokens => ({
			...baseFedTokens,
			expiresAt: new Date(Date.now() - 1000),
		});

		/** Providers with google refreshing through `refreshToken`. */
		const refreshingGoogle =
			(refreshToken: (rt: string) => Promise<unknown>) =>
			(): ReadonlyMap<string, FederationProvider> =>
				new Map<string, FederationProvider>([
					["google", { ...federationBase("google"), refreshToken } as FederationProvider],
				]);

		it("the family revocation check — an outage line, at error level", async () => {
			const logger = createMockLogger();
			const refreshFamilyRevocation = makeFamilyRevocation({
				isFamilyRevoked: vi.fn().mockRejectedValue(storeReplyError()),
			});
			const res = await postFedToken(
				buildApp({ refreshFamilyRevocation, logger }),
				"google",
				await mintAccessToken(),
			);
			expect(res.status).toBe(503);
			expect(res.body.error_description).toBe("refresh token store unavailable");
			expect(logger.error).toHaveBeenCalledWith(
				{
					federation: "google",
					store: "refresh_token_family",
					err: expect.objectContaining({ name: "ReplyError" }),
				},
				"federation_token_store_unavailable",
			);
			const line = logger.error.mock.calls.find(
				([, event]) => event === "federation_token_store_unavailable",
			);
			expect(line?.[0].err).not.toBeInstanceOf(Error);
			expect(serialisedCalls(logger)).not.toContain(REFUSED_COMMAND_MARKER);
		});

		for (const [label, raw] of [
			["a control character", "goo\u0007gle"],
			["more than 200 characters", "g".repeat(300)],
		] as const) {
			it(`records a federation name carrying ${label} sanitised and capped`, async () => {
				// The path parameter is the caller's text, logged before any
				// membership check: any holder of a valid access token chooses it.
				const logger = createMockLogger();
				const refreshFamilyRevocation = makeFamilyRevocation({
					isFamilyRevoked: vi.fn().mockRejectedValue(storeReplyError()),
				});
				const res = await postFedToken(
					buildApp({ refreshFamilyRevocation, logger }),
					encodeURIComponent(raw),
					await mintAccessToken(),
				);
				expect(res.status).toBe(503);
				const line = expectOutageLine(logger, "federation_token_store_unavailable", {
					store: "refresh_token_family",
				});
				const logged = String(line.federation);
				expect(logged.length).toBeLessThanOrEqual(200);
				// biome-ignore lint/suspicious/noControlCharactersInRegex: a control character is what must not be logged.
				expect(logged).not.toMatch(/[\u0000-\u001f\u007f]/);
			});
		}

		it("the client lookup", async () => {
			const logger = createMockLogger();
			const clientRepo = makeClientRepo({ findById: vi.fn().mockRejectedValue(storeReplyError()) });
			const res = await postFedToken(
				buildApp({ clientRepo, logger }),
				"google",
				await mintAccessToken(),
			);
			expect(res.status).toBe(503);
			expect(res.body.error_description).toBe("client repository unavailable");
			expectOutageLine(logger, "client_repository_unavailable", {
				site: "federation_token",
				step: "find",
				clientId: "client-1",
			});
		});

		it("the session store", async () => {
			const logger = createMockLogger();
			const sessionStore = makeSessionStore({ get: vi.fn().mockRejectedValue(storeReplyError()) });
			const res = await postFedToken(
				buildApp({ sessionStore, logger }),
				"google",
				await mintAccessToken(),
			);
			expect(res.status).toBe(503);
			expect(res.body.error_description).toBe("session store unavailable");
			expectOutageLine(logger, "federation_token_store_unavailable", {
				federation: "google",
				store: "user_session",
				step: "get",
			});
		});

		it("the session's federation index", async () => {
			const logger = createMockLogger();
			const sessionFederationIndex = makeSessionFederationIndex({
				listFederations: vi.fn().mockRejectedValue(storeReplyError()),
			});
			const res = await postFedToken(
				buildApp({ sessionFederationIndex, logger }),
				"google",
				await mintAccessToken(),
			);
			expect(res.status).toBe(503);
			expect(res.body.error_description).toBe("session store unavailable");
			expectOutageLine(logger, "federation_token_store_unavailable", {
				federation: "google",
				store: "session_federation_index",
				step: "list",
			});
		});

		it("the token store's read", async () => {
			const logger = createMockLogger();
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockRejectedValue(storeReplyError()),
			});
			const res = await postFedToken(
				buildApp({ fedTokenStore, logger }),
				"google",
				await mintAccessToken(),
			);
			expect(res.status).toBe(503);
			expectOutageLine(logger, "federation_token_store_unavailable", {
				federation: "google",
				store: "federation_token",
				step: "get",
			});
		});

		it("the dangling link's self-heal", async () => {
			const logger = createMockLogger();
			const fedTokenStore = makeFedTokenStore({ get: vi.fn().mockResolvedValue(null) });
			const sessionFederationIndex = makeSessionFederationIndex({
				removeFederation: vi.fn().mockRejectedValue(storeReplyError()),
			});
			const res = await postFedToken(
				buildApp({ fedTokenStore, sessionFederationIndex, logger }),
				"google",
				await mintAccessToken(),
			);
			expect(res.status).toBe(404);
			expectBestEffortWarn(logger, "federation_token_index_self_heal_failed", {
				federation: "google",
				store: "session_federation_index",
				step: "remove",
			});
		});

		it("the refresh lock", async () => {
			const logger = createMockLogger();
			const fedTokenStore = {
				...makeFedTokenStore({ get: vi.fn().mockResolvedValue(expired()) }),
				acquireLock: vi.fn().mockRejectedValue(storeReplyError()),
			};
			const res = await postFedToken(
				buildApp({
					fedTokenStore,
					logger,
					getFederationProviders: refreshingGoogle(vi.fn()),
				}),
				"google",
				await mintAccessToken(),
			);
			expect(res.status).toBe(503);
			expectOutageLine(logger, "federation_token_store_unavailable", {
				federation: "google",
				store: "federation_token",
				step: "acquire_lock",
			});
		});

		it("the read after the lock", async () => {
			const logger = createMockLogger();
			const release = vi.fn().mockResolvedValue(undefined);
			const fedTokenStore = {
				...makeFedTokenStore({
					get: vi.fn().mockResolvedValueOnce(expired()).mockRejectedValueOnce(storeReplyError()),
				}),
				acquireLock: vi.fn().mockResolvedValue({ acquired: true, release }),
			};
			const res = await postFedToken(
				buildApp({
					fedTokenStore,
					logger,
					getFederationProviders: refreshingGoogle(vi.fn()),
				}),
				"google",
				await mintAccessToken(),
			);
			expect(res.status).toBe(503);
			expect(release).toHaveBeenCalled();
			expectOutageLine(logger, "federation_token_store_unavailable", {
				federation: "google",
				store: "federation_token",
				step: "get_after_lock",
			});
		});

		it("the write of the refreshed token", async () => {
			const logger = createMockLogger();
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(expired()),
				update: vi.fn().mockRejectedValue(storeReplyError()),
			});
			const res = await postFedToken(
				buildApp({
					fedTokenStore,
					logger,
					getFederationProviders: refreshingGoogle(
						vi.fn().mockResolvedValue({
							accessToken: "new-at",
							expiresAt: new Date(Date.now() + 3_600_000),
						}),
					),
				}),
				"google",
				await mintAccessToken(),
			);
			expect(res.status).toBe(503);
			expect(res.body.error_description).toBe("federation token store unavailable");
			expectOutageLine(logger, "federation_token_store_unavailable", {
				federation: "google",
				store: "federation_token",
				step: "update",
			});
		});

		it("an upstream provider that cannot be reached", async () => {
			const logger = createMockLogger();
			const unreachable = Object.assign(new Error("connect ECONNREFUSED 10.0.0.9:443"), {
				name: "ReplyError",
				code: "ECONNREFUSED",
			});
			const res = await postFedToken(
				buildApp({
					fedTokenStore: makeFedTokenStore({ get: vi.fn().mockResolvedValue(expired()) }),
					logger,
					getFederationProviders: refreshingGoogle(vi.fn().mockRejectedValue(unreachable)),
				}),
				"google",
				await mintAccessToken(),
			);
			expect(res.status).toBe(503);
			expect(res.body.error_description).toBe(
				"upstream federation provider temporarily unavailable",
			);
			expectOutageLine(logger, "federation_token_upstream_unavailable", {
				federation: "google",
				reason: "network",
			});
		});

		it("a provider that cannot refresh, which the deployment has to fix", async () => {
			const logger = createMockLogger();
			const res = await postFedToken(
				buildApp({
					fedTokenStore: makeFedTokenStore({ get: vi.fn().mockResolvedValue(expired()) }),
					logger,
					getFederationProviders: () =>
						new Map<string, FederationProvider>([["google", federationBase("google")]]),
				}),
				"google",
				await mintAccessToken(),
			);
			expect(res.status).toBe(503);
			expect(res.body.error).toBe("refresh_not_supported");
			expect(logger.warn.mock.calls.filter(([first]) => typeof first === "string")).toEqual([]);
			expect(logger.error).toHaveBeenCalledTimes(1);
			expect(logger.error).toHaveBeenCalledWith(
				{ federation: "google" },
				"federation_token_refresh_unsupported",
			);
		});

		it("both cleanups after invalid_grant", async () => {
			const logger = createMockLogger();
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue(expired()),
				delete: vi.fn().mockRejectedValue(storeReplyError()),
			});
			const sessionFederationIndex = makeSessionFederationIndex({
				removeFederation: vi.fn().mockRejectedValue(storeReplyError()),
			});
			const res = await postFedToken(
				buildApp({
					fedTokenStore,
					sessionFederationIndex,
					logger,
					getFederationProviders: refreshingGoogle(
						vi.fn().mockRejectedValue(
							Object.assign(new Error("server responded with an error in the response body"), {
								error: "invalid_grant",
								status: 400,
							}),
						),
					),
				}),
				"google",
				await mintAccessToken(),
			);
			expect(res.status).toBe(410);
			expectBestEffortWarn(logger, "federation_token_cleanup_failed", {
				federation: "google",
				store: "federation_token",
				step: "delete",
			});
			expectBestEffortWarn(logger, "federation_token_cleanup_failed", {
				federation: "google",
				store: "session_federation_index",
				step: "remove",
			});
		});

		it("the lock's release", async () => {
			const logger = createMockLogger();
			const fresh = { ...baseFedTokens, expiresAt: new Date(Date.now() + 3_600_000) };
			const fedTokenStore = {
				...makeFedTokenStore({
					get: vi.fn().mockResolvedValueOnce(expired()).mockResolvedValueOnce(fresh),
				}),
				acquireLock: vi.fn().mockResolvedValue({
					acquired: true,
					release: vi.fn().mockRejectedValue(storeReplyError()),
				}),
			};
			const res = await postFedToken(
				buildApp({
					fedTokenStore,
					logger,
					getFederationProviders: refreshingGoogle(vi.fn()),
				}),
				"google",
				await mintAccessToken(),
			);
			expect(res.status).toBe(200);
			expectBestEffortWarn(logger, "federation_token_lock_release_failed", {
				federation: "google",
				store: "federation_token",
				step: "release_lock",
			});
		});
	});

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
	// The structural lock this deferred is no longer a separate anchor: since
	// #626 P1 the route narrows with core's own `supportsRefresh` over core's
	// `SupportsRefresh`, so a rename of the method is a compile error rather
	// than a probe that quietly matches nothing. There is no local
	// `SupportsRefreshShape` left to keep in step, and nothing has to import
	// session to say so.
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
			const realShapeProvider: FederationProvider & {
				refreshToken: (rt: string) => Promise<{
					accessToken: string;
					refreshToken?: string;
					expiresAt: Date;
				}>;
			} = {
				...federationBase("google"),
				refreshToken: refreshFn,
			};
			const app = buildApp({
				fedTokenStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", realShapeProvider]]),
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
			const refreshProvider: FederationProvider & {
				refreshToken: typeof refreshFn;
			} = { ...federationBase("google"), refreshToken: refreshFn };
			const app = buildApp({
				fedTokenStore: makeFedTokenStore({ get: vi.fn().mockResolvedValue(expiredTokens) }),
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
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
			const refreshProvider: FederationProvider & {
				refreshToken: typeof refreshFn;
			} = { ...federationBase("google"), refreshToken: refreshFn };
			const app = buildApp({
				fedTokenStore: lockingStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
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
			const refreshProvider: FederationProvider & {
				refreshToken: typeof refreshFn;
			} = { ...federationBase("google"), refreshToken: refreshFn };
			const app = buildApp({
				fedTokenStore: lockingStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
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
			const refreshProvider: FederationProvider & {
				refreshToken: typeof refreshFn;
			} = { ...federationBase("google"), refreshToken: refreshFn };
			return buildApp({
				fedTokenStore: makeFedTokenStore({ get: vi.fn().mockResolvedValue(expiredTokens) }),
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
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
			// The upstream named no wait, so none is invented.
			expect(res.headers["retry-after"]).toBeUndefined();
		});

		it("forwards the upstream's Retry-After on the 429", async () => {
			const providerError = Object.assign(new Error("rate limit hit"), {
				error: "too_many_requests",
				status: 429,
				response: new Response(null, { status: 429, headers: { "retry-after": "30" } }),
			});
			const app = buildRefreshFailure(providerError);

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(429);
			expect(res.headers["retry-after"]).toBe("30");
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
			// undici's cause is an Error; a plain object there is read as nothing,
			// since openid-client puts the IdP's parsed body in the same place.
			const providerError = new TypeError("fetch failed", {
				cause: Object.assign(new Error("getaddrinfo ENOTFOUND idp.example"), {
					code: "ENOTFOUND",
				}),
			});
			const app = buildRefreshFailure(providerError);
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(503);
			expect(res.body.error).toBe("temporarily_unavailable");
		});

		// A message that names invalid_grant is not the upstream's verdict: it is
		// whatever the library, a proxy or the upstream wrote. The stored tokens
		// are kept, and the failure is the unclassified 500.
		it("returns 500 refresh_failed, not 410, when only error.message contains invalid_grant", async () => {
			const providerError = new Error("400 invalid_grant: token revoked");
			const app = buildRefreshFailure(providerError);
			const token = await mintAccessToken();

			const res = await postFedToken(app, "google", token);

			expect(res.status).toBe(500);
			expect(res.body.error).toBe("refresh_failed");
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

	// ---------------------------------------------------------------------------
	// Only the upstream's own verdict ends the session's upstream tokens
	// ---------------------------------------------------------------------------

	describe("the stored tokens are ended only on a structured invalid_grant, never during an outage", () => {
		/**
		 * The session's link to google, its expired tokens and a provider whose
		 * refresh rejects with `error`, plus the stores to look at afterwards.
		 */
		function refreshRejectingWith(error: unknown, logger?: Logger) {
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue({
					...baseFedTokens,
					expiresAt: new Date(Date.now() - 1000),
				}),
			});
			const sessionFederationIndex = makeSessionFederationIndex();
			const auditSink: AuditSink = { kind: "mock", record: vi.fn().mockResolvedValue(undefined) };
			const provider = {
				...federationBase("google"),
				refreshToken: vi.fn().mockRejectedValue(error),
			} as FederationProvider;
			const app = buildApp({
				fedTokenStore,
				sessionFederationIndex,
				auditSink,
				logger,
				getFederationProviders: () => new Map<string, FederationProvider>([["google", provider]]),
			});
			return { app, fedTokenStore, sessionFederationIndex, auditSink };
		}

		const expectKept = (
			fedTokenStore: FederationTokenStore,
			sessionFederationIndex: SessionFederationIndex,
			auditSink: AuditSink,
		) => {
			expect(fedTokenStore.delete).not.toHaveBeenCalled();
			expect(sessionFederationIndex.removeFederation).not.toHaveBeenCalled();
			expect(auditSink.record).not.toHaveBeenCalledWith(
				expect.objectContaining({ type: "federation.token.reauthentication_required" }),
			);
		};

		/** An outage is logged, not audited: no `federation.token.refresh_failed` for it. */
		const expectNoRefreshFailedAudit = (auditSink: AuditSink) => {
			expect(auditSink.record).not.toHaveBeenCalledWith(
				expect.objectContaining({ type: "federation.token.refresh_failed" }),
			);
		};

		it("keeps them and answers 503 when a 5xx answer's body says invalid_grant", async () => {
			// An adapter whose library puts the body's code and the status on one
			// error, as openid-client's ResponseBodyError does for a 4xx.
			const logger = createMockLogger();
			const { app, fedTokenStore, sessionFederationIndex, auditSink } = refreshRejectingWith(
				Object.assign(new Error("server responded with an error in the response body"), {
					name: "ResponseBodyError",
					error: "invalid_grant",
					status: 503,
				}),
				logger,
			);

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(503);
			expect(res.body).toEqual({
				error: "temporarily_unavailable",
				error_description: "upstream federation provider temporarily unavailable",
			});
			expectKept(fedTokenStore, sessionFederationIndex, auditSink);
			expectNoRefreshFailedAudit(auditSink);
			expectOutageLine(
				logger,
				"federation_token_upstream_unavailable",
				{ federation: "google", reason: "network" },
				"ResponseBodyError",
			);
		});

		it("keeps them and answers 503 when the 5xx is on the Response the error was raised over", async () => {
			// oauth4webapi raises a 5xx it would not read as an
			// OperationProcessingError over the Response, and an adapter may wrap
			// that in an error carrying the code it expected.
			const { app, fedTokenStore, sessionFederationIndex, auditSink } = refreshRejectingWith(
				Object.assign(
					new Error('"response" is not a conform Token Endpoint response', {
						cause: new Response('{"error":"invalid_grant"}', { status: 502 }),
					}),
					{ error: "invalid_grant" },
				),
			);

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(503);
			expectKept(fedTokenStore, sessionFederationIndex, auditSink);
			expectNoRefreshFailedAudit(auditSink);
		});

		it("answers no outage for a 4xx whose parsed body names a connection code", async () => {
			// openid-client's ResponseBodyError carries the IdP's JSON body as its
			// cause: a `code` there is the IdP's text, not this server's transport.
			const { app, fedTokenStore, sessionFederationIndex, auditSink } = refreshRejectingWith(
				Object.assign(
					new Error("server responded with an error in the response body", {
						cause: { error: "login_required", code: "ECONNREFUSED" },
					}),
					{ name: "ResponseBodyError", error: "login_required", status: 400 },
				),
			);

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(500);
			expect(res.body.error).toBe("refresh_failed");
			expectKept(fedTokenStore, sessionFederationIndex, auditSink);
		});

		it("keeps them and answers 429 with the upstream's Retry-After when a 429 names invalid_grant", async () => {
			const { app, fedTokenStore, sessionFederationIndex, auditSink } = refreshRejectingWith(
				Object.assign(new Error("server responded with an error in the response body"), {
					name: "ResponseBodyError",
					error: "invalid_grant",
					status: 429,
					response: new Response(null, { status: 429, headers: { "retry-after": "120" } }),
				}),
			);

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(429);
			expect(res.body.error).toBe("rate_limited");
			expect(res.headers["retry-after"]).toBe("120");
			expectKept(fedTokenStore, sessionFederationIndex, auditSink);
		});

		it("keeps them when only the message says invalid_grant", async () => {
			const { app, fedTokenStore, sessionFederationIndex, auditSink } = refreshRejectingWith(
				new Error("invalid_grant: token revoked"),
			);

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(500);
			expect(res.body.error).toBe("refresh_failed");
			expectKept(fedTokenStore, sessionFederationIndex, auditSink);
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "federation.token.refresh_failed",
					details: expect.objectContaining({ reason: "unknown" }),
				}),
			);
		});

		it("ends them on a structured 400 invalid_grant", async () => {
			const { app, fedTokenStore, sessionFederationIndex, auditSink } = refreshRejectingWith(
				Object.assign(new Error("server responded with an error in the response body"), {
					name: "ResponseBodyError",
					error: "invalid_grant",
					status: 400,
				}),
			);

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(410);
			expect(res.body.error).toBe("re_authentication_required");
			expect(fedTokenStore.delete).toHaveBeenCalledWith("sid-1", "google");
			expect(sessionFederationIndex.removeFederation).toHaveBeenCalledWith("sid-1", "google");
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({ type: "federation.token.reauthentication_required" }),
			);
		});
	});

	// ---------------------------------------------------------------------------
	// #645 — what the upstream said its token is, and whether it may be handed on
	// ---------------------------------------------------------------------------

	describe("token_type: the upstream's, and only one kind of it (#645)", () => {
		/** A record that is still valid, with whatever `tokenType` the case names. */
		const storedApp = (stored: Record<string, unknown>) => {
			const auditSink: AuditSink = { kind: "mock", record: vi.fn().mockResolvedValue(undefined) };
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue({ ...baseFedTokens, ...stored }),
			});
			return { app: buildApp({ fedTokenStore, auditSink }), fedTokenStore, auditSink };
		};

		/** An expired record whose refresh answers `answer`. */
		const refreshingApp = (answer: unknown, stored: Record<string, unknown> = {}) => {
			const auditSink: AuditSink = { kind: "mock", record: vi.fn().mockResolvedValue(undefined) };
			const fedTokenStore = makeFedTokenStore({
				get: vi.fn().mockResolvedValue({
					...baseFedTokens,
					...stored,
					expiresAt: new Date(Date.now() - 1000),
				}),
			});
			const refreshProvider = {
				...federationBase("google"),
				refreshToken: vi.fn().mockResolvedValue(answer),
			} as unknown as FederationProvider;
			const app = buildApp({
				fedTokenStore,
				auditSink,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
			});
			return { app, fedTokenStore, auditSink };
		};

		const written = (fedTokenStore: FederationTokenStore) =>
			(fedTokenStore.update as ReturnType<typeof vi.fn>).mock.calls[0][2] as Record<
				string,
				unknown
			>;

		it.each([
			["a record written before #645", undefined],
			["the spelling oauth4webapi reports", "bearer"],
			["the spelling RFC 6750 §2.1 uses", "Bearer"],
			["an upstream shouting it", "BEARER"],
		])("answers Bearer for %s", async (_label, tokenType) => {
			// Always `Bearer`, never the upstream's own spelling. Once a non-bearer
			// type is refused, the only values left are case-variants of one word —
			// RFC 6749 §5.1 makes the comparison case-insensitive, so the spelling
			// carries nothing a caller can act on, and echoing it would flip every
			// connection whose upstream spells it `bearer` — every bundled adapter
			// reports oauth4webapi's lower-cased spelling — for no gain.
			//
			// Silence is Bearer: §5.1 makes `token_type` REQUIRED, so a record that
			// names none is an adapter written before `FederationProfile` carried
			// the field — a third-party one, or a record linked before the bundled
			// adapters reported it — and not an upstream meaning something else. This is what keeps every record
			// written before #645 working.
			const { app } = storedApp({ tokenType });

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(200);
			expect(res.body.token_type).toBe("Bearer");
		});

		it.each([
			["DPoP"],
			["dpop"],
			["PoP"],
			["N_A"],
			["mac"],
			// Not a token type at all. Reading one of these as silence would
			// answer `Bearer` for it — the behaviour #645 exists to stop, reached
			// through a narrower door — so the record is read, not just parsed.
			["DPoP "],
			[" DPoP"],
			["Bearer token"],
			[""],
		])("refuses to hand on a %s token", async (tokenType) => {
			// Every type in IANA's registry other than Bearer is
			// sender-constrained: presenting one takes proof of possession of a
			// key, and a caller handed the token by value holds no such key. This
			// route used to answer `Bearer` regardless, which dropped the
			// constraint the upstream imposed and handed out a credential that
			// only looked usable.
			const { app } = storedApp({ tokenType });

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(502);
			expect(res.body.error).toBe("upstream_token_ineligible");
			expect(res.body.error_description).toBe("token_type_unsupported");
			expect(res.body.access_token).toBeUndefined();
			// Not transient: an operator has to change the upstream's
			// registration back. Without this a client that retries a 5xx
			// drives one upstream refresh per retry.
			expect(res.headers["retry-after"]).toBe("300");
		});

		it.each([
			["a number", 7],
			["an array", ["DPoP"]],
			["an object", { toString: () => "Bearer" }],
			// Not a second spelling of absence: a JSON round-trip DROPS an
			// undefined field rather than writing `null`, so a stored `null` is a
			// store writing one on purpose — and the built-in Redis codec already
			// refuses the record that holds it.
			["null", null],
		])("refuses to hand on a record whose type is %s", async (_label, tokenType) => {
			// A store is another thing this route does not own (D5). A value that
			// is not a string cannot be a bearer spelling, so it is refused rather
			// than read as the silence that would answer `Bearer`.
			const { app } = storedApp({ tokenType });

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(502);
			expect(res.body.error).toBe("upstream_token_ineligible");
		});

		it("does not count a refused disclosure as a success", async () => {
			// A dashboard grouping on `federation.token.success` would otherwise
			// count a token that was never handed out.
			const { app, auditSink } = storedApp({ tokenType: "DPoP" });

			await postFedToken(app, "google", await mintAccessToken());

			const types = (auditSink.record as ReturnType<typeof vi.fn>).mock.calls.map(
				(call) => (call[0] as { type: string }).type,
			);
			expect(types).toEqual(["federation.token.upstream_ineligible"]);
		});

		it.each([
			["a type name", "DPoP", "DPoP"],
			["a value that is not a token type, so an operator can see that", "DPoP ", "DPoP "],
			["null for a value that is not a string at all", 7, null],
		])("tells the audit sink %s", async (_label, stored, reported) => {
			// The caller can do nothing with it but retry; an operator needs to
			// know which upstream started answering something else, and what.
			const { app, auditSink } = storedApp({ tokenType: stored });

			await postFedToken(app, "google", await mintAccessToken());

			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "federation.token.upstream_ineligible",
					details: expect.objectContaining({
						federation: "google",
						reason: "token_type_unsupported",
						tokenType: reported,
					}),
				}),
			);
		});

		describe("a type that is a line break, control characters and 10 000 characters", () => {
			const HOSTILE = `DPoP\r\nFORGED federation.token.success\u001b[31m\u0000${"t".repeat(10_000)}`;
			/** What the event carried, as an assertion needs it: a failure prints this, not the value. */
			const auditedType = (auditSink: AuditSink) => {
				const event = vi
					.mocked(auditSink.record)
					.mock.calls.map(([recorded]) => recorded)
					.find((recorded) => recorded.type === "federation.token.upstream_ineligible");
				const tokenType = event?.details?.tokenType;
				return {
					string: typeof tokenType === "string",
					// biome-ignore lint/suspicious/noControlCharactersInRegex: a control character is what must not be audited.
					control: /[\u0000-\u001f\u007f]/.test(String(tokenType)),
					within200: String(tokenType).length <= 200,
					head: String(tokenType).slice(0, 12),
				};
			};
			const BOUNDED = { string: true, control: false, within200: true, head: "DPoP??FORGED" };

			it("tells the audit sink the stored type sanitised and capped", async () => {
				// The upstream wrote it, a store kept it: the audit sink is read by
				// systems that split on a line break, and the value is still worth
				// seeing — so it is kept, bounded, rather than dropped. (A refresh
				// that answers such a type never gets here: `canonicalTokenType`
				// refuses it as `invalid_token_type`.)
				const { app, auditSink } = storedApp({ tokenType: HOSTILE });

				const res = await postFedToken(app, "google", await mintAccessToken());

				expect(res.status).toBe(502);
				expect(auditedType(auditSink)).toEqual(BOUNDED);
			});
		});

		it("judges the record a concurrent refresh wrote, on the post-lock re-read", async () => {
			// The refresh that wrote this record is not this request, so its answer
			// is no more trusted here than on the fast path.
			const release = vi.fn().mockResolvedValue(undefined);
			const lockingStore = {
				...makeFedTokenStore({
					get: vi
						.fn()
						.mockResolvedValueOnce({ ...baseFedTokens, expiresAt: new Date(Date.now() - 1000) })
						.mockResolvedValueOnce({ ...baseFedTokens, tokenType: "DPoP" }),
				}),
				acquireLock: vi.fn().mockResolvedValue({ acquired: true, release }),
			};
			const refreshToken = vi.fn();
			const refreshProvider = {
				...federationBase("google"),
				refreshToken,
			} as unknown as FederationProvider;
			const app = buildApp({
				fedTokenStore: lockingStore,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", refreshProvider]]),
			});

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(502);
			expect(res.body.error).toBe("upstream_token_ineligible");
			expect(refreshToken).not.toHaveBeenCalled();
			// The refusal is not a reason to hold the lock.
			expect(release).toHaveBeenCalled();
		});

		it("carries a refreshed type into the record, and still answers Bearer", async () => {
			// The record keeps the upstream's spelling — it is the evidence an
			// operator reads — while the wire value stays the one constant a
			// caller can rely on.
			const { app, fedTokenStore } = refreshingApp({
				accessToken: "new-at",
				expiresIn: 3600,
				tokenType: "bearer",
			});

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(200);
			expect(res.body.token_type).toBe("Bearer");
			expect(written(fedTokenStore).tokenType).toBe("bearer");
		});

		it("leaves the stored type standing when the refresh names none", async () => {
			// A refresh is not where a connection changes how its tokens are
			// presented. Every bundled adapter names one; a third-party adapter may
			// not, and that is the case pinned here.
			const { app, fedTokenStore } = refreshingApp(
				{ accessToken: "new-at", expiresIn: 3600 },
				{ tokenType: "bearer" },
			);

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(200);
			expect(written(fedTokenStore).tokenType).toBe("bearer");
		});

		it("refuses a stored type that is not a token type when the refresh names none", async () => {
			// The stored value is carried verbatim rather than re-read through
			// `canonicalTokenType`: doing that would turn it into `undefined`, and
			// absence is what the disclosure check reads as Bearer. Nothing is
			// written, so the evidence survives for the next request too.
			const { app, fedTokenStore } = refreshingApp(
				{ accessToken: "new-at", expiresIn: 3600 },
				{ tokenType: "DPoP " },
			);

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(502);
			expect(res.body.error).toBe("upstream_token_ineligible");
			expect(fedTokenStore.update).not.toHaveBeenCalled();
		});

		it.each([
			["an empty string", ""],
			["a value with a space in it", "Bearer token"],
			["something that is not a string", 7],
			// Printable, and not a token type: no URI may contain `^`. The old
			// NQCHAR bound read this as a type name and sent it down the 502
			// meant for a real type the upstream issued (#649 review).
			["a value with a character no URI may contain", "Bearer^"],
			// Every character is legal and the reference is not: an IP-literal
			// that never closes. The lexical check read it as a type name.
			["a structurally malformed URI reference", "https://["],
		])("refuses the refresh when the answered type is %s", async (_label, tokenType) => {
			// Not a name at all: §A.13's `token-type` admits a `type-name` or a URI
			// reference, and none of these is either. The
			// adapter answered something broken, which is a failed refresh rather
			// than an upstream this provider may not delegate for — and the record
			// keeps the type it had.
			const { app, fedTokenStore } = refreshingApp({
				accessToken: "new-at",
				expiresIn: 3600,
				tokenType,
			});

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(500);
			expect(res.body.error).toBe("refresh_failed");
			expect(fedTokenStore.update).not.toHaveBeenCalled();
		});

		it.each([
			["invalid_token_type", { accessToken: "new-at", expiresIn: 3600, tokenType: "Bearer token" }],
			["invalid_expiry", { accessToken: "new-at", expiresIn: Number.NaN }],
			["no_access_token", { expiresIn: 3600 }],
		])("audits a broken answer with reason %s", async (reason, answer) => {
			// `packages/oauth/README.md` tells SIEM rules to group on
			// `details.reason`, so the three readings this refusal can carry are
			// pinned rather than left to the ternary.
			const { app, auditSink } = refreshingApp(answer);

			await postFedToken(app, "google", await mintAccessToken());

			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "federation.token.refresh_failed",
					details: expect.objectContaining({ federation: "google", reason }),
				}),
			);
		});

		it("refuses the refresh when the answered type cannot be read", async () => {
			// An adapter is a third-party extension point, so the answer may be an
			// object whose getters throw. Unreadable is not the same as absent:
			// absent leaves the stored type standing, and collapsing the two would
			// hand on a token under a type nobody could read.
			const { app, fedTokenStore } = refreshingApp({
				accessToken: "new-at",
				expiresIn: 3600,
				get tokenType(): string {
					throw new Error("boom");
				},
			});

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(500);
			expect(res.body.error).toBe("refresh_failed");
			expect(fedTokenStore.update).not.toHaveBeenCalled();
		});

		it("refuses to hand on a refreshed token that is sender-constrained", async () => {
			// The refresh itself worked. What it brought is a token the caller
			// could not present, which is the upstream's doing and not a failure —
			// so 502, and the record is not rewritten with a token nobody can use.
			const { app, fedTokenStore, auditSink } = refreshingApp({
				accessToken: "new-at",
				expiresIn: 3600,
				tokenType: "DPoP",
			});

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(502);
			expect(res.body.error).toBe("upstream_token_ineligible");
			expect(res.body.error_description).toBe("token_type_unsupported");
			expect(fedTokenStore.update).not.toHaveBeenCalled();
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "federation.token.upstream_ineligible",
					details: expect.objectContaining({ tokenType: "DPoP" }),
				}),
			);
		});

		it("salvages a rotated refresh token from the refusal to hand one on", async () => {
			// This matters more here than on a failed refresh: the connection is
			// healthy, and an operator who fixes the upstream's configuration must
			// not have to send the user back for consent. The upstream has already
			// invalidated the token this one replaced (RFC 6749 §6).
			const { app, fedTokenStore } = refreshingApp(
				{
					accessToken: "new-at",
					expiresIn: 3600,
					tokenType: "DPoP",
					refreshToken: "rotated-rt",
				},
				{ refreshToken: "original-rt" },
			);

			const res = await postFedToken(app, "google", await mintAccessToken());

			expect(res.status).toBe(502);
			expect(written(fedTokenStore).refreshToken).toBe("rotated-rt");
			// Only the credential was salvaged — not the token that cannot be used.
			expect(written(fedTokenStore).accessToken).toBe(baseFedTokens.accessToken);
		});
	});
});

describe("POST /oauth/federation/:name/token — keeping a rotated refresh token is logged, structured", () => {
	// A refresh that answers no usable access token but rotates the refresh
	// token: the route answers 500 refresh_failed and, best effort, re-reads
	// the record and keeps the rotated token. Whatever happens there is one
	// object-first warn: the route answers the refusal it would anyway, not a
	// 503, so none of it is an error-level outage line.
	const expiredTokens = (): FederationTokens => ({
		...baseFedTokens,
		expiresAt: new Date(Date.now() - 1000),
		refreshToken: "original-rt",
	});
	const rotatingProvider = () =>
		({
			...federationBase("google"),
			refreshToken: vi.fn().mockResolvedValue({ refreshToken: "rotated-rt" }),
		}) as unknown as FederationProvider;
	const run = async (store: Partial<FederationTokenStore>) => {
		const logger = createMockLogger();
		const fedTokenStore = makeFedTokenStore(store);
		const app = buildApp({
			fedTokenStore,
			getFederationProviders: () =>
				new Map<string, FederationProvider>([["google", rotatingProvider()]]),
			logger,
		});
		const res = await postFedToken(app, "google", await mintAccessToken());
		expect(res.status).toBe(500);
		expect(res.body.error).toBe("refresh_failed");
		return { logger, fedTokenStore };
	};

	it("logs a failed re-read once, with the store, the step and the projection", async () => {
		const { logger, fedTokenStore } = await run({
			get: vi.fn().mockResolvedValueOnce(expiredTokens()).mockRejectedValue(storeReplyError()),
		});
		expect(fedTokenStore.update).not.toHaveBeenCalled();
		expectBestEffortWarn(logger, "federation_token_keep_rotated_failed", {
			federation: "google",
			store: "federation_token",
			step: "get",
		});
	});

	it("logs a failed write once, with the store, the step and the projection", async () => {
		const { logger } = await run({
			get: vi.fn().mockResolvedValue(expiredTokens()),
			update: vi.fn().mockRejectedValue(storeReplyError()),
		});
		expectBestEffortWarn(logger, "federation_token_keep_rotated_failed", {
			federation: "google",
			store: "federation_token",
			step: "update",
		});
	});

	it("says why it kept nothing when a concurrent logout removed the record", async () => {
		const { logger } = await run({
			get: vi.fn().mockResolvedValueOnce(expiredTokens()).mockResolvedValue(null),
		});
		expectBestEffortWarn(
			logger,
			"federation_token_keep_rotated_skipped",
			{ federation: "google", store: "federation_token", reason: "record_gone" },
			null,
		);
	});

	it("says why it kept nothing when a concurrent refresh rotated the connection", async () => {
		const { logger } = await run({
			get: vi
				.fn()
				.mockResolvedValueOnce(expiredTokens())
				.mockResolvedValue({ ...expiredTokens(), refreshToken: "concurrent-rt" }),
		});
		expectBestEffortWarn(
			logger,
			"federation_token_keep_rotated_skipped",
			{ federation: "google", store: "federation_token", reason: "rotated_concurrently" },
			null,
		);
	});
});

/**
 * A token whose `typ` header is text the verifier reads before the signature
 * and quotes in its refusal's message. A route's own line about the refusal
 * carries the verifier's reason and nothing of the token.
 */
const TYP_MARKER = "typ-must-never-reach-a-route-line";
const mintTypMarkerToken = (): Promise<string> =>
	new SignJWT({ sub: "u-1", sid: "sid-1", azp: "client-1", family_id: "fam-1" })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: TYP_MARKER })
		.setExpirationTime("1h")
		.setIssuedAt()
		.setIssuer("https://auth.example.com")
		.sign(secretKey);

describe("POST /oauth/federation/:name/token — a refused access token is logged by the verifier's reason", () => {
	it("logs the reason alone, nothing the token carries", async () => {
		const logger = createMockLogger();
		const res = await postFedToken(buildApp({ logger }), "google", await mintTypMarkerToken());
		expect(res.status).toBe(401);
		const line = expectBestEffortWarn(
			logger,
			"federation_token_jwt_verify_failed",
			{ federation: "google" },
			null,
		);
		expect(line).toEqual({ federation: "google", reason: "typ" });
	});
});
