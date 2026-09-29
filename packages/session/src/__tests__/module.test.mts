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

import type { FederationProvider } from "@o3co/auth-provider-core";
import {
	type AppConfig,
	defineModule,
	type FederationTokenStore,
	type SessionFederationIndex,
	type SessionRequirement,
	SUBJECT_REVOCATION_ABSENCE_POLICY,
	type SubjectRevocation,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	createTestApp,
	makeValidAppConfig,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { sessionModule } from "#/module.mjs";

// ---------------------------------------------------------------------------
// Shared test-only stubs (per A5 §10.1 typed-slot const-Module pattern)
// ---------------------------------------------------------------------------

const fakeUserRepository: UserRepository = {
	authenticate: async () => null,
	authenticateByToken: async () => null,
} as unknown as UserRepository;

const userRepositoryModule = defineModule({
	name: "test:user-repository",
	provides: { userRepository: () => fakeUserRepository },
});

function makeUserSessionStore(): UserSessionStore {
	return {
		kind: "memory",
		async create() {},
		async get() {
			return null;
		},
		async delete() {},
	} as unknown as UserSessionStore;
}

const userSessionStoreModule = defineModule({
	name: "test:user-session-store",
	provides: { userSessionStore: () => makeUserSessionStore() },
});

function makeFederationTokenStore(): FederationTokenStore {
	return {
		kind: "memory",
		async attach() {},
		async get() {
			return null;
		},
		async update() {},
		async removeBySid() {},
		async delete() {},
	} as unknown as FederationTokenStore;
}

const federationTokenStoreModule = defineModule({
	name: "test:federation-token-store",
	provides: { federationTokenStore: () => makeFederationTokenStore() },
});

function makeSessionFederationIndex(): SessionFederationIndex {
	return {
		kind: "memory",
		async addFederation() {},
		async listFederations() {
			return [];
		},
		async removeFederation() {},
		async removeBySid() {},
	} as unknown as SessionFederationIndex;
}

const sessionFederationIndexModule = defineModule({
	name: "test:session-federation-index",
	provides: { sessionFederationIndex: () => makeSessionFederationIndex() },
});

/**
 * Stub modules for `sessionRPRegistry`, `sessionFamilyIndex`, and
 * `refreshTokenFamilyRevocation`. These slots are oauth-package concerns (not
 * provided by sessionModule or any session-package module), but the boot-time
 * `federation-stores-incomplete` validator requires them whenever any
 * federation is enabled in config (the validator stays aligned with route-level
 * gating in packages/oauth/src/routes.mts logoutSupported /
 * federationTokenSupported). Tests that enable a federation must include these
 * stubs so the guard passes and the session-level validations under test can
 * fire.
 */
const sessionRPRegistryModule = defineModule({
	name: "test:session-rp-registry",
	provides: { sessionRPRegistry: () => ({ kind: "stub" }) } as never,
});

const sessionFamilyIndexModule = defineModule({
	name: "test:session-family-index",
	provides: { sessionFamilyIndex: () => ({ kind: "stub" }) } as never,
});

const refreshTokenFamilyRevocationModule = defineModule({
	name: "test:refresh-token-family-revocation",
	provides: { refreshTokenFamilyRevocation: () => ({ kind: "stub" }) } as never,
});

/**
 * Stub federation module — contributes `federations.stub` + the paired
 * `federationRedirectPolicies.stub`. Needed for any test that exercises the
 * boot path with at least one enabled federation in config (otherwise the
 * planner's pairing invariant would fail to satisfy from config alone).
 */
const stubFederationProvider: FederationProvider = {
	name: "stub",
	scope: ["openid"],
	buildAuthorizationUrl: () => new URL("https://example.com/authorize"),
	exchangeCode: async () => ({ issuer: "https://example.com", sub: "user-1", expiresAt: null }),
};

const stubFederationModule = defineModule({
	name: "test:stub-federation",
	contributes: {
		federations: {
			stub: () => stubFederationProvider,
		},
		federationRedirectPolicies: {
			stub: () => ({
				validateRedirect: () => ({ ok: true as const, value: undefined }),
				resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
			}),
		},
	},
});

const baseTestModules = [
	sessionModule,
	userRepositoryModule,
	userSessionStoreModule,
	federationTokenStoreModule,
	sessionFederationIndexModule,
	// Required by the boot-time `federation-stores-incomplete` validator whenever
	// any federation is enabled in config. These are oauth-package concerns;
	// the session-package tests use stubs so the guard passes and session-level
	// validations under test can fire. Per issue #101 TODO-F-1, plus #103 review
	// (refreshTokenFamilyRevocation added so validator matches route-level gating).
	sessionRPRegistryModule,
	sessionFamilyIndexModule,
	refreshTokenFamilyRevocationModule,
];

// ---------------------------------------------------------------------------
// Static manifest assertions (Codex-recommended: keep structural assertions
// for declarative shape; HTTP / integration tests cover behavior)
// ---------------------------------------------------------------------------

describe("sessionModule (static manifest)", () => {
	it("exposes the const Module shape — not a factory", () => {
		expect(typeof sessionModule).toBe("object");
		expect(sessionModule.name).toBe("session");
	});

	it("declares the Amendment 5 + A5 dep set in `requires`", () => {
		expect(sessionModule.requires).toEqual(
			expect.arrayContaining([
				"config",
				"userRepository",
				"userSessionStore",
				"federationTokenStore",
				"sessionFederationIndex",
				"federationProviders",
				"federationRedirectPolicyResolver",
			]),
		);
		// Amendment 5 (§1.1.5): `sessionRPRegistry` and `sessionFamilyIndex` are
		// oauth-package concerns, MUST NOT appear in sessionModule.requires.
		expect(sessionModule.requires).not.toContain("sessionRPRegistry");
		expect(sessionModule.requires).not.toContain("sessionFamilyIndex");
		// …and this is also the pin on how far `POST /session/logout` cascades.
		// It invalidates the `UserSession` record, the subject index and the
		// federation pair — every store in the list above. It does NOT revoke
		// refresh-token families: that needs these three keys, and reaching
		// them would mean depending on `@o3co/auth-provider-oauth` (a
		// forbidden sibling edge) or writing a second `cascadeLogout`. A widened
		// cascade must widen this list first, deliberately, not by accident.
		expect(sessionModule.requires).not.toContain("refreshTokenFamilyRevocation");
		expect(sessionModule.optional ?? []).not.toContain("refreshTokenFamilyRevocation");
	});

	it("contributes exactly two routes, both at /session, with distinct ids", () => {
		const routes = sessionModule.contributes?.routes;
		expect(routes).toBeDefined();
		expect(routes).toHaveLength(2);
	});
});

// ---------------------------------------------------------------------------
// Boot-level integration tests (createTestApp)
// ---------------------------------------------------------------------------

describe("sessionModule (boot integration)", () => {
	it("boots successfully when no federations are enabled", async () => {
		const config = makeValidAppConfig();
		const handle = await createTestApp({
			modules: baseTestModules,
			bootstrapComponents: { config, pathResolver: (s: string) => s },
		});
		expect(handle.routes.some((r) => r.contribution.mountPath === "/session")).toBe(true);
		await handle.dispose();
	});

	it("registers a federation provider contributed via per-federation module", async () => {
		const base = makeValidAppConfig();
		const config: AppConfig = {
			...base,
			federations: {
				...base.federations,
				stub: {
					enabled: true,
					clientId: "id",
					clientSecret: "secret",
					callbackURL: "https://example.com/cb",
				} as never,
			},
		} as AppConfig;
		const handle = await createTestApp({
			modules: [...baseTestModules, stubFederationModule],
			bootstrapComponents: { config, pathResolver: (s: string) => s },
		});
		expect(handle.inspect.federations.has("stub")).toBe(true);
		await handle.dispose();
	});

	it("fails to boot when an enabled federation has no callbackURL", async () => {
		const base = makeValidAppConfig();
		const config: AppConfig = {
			...base,
			federations: {
				...base.federations,
				stub: {
					enabled: true,
					clientId: "id",
					clientSecret: "secret",
					// callbackURL intentionally absent
				} as never,
			},
		} as AppConfig;
		await expect(
			createTestApp({
				modules: [...baseTestModules, stubFederationModule],
				bootstrapComponents: { config, pathResolver: (s: string) => s },
			}),
		).rejects.toThrow(/callbackURL is required/);
	});

	it("skips disabled federations in the providerCallbackUrls projection", async () => {
		const base = makeValidAppConfig();
		const config: AppConfig = {
			...base,
			federations: {
				...base.federations,
				disabledFed: {
					enabled: false,
					// no callbackURL — must NOT throw because disabled
				} as never,
			},
		} as AppConfig;
		const handle = await createTestApp({
			modules: baseTestModules,
			bootstrapComponents: { config, pathResolver: (s: string) => s },
		});
		// No throw at boot, no entry in the federation registry.
		expect(handle.inspect.federations.has("disabledFed")).toBe(false);
		await handle.dispose();
	});
});

describe("auditSink absence policy (#363)", () => {
	it("carries the shared AUDIT_SINK_ABSENCE_POLICY constant, by identity", async () => {
		// Identity, not shape: the declared-absence guard refuses modules whose
		// policies for one key disagree, and sharing the one constant is what
		// makes disagreement impossible by construction.
		const { AUDIT_SINK_ABSENCE_POLICY } = await import("@o3co/auth-provider-core");
		expect(sessionModule.absencePolicies?.auditSink).toBe(AUDIT_SINK_ABSENCE_POLICY);
	});
});

// ---------------------------------------------------------------------------
// A consumer of session admission (the session-admission ADR's D1, D8)
// ---------------------------------------------------------------------------

describe("sessionModule — the link routes are a consumer of session admission", () => {
	it("requires sessionRequirementResolver, the synthetic key every consumer of admission takes", () => {
		expect(sessionModule.requires).toContain("sessionRequirementResolver");
	});

	it("takes subjectRevocation as an optional slot, under the one subject-revocation policy it attaches for subjectSessionIndex", () => {
		expect(sessionModule.optional).toContain("subjectRevocation");
		expect(sessionModule.requires).not.toContain("subjectRevocation");
		// Identity, not shape: the declared-absence guard compares policies per
		// key, and the two subject-revocation slots are one capability (#406).
		expect(sessionModule.absencePolicies?.subjectRevocation).toBe(
			SUBJECT_REVOCATION_ABSENCE_POLICY,
		);
		expect(sessionModule.absencePolicies?.subjectSessionIndex).toBe(
			SUBJECT_REVOCATION_ABSENCE_POLICY,
		);
	});

	/**
	 * The federation-routes factory, called as the planner calls it, its
	 * router mounted behind a cookie session signed in as user-1 whose record
	 * is live: what the link start answers says what the factory handed the
	 * routes.
	 */
	async function linkStart(extra: {
		subjectRevocation?: SubjectRevocation;
		requirements?: readonly SessionRequirement[];
	}): Promise<request.Response> {
		const base = makeValidAppConfig();
		const config = {
			...base,
			federations: {
				...base.federations,
				stub: {
					enabled: true,
					clientId: "id",
					clientSecret: "secret",
					callbackURL: "https://example.com/session/oauth/federation/stub/callback",
				},
			},
		} as unknown as AppConfig;
		const record = {
			sid: "s-1",
			sub: "user-1",
			authTime: new Date(Date.now() - 60_000),
			createdAt: new Date(Date.now() - 60_000),
			expiresAt: new Date(Date.now() + 3_600_000),
			claims: {},
			amr: undefined,
			authentication: undefined,
		};
		const factory = sessionModule.contributes?.routes?.[1] as unknown as (deps: unknown) => {
			id: string;
			handler: express.RequestHandler;
		};
		const contribution = factory({
			config,
			federationProviders: new Map([["stub", stubFederationProvider]]),
			federationRedirectPolicyResolver: new Map([
				[
					"stub",
					{
						validateRedirect: () => ({ ok: true as const, value: undefined }),
						resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
					},
				],
			]),
			userRepository: {
				...fakeUserRepository,
				linkFederatedIdentity: async () => ({ ok: true, user: { id: "user-1" } }),
			},
			userSessionStore: { ...makeUserSessionStore(), get: async () => record },
			federationTokenStore: makeFederationTokenStore(),
			sessionFederationIndex: makeSessionFederationIndex(),
			sessionRequirementResolver: resolverForTests(extra.requirements ?? []),
			...(extra.subjectRevocation ? { subjectRevocation: extra.subjectRevocation } : {}),
		});
		expect(contribution.id).toBe("federation-routes");
		const app = express();
		app.use((req, _res, next) => {
			(req as unknown as { session: Record<string, unknown> }).session = {
				sid: "s-1",
				isAuthenticated: true,
				user: { id: "user-1" },
				save: (cb: (err: unknown) => void) => cb(null),
			};
			next();
		});
		app.use("/session", contribution.handler);
		return request(app)
			.get("/session/oauth/federation/stub?link=1")
			.set("Sec-Fetch-Site", "same-origin");
	}

	it("hands the link routes the wired subjectRevocation: (4) a revoked subject's link start is refused", async () => {
		const subjectRevocation = {
			kind: "test",
			revokeBefore: async () => {},
			revokedBefore: vi.fn(async () => new Date()),
		} as unknown as SubjectRevocation;
		const res = await linkStart({ subjectRevocation });
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("login_required");
		expect(subjectRevocation.revokedBefore).toHaveBeenCalledWith("user-1");
	});

	it("admits the same start when no subjectRevocation is wired", async () => {
		expect((await linkStart({})).status).toBe(302);
	});

	it("hands the link routes the resolver: a registered requirement's step-up answers the start", async () => {
		const res = await linkStart({
			requirements: [
				{
					name: "fixture",
					reach: new Set<string>(),
					stepUpPage: { url: "/fixture/step-up", params: {} },
					remediations: [],
					hintKeys: [],
					admit: async () => ({ outcome: "step_up", whenStillUnmet: "reauthenticate" }),
				},
			],
		});
		expect(res.status).toBe(403);
		expect(res.body).toMatchObject({
			error: "step_up_required",
			requirement: "fixture",
			// Resolved on the issuer the module reads, oauth.jwt.issuer — the
			// valid config's.
			page: "https://auth.test/fixture/step-up",
		});
	});
});

describe("sessionModule — the password login is a consumer of session admission (the session-admission ADR's D5)", () => {
	/**
	 * The session-routes factory, called as the planner calls it, its router
	 * mounted behind a cookie session: what a password login answers says
	 * what the factory handed the route.
	 */
	async function passwordLogin(requirements: readonly SessionRequirement[]) {
		const base = makeValidAppConfig();
		const config = {
			...base,
			session: { ...base.session, secret: "module-test-secret" },
			deployment: { mode: "single" },
		} as unknown as AppConfig;
		const factory = sessionModule.contributes?.routes?.[0] as unknown as (deps: unknown) => {
			id: string;
			handler: express.RequestHandler;
		};
		const contribution = factory({
			config,
			userRepository: {
				authenticate: async () => ({ id: "user-1", username: "alice" }),
				authenticateByToken: async () => null,
			},
			userSessionStore: makeUserSessionStore(),
			federationTokenStore: makeFederationTokenStore(),
			sessionFederationIndex: makeSessionFederationIndex(),
			sessionRequirementResolver: resolverForTests(requirements),
		});
		expect(contribution.id).toBe("session-routes");
		const app = express();
		app.use((req, _res, next) => {
			const fresh = (): Record<string, unknown> => ({
				regenerate: (cb: (err: unknown) => void) => {
					(req as unknown as { session: Record<string, unknown> }).session = fresh();
					(req as unknown as { sessionID: string }).sessionID = "regenerated";
					cb(null);
				},
				save: (cb: (err: unknown) => void) => cb(null),
			});
			(req as unknown as { session: Record<string, unknown> }).session = fresh();
			next();
		});
		app.use("/session", contribution.handler);
		const csrf = await request(app).get("/session/csrf");
		return request(app)
			.post("/session/login")
			.set("Cookie", csrf.headers["set-cookie"] as unknown as string[])
			.set(csrf.body.header_name as string, csrf.body.csrf_token as string)
			.send({ username: "alice", password: "secret" });
	}

	it("hands the login route the resolver: a registered requirement's interruption answers the login", async () => {
		const res = await passwordLogin([
			{
				name: "fixture",
				reach: new Set<string>(),
				stepUpPage: undefined,
				remediations: [],
				hintKeys: [],
				admit: async () => ({ outcome: "met" }),
				admitPrimary: async () => ({
					open: async () => ({ status: 403, body: { error: "fixture_required" } }),
				}),
			},
		]);
		expect(res.status).toBe(403);
		expect(res.body).toEqual({ error: "fixture_required" });
	});

	it("logs in as before when no requirement is registered", async () => {
		expect((await passwordLogin([])).status).toBe(200);
	});
});
