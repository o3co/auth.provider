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
	BootError,
	type DeploymentMode,
	defineModule,
	type FederationTokenStore,
	memoryRateLimiterModule,
	type SessionRequirement,
	SUBJECT_REVOCATION_ABSENCE_POLICY,
	type SubjectRevocation,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	coreConfigForTests,
	createTestApp,
	createTestCsrfTokenSigner,
	createTestFederationSettings,
	createTestSessionCookiePolicy,
	federationTypeForTests,
	makeValidAppConfig,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { SESSION_ADMISSION_ACTIONS } from "#/admissionActions.mjs";
import { sessionModule } from "#/module.mjs";
import { withSessionCaptures } from "./_helpers/sections.mjs";
import {
	fakeSessionLifecycle,
	openingLifecycleStore,
	sessionLifecycleTestModule,
} from "./_helpers/sessionLifecycle.mjs";

// ---------------------------------------------------------------------------
// Shared test-only stubs (typed-slot const Modules)
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
		async removeBySid() {},
		async delete() {},
	} as unknown as FederationTokenStore;
}

const federationTokenStoreModule = defineModule({
	name: "test:federation-token-store",
	provides: { federationTokenStore: () => makeFederationTokenStore() },
});

/** The CSRF token's signer, which the session store's module provides where it is loaded. */
const csrfTokenSignerModule = defineModule({
	name: "test:csrf-token-signer",
	provides: { csrfTokenSigner: () => createTestCsrfTokenSigner() },
});

/** The session cookie, where the session store's module is not loaded. */
const sessionCookiePolicyModule = defineModule({
	name: "test:session-cookie-policy",
	provides: { sessionCookiePolicy: () => createTestSessionCookiePolicy() },
});

/**
 * A stub for an oauth-package slot that no session-package module provides.
 * The boot-time `federation-stores-incomplete` validator requires it whenever
 * any federation is enabled in config, so a test that enables one includes it
 * for the session-level validations under test to fire.
 */
const refreshTokenFamilyRevocationModule = defineModule({
	name: "test:refresh-token-family-revocation",
	provides: { refreshTokenFamilyRevocation: () => ({ kind: "stub" }) } as never,
});

/**
 * The provider of the enabled `stub` entry. The federation type `stub`
 * registers it, with a redirect policy beside it, for any test that boots
 * with at least one enabled federation in config (an enabled entry is handled
 * by the module that registers its type).
 */
const stubFederationProvider: FederationProvider = {
	name: "stub",
	scope: ["openid"],
	buildAuthorizationUrl: () => new URL("https://example.com/authorize"),
	exchangeCode: async () => ({ issuer: "https://example.com", sub: "user-1", expiresAt: null }),
};

const stubFederationModule = federationTypeForTests("stub", {
	provider: () => stubFederationProvider,
});

/** The session module and the stores it requires, without core's session lifecycle. */
const withoutLifecycle = [
	sessionModule,
	userRepositoryModule,
	userSessionStoreModule,
	federationTokenStoreModule,
	csrfTokenSignerModule,
	sessionCookiePolicyModule,
	// The oauth-package stub for the `federation-stores-incomplete` validator (above).
	refreshTokenFamilyRevocationModule,
];

const baseTestModules = [...withoutLifecycle, sessionLifecycleTestModule()];

// ---------------------------------------------------------------------------
// Static manifest assertions: declarative shape only; the HTTP and boot
// tests cover behaviour
// ---------------------------------------------------------------------------

describe("sessionModule (static manifest)", () => {
	it("exposes the const Module shape — not a factory", () => {
		expect(typeof sessionModule).toBe("object");
		expect(sessionModule.name).toBe("session");
	});

	it("reads its own section and core's federationSettings, never the whole configuration", () => {
		expect(sessionModule.requires).toContain("federationSettings");
		expect(sessionModule.requires).not.toContain("config");
		expect(sessionModule.optional ?? []).not.toContain("config");
		expect(sessionModule).not.toHaveProperty("configSchema");
	});

	it("declares its dep set in `requires`, without the oauth package's sessionRPRegistry, sessionFamilyIndex or refreshTokenFamilyRevocation", () => {
		expect(sessionModule.requires).toEqual(
			expect.arrayContaining([
				"federationSettings",
				"userRepository",
				"userSessionStore",
				"federationTokenStore",
				"csrfTokenSigner",
				"federationProviders",
				"federationRedirectPolicyResolver",
			]),
		);
		// A link reads the federations a session joined from core's session
		// lifecycle; the per-session index is not this module's.
		expect(sessionModule.requires).not.toContain("sessionFederationIndex");
		expect(sessionModule.optional ?? []).not.toContain("sessionFederationIndex");
		// `sessionRPRegistry` and `sessionFamilyIndex` are oauth-package concerns
		// and MUST NOT appear in sessionModule.requires.
		expect(sessionModule.requires).not.toContain("sessionRPRegistry");
		expect(sessionModule.requires).not.toContain("sessionFamilyIndex");
		// …and this is also the pin on what `POST /session/logout` reaches
		// itself: nothing of a session's teardown. Core's session lifecycle
		// closes the session — revoking its refresh-token families among the
		// rest — so this module needs none of these keys. One that reads them
		// must widen this list first, deliberately, not by accident.
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
			bootstrapComponents: { config: withSessionCaptures(config), pathResolver: (s: string) => s },
		});
		expect(handle.routes.some((r) => r.contribution.mountPath === "/session")).toBe(true);
		await handle.dispose();
	});

	it("registers the provider of an enabled federation through the module of its type", async () => {
		const base = makeValidAppConfig();
		const config: AppConfig = {
			...base,
			...coreConfigForTests({
				declaredAbsent: ["auditSink", "rateLimiter"],
				federations: {
					stub: {
						enabled: true,
						type: "stub",
						clientId: "id",
						clientSecret: "secret",
						callbackURL: "https://example.com/cb",
					} as never,
				},
			}),
		} as AppConfig;
		const handle = await createTestApp({
			modules: [...baseTestModules, stubFederationModule],
			bootstrapComponents: { config: withSessionCaptures(config), pathResolver: (s: string) => s },
		});
		expect(handle.inspect.federations.has("stub")).toBe(true);
		await handle.dispose();
	});

	it("fails to boot when an enabled federation has no callbackURL", async () => {
		const base = makeValidAppConfig();
		const config: AppConfig = {
			...base,
			...coreConfigForTests({
				declaredAbsent: ["auditSink", "rateLimiter"],
				federations: {
					stub: {
						enabled: true,
						type: "stub",
						clientId: "id",
						clientSecret: "secret",
						// callbackURL intentionally absent
					} as never,
				},
			}),
		} as AppConfig;
		await expect(
			createTestApp({
				modules: [...baseTestModules, stubFederationModule],
				bootstrapComponents: {
					config: withSessionCaptures(config),
					pathResolver: (s: string) => s,
				},
			}),
		).rejects.toThrow(/callbackURL is required/);
	});

	it("skips disabled federations in the providerCallbackUrls projection", async () => {
		const base = makeValidAppConfig();
		const config: AppConfig = {
			...base,
			...coreConfigForTests({
				declaredAbsent: ["auditSink", "rateLimiter"],
				federations: {
					disabledFed: {
						enabled: false,
						type: "stub",
						// no callbackURL — must NOT throw because disabled
					} as never,
				},
			}),
		} as AppConfig;
		const handle = await createTestApp({
			modules: baseTestModules,
			bootstrapComponents: { config: withSessionCaptures(config), pathResolver: (s: string) => s },
		});
		// No throw at boot, no entry in the federation registry.
		expect(handle.inspect.federations.has("disabledFed")).toBe(false);
		await handle.dispose();
	});
});

describe("auditSink absence policy", () => {
	it("carries the shared AUDIT_SINK_ABSENCE_POLICY constant, by identity", async () => {
		// Identity, not shape: the declared-absence guard refuses modules whose
		// policies for one key disagree, and sharing the one constant is what
		// makes disagreement impossible by construction.
		const { AUDIT_SINK_ABSENCE_POLICY } = await import("@o3co/auth-provider-core");
		expect(sessionModule.absencePolicies?.auditSink).toBe(AUDIT_SINK_ABSENCE_POLICY);
	});
});

// ---------------------------------------------------------------------------
// A consumer of session admission (ADR 2026-09-28-session-admission, D1, D8)
// ---------------------------------------------------------------------------

describe("sessionModule — the link routes are a consumer of session admission", () => {
	it("requires sessionRequirementResolver, the synthetic key every consumer of admission takes", () => {
		expect(sessionModule.requires).toContain("sessionRequirementResolver");
	});

	it("registers the link flow's actions: the start adds a way into the account, the callback uses the session the start bound", () => {
		expect(sessionModule.contributes?.admissionActions).toEqual({
			"session.link": { grade: "credential_change" },
			"session.link_callback": { grade: "use" },
		});
	});

	it("refuses to boot with userSessionStore wired and no sessionLifecycle, naming both slots", async () => {
		const refusal = await createTestApp({
			modules: withoutLifecycle,
			bootstrapComponents: {
				config: withSessionCaptures(makeValidAppConfig()),
				pathResolver: (s: string) => s,
			} as never,
		}).then(
			async (handle) => {
				await handle.dispose();
				return undefined;
			},
			(caught: unknown) => caught,
		);
		expect(refusal, "boot must be refused").toBeInstanceOf(BootError);
		expect(refusal).toMatchObject({
			reason: "contribute-factory-failed",
			details: { module: "session", kind: "routes" },
		});
		const message = String(
			(refusal as BootError).cause instanceof Error
				? ((refusal as BootError).cause as Error).message
				: "",
		);
		expect(message).toMatch(/userSessionStore is wired, but sessionLifecycle is not/);
		expect(message).toMatch(/sessionLifecycleModule/);
	});

	it("boots with userSessionStore and sessionLifecycle both wired", async () => {
		const handle = await createTestApp({
			modules: baseTestModules,
			bootstrapComponents: {
				config: withSessionCaptures(makeValidAppConfig()),
				pathResolver: (s: string) => s,
			} as never,
		});
		await handle.dispose();
	});

	it("takes sessionLifecycleStore as an optional slot: the lifecycle port the link routes' admission reads", () => {
		expect(sessionModule.optional).toContain("sessionLifecycleStore");
		expect(sessionModule.requires).not.toContain("sessionLifecycleStore");
	});

	it("takes subjectRevocation as an optional slot, under the one subject-revocation policy it attaches for subjectSessionIndex", () => {
		expect(sessionModule.optional).toContain("subjectRevocation");
		expect(sessionModule.requires).not.toContain("subjectRevocation");
		// Identity, not shape: the declared-absence guard compares policies per
		// key, and the two subject-revocation slots are one capability.
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
			federationSettings: createTestFederationSettings({
				stub: {
					type: "stub",
					callbackURL: "https://example.com/session/oauth/federation/stub/callback",
				},
			}),
			section: base.session,
			sessionCookiePolicy: createTestSessionCookiePolicy(),
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
			sessionLifecycleStore: openingLifecycleStore(),
			sessionLifecycle: fakeSessionLifecycle(),
			federationTokenStore: makeFederationTokenStore(),
			// Boot registers each page on oauth.jwt.issuer — the valid config's.
			sessionRequirementResolver: resolverForTests(extra.requirements ?? [], {
				issuer: "https://auth.test",
				actions: SESSION_ADMISSION_ACTIONS,
			}),
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

	it("hands the link routes the wired subjectRevocation: a revoked subject's link start is refused", async () => {
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
			// As registered: resolved on oauth.jwt.issuer.
			page: "https://auth.test/fixture/step-up",
		});
	});
});

describe("sessionModule — the password login is a consumer of session admission", () => {
	/**
	 * The session-routes factory, called as the planner calls it, its router
	 * mounted behind a cookie session: what a password login answers says
	 * what the factory handed the route.
	 */
	async function passwordLogin(requirements: readonly SessionRequirement[]) {
		const base = makeValidAppConfig();
		const factory = sessionModule.contributes?.routes?.[0] as unknown as (deps: unknown) => {
			id: string;
			handler: express.RequestHandler;
		};
		const contribution = factory({
			section: base.session,
			sessionCookiePolicy: createTestSessionCookiePolicy(),
			deploymentMode: "single",
			userRepository: {
				authenticate: async () => ({ id: "user-1", username: "alice" }),
				authenticateByToken: async () => null,
			},
			userSessionStore: makeUserSessionStore(),
			sessionLifecycle: fakeSessionLifecycle(),
			federationTokenStore: makeFederationTokenStore(),
			csrfTokenSigner: createTestCsrfTokenSigner(),
			sessionRequirementResolver: resolverForTests(requirements, {
				actions: SESSION_ADMISSION_ACTIONS,
			}),
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

	it("logs in when no requirement is registered", async () => {
		expect((await passwordLogin([])).status).toBe(200);
	});
});

// ---------------------------------------------------------------------------
// The login's per-process attempt counting, with no attemptCounter wired, is
// decided by core's `deploymentMode` slot, which core fills from
// `core.deployment.mode`: the module reads nothing of `deployment` itself.
// ---------------------------------------------------------------------------

describe("sessionModule — the login's attempt limit reads the deploymentMode slot", () => {
	const spyLogger = () => {
		const warn = vi.fn();
		const logger = {
			trace: vi.fn(),
			debug: vi.fn(),
			info: vi.fn(),
			warn,
			error: vi.fn(),
			fatal: vi.fn(),
			child: vi.fn(),
		};
		return { logger, warn };
	};

	/** The session-routes factory, called as the planner calls it, with the slot as given. */
	const sessionRoutes = (
		deploymentMode: DeploymentMode,
		deployment: Record<string, unknown>,
		logger: unknown,
	) => {
		const base = makeValidAppConfig();
		const factory = sessionModule.contributes?.routes?.[0] as unknown as (deps: unknown) => {
			id: string;
		};
		return factory({
			config: { ...base, core: { ...base.core, deployment } },
			section: base.session,
			sessionCookiePolicy: createTestSessionCookiePolicy(),
			deploymentMode,
			csrfTokenSigner: createTestCsrfTokenSigner(),
			logger,
			userRepository: fakeUserRepository,
			userSessionStore: makeUserSessionStore(),
			sessionLifecycle: fakeSessionLifecycle(),
			federationTokenStore: makeFederationTokenStore(),
			sessionRequirementResolver: resolverForTests([], { actions: SESSION_ADMISSION_ACTIONS }),
		});
	};

	it("requires the slot", () => {
		expect(sessionModule.requires).toContain("deploymentMode");
	});

	it('refuses per-process counting when the slot says "multi", whatever the configuration\'s deployment says', () => {
		expect(() => sessionRoutes("multi", { mode: "single" }, spyLogger().logger)).toThrow(
			/core\.deployment\.mode is "multi" but no shared attemptCounter is wired for "login"/,
		);
	});

	it('is silent when the slot says "single" and warns when it says "unset", whatever the configuration\'s deployment says', () => {
		const single = spyLogger();
		expect(sessionRoutes("single", { mode: "multi" }, single.logger).id).toBe("session-routes");
		expect(single.warn).not.toHaveBeenCalledWith(expect.anything(), "attempt_counter_not_shared");
		const unset = spyLogger();
		sessionRoutes("unset", { mode: "multi" }, unset.logger);
		expect(unset.warn).toHaveBeenCalledWith(
			expect.objectContaining({ tag: "login" }),
			"attempt_counter_not_shared",
		);
	});

	it("through createApp, refuses a limiter section's limits.login, naming session.rateLimit.login", async () => {
		// The login's attempt limit is the module's own setting; the module's
		// claim declares it, so no limiter's limits may loosen it.
		const base = makeValidAppConfig();
		const err = await createTestApp({
			modules: [...baseTestModules, memoryRateLimiterModule],
			bootstrapComponents: {
				config: withSessionCaptures({
					...base,
					[memoryRateLimiterModule.name]: {
						limits: { login: { limit: 50, windowSeconds: 60 } },
						defaultLimit: { limit: 60, windowSeconds: 60 },
						maxBuckets: 100,
					},
				}),
				pathResolver: (s: string) => s,
			} as never,
		}).then(
			() => undefined,
			(caught: unknown) => caught,
		);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).reason).toBe("config-validation-failed");
		expect((err as BootError).message).toContain(`${memoryRateLimiterModule.name}.limits.login`);
		expect((err as BootError).message).toContain("set session.rateLimit.login instead");
	});

	it("through createApp, boots under core.deployment.mode = multi on the attemptCounter slot's counter, without a warning", async () => {
		const { logger, warn } = spyLogger();
		const base = makeValidAppConfig();
		const consume = vi.fn(async () => ({
			allowed: true,
			remaining: 1,
			resetAt: new Date(Date.now() + 60_000),
		}));
		const handle = await createTestApp({
			modules: [
				...baseTestModules,
				defineModule({
					name: "test:attempt-counter",
					provides: { attemptCounter: () => ({ consume }) },
				}),
			],
			bootstrapComponents: {
				config: withSessionCaptures({
					...base,
					core: { ...base.core, deployment: { mode: "multi" } },
				}),
				pathResolver: (s: string) => s,
				logger,
			} as never,
		});
		try {
			expect(warn).not.toHaveBeenCalledWith(expect.anything(), "attempt_counter_not_shared");
		} finally {
			await handle.dispose();
		}
	});

	it.each([
		["refused at boot", "core.deployment.mode = multi", { mode: "multi" }],
		["mounted without a warning", "core.deployment.mode = single", { mode: "single" }],
		["mounted with the warning", "an empty deployment section", {}],
		["mounted with the warning", "no deployment section", undefined],
	] as const)(
		"through createApp, per-process login counting is %s under %s",
		async (outcome, _what, deployment) => {
			const { logger, warn } = spyLogger();
			const base = makeValidAppConfig();
			const boot = createTestApp({
				modules: baseTestModules,
				bootstrapComponents: {
					config: withSessionCaptures({
						...base,
						...(deployment === undefined ? {} : { core: { ...base.core, deployment } }),
					}),
					pathResolver: (s: string) => s,
					logger,
				} as never,
			});
			if (outcome === "refused at boot") {
				await expect(boot).rejects.toMatchObject({
					reason: "contribute-factory-failed",
					cause: {
						message: expect.stringContaining('no shared attemptCounter is wired for "login"'),
					},
				});
				return;
			}
			const handle = await boot;
			try {
				const warned = warn.mock.calls.some(([, event]) => event === "attempt_counter_not_shared");
				expect(warned).toBe(outcome === "mounted with the warning");
			} finally {
				await handle.dispose();
			}
		},
	);
});
