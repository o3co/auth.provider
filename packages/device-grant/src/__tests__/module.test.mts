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

/**
 * The device-grant module's boot invariants.
 *
 * Two settings have no default and fail boot instead, for two different
 * reasons — and both reasons are the point of the test.
 */

import type {
	AttemptCounter,
	BootstrapMap,
	ClientRepository,
	CsrfGuard,
	DeviceCodeStore,
	Module,
	RateLimiter,
	RateLimitSpec,
} from "@o3co/auth-provider-core";
import {
	BootError,
	createApp,
	createInMemorySessionLifecycleStore,
	createInMemoryUserSessionStore,
	createMemoryAttemptCounter,
	createMemoryDeviceCodeStore,
	createMemoryRateLimiter,
	createMemoryReplaySeenSet,
	createSymmetricKeyStore,
	DeviceCodeStoreError,
	memoryRateLimiterModule,
} from "@o3co/auth-provider-core";
import {
	coreConfigForTests,
	createTestCsrfGuard,
	createTestOAuthTokenSettings,
	makeValidCoreConfig,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import { decodeJwt, exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import request from "supertest";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { DEVICE_GRANT_ADMISSION_ACTIONS } from "#/admissionActions.mjs";
import { deviceAuthorizationGrantModule, deviceGrantConfigSchema } from "#/module.mjs";
import { DEVICE_CODE_GRANT_TYPE } from "#/types.mjs";
import { LIVE_AUTH_TIME_MS, liveCookieSession, liveSessionStore } from "./liveSessions.mjs";
import { shippedDeviceGrantSection } from "./shippedSection.mjs";

afterEach(() => {
	vi.useRealTimers();
});

const clientRepository: ClientRepository = {
	findById: async () => null,
	authenticate: async () => null,
};

/** A logged projection's `stack`: frames only, from the first. */
const FRAMES = expect.stringMatching(/^ {4}at /);

/**
 * A projected error, held to what these routes may log without naming the
 * field its text sits in (that field is the projection's own business): its
 * `name` and stack frames, the numeric or string fields named, and none of
 * the fields that carry a request or a command's arguments — `body` (a
 * client secret), `args`, `expose`, and a command's `args` (a user code, the
 * approving subject). Core's projection keeps a command's name, and nothing
 * else of it, and a cause only as a projection of its own.
 */
const expectProjection = (err: unknown, fields: Record<string, unknown>): void => {
	expect(err).not.toBeInstanceOf(Error);
	expect(err).toMatchObject({ ...fields, stack: FRAMES });
	for (const carrier of ["body", "args", "expose"]) {
		expect(err).not.toHaveProperty(carrier);
	}
	expect(err).not.toHaveProperty(["command", "args"]);
	if (typeof err === "object" && err !== null && "cause" in err) {
		expect(err.cause).not.toBeInstanceOf(Error);
	}
};

/** The one call `mock` received as `event`, and its line — failing when there is not exactly one. */
const loggedAs = (
	mock: { mock: { calls: unknown[][] } },
	event: string,
): Record<string, unknown> => {
	const calls = mock.mock.calls.filter((call) => call[1] === event);
	expect(calls, event).toHaveLength(1);
	return calls[0]?.[0] as Record<string, unknown>;
};

/** What every device route answers a device-code store outage with. */
const STORE_UNAVAILABLE = {
	error: "temporarily_unavailable",
	error_description: "the device authorization store is unavailable; retry later",
};

const CONFIDENTIAL_ID = "backend-app";
const CONFIDENTIAL_SECRET = "s3cret-value";
const confidentialClient = {
	clientId: CONFIDENTIAL_ID,
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	allowedScopes: ["openid"],
	defaultScopes: ["openid"],
	allowedGrantTypes: [DEVICE_CODE_GRANT_TYPE],
};

const confidentialRepository: ClientRepository = {
	findById: async (id) => (id === CONFIDENTIAL_ID ? (confidentialClient as never) : null),
	authenticate: async (id, secret) =>
		id === CONFIDENTIAL_ID && secret === CONFIDENTIAL_SECRET ? (confidentialClient as never) : null,
};

interface Overrides {
	readonly deviceGrant?: Record<string, unknown>;
	readonly withStore?: boolean;
	readonly withRateLimiter?: boolean;
	/** What `core.declaredAbsent` lists. Default `["auditSink"]`. */
	readonly declaredAbsent?: readonly string[];
	/** Filled into the `attemptCounter` slot. */
	readonly attemptCounter?: AttemptCounter;
	readonly withUserSessionStore?: boolean;
	/** Leave the `sessionLifecycleStore` slot unfilled; core's session lifecycle wires it beside the user-session store. */
	readonly withSessionLifecycleStore?: boolean;
	readonly withCsrfGuard?: boolean;
	/** Leave the audit sink's absence undeclared: no `auditSink` in `core.declaredAbsent`. */
	readonly withoutAuditDeclaration?: boolean;
	/** Leave the `oauthTokenSettings` slot unfilled, as a composition without the oauth module would. */
	readonly withoutOAuthTokenSettings?: boolean;
	/** Modules listed after the device grant's. */
	readonly extraModules?: readonly Module[];
}

const makeBoot = (overrides: Overrides): BootstrapMap => {
	const core = makeValidCoreConfig();
	return {
		config: {
			...core,
			// The module attaches AUDIT_SINK_ABSENCE_POLICY, so a boot
			// with no sink must say so — which is what this fixture is.
			...(overrides.withoutAuditDeclaration === true
				? {}
				: coreConfigForTests({ declaredAbsent: overrides.declaredAbsent ?? ["auditSink"] })),
			oauth: {
				...core.oauth,
			},
			// The section as a composition layers the package's reference under it.
			"device-grant": shippedDeviceGrantSection(overrides.deviceGrant),
		},
		pathResolver: (s: string) => s,
		// What the oauth module provides, filled by hand: no oauth module here.
		...(overrides.withoutOAuthTokenSettings === true
			? {}
			: { oauthTokenSettings: createTestOAuthTokenSettings() }),
		clientRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!!"),
		...(overrides.withStore === false ? {} : { deviceCodeStore: createMemoryDeviceCodeStore() }),
		...(overrides.withUserSessionStore === false
			? {}
			: { userSessionStore: createInMemoryUserSessionStore() }),
		...(overrides.withSessionLifecycleStore === false || overrides.withUserSessionStore === false
			? {}
			: { sessionLifecycleStore: createInMemorySessionLifecycleStore() }),
		// The verification route's CSRF guard is the `csrfGuard` slot, which
		// the session module provides: core's double stands in for it.
		...(overrides.withCsrfGuard === false ? {} : { csrfGuard: createTestCsrfGuard() }),
		...(overrides.withRateLimiter === false
			? {}
			: {
					rateLimiter: createMemoryRateLimiter({
						limits: {},
						defaultLimit: { limit: 60, windowSeconds: 60 },
					}),
				}),
		...(overrides.attemptCounter === undefined ? {} : { attemptCounter: overrides.attemptCounter }),
	} as unknown as BootstrapMap;
};

/** Boot the module, which reads its switch from the configuration `createApp` parses. */
const boot = (overrides: Overrides) =>
	createApp({
		modules: [deviceAuthorizationGrantModule, ...(overrides.extraModules ?? [])],
		bootstrapComponents: makeBoot(overrides),
	});

/** What `createApp` hands a contribution: the module's section, and whatever slots the test wires. */
type TestDeps = Readonly<Record<string, unknown>>;

/** Lifetimes within the 300 s access token these tests configure, which every reader holds a slot to. */
const WITHIN_CONFIGURATION = { accessTokenLifetime: { defaultExpiresIn: 300, maxExpiresIn: 300 } };

/** The section `written` lays over the shipped one, parsed as boot parses it. */
const sectionOf = (written: Readonly<Record<string, unknown>>) =>
	deviceGrantConfigSchema.parse(shippedDeviceGrantSection(written));

/** The contributions of the module, as `createApp` calls each factory with its deps. */
const contributionsFor = (_deps?: TestDeps) => {
	const contributes = deviceAuthorizationGrantModule.contributes;
	type Factory = (d: unknown) => unknown;
	const handed =
		(factory: unknown): Factory =>
		(d) =>
			(factory as Factory)(d);
	const each = (kind: Readonly<Record<string, unknown>> | undefined) =>
		kind === undefined
			? undefined
			: Object.fromEntries(Object.entries(kind).map(([key, factory]) => [key, handed(factory)]));
	return {
		routes: contributes?.routes?.map(handed),
		discoveryMetadata: contributes?.discoveryMetadata?.map(handed),
		grants: each(contributes?.grants),
		rateLimitBudgets: each(contributes?.rateLimitBudgets),
	};
};

const ENABLED = {
	enabled: true,
	verificationUri: "https://example.test/device",
};

describe("the device-grant module — boot", () => {
	it("boots disabled without any of the required settings", async () => {
		// Installing the package must not turn on a grant, and a deployment
		// that leaves it off must never trip settings it does not use.
		const handle = await boot({});
		await handle.dispose();
	});

	it("refuses a limiter section's limits.device_verification, naming device-grant.rateLimit", async () => {
		// The verification's attempt limit is the module's own setting; the
		// module's claim declares it, so no limiter's limits may loosen it.
		const bootstrap = makeBoot({ withRateLimiter: false });
		const err = await createApp({
			modules: [deviceAuthorizationGrantModule, memoryRateLimiterModule],
			bootstrapComponents: {
				...bootstrap,
				config: {
					...bootstrap.config,
					[memoryRateLimiterModule.name]: {
						limits: { device_verification: { limit: 50, windowSeconds: 60 } },
						defaultLimit: { limit: 60, windowSeconds: 60 },
						maxBuckets: 100,
					},
				} as never,
			},
		}).then(
			() => undefined,
			(caught: unknown) => caught,
		);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).reason).toBe("config-validation-failed");
		expect((err as BootError).message).toContain(
			`${memoryRateLimiterModule.name}.limits.device_verification`,
		);
		expect((err as BootError).message).toContain("set device-grant.rateLimit instead");
	});

	it("refuses to boot enabled without a verificationUri", async () => {
		// No default is possible: the page belongs to the deployment, and the
		// device displays this string verbatim to people who need to reach it.
		await expect(boot({ deviceGrant: { enabled: true } })).rejects.toThrow(/verificationUri/);
	});

	it("boots enabled without a rate limiter once its absence is declared: device_authorization passes through", async () => {
		// The rate limiter is the deployment's abuse control, not the user
		// code's attempt limit, which the attempt guard counts.
		const handle = await boot({
			deviceGrant: ENABLED,
			withRateLimiter: false,
			declaredAbsent: ["auditSink", "rateLimiter"],
		});
		try {
			const app = express();
			app.use(handle.router);
			for (let i = 0; i < 65; i++) {
				const res = await request(app)
					.post("/oauth/device_authorization")
					.send({ client_id: CONFIDENTIAL_ID });
				expect(res.status).toBe(401);
				expect(res.headers["ratelimit-limit"]).toBeUndefined();
			}
		} finally {
			await handle.dispose();
		}
	});

	it("refuses to boot enabled without a rate limiter or its declaration, as core's absence policy does", async () => {
		const err = await boot({ deviceGrant: ENABLED, withRateLimiter: false }).then(
			() => undefined,
			(caught: unknown) => caught,
		);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).reason).toBe("component-absence-undeclared");
		expect((err as BootError).message).toContain("rateLimiter");
	});

	it("refuses to boot enabled without a userSessionStore, naming the component", async () => {
		// An approval turns the browser session into a device token that
		// carries no `sid` and no `family_id`, so nothing a logout or a
		// credential change does afterwards reaches it. Whether the session
		// behind the cookie is still live is the one question the approval can
		// ask, and without the store it cannot — so an enabled grant without
		// one is a boot refusal, as a missing limiter is, not an endpoint that
		// trusts the cookie alone.
		await expect(boot({ deviceGrant: ENABLED, withUserSessionStore: false })).rejects.toThrow(
			/enabled = true requires a userSessionStore component/,
		);
	});

	it("refuses to boot enabled with a userSessionStore and no sessionLifecycleStore, naming both slots", async () => {
		const err = await boot({ deviceGrant: ENABLED, withSessionLifecycleStore: false }).then(
			async (handle) => {
				await handle.dispose();
				return undefined;
			},
			(caught: unknown) => caught as BootError,
		);
		expect(err, "boot must be refused").toBeInstanceOf(BootError);
		expect(err?.reason).toBe("contribute-factory-failed");
		expect(err?.message).toMatch(
			/device-grant: userSessionStore is wired, but sessionLifecycleStore is not\.[\s\S]*Install sessionLifecycleModule/,
		);
	});

	it("refuses to boot enabled without a csrfGuard, naming the component", async () => {
		// POST /oauth/device/verification authorises on the session cookie, the
		// credential a browser attaches to a request another site made (RFC 8628
		// §5.4), and runs the one CSRF policy the session module provides as the
		// `csrfGuard` slot. Enabled without it, the endpoint would be
		// mounted with no CSRF defence, so boot is refused, as without a limiter.
		await expect(boot({ deviceGrant: ENABLED, withCsrfGuard: false })).rejects.toThrow(
			/enabled = true requires a csrfGuard component/,
		);
	});

	/** Boot the enabled grant with `csrfGuard` in the slot, filled by hand. */
	const bootWithGuard = (csrfGuard: unknown) => {
		const bootstrapComponents = {
			...makeBoot({ deviceGrant: ENABLED }),
			csrfGuard,
		} as unknown as BootstrapMap;
		return createApp({ modules: [deviceAuthorizationGrantModule], bootstrapComponents });
	};

	it.each([
		["absent", undefined],
		["not a function", "middleware"],
		// Express skips a four-parameter function on every request: it is an error handler.
		["an error handler", (_err: unknown, _req: unknown, _res: unknown, next: () => void) => next()],
	])(
		"refuses to boot enabled with a csrfGuard whose middleware is %s, naming the slot",
		async (_, middleware) => {
			// The verification route mounts the guard's `middleware`; a guard filled
			// by hand without a usable one is refused by name, before the route is built.
			await expect(bootWithGuard({ ...createTestCsrfGuard(), middleware })).rejects.toThrow(
				/csrfGuard\.middleware is not a request handler.*sessionModule/s,
			);
		},
	);

	const throwing = {
		get: () => {
			throw new Error("adapter unavailable");
		},
	};
	it.each([
		[
			"middleware",
			() => Object.defineProperty({ ...createTestCsrfGuard() }, "middleware", throwing),
		],
		[
			"middleware's arity",
			() => ({
				...createTestCsrfGuard(),
				middleware: Object.defineProperty(() => undefined, "length", throwing),
			}),
		],
	])(
		"refuses to boot enabled with a csrfGuard whose %s cannot be read, naming the slot",
		async (_, guard) => {
			// The getter's own error stays reachable as the refusal's `cause`.
			await expect(bootWithGuard(guard())).rejects.toMatchObject({
				cause: {
					message: expect.stringMatching(/csrfGuard\.middleware could not be read/),
					cause: { message: "adapter unavailable" },
				},
			});
		},
	);

	it("boots disabled without a csrfGuard", async () => {
		// The slot is optional in the manifest: a deployment that installs the
		// package and leaves the grant off mounts no verification route.
		const handle = await boot({ withCsrfGuard: false });
		await handle.dispose();
	});

	it("takes csrfGuard as an optional slot, and imports nothing of the session package", () => {
		const installed = deviceAuthorizationGrantModule;
		expect(installed.optional).toContain("csrfGuard");
		expect(installed.requires).not.toContain("csrfGuard");
	});

	it("boots disabled without a userSessionStore", async () => {
		// The slot stays optional in the manifest: a deployment that installs
		// the package and leaves the grant off has no approvals to check.
		const handle = await boot({ withUserSessionStore: false });
		await handle.dispose();
	});

	it("refuses to boot enabled without a device code store, naming the component", async () => {
		// Optional to wire, required once the grant is on: a composition with
		// no store cannot authorize any device at all, so the failure belongs at
		// boot rather than on the first request, beside `rateLimiter` and
		// `verificationUri`.
		await expect(boot({ deviceGrant: ENABLED, withStore: false })).rejects.toThrow(
			/enabled = true requires a deviceCodeStore component/,
		);
	});

	it("boots with the grant off and no store, declaring nothing: a switched-off module requires nothing", async () => {
		const handle = await boot({
			deviceGrant: { enabled: false },
			withStore: false,
			withoutAuditDeclaration: true,
		});
		await handle.dispose();
	});

	it.each([
		["off", "unsupported", { enabled: false }],
		["off", "redis", { enabled: false }],
		["on", "unsupported", ENABLED],
		["on", true, ENABLED],
	])(
		"refuses device-grant.store with the grant %s, at %j, as a removed key",
		async (_, store, deviceGrant) => {
			// No value of it declares anything: the grant needs a store while on
			// and nothing while off. Ignored, a stale line would read as a
			// decision the deployment still makes.
			const refusal = await boot({ deviceGrant: { ...deviceGrant, store } }).then(
				async (handle) => {
					await handle.dispose();
					return undefined;
				},
				(err: unknown) => err as { reason?: unknown; message?: string; details?: unknown },
			);
			expect(refusal).toMatchObject({
				name: "BootError",
				reason: "config-path-relocated",
				details: {
					relocated: [{ module: "device-grant", from: "device-grant.store", to: null }],
				},
			});
			expect(refusal?.message).toMatch(/device-grant\.store was removed/);
		},
	);

	it("boots with everything wired, without oauthEndpointsModule", async () => {
		// The routes declare no ordering edge — each module under `/oauth`
		// parses its own body — so nothing here needs another module's route
		// to exist. The composition beside oauthEndpointsModule is composition.test.mts.
		const handle = await boot({ deviceGrant: ENABLED });
		await handle.dispose();
	});

	it("refuses to boot enabled without oauthTokenSettings, naming the slot", async () => {
		// The issuer client authentication checks an assertion's audience
		// against, the device token's lifetime and the email-verified gate are
		// the oauth module's: the grant reads them from the slot alone, never
		// from the configuration.
		await expect(boot({ deviceGrant: ENABLED, withoutOAuthTokenSettings: true })).rejects.toThrow(
			/oauthTokenSettings/,
		);
	});

	it("boots disabled without oauthTokenSettings: switched off, the module requires nothing", async () => {
		const handle = await boot({ withoutOAuthTokenSettings: true });
		await handle.dispose();
	});

	it.each([
		["true", true],
		["false", false],
	])(
		"reads the switch written as an environment variable's %j, as its section's schema reads it",
		async (written, on) => {
			const handle = await boot({ deviceGrant: { ...ENABLED, enabled: written } });
			try {
				expect(
					handle.components.grantHandlerResolver?.get(DEVICE_CODE_GRANT_TYPE) !== undefined,
				).toBe(on);
			} finally {
				await handle.dispose();
			}
		},
	);

	it("reads an absent switch as off: a section without enabled registers nothing", async () => {
		const { enabled: _enabled, ...withoutSwitch } = shippedDeviceGrantSection(ENABLED);
		const bootstrapComponents = makeBoot({});
		const handle = await createApp({
			modules: [deviceAuthorizationGrantModule],
			bootstrapComponents: {
				...bootstrapComponents,
				config: { ...bootstrapComponents.config, "device-grant": withoutSwitch },
			} as unknown as BootstrapMap,
		});
		try {
			expect(handle.components.grantHandlerResolver?.get(DEVICE_CODE_GRANT_TYPE)).toBeUndefined();
		} finally {
			await handle.dispose();
		}
	});

	it("refuses to boot with no audit sink unless core.declaredAbsent lists it", async () => {
		// On the decision that turns a code into a token, `auditSink` is
		// optional to wire, not optional to decide. A composition that
		// silently discards every device approval must have written that down.
		await expect(boot({ deviceGrant: ENABLED, withoutAuditDeclaration: true })).rejects.toThrow(
			/core\.declaredAbsent/,
		);
	});
});

describe("the device-grant module — the actions it registers", () => {
	it("registers the three body actions device verification admits, lookup and deny granting nothing", async () => {
		const handle = await boot({ deviceGrant: ENABLED });
		try {
			const resolver = handle.components.sessionRequirementResolver;
			expect(
				["device.lookup", "device.approve", "device.deny"].map((name) => resolver?.action(name)),
			).toEqual([
				{ name: "device.lookup", grade: "grants_nothing" },
				{ name: "device.approve", grade: "use" },
				{ name: "device.deny", grade: "grants_nothing" },
			]);
		} finally {
			await handle.dispose();
		}
	});

	it("registers none while the grant is off: nothing admits them", async () => {
		const handle = await boot({});
		try {
			expect(handle.components.sessionRequirementResolver?.action("device.lookup")).toBeUndefined();
		} finally {
			await handle.dispose();
		}
	});

	it("exports what it registers, for a composition that mounts the verification handler itself", async () => {
		const { DEVICE_GRANT_ADMISSION_ACTIONS } = await import("#/index.mjs");
		expect(DEVICE_GRANT_ADMISSION_ACTIONS).toEqual({
			"device.lookup": { grade: "grants_nothing" },
			"device.approve": { grade: "use" },
			"device.deny": { grade: "grants_nothing" },
		});
	});
});

describe("the device-grant module — discovery (RFC 8628 §4)", () => {
	it("contributes the endpoint as an issuer-relative path when enabled", () => {
		// A client has no other way to find the endpoint, so the metadata is
		// the feature being reachable rather than a description of it. Under
		// `endpoints`, not `metadata`: core prefixes the issuer and refuses an
		// `*_endpoint` literal — the served document is pinned end to end in
		// composition.test.mts.
		const deps = { section: sectionOf(ENABLED) };
		const contribution = contributionsFor(deps)?.discoveryMetadata?.[0] as (
			deps: unknown,
		) => Record<string, unknown>;
		const result = contribution(deps);
		expect(result).toEqual({
			endpoints: { device_authorization_endpoint: "/oauth/device_authorization" },
		});
	});

	it("advertises nothing when disabled: the switch reads off, so boot runs none of its factories", () => {
		// The discovery document must not claim a capability the deployment
		// does not have; the document served is pinned in composition.test.mts.
		expect(deviceAuthorizationGrantModule.section?.isEnabled?.(sectionOf({ enabled: false }))).toBe(
			false,
		);
	});
});

describe("the device-grant module — the route it actually contributes", () => {
	/** Build the contributed router and mount it, as `assembleApp` would. */
	const mountContributedRoute = (index: number, deps: TestDeps) => {
		const factory = contributionsFor(deps)?.routes?.[index] as (d: unknown) => {
			mountPath: string;
			handler: express.RequestHandler;
		};
		const route = factory(deps);
		const app = express();
		app.use(route.mountPath, route.handler);
		return app;
	};

	const enabledDeps = (overrides: { limits?: Record<string, RateLimitSpec> } = {}) => ({
		// The synthetic key boot fills from `core.deployment.mode`.
		deploymentMode: "single",
		section: sectionOf({
			enabled: true,
			verificationUri: "https://example.test/device",
			verificationUriComplete: false,
			codeLifetimeSeconds: 600,
			pollingIntervalSeconds: 5,
			rateLimit: { limit: 5, windowSeconds: 300 },
		}),
		// What the oauth module provides: the issuer and the lifetimes.
		oauthTokenSettings: createTestOAuthTokenSettings({
			...WITHIN_CONFIGURATION,
			issuer: "https://as.example.test",
		}),
		clientRepository: confidentialRepository,
		deviceCodeStore: createMemoryDeviceCodeStore(),
		userSessionStore: liveSessionStore(),
		sessionLifecycleStore: createInMemorySessionLifecycleStore(),
		// The `csrfGuard` slot: core's double, which accepts this origin.
		csrfGuard: createTestCsrfGuard(),
		// The synthetic key the planner fills (the session-admission ADR's D1).
		sessionRequirementResolver: resolverForTests([], { actions: DEVICE_GRANT_ADMISSION_ACTIONS }),
		rateLimiter: createMemoryRateLimiter({
			limits: { ...(overrides.limits ?? {}) },
			defaultLimit: { limit: 60, windowSeconds: 60 },
		}),
	});

	it("enforces client authentication on the mounted device_authorization route", async () => {
		// The handler trusts `req.oauthClient`, so whether a confidential
		// client can be impersonated depends on the module *mounting* the
		// middleware — which no test of the handler alone can observe.
		const app = mountContributedRoute(0, enabledDeps());
		const res = await request(app)
			.post("/oauth/device_authorization")
			.send({ client_id: CONFIDENTIAL_ID });

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_client");
		// Asserted on the *middleware's* wording specifically. The handler
		// also refuses an absent `req.oauthClient` — a deliberate fail-closed
		// backstop — so a looser matcher would pass on that instead and stop
		// noticing if the middleware were unmounted, which is the one thing
		// this test exists to catch.
		expect(res.body.error_description).toContain("confidential clients");
	});

	it("lets an authenticated confidential client through the mounted route", async () => {
		const app = mountContributedRoute(0, enabledDeps());
		const res = await request(app)
			.post("/oauth/device_authorization")
			.auth(CONFIDENTIAL_ID, CONFIDENTIAL_SECRET)
			.send({});

		expect(res.status).toBe(200);
		expect(typeof res.body.device_code).toBe("string");
	});

	it("rate-limits the mounted device_authorization route, ahead of client authentication", async () => {
		// Every other public entry point sits behind `createRateLimitGuard`, and
		// so does this one: its store is what an unthrottled caller would fill.
		// The guard is mounted BEFORE client auth, as on the token endpoint:
		// the second unauthenticated hit is throttled, not 401'd,
		// which is what bounds repository lookups from a caller with no
		// credentials at all.
		const app = mountContributedRoute(
			0,
			enabledDeps({ limits: { device_authorization: { limit: 1, windowSeconds: 60 } } }),
		);

		const first = await request(app)
			.post("/oauth/device_authorization")
			.send({ client_id: CONFIDENTIAL_ID });
		expect(first.status).toBe(401);
		expect(first.headers["ratelimit-limit"]).toBe("1");

		const second = await request(app)
			.post("/oauth/device_authorization")
			.send({ client_id: CONFIDENTIAL_ID });
		expect(second.status).toBe(429);
		expect(second.body.error).toBe("rate_limited");
		expect(second.headers["retry-after"]).toBeDefined();
	});

	it("counts an oversized device_authorization request against the per-IP budget", async () => {
		// federation-grants' order: the throttle ahead of the size check, so a
		// caller cannot send oversized bodies without spending attempts. With
		// the check first, the 413 was free and the next request still found
		// the whole budget.
		const app = mountContributedRoute(
			0,
			enabledDeps({ limits: { device_authorization: { limit: 1, windowSeconds: 60 } } }),
		);

		const oversized = await request(app)
			.post("/oauth/device_authorization")
			.auth(CONFIDENTIAL_ID, CONFIDENTIAL_SECRET)
			.send({ padding: "x".repeat(40_000) });
		expect(oversized.status).toBe(413);
		expect(oversized.headers["ratelimit-limit"]).toBe("1");

		const next = await request(app)
			.post("/oauth/device_authorization")
			.auth(CONFIDENTIAL_ID, CONFIDENTIAL_SECRET)
			.send({});
		expect(next.status).toBe(429);
	});

	it("passes device_authorization through with no rate limiter wired", async () => {
		const { rateLimiter: _rateLimiter, ...deps } = enabledDeps();
		const app = mountContributedRoute(0, deps);
		for (let i = 0; i < 65; i++) {
			const res = await request(app)
				.post("/oauth/device_authorization")
				.send({ client_id: CONFIDENTIAL_ID });
			expect(res.status).toBe(401);
			expect(res.headers["ratelimit-limit"]).toBeUndefined();
		}
	});

	it.each([0, 1])("mounts route %i with no configuration at all", (index) => {
		const deps = enabledDeps();
		expect(deps).not.toHaveProperty("config");
		const factory = contributionsFor(deps)?.routes?.[index] as (d: unknown) => unknown;
		expect(() => factory(deps)).not.toThrow();
	});

	/** Mount the contributed verification route behind a fixed end-user session. */
	const mountVerificationRoute = (deps: TestDeps) => {
		const factory = contributionsFor(deps)?.routes?.[1] as (d: unknown) => {
			mountPath: string;
			handler: express.RequestHandler;
		};
		const route = factory(deps);
		const app = express();
		app.use((req, _res, next) => {
			(req as unknown as { session: unknown }).session = liveCookieSession();
			next();
		});
		app.use(route.mountPath, route.handler);
		return app;
	};

	it("runs the csrfGuard it is handed in front of the whole route, with no session.* in the configuration", async () => {
		// The guard is the slot's, not one rebuilt from the session's
		// configuration: `enabledDeps` carries no configuration, and a
		// guard that refuses everything refuses a request the handler would
		// otherwise answer, whatever its action.
		const refusing: CsrfGuard = Object.freeze({
			...createTestCsrfGuard(),
			middleware: (_req: express.Request, res: express.Response) => {
				res.status(403).json({ error: "access_denied", error_description: "refused by the slot" });
			},
		});
		const deps = { ...enabledDeps(), csrfGuard: refusing };
		expect(deps).not.toHaveProperty("config");
		const app = mountVerificationRoute(deps);
		for (const action of ["lookup", "approve", "deny"]) {
			const res = await request(app)
				.post("/oauth/device/verification")
				.send({ action, user_code: "BCDF-GHJK" });
			expect(res.status).toBe(403);
			expect(res.body.error_description).toBe("refused by the slot");
		}
	});

	/**
	 * The mounted route reads the wall clock, and an approval from a session
	 * that authenticated ahead of it is refused before the email gate: held at
	 * the fixed sessions' authentication instant while `run` runs.
	 */
	const atLiveAuthTime = async (run: () => Promise<void>): Promise<void> => {
		vi.useFakeTimers({ toFake: ["Date"], now: LIVE_AUTH_TIME_MS });
		try {
			await run();
		} finally {
			vi.useRealTimers();
		}
	};

	it("holds an approval to requireEmailVerified of the oauthTokenSettings a module provides", () =>
		atLiveAuthTime(async () => {
			// The slot turns it on, and the signed-in user-1 has no verified email.
			const app = mountVerificationRoute({
				...enabledDeps(),
				oauthTokenSettings: createTestOAuthTokenSettings({
					...WITHIN_CONFIGURATION,
					requireEmailVerified: true,
				}),
			});
			const res = await request(app)
				.post("/oauth/device/verification")
				.set("Host", "as.example.test")
				.set("Origin", "http://as.example.test")
				.send({ action: "approve", user_code: "BCDF-GHJK" });
			expect(res.status).toBe(403);
			expect(res.body).toEqual({
				error: "access_denied",
				error_description: "email address is not verified",
			});
		}));

	it("reads no requireEmailVerified from the configuration: the slot's false approves as the setting off does", () =>
		atLiveAuthTime(async () => {
			// A configuration that turns it on, handed beside a slot that says
			// false: the module reads the slot alone.
			const approve = (deps: TestDeps) =>
				request(mountVerificationRoute(deps))
					.post("/oauth/device/verification")
					.set("Host", "as.example.test")
					.set("Origin", "http://as.example.test")
					.send({ action: "approve", user_code: "BCDF-GHJK" });
			const res = await approve({
				...enabledDeps(),
				config: { oauth: { requireEmailVerified: true } },
				oauthTokenSettings: createTestOAuthTokenSettings({
					...WITHIN_CONFIGURATION,
					requireEmailVerified: false,
				}),
			});
			const off = await approve(enabledDeps());
			expect(res.status).not.toBe(403);
			expect(res.status).toBe(off.status);
			expect(res.body).toEqual(off.body);
		}));

	/** A limiter whose backend is down: every check rejects, as a Redis client would. */
	const brokenLimiter: RateLimiter = {
		kind: "broken",
		check: async () => {
			throw new Error("redis down");
		},
	};

	/** A lookup on the mounted verification route. */
	const lookup = (app: express.Express) =>
		request(app)
			.post("/oauth/device/verification")
			.set("Host", "as.example.test")
			.set("Origin", "http://as.example.test")
			.send({ action: "lookup", user_code: "BCDF-GHJK" });

	it("counts the verification's attempts on the attemptCounter slot, under the subject, against device-grant.rateLimit", async () => {
		// What no test of the handler alone can observe: that the module hands
		// this route the slot's counter and the section's limit.
		const calls: { key: string; spec: unknown }[] = [];
		const inner = createMemoryAttemptCounter();
		const attemptCounter: AttemptCounter = {
			consume: (key, spec) => {
				calls.push({ key, spec });
				return inner.consume(key, spec);
			},
		};
		const deps = enabledDeps();
		const app = mountVerificationRoute({
			...deps,
			section: { ...deps.section, rateLimit: { limit: 2, windowSeconds: 120 } },
			attemptCounter,
		});

		expect((await lookup(app)).status).toBe(404);
		expect((await lookup(app)).status).toBe(404);
		const limited = await lookup(app);
		expect(limited.status).toBe(429);
		expect(limited.body.error).toBe("slow_down");
		expect(calls.map(({ key }) => key)).toEqual(Array(3).fill("device_verification:user:user-1"));
		expect(calls[0]?.spec).toEqual({ limit: 2, windowSeconds: 120 });
	});

	it.each(["closed", "open"] as const)(
		"answers 503 while the attempt counter is down, whatever a limiter with failMode = %s says",
		async (failMode) => {
			const app = mountVerificationRoute({
				...enabledDeps(),
				rateLimiter: { ...brokenLimiter, failMode },
				attemptCounter: {
					consume: async () => {
						throw new Error("redis down");
					},
				} satisfies AttemptCounter,
			});
			const res = await lookup(app);
			expect(res.status).toBe(503);
			expect(res.body).toEqual({
				error: "service_unavailable",
				error_description: "Attempt counter temporarily unavailable",
			});
		},
	);

	it("asks no rate limiter on the verification route: a limiter that is down changes nothing there", async () => {
		const check = vi.fn(brokenLimiter.check);
		const app = mountVerificationRoute({
			...enabledDeps(),
			rateLimiter: { kind: "broken", failMode: "closed", check } satisfies RateLimiter,
		});
		expect((await lookup(app)).status).toBe(404);
		expect(check).not.toHaveBeenCalled();
	});

	it('refuses to mount device/verification under "multi" with no attemptCounter, naming it', () => {
		const deps = { ...enabledDeps(), deploymentMode: "multi" };
		const factory = contributionsFor(deps)?.routes?.[1] as (d: unknown) => unknown;
		expect(() => factory(deps)).toThrow(
			/core\.deployment\.mode is "multi" but no shared attemptCounter is wired for "device_verification"/,
		);
		expect(() => factory({ ...deps, attemptCounter: createMemoryAttemptCounter() })).not.toThrow();
	});

	it("hands the verification route the resolver the planner built: a requirement's step-up reaches approve", async () => {
		// The session-admission ADR's D1: the module requires the synthetic key
		// and hands it on; what a requirement answers is what the route answers.
		const deps = enabledDeps();
		const app = mountVerificationRoute({
			...deps,
			sessionRequirementResolver: resolverForTests(
				[
					{
						name: "fixture",
						reach: new Set<string>(),
						stepUpPage: { url: "/step-up", params: {} },
						remediations: [],
						hintKeys: [],
						admit: async ({ action }) =>
							action.name === "device.approve"
								? { outcome: "step_up", whenStillUnmet: "reauthenticate" }
								: { outcome: "met" },
					},
				],
				{
					...// Boot registers each page on oauth.jwt.issuer.
					{ issuer: "https://as.example.test" },
					actions: DEVICE_GRANT_ADMISSION_ACTIONS,
				},
			),
		});
		const verify = (action: string) =>
			request(app)
				.post("/oauth/device/verification")
				.set("Host", "as.example.test")
				.set("Origin", "http://as.example.test")
				.send({ action, user_code: "BCDF-GHJK" });
		const approve = await verify("approve");
		expect(approve.status).toBe(403);
		expect(approve.body).toMatchObject({
			error: "step_up_required",
			requirement: "fixture",
			// Resolved at registration on the issuer, oauth.jwt.issuer.
			page: "https://as.example.test/step-up",
		});
		expect((await verify("lookup")).status).toBe(404);
	});

	it("refuses to mount device/verification without the resolver — a hand-built composition cannot run it unasked", () => {
		const { sessionRequirementResolver: _omitted, ...deps } = enabledDeps();
		const factory = contributionsFor(deps)?.routes?.[1] as (d: unknown) => unknown;
		expect(() => factory(deps)).toThrow(/requirements/);
	});

	/**
	 * A logger that keeps every line as a JSON log shipper would write it:
	 * an `Error` with all of its own properties, not only the enumerable ones.
	 */
	const serialisingLogger = () => {
		const lines: string[] = [];
		const serialise = (value: unknown): string =>
			JSON.stringify(value, (_key, v: unknown) =>
				v instanceof Error
					? Object.fromEntries(
							Object.getOwnPropertyNames(v).map((k) => [
								k,
								(v as unknown as Record<string, unknown>)[k],
							]),
						)
					: v,
			);
		const record = (level: string) =>
			vi.fn((obj: Record<string, unknown>, msg?: string) => {
				lines.push(`${level} ${msg ?? ""} ${serialise(obj)}`);
			});
		return {
			lines,
			logger: {
				warn: record("warn"),
				info: record("info"),
				error: record("error"),
				debug: record("debug"),
			},
		};
	};

	it("answers a device-code store that throws on the verification route with JSON 503, and logs a projection of it", async () => {
		// RFC 8628 §3.2 → RFC 6749 §5.2: this API answers in JSON, a failure
		// included. A store that throws is the host's outage, not the
		// caller's business: `503 temporarily_unavailable` with a fixed
		// description, and in the log a projection of the error — never the
		// error itself. An ioredis reply error carries the command's arguments
		// (the user code, the approving subject); a body-parser error carries
		// the body.
		const deps = enabledDeps();
		const { lines, logger } = serialisingLogger();
		const replyError = Object.assign(
			new Error("READONLY You can't write against a read only replica."),
			{
				name: "ReplyError",
				command: { name: "evalsha", args: ["devauth:{devauth}:user:BCDFGHJK", "user-1"] },
				body: "client_secret=s3cret-value",
			},
		);
		const app = mountVerificationRoute({
			...deps,
			logger,
			deviceCodeStore: {
				...deps.deviceCodeStore,
				findPendingByUserCode: async () => {
					throw replyError;
				},
			},
		});

		const res = await request(app)
			.post("/oauth/device/verification")
			.set("Host", "as.example.test")
			.set("Origin", "http://as.example.test")
			.send({ action: "lookup", user_code: "BCDF-GHJK" });

		expect(res.status).toBe(503);
		expect(res.headers["content-type"]).toMatch(/^application\/json/);
		expect(res.headers["cache-control"]).toBe("no-store");
		expect(res.body).toEqual(STORE_UNAVAILABLE);
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{
				action: "lookup",
				err: {
					name: "ReplyError",
					detail: "READONLY You can't write against a read only replica.",
					command: { name: "evalsha" },
					stack: FRAMES,
				},
			},
			"device_verification_store_unavailable",
		);
		for (const line of lines) {
			expect(line).not.toContain("BCDFGHJK");
			expect(line).not.toContain("user-1");
			expect(line).not.toContain("s3cret-value");
		}
	});

	it("answers an unexpected failure on the mounted device/verification route with JSON 500, and logs a projection of it", async () => {
		// A logger that throws on the decision's line is a failure of the
		// host's code, not an outage and not the caller's mistake.
		const deps = enabledDeps();
		const { logger } = serialisingLogger();
		const app = mountVerificationRoute({
			...deps,
			logger: {
				...logger,
				info: () => {
					throw new TypeError("the info channel is broken");
				},
			},
			deviceCodeStore: {
				...deps.deviceCodeStore,
				deny: async () => ({
					status: "ok" as const,
					authorization: {
						userCode: "BCDFGHJK",
						clientId: "tv-app",
						requestedScope: undefined,
						expiresAtMs: Date.now() + 600_000,
						intervalSeconds: 5,
						status: "denied" as const,
						subject: undefined,
						grantedScope: undefined,
						approvedAtMs: undefined,
						amr: undefined,
						authTimeMs: undefined,
					},
				}),
			},
		});

		const res = await request(app)
			.post("/oauth/device/verification")
			.set("Host", "as.example.test")
			.set("Origin", "http://as.example.test")
			.send({ action: "deny", user_code: "BCDF-GHJK" });

		expect(res.status).toBe(500);
		expect(res.headers["content-type"]).toMatch(/^application\/json/);
		expect(res.headers["cache-control"]).toBe("no-store");
		expect(res.body).toEqual({ error: "server_error", error_description: "unexpected_error" });
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{ err: expect.anything() },
			"device_route_unexpected_error",
		);
		expectProjection(loggedAs(logger.error, "device_route_unexpected_error").err, {
			name: "TypeError",
		});
	});

	it("answers an unexpected failure on the mounted device_authorization route with JSON 500, and logs a projection of it", async () => {
		// A rate limiter that answers a decision whose `resetAt` is not a
		// `Date` is a failure of the host's adapter, not of the request: the
		// throttle in front of the route fails on it.
		// Chosen because no fault this package owns escapes the handler: its
		// store errors are answered, and a malformed registration is refused
		// before it (see the test below).
		const { lines, logger } = serialisingLogger();
		const app = mountContributedRoute(0, {
			...enabledDeps(),
			logger,
			rateLimiter: {
				kind: "buggy",
				check: async () =>
					({ allowed: true, resetAt: "soon" }) as unknown as Awaited<
						ReturnType<RateLimiter["check"]>
					>,
			} satisfies RateLimiter,
		});

		const res = await request(app)
			.post("/oauth/device_authorization")
			.auth(CONFIDENTIAL_ID, CONFIDENTIAL_SECRET)
			.send({});

		expect(res.status).toBe(500);
		expect(res.headers["content-type"]).toMatch(/^application\/json/);
		expect(res.headers["cache-control"]).toBe("no-store");
		expect(res.body).toEqual({ error: "server_error", error_description: "unexpected_error" });
		// The frames are what an operator finds the failing code by — and the
		// header line, which repeats the message, is not among them.
		expect(logger.error).toHaveBeenCalledWith(
			{
				err: {
					name: "TypeError",
					detail: expect.any(String),
					stack: FRAMES,
				},
			},
			"device_route_unexpected_error",
		);
		for (const line of lines) {
			expect(line).not.toContain(CONFIDENTIAL_SECRET);
			expect(line).not.toContain("TypeError:");
		}
	});

	it("answers a client whose registration the boundary refuses 503 on the mounted device_authorization route", async () => {
		// `defaultScopes` a string rather than a list: the client authentication
		// reads registrations through core's client-record boundary, which
		// refuses the record, so the lookup rejects and the handler never sees it.
		const { lines, logger } = serialisingLogger();
		const malformed = { ...confidentialClient, defaultScopes: "openid" };
		const app = mountContributedRoute(0, {
			...enabledDeps(),
			logger,
			clientRepository: {
				findById: async (id: string) => (id === CONFIDENTIAL_ID ? (malformed as never) : null),
				authenticate: async (id: string, secret: string) =>
					id === CONFIDENTIAL_ID && secret === CONFIDENTIAL_SECRET ? (malformed as never) : null,
			} satisfies ClientRepository,
		});

		const res = await request(app)
			.post("/oauth/device_authorization")
			.auth(CONFIDENTIAL_ID, CONFIDENTIAL_SECRET)
			.send({});

		expect(res.status).toBe(503);
		expect(res.body.error).toBe("temporarily_unavailable");
		expect(logger.warn).toHaveBeenCalledTimes(1);
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ step: "find", clientId: CONFIDENTIAL_ID }),
			"client_record_refused",
		);
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({
				step: "find",
				err: expect.objectContaining({ reason: "client_record_refused" }),
			}),
			"client_repository_unavailable",
		);
		for (const line of lines) expect(line).not.toContain(CONFIDENTIAL_SECRET);
	});

	/** The verification route, signed in, with a store whose lookup throws `thrown`. */
	const lookupThrowing = async (thrown: unknown) => {
		const deps = enabledDeps();
		const { lines, logger } = serialisingLogger();
		const app = mountVerificationRoute({
			...deps,
			logger,
			deviceCodeStore: {
				...deps.deviceCodeStore,
				findPendingByUserCode: async () => {
					throw thrown;
				},
			},
		});
		const res = await request(app)
			.post("/oauth/device/verification")
			.set("Host", "as.example.test")
			.set("Origin", "http://as.example.test")
			.send({ action: "lookup", user_code: "BCDF-GHJK" });
		return { res, lines, logger };
	};

	it("treats an exposed 4xx a store throws as the outage it is — 503, logged", async () => {
		// Only the parsers' errors are the caller's mistake. A store that throws
		// an `http-errors`-shaped 403 has failed; it has not been refused a body.
		const { res, lines, logger } = await lookupThrowing(
			Object.assign(new Error("forbidden"), { expose: true, status: 403 }),
		);

		expect(res.status).toBe(503);
		expect(res.body).toEqual(STORE_UNAVAILABLE);
		expect(logger.error).toHaveBeenCalledWith(
			{ action: "lookup", err: { name: "Error", detail: "forbidden", status: 403, stack: FRAMES } },
			"device_verification_store_unavailable",
		);
		for (const logged of lines) {
			expect(logged).not.toContain("BCDFGHJK");
			expect(logged).not.toContain("user-1");
		}
	});

	it("logs what a Redis reply error's message says, not the command arguments it echoes", async () => {
		// redis-errors' `ReplyError` for an unknown command quotes the first
		// arguments into its message — here the user code and the subject.
		const { res, lines, logger } = await lookupThrowing(
			Object.assign(
				new Error(
					"ERR unknown command 'evalsha', with args beginning with: 'sha' '1' 'devauth:user:BCDFGHJK' 'user-1'",
				),
				{ name: "ReplyError" },
			),
		);

		expect(res.status).toBe(503);
		expect(logger.error).toHaveBeenCalledWith(
			{
				action: "lookup",
				err: { name: "ReplyError", detail: "ERR unknown command 'evalsha'", stack: FRAMES },
			},
			"device_verification_store_unavailable",
		);
		for (const line of lines) {
			expect(line).not.toContain("BCDFGHJK");
			expect(line).not.toContain("user-1");
		}
	});

	it("logs a JSON SyntaxError's message without the input V8 quotes in it", async () => {
		let parseError: unknown;
		try {
			JSON.parse("user_code=BCDFGHJK&sub=user-1");
		} catch (error) {
			parseError = error;
		}
		expect(String((parseError as Error).message)).toContain("user_code");

		const { res, lines } = await lookupThrowing(parseError);

		expect(res.status).toBe(503);
		for (const line of lines) {
			expect(line).not.toContain("user_code");
			expect(line).not.toContain("BCDFGHJK");
		}
	});

	it("caps the logged message at its first 256 characters", async () => {
		const message = `failure ${"x".repeat(1000)}`;
		const { lines } = await lookupThrowing(new Error(message));
		const logged = JSON.parse(lines[0]?.split(" ").slice(2).join(" ") ?? "{}") as {
			err?: { detail?: string };
		};
		expect(logged.err?.detail).toBe(message.slice(0, 256));
	});

	it("logs a store error's Error causes the same way, and nothing of what they carry", async () => {
		// A store that wraps the Redis reply it got: the cause says what
		// failed, so it is logged — projected like the error itself, with
		// Redis's echo of the command cut and the command's arguments and a
		// non-Error cause's body left out.
		const reply = Object.assign(
			new Error(
				"ERR unknown command 'evalsha', with args beginning with: 'sha' '1' 'devauth:user:BCDFGHJK' 'user-1'",
				{ cause: { body: "client_secret=s3cret-value" } },
			),
			{
				name: "ReplyError",
				command: { name: "evalsha", args: ["devauth:{devauth}:user:BCDFGHJK", "user-1"] },
			},
		);
		const { res, lines, logger } = await lookupThrowing(
			new Error("device code lookup failed", { cause: reply }),
		);

		expect(res.status).toBe(503);
		expect(logger.error).toHaveBeenCalledWith(
			{
				action: "lookup",
				err: {
					name: "Error",
					detail: "device code lookup failed",
					stack: FRAMES,
					cause: {
						name: "ReplyError",
						detail: "ERR unknown command 'evalsha'",
						command: { name: "evalsha" },
						stack: FRAMES,
					},
				},
			},
			"device_verification_store_unavailable",
		);
		for (const line of lines) {
			expect(line).not.toContain("BCDFGHJK");
			expect(line).not.toContain("user-1");
			expect(line).not.toContain("s3cret-value");
		}
	});

	it.each([
		["a string status", { status: "503" }, {}],
		["a fractional status", { status: 503.5 }, {}],
		["a non-finite code", { code: Number.NaN }, {}],
		["a numeric code", { code: 42 }, { code: 42 }],
		[
			"an upstream's OAuth error and description",
			{ error: "invalid_grant", error_description: "Token has been expired or revoked." },
			{ error: "invalid_grant", error_description: "Token has been expired or revoked." },
		],
	] as const)("logs %s as core's projection keeps it", async (_label, fields, kept) => {
		const { logger } = await lookupThrowing(Object.assign(new Error("store failed"), fields));

		expect(logger.error).toHaveBeenCalledWith(
			{ action: "lookup", err: { name: "Error", detail: "store failed", stack: FRAMES, ...kept } },
			"device_verification_store_unavailable",
		);
	});

	it("logs an error whose name is not a string as an Error", async () => {
		const { lines, logger } = await lookupThrowing(
			Object.assign(new Error("store failed"), { name: { toString: () => "s3cret-name" } }),
		);

		expect(logger.error).toHaveBeenCalledWith(
			{ action: "lookup", err: expect.objectContaining({ name: "Error", detail: "store failed" }) },
			"device_verification_store_unavailable",
		);
		for (const line of lines) expect(line).not.toContain("s3cret-name");
	});

	it("logs a thrown value that is not an Error as a NonError of its type, and nothing of it", async () => {
		const { res, lines, logger } = await lookupThrowing("device code s3cret-value");

		expect(res.status).toBe(503);
		expect(logger.error).toHaveBeenCalledWith(
			{ action: "lookup", err: { name: "NonError", thrown: "string" } },
			"device_verification_store_unavailable",
		);
		for (const line of lines) expect(line).not.toContain("s3cret-value");
	});

	it("answers a device-code store that cannot be reached with 503, asked once, and logs it through the same projection", async () => {
		// An outage is not a collision: re-drawing a code cannot reach a store
		// that is down, and a 500 would blame the server for what is, per the
		// product's rule, a store outage — 503 temporarily_unavailable. Only
		// the store's own collision signal is retried. The line carries the
		// error's projection, never `String(error)` — the whole message,
		// command arguments included.
		const deps = enabledDeps();
		const { lines, logger } = serialisingLogger();
		let creates = 0;
		const app = mountContributedRoute(0, {
			...deps,
			logger,
			deviceCodeStore: {
				...deps.deviceCodeStore,
				create: async () => {
					creates += 1;
					throw Object.assign(
						new Error(
							"ERR unknown command 'evalsha', with args beginning with: 'sha' '2' 'devauth:{devauth}:code:DC' 'devauth:{devauth}:user:BCDFGHJK'",
						),
						{ name: "ReplyError" },
					);
				},
			},
		});

		const res = await request(app)
			.post("/oauth/device_authorization")
			.auth(CONFIDENTIAL_ID, CONFIDENTIAL_SECRET)
			.send({});

		expect(res.status).toBe(503);
		expect(res.body).toEqual(STORE_UNAVAILABLE);
		expect(res.headers["cache-control"]).toContain("no-store");
		expect(creates).toBe(1);
		// The projection, not the error: the kept text without the arguments.
		expect(logger.error).toHaveBeenCalledWith(
			{
				clientId: CONFIDENTIAL_ID,
				err: { name: "ReplyError", detail: "ERR unknown command 'evalsha'", stack: FRAMES },
			},
			"device_authorization_store_unavailable",
		);
		expect(logger.warn).not.toHaveBeenCalledWith(
			expect.anything(),
			"device_authorization_code_collision",
		);
		for (const logged of lines) {
			expect(logged).not.toContain("BCDFGHJK");
			expect(logged).not.toContain("'sha'");
		}
	});

	it("still re-draws on the store's collision signal, and gives up with 500 after a run of them", async () => {
		// A collision every time is a generator that keeps drawing live codes —
		// a server fault the caller cannot cause, so 500, logged as the
		// collision it is.
		const deps = enabledDeps();
		const { logger } = serialisingLogger();
		let creates = 0;
		const app = mountContributedRoute(0, {
			...deps,
			logger,
			deviceCodeStore: {
				...deps.deviceCodeStore,
				create: async () => {
					creates += 1;
					throw new DeviceCodeStoreError({ reason: "collision" });
				},
			},
		});

		const res = await request(app)
			.post("/oauth/device_authorization")
			.auth(CONFIDENTIAL_ID, CONFIDENTIAL_SECRET)
			.send({});

		expect(res.status).toBe(500);
		expect(res.body.error).toBe("server_error");
		expect(creates).toBe(5);
		const line = loggedAs(logger.warn, "device_authorization_code_collision");
		expect(Object.keys(line).sort()).toEqual(["clientId", "err"]);
		expectProjection(line.err, { name: "DeviceCodeStoreError" });
	});

	/** 1000 parameters is body-parser's `parameterLimit`; the secret rides along. */
	const tooManyParameters = [
		`client_id=${CONFIDENTIAL_ID}`,
		`client_secret=${CONFIDENTIAL_SECRET}`,
		...Array.from({ length: 1000 }, (_, i) => `p${i}=1`),
	].join("&");

	it.each([
		// [label, route, headers, body, status, description]
		[
			"a charset the parser cannot decode",
			1,
			{ "Content-Type": "application/json; charset=latin1" },
			'{"action":"lookup"}',
			415,
			"unsupported_encoding",
		],
		[
			"a Content-Encoding the parser does not support",
			0,
			{ "Content-Type": "application/json", "Content-Encoding": "compress" },
			"{}",
			415,
			"unsupported_encoding",
		],
		[
			"a compressed body that does not decompress",
			0,
			{ "Content-Type": "application/json", "Content-Encoding": "gzip" },
			"not gzip at all",
			400,
			"malformed_body",
		],
		[
			"more form parameters than the parser takes",
			0,
			{ "Content-Type": "application/x-www-form-urlencoded" },
			tooManyParameters,
			413,
			"body_too_large",
		],
	] as const)(
		"answers %s with a 4xx in JSON, logging nothing at error level and nothing of the body",
		async (_label, route, headers, body, status, description) => {
			// body-parser marks these `expose` with a 4xx status: the caller's
			// mistake. On the verification route the parser runs ahead of the
			// CSRF guard and of any throttle, so a 500 and an error line here
			// would be a free way for anyone to fill the error log.
			const { lines, logger } = serialisingLogger();
			const deps = { ...enabledDeps(), logger };
			const app = route === 0 ? mountContributedRoute(0, deps) : mountVerificationRoute(deps);
			const path = route === 0 ? "/oauth/device_authorization" : "/oauth/device/verification";

			const res = await request(app).post(path).set(headers).send(body);

			expect(res.status).toBe(status);
			expect(res.headers["content-type"]).toMatch(/^application\/json/);
			expect(res.headers["cache-control"]).toBe("no-store");
			expect(res.body).toEqual({ error: "invalid_request", error_description: description });
			expect(logger.error).not.toHaveBeenCalled();
			for (const line of lines) expect(line).not.toContain(CONFIDENTIAL_SECRET);
		},
	);

	/**
	 * device_authorization with a limiter whose decision throws `thrown` when
	 * the throttle reads it: an error raised ahead of the parsers, which the
	 * parsers' refusal handler is the first to see.
	 */
	const throttleThrowing = async (thrown: unknown) => {
		const { lines, logger } = serialisingLogger();
		const app = mountContributedRoute(0, {
			...enabledDeps(),
			logger,
			rateLimiter: {
				kind: "hostile",
				check: async () => ({
					allowed: true,
					get limit(): number {
						throw thrown;
					},
				}),
			} satisfies RateLimiter,
		});
		const res = await request(app)
			.post("/oauth/device_authorization")
			.type("form")
			.send(`client_id=${CONFIDENTIAL_ID}`);
		return { res, lines, logger };
	};

	it("answers an error whose `expose` getter throws as JSON 500, logging that error rather than the getter's", async () => {
		// The refusal handler asks every error it sees whether it is a parser's.
		// Asking must not throw: a throw there replaced the error in hand with
		// the getter's, and the log named the wrong failure.
		const hostile = Object.defineProperty(new Error("limiter decision unreadable"), "expose", {
			get() {
				throw new Error("expose getter threw");
			},
		});

		const { res, logger } = await throttleThrowing(hostile);

		expect(res.status).toBe(500);
		expect(res.headers["content-type"]).toMatch(/^application\/json/);
		expect(res.body).toEqual({ error: "server_error", error_description: "unexpected_error" });
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{ err: { name: "Error", detail: "limiter decision unreadable", stack: FRAMES } },
			"device_route_unexpected_error",
		);
	});

	it("answers a Proxy whose every trap throws as JSON 500, logged as the thrown value it is", async () => {
		const trap = () => {
			throw new Error("trap threw");
		};
		const hostile = new Proxy(
			{},
			{ get: trap, has: trap, ownKeys: trap, getOwnPropertyDescriptor: trap, getPrototypeOf: trap },
		);

		const { res, logger } = await throttleThrowing(hostile);

		expect(res.status).toBe(500);
		expect(res.headers["content-type"]).toMatch(/^application\/json/);
		expect(res.body).toEqual({ error: "server_error", error_description: "unexpected_error" });
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{ err: { name: "NonError", thrown: "object" } },
			"device_route_unexpected_error",
		);
	});

	it.each([
		["the per-IP throttle's 429 on device_authorization", "throttle"],
		["client authentication's 401 on device_authorization", "client-auth"],
		["the CSRF guard's 403 on device/verification", "csrf"],
	] as const)("sends no-store on %s, as on every other exit", async (_label, which) => {
		// A refusal an intermediary caches is served to the next caller too.
		if (which === "csrf") {
			const app = mountVerificationRoute(enabledDeps());
			const res = await request(app)
				.post("/oauth/device/verification")
				.set("Origin", "https://evil.example")
				.send({ action: "lookup", user_code: "BCDF-GHJK" });
			expect(res.status).toBe(403);
			expect(res.headers["cache-control"]).toBe("no-store");
			return;
		}
		const app = mountContributedRoute(
			0,
			enabledDeps({ limits: { device_authorization: { limit: 1, windowSeconds: 60 } } }),
		);
		const first = await request(app)
			.post("/oauth/device_authorization")
			.send({ client_id: CONFIDENTIAL_ID });
		expect(first.status).toBe(401);
		if (which === "client-auth") {
			expect(first.headers["cache-control"]).toBe("no-store");
			return;
		}
		const second = await request(app)
			.post("/oauth/device_authorization")
			.send({ client_id: CONFIDENTIAL_ID });
		expect(second.status).toBe(429);
		expect(second.headers["cache-control"]).toBe("no-store");
	});

	/**
	 * `enabledDeps()` with `device-grant.rateLimit` replaced, handed to the
	 * factory as a hand-built section that never passed the schema.
	 */
	const withAttemptLimit = (rateLimit: unknown) => {
		const deps = enabledDeps();
		return { ...deps, section: { ...deps.section, rateLimit } };
	};

	it("refuses to mount device/verification without its attempt limit, device-grant.rateLimit", () => {
		// RFC 8628 §5.1 sizes the user code against this limit; a hand-built
		// section that never passed the schema must not mount the route
		// without it.
		const deps = withAttemptLimit(undefined);
		const factory = contributionsFor(deps)?.routes?.[1] as (d: unknown) => unknown;
		expect(() => factory(deps)).toThrow(/device-grant\.rateLimit/);
	});

	it.each([
		["a zero limit", { limit: 0, windowSeconds: 300 }],
		["a fractional window", { limit: 5, windowSeconds: 0.5 }],
		["a non-numeric string limit", { limit: "five", windowSeconds: 300 }],
		["a blank window", { limit: 5, windowSeconds: " " }],
		["a window over a day", { limit: 5, windowSeconds: 86_401 }],
		["a window past the Date range", { limit: 5, windowSeconds: 1e13 }],
	])("refuses to mount device/verification with %s as the limit", (_label, rateLimit) => {
		const deps = withAttemptLimit(rateLimit);
		const factory = contributionsFor(deps)?.routes?.[1] as (d: unknown) => unknown;
		expect(() => factory(deps)).toThrow(/device-grant\.rateLimit/);
	});

	it("mounts device/verification with a usable limit", () => {
		const deps = withAttemptLimit({ limit: 5, windowSeconds: 300 });
		const factory = contributionsFor(deps)?.routes?.[1] as (d: unknown) => unknown;
		expect(() => factory(deps)).not.toThrow();
	});

	it("mounts device/verification with the limit as numeric strings, as the schema reads it", () => {
		const deps = withAttemptLimit({ limit: "5", windowSeconds: "300" });
		const factory = contributionsFor(deps)?.routes?.[1] as (d: unknown) => unknown;
		expect(() => factory(deps)).not.toThrow();
	});

	it("mounts nothing when the grant is disabled: the host answers its paths", async () => {
		const handle = await boot({});
		const app = express();
		app.use(handle.router);
		app.use((_req, res) => {
			res.status(404).json({ answeredBy: "host" });
		});
		for (const path of ["/oauth/device_authorization", "/oauth/device/verification"]) {
			const res = await request(app).post(path).send({});
			expect(res.body, path).toEqual({ answeredBy: "host" });
		}
		await handle.dispose();
	});
});

describe("the device-grant module — disabled surface", () => {
	it("registers no grant when disabled", async () => {
		// Observable behaviour matches "not installed": with nothing
		// registered, the token endpoint answers `unsupported_grant_type` and
		// `grant_types_supported` does not name the grant — both pinned beside
		// `oauthEndpointsModule` in composition.test.mts. A refusing handler registered
		// in its place was advertised as a supported grant.
		const handle = await boot({ deviceGrant: { enabled: false } });
		try {
			expect(handle.components.grantHandlerResolver?.get(DEVICE_CODE_GRANT_TYPE)).toBeUndefined();
		} finally {
			await handle.dispose();
		}
	});

	it("refuses to boot with a switch its section's schema does not read, naming the key", async () => {
		await expect(boot({ deviceGrant: { ...ENABLED, enabled: "yes" } })).rejects.toThrow(
			/device-grant\.enabled/,
		);
	});

	it("refuses the grant factory called directly without oauthTokenSettings, naming the slot", () => {
		const factory = contributionsFor()?.grants?.[DEVICE_CODE_GRANT_TYPE] as (d: unknown) => unknown;
		expect(() =>
			factory({
				section: sectionOf(ENABLED),
				deviceCodeStore: createMemoryDeviceCodeStore(),
				keyStore: createSymmetricKeyStore("device-lifetime-secret.at-least-32-bytes"),
			}),
		).toThrow(/oauthTokenSettings/);
	});
});

describe("the device-grant module — the access-token lifetime", () => {
	it("mints the default lifetime of the oauthTokenSettings slot and ignores an expires_in request parameter", async () => {
		// `expires_in` is the time left when answered: read on a frozen clock.
		vi.useFakeTimers({ toFake: ["Date"], now: Date.now() });
		// The module hands the grant its lifetime at composition, from the
		// slot the oauth module provides.
		const approvedStore = {
			...createMemoryDeviceCodeStore(),
			poll: async () => ({
				status: "approved" as const,
				authorization: {
					userCode: "BCDF-GHJK",
					clientId: CONFIDENTIAL_ID,
					requestedScope: ["openid"],
					expiresAtMs: Date.now() + 600_000,
					intervalSeconds: 5,
					status: "approved" as const,
					subject: "user-1",
					grantedScope: ["openid"],
					approvedAtMs: Date.now(),
					amr: undefined,
					authTimeMs: undefined,
				},
			}),
		} satisfies DeviceCodeStore;
		const deps = {
			section: sectionOf(ENABLED),
			oauthTokenSettings: createTestOAuthTokenSettings({
				accessTokenLifetime: { defaultExpiresIn: 600, maxExpiresIn: 7200 },
			}),
			deviceCodeStore: approvedStore,
			keyStore: createSymmetricKeyStore("device-lifetime-secret.at-least-32-bytes"),
		};
		const factory = contributionsFor(deps)?.grants?.[DEVICE_CODE_GRANT_TYPE] as (deps: unknown) => {
			handle(ctx: unknown): Promise<{ result: { tokens?: Record<string, unknown> } }>;
		};
		const handler = factory(deps);

		const { result } = await handler.handle({
			body: { device_code: "device-code-1", expires_in: "7200" },
			session: {},
			metadata: {},
			issuer: "https://as.example.test",
			authenticatedClient: confidentialClient,
		});

		expect(result.tokens?.expires_in).toBe(600);
		const payload = decodeJwt(result.tokens?.access_token as string);
		expect((payload.exp as number) - (payload.iat as number)).toBe(600);
	});

	it("reads no lifetime from the configuration: the slot's is minted whatever `oauth.accessToken` says", async () => {
		// `expires_in` is the time left when answered: read on a frozen clock.
		vi.useFakeTimers({ toFake: ["Date"], now: Date.now() });
		// The oauth module owns `oauth {}` and provides what others read of it;
		// a composition without it fills the slot.
		const store = {
			...createMemoryDeviceCodeStore(),
			poll: async () => ({
				status: "approved" as const,
				authorization: {
					userCode: "BCDF-GHJK",
					clientId: CONFIDENTIAL_ID,
					requestedScope: ["openid"],
					expiresAtMs: Date.now() + 600_000,
					intervalSeconds: 5,
					status: "approved" as const,
					subject: "user-1",
					grantedScope: ["openid"],
					approvedAtMs: Date.now(),
					amr: undefined,
					authTimeMs: undefined,
				},
			}),
		} satisfies DeviceCodeStore;
		const base = makeValidCoreConfig();
		const deps = {
			config: {
				oauth: {
					...base.oauth,
					accessToken: { defaultExpiresIn: 600, maxExpiresIn: 7200 },
				},
			},
			section: sectionOf(ENABLED),
			oauthTokenSettings: createTestOAuthTokenSettings({
				accessTokenLifetime: { defaultExpiresIn: 900, maxExpiresIn: 7200 },
			}),
			deviceCodeStore: store,
			keyStore: createSymmetricKeyStore("device-lifetime-secret.at-least-32-bytes"),
		};
		const factory = contributionsFor(deps)?.grants?.[DEVICE_CODE_GRANT_TYPE] as (deps: unknown) => {
			handle(ctx: unknown): Promise<{ result: { tokens?: Record<string, unknown> } }>;
		};
		const { result } = await factory(deps).handle({
			body: { device_code: "device-code-1" },
			session: {},
			metadata: {},
			issuer: "https://as.example.test",
			authenticatedClient: confidentialClient,
		});
		expect(result.tokens?.expires_in).toBe(900);
	});
});

describe("the device-grant module — private_key_jwt on the mounted route", () => {
	const ISSUER = "https://as.example.test";
	const JWT_CLIENT = "assertion-app";
	const JWT_BEARER_CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
	let privateKey: CryptoKey;
	let publicJwk: JWK;

	beforeAll(async () => {
		const pair = await generateKeyPair("ES256");
		privateKey = pair.privateKey;
		publicJwk = { ...(await exportJWK(pair.publicKey)), kid: "k1" };
	});

	const jwtRepository: ClientRepository = {
		findById: async (id) =>
			id === JWT_CLIENT
				? ({
						clientId: JWT_CLIENT,
						tokenEndpointAuthMethod: "private_key_jwt",
						allowedScopes: ["openid"],
						defaultScopes: ["openid"],
						allowedGrantTypes: [DEVICE_CODE_GRANT_TYPE],
						jwks: { keys: [publicJwk] },
					} as never)
				: null,
		authenticate: async () => null,
	};

	const assertion = async (issuer = ISSUER): Promise<string> => {
		const now = Math.floor(Date.now() / 1000);
		return new SignJWT({
			iss: JWT_CLIENT,
			sub: JWT_CLIENT,
			aud: `${issuer}/oauth/token`,
			iat: now,
			exp: now + 60,
			jti: `jti-${Math.random().toString(36).slice(2)}`,
		})
			.setProtectedHeader({ alg: "ES256", kid: "k1" })
			.sign(privateKey);
	};

	const mountWith = (deps: TestDeps) => {
		const factory = contributionsFor(deps)?.routes?.[0] as (d: unknown) => {
			mountPath: string;
			handler: express.RequestHandler;
		};
		const route = factory(deps);
		const app = express();
		app.use(route.mountPath, route.handler);
		return app;
	};

	const depsWith = (replaySeenSet?: unknown) => ({
		section: sectionOf(ENABLED),
		oauthTokenSettings: createTestOAuthTokenSettings({ ...WITHIN_CONFIGURATION, issuer: ISSUER }),
		clientRepository: jwtRepository,
		deviceCodeStore: createMemoryDeviceCodeStore(),
		deploymentMode: "single",
		rateLimiter: createMemoryRateLimiter({
			limits: {},
			defaultLimit: { limit: 60, windowSeconds: 60 },
		}),
		...(replaySeenSet === undefined ? {} : { replaySeenSet }),
	});

	it("authenticates a private_key_jwt client against the composition's replay store", async () => {
		// The module builds the same client-auth middleware `/oauth/token`
		// builds, but never handed it the replay store — so a client using the
		// method the discovery document advertises got `500 server_error` here
		// while it worked at every other endpoint.
		const app = mountWith(depsWith(createMemoryReplaySeenSet()));
		const res = await request(app)
			.post("/oauth/device_authorization")
			.type("form")
			.send({
				client_assertion_type: JWT_BEARER_CLIENT_ASSERTION_TYPE,
				client_assertion: await assertion(),
			});

		expect(res.status).toBe(200);
		expect(typeof res.body.device_code).toBe("string");
	});

	it("authenticates the client against the issuer of the oauthTokenSettings a module provides", async () => {
		const SLOT_ISSUER = "https://slot.example.test";
		const app = mountWith({
			...depsWith(createMemoryReplaySeenSet()),
			oauthTokenSettings: createTestOAuthTokenSettings({
				...WITHIN_CONFIGURATION,
				issuer: SLOT_ISSUER,
			}),
		});
		const post = async (issuer: string) =>
			request(app)
				.post("/oauth/device_authorization")
				.type("form")
				.send({
					client_assertion_type: JWT_BEARER_CLIENT_ASSERTION_TYPE,
					client_assertion: await assertion(issuer),
				});
		expect((await post(SLOT_ISSUER)).status).toBe(200);
		expect((await post(ISSUER)).status).toBe(401);
	});

	it("refuses a replayed assertion, because the store is the composition's", async () => {
		const app = mountWith(depsWith(createMemoryReplaySeenSet()));
		const jwt = await assertion();
		const form = {
			client_assertion_type: JWT_BEARER_CLIENT_ASSERTION_TYPE,
			client_assertion: jwt,
		};
		expect(
			(await request(app).post("/oauth/device_authorization").type("form").send(form)).status,
		).toBe(200);
		const replay = await request(app).post("/oauth/device_authorization").type("form").send(form);
		expect(replay.status).toBe(401);
		expect(replay.body.error).toBe("invalid_client");
	});

	it("answers server_error without a store rather than accepting an unchecked jti", async () => {
		const app = mountWith(depsWith());
		const res = await request(app)
			.post("/oauth/device_authorization")
			.type("form")
			.send({
				client_assertion_type: JWT_BEARER_CLIENT_ASSERTION_TYPE,
				client_assertion: await assertion(),
			});
		expect(res.status).toBe(500);
		expect(res.body.error).toBe("server_error");
	});
});
