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
 * `deviceGrantModule` boot invariants (#298).
 *
 * Two settings have no default and fail boot instead, for two different
 * reasons — and both reasons are the point of the test.
 */

import type {
	AppConfig,
	BootstrapMap,
	ClientRepository,
	DeviceCodeStore,
	Module,
	RateLimiter,
	RateLimitSpec,
} from "@o3co/auth-provider-core";
import {
	createApp,
	createMemoryDeviceCodeStore,
	createMemoryRateLimiter,
	createMemoryReplaySeenSet,
	createSymmetricKeyStore,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig, makeValidFullSections } from "@o3co/auth-provider-core/testing";
import express from "express";
import { decodeJwt, exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import request from "supertest";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { deviceGrantModule } from "#/module.mjs";
import { DEVICE_CODE_GRANT_TYPE } from "#/types.mjs";

const clientRepository: ClientRepository = {
	findById: async () => null,
	authenticate: async () => null,
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
	readonly deviceAuthorization?: Record<string, unknown>;
	readonly withStore?: boolean;
	readonly withRateLimiter?: boolean;
	/** Drop the `audit.sink.type = "none"` declaration the fixture carries. */
	readonly withoutAuditDeclaration?: boolean;
}

const makeBoot = (overrides: Overrides): BootstrapMap => {
	const core = makeValidCoreConfig();
	const full = makeValidFullSections();
	return {
		config: {
			...core,
			// The verification route's CSRF guard is built from `session.*`, the
			// same slice `/session/login` reads; enabling the grant without it
			// is a boot refusal, so the fixture carries the standard one.
			session: full.session,
			// The device_authorization guard reads the product-wide outage
			// policy, `rateLimit.failMode`, like every other guarded route.
			rateLimit: full.rateLimit,
			// #363: the module attaches AUDIT_SINK_ABSENCE_POLICY, so a boot
			// with no sink must say so — which is what this fixture is.
			...(overrides.withoutAuditDeclaration === true ? {} : { audit: full.audit }),
			oauth: {
				...core.oauth,
				deviceAuthorization: {
					enabled: false,
					"verification-uri-complete": false,
					"code-lifetime-seconds": 600,
					"polling-interval-seconds": 5,
					...(overrides.deviceAuthorization ?? {}),
				},
			},
		},
		pathResolver: (s: string) => s,
		clientRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!!"),
		...(overrides.withStore === false ? {} : { deviceCodeStore: createMemoryDeviceCodeStore() }),
		...(overrides.withRateLimiter === false
			? {}
			: {
					rateLimiter: createMemoryRateLimiter({
						limits: { device_verification: { limit: 5, windowSeconds: 300 } },
						defaultLimit: { limit: 60, windowSeconds: 60 },
					}),
				}),
	} as unknown as BootstrapMap;
};

/**
 * Boot the module built from the same config `createApp` validates — the
 * one a composition root holds and hands both.
 */
const boot = (overrides: Overrides) => {
	const bootstrapComponents = makeBoot(overrides);
	return createApp({
		modules: [deviceGrantModule({ config: bootstrapComponents.config as AppConfig })],
		bootstrapComponents,
	});
};

/** What `createApp` hands a contribution: the config, and whatever slots the test wires. */
type TestDeps = { readonly config: unknown } & Readonly<Record<string, unknown>>;

/** The contributions of the module built for `deps.config`, as `createApp` would call them with `deps`. */
const contributionsFor = (deps: TestDeps) =>
	deviceGrantModule({ config: deps.config as AppConfig }).contributes;

const ENABLED = {
	enabled: true,
	"verification-uri": "https://example.test/device",
};

describe("deviceGrantModule — boot", () => {
	it("refuses the factory listed uncalled — the pre-factory form, `modules: [deviceGrantModule]`", async () => {
		// The compiler does not catch it: a function has a `name`, the one
		// field `Module` requires. Listed that way the module contributed
		// nothing and boot succeeded, with no grant, no route and none of the
		// refusals below. Core refuses any such entry.
		await expect(
			createApp({
				modules: [deviceGrantModule as unknown as Module],
				bootstrapComponents: makeBoot({ deviceAuthorization: ENABLED }),
			}),
		).rejects.toMatchObject({
			reason: "module-factory-not-called",
			message: expect.stringMatching(
				/module entry "deviceGrantModule" is a function — call it with its arguments/,
			),
		});
	});

	it("boots disabled without any of the required settings", async () => {
		// Installing the package must not turn on a grant, and a deployment
		// that leaves it off must never trip settings it does not use.
		const handle = await boot({});
		await handle.dispose();
	});

	it("refuses to boot enabled without a verification-uri", async () => {
		// No default is possible: the page belongs to the deployment, and the
		// device displays this string verbatim to people who need to reach it.
		await expect(boot({ deviceAuthorization: { enabled: true } })).rejects.toThrow(
			/verification-uri/,
		);
	});

	it("refuses to boot enabled without a rate limiter", async () => {
		// RFC 8628 §5.1 sizes the user code's entropy AGAINST a rate limit:
		// ~34.5 bits is sufficient only where an attacker gets a handful of
		// attempts. Without a limiter that argument does not hold, so this is a
		// refusal rather than a degraded mode.
		await expect(boot({ deviceAuthorization: ENABLED, withRateLimiter: false })).rejects.toThrow(
			/§5\.1|rate/i,
		);
	});

	it("refuses to boot without a device code store, naming the config key", async () => {
		// #363's absence policy: optional to wire, not optional to decide. A
		// composition with no store cannot authorize any device at all, so the
		// failure belongs at boot rather than on the first request.
		await expect(boot({ deviceAuthorization: ENABLED, withStore: false })).rejects.toThrow(
			/oauth\.deviceAuthorization\.store/,
		);
	});

	it("boots when the operator declares the store absent on purpose and leaves the grant off", async () => {
		// The absence policy is applied whether or not the feature is on, so
		// this is the declaration a deployment that installs the package and
		// never enables the grant has to write.
		const handle = await boot({
			deviceAuthorization: { enabled: false, store: "unsupported" },
			withStore: false,
		});
		await handle.dispose();
	});

	it("refuses to boot enabled with the store declared absent, naming the component", async () => {
		// `store = "unsupported"` says why the slot is empty; it does not make
		// the grant work without one. An enabled grant with no store used to
		// boot and mount endpoints that threw on the first request; the
		// refusal belongs at boot, beside `rateLimiter` and `verification-uri`.
		// The phrase is the module's own, not the stage-1 policy message,
		// which also names `deviceCodeStore`.
		await expect(
			boot({ deviceAuthorization: { ...ENABLED, store: "unsupported" }, withStore: false }),
		).rejects.toThrow(/enabled = true requires a deviceCodeStore component/);
	});

	it("boots with everything wired, without oauthModule", async () => {
		// The routes declare no ordering edge — each module under `/oauth`
		// parses its own body — so nothing here needs another module's route
		// to exist. The composition beside oauthModule is composition.test.mts.
		const handle = await boot({ deviceAuthorization: ENABLED });
		await handle.dispose();
	});

	it.each([
		["built enabled, booted with the grant off", ENABLED, { enabled: false }],
		["built disabled, booted with the grant on", { enabled: false }, ENABLED],
	])("refuses to boot when the module was %s", async (_label, builtFrom, bootedWith) => {
		// The factory decides from the config it is handed whether the grant
		// is contributed; the routes and the discovery field read the config
		// `createApp` validated. Two configs that disagree would register a
		// grant whose device can never start, or serve a flow whose token
		// endpoint refuses the grant — so the disagreement is the refusal.
		const bootstrapComponents = makeBoot({ deviceAuthorization: bootedWith });
		const config = bootstrapComponents.config as AppConfig;
		const handedToFactory = {
			...config,
			oauth: { ...config.oauth, deviceAuthorization: builtFrom },
		} as AppConfig;
		await expect(
			createApp({
				modules: [deviceGrantModule({ config: handedToFactory })],
				bootstrapComponents,
			}),
		).rejects.toThrow(/the same config/);
	});

	it("names the disagreement, not a missing store, when the booted config declares the store absent", async () => {
		// The grant is contributed before the routes are, and it needs a
		// store. Built enabled and booted off with `store = "unsupported"`
		// and no store wired, the first refusal has to be the one that says
		// what is actually wrong — the two configs — rather than the store
		// the booted config correctly says it does not need.
		const bootstrapComponents = makeBoot({
			deviceAuthorization: { enabled: false, store: "unsupported" },
			withStore: false,
		});
		const config = bootstrapComponents.config as AppConfig;
		const handedToFactory = {
			...config,
			oauth: { ...config.oauth, deviceAuthorization: ENABLED },
		} as AppConfig;
		await expect(
			createApp({
				modules: [deviceGrantModule({ config: handedToFactory })],
				bootstrapComponents,
			}),
		).rejects.toThrow(/the same config/);
	});

	it('refuses to boot with no audit sink unless audit.sink.type = "none" says so', async () => {
		// #363's rule, applied to the decision that turns a code into a token:
		// `auditSink` is optional to wire, not optional to decide. A composition
		// that silently discards every device approval must have written that
		// down.
		await expect(
			boot({ deviceAuthorization: ENABLED, withoutAuditDeclaration: true }),
		).rejects.toThrow(/audit\.sink\.type/);
	});
});

describe("deviceGrantModule — discovery (RFC 8628 §4)", () => {
	it("contributes the endpoint as an issuer-relative path when enabled", () => {
		// A client has no other way to find the endpoint, so the metadata is
		// the feature being reachable rather than a description of it. Under
		// `endpoints`, not `metadata`: core prefixes the issuer and refuses an
		// `*_endpoint` literal — the served document is pinned end to end in
		// composition.test.mts.
		const deps = {
			config: {
				oauth: {
					jwt: { issuer: "https://as.example.test" },
					deviceAuthorization: ENABLED,
				},
			},
		};
		const contribution = contributionsFor(deps)?.discoveryMetadata?.[0] as (
			deps: unknown,
		) => Record<string, unknown>;
		const result = contribution(deps);
		expect(result).toEqual({
			endpoints: { device_authorization_endpoint: "/oauth/device_authorization" },
		});
	});

	it("advertises nothing when disabled", async () => {
		// #283's rule: the document must not claim a capability the deployment
		// does not have.
		const deps = {
			config: {
				oauth: {
					jwt: { issuer: "https://as.example.test" },
					deviceAuthorization: { enabled: false },
				},
			},
		};
		const contribution = contributionsFor(deps)?.discoveryMetadata?.[0] as (
			deps: unknown,
		) => Record<string, unknown>;
		expect(contribution(deps)).toEqual({});
	});
});

describe("deviceGrantModule — the route it actually contributes", () => {
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
		config: {
			oauth: {
				jwt: { issuer: "https://as.example.test" },
				accessToken: { expiresIn: 300 },
				deviceAuthorization: {
					enabled: true,
					"verification-uri": "https://example.test/device",
					"verification-uri-complete": false,
					"code-lifetime-seconds": 600,
					"polling-interval-seconds": 5,
					rateLimit: { limit: 5, windowSeconds: 300 },
				},
			},
			session: makeValidFullSections().session,
			rateLimit: makeValidFullSections().rateLimit,
		},
		clientRepository: confidentialRepository,
		deviceCodeStore: createMemoryDeviceCodeStore(),
		rateLimiter: createMemoryRateLimiter({
			limits: {
				device_verification: { limit: 5, windowSeconds: 300 },
				...(overrides.limits ?? {}),
			},
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
		// Every other public entry point sits behind `createRateLimitGuard`;
		// this one did not, and its store is what an unthrottled caller fills.
		// The guard is mounted BEFORE client auth (the token endpoint's D-6
		// ordering): the second unauthenticated hit is throttled, not 401'd,
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

	it("refuses to mount device_authorization without the outage policy, rateLimit.failMode", () => {
		// The guard's fail-open / fail-closed choice is the product's, made
		// once in config. Defaulting it here would be a second policy.
		const deps = enabledDeps();
		const factory = contributionsFor(deps)?.routes?.[0] as (d: unknown) => unknown;
		expect(() => factory({ ...deps, config: { ...deps.config, rateLimit: undefined } })).toThrow(
			/rateLimit\.failMode/,
		);
	});

	it("refuses to mount device/verification without the outage policy, rateLimit.failMode (#457)", () => {
		// The verification endpoint applies the same policy from the same key
		// (#457). A composition that enables the grant with no `failMode` is
		// refused for this route too, not only for device_authorization — or
		// the refusal would depend on which factory the planner ran first.
		const deps = enabledDeps();
		const factory = contributionsFor(deps)?.routes?.[1] as (d: unknown) => unknown;
		expect(() => factory({ ...deps, config: { ...deps.config, rateLimit: undefined } })).toThrow(
			/rateLimit\.failMode/,
		);
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
			(req as unknown as { session: unknown }).session = {
				isAuthenticated: true,
				user: { id: "user-1" },
			};
			next();
		});
		app.use(route.mountPath, route.handler);
		return app;
	};

	/** A limiter whose backend is down: every check rejects, as a Redis client would. */
	const brokenLimiter: RateLimiter = {
		kind: "broken",
		check: async () => {
			throw new Error("redis down");
		},
	};

	it.each([
		// Under `closed` the outage is the answer; under `open` the lookup
		// proceeds to the store, which has never heard of the code.
		["closed", 503, "service_unavailable"],
		["open", 404, "invalid_user_code"],
	] as const)(
		"applies rateLimit.failMode = %s from config on the mounted device/verification route (#457)",
		async (failMode, status, error) => {
			// What no test of the handler alone can observe: that the module
			// reads `rateLimit.failMode` and hands it to this route. Before
			// #457 a limiter outage here was an unhandled throw — Express's
			// default 500, whatever the config said.
			const deps = enabledDeps();
			const app = mountVerificationRoute({
				...deps,
				config: { ...deps.config, rateLimit: { failMode } },
				rateLimiter: brokenLimiter,
			});

			const res = await request(app)
				.post("/oauth/device/verification")
				.set("Host", "as.example.test")
				.set("Origin", "http://as.example.test")
				.send({ action: "lookup", user_code: "BCDF-GHJK" });

			expect(res.status).toBe(status);
			expect(res.body.error).toBe(error);
		},
	);

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

	it("answers an unexpected failure on the mounted device/verification route with JSON 500, and logs a projection of it", async () => {
		// RFC 8628 §3.2 → RFC 6749 §5.2: this API answers in JSON, a failure
		// included. A store that throws is the host's outage, not the
		// caller's business: a fixed description in the response, and in the
		// log the error's name and message — never the error itself. An
		// ioredis reply error carries the command's arguments (the user code,
		// the approving subject); a body-parser error carries the body.
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

		expect(res.status).toBe(500);
		expect(res.headers["content-type"]).toMatch(/^application\/json/);
		expect(res.headers["cache-control"]).toBe("no-store");
		expect(res.body).toEqual({ error: "server_error", error_description: "unexpected_error" });
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{
				err: {
					name: "ReplyError",
					message: "READONLY You can't write against a read only replica.",
				},
			},
			"device_route_unexpected_error",
		);
		for (const line of lines) {
			expect(line).not.toContain("BCDFGHJK");
			expect(line).not.toContain("user-1");
			expect(line).not.toContain("s3cret-value");
		}
	});

	it("answers an unexpected failure on the mounted device_authorization route with JSON 500, and logs a projection of it", async () => {
		// A client repository that hands back a malformed registration —
		// `defaultScopes` a string rather than a list — is a failure of the
		// host's data, not of the request.
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

		expect(res.status).toBe(500);
		expect(res.headers["content-type"]).toMatch(/^application\/json/);
		expect(res.headers["cache-control"]).toBe("no-store");
		expect(res.body).toEqual({ error: "server_error", error_description: "unexpected_error" });
		expect(logger.error).toHaveBeenCalledWith(
			{ err: { name: "TypeError", message: expect.any(String) } },
			"device_route_unexpected_error",
		);
		for (const line of lines) expect(line).not.toContain(CONFIDENTIAL_SECRET);
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

	/** `enabledDeps()` with `oauth.deviceAuthorization.rateLimit` replaced. */
	const withVerificationBudget = (rateLimit: unknown) => {
		const deps = enabledDeps();
		return {
			...deps,
			config: {
				...deps.config,
				oauth: {
					...deps.config.oauth,
					deviceAuthorization: { ...deps.config.oauth.deviceAuthorization, rateLimit },
				},
			},
		};
	};

	it("refuses to mount device/verification without the budget, oauth.deviceAuthorization.rateLimit", () => {
		// #448: the "requires a rateLimiter" refusal reasons from a budget of
		// five, and the limiter applies five only because its adapter module
		// seeded `device_verification` from this key. The seed leaves the
		// adapter's 60/60s default in place when the key is missing, so a
		// hand-built config that never passed the schema booted with a
		// refusal that argued from five while the limiter applied sixty.
		const deps = withVerificationBudget(undefined);
		const factory = contributionsFor(deps)?.routes?.[1] as (d: unknown) => unknown;
		expect(() => factory(deps)).toThrow(/oauth\.deviceAuthorization\.rateLimit/);
	});

	it.each([
		["a zero limit", { limit: 0, windowSeconds: 300 }],
		["a fractional window", { limit: 5, windowSeconds: 0.5 }],
		["a string limit", { limit: "5", windowSeconds: 300 }],
	])("refuses to mount device/verification with %s as the budget", (_label, rateLimit) => {
		// The same shapes the seed declines to apply: with one definition of
		// "usable" shared with core, a budget the module accepts is one the
		// limiter was seeded from.
		const deps = withVerificationBudget(rateLimit);
		const factory = contributionsFor(deps)?.routes?.[1] as (d: unknown) => unknown;
		expect(() => factory(deps)).toThrow(/oauth\.deviceAuthorization\.rateLimit/);
	});

	it("mounts device/verification with a usable budget", () => {
		const deps = withVerificationBudget({ limit: 5, windowSeconds: 300 });
		const factory = contributionsFor(deps)?.routes?.[1] as (d: unknown) => unknown;
		expect(() => factory(deps)).not.toThrow();
	});

	it("answers 404 with no-store when the grant is disabled", async () => {
		// A 404 carrying no cache directives is the shape an intermediary
		// heuristically caches, and a cached "no device grant here" would
		// outlive the operator turning it on.
		const app = mountContributedRoute(0, {
			config: { oauth: { deviceAuthorization: { enabled: false } } },
		});
		const res = await request(app).post("/oauth/device_authorization").send({});

		expect(res.status).toBe(404);
		expect(res.headers["cache-control"]).toContain("no-store");
	});
});

describe("deviceGrantModule — disabled surface", () => {
	it("contributes no grant when disabled", () => {
		// Observable behaviour matches "not installed": with nothing
		// registered, the token endpoint answers `unsupported_grant_type` and
		// `grant_types_supported` does not name the grant — both pinned beside
		// `oauthModule` in composition.test.mts. A refusing handler registered
		// in its place was advertised as a supported grant.
		const contributes = contributionsFor({
			config: { oauth: { deviceAuthorization: { enabled: false } } },
		});
		expect(contributes?.grants).toBeUndefined();
	});

	it("contributes the grant when enabled", () => {
		const contributes = contributionsFor({
			config: { oauth: { deviceAuthorization: ENABLED } },
		});
		expect(Object.keys(contributes?.grants ?? {})).toEqual([DEVICE_CODE_GRANT_TYPE]);
	});
});

describe("deviceGrantModule — the access-token lifetime", () => {
	it("mints the configured default lifetime and ignores an expires_in request parameter", async () => {
		// The module hands the grant its lifetime at composition. Only the new
		// keys are configured, so reading the deprecated `expiresIn` would hand
		// it `undefined` and mint a token with no `exp` claim at all.
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
				},
			}),
		} satisfies DeviceCodeStore;
		const base = makeValidCoreConfig();
		const deps = {
			config: {
				oauth: {
					...base.oauth,
					accessToken: { defaultExpiresIn: 600, maxExpiresIn: 7200 },
					deviceAuthorization: {
						enabled: true,
						"verification-uri": "https://example.test/device",
					},
				},
			},
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
});

describe("deviceGrantModule — private_key_jwt on the mounted route (#484)", () => {
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

	const assertion = async (): Promise<string> => {
		const now = Math.floor(Date.now() / 1000);
		return new SignJWT({
			iss: JWT_CLIENT,
			sub: JWT_CLIENT,
			aud: `${ISSUER}/oauth/token`,
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
		config: {
			oauth: {
				jwt: { issuer: ISSUER },
				accessToken: { expiresIn: 300 },
				deviceAuthorization: {
					enabled: true,
					"verification-uri": "https://example.test/device",
					"verification-uri-complete": false,
					"code-lifetime-seconds": 600,
					"polling-interval-seconds": 5,
					rateLimit: { limit: 5, windowSeconds: 300 },
				},
			},
			session: makeValidFullSections().session,
			rateLimit: makeValidFullSections().rateLimit,
		},
		clientRepository: jwtRepository,
		deviceCodeStore: createMemoryDeviceCodeStore(),
		rateLimiter: createMemoryRateLimiter({
			limits: { device_verification: { limit: 50, windowSeconds: 300 } },
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
