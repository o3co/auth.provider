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

import type { BootstrapMap, ClientRepository } from "@o3co/auth-provider-core";
import {
	createApp,
	createMemoryDeviceCodeStore,
	createMemoryRateLimiter,
	createSymmetricKeyStore,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig, makeValidFullSections } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
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

const boot = (overrides: Overrides) =>
	createApp({ modules: [deviceGrantModule], bootstrapComponents: makeBoot(overrides) });

const ENABLED = {
	enabled: true,
	"verification-uri": "https://example.test/device",
};

describe("deviceGrantModule — boot", () => {
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

	it("boots when the operator declares the store absent on purpose", async () => {
		const handle = await boot({
			deviceAuthorization: { ...ENABLED, store: "unsupported" },
			withStore: false,
		});
		await handle.dispose();
	});

	it("boots with everything wired", async () => {
		const handle = await boot({ deviceAuthorization: ENABLED });
		await handle.dispose();
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
	it("advertises the endpoint and the grant type when enabled", async () => {
		// A client has no other way to find the endpoint, so the metadata is
		// the feature being reachable rather than a description of it.
		const handle = await boot({ deviceAuthorization: ENABLED });
		const contribution = deviceGrantModule.contributes?.discoveryMetadata?.[0] as (
			deps: unknown,
		) => { metadata?: Record<string, unknown>; grantTypes?: readonly string[] };
		const result = contribution({
			config: {
				oauth: {
					jwt: { issuer: "https://as.example.test" },
					deviceAuthorization: ENABLED,
				},
			},
		});
		expect(result.metadata?.device_authorization_endpoint).toBe(
			"https://as.example.test/oauth/device_authorization",
		);
		expect(result.grantTypes).toEqual([DEVICE_CODE_GRANT_TYPE]);
		await handle.dispose();
	});

	it("advertises nothing when disabled", async () => {
		// #283's rule: the document must not claim a capability the deployment
		// does not have.
		const contribution = deviceGrantModule.contributes?.discoveryMetadata?.[0] as (
			deps: unknown,
		) => Record<string, unknown>;
		expect(
			contribution({
				config: {
					oauth: {
						jwt: { issuer: "https://as.example.test" },
						deviceAuthorization: { enabled: false },
					},
				},
			}),
		).toEqual({});
	});
});

describe("deviceGrantModule — the route it actually contributes", () => {
	/** Build the contributed router and mount it, as `assembleApp` would. */
	const mountContributedRoute = (index: number, deps: Record<string, unknown>) => {
		const factory = deviceGrantModule.contributes?.routes?.[index] as (d: unknown) => {
			mountPath: string;
			handler: express.RequestHandler;
		};
		const route = factory(deps);
		const app = express();
		app.use(route.mountPath, route.handler);
		return app;
	};

	const enabledDeps = () => ({
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
				},
			},
			session: makeValidFullSections().session,
		},
		clientRepository: confidentialRepository,
		deviceCodeStore: createMemoryDeviceCodeStore(),
		rateLimiter: createMemoryRateLimiter({
			limits: { device_verification: { limit: 5, windowSeconds: 300 } },
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
	it("answers unsupported_grant_type at the token endpoint when disabled", async () => {
		// Observable behaviour matches "not installed": the token endpoint
		// answers the same code it uses for an unregistered grant.
		const factory = deviceGrantModule.contributes?.grants?.[DEVICE_CODE_GRANT_TYPE] as (
			deps: unknown,
		) => { handle(ctx: unknown): Promise<{ result: { error?: string } }> };
		const handler = factory({ config: { oauth: { deviceAuthorization: { enabled: false } } } });
		const { result } = await handler.handle({});
		expect(result.error).toBe("unsupported_grant_type");
	});
});
