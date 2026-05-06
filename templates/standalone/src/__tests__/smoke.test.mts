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

import {
	type AppConfig,
	createApp,
	createKeyStoreFactory,
	defineModule,
	generateToken,
	InMemoryClientRepository,
	InMemoryUserRepository,
	memoryRefreshTokenFamilyStoreModule,
	registerBuiltinKeyStores,
} from "@o3co/auth-provider-core";
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildModules } from "../buildModules.mjs";

const config: AppConfig = {
	http: { port: 0, trustProxy: false },
	oauth: {
		jwt: {
			signingKey: {
				provider: "local",
				local: {
					algorithm: "HS256",
					secret: "test-secret-for-smoke-test",
					kid: "v0",
					previousKeys: [],
				},
			},
		},
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {},
		// OR-9: explicit memory adapter for the smoke test. The legacy
		// `repositories.code.type` fallback would also pick memory here,
		// but the explicit setting documents the intent and avoids
		// console.warn deprecation noise in the test output.
		code: { adapter: "memory" as const },
	},
	session: {
		secret: "test-session-secret",
		maxAge: 3600000,
		secure: false,
		sameSite: "lax",
		domain: null,
		storage: { type: "memory", redis: { url: "redis://localhost:6379" } },
	},
	rateLimit: {
		login: { windowMs: 60000, limit: 10 },
		failMode: "open",
	},
	federations: {
		google: { enabled: false },
	},
	repositories: {
		client: { type: "yaml", path: "./config/clients.yaml" },
		user: { type: "yaml", path: "./config/users.yaml", timeout: 5000 },
		code: { type: "memory", defaultExpiresIn: 600 },
	},
	endpoints: {
		login: { url: "/login" },
	},
	cors: { allowedOrigins: [] },
};

/**
 * Test-only repository module — bypasses the file-system-backed repositories
 * that `repositoriesModule` provides in production. Smoke tests use in-memory
 * empty repositories to verify the boot pipeline shape, not the data layer.
 *
 * Post-OR-9 (Wave 5d): `codeRepository` is no longer provided here — it is
 * wired by `inMemoryCodeRepositoryModule` (or `redisCodeRepositoryModule`)
 * via the `oauth.code.adapter` switch in `buildModules`. The smoke test
 * config sets `oauth.code.adapter = "memory"`, so `inMemoryCodeRepositoryModule`
 * is added automatically and provides the slot.
 *
 * D-6 (v0.5.1): a single confidential client is registered so the
 * `clientAuthMw` middleware in front of `/oauth/token` has a record to
 * authenticate against. Smoke tests that hit `/oauth/token` send
 * `Authorization: ${SMOKE_BASIC_AUTH}`.
 */
const SMOKE_CLIENT_ID = "smoke-client";
const SMOKE_CLIENT_SECRET = "smoke-secret";
const SMOKE_BASIC_AUTH = `Basic ${Buffer.from(`${SMOKE_CLIENT_ID}:${SMOKE_CLIENT_SECRET}`).toString("base64")}`;

const testRepositoriesModule = defineModule({
	name: "test:repositories",
	provides: {
		// `InMemoryClientRepository` constructor parameter `Map<string, ClientEntry>`
		// uses `ClientEntry = z.infer<typeof ClientEntrySchema>` (the schema's
		// OUTPUT type) — fields with `.default(...)` are non-optional in the
		// output even though they are optional on input. The fixture supplies
		// every field explicitly so the literal satisfies the output shape
		// without requiring a cast.
		clientRepository: () =>
			new InMemoryClientRepository(
				new Map([
					[
						SMOKE_CLIENT_ID,
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: SMOKE_CLIENT_SECRET,
							allowedRedirectUris: [],
							allowedScopes: [],
							allowedAudiences: [],
							backchannelLogoutSessionRequired: true,
							frontchannelLogoutSessionRequired: true,
							allowedAzpForFederationToken: false,
						},
					],
				]),
			),
		userRepository: () => new InMemoryUserRepository(new Map()),
	},
});

const testKeyStoreModule = defineModule({
	name: "test:key-store",
	requires: ["config"] as const,
	provides: {
		keyStore: async ({ config: c }) => {
			const factory = createKeyStoreFactory();
			registerBuiltinKeyStores(factory);
			return factory.create({
				type: "local",
				...((c as AppConfig).oauth.jwt.signingKey.local ?? {}),
			});
		},
	},
});

describe("standalone smoke test", () => {
	let handleRef: Awaited<ReturnType<typeof buildApp>>["handle"] | undefined;

	async function buildApp() {
		const handle = await createApp({
			modules: buildModules(config, {
				keyStoreModule: testKeyStoreModule,
				repositoriesModule: testRepositoriesModule,
				// D-2 v2: smoke tests stay in-memory for the RT family store.
				// Production composition root pairs `refreshTokenFamilyClientModule`
				// with `redisRefreshTokenFamilyStoreModule`; this override replaces
				// the pair entirely with a single memory-backed store module so no
				// real ioredis connection is opened during CI unit tests.
				refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
			}),
			bootstrapComponents: { config, pathResolver: (s) => s },
		});

		const app = express();
		app.get("/_healthcheck", (_req, res) => {
			res.status(200).json({ status: "ok" });
		});
		app.use(handle.router);
		return { app, handle };
	}

	afterEach(async () => {
		await handleRef?.dispose();
		handleRef = undefined;
	});

	it("GET /_healthcheck returns 200", async () => {
		const { app, handle } = await buildApp();
		handleRef = handle;
		const res = await request(app).get("/_healthcheck");
		expect(res.status).toBe(200);
	});

	it("POST /oauth/token with unsupported grant_type returns 400", async () => {
		const { app, handle } = await buildApp();
		handleRef = handle;
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", SMOKE_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "unsupported" });
		expect(res.status).toBe(400);
	});

	it("POST /oauth/token 400 responses do NOT have Cache-Control: no-store", async () => {
		const { app, handle } = await buildApp();
		handleRef = handle;
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", SMOKE_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "unsupported" });
		expect(res.status).toBe(400);
		expect(res.headers["cache-control"]).not.toBe("no-store");
	});

	// Regression guard: a freshly scaffolded standalone app must boot under
	// the default `federations.google.enabled = false`. The earlier shape of
	// app.mts unconditionally listed `googleFederationModule` and the config
	// bridge `googleFederationConfigModule`, so the bridge's
	// `extractFederationSection` returned undefined and threw at boot. The
	// fix moved the manifest assembly into `buildModules`, which conditionally
	// includes the federation pair. The first sub-assertion asserts directly
	// on the manifest list — a regression that bypasses the gate fails the
	// `not.toContain` even if `googleFederationConfigModule` is later made
	// tolerant of `undefined` (which would otherwise mask the gating bug).
	// The second sub-assertion verifies the resulting handle still boots
	// (Codex Round 1 P1 reproducibility).
	it("boots when google federation is disabled (default scaffold config)", async () => {
		const modules = buildModules(config, {
			keyStoreModule: testKeyStoreModule,
			repositoriesModule: testRepositoriesModule,
			refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
		});
		const moduleNames = modules.map((m) => m.name);
		expect(moduleNames).not.toContain("federation:google");
		expect(moduleNames).not.toContain("standalone:google-federation-config");

		const handle = await createApp({
			modules,
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		handleRef = handle;
		expect(handle).toBeDefined();
	});

	// D-2 v2 / OR-1 closure: the standalone composition root must default to the
	// Redis-backed RT family store + ioredis client module pair, NOT the
	// in-memory store. Multi-replica deployments lose RT family persistence
	// when each replica holds families in-process; this test guards the
	// production default. The override path is exercised by the smoke tests
	// above (which substitute the memory store for CI).
	describe("D-2 v2 + Wave 5d: redis-clients + adapter wiring", () => {
		it("buildModules includes the shared redis-clients module + redis store by default", () => {
			const modules = buildModules(config, {
				keyStoreModule: testKeyStoreModule,
				repositoriesModule: testRepositoriesModule,
			});
			const names = modules.map((m) => m.name);
			// Wave 5d: single shared ioredis client module (was per-purpose
			// `standalone:refresh-token-family-client` in PR1).
			expect(names).toContain("standalone:redis-clients");
			expect(names).toContain("redis-refresh-token-family-store");
			expect(names).not.toContain("core-refresh-token-family-store-memory");
		});

		it("buildModules drops the shared redis-clients module when override forces memory-only", () => {
			const modules = buildModules(config, {
				keyStoreModule: testKeyStoreModule,
				repositoriesModule: testRepositoriesModule,
				refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
			});
			const names = modules.map((m) => m.name);
			expect(names).toContain("core-refresh-token-family-store-memory");
			expect(names).not.toContain("standalone:redis-clients");
			expect(names).not.toContain("redis-refresh-token-family-store");
		});

		it("buildModules wires memoryRateLimiterModule by default (closes IH-14)", () => {
			const modules = buildModules(config, {
				keyStoreModule: testKeyStoreModule,
				repositoriesModule: testRepositoriesModule,
				refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
			});
			const names = modules.map((m) => m.name);
			expect(names).toContain("core-rate-limiter-memory");
			expect(names).not.toContain("redis-rate-limiter");
		});

		it("buildModules switches to redisRateLimiterModule when rateLimiter.adapter = 'redis'", () => {
			const redisRlConfig = {
				...config,
				rateLimiter: { adapter: "redis" as const },
			};
			const modules = buildModules(redisRlConfig, {
				keyStoreModule: testKeyStoreModule,
				repositoriesModule: testRepositoriesModule,
				refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
			});
			const names = modules.map((m) => m.name);
			expect(names).toContain("redis-rate-limiter");
			expect(names).not.toContain("core-rate-limiter-memory");
			// Adapter = redis pulls in the shared redis-clients module too.
			expect(names).toContain("standalone:redis-clients");
		});

		it("buildModules switches to redisSessionStoresModule when userSessionStores.adapter = 'redis'", () => {
			const redisSessConfig = {
				...config,
				userSessionStores: { adapter: "redis" as const },
			};
			const modules = buildModules(redisSessConfig, {
				keyStoreModule: testKeyStoreModule,
				repositoriesModule: testRepositoriesModule,
				refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
			});
			const names = modules.map((m) => m.name);
			expect(names).toContain("redisSessionStores");
			expect(names).not.toContain("standalone:stores");
			expect(names).toContain("standalone:redis-clients");
		});
	});

	// OR-9 (Wave 5d): adapter switch for the OAuth code repository. Closes
	// the deferred Phase 10 module-pattern wrapper for `codeRepository`. The
	// memory branch wires `inMemoryCodeRepositoryModule`; the redis branch
	// wires `redisCodeRepositoryModule` against the shared ioredis socket
	// (same `standaloneRedisClientsModule` as the RT family / rate limiter).
	describe("OR-9: code-repository adapter wiring", () => {
		it("buildModules wires inMemoryCodeRepositoryModule by default (oauth.code.adapter = 'memory')", () => {
			const modules = buildModules(config, {
				keyStoreModule: testKeyStoreModule,
				repositoriesModule: testRepositoriesModule,
				refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
			});
			const names = modules.map((m) => m.name);
			expect(names).toContain("standalone:in-memory-code-repository");
			expect(names).not.toContain("redis-code-repository");
		});

		it("buildModules switches to redisCodeRepositoryModule when oauth.code.adapter = 'redis'", () => {
			const redisCodeConfig = {
				...config,
				oauth: { ...config.oauth, code: { adapter: "redis" as const } },
			};
			const modules = buildModules(redisCodeConfig, {
				keyStoreModule: testKeyStoreModule,
				repositoriesModule: testRepositoriesModule,
				refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
			});
			const names = modules.map((m) => m.name);
			expect(names).toContain("redis-code-repository");
			expect(names).not.toContain("standalone:in-memory-code-repository");
			// adapter = "redis" pulls in the shared ioredis socket so the
			// `codeRepositoryClient` slot is satisfied.
			expect(names).toContain("standalone:redis-clients");
		});

		it("buildModules honors legacy repositories.code.type='redis' with deprecation warn when oauth.code.adapter is absent", () => {
			const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
			try {
				const legacyConfig = {
					...config,
					oauth: { ...config.oauth, code: undefined },
					repositories: {
						...config.repositories,
						code: { type: "redis" as const, defaultExpiresIn: 600 },
					},
				};
				const modules = buildModules(legacyConfig, {
					keyStoreModule: testKeyStoreModule,
					repositoriesModule: testRepositoriesModule,
					refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
				});
				const names = modules.map((m) => m.name);
				expect(names).toContain("redis-code-repository");
				expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("repositories.code.type"));
			} finally {
				warnSpy.mockRestore();
			}
		});

		it("buildModules has only ONE codeRepository provider in the manifest (no slot collision)", () => {
			// Regression guard: `repositoriesModule` must NOT provide
			// `codeRepository` post-OR-9 — the slot is owned by
			// `inMemoryCodeRepositoryModule` or `redisCodeRepositoryModule`
			// exclusively, selected via `oauth.code.adapter`.
			const modules = buildModules(config, {
				keyStoreModule: testKeyStoreModule,
				// Use the production repositoriesModule (not the test override)
				// so we exercise its post-OR-9 provides-shape.
				refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
			});
			const codeRepoProviders = modules.filter((m) =>
				Object.keys(m.provides ?? {}).includes("codeRepository"),
			);
			expect(codeRepoProviders).toHaveLength(1);
			expect(codeRepoProviders[0]?.name).toBe("standalone:in-memory-code-repository");
		});
	});

	it("POST /oauth/introspect returns iat in active token response", async () => {
		const { app, handle } = await buildApp();
		handleRef = handle;

		const ksf = createKeyStoreFactory();
		registerBuiltinKeyStores(ksf);
		const keyStore = await ksf.create({
			type: "local",
			...(config.oauth.jwt.signingKey.local ?? {}),
		});
		const { token } = await generateToken(
			{},
			{ keyStore, subject: "u1", expiresIn: 3600, tokenType: "at+jwt" },
		);

		const res = await request(app)
			.post("/oauth/introspect")
			.set("Authorization", `Bearer ${token}`)
			.type("form")
			.send({ token });

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
		expect(typeof res.body.iat).toBe("number");
	});
});
