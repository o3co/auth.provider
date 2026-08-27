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

import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import {
	type AppConfig,
	createApp,
	createHealthcheckRouter,
	createKeyStoreFactory,
	createReadinessRouter,
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

const dockerfile = readFileSync(new URL("../../Dockerfile", import.meta.url), "utf8");

// #282: the template's shipped default is EdDSA with a published JWKS, so the
// smoke test signs the way a real deployment of this scaffold does. Generated
// per run — no key material is committed.
const smokeKeyPair = generateKeyPairSync("ed25519", {
	publicKeyEncoding: { type: "spki", format: "pem" },
	privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const config: AppConfig = {
	http: { port: 0, trustProxy: false, readinessTimeoutMs: 1000 },
	logging: { level: "silent" },
	oauth: {
		jwt: {
			issuer: "https://auth.test",
			signingKey: {
				provider: "local",
				local: {
					algorithm: "EdDSA",
					kid: "v0",
					privateKey: smokeKeyPair.privateKey,
					publicKey: smokeKeyPair.publicKey,
					previousKeys: [],
				},
			},
		},
		accessToken: { expiresIn: 3600 },
		refreshToken: {
			expiresIn: 86400,
			unknownFamilyPolicy: "reject" as const,
			legacyRtPolicy: "reject" as const,
		},
		grants: {},
		oidcMode: "oidc-required",
		// #330: no `authorize` section — the `allowUnmarkedClients` migration
		// flag was removed; the first-party invariant is unconditional.
		// OR-9: explicit memory adapter for the smoke test. The legacy
		// `repositories.code.type` fallback would also pick memory here,
		// but the explicit setting documents the intent and avoids
		// console.warn deprecation noise in the test output.
		code: { adapter: "memory" as const },
	},
	session: {
		// #282: `session.secret` carries a 256-bit entropy floor.
		secret: "test-session-secret.at-least-32-bytes.ok",
		name: "auth.sid",
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
		app.use(createHealthcheckRouter(express));
		app.use(
			createReadinessRouter(express, {
				probes: handle.readinessProbes,
				timeoutMs: config.http.readinessTimeoutMs,
			}),
		);
		app.use(handle.router);
		return { app, handle };
	}

	afterEach(async () => {
		await handleRef?.dispose();
		handleRef = undefined;
	});

	it("Dockerfile declares runtime metadata and runs install/build steps as node", () => {
		// Default port is 3000 but the HEALTHCHECK and EXPOSE must read it
		// from ${HTTP_PORT} so an operator overriding the env var keeps the
		// app, EXPOSE metadata, and healthcheck in sync. Assert the ENV /
		// EXPOSE / HEALTHCHECK structure rather than the literal port so the
		// test is not brittle when operators or downstream forks change the
		// default.
		// The literal `${HTTP_PORT}` token from the Dockerfile is split across
		// concatenations to sidestep biome's `noTemplateCurlyInString` rule
		// (it cannot statically tell that this string is intentionally NOT
		// a JS template placeholder — it is a Dockerfile env-substitution).
		const HTTP_PORT_VAR = `$${"{"}HTTP_PORT}`;
		expect(dockerfile).toContain("ENV HTTP_PORT=3000");
		expect(dockerfile).toContain(`EXPOSE ${HTTP_PORT_VAR}`);
		expect(dockerfile).toMatch(
			/HEALTHCHECK\s+--interval=30s\s+--timeout=3s\s+--start-period=10s\s+--retries=3/,
		);
		// Match the literal `${HTTP_PORT}` token inside the HEALTHCHECK CMD.
		// `[$]` (character class) sidesteps biome's `noTemplateCurlyInString`
		// false-positive without changing what we actually accept.
		expect(dockerfile).toMatch(
			/CMD\s+wget\s+-q\s+-O\s+\/dev\/null\s+"http:\/\/localhost:[$]\{HTTP_PORT\}\/_healthcheck"\s+\|\|\s+exit\s+1/,
		);
		expect(dockerfile).toMatch(/FROM node-base AS deps[\s\S]*USER node[\s\S]*RUN pnpm install/);
		expect(dockerfile).toMatch(/FROM deps AS builder[\s\S]*USER node[\s\S]*RUN pnpm run build/);
		expect(dockerfile).toMatch(
			/FROM node-base AS runtime[\s\S]*USER node[\s\S]*RUN pnpm install --prod/,
		);
	});

	it("GET /_healthcheck returns 200", async () => {
		const { app, handle } = await buildApp();
		handleRef = handle;
		const res = await request(app).get("/_healthcheck");
		expect(res.status).toBe(200);
	});

	it("GET /readyz returns 200 for a memory-only composition with no probes", async () => {
		// These smoke modules are all in-memory, so nothing registers a probe.
		// Readiness must not invent a dependency that is not wired.
		const { app, handle } = await buildApp();
		handleRef = handle;
		const res = await request(app).get("/readyz");
		expect(res.status).toBe(200);
		expect(res.body).toEqual({ status: "ready", checks: [] });
	});

	it("GET /readyz returns 503 naming the dependency when a probe fails", async () => {
		const { handle } = await buildApp();
		handleRef = handle;
		const app = express();
		app.use(
			createReadinessRouter(express, {
				probes: [
					{
						name: "redis",
						check: async () => {
							throw new Error("ECONNREFUSED");
						},
					},
				],
				timeoutMs: config.http.readinessTimeoutMs,
			}),
		);
		const res = await request(app).get("/readyz");
		expect(res.status).toBe(503);
		expect(res.body.status).toBe("unready");
		expect(res.body.checks[0].name).toBe("redis");
	});

	it("issuer-configured buildModules serves the advertised jwks_uri (discovery <-> JWKS presence contract)", async () => {
		// Guards the cross-module contract end-to-end against the REAL composition
		// root: core's `jwksModule` contributes `jwks_uri` to discovery AND mounts
		// the JWKS route, while `oauthModule` contributes the provider endpoints;
		// core's aggregator assembles the document. If `buildModules` ever drops
		// `jwksModule`, the issuer-configured composition now fails the discovery
		// presence contract at boot (missing `jwks_uri`) — this test fails (RED) in
		// that case. (The oauth package's integration test hand-composes both
		// modules, so only a scaffold-level test like this can catch the
		// composition root forgetting to wire jwksModule.)
		const issuerConfig: AppConfig = {
			...config,
			oauth: {
				...config.oauth,
				jwt: { ...config.oauth.jwt, issuer: "https://auth.example.com" },
			},
		};
		const handle = await createApp({
			modules: buildModules(issuerConfig, {
				keyStoreModule: testKeyStoreModule,
				repositoriesModule: testRepositoriesModule,
				refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
			}),
			bootstrapComponents: { config: issuerConfig, pathResolver: (s) => s },
		});
		handleRef = handle;
		const app = express();
		app.use(handle.router);
		const disco = await request(app).get("/.well-known/openid-configuration");
		expect(disco.status).toBe(200);
		const jwksPath = new URL(disco.body.jwks_uri as string).pathname;
		const res = await request(app).get(jwksPath);
		expect(res.status).toBe(200);
		expect(Array.isArray(res.body.keys)).toBe(true);
		// #282: presence is no longer enough — the advertised jwks_uri must
		// publish an actual verification key, and never the private half.
		expect(res.body.keys).toHaveLength(1);
		expect(res.body.keys[0].alg).toBe("EdDSA");
		expect(res.body.keys[0].kid).toBe("v0");
		expect(res.body.keys[0].d).toBeUndefined();
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

	// #277: the scaffold used to wire NO access-token denylist, so the
	// `/oauth/revoke` it shipped answered 200 for an access token and left the
	// JWT working until expiry. The template now always wires one, and its own
	// application.conf selects the Redis-backed adapter — the memory one forks
	// per replica and `deployment.mode = "multi"` refuses it.
	describe("#277: access-token denylist wiring", () => {
		it("always wires a denylist, so /oauth/revoke can keep its promise", () => {
			const modules = buildModules(config, {
				keyStoreModule: testKeyStoreModule,
				repositoriesModule: testRepositoriesModule,
				refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
			});
			const providesDenylist = modules.filter((m) =>
				Object.keys(m.provides ?? {}).includes("accessTokenDenylist"),
			);
			expect(providesDenylist).toHaveLength(1);
		});

		it("defaults to the memory denylist when no adapter is configured", () => {
			const modules = buildModules(config, {
				keyStoreModule: testKeyStoreModule,
				repositoriesModule: testRepositoriesModule,
				refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
			});
			const names = modules.map((m) => m.name);
			expect(names).toContain("core-access-token-denylist-memory");
			expect(names).not.toContain("redis-access-token-denylist");
		});

		it("switches to the Redis denylist when accessTokenDenylist.adapter = 'redis'", () => {
			const redisDenylistConfig = {
				...config,
				accessTokenDenylist: { adapter: "redis" as const },
			};
			const modules = buildModules(redisDenylistConfig, {
				keyStoreModule: testKeyStoreModule,
				repositoriesModule: testRepositoriesModule,
				refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
			});
			const names = modules.map((m) => m.name);
			expect(names).toContain("redis-access-token-denylist");
			expect(names).not.toContain("core-access-token-denylist-memory");
			// The Redis branch must also pull in the shared ioredis socket, or the
			// `accessTokenDenylistClient` slot has no provider and boot fails on a
			// missing component instead of on the thing the operator changed.
			expect(names).toContain("standalone:redis-clients");
		});

		it("the shipped application.conf selects the replica-safe adapter", () => {
			// The template's own config is the artifact operators deploy. It runs
			// with `deployment.mode = multi` in the umbrella E2E, which refuses
			// every in-memory shared store — so shipping the memory denylist here
			// would be a boot failure in the very stack that proves the scaffold
			// works.
			const conf = readFileSync(new URL("../../config/application.conf", import.meta.url), "utf8");
			expect(conf).toMatch(/accessTokenDenylist\s*\{[\s\S]*?adapter\s*=\s*"redis"/);
		});

		it("keeps the composition boot-valid end to end", async () => {
			// The core boot guard (#277 step 13.9) refuses a composition that reads
			// the denylist slot without one. A scaffold that trips its own library's
			// guard is not a scaffold.
			const handle = await createApp({
				modules: buildModules(config, {
					keyStoreModule: testKeyStoreModule,
					repositoriesModule: testRepositoriesModule,
					refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
				}),
				bootstrapComponents: { config, pathResolver: (s) => s },
			});
			handleRef = handle;
			expect(handle).toBeDefined();
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
		// The token must carry the deployment's configured `iss`: introspection
		// pins it (RFC 9068 §4), and since #266 every deployment has one.
		const { token } = await generateToken(
			{},
			{
				keyStore,
				subject: "u1",
				expiresIn: 3600,
				tokenType: "at+jwt",
				issuer: config.oauth.jwt.issuer,
			},
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
