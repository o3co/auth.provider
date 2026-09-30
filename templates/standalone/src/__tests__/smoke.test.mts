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

// The template's shipped default is EdDSA with a published JWKS, so the
// smoke test signs the way a real deployment of this scaffold does. Generated
// per run — no key material is committed.
const smokeKeyPair = generateKeyPairSync("ed25519", {
	publicKeyEncoding: { type: "spki", format: "pem" },
	privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

/** The `http` module's section, as the hand-built configuration below carries it. */
const HTTP = { port: 0, trustProxy: false, readinessTimeoutMs: 1000 };

const config: AppConfig = {
	http: HTTP,
	logging: { level: "silent" },
	// A composition with a consumer of session admission states what it
	// expects (ADR 2026-09-28-session-admission): the shipped
	// `application.conf` expects none, and so does this hand-built config.
	sessionRequirements: { expected: [] },
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
		// No `authorize` section: the first-party invariant is unconditional.
		// The memory adapter is explicit: the legacy `repositories.code.type`
		// fallback would also pick memory, but with a deprecation warning.
		code: { adapter: "memory" as const },
	},
	session: {
		// `session.secret` carries a 256-bit entropy floor.
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
 * The one confidential client, so the `clientAuthMw` middleware in front of
 * `/oauth/token` has a record to authenticate against. Smoke tests that hit
 * `/oauth/token` send `Authorization: ${SMOKE_BASIC_AUTH}`.
 */
const SMOKE_CLIENT_ID = "smoke-client";
const SMOKE_CLIENT_SECRET = "smoke-secret";
const SMOKE_BASIC_AUTH = `Basic ${Buffer.from(`${SMOKE_CLIENT_ID}:${SMOKE_CLIENT_SECRET}`).toString("base64")}`;

/**
 * Test-only repository module in place of the file-system-backed repositories
 * `repositoriesModule` provides in production: the smoke tests verify the
 * boot pipeline shape, not the data layer. `codeRepository` is not provided
 * here; the `oauth.code.adapter` switch in `buildModules` wires it.
 */
const testRepositoriesModule = defineModule({
	name: "test:repositories",
	provides: {
		// The map takes `ClientEntry`, the schema's OUTPUT type, where fields
		// with `.default(...)` are required; every field is supplied so the
		// literal needs no cast.
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
				...((c as AppConfig).oauth.jwt.signingKey?.local ?? {}),
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
				// A memory RT family store in place of the default Redis store and
				// its client, so no real ioredis connection is opened.
				refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
			}),
			bootstrapComponents: { config, pathResolver: (s) => s },
		});

		const app = express();
		app.use(createHealthcheckRouter(express));
		app.use(
			createReadinessRouter(express, {
				probes: handle.readinessProbes,
				timeoutMs: HTTP.readinessTimeoutMs,
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
		// HEALTHCHECK and EXPOSE must read the port from ${HTTP_PORT} so an
		// operator overriding it keeps the app, EXPOSE and the healthcheck in
		// sync; they are asserted by that token, not the literal port. The token
		// is built by concatenation to sidestep biome's
		// `noTemplateCurlyInString`: it is a Dockerfile substitution, not JS.
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
		expect(dockerfile).toMatch(
			/FROM node-base AS deps[\s\S]*USER node[\s\S]*RUN pnpm install --frozen-lockfile/,
		);
		expect(dockerfile).toMatch(/FROM deps AS builder[\s\S]*USER node[\s\S]*RUN pnpm run build/);
		// Dependencies are resolved exactly once, in `deps`. The runtime
		// stage must take its node_modules from a prune of that same tree — a
		// second `pnpm install` would be a second resolution, so its absence
		// after the runtime FROM is part of the contract.
		expect(dockerfile).toMatch(
			/FROM deps AS prod-deps[\s\S]*USER node[\s\S]*RUN pnpm prune --prod/,
		);
		expect(dockerfile).toMatch(
			/FROM node-base AS runtime[\s\S]*COPY --from=prod-deps[\s\S]*USER node/,
		);
		expect(dockerfile.slice(dockerfile.indexOf("FROM node-base AS runtime"))).not.toContain(
			"pnpm install",
		);
	});

	it("Dockerfile pins its mutable build inputs", () => {
		// Base image by digest — the tag alone is a moving pointer, and
		// Dependabot's docker ecosystem bumps tag and digest together.
		expect(dockerfile).toMatch(/FROM node:26-alpine@sha256:[0-9a-f]{64} AS node-base/);
		// Global corepack by version — `npm install -g corepack` with no pin
		// resolves whatever is latest at build time.
		expect(dockerfile).toMatch(/npm install -g corepack@\d+\.\d+\.\d+ --force/);
		// The lockfile is a required build input for --frozen-lockfile.
		expect(dockerfile).toMatch(/COPY --chown=node:node package\.json pnpm-lock\.yaml/);
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
				timeoutMs: HTTP.readinessTimeoutMs,
			}),
		);
		const res = await request(app).get("/readyz");
		expect(res.status).toBe(503);
		expect(res.body.status).toBe("unready");
		expect(res.body.checks[0].name).toBe("redis");
	});

	it("issuer-configured buildModules serves the advertised jwks_uri (discovery <-> JWKS presence contract)", async () => {
		// Against the REAL composition root: core's `jwksModule` contributes
		// `jwks_uri` to discovery AND mounts the JWKS route. Without it the
		// issuer-configured composition fails the discovery presence contract
		// at boot. The oauth package's integration test composes both modules by
		// hand, so only a scaffold-level test catches `buildModules` dropping it.
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
		// Presence is not enough — the advertised jwks_uri must
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

	// A freshly scaffolded app must boot under the default
	// `federations.google.enabled = false`. `buildModules` includes
	// `googleFederationModule` and its config bridge only when enabled, since
	// the bridge throws at boot when `extractFederationSection` returns
	// undefined. The manifest is asserted directly, so a bypassed gate fails
	// even if the bridge is later made tolerant of `undefined`; then the
	// handle must still boot.
	it("boots when google federation is disabled (default scaffold config)", async () => {
		const modules = buildModules(config, {
			keyStoreModule: testKeyStoreModule,
			repositoriesModule: testRepositoriesModule,
			refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
		});
		const moduleNames = modules.map((m) => m.name);
		expect(moduleNames).not.toContain("federation-google");
		expect(moduleNames).not.toContain("google-federation-config");

		const handle = await createApp({
			modules,
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		handleRef = handle;
		expect(handle).toBeDefined();
	});

	// The composition root must default to the Redis-backed RT family store
	// and the ioredis client module, NOT the in-memory store: multi-replica
	// deployments lose RT family persistence when each replica holds families
	// in-process. The smoke tests above exercise the memory override.
	describe("redis-clients + adapter wiring", () => {
		it("buildModules includes the shared redis-clients module + redis store by default", () => {
			const modules = buildModules(config, {
				keyStoreModule: testKeyStoreModule,
				repositoriesModule: testRepositoriesModule,
			});
			const names = modules.map((m) => m.name);
			expect(names).toContain("redis-clients");
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
			expect(names).not.toContain("redis-clients");
			expect(names).not.toContain("redis-refresh-token-family-store");
		});

		it("buildModules wires memoryRateLimiterModule by default", () => {
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
			expect(names).toContain("redis-clients");
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
			expect(names).toContain("redis-session-stores");
			expect(names).not.toContain("stores");
			expect(names).toContain("redis-clients");
		});

		// The tests above check which modules are selected, not whether the
		// selection is satisfiable: a `*Client` slot with no provider (such as
		// `redisSessionStoresModule`'s `subjectSessionIndexClient`) fails
		// stage-1 boot with `missing-required-component`. The invariant the
		// shared clients module exists for: every `*Client` slot any selected
		// module requires is one it provides.
		it("redis-clients provides every *Client slot the Redis branches require", () => {
			const allRedisConfig = {
				...config,
				userSessionStores: { adapter: "redis" as const },
				rateLimiter: { adapter: "redis" as const },
				accessTokenDenylist: { adapter: "redis" as const },
				consentStore: { adapter: "redis" as const },
				oauth: { ...config.oauth, code: { adapter: "redis" as const } },
			};
			// No `refreshTokenFamilyModules` override: the default is the Redis
			// RT-family store, so `refreshTokenFamilyClient` is part of what the
			// invariant covers. Still hermetic — buildModules opens no socket.
			const modules = buildModules(allRedisConfig, {
				keyStoreModule: testKeyStoreModule,
				repositoriesModule: testRepositoriesModule,
			});
			const clients = modules.find((m) => m.name === "redis-clients");
			expect(clients).toBeDefined();
			const provided = new Set(Object.keys(clients?.provides ?? {}));
			const requiredClientSlots = new Set(
				modules.flatMap((m) => [...(m.requires ?? [])]).filter((key) => key.endsWith("Client")),
			);
			expect(requiredClientSlots.size).toBeGreaterThan(0);
			const missing = [...requiredClientSlots].filter((key) => !provided.has(key));
			expect(missing).toEqual([]);
		});
	});

	// Without an access-token denylist, `/oauth/revoke` would answer 200 for
	// an access token and leave the JWT working until expiry. The template
	// always wires one, and its own application.conf selects the Redis-backed
	// adapter — the memory one forks per replica and `deployment.mode =
	// "multi"` refuses it.
	describe("access-token denylist wiring", () => {
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
			expect(names).toContain("redis-clients");
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
			// The core boot guard refuses a composition that reads
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

	// Adapter switch for the OAuth code repository: the memory branch wires
	// `inMemoryCodeRepositoryModule`; the redis branch wires
	// `redisCodeRepositoryModule` against the shared ioredis socket.
	describe("code-repository adapter wiring", () => {
		it("buildModules wires inMemoryCodeRepositoryModule by default (oauth.code.adapter = 'memory')", () => {
			const modules = buildModules(config, {
				keyStoreModule: testKeyStoreModule,
				repositoriesModule: testRepositoriesModule,
				refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
			});
			const names = modules.map((m) => m.name);
			expect(names).toContain("standalone-in-memory-code-repository");
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
			expect(names).not.toContain("standalone-in-memory-code-repository");
			// adapter = "redis" pulls in the shared ioredis socket so the
			// `codeRepositoryClient` slot is satisfied.
			expect(names).toContain("redis-clients");
		});

		it("buildModules honors legacy repositories.code.type='redis' with one object-first deprecation warn when oauth.code.adapter is absent", () => {
			const warn = vi.fn();
			const logger = {
				trace: vi.fn(),
				debug: vi.fn(),
				info: vi.fn(),
				warn,
				error: vi.fn(),
				fatal: vi.fn(),
				child: () => logger,
			};
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
				logger,
			});
			const names = modules.map((m) => m.name);
			expect(names).toContain("redis-code-repository");
			expect(warn.mock.calls).toEqual([
				[
					{
						key: "repositories.code.type",
						env: "CLIENT_CODE_TYPE",
						replacement: "oauth.code.adapter",
						replacementEnv: "OAUTH_CODE_ADAPTER",
					},
					"config_key_deprecated",
				],
			]);
			for (const level of ["trace", "debug", "info", "error", "fatal"] as const) {
				expect(logger[level]).not.toHaveBeenCalled();
			}
		});

		it("buildModules has only ONE codeRepository provider in the manifest (no slot collision)", () => {
			// `repositoriesModule` must NOT provide `codeRepository` — the slot
			// is owned by `inMemoryCodeRepositoryModule` or
			// `redisCodeRepositoryModule` exclusively, selected via
			// `oauth.code.adapter`.
			const modules = buildModules(config, {
				keyStoreModule: testKeyStoreModule,
				// The production repositoriesModule (not the test override), so
				// its own provides are exercised.
				refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
			});
			const codeRepoProviders = modules.filter((m) =>
				Object.keys(m.provides ?? {}).includes("codeRepository"),
			);
			expect(codeRepoProviders).toHaveLength(1);
			expect(codeRepoProviders[0]?.name).toBe("standalone-in-memory-code-repository");
		});
	});

	it("POST /oauth/introspect returns iat in active token response", async () => {
		const { app, handle } = await buildApp();
		handleRef = handle;

		const ksf = createKeyStoreFactory();
		registerBuiltinKeyStores(ksf);
		const keyStore = await ksf.create({
			type: "local",
			...(config.oauth.jwt.signingKey?.local ?? {}),
		});
		// The token must carry the deployment's configured `iss`: introspection
		// pins it (RFC 9068 §4), and every deployment has one.
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
