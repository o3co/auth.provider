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
	InMemoryCodeRepository,
	InMemoryUserRepository,
	registerBuiltinKeyStores,
} from "@o3co/auth-provider-core";
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
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
		client: { url: undefined },
		authCallback: { url: undefined },
	},
	cors: { allowedOrigins: [] },
};

/**
 * Test-only repository module — bypasses the file-system-backed repositories
 * that `repositoriesModule` provides in production. Smoke tests use in-memory
 * empty repositories to verify the boot pipeline shape, not the data layer.
 */
const testRepositoriesModule = defineModule({
	name: "test:repositories",
	provides: {
		clientRepository: () => new InMemoryClientRepository(new Map()),
		userRepository: () => new InMemoryUserRepository(new Map()),
		codeRepository: () => new InMemoryCodeRepository(),
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
			.type("form")
			.send({ grant_type: "unsupported" });
		expect(res.status).toBe(400);
	});

	it("POST /oauth/token 400 responses do NOT have Cache-Control: no-store", async () => {
		const { app, handle } = await buildApp();
		handleRef = handle;
		const res = await request(app)
			.post("/oauth/token")
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
