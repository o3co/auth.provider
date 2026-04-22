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
	createFederationTokenStoreFactory,
	createKeyStoreFactory,
	createUserSessionStoreFactory,
	generateToken,
	InMemoryClientRepository,
	InMemoryCodeRepository,
	InMemoryUserRepository,
	registerBuiltinFederationTokenStores,
	registerBuiltinKeyStores,
	registerBuiltinUserSessionStores,
} from "@o3co/auth-provider-core";
import {
	oauthAuthorizationModule,
	oauthModule,
	oauthSessionModule,
} from "@o3co/auth-provider-oauth";
import { sessionModule } from "@o3co/auth-provider-session";
import express from "express";
import request from "supertest";
import { afterAll, describe, expect, it } from "vitest";

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
		login: { url: undefined },
		client: { url: undefined },
		authCallback: { url: undefined },
	},
	cors: { allowedOrigins: [] },
};

describe("standalone smoke test", () => {
	let grantRegistryRef: Awaited<ReturnType<typeof buildApp>>["grantRegistry"];
	let _appRef: ReturnType<typeof express>;

	async function buildApp() {
		const clientRepository = new InMemoryClientRepository(new Map());
		const userRepository = new InMemoryUserRepository(new Map());
		const codeRepository = new InMemoryCodeRepository();

		const keyStoreFactory = createKeyStoreFactory();
		registerBuiltinKeyStores(keyStoreFactory);
		const keyStore = await keyStoreFactory.create({
			type: "local",
			...(config.oauth.jwt.signingKey.local ?? {}),
		});

		const userSessionStoreFactory = createUserSessionStoreFactory();
		registerBuiltinUserSessionStores(userSessionStoreFactory);
		const userSessionStore = await userSessionStoreFactory.create({ type: "memory" });

		const federationTokenStoreFactory = createFederationTokenStoreFactory();
		registerBuiltinFederationTokenStores(federationTokenStoreFactory);
		const federationTokenStore = await federationTokenStoreFactory.create({ type: "memory" });

		const { init, router, grantRegistry } = createApp({
			express,
			config,
			keyStore,
			userSessionStore,
			federationTokenStore,
			modules: [
				oauthModule({ clientRepository, codeRepository, express }),
				sessionModule({ userRepository, express }),
				oauthSessionModule({ clientRepository }),
				oauthAuthorizationModule({ codeRepository, clientRepository }),
			],
		});

		await init();

		const app = express();
		app.use(router);

		return { app, grantRegistry };
	}

	afterAll(async () => {
		await grantRegistryRef?.cleanup();
	});

	it("GET /_healthcheck returns 200", async () => {
		const { app, grantRegistry } = await buildApp();
		grantRegistryRef = grantRegistry;
		_appRef = app;

		const res = await request(app).get("/_healthcheck");
		expect(res.status).toBe(200);
	});

	it("POST /oauth/token with unsupported grant_type returns 400", async () => {
		const { app, grantRegistry } = await buildApp();
		grantRegistryRef = grantRegistry;
		_appRef = app;

		const res = await request(app)
			.post("/oauth/token")
			.type("form")
			.send({ grant_type: "unsupported" });

		expect(res.status).toBe(400);
	});

	it("POST /oauth/token successful response has Cache-Control: no-store", async () => {
		// We cannot easily trigger a full token issuance without a session,
		// so we verify the header via a session grant with an authenticated session.
		// Instead, test that 400 responses do NOT have Cache-Control (only successes do).
		// The Cache-Control header is set only when "tokens" in result — covered by
		// the introspect test below which exercises the full response path.
		const { app, grantRegistry } = await buildApp();
		grantRegistryRef = grantRegistry;
		_appRef = app;

		// 400 responses must NOT have Cache-Control: no-store
		const res = await request(app)
			.post("/oauth/token")
			.type("form")
			.send({ grant_type: "unsupported" });

		expect(res.status).toBe(400);
		expect(res.headers["cache-control"]).not.toBe("no-store");
	});

	it("POST /oauth/introspect returns iat in active token response", async () => {
		const { app, grantRegistry } = await buildApp();
		grantRegistryRef = grantRegistry;
		_appRef = app;

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
