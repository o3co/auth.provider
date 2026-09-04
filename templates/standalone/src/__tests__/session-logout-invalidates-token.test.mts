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
 * `POST /session/logout` must invalidate the token the `session` grant minted
 * from the same browser session.
 *
 * This lives here rather than in `packages/session` or `packages/oauth`
 * because it is the one assertion neither package can make alone: the logout
 * endpoint is in `@o3co/auth-provider-session`, the introspection and userinfo
 * endpoints are in `@o3co/auth-provider-oauth`, and the two are siblings that
 * may not import each other. The standalone template is the composition root
 * where both are mounted on one app, so it is where the contract between them
 * is testable.
 *
 * What it pins: #506 stamped `sid` on the `session` grant's access token and
 * gave `/oauth/introspect` the session-liveness check `/oauth/userinfo`
 * already ran. Both resolve the `UserSession` record — which `/session/logout`
 * used to leave alive, because it destroyed the cookie and nothing else. So in
 * the BFF / `auth.proxy` injection topology, whose logout IS this endpoint, an
 * access token minted from the session kept introspecting `active: true` and
 * kept answering at `/userinfo` for its full lifetime after the user logged
 * out. Only `/oauth/logout` with an `id_token_hint` was ever closed by #506.
 */

import { generateKeyPairSync } from "node:crypto";
import {
	type AppConfig,
	createApp,
	createKeyStoreFactory,
	createReadinessRouter,
	defineModule,
	InMemoryClientRepository,
	InMemoryUserRepository,
	memoryRefreshTokenFamilyStoreModule,
	registerBuiltinKeyStores,
} from "@o3co/auth-provider-core";
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { buildModules } from "../buildModules.mjs";

const keyPair = generateKeyPairSync("ed25519", {
	publicKeyEncoding: { type: "spki", format: "pem" },
	privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const CLIENT_ID = "bff-client";
const CLIENT_SECRET = "bff-secret";
const BASIC = `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64")}`;
const USERNAME = "alice";
const PASSWORD = "correct-horse-battery-staple";

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
					privateKey: keyPair.privateKey,
					publicKey: keyPair.publicKey,
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
		// The grant this whole test is about: it mints straight from an
		// authenticated browser session, which is the BFF topology.
		grants: { session: { enabled: true } },
		oidcMode: "oidc-required",
		code: { adapter: "memory" as const },
	},
	session: {
		secret: "test-session-secret.at-least-32-bytes.ok",
		name: "auth.sid",
		maxAge: 3600000,
		secure: false,
		sameSite: "lax",
		domain: null,
		storage: { type: "memory", redis: { url: "redis://localhost:6379" } },
	},
	rateLimit: {
		login: { windowMs: 60000, limit: 100 },
		failMode: "open",
	},
	federations: { google: { enabled: false } },
	repositories: {
		client: { type: "yaml", path: "./config/clients.yaml" },
		user: { type: "yaml", path: "./config/users.yaml", timeout: 5000 },
		code: { type: "memory", defaultExpiresIn: 600 },
	},
	endpoints: { login: { url: "/login" } },
	cors: { allowedOrigins: [] },
} as unknown as AppConfig;

const testRepositoriesModule = defineModule({
	name: "test:repositories",
	provides: {
		clientRepository: () =>
			new InMemoryClientRepository(
				new Map([
					[
						CLIENT_ID,
						{
							tokenEndpointAuthMethod: "client_secret_basic",
							clientSecret: CLIENT_SECRET,
							allowedRedirectUris: [],
							allowedScopes: ["openid", "profile"],
							allowedAudiences: [],
							allowedGrantTypes: ["session"],
							backchannelLogoutSessionRequired: true,
							frontchannelLogoutSessionRequired: true,
							allowedAzpForFederationToken: false,
						},
					],
				]),
			),
		userRepository: () =>
			new InMemoryUserRepository(
				new Map([[USERNAME, { id: "u-alice", password: PASSWORD, email: "alice@example.com" }]]),
			),
	} as never,
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

describe("POST /session/logout invalidates the session grant's access token", () => {
	let handleRef: Awaited<ReturnType<typeof createApp>> | undefined;

	afterEach(async () => {
		await handleRef?.dispose();
		handleRef = undefined;
	});

	async function buildApp() {
		const handle = await createApp({
			modules: buildModules(config, {
				keyStoreModule: testKeyStoreModule,
				repositoriesModule: testRepositoriesModule,
				refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
			}),
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		handleRef = handle;

		const app = express();
		app.use(
			createReadinessRouter(express, {
				probes: handle.readinessProbes,
				timeoutMs: config.http.readinessTimeoutMs,
			}),
		);
		app.use(handle.router);
		return app;
	}

	/**
	 * Drives the real browser half: fetch a CSRF pair, log in, and return the
	 * cookies plus the token the login response reissued. `/session/login`
	 * hands back a fresh CSRF cookie precisely so the follow-up logout needs no
	 * second round trip.
	 */
	async function login(app: express.Express) {
		const csrfRes = await request(app).get("/session/csrf");
		expect(csrfRes.status).toBe(200);
		const csrfToken = csrfRes.body.csrf_token as string;
		const headerName = csrfRes.body.header_name as string;
		const csrfCookies = csrfRes.headers["set-cookie"] as unknown as string[];

		const loginRes = await request(app)
			.post("/session/login")
			.set("Cookie", csrfCookies)
			.set(headerName, csrfToken)
			.type("form")
			.send({ username: USERNAME, password: PASSWORD });
		expect(loginRes.status).toBe(200);

		const loginCookies = loginRes.headers["set-cookie"] as unknown as string[];
		// The session cookie comes from the login response, and so does a FRESH
		// CSRF cookie — the login handler reissues one on the regenerated
		// session so the follow-up logout needs no second round trip. The
		// mechanism is a signed double-submit, so the cookie's value IS the
		// token the header has to echo; the pre-login token no longer matches.
		const reissued = loginCookies
			.map((c) => /^auth\.sid\.csrf=([^;]+)/.exec(c)?.[1])
			.find((v): v is string => v !== undefined);
		expect(reissued).toBeDefined();
		return {
			cookies: loginCookies,
			csrfToken: decodeURIComponent(reissued as string),
			headerName,
		};
	}

	it("a token minted from the session stops introspecting active after the session logs out", async () => {
		const app = await buildApp();
		const { cookies, csrfToken, headerName } = await login(app);

		// The BFF exchanges the browser session for an access token.
		const tokenRes = await request(app)
			.post("/oauth/token")
			.set("Authorization", BASIC)
			.set("Cookie", cookies)
			.type("form")
			.send({ grant_type: "session", scope: "openid profile" });
		expect(tokenRes.status).toBe(200);
		const accessToken = tokenRes.body.access_token as string;
		expect(typeof accessToken).toBe("string");

		// Before the logout the token is a live credential at both surfaces.
		const beforeIntrospect = await request(app)
			.post("/oauth/introspect")
			.set("Authorization", BASIC)
			.type("form")
			.send({ token: accessToken });
		expect(beforeIntrospect.status).toBe(200);
		expect(beforeIntrospect.body.active).toBe(true);

		const beforeUserinfo = await request(app)
			.get("/oauth/userinfo")
			.set("Authorization", `Bearer ${accessToken}`);
		expect(beforeUserinfo.status).toBe(200);

		// The logout the BFF topology actually performs — no id_token_hint, no
		// `/oauth/logout`, just the session endpoint the browser calls.
		const logoutRes = await request(app)
			.post("/session/logout")
			.set("Cookie", cookies)
			.set(headerName, csrfToken);
		expect(logoutRes.status).toBe(200);
		expect(logoutRes.body).toMatchObject({ message: "Logged out successfully" });

		// After it, the same token no longer authorizes anything. This is the
		// assertion that failed before the fix: the `UserSession` record the
		// liveness checks resolve outlived the logout.
		const afterIntrospect = await request(app)
			.post("/oauth/introspect")
			.set("Authorization", BASIC)
			.type("form")
			.send({ token: accessToken });
		expect(afterIntrospect.status).toBe(200);
		expect(afterIntrospect.body.active).toBe(false);

		const afterUserinfo = await request(app)
			.get("/oauth/userinfo")
			.set("Authorization", `Bearer ${accessToken}`);
		expect(afterUserinfo.status).toBe(401);
		expect(afterUserinfo.body.error_description).toBe("session_invalid");
	});
});
