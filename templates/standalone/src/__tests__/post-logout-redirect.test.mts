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
 * A logout's `post_logout_redirect_uri` reaches the upstream federation's
 * end-session call only once it has matched one of the client's registered
 * `postLogoutRedirectUris` — at `/oauth/logout` and at
 * `POST /oauth/federation/:name/logout` alike.
 *
 * Google publishes no end-session endpoint, and without one configured its
 * adapter sends the browser straight to the `postLogoutRedirectUri` it is
 * handed. Both logout routes used to hand it the caller's value unchecked,
 * ahead of the allowlist check that guarded their own redirect, so a fresh
 * id_token of the caller's own and `post_logout_redirect_uri=https://evil…`
 * made this provider's origin answer `303` to any site. With an end-session
 * endpoint configured, the unchecked value was forwarded to the upstream
 * instead.
 *
 * The oauth package cannot show this: it does not depend on an adapter, so
 * its route tests stand one in. This is the composition a deployment runs —
 * `oauthModule`, the session module and the real Google adapter, booted
 * through `createApp` — so the redirect asserted here is the one a browser
 * would follow.
 */

import { createHmac } from "node:crypto";
import { fileURLToPath } from "node:url";
import {
	type AppConfig,
	AppConfigSchema,
	createApp,
	createKeyStoreFactory,
	defineModule,
	type FederationTokenStore,
	InMemoryClientRepository,
	InMemoryUserRepository,
	memoryRefreshTokenFamilyStoreModule,
	registerBuiltinKeyStores,
	type SessionFederationIndex,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	type GoogleProviderConfig,
	googleFederationModule,
} from "@o3co/auth-provider-federation-google";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { buildModules } from "../buildModules.mjs";
import { resolveConfigPaths, resolveLibraryReferenceConfPath } from "../configPath.mjs";

const configDir = fileURLToPath(new URL("../../config", import.meta.url));

const ISSUER = "https://auth.test";
const JWT_SECRET = "post-logout-redirect.test.at-least-32-bytes.ok";

const CLIENT_ID = "rp";
const CLIENT_SECRET = "rp-secret-value";
const BASIC = `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64")}`;
const USERNAME = "alice";
const PASSWORD = "correct-horse-battery-staple";
const SUB = "u-alice";

const REGISTERED = "https://rp.example/signed-out";
const UNREGISTERED = "https://evil.example/landing";
const GOOGLE_LOGOUT = "https://accounts.google.com/Logout";
const UPSTREAM_END_SESSION = "https://idp-logout.example/end-session";
const UPSTREAM_ID_TOKEN = "upstream-id-token";

const ENV: Readonly<Record<string, string>> = {
	OAUTH_JWT_ALGORITHM: "HS256",
	OAUTH_JWT_SECRET: JWT_SECRET,
	OAUTH_JWT_ISSUER: ISSUER,
	SESSION_SECRET: "post-logout-redirect-session.at-least-32-bytes.ok",
	SESSION_SECURE: "false",
	SESSION_NAME: "auth.session",
	SESSION_STORAGE_TYPE: "memory",
	CLIENT_USER_TYPE: "yaml",
	REFRESH_TOKEN_FAMILY_STORE_REDIS_URL: "redis://redis.test:6379",
	USER_SESSION_STORES_ADAPTER: "memory",
	RATE_LIMITER_ADAPTER: "memory",
	OAUTH_CODE_ADAPTER: "memory",
	ACCESS_TOKEN_DENYLIST_ADAPTER: "memory",
	REPLAY_SEEN_SET_ADAPTER: "memory",
	FEDERATION_TOKEN_STORE_TYPE: "memory",
	CONSENT_STORE_ADAPTER: "none",
};

/**
 * The shipped configuration under the environment above. `google: "shipped"`
 * switches the Google federation on the way an operator does, through its
 * environment variables, which is the composition with no end-session
 * endpoint (the shipped bridge has no setting for one); `"manual"` leaves it
 * off so the test can compose the adapter itself with an endpoint.
 */
function resolveConfig(google: "shipped" | "manual"): AppConfig {
	const env: Record<string, string> =
		google === "shipped"
			? {
					...ENV,
					FEDERATIONS_GOOGLE_ENABLED: "true",
					FEDERATIONS_GOOGLE_CLIENT_ID: "google-client",
					FEDERATIONS_GOOGLE_CLIENT_SECRET: "google-secret",
					FEDERATIONS_GOOGLE_CALLBACK_URL: `${ISSUER}/session/oauth/federation/google/callback`,
				}
			: { ...ENV };
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "production");
	return validate(
		parseFile(envConfPath, { env })
			.withFallback(parseFile(applicationConfPath, { env }))
			.withFallback(parseFile(resolveLibraryReferenceConfPath(), { env })),
		AppConfigSchema,
	) as AppConfig;
}

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
							postLogoutRedirectUris: [REGISTERED],
							backchannelLogoutSessionRequired: true,
							frontchannelLogoutSessionRequired: true,
							allowedAzpForFederationToken: false,
						},
					],
				]),
			),
		userRepository: () =>
			new InMemoryUserRepository(
				new Map([[USERNAME, { id: SUB, password: PASSWORD, email: "alice@example.com" }]]),
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

/** The Google federation's configuration where a deployment names an end-session endpoint. */
const googleWithEndSessionModule = defineModule({
	name: "test:google-federation-config",
	provides: {
		googleFederationConfig: (): GoogleProviderConfig => ({
			clientId: "google-client",
			clientSecret: "google-secret",
			callbackURL: `${ISSUER}/session/oauth/federation/google/callback`,
			endSessionEndpoint: UPSTREAM_END_SESSION,
		}),
	},
});

const base64url = (value: unknown): string =>
	Buffer.from(JSON.stringify(value)).toString("base64url");

/**
 * An id_token for the session, fresh, signed with the deployment's own HS256
 * key: what an RP — or anyone holding their own id_token — presents.
 */
function idTokenHint(sid: string): string {
	const header = base64url({ alg: "HS256", kid: "v0", typ: "JWT" });
	const now = Math.floor(Date.now() / 1000);
	const payload = base64url({
		iss: ISSUER,
		sub: SUB,
		aud: CLIENT_ID,
		sid,
		iat: now,
		exp: now + 3600,
	});
	const signature = createHmac("sha256", JWT_SECRET)
		.update(`${header}.${payload}`)
		.digest("base64url");
	return `${header}.${payload}.${signature}`;
}

const claimsOf = (jwt: string): Record<string, unknown> =>
	JSON.parse(Buffer.from(jwt.split(".")[1] ?? "", "base64url").toString("utf8")) as Record<
		string,
		unknown
	>;

describe("a logout's post_logout_redirect_uri reaches the upstream only once it is registered", () => {
	let handleRef: Awaited<ReturnType<typeof createApp>> | undefined;

	afterEach(async () => {
		await handleRef?.dispose();
		handleRef = undefined;
	});

	/**
	 * Boots the deployment, signs alice in, and links Google to her session as
	 * a federated sign-in would: the session's federation index names it and
	 * the token store holds its id_token. Answers the session's `sid` and the
	 * access token the `session` grant minted for it (it carries `azp`).
	 */
	async function signedInWithGoogle(google: "shipped" | "manual") {
		const config = resolveConfig(google);
		const handle = await createApp({
			modules: [
				...buildModules(config, {
					keyStoreModule: testKeyStoreModule,
					repositoriesModule: testRepositoriesModule,
					refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
				}),
				...(google === "manual" ? [googleFederationModule, googleWithEndSessionModule] : []),
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		handleRef = handle;
		const components = handle.components as {
			userSessionStore: UserSessionStore;
			sessionFederationIndex: SessionFederationIndex;
			federationTokenStore: FederationTokenStore;
		};
		const app = express();
		app.use(handle.router);

		const csrfRes = await request(app).get("/session/csrf");
		expect(csrfRes.status).toBe(200);
		const loginRes = await request(app)
			.post("/session/login")
			.set("Cookie", csrfRes.headers["set-cookie"] as unknown as string[])
			.set(csrfRes.body.header_name as string, csrfRes.body.csrf_token as string)
			.type("form")
			.send({ username: USERNAME, password: PASSWORD });
		expect(loginRes.status).toBe(200);
		const cookies = loginRes.headers["set-cookie"] as unknown as string[];

		const tokenRes = await request(app)
			.post("/oauth/token")
			.set("Authorization", BASIC)
			.set("Cookie", cookies)
			.type("form")
			.send({ grant_type: "session" });
		expect(tokenRes.status).toBe(200);
		const accessToken = tokenRes.body.access_token as string;
		const claims = claimsOf(accessToken);
		expect(claims.azp).toBe(CLIENT_ID);
		const sid = claims.sid as string;
		expect(typeof sid).toBe("string");

		const session = await components.userSessionStore.get(sid);
		if (session === null) throw new Error("fixture: the sign-in left no session");
		await components.sessionFederationIndex.addFederation(sid, "google", session.expiresAt);
		await components.federationTokenStore.attach(sid, "google", {
			accessToken: "upstream-access-token",
			expiresAt: null,
			refreshToken: undefined,
			idToken: UPSTREAM_ID_TOKEN,
			tokenType: "Bearer",
			scope: undefined,
			grantedScope: undefined,
		});
		return { app, sid, accessToken, ...components };
	}

	const rpLogout = (app: express.Express, sid: string, postLogoutRedirectUri: string) =>
		request(app)
			.get("/oauth/logout")
			.query({
				id_token_hint: idTokenHint(sid),
				post_logout_redirect_uri: postLogoutRedirectUri,
				state: "s-1",
			});

	const federationLogout = (
		app: express.Express,
		accessToken: string,
		postLogoutRedirectUri: string,
	) =>
		request(app)
			.post("/oauth/federation/google/logout")
			.set("Authorization", `Bearer ${accessToken}`)
			.type("form")
			.send({ post_logout_redirect_uri: postLogoutRedirectUri, state: "s-1" });

	describe("GET /oauth/logout, Google with no end-session endpoint", () => {
		it("does not send the browser to an unregistered post_logout_redirect_uri", async () => {
			const { app, sid, userSessionStore } = await signedInWithGoogle("shipped");

			const res = await rpLogout(app, sid, UNREGISTERED);

			expect(res.status).toBe(303);
			expect(new URL(res.headers.location as string).origin).not.toBe("https://evil.example");
			// Google's own logout page: the adapter's answer when it is handed no
			// redirect target, which is what an unregistered one now is.
			expect(res.headers.location).toBe(`${GOOGLE_LOGOUT}?state=s-1`);
			// The logout itself still happened.
			expect(await userSessionStore.get(sid)).toBeNull();
		});

		it("still returns the browser to a registered post_logout_redirect_uri, with state", async () => {
			const { app, sid, userSessionStore } = await signedInWithGoogle("shipped");

			const res = await rpLogout(app, sid, REGISTERED);

			expect(res.status).toBe(303);
			expect(res.headers.location).toBe(`${REGISTERED}?state=s-1`);
			expect(await userSessionStore.get(sid)).toBeNull();
		});
	});

	describe("GET /oauth/logout, Google with a configured end-session endpoint", () => {
		it("does not forward an unregistered post_logout_redirect_uri to the upstream", async () => {
			const { app, sid } = await signedInWithGoogle("manual");

			const res = await rpLogout(app, sid, UNREGISTERED);

			expect(res.status).toBe(303);
			const location = new URL(res.headers.location as string);
			expect(`${location.origin}${location.pathname}`).toBe(UPSTREAM_END_SESSION);
			expect(location.searchParams.get("id_token_hint")).toBe(UPSTREAM_ID_TOKEN);
			expect(location.searchParams.has("post_logout_redirect_uri")).toBe(false);
			expect(res.headers.location).not.toContain("evil.example");
		});

		it("forwards a registered one", async () => {
			const { app, sid } = await signedInWithGoogle("manual");

			const res = await rpLogout(app, sid, REGISTERED);

			expect(res.status).toBe(303);
			const location = new URL(res.headers.location as string);
			expect(`${location.origin}${location.pathname}`).toBe(UPSTREAM_END_SESSION);
			expect(location.searchParams.get("post_logout_redirect_uri")).toBe(REGISTERED);
			expect(location.searchParams.get("state")).toBe("s-1");
		});
	});

	describe("POST /oauth/federation/google/logout", () => {
		it("does not send the browser to an unregistered post_logout_redirect_uri", async () => {
			const { app, sid, accessToken, sessionFederationIndex } = await signedInWithGoogle("shipped");

			const res = await federationLogout(app, accessToken, UNREGISTERED);

			expect(res.status).toBe(303);
			expect(new URL(res.headers.location as string).origin).not.toBe("https://evil.example");
			expect(res.headers.location).toBe(`${GOOGLE_LOGOUT}?state=s-1`);
			// The federation was disconnected all the same.
			expect(await sessionFederationIndex.listFederations(sid)).not.toContain("google");
		});

		it("still returns the browser to one registered for the token's client", async () => {
			const { app, accessToken } = await signedInWithGoogle("shipped");

			const res = await federationLogout(app, accessToken, REGISTERED);

			expect(res.status).toBe(303);
			expect(res.headers.location).toBe(`${REGISTERED}?state=s-1`);
		});

		it("does not forward an unregistered one to a configured end-session endpoint", async () => {
			const { app, accessToken } = await signedInWithGoogle("manual");

			const res = await federationLogout(app, accessToken, UNREGISTERED);

			expect(res.status).toBe(303);
			const location = new URL(res.headers.location as string);
			expect(`${location.origin}${location.pathname}`).toBe(UPSTREAM_END_SESSION);
			expect(location.searchParams.has("post_logout_redirect_uri")).toBe(false);
		});
	});
});
