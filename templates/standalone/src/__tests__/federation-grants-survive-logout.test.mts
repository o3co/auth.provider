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
 * #593 acceptance criterion 8, at the two HTTP logout endpoints (D14).
 *
 * A federation grant outlives the session it was agreed through. The proof of
 * that used to be a direct call to `cascadeLogout()` — which is the cascade
 * `/oauth/logout` runs, and not what `/session/logout` runs: that endpoint has
 * its own record hygiene (`invalidateSessionRecords`) and reaches the grant
 * store on no path, by construction. A proof of the helper is not a proof of
 * the endpoints. So this drives both, on the standalone, as a deployment
 * composes them: a grant seeded beside a live browser session, the session's
 * records gone afterwards, the grant and its credential exactly as they were,
 * and `/token` still disclosing.
 *
 * The seeded grant's access token is fresh, so the disclosure is the cached
 * one and no upstream is asked — the OIDC federation the connection names is
 * configured with `discovery = false` and hand-typed endpoints so that the
 * deployment boots without a network.
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
	federationGrantAuthorizationRevision,
	federationGrantIdentityRevision,
	InMemoryClientRepository,
	InMemoryUserRepository,
	type MemoryFederationGrantStore,
	memoryRefreshTokenFamilyStoreModule,
	registerBuiltinKeyStores,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { buildModules } from "../buildModules.mjs";
import { resolveConfigPaths, resolveLibraryReferenceConfPath } from "../configPath.mjs";

const DAY = 86_400_000;
const configDir = fileURLToPath(new URL("../../config", import.meta.url));

const ISSUER = "https://auth.test";
const JWT_SECRET = "federation-grants-survive-logout.at-least-32-bytes.ok";
const UPSTREAM = "https://issuer.example";
const UPSTREAM_CLIENT_ID = "provider-client";
const ENCRYPTION_KEY = Buffer.alloc(32, 9).toString("base64");

const CLIENT_ID = "worker";
const CLIENT_SECRET = "worker-secret-value";
const BASIC = `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64")}`;
const USERNAME = "alice";
const PASSWORD = "correct-horse-battery-staple";
const SUB = "u-alice";

const CONNECTION = "calendar";
const SCOPES: readonly string[] = ["openid", "offline_access", "calendar.read"];
const BOUNDARY = "production";
const GRANT_ID = "g-1";
const REFRESH_TOKEN = "SENTINEL-refresh-token";
const ACCESS_TOKEN = "upstream-access-token";

const ENV: Readonly<Record<string, string>> = {
	OAUTH_JWT_ALGORITHM: "HS256",
	OAUTH_JWT_SECRET: JWT_SECRET,
	OAUTH_JWT_ISSUER: ISSUER,
	SESSION_SECRET: "federation-grants-survive-logout-session.at-least-32-bytes.ok",
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
	FEDERATION_GRANT_STORE_ADAPTER: "memory",
	FEDERATION_GRANT_INTENT_STORE_ADAPTER: "memory",
	FEDERATION_GRANTS_ENABLED: "true",
	FEDERATION_GRANTS_CONSENT_URL: "/consent/grants",
	// The connect flow is not driven here, and the bundled repository has no
	// identity lookup; "unsupported" is the declaration a deployment without one
	// makes (#613), and what lets a connection be configured at all.
	FEDERATION_GRANTS_IDENTITY_LOOKUP: "unsupported",
};

/**
 * The shipped configuration under the environment above, with the two lists
 * that have no environment form (comment 9 on #593) written over it: the
 * upstream federation the connection names, and the connection.
 */
function resolveConfig(): AppConfig {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "production");
	const config = validate(
		parseFile(envConfPath, { env: ENV })
			.withFallback(parseFile(applicationConfPath, { env: ENV }))
			.withFallback(parseFile(resolveLibraryReferenceConfPath(), { env: ENV })),
		AppConfigSchema,
	);
	return {
		...config,
		federations: {
			...config.federations,
			upstream: {
				enabled: true,
				type: "oidc",
				issuer: UPSTREAM,
				clientId: UPSTREAM_CLIENT_ID,
				clientSecret: "provider-secret",
				callbackURL: `${ISSUER}/session/oauth/federation/upstream/callback`,
				scopes: [...SCOPES],
				discovery: false,
				endpoints: {
					authorizationEndpoint: `${UPSTREAM}/authorize`,
					tokenEndpoint: `${UPSTREAM}/token`,
					jwksUri: `${UPSTREAM}/jwks`,
				},
				redirectAllowlist: [],
			},
		},
		federationGrants: {
			...config.federationGrants,
			encryptionKeys: [{ id: "k-test", key: ENCRYPTION_KEY }],
			connections: {
				[CONNECTION]: {
					federation: "upstream",
					scopes: [...SCOPES],
					boundary: BOUNDARY,
					maxAccessTokenLifetime: 3600,
					callbackURL: `${ISSUER}/session/federation-grants/callback/${CONNECTION}`,
				},
			},
		},
	} as AppConfig;
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
							backchannelLogoutSessionRequired: true,
							frontchannelLogoutSessionRequired: true,
							allowedAzpForFederationToken: false,
							allowedFederationGrantConnections: [CONNECTION],
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

/** The grant as the connect flow would have left it, a fresh upstream token in hand. */
async function seedGrant(store: MemoryFederationGrantStore): Promise<void> {
	const at = new Date();
	// The revisions as `connections.mts` resolves them from the configuration
	// above: the federation's issuer and client, the connection's scopes and
	// boundary, no resource, no authorization parameters.
	const resolved = {
		upstreamIssuer: UPSTREAM,
		upstreamClientId: UPSTREAM_CLIENT_ID,
		scopes: SCOPES,
		boundary: BOUNDARY,
		authorizationParams: {},
	};
	await store.createPending({
		id: GRANT_ID,
		subject: SUB,
		clientId: CLIENT_ID,
		connection: CONNECTION,
		intent: { handle: "h", expiresAt: new Date(at.getTime() + 600_000) },
		now: at,
	});
	const written = await store.activate({
		grantId: GRANT_ID,
		intentHandle: "h",
		authorization: {
			identityRevision: federationGrantIdentityRevision(resolved),
			authorizationRevision: federationGrantAuthorizationRevision(resolved),
			upstream: { issuer: UPSTREAM, subject: "upstream-alice" },
			scopes: [...SCOPES],
			consent: { at, sid: "sid-consent", scopes: [...SCOPES] },
			authorizedAt: at,
			expiresAt: new Date(at.getTime() + 30 * DAY),
		},
		credentials: {
			refreshToken: REFRESH_TOKEN,
			accessToken: {
				value: ACCESS_TOKEN,
				tokenType: "Bearer",
				obtainedAt: at,
				issuedLifetime: 3600,
				scopes: [...SCOPES],
			},
		},
		now: at,
	});
	if (!written.ok) throw new Error("fixture: the grant was not activated");
}

const base64url = (value: unknown): string =>
	Buffer.from(JSON.stringify(value)).toString("base64url");

/**
 * An id_token for the session, signed with the deployment's own HS256 key, as
 * the RP would present it: `/oauth/logout` reads `sid` from the hint and from
 * nothing else.
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

describe("#593 AC8: a grant outlives the browser session at both logout endpoints (D14)", () => {
	let handleRef: Awaited<ReturnType<typeof createApp>> | undefined;

	afterEach(async () => {
		await handleRef?.dispose();
		handleRef = undefined;
	});

	async function boot() {
		const config = resolveConfig();
		const handle = await createApp({
			modules: buildModules(config, {
				keyStoreModule: testKeyStoreModule,
				repositoriesModule: testRepositoriesModule,
				refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
			}),
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		handleRef = handle;
		const components = handle.components as {
			federationGrantStore: MemoryFederationGrantStore;
			userSessionStore: UserSessionStore;
			federationTokenStore: FederationTokenStore;
		};
		await seedGrant(components.federationGrantStore);
		const app = express();
		app.use(handle.router);
		return { app, config, ...components };
	}

	/** The real browser half: a CSRF pair, a login, and the cookies plus the token the login reissued. */
	async function login(app: express.Express, config: AppConfig) {
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

		const cookies = loginRes.headers["set-cookie"] as unknown as string[];
		const csrfCookiePrefix = `${config.session.name}.csrf=`;
		const reissued = cookies
			.find((c) => c.startsWith(csrfCookiePrefix))
			?.slice(csrfCookiePrefix.length)
			.split(";")[0];
		expect(reissued).toBeDefined();
		return { cookies, csrfToken: decodeURIComponent(reissued as string), headerName };
	}

	/** The session's `sid`, read off the access token the session grant mints for it. */
	async function sidOf(app: express.Express, cookies: string[]): Promise<string> {
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", BASIC)
			.set("Cookie", cookies)
			.type("form")
			.send({ grant_type: "session" });
		expect(res.status).toBe(200);
		const sid = claimsOf(res.body.access_token as string).sid;
		expect(typeof sid).toBe("string");
		return sid as string;
	}

	const disclose = (app: express.Express) =>
		request(app)
			.post(`/oauth/federation-grants/${GRANT_ID}/token`)
			.set("Authorization", BASIC)
			.send({ sub: SUB });

	/**
	 * What a logout has to leave: the record, its credential — the values, not
	 * only a readable state, since a rotated or dropped refresh token beside an
	 * untouched access token would still read `"ok"` — and a disclosure that
	 * still answers.
	 */
	async function expectGrantUntouched(app: express.Express, store: MemoryFederationGrantStore) {
		expect((await store.find(GRANT_ID, new Date()))?.status).toBe("active");
		const opened = await store.open(GRANT_ID, new Date());
		if (opened?.credentials.state !== "ok")
			throw new Error("the grant's credential is not readable");
		expect(opened.credentials.value).toMatchObject({
			refreshToken: REFRESH_TOKEN,
			accessToken: { value: ACCESS_TOKEN },
		});
		const response = await disclose(app);
		expect(response.status).toBe(200);
		expect(response.body.access_token).toBe(ACCESS_TOKEN);
	}

	it("POST /session/logout ends the session's own records and leaves the grant spendable", async () => {
		const { app, config, federationGrantStore, userSessionStore, federationTokenStore } =
			await boot();
		const { cookies, csrfToken, headerName } = await login(app, config);
		const sid = await sidOf(app, cookies);
		// A session-bound upstream token beside the grant: the record #276's
		// guarantee is about, keyed by this session.
		await federationTokenStore.attach(sid, "upstream", {
			accessToken: "session-bound-upstream-token",
			expiresAt: null,
			// Every field is a required key since the #645 follow-up; this
			// record carries only the access token.
			refreshToken: undefined,
			idToken: undefined,
			tokenType: undefined,
			scope: undefined,
			grantedScope: undefined,
		});
		expect(await userSessionStore.get(sid)).not.toBeNull();
		await expectGrantUntouched(app, federationGrantStore);

		const logout = await request(app)
			.post("/session/logout")
			.set("Cookie", cookies)
			.set(headerName, csrfToken);
		expect([200, 204]).toContain(logout.status);

		// The session-bound records are gone (#276 holds) ...
		expect(await userSessionStore.get(sid)).toBeNull();
		expect(await federationTokenStore.get(sid, "upstream")).toBeNull();
		// ... and the grant is not among them.
		await expectGrantUntouched(app, federationGrantStore);
	});

	it("POST /oauth/logout runs the cascade and leaves the grant spendable", async () => {
		const { app, config, federationGrantStore, userSessionStore, federationTokenStore } =
			await boot();
		const { cookies } = await login(app, config);
		const sid = await sidOf(app, cookies);
		await federationTokenStore.attach(sid, "upstream", {
			accessToken: "session-bound-upstream-token",
			expiresAt: null,
			// Every field is a required key since the #645 follow-up; this
			// record carries only the access token.
			refreshToken: undefined,
			idToken: undefined,
			tokenType: undefined,
			scope: undefined,
			grantedScope: undefined,
		});
		expect(await userSessionStore.get(sid)).not.toBeNull();
		await expectGrantUntouched(app, federationGrantStore);

		const logout = await request(app)
			.post("/oauth/logout")
			.type("form")
			.send({ id_token_hint: idTokenHint(sid) });
		expect(logout.status).toBe(200);

		expect(await userSessionStore.get(sid)).toBeNull();
		expect(await federationTokenStore.get(sid, "upstream")).toBeNull();
		await expectGrantUntouched(app, federationGrantStore);
	});
});
