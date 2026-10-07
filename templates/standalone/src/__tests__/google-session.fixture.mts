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
 * A browser session with Google linked, on the standalone composed as a
 * deployment does: `oauthEndpointsModule`, the session module and the real Google
 * adapter — the Google federation type `buildModules` lists, handed the
 * shipped `core.federations.google` entry — booted through `createApp` under
 * the shipped configuration.
 *
 * The two logout routes and `POST /oauth/federation/:name/token` live in
 * `@o3co/auth-provider-oauth`, which depends on no adapter; only here can a
 * test see what they hand the real adapter and what they make of what its
 * library raises.
 *
 * Unlike `all-modules-composition.fixture.mts`, the deployment signs with an
 * HS256 secret this file holds, so tests can present an `id_token_hint` and
 * access token of their own; nothing but Google is federated.
 */

import { createHmac } from "node:crypto";
import { fileURLToPath } from "node:url";
import {
	createApp,
	createKeyStoreFactory,
	defineModule,
	type FederationTokenStore,
	type FederationTokens,
	InMemoryClientRepository,
	InMemoryUserRepository,
	memoryRefreshTokenFamilyStoreModule,
	registerBuiltinKeyStores,
	type SessionLifecycle,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { googleFederationTypeModule } from "@o3co/auth-provider-federation-google";
import { parseFile } from "@o3co/ts.hocon";
import express from "express";
import request from "supertest";
import { expect } from "vitest";
import { buildModules } from "#/buildModules.mjs";
import { resolveConfigPaths } from "#/configPath.mjs";
import { templateReference } from "../modules.mjs";
import { keyStoreSectionSchema } from "../sections.mjs";
import {
	type BothPhases,
	bothPhasesOf,
	capturedRenames,
	libraryLayers,
} from "./library-references.fixture.mjs";

const configDir = fileURLToPath(new URL("../../config", import.meta.url));

export const ISSUER = "https://auth.test";
const JWT_SECRET = "google-session.fixture.at-least-32-bytes.ok";

/** The one client: first-party, allowed federation tokens, one post-logout URI registered. */
export const CLIENT_ID = "rp";
const CLIENT_SECRET = "rp-secret-value";
const BASIC = `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64")}`;
export const REGISTERED_POST_LOGOUT_REDIRECT_URI = "https://rp.example/signed-out";

const USERNAME = "alice";
const PASSWORD = "correct-horse-battery-staple";
const SUB = "u-alice";

/** The Google client the adapter is configured with. */
export const GOOGLE_CLIENT_ID = "google-client";
const GOOGLE_CLIENT_SECRET = "google-secret";
const GOOGLE_CALLBACK = `${ISSUER}/session/oauth/federation/google/callback`;

const ENV: Readonly<Record<string, string>> = {
	// A session signed in through Google alone, no second factor.
	MFA_MODE: "off",
	KEY_STORE_LOCAL_ALGORITHM: "HS256",
	KEY_STORE_LOCAL_SECRET: JWT_SECRET,
	OAUTH_JWT_ISSUER: ISSUER,
	SESSION_STORE_SECRET: "google-session.fixture-session.at-least-32-bytes.ok",
	SESSION_STORE_SECURE: "false",
	SESSION_STORE_NAME: "auth.session",
	SESSION_STORE_STORAGE_TYPE: "memory",
	ADAPTERS_USER_REPOSITORY: "yaml",
	REDIS_CLIENTS_URL: "redis://redis.test:6379",
	ADAPTERS_USER_SESSION_STORES: "memory",
	ADAPTERS_RATE_LIMITER: "memory",
	ADAPTERS_CODE_REPOSITORY: "memory",
	ADAPTERS_ACCESS_TOKEN_DENYLIST: "memory",
	ADAPTERS_REPLAY_SEEN_SET: "memory",
	ADAPTERS_FEDERATION_TOKEN_STORE: "memory",
	ADAPTERS_CONSENT_STORE: "none",
};

/**
 * Google switched on the way an operator does, through its environment
 * variables, and handled by the Google federation type the template lists.
 * `"shipped"` is that alone. Otherwise, beside it: `endSessionEndpoint`, a key
 * of the entry with no environment form, written into the entry as an
 * operator's own layer would; and `fetch`, the one the type module is built
 * with in place of the global one.
 */
export type GoogleWiring =
	| "shipped"
	| { readonly endSessionEndpoint?: string; readonly fetch?: typeof fetch };

const GOOGLE_ENV: Readonly<Record<string, string>> = {
	CORE_FEDERATIONS_GOOGLE_ENABLED: "true",
	CORE_FEDERATIONS_GOOGLE_CLIENT_ID: GOOGLE_CLIENT_ID,
	CORE_FEDERATIONS_GOOGLE_CLIENT_SECRET: GOOGLE_CLIENT_SECRET,
	CORE_FEDERATIONS_GOOGLE_CALLBACK_URL: GOOGLE_CALLBACK,
};

function resolveConfig(google: GoogleWiring): BothPhases {
	const env: Record<string, string> = { ...ENV, ...GOOGLE_ENV };
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "production");
	const layers = parseFile(envConfPath, { env })
		.withFallback(parseFile(applicationConfPath, { env }))
		.withFallback(parseFile(fileURLToPath(templateReference()), { env }))
		.withFallback(libraryLayers(env));
	const config = bothPhasesOf(layers, env);
	const endSessionEndpoint = google === "shipped" ? undefined : google.endSessionEndpoint;
	const federations = config.core?.federations;
	return {
		...config,
		...(endSessionEndpoint === undefined
			? {}
			: {
					core: {
						...config.core,
						federations: {
							...federations,
							google: { ...federations?.google, endSessionEndpoint },
						},
					},
				}),
		// What the resolution captured of the renamed variables.
		"renamed-variables": capturedRenames(env),
	} as BothPhases;
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
							postLogoutRedirectUris: [REGISTERED_POST_LOGOUT_REDIRECT_URI],
							backchannelLogoutSessionRequired: true,
							frontchannelLogoutSessionRequired: true,
							allowedAzpForFederationToken: true,
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

// The template's `key-store` section, read by its own schema, without the
// section's relocation bridge.
const testKeyStoreModule = defineModule({
	name: "key-store",
	section: { schema: keyStoreSectionSchema },
	provides: {
		keyStore: async ({ section }) => {
			const factory = createKeyStoreFactory();
			registerBuiltinKeyStores(factory);
			return factory.create({
				type: "local",
				...(section.local ?? {}),
			});
		},
	},
});

const base64url = (value: unknown): string =>
	Buffer.from(JSON.stringify(value)).toString("base64url");

/** A JWT signed with the deployment's own HS256 key: what its keystore verifies. */
function signed(typ: string, claims: Record<string, unknown>): string {
	const header = base64url({ alg: "HS256", kid: "v0", typ });
	const now = Math.floor(Date.now() / 1000);
	const payload = base64url({ iss: ISSUER, sub: SUB, iat: now, exp: now + 3600, ...claims });
	const signature = createHmac("sha256", JWT_SECRET)
		.update(`${header}.${payload}`)
		.digest("base64url");
	return `${header}.${payload}.${signature}`;
}

/**
 * A fresh id_token for the session, issued to the client: what an RP — or
 * anyone holding an id_token of their own — presents as `id_token_hint`.
 */
export const idTokenHint = (sid: string): string => signed("JWT", { aud: CLIENT_ID, sid });

/**
 * An access token for the session as the authorization-code grant issues it
 * to the client: `azp`, `sid` and a refresh-token `family_id`. The `session`
 * grant's token names no family, and the federation token route asks for one.
 */
export const accessTokenWithFamily = (sid: string): string =>
	signed("at+jwt", { azp: CLIENT_ID, sid, family_id: "family-1", scope: "openid" });

const claimsOf = (jwt: string): Record<string, unknown> =>
	JSON.parse(Buffer.from(jwt.split(".")[1] ?? "", "base64url").toString("utf8")) as Record<
		string,
		unknown
	>;

export interface GoogleSession {
	readonly app: express.Express;
	readonly sid: string;
	/** The access token the `session` grant minted for the session; it carries `azp`. */
	readonly accessToken: string;
	readonly userSessionStore: UserSessionStore;
	readonly sessionLifecycle: SessionLifecycle;
	readonly federationTokenStore: FederationTokenStore;
	readonly dispose: () => Promise<void>;
}

/**
 * Boots the deployment, signs alice in with her password, and links Google to
 * her session as a federated sign-in would: the token store holds `tokens`,
 * and Google joins the session through its lifecycle.
 */
export async function signInLinkedToGoogle(options: {
	readonly google: GoogleWiring;
	readonly tokens: FederationTokens;
}): Promise<GoogleSession> {
	const { google, tokens } = options;
	const config = resolveConfig(google);
	const upstreamFetch = google === "shipped" ? undefined : google.fetch;
	const googleType = googleFederationTypeModule().name;
	const handle = await createApp({
		modules: buildModules(config, {
			keyStoreModule: testKeyStoreModule,
			repositoriesModule: testRepositoriesModule,
			refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
		}).map((module) =>
			module.name === googleType && upstreamFetch !== undefined
				? googleFederationTypeModule({ fetch: upstreamFetch })
				: module,
		),
		bootstrapComponents: { config, pathResolver: (s) => s },
	});
	try {
		const components = handle.components as {
			userSessionStore: UserSessionStore;
			sessionLifecycle: SessionLifecycle;
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

		const tokenRes = await request(app)
			.post("/oauth/token")
			.set("Authorization", BASIC)
			.set("Cookie", loginRes.headers["set-cookie"] as unknown as string[])
			.type("form")
			.send({ grant_type: "session" });
		expect(tokenRes.status).toBe(200);
		const accessToken = tokenRes.body.access_token as string;
		const claims = claimsOf(accessToken);
		expect(claims.azp).toBe(CLIENT_ID);
		const sid = claims.sid as string;
		expect(typeof sid).toBe("string");

		await components.federationTokenStore.attach(sid, "google", tokens);
		expect(await components.sessionLifecycle.join(sid, { federation: "google" })).toEqual({
			outcome: "joined",
		});
		return { app, sid, accessToken, ...components, dispose: () => handle.dispose() };
	} catch (error) {
		await handle.dispose();
		throw error;
	}
}
