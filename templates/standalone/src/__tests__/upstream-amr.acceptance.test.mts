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
 * What an upstream IdP asserted about its own login counts only for a
 * federation configured with `federations.<name>.trustUpstreamAmr = true`
 * (ADR 2026-09-25-multi-factor-authentication), end to end: a federated login
 * through the session routes, `/oauth/authorize` with `acr_values`, and
 * `/oauth/token`, on the standalone as a deployment composes it
 * (`buildModules`), with a federation whose IdP asserts `mfa` and `hwk`.
 * By default they are kept in `authentication.upstreamAmr` and an `acr` entry
 * only they could meet is withheld; trusted, they are recorded beside `fed`.
 * The session routes and `oauth` read the switch separately (neither package
 * depends on the other); this is where the two meet.
 */

import { createHash, randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import {
	type AppConfig,
	AppConfigSchema,
	coreReference,
	createApp,
	createKeyStoreFactory,
	defineModule,
	type FederationProvider,
	InMemoryClientRepository,
	InMemoryUserRepository,
	memoryRefreshTokenFamilyStoreModule,
	registerBuiltinKeyStores,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { buildModules } from "#/buildModules.mjs";
import { resolveConfigPaths } from "#/configPath.mjs";
import { templateReference } from "../modules.mjs";

const configDir = fileURLToPath(new URL("../../config", import.meta.url));

const ISSUER = "https://auth.test";
const CLIENT_ID = "rp";
const CLIENT_SECRET = "rp-secret-value";
const BASIC = `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64")}`;
const REDIRECT_URI = "https://rp.example/callback";
const FEDERATION = "partner";
const CALLBACK_URL = `${ISSUER}/session/oauth/federation/${FEDERATION}/callback`;
/** What the partner IdP asserts about its own login. */
const UPSTREAM_AMR = ["mfa", "hwk"];
const MFA_ACR = "urn:example:mfa";
const FED_ACR = "urn:example:fed";

const ENV: Readonly<Record<string, string>> = {
	OAUTH_JWT_ALGORITHM: "HS256",
	OAUTH_JWT_SECRET: "upstream-amr.acceptance.at-least-32-bytes",
	OAUTH_JWT_ISSUER: ISSUER,
	SESSION_SECRET: "upstream-amr.acceptance-session.at-least-32-bytes",
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

/** The shipped configuration, with the partner federation and an acr table beside it. */
function resolveConfig(trustUpstreamAmr: boolean | undefined): AppConfig {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "production");
	const shipped = validate(
		parseFile(envConfPath, { env: ENV })
			.withFallback(parseFile(applicationConfPath, { env: ENV }))
			.withFallback(parseFile(fileURLToPath(templateReference()), { env: ENV }))
			.withFallback(parseFile(fileURLToPath(coreReference()), { env: ENV })),
		AppConfigSchema,
	) as AppConfig;
	return AppConfigSchema.parse({
		...shipped,
		federations: {
			...shipped.federations,
			[FEDERATION]: {
				enabled: true,
				type: FEDERATION,
				callbackURL: CALLBACK_URL,
				...(trustUpstreamAmr === undefined ? {} : { trustUpstreamAmr }),
			},
		},
		oauth: {
			...shipped.oauth,
			authorize: {
				...shipped.oauth.authorize,
				acrValues: { [MFA_ACR]: ["mfa"], [FED_ACR]: ["fed"] },
			},
		},
	}) as AppConfig;
}

/** An IdP that authenticates `ext-1` and says it did so with `mfa` and `hwk`. */
const partner: FederationProvider = {
	name: FEDERATION,
	scope: ["openid"],
	buildAuthorizationUrl: ({ state }) => {
		const url = new URL("https://idp.partner.example/authorize");
		url.searchParams.set("state", state);
		return url;
	},
	exchangeCode: async () => ({
		issuer: "https://idp.partner.example",
		sub: "ext-1",
		accessToken: "upstream-at",
		expiresAt: null,
		amr: UPSTREAM_AMR,
	}),
};

const partnerFederationModule = defineModule({
	name: "test:partner-federation",
	contributes: {
		federations: { [FEDERATION]: () => partner },
		federationRedirectPolicies: {
			[FEDERATION]: () => ({
				validateRedirect: () => ({ ok: true as const, value: undefined }),
				resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
			}),
		},
	} as never,
});

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
							allowedRedirectUris: [REDIRECT_URI],
							allowedScopes: ["openid"],
							allowedAudiences: [],
							allowedGrantTypes: ["authorization_code"],
							firstParty: true,
							backchannelLogoutSessionRequired: false,
							frontchannelLogoutSessionRequired: false,
							allowedAzpForFederationToken: false,
						},
					],
				]),
			),
		// The partner's `ext-1` is alice's linked identity.
		userRepository: () =>
			new InMemoryUserRepository(
				new Map([["alice", { id: "u-alice", password: "unused", token: `${FEDERATION}:ext-1` }]]),
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
				...((c as AppConfig).oauth.jwt.signingKey?.local ?? {}),
			});
		},
	},
});

/** A JWT's claims, unverified: the deployment signed it, and the test reads what it said. */
const decodeJwt = (jwt: string): Record<string, unknown> =>
	JSON.parse(Buffer.from(jwt.split(".")[1] ?? "", "base64url").toString("utf8")) as Record<
		string,
		unknown
	>;

const cookiesOf = (res: request.Response): string[] =>
	(res.headers["set-cookie"] as unknown as string[] | undefined) ?? [];

interface Deployment {
	readonly app: express.Express;
	readonly userSessionStore: UserSessionStore;
	readonly dispose: () => Promise<void>;
}

async function boot(trustUpstreamAmr: boolean | undefined): Promise<Deployment> {
	const config = resolveConfig(trustUpstreamAmr);
	const handle = await createApp({
		modules: [
			...buildModules(config, {
				keyStoreModule: testKeyStoreModule,
				repositoriesModule: testRepositoriesModule,
				refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
			}),
			partnerFederationModule,
		],
		bootstrapComponents: { config, pathResolver: (s) => s },
	});
	const app = express();
	app.use(handle.router);
	return {
		app,
		userSessionStore: (handle.components as { userSessionStore: UserSessionStore })
			.userSessionStore,
		dispose: () => handle.dispose(),
	};
}

/** Signs alice in through the partner federation; the browser's cookies after the callback. */
async function signInThroughPartner(app: express.Express): Promise<string[]> {
	const start = await request(app).get(`/session/oauth/federation/${FEDERATION}`);
	expect(start.status).toBe(302);
	const state = new URL(start.headers.location as string).searchParams.get("state");
	expect(state).toBeTruthy();
	const callback = await request(app)
		.get(`/session/oauth/federation/${FEDERATION}/callback`)
		.query({ state, code: "upstream-code" })
		.set("Cookie", cookiesOf(start));
	expect(callback.status).toBe(302);
	return cookiesOf(callback);
}

/** `/oauth/authorize` for the signed-in browser: the redirect back to the client, as parameters. */
async function authorize(
	app: express.Express,
	cookies: readonly string[],
	acrValues: string,
): Promise<{ readonly params: URLSearchParams; readonly verifier: string }> {
	const verifier = randomBytes(32).toString("base64url");
	const res = await request(app)
		.get("/oauth/authorize")
		.query({
			response_type: "code",
			client_id: CLIENT_ID,
			redirect_uri: REDIRECT_URI,
			scope: "openid",
			state: "rp-state",
			code_challenge: createHash("sha256").update(verifier).digest("base64url"),
			code_challenge_method: "S256",
			acr_values: acrValues,
		})
		.set("Cookie", [...cookies]);
	expect(res.status).toBe(302);
	const location = new URL(res.headers.location as string);
	expect(`${location.origin}${location.pathname}`).toBe(REDIRECT_URI);
	return { params: location.searchParams, verifier };
}

/** The tokens `/oauth/token` mints for `code`, decoded. */
async function tokensFor(
	app: express.Express,
	code: string,
	verifier: string,
): Promise<{
	readonly idToken: Record<string, unknown>;
	readonly accessToken: Record<string, unknown>;
}> {
	const res = await request(app)
		.post("/oauth/token")
		.set("Authorization", BASIC)
		.type("form")
		.send({
			grant_type: "authorization_code",
			code,
			redirect_uri: REDIRECT_URI,
			code_verifier: verifier,
		});
	expect(res.status).toBe(200);
	return {
		idToken: decodeJwt(res.body.id_token as string),
		accessToken: decodeJwt(res.body.access_token as string),
	};
}

describe("an upstream IdP's amr counts only for a federation that trusts it", () => {
	let deployment: Deployment | undefined;

	afterEach(async () => {
		await deployment?.dispose();
		deployment = undefined;
	});

	it("by default: kept apart in the session, withheld from discovery, unmet at /authorize, on no token", async () => {
		deployment = await boot(undefined);
		const { app, userSessionStore } = deployment;

		const discovery = await request(app).get("/.well-known/openid-configuration");
		// The entry only the IdP's `mfa` could meet is dropped, since that `mfa`
		// is not recorded: no deployment advertises what it cannot meet.
		expect(discovery.body.acr_values_supported).toEqual([FED_ACR]);

		const cookies = await signInThroughPartner(app);

		const unmet = await authorize(app, cookies, MFA_ACR);
		expect(unmet.params.get("error")).toBe("unmet_authentication_requirements");
		expect(unmet.params.get("code")).toBeNull();

		const { params, verifier } = await authorize(app, cookies, FED_ACR);
		const code = params.get("code");
		expect(code).toBeTruthy();
		const { idToken, accessToken } = await tokensFor(app, code as string, verifier);
		expect(idToken.acr).toBe(FED_ACR);
		expect(idToken.amr).toEqual(["fed"]);
		expect(accessToken.amr).toEqual(["fed"]);

		// The session keeps what the IdP said, for the record.
		const session = await userSessionStore.get(idToken.sid as string);
		expect(session?.amr).toEqual(["fed"]);
		expect(session?.authentication).toStrictEqual({
			primary: "fed",
			federation: FEDERATION,
			upstreamAmr: UPSTREAM_AMR,
			mfaAt: undefined,
		});
	});

	it("trusted: recorded beside fed, advertised, met at /authorize and stamped", async () => {
		deployment = await boot(true);
		const { app, userSessionStore } = deployment;

		const discovery = await request(app).get("/.well-known/openid-configuration");
		expect(discovery.body.acr_values_supported).toEqual([MFA_ACR, FED_ACR]);

		const cookies = await signInThroughPartner(app);
		const { params, verifier } = await authorize(app, cookies, MFA_ACR);
		const code = params.get("code");
		expect(code).toBeTruthy();
		const { idToken, accessToken } = await tokensFor(app, code as string, verifier);
		expect(idToken.acr).toBe(MFA_ACR);
		expect(idToken.amr).toEqual([...UPSTREAM_AMR, "fed"]);
		expect(accessToken.amr).toEqual([...UPSTREAM_AMR, "fed"]);

		const session = await userSessionStore.get(idToken.sid as string);
		expect(session?.authentication).toStrictEqual({
			primary: "fed",
			federation: FEDERATION,
			upstreamAmr: undefined,
			mfaAt: undefined,
		});
	});

	it("says false explicitly as it says nothing: kept apart", async () => {
		deployment = await boot(false);
		const discovery = await request(deployment.app).get("/.well-known/openid-configuration");
		expect(discovery.body.acr_values_supported).toEqual([FED_ACR]);
	});
});
