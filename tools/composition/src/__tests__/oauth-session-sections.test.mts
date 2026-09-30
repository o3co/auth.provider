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
 * The oauth and session packages' sections and core's token-binding settings,
 * through the template's own reading of the full set: the operator's layer
 * and environment read once, phase one's switches, then the layers over every
 * loaded package's `reference.conf` handed to boot. The grant switches sit in
 * the sections of the modules that install the grants, `oauth-session` and
 * `oauth-authorization`, and phase one reads them there; the consent page and
 * the Client ID Metadata Documents in the oauth module's `oauth {}`; the
 * token-binding settings in core's `core {}`; the session cookie and its store
 * in the session store's `session-store {}`, whose storage phase one reads;
 * the login page and the login's budget in the session module's `session {}`.
 * A path they moved from refuses boot naming the new one, a key a section does
 * not declare is refused, and a variable renamed with them refuses boot unless
 * its new name carries the same value.
 */

import { BootError, resolveTokenBindingSettings } from "@o3co/auth-provider-core";
import {
	DISCOVERY_PATHS,
	MULTI_ENV,
	SINGLE_ENV,
} from "@o3co/auth-provider-standalone/src/__tests__/all-modules-composition.fixture.mts";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { composeFullSet, type FullSet, type FullSetOptions } from "./full-set.fixture.mts";

let current: FullSet | undefined;

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
});

/** Boots the full set, the operator's layer and environment as given, and remembers it. */
async function boot(options: FullSetOptions = {}): Promise<FullSet> {
	current = await composeFullSet(options);
	return current;
}

/** What boot refused the full set with. */
async function refused(options: FullSetOptions): Promise<BootError> {
	try {
		current = await composeFullSet(options);
	} catch (err) {
		if (err instanceof BootError) return err;
		throw err;
	}
	throw new Error("the full set booted");
}

/** The value at a dotted path of the configuration boot parsed. */
function parsedAt(composition: FullSet, path: string): unknown {
	let cursor: unknown = composition.config;
	for (const key of path.split(".")) {
		if (typeof cursor !== "object" || cursor === null) return undefined;
		cursor = (cursor as Record<string, unknown>)[key];
	}
	return cursor;
}

/** The environment of the shipped full set without the variables named. */
function without(...names: readonly string[]): Record<string, string> {
	return Object.fromEntries(Object.entries(SINGLE_ENV).filter(([name]) => !names.includes(name)));
}

/** The grant types the discovery document advertises. */
async function advertisedGrants(composition: FullSet): Promise<string[]> {
	const doc = (await request(composition.app).get(DISCOVERY_PATHS[0])).body;
	return [...(doc.grant_types_supported as string[])].sort();
}

describe("the grant switches, read by phase one at their modules' sections", () => {
	it("OAUTH_SESSION_ENABLED=false: phase one leaves the session grant out", async () => {
		const composition = await boot({ env: { ...SINGLE_ENV, OAUTH_SESSION_ENABLED: "false" } });

		expect(await advertisedGrants(composition)).not.toContain("session");
		expect(parsedAt(composition, "oauth-session.enabled")).toBe(false);
	});

	it("oauth-authorization.grants.clientCredentials.enabled = false in the operator's layer: phase one leaves the grant out", async () => {
		const composition = await boot({
			env: without("OAUTH_AUTHORIZATION_GRANTS_CLIENT_CREDENTIALS_ENABLED"),
			operatorHocon: "oauth-authorization.grants.clientCredentials.enabled = false\n",
		});

		const grants = await advertisedGrants(composition);
		expect(grants).not.toContain("client_credentials");
		expect(grants).toContain("authorization_code");
		expect(parsedAt(composition, "oauth-authorization.grants.clientCredentials.enabled")).toBe(
			false,
		);
	});

	it("OAUTH_AUTHORIZATION_GRANTS_CLIENT_CREDENTIALS_ENABLED=true: phase one installs the grant", async () => {
		const composition = await boot();

		expect(await advertisedGrants(composition)).toContain("client_credentials");
	});
});

describe("the oauth module's section and core's token-binding settings, read where they now sit", () => {
	it("oauth.consentPage.url, which OAUTH_CONSENT_PAGE_URL sets", async () => {
		const composition = await boot({
			env: { ...SINGLE_ENV, OAUTH_CONSENT_PAGE_URL: "/consent/page?tenant=acme" },
		});

		expect(parsedAt(composition, "oauth.consentPage.url")).toBe("/consent/page?tenant=acme");
	});

	it("oauth.clientIdMetadataDocuments, which OAUTH_CLIENT_ID_METADATA_DOCUMENTS_* set", async () => {
		const composition = await boot({
			env: {
				...SINGLE_ENV,
				OAUTH_CLIENT_ID_METADATA_DOCUMENTS_ALLOWED_HOSTS: "a.example, .b.example",
				OAUTH_CLIENT_ID_METADATA_DOCUMENTS_MAX_BYTES: "4096",
			},
		});

		expect(parsedAt(composition, "oauth.clientIdMetadataDocuments")).toMatchObject({
			enabled: true,
			allowedHosts: ["a.example", ".b.example"],
			maxBytes: 4096,
		});
		const doc = (await request(composition.app).get(DISCOVERY_PATHS[0])).body;
		expect(doc.client_id_metadata_document_supported).toBe(true);
	});

	it("core.tokenBinding, which CORE_TOKEN_BINDING_* set", async () => {
		const composition = await boot({
			env: {
				...SINGLE_ENV,
				CORE_TOKEN_BINDING_DISPATCH_POLICY: "strict-mutual-exclusion",
				CORE_TOKEN_BINDING_BIND_CONFIDENTIAL_CLIENT_REFRESH_TOKENS: "true",
			},
		});

		expect(resolveTokenBindingSettings(composition.config)).toEqual({
			dispatchPolicy: "strict-mutual-exclusion",
			bindConfidentialClientRefreshTokens: true,
		});
	});
});

describe("the session modules' sections, read where they now sit", () => {
	it("session-store: the session cookie the SESSION_STORE_* variables describe, which the sessionCookiePolicy slot carries", async () => {
		const composition = await boot({
			env: {
				...SINGLE_ENV,
				SESSION_STORE_NAME: "auth.moved",
				SESSION_STORE_MAX_AGE: "7200000",
				SESSION_STORE_SAME_SITE: "strict",
			},
		});

		expect(parsedAt(composition, "session-store")).toMatchObject({
			name: "auth.moved",
			maxAge: 7_200_000,
			secure: false,
			sameSite: "strict",
		});
		expect(composition.handle.components.sessionCookiePolicy).toMatchObject({
			name: "auth.moved",
			secure: false,
			sameSite: "strict",
			maxAgeMs: 7_200_000,
		});
	});

	it("session.loginPage.url, which SESSION_LOGIN_PAGE_URL sets, is the page the loginEntry slot sends a browser to", async () => {
		const composition = await boot({
			env: { ...SINGLE_ENV, SESSION_LOGIN_PAGE_URL: "/sign-in?tenant=acme" },
		});

		expect(parsedAt(composition, "session.loginPage.url")).toBe("/sign-in?tenant=acme");
		expect(composition.handle.components.loginEntry?.urlFor("/back")).toBe(
			"/sign-in?tenant=acme&redirect_to=%2Fback",
		);
	});

	it.each([
		["SESSION_STORE_STORAGE_TYPE=memory", { SESSION_STORE_STORAGE_TYPE: "memory" }, ""],
		[
			'session-store.storage.type = "memory" in the operator\'s layer',
			{},
			'session-store.storage.type = "memory"\n',
		],
	])(
		'%s under core.deployment.mode = "multi": phase one builds the store for memory, and the guard refuses it by name',
		async (_what, env, operatorHocon) => {
			/** The modules the guard refuses: the full set leaves its own stores in memory. */
			const unsafe = async (options: FullSetOptions): Promise<unknown> => {
				const err = await refused(options);
				expect(err.reason).toBe("replica-unsafe-adapter");
				return (err.details as { modules: unknown }).modules;
			};

			expect(await unsafe({ env: { ...MULTI_ENV, ...env }, operatorHocon })).toContain(
				"session-store",
			);
			expect(await unsafe({ env: MULTI_ENV })).not.toContain("session-store");
		},
	);
});

describe("a path the settings moved from, written in the operator's own layer", () => {
	/** Every key written at an old path, refused as moved. */
	async function relocatedBy(operatorHocon: string): Promise<unknown> {
		const err = await refused({ operatorHocon });
		expect(err.reason).toBe("config-path-relocated");
		return (err.details as { relocated: unknown }).relocated;
	}

	it("oauth.grants: each grant's switch refused, naming its path under its module's section and its variable", async () => {
		const relocated = await relocatedBy(
			[
				"oauth.grants {",
				"  session.enabled = true",
				"  authorization_code.enabled = true",
				"  refresh_token.enabled = true",
				"  client_credentials.enabled = true",
				'  "urn:ietf:params:oauth:grant-type:jwt-bearer".enabled = false',
				"}",
				"",
			].join("\n"),
		);

		expect(relocated).toHaveLength(5);
		expect(relocated).toEqual(
			expect.arrayContaining([
				{
					module: "oauth-session",
					from: "oauth.grants.session.enabled",
					to: "oauth-session.enabled",
					environmentVariable: "OAUTH_SESSION_ENABLED",
				},
				{
					module: "oauth-authorization",
					from: "oauth.grants.authorization_code.enabled",
					to: "oauth-authorization.grants.authorizationCode.enabled",
					environmentVariable: "OAUTH_AUTHORIZATION_GRANTS_AUTHORIZATION_CODE_ENABLED",
				},
				{
					module: "oauth-authorization",
					from: "oauth.grants.refresh_token.enabled",
					to: "oauth-authorization.grants.refreshToken.enabled",
					environmentVariable: "OAUTH_AUTHORIZATION_GRANTS_REFRESH_TOKEN_ENABLED",
				},
				{
					module: "oauth-authorization",
					from: "oauth.grants.client_credentials.enabled",
					to: "oauth-authorization.grants.clientCredentials.enabled",
					environmentVariable: "OAUTH_AUTHORIZATION_GRANTS_CLIENT_CREDENTIALS_ENABLED",
				},
				{
					module: "oauth-authorization",
					from: "oauth.grants.urn:ietf:params:oauth:grant-type:jwt-bearer.enabled",
					to: "oauth-authorization.grants.jwtBearer.enabled",
					environmentVariable: "OAUTH_AUTHORIZATION_GRANTS_JWT_BEARER_ENABLED",
				},
			]),
		);
	});

	it("oauth.grants.authorization_code.pkce: refused as removed", async () => {
		expect(
			await relocatedBy("oauth.grants.authorization_code.pkce.requireS256 = true\n"),
		).toEqual([
			{
				module: "oauth-authorization",
				from: "oauth.grants.authorization_code.pkce.requireS256",
				to: null,
			},
		]);
	});

	it("endpoints.consent.url: refused, naming oauth.consentPage.url and its variable", async () => {
		expect(await relocatedBy('endpoints.consent.url = "/consent"\n')).toEqual([
			{
				module: "oauth",
				from: "endpoints.consent.url",
				to: "oauth.consentPage.url",
				environmentVariable: "OAUTH_CONSENT_PAGE_URL",
			},
		]);
	});

	it("session: each key of the session cookie and its store refused, naming its path under session-store and its variable", async () => {
		const relocated = await relocatedBy(
			[
				"session {",
				'  secret = "moved-session-secret.at-least-32-bytes.ok"',
				'  name = "auth.moved"',
				"  maxAge = 7200000",
				"  secure = false",
				'  sameSite = "strict"',
				'  domain = "auth.example.com"',
				'  storage { type = "memory", redis { url = "redis://x:6379", password = "p" } }',
				"}",
				"",
			].join("\n"),
		);

		expect(relocated).toHaveLength(9);
		expect(relocated).toEqual(
			expect.arrayContaining(
				(
					[
						["secret", "SECRET"],
						["name", "NAME"],
						["maxAge", "MAX_AGE"],
						["secure", "SECURE"],
						["sameSite", "SAME_SITE"],
						["domain", "DOMAIN"],
						["storage.type", "STORAGE_TYPE"],
						["storage.redis.url", "STORAGE_REDIS_URL"],
						["storage.redis.password", "STORAGE_REDIS_PASSWORD"],
					] as const
				).map(([key, variable]) => ({
					module: "session-store",
					from: `session.${key}`,
					to: `session-store.${key}`,
					environmentVariable: `SESSION_STORE_${variable}`,
				})),
			),
		);
	});

	it("endpoints.login.url: refused, naming session.loginPage.url and its variable", async () => {
		expect(await relocatedBy('endpoints.login.url = "/sign-in"\n')).toEqual([
			{
				module: "session",
				from: "endpoints.login.url",
				to: "session.loginPage.url",
				environmentVariable: "SESSION_LOGIN_PAGE_URL",
			},
		]);
	});

	it("rateLimit.login: refused, naming session.rateLimit.login and no variable", async () => {
		expect(await relocatedBy("rateLimit.login { windowMs = 60000, limit = 7 }\n")).toEqual([
			{
				module: "session",
				from: "rateLimit.login.windowMs",
				to: "session.rateLimit.login.windowMs",
			},
			{ module: "session", from: "rateLimit.login.limit", to: "session.rateLimit.login.limit" },
		]);
	});

	it("oauth.tokenBinding: each key refused, naming its path under core.tokenBinding and its variable", async () => {
		const relocated = await relocatedBy(
			[
				"oauth.tokenBinding {",
				'  dispatch-policy = "strict-mutual-exclusion"',
				"  bindConfidentialClientRefreshTokens = true",
				"}",
				"",
			].join("\n"),
		);

		expect(relocated).toEqual(
			expect.arrayContaining([
				{
					module: "core",
					from: "oauth.tokenBinding.dispatch-policy",
					to: "core.tokenBinding.dispatchPolicy",
					environmentVariable: "CORE_TOKEN_BINDING_DISPATCH_POLICY",
				},
				{
					module: "core",
					from: "oauth.tokenBinding.bindConfidentialClientRefreshTokens",
					to: "core.tokenBinding.bindConfidentialClientRefreshTokens",
					environmentVariable: "CORE_TOKEN_BINDING_BIND_CONFIDENTIAL_CLIENT_REFRESH_TOKENS",
				},
			]),
		);
	});
});

describe("a key a section does not declare", () => {
	it.each([
		["oauth-session.enable = true", "enable"],
		["oauth-authorization.grants.authCode.enabled = true", "authCode"],
		["oauth-authorization.grants.refreshToken.enable = true", "enable"],
		['oauth.consentPage.path = "/consent"', "path"],
		['core.tokenBinding.policy = "strict-mutual-exclusion"', "policy"],
		['session.loginPag.url = "/sign-in"', "loginPag"],
		["session.rateLimit.login.windowSeconds = 60", "windowSeconds"],
		['session-store.storag.type = "memory"', "storag"],
		['session-store.storage.redis.passwd = "p"', "passwd"],
	])("%s: refused, naming %s", async (hocon, key) => {
		const err = await refused({ operatorHocon: `${hocon}\n` });

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain(`"${key}"`);
	});
});

describe("a variable renamed with the move, through the template's reading", () => {
	/** Each renamed variable: its module, old and new names, the path the new one binds, a value, and what boot parses of it. */
	const ROWS = [
		{
			module: "oauth-session",
			from: "OAUTH_GRANTS_SESSION_ENABLED",
			to: "OAUTH_SESSION_ENABLED",
			path: "oauth-session.enabled",
			value: "true",
			parsed: true,
		},
		{
			module: "oauth-authorization",
			from: "OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED",
			to: "OAUTH_AUTHORIZATION_GRANTS_AUTHORIZATION_CODE_ENABLED",
			path: "oauth-authorization.grants.authorizationCode.enabled",
			value: "true",
			parsed: true,
		},
		{
			module: "oauth-authorization",
			from: "OAUTH_GRANTS_REFRESH_TOKEN_ENABLED",
			to: "OAUTH_AUTHORIZATION_GRANTS_REFRESH_TOKEN_ENABLED",
			path: "oauth-authorization.grants.refreshToken.enabled",
			value: "true",
			parsed: true,
		},
		{
			module: "oauth-authorization",
			from: "OAUTH_GRANTS_CLIENT_CREDENTIALS_ENABLED",
			to: "OAUTH_AUTHORIZATION_GRANTS_CLIENT_CREDENTIALS_ENABLED",
			path: "oauth-authorization.grants.clientCredentials.enabled",
			value: "true",
			parsed: true,
		},
		{
			module: "oauth-authorization",
			from: "OAUTH_GRANTS_JWT_BEARER_ENABLED",
			to: "OAUTH_AUTHORIZATION_GRANTS_JWT_BEARER_ENABLED",
			path: "oauth-authorization.grants.jwtBearer.enabled",
			value: "false",
			parsed: false,
		},
		{
			module: "oauth",
			from: "ENDPOINTS_CONSENT_URL",
			to: "OAUTH_CONSENT_PAGE_URL",
			path: "oauth.consentPage.url",
			value: "/consent/page",
			parsed: "/consent/page",
		},
		...(
			[
				["ENABLED", "enabled", "true", true],
				["ALLOWED_SCOPES", "allowedScopes", "read", ["read"]],
				["ALLOWED_AUDIENCES", "allowedAudiences", "https://api.example", ["https://api.example"]],
				["ALLOWED_HOSTS", "allowedHosts", "a.example", ["a.example"]],
				["DENIED_HOSTS", "deniedHosts", "b.example", ["b.example"]],
				["MAX_BYTES", "maxBytes", "4096", 4096],
				["TIMEOUT_MS", "timeoutMs", "3000", 3000],
				["CACHE_MAX_AGE_MS", "cacheMaxAgeMs", "60000", 60000],
				["MAX_CACHE_ENTRIES", "maxCacheEntries", "64", 64],
				["STALE_IF_ERROR_MS", "staleIfErrorMs", "1000", 1000],
				["NEGATIVE_CACHE_MS", "negativeCacheMs", "2000", 2000],
				["MAX_CONCURRENT_FETCHES", "maxConcurrentFetches", "2", 2],
			] as const
		).map(([name, key, value, parsed]) => ({
			module: "oauth",
			from: `OAUTH_CIMD_${name}`,
			to: `OAUTH_CLIENT_ID_METADATA_DOCUMENTS_${name}`,
			path: `oauth.clientIdMetadataDocuments.${key}`,
			value,
			parsed,
		})),
		{
			module: "core",
			from: "OAUTH_TOKEN_BINDING_DISPATCH_POLICY",
			to: "CORE_TOKEN_BINDING_DISPATCH_POLICY",
			path: "core.tokenBinding.dispatchPolicy",
			value: "strict-mutual-exclusion",
			parsed: "strict-mutual-exclusion",
		},
		{
			module: "core",
			from: "OAUTH_TOKEN_BINDING_BIND_CONFIDENTIAL_CLIENT_REFRESH_TOKENS",
			to: "CORE_TOKEN_BINDING_BIND_CONFIDENTIAL_CLIENT_REFRESH_TOKENS",
			path: "core.tokenBinding.bindConfidentialClientRefreshTokens",
			value: "true",
			parsed: true,
		},
		{
			module: "session",
			from: "ENDPOINTS_LOGIN_URL",
			to: "SESSION_LOGIN_PAGE_URL",
			path: "session.loginPage.url",
			value: "/sign-in",
			parsed: "/sign-in",
		},
		...(
			[
				["SECRET", "secret", "t-prime-session-secret.at-least-32-bytes.ok", undefined],
				["NAME", "name", "auth.renamed", undefined],
				["MAX_AGE", "maxAge", "7200000", 7_200_000],
				["SECURE", "secure", "false", false],
				["SAME_SITE", "sameSite", "strict", undefined],
				["DOMAIN", "domain", "auth.example.com", undefined],
				["STORAGE_TYPE", "storage.type", "memory", undefined],
				["STORAGE_REDIS_URL", "storage.redis.url", "redis://renamed.test:6379", undefined],
				["STORAGE_REDIS_PASSWORD", "storage.redis.password", "renamed-password", undefined],
			] as const
		).map(([name, key, value, parsed]) => ({
			module: "session-store",
			from: `SESSION_${name}`,
			to: `SESSION_STORE_${name}`,
			path: `session-store.${key}`,
			value,
			parsed: parsed ?? value,
		})),
	];

	it.each(ROWS)(
		"$from set alone: refused, naming $to and $path",
		async ({ module, from, to, path, value }) => {
			const err = await refused({ env: { ...without(to), [from]: value } });

			expect(err.details).toEqual({
				reason: "environment-variable-renamed",
				renamed: [{ module, from, to, path, state: "unset" }],
			});
		},
	);

	it.each(ROWS)(
		"$from set beside $to at a different value: refused, naming neither value",
		async ({ from, to }) => {
			const err = await refused({
				env: { ...SINGLE_ENV, [from]: "old-value-5e2d", [to]: "new-value-c81a" },
			});

			expect(err.details).toMatchObject({ renamed: [{ from, to, state: "different" }] });
			for (const value of ["old-value-5e2d", "new-value-c81a"]) {
				expect(err.message).not.toContain(value);
				expect(JSON.stringify(err.details)).not.toContain(value);
			}
		},
	);

	it.each(ROWS)(
		"$from set beside $to at the same value: boots, $path parsed from it",
		async ({ from, to, path, value, parsed }) => {
			const composition = await boot({ env: { ...SINGLE_ENV, [from]: value, [to]: value } });

			expect(parsedAt(composition, path)).toEqual(parsed);
		},
	);

	it("OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256 set at all: refused, its key removed", async () => {
		const err = await refused({
			env: { ...SINGLE_ENV, OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256: "true" },
		});

		expect(err.details).toEqual({
			reason: "environment-variable-renamed",
			renamed: [
				{
					module: "oauth-authorization",
					from: "OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256",
					to: null,
					path: null,
					state: "removed",
				},
			],
		});
	});
});
