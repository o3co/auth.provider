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
	type AppHandle,
	BootError,
	createApp,
	defaultRefreshTokenFamilyRevocationModule,
	defineModule,
	type FederationProvider,
	federationsOf,
	type Module,
	memoryFederationTokenStoreModule,
	memoryRefreshTokenFamilyStoreModule,
	memorySessionStoresModule,
} from "@o3co/auth-provider-core";
import {
	coreConfigForTests,
	createFakeIdp,
	type FakeIdp,
	makeValidAppConfig,
	renamedVariableCaptures,
} from "@o3co/auth-provider-core/testing";
import {
	type FederationRedirectPolicy,
	sessionModule,
	sessionStoreModuleFor,
} from "@o3co/auth-provider-session";
import express from "express";
import { decodeJwt, decodeProtectedHeader, jwtVerify } from "jose";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	APPLE_ISSUER,
	type AppleProvider,
	type AppleProviderConfig,
	appleFederationModule,
	appleFederationTypeModule,
} from "#/index.mjs";
import { makeTestSigningKey } from "./helpers.mjs";

/**
 * The module that handles every `core.federations` entry of type `apple`,
 * through core's `createApp`: one provider and one redirect policy per
 * enabled entry, under the entry's name; the entry flat and held to a strict
 * schema; Apple reached through the fetch the module was given; and the same
 * provider and policy as the deprecated fixed-name module builds for the same
 * entry.
 */

const APPLE = {
	issuer: APPLE_ISSUER,
	authorizationEndpoint: "https://appleid.apple.com/auth/authorize",
	tokenEndpoint: "https://appleid.apple.com/auth/token",
	jwksUri: "https://appleid.apple.com/auth/keys",
};
const CALLBACK_WEB = "https://auth.test/session/oauth/federation/apple-web/callback";
const CALLBACK_PARTNER = "https://auth.test/session/oauth/federation/apple-partner/callback";

const entryWeb = {
	enabled: true,
	type: "apple",
	clientId: "com.example.web",
	clientSecret: "web-static-secret",
	callbackURL: CALLBACK_WEB,
	clientUrl: "https://web.test/",
};
const entryPartner = {
	enabled: true,
	type: "apple",
	clientId: "com.example.partner",
	clientSecret: "partner-static-secret",
	callbackURL: CALLBACK_PARTNER,
	clientUrl: "https://partner.test/",
};

/** A `.p8`-shaped signing key, for the entries that sign their own client secret. */
const signingKey = await makeTestSigningKey();
const PEM = signingKey.privateKeyPem;

/** `entryWeb` with the key material in place of its static secret. */
const withKeyMaterial = (keys: Record<string, unknown>) => {
	const { clientSecret: _secret, ...entry } = entryWeb;
	return { ...entry, ...keys };
};
const KEY_MATERIAL = { teamId: "TEAM123456", keyId: "KEY9876543", privateKey: PEM };

/**
 * One fetch in front of several fake Apples, each holding one client: a token
 * request goes to the fake of the `client_id` it carries, and the JWKS
 * request that verifies its answer to the same fake.
 */
const routedFetch = (...fakes: readonly FakeIdp[]): typeof fetch => {
	let current: FakeIdp | undefined;
	return (input, init) => {
		const raw = init?.body;
		const clientId =
			raw === undefined || raw === null
				? undefined
				: new URLSearchParams(String(raw)).get("client_id");
		if (clientId !== undefined && clientId !== null) {
			current = fakes.find((fake) => fake.clientId === clientId);
		}
		if (current === undefined) throw new Error("no fake Apple holds this client");
		return current.fetch(input, init);
	};
};

const fakeApple = (clientId: string, sub?: string) =>
	createFakeIdp({ ...APPLE, clientId, ...(sub !== undefined ? { sub } : {}) });

function configWith(federations: Record<string, unknown>): AppConfig {
	const base = makeValidAppConfig();
	return {
		...base,
		...coreConfigForTests({ declaredAbsent: ["auditSink"], federations: federations as never }),
	} as unknown as AppConfig;
}

// Requires both projections, so the boot planner materialises them into
// `handle.components`.
const activatorModule = defineModule({
	name: "test-apple-activator",
	requires: ["federationProviders", "federationRedirectPolicyResolver"] as never,
	contributes: {
		routes: [
			{
				mountPath: "/__test_apple_noop__",
				id: "test-apple-noop",
				handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
			},
		],
	},
});

interface BootOptions {
	/** The modules that handle the entries; default the type module over `fetch`. */
	readonly federationModules?: readonly Module[];
	readonly fetch?: typeof fetch;
	readonly authenticateByToken?: (token: string) => Promise<unknown>;
}

async function boot(federations: Record<string, unknown>, options: BootOptions = {}) {
	const config = configWith(federations);
	const repo = {
		authenticate: vi.fn(async () => null),
		authenticateByToken: vi.fn(options.authenticateByToken ?? (async () => null)),
	};
	const repositoryModule = defineModule({
		name: "test:user-repository",
		provides: { userRepository: () => repo } as never,
	});
	const modules = [
		sessionStoreModuleFor(config),
		sessionModule,
		memorySessionStoresModule,
		memoryFederationTokenStoreModule,
		memoryRefreshTokenFamilyStoreModule,
		defaultRefreshTokenFamilyRevocationModule,
		repositoryModule,
		activatorModule,
		...(options.federationModules ?? [
			appleFederationTypeModule(options.fetch ? { fetch: options.fetch } : {}),
		]),
	];
	const handle = await createApp({
		modules,
		bootstrapComponents: {
			config: {
				...config,
				"renamed-variables": {
					...(config as { "renamed-variables"?: object })["renamed-variables"],
					...renamedVariableCaptures({ modules, env: {} }),
				},
			},
			pathResolver: (s: string) => s,
		},
	});
	handles.push(handle);
	const app = express();
	app.use(handle.router);
	return { handle, app, repo };
}

const handles: AppHandle[] = [];
afterEach(async () => {
	for (const handle of handles.splice(0)) await handle.dispose();
});

const providersOf = (handle: AppHandle) =>
	(handle.components as Record<string, unknown>).federationProviders as ReadonlyMap<
		string,
		FederationProvider
	>;
const policiesOf = (handle: AppHandle) =>
	(handle.components as Record<string, unknown>).federationRedirectPolicyResolver as ReadonlyMap<
		string,
		FederationRedirectPolicy
	>;

/** What `createApp` refused with, or a failure when it booted. */
async function refusal(promise: Promise<unknown>): Promise<BootError> {
	try {
		await promise;
	} catch (err) {
		expect(err).toBeInstanceOf(BootError);
		return err as BootError;
	}
	return expect.fail("boot should have been refused");
}

/** The paths of a `config-validation-failed` refusal's issues, each joined as the operator writes it. */
const issuePaths = (err: BootError): string[] =>
	((err.details as { issues?: { path: PropertyKey[] }[] }).issues ?? []).map((issue) =>
		issue.path.map(String).join("."),
	);

/** The `name=value` pairs a response set, as a `Cookie` header sends them back. */
const cookiesOf = (res: request.Response): string =>
	([] as string[])
		.concat(res.headers["set-cookie"] ?? [])
		.map((cookie) => cookie.split(";")[0])
		.join("; ");

/** A login through the session routes: the start, Apple's answer, and the form_post callback. */
async function login(app: express.Express, name: string, fake: FakeIdp) {
	const start = await request(app).get(`/session/oauth/federation/${name}`);
	expect(start.status).toBe(302);
	const authUrl = new URL(start.headers.location ?? "");
	const answer = fake.authorize(authUrl);
	const callback = await request(app)
		.post(`/session/oauth/federation/${name}/callback`)
		.set("Cookie", cookiesOf(start))
		.type("form")
		.send({ code: answer.code, state: answer.state ?? "" });
	return { authUrl, callback };
}

describe("appleFederationTypeModule", () => {
	it("contributes the type apple, and requires no dependency — the whole config least of all", () => {
		const module = appleFederationTypeModule();
		expect(module.name).toBe("federation-apple-type");
		expect(module.requires ?? []).toEqual([]);
		expect(module.optional ?? []).toEqual([]);
		const contributes = module.contributes as Record<string, Record<string, unknown>>;
		expect(Object.keys(contributes)).toEqual(["federationTypes"]);
		expect(Object.keys(contributes.federationTypes ?? {})).toEqual(["apple"]);
	});
});

describe("appleFederationTypeModule through createApp", () => {
	it("builds one provider and one redirect policy per enabled entry of type apple, under the entry's name", async () => {
		const web = await fakeApple(entryWeb.clientId);
		const partner = await fakeApple(entryPartner.clientId);

		const { handle } = await boot(
			{
				"apple-web": entryWeb,
				"apple-partner": entryPartner,
				// Not read: a disabled entry is neither parsed nor built.
				off: { enabled: false, type: "apple", bogus: true },
			},
			{ fetch: routedFetch(web, partner) },
		);

		const providers = providersOf(handle);
		expect([...providers.keys()].sort()).toEqual(["apple-partner", "apple-web"]);
		expect(providers.get("apple-web")?.name).toBe("apple-web");
		expect(providers.get("apple-partner")?.name).toBe("apple-partner");
		expect(providers.get("apple-web")?.responseMode).toBe("form_post");
		expect([...policiesOf(handle).keys()].sort()).toEqual(["apple-partner", "apple-web"]);

		const authorize = (name: string, redirectUri: string) =>
			providers.get(name)?.buildAuthorizationUrl({
				redirectUri,
				state: "s",
				codeVerifier: "v".repeat(43),
				nonce: "n",
			});
		const urlWeb = authorize("apple-web", CALLBACK_WEB);
		const urlPartner = authorize("apple-partner", CALLBACK_PARTNER);
		expect(urlWeb?.searchParams.get("client_id")).toBe("com.example.web");
		expect(urlWeb?.searchParams.get("redirect_uri")).toBe(CALLBACK_WEB);
		expect(urlPartner?.searchParams.get("client_id")).toBe("com.example.partner");
		expect(urlPartner?.searchParams.get("redirect_uri")).toBe(CALLBACK_PARTNER);
		// Each provider holds its own entry's callbackURL, the one core handed it.
		expect(() => authorize("apple-web", CALLBACK_PARTNER)).toThrow(/"apple-web"/);
	});

	it("logs in through the session routes: the entry's callback, the module's fetch to Apple, the entry's redirect policy, the identity under the entry's name", async () => {
		const web = await fakeApple(entryWeb.clientId, "sub-web-1");
		const partner = await fakeApple(entryPartner.clientId, "sub-partner-1");
		const { app, repo } = await boot(
			{ "apple-web": entryWeb, "apple-partner": entryPartner },
			{
				fetch: routedFetch(web, partner),
				authenticateByToken: async (token) =>
					token === "apple-partner:sub-partner-1" ? { id: "user-p", username: "pat" } : null,
			},
		);

		const { authUrl, callback } = await login(app, "apple-partner", partner);
		expect(`${authUrl.origin}${authUrl.pathname}`).toBe(APPLE.authorizationEndpoint);
		expect(authUrl.searchParams.get("response_mode")).toBe("form_post");
		expect(callback.status).toBe(302);
		// The redirect policy built from the entry: its clientUrl.
		expect(callback.headers.location).toBe("https://partner.test/");
		expect(repo.authenticateByToken).toHaveBeenCalledWith("apple-partner:sub-partner-1");

		// The token and JWKS requests went through the module's fetch, to the
		// partner's client alone, with the partner's secret.
		const token = partner.lastTokenRequest();
		expect(token?.body?.get("client_id")).toBe("com.example.partner");
		expect(token?.body?.get("client_secret")).toBe("partner-static-secret");
		expect(token?.body?.get("redirect_uri")).toBe(CALLBACK_PARTNER);
		expect(partner.requestsTo(APPLE.jwksUri)).toHaveLength(1);
		expect(web.requests).toHaveLength(0);
	});

	it("signs the client secret from the entry's key material", async () => {
		const fake = await fakeApple(entryWeb.clientId);
		const { app } = await boot(
			{ "apple-web": withKeyMaterial(KEY_MATERIAL) },
			{ fetch: fake.fetch, authenticateByToken: async () => ({ id: "u", username: "u" }) },
		);
		const { callback } = await login(app, "apple-web", fake);
		expect(callback.status).toBe(302);
		const secret = fake.lastTokenRequest()?.body?.get("client_secret") ?? "";
		const { payload, protectedHeader } = await jwtVerify(secret, signingKey.publicKey, {
			audience: APPLE_ISSUER,
		});
		expect(protectedHeader).toMatchObject({ alg: "ES256", kid: "KEY9876543" });
		expect(payload).toMatchObject({ iss: "TEAM123456", sub: "com.example.web" });
	});

	it("refuses a key the type does not read, at the entry's path", async () => {
		const err = await refusal(boot({ "apple-web": { ...entryWeb, clientSecrte: "typo" } }));
		expect(err.reason).toBe("config-validation-failed");
		expect(issuePaths(err)).toContain("core.federations.apple-web");
		expect(err.message).toMatch(/core\.federations\.apple-web: .*"clientSecrte"/);
	});

	it("refuses the nested apple { … } shape: an entry is flat", async () => {
		const { clientId, clientSecret, callbackURL, ...outer } = entryWeb;
		const err = await refusal(
			boot({ "apple-web": { ...outer, apple: { clientId, clientSecret, callbackURL } } }),
		);
		expect(err.reason).toBe("config-validation-failed");
		const paths = issuePaths(err);
		expect(paths).toContain("core.federations.apple-web.callbackURL");
		expect(paths).toContain("core.federations.apple-web.clientId");
		expect(err.message).toMatch(/core\.federations\.apple-web: .*"apple"/);
		expect(err.message).toMatch(/a dispatched entry is flat/);
	});

	it.each([
		["clientId", "core.federations.apple-web.clientId"],
		["callbackURL", "core.federations.apple-web.callbackURL"],
	])("refuses an entry without %s, at its path", async (key, path) => {
		const { [key as keyof typeof entryWeb]: _dropped, ...entry } = entryWeb;
		const err = await refusal(boot({ "apple-web": entry }));
		expect(err.reason).toBe("config-validation-failed");
		expect(issuePaths(err)).toContain(path);
	});

	it("refuses an entry that sets neither, or both, of clientSecret and the key material", async () => {
		const { clientSecret: _dropped, ...neither } = entryWeb;
		const both = { ...entryWeb, ...KEY_MATERIAL };
		for (const entry of [neither, both]) {
			const err = await refusal(boot({ "apple-web": entry }));
			expect(err.reason).toBe("config-validation-failed");
			expect(issuePaths(err)).toContain("core.federations.apple-web");
			expect(err.message).toMatch(/exactly one of clientSecret[\s\S]*teamId/);
		}
	});

	it.each([
		["teamId", "core.federations.apple-web.teamId"],
		["keyId", "core.federations.apple-web.keyId"],
		["privateKey", "core.federations.apple-web.privateKey"],
	])("refuses key material without %s, at its path", async (key, path) => {
		const { [key as keyof typeof KEY_MATERIAL]: _dropped, ...keys } = KEY_MATERIAL;
		const err = await refusal(boot({ "apple-web": withKeyMaterial(keys) }));
		expect(err.reason).toBe("config-validation-failed");
		expect(issuePaths(err)).toEqual([path]);
	});

	it.each([
		["clientId", 42, "core.federations.apple-web.clientId"],
		["clientSecret", 42, "core.federations.apple-web.clientSecret"],
		["redirectAllowlist", "https://web.test/", "core.federations.apple-web.redirectAllowlist"],
		["redirectAllowlist", [1], "core.federations.apple-web.redirectAllowlist.0"],
		["sessionDomain", 42, "core.federations.apple-web.sessionDomain"],
		["authCallbackUrl", false, "core.federations.apple-web.authCallbackUrl"],
		["clientUrl", {}, "core.federations.apple-web.clientUrl"],
		["endSessionEndpoint", 1, "core.federations.apple-web.endSessionEndpoint"],
		["jwksUri", ["https://x"], "core.federations.apple-web.jwksUri"],
	])("refuses %s of the wrong shape (%j), at its path", async (key, value, path) => {
		const err = await refusal(boot({ "apple-web": { ...entryWeb, [key]: value } }));
		expect(err.reason).toBe("config-validation-failed");
		expect(issuePaths(err)).toContain(path);
	});

	it("reads a key written null as absent", async () => {
		const fake = await fakeApple(entryWeb.clientId);
		const { handle } = await boot(
			{ "apple-web": { ...entryWeb, teamId: null, keyId: null, privateKey: null, jwksUri: null } },
			{ fetch: fake.fetch },
		);
		expect(providersOf(handle).get("apple-web")?.name).toBe("apple-web");
	});

	it.each([
		["a plain-http callbackURL", "http://auth.test/cb", /https/],
		["a loopback callbackURL", "https://localhost/cb", /loopback/],
	])("refuses %s when the entry's provider is built", async (_what, callbackURL, pattern) => {
		const err = await refusal(boot({ "apple-web": { ...entryWeb, callbackURL } }));
		expect(`${err.message} ${JSON.stringify(err.details)}`).toMatch(pattern);
		expect(`${err.message} ${JSON.stringify(err.details)}`).toMatch(/"apple-web"/);
	});

	describe("a refusal never quotes a credential", () => {
		const SECRET = "s3cret-that-must-not-be-echoed";
		const cases: readonly (readonly [string, Record<string, unknown>])[] = [
			["a clientSecret of the wrong type", { ...entryWeb, clientSecret: [SECRET] }],
			["both credentials", { ...entryWeb, clientSecret: SECRET, ...KEY_MATERIAL }],
			["a privateKey of the wrong type", withKeyMaterial({ ...KEY_MATERIAL, privateKey: [PEM] })],
			[
				"key material without teamId, beside an unknown key",
				withKeyMaterial({ keyId: "KEY9876543", privateKey: PEM, privateKeyPath: PEM }),
			],
			[
				"a plain-http callbackURL beside the secret",
				{ ...entryWeb, clientSecret: SECRET, callbackURL: "http://auth.test/cb" },
			],
			[
				"a loopback callbackURL beside the key material",
				withKeyMaterial({ ...KEY_MATERIAL, callbackURL: "https://127.0.0.1/cb" }),
			],
		];
		/** The secret, the PEM, and the PEM's base64 body without its armour. */
		const credentials = [SECRET, PEM, PEM.split("\n")[1] ?? PEM];

		it.each(cases)("%s", async (_what, entry) => {
			const err = await refusal(boot({ "apple-web": entry }));
			const details = JSON.stringify(err.details);
			for (const credential of credentials) {
				expect(err.message).not.toContain(credential);
				expect(details).not.toContain(credential);
			}
		});
	});

	it("refuses the deprecated fixed-name module beside it for the same entry: one federation has one handler", async () => {
		const fake = await fakeApple(entryWeb.clientId);
		const err = await refusal(
			boot(
				{ apple: entryWeb },
				{
					federationModules: [
						appleFederationTypeModule({ fetch: fake.fetch }),
						appleFederationModule,
						bridgeFor("apple", fake.fetch),
					],
				},
			),
		);
		expect(err.reason).toBe("duplicate-contribute");
		expect(err.message).toMatch(/federation-apple-type/);
		expect(err.message).toMatch(/"federation-apple"/);
	});
});

/**
 * A bridge as composition roots write one for the deprecated module: the
 * entry's keys copied into the `appleFederationConfig` slot, with the fetch
 * beside them.
 */
function bridgeFor(name: string, upstreamFetch: typeof fetch): Module {
	return defineModule({
		name: "test:apple-federation-config",
		requires: ["config"] as const,
		provides: {
			appleFederationConfig: ({ config }): AppleProviderConfig => {
				const {
					enabled: _enabled,
					type: _type,
					...entry
				} = federationsOf(config)[name] as Record<string, unknown>;
				return { ...(entry as unknown as AppleProviderConfig), fetch: upstreamFetch };
			},
		},
	});
}

describe("appleFederationTypeModule — parity with the deprecated fixed-name module", () => {
	const options = {
		redirectAllowlist: ["https://web.test/welcome"],
		sessionDomain: "web.test",
		authCallbackUrl: "https://web.test/auth/callback",
		endSessionEndpoint: "https://web.test/apple-logout",
	};
	const CALLBACK = "https://auth.test/session/oauth/federation/apple/callback";
	const entries: readonly (readonly [string, Record<string, unknown>])[] = [
		["a static clientSecret", { ...entryWeb, callbackURL: CALLBACK, ...options }],
		["key material", { ...withKeyMaterial(KEY_MATERIAL), callbackURL: CALLBACK, ...options }],
	];

	/** The provider and the policy one path builds for `apple` from `entry`, against a fresh fake Apple. */
	async function built(path: "fixed-name" | "type", entry: Record<string, unknown>) {
		const fake = await fakeApple(entryWeb.clientId, "sub-1");
		const { handle } = await boot(
			{ apple: entry },
			{
				federationModules:
					path === "type"
						? [appleFederationTypeModule({ fetch: fake.fetch })]
						: [appleFederationModule, bridgeFor("apple", fake.fetch)],
			},
		);
		const provider = providersOf(handle).get("apple");
		const policy = policiesOf(handle).get("apple");
		if (provider === undefined || policy === undefined) {
			return expect.fail(`the ${path} path built no provider or no policy for apple`);
		}
		return { fake, provider, policy };
	}

	it.each(entries)(
		"builds the same provider and the same redirect policy from one entry (%s)",
		async (_what, entry) => {
			const fixedName = await built("fixed-name", entry);
			const type = await built("type", entry);

			expect(type.provider.name).toBe(fixedName.provider.name);
			expect(type.provider.scope).toEqual(fixedName.provider.scope);
			expect(type.provider.responseMode).toBe(fixedName.provider.responseMode);
			expect(Object.keys(type.provider).sort()).toEqual(Object.keys(fixedName.provider).sort());

			const authorize = (provider: FederationProvider) =>
				provider.buildAuthorizationUrl({
					redirectUri: CALLBACK,
					state: "state-1",
					codeVerifier: "v".repeat(43),
					nonce: "nonce-1",
				}).href;
			expect(authorize(type.provider)).toBe(authorize(fixedName.provider));

			const exchange = async ({ fake, provider }: Awaited<ReturnType<typeof built>>) => {
				fake.nonce = "nonce-1";
				const profile = await provider.exchangeCode({
					code: "code-1",
					codeVerifier: "v".repeat(43),
					redirectUri: CALLBACK,
					nonce: "nonce-1",
				});
				// A signed client secret is minted per instance (its iat and exp
				// differ): compared by its header and the claims that name the
				// team, the client and the audience.
				const { client_secret: secret, ...body } = Object.fromEntries(
					fake.lastTokenRequest()?.body ?? [],
				);
				const signed =
					secret === undefined || !secret.includes(".")
						? secret
						: {
								header: decodeProtectedHeader(secret),
								claims: (({ iss, sub, aud }) => ({ iss, sub, aud }))(decodeJwt(secret)),
							};
				return {
					issuer: profile.issuer,
					sub: profile.sub,
					email: profile.email,
					jwks: fake.requestsTo(APPLE.jwksUri).length,
					body,
					signed,
				};
			};
			expect(await exchange(type)).toEqual(await exchange(fixedName));

			const logout = (provider: FederationProvider) =>
				(provider as AppleProvider)
					.endSession({ idTokenHint: "id-1", postLogoutRedirectUri: "https://web.test/bye" })
					.then(({ url, method }) => ({ url: url.href, method }));
			expect(await logout(type.provider)).toEqual(await logout(fixedName.provider));

			for (const url of ["https://web.test/welcome", "https://elsewhere.test/"]) {
				expect(type.policy.validateRedirect(url)).toEqual(fixedName.policy.validateRedirect(url));
			}
			for (const session of [{}, { redirectTo: "https://web.test/welcome" }]) {
				expect(type.policy.resolveCallbackRedirect(session)).toEqual(
					fixedName.policy.resolveCallbackRedirect(session),
				);
			}
		},
	);
});
