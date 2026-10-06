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
	codeChallenge,
	createApp,
	defaultRefreshTokenFamilyRevocationModule,
	defineModule,
	type FederationProvider,
	memoryFederationTokenStoreModule,
	memoryRefreshTokenFamilyStoreModule,
	memorySessionStoresModule,
	sessionLifecycleModule,
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
	sessionStoreModule,
} from "@o3co/auth-provider-session";
import express from "express";
import { jwtVerify } from "jose";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { APPLE_ISSUER, type AppleProvider, appleFederationTypeModule } from "#/index.mjs";
import { makeTestSigningKey } from "./helpers.mjs";

/**
 * The module that handles every `core.federations` entry of type `apple`,
 * through core's `createApp`: one provider and one redirect policy per
 * enabled entry, under the entry's name; the entry flat and held to a strict
 * schema; Apple reached through the fetch the module was given; and every
 * key of an entry reaching the provider or the redirect policy built from it.
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
		...coreConfigForTests({
			declaredAbsent: ["auditSink", "rateLimiter"],
			federations: federations as never,
		}),
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
		sessionStoreModule,
		sessionModule,
		memorySessionStoresModule,
		sessionLifecycleModule,
		memoryFederationTokenStoreModule,
		memoryRefreshTokenFamilyStoreModule,
		defaultRefreshTokenFamilyRevocationModule,
		repositoryModule,
		activatorModule,
		appleFederationTypeModule(options.fetch ? { fetch: options.fetch } : {}),
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

	it("refuses jwksUri: a test seam of the provider, not an entry key — the fetch option is the type's", async () => {
		const err = await refusal(
			boot({ "apple-web": { ...entryWeb, jwksUri: "https://keys.example/jwks" } }),
		);
		expect(err.reason).toBe("config-validation-failed");
		expect(issuePaths(err)).toContain("core.federations.apple-web");
		expect(err.message).toMatch(/core\.federations\.apple-web: .*"jwksUri"/);
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
	])("refuses %s of the wrong shape (%j), at its path", async (key, value, path) => {
		const err = await refusal(boot({ "apple-web": { ...entryWeb, [key]: value } }));
		expect(err.reason).toBe("config-validation-failed");
		expect(issuePaths(err)).toContain(path);
	});

	it.each([
		["an empty clientSecret", { ...entryWeb, clientSecret: "" }, "clientSecret"],
		["an empty teamId", withKeyMaterial({ ...KEY_MATERIAL, teamId: "" }), "teamId"],
		["a keyId that is a number", withKeyMaterial({ ...KEY_MATERIAL, keyId: 42 }), "keyId"],
		["an empty keyId", withKeyMaterial({ ...KEY_MATERIAL, keyId: "" }), "keyId"],
		["an empty privateKey", withKeyMaterial({ ...KEY_MATERIAL, privateKey: "" }), "privateKey"],
	])(
		"refuses %s as a key that must be a non-empty string, not as a missing one",
		async (_what, entry, key) => {
			const err = await refusal(boot({ "apple-web": entry }));
			expect(err.reason).toBe("config-validation-failed");
			expect(issuePaths(err)).toEqual([`core.federations.apple-web.${key}`]);
			expect(err.message).toContain(
				`core.federations.apple-web.${key}: must be a non-empty string`,
			);
			expect(err.message).not.toMatch(/is required/);
		},
	);

	it("reads a key written null as absent", async () => {
		const fake = await fakeApple(entryWeb.clientId);
		const { handle } = await boot(
			{
				"apple-web": {
					...entryWeb,
					teamId: null,
					keyId: null,
					privateKey: null,
					endSessionEndpoint: null,
				},
			},
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
});

describe("appleFederationTypeModule — what the provider and the policy make of an entry's keys", () => {
	const options = {
		redirectAllowlist: ["https://web.test/welcome"],
		sessionDomain: "web.test",
		authCallbackUrl: "https://web.test/auth/callback",
		endSessionEndpoint: "https://web.test/apple-logout",
	};
	const CALLBACK = "https://auth.test/session/oauth/federation/apple/callback";
	const VERIFIER = "v".repeat(43);
	const entries: readonly (readonly [string, Record<string, unknown>])[] = [
		["a static clientSecret", { ...entryWeb, callbackURL: CALLBACK, ...options }],
		["key material", { ...withKeyMaterial(KEY_MATERIAL), callbackURL: CALLBACK, ...options }],
	];

	it.each(entries)(
		"builds the Apple provider and the redirect policy from the entry (%s)",
		async (_what, entry) => {
			const fake = await fakeApple(entryWeb.clientId, "sub-1");
			const { handle } = await boot({ apple: entry }, { fetch: fake.fetch });
			const provider = providersOf(handle).get("apple") as AppleProvider | undefined;
			const policy = policiesOf(handle).get("apple");
			if (provider === undefined || policy === undefined) {
				return expect.fail("the type module built no provider or no policy for apple");
			}

			expect(provider.name).toBe("apple");
			expect(provider.scope).toEqual(["name", "email"]);
			expect(provider.responseMode).toBe("form_post");
			// The whole Apple provider: refresh, upstream logout and claim mapping
			// beside the login flow.
			expect(Object.keys(provider).sort()).toEqual([
				"buildAuthorizationUrl",
				"endSession",
				"exchangeCode",
				"mapClaims",
				"name",
				"refreshToken",
				"responseMode",
				"scope",
			]);

			const authUrl = provider.buildAuthorizationUrl({
				redirectUri: CALLBACK,
				state: "state-1",
				codeVerifier: VERIFIER,
				nonce: "nonce-1",
			});
			expect(`${authUrl.origin}${authUrl.pathname}`).toBe(APPLE.authorizationEndpoint);
			expect(Object.fromEntries(authUrl.searchParams)).toEqual({
				client_id: "com.example.web",
				redirect_uri: CALLBACK,
				response_type: "code",
				scope: "name email",
				state: "state-1",
				code_challenge: codeChallenge(VERIFIER),
				code_challenge_method: "S256",
				nonce: "nonce-1",
			});

			fake.nonce = "nonce-1";
			const profile = await provider.exchangeCode({
				code: "code-1",
				codeVerifier: VERIFIER,
				redirectUri: CALLBACK,
				nonce: "nonce-1",
			});
			expect(profile).toMatchObject({
				issuer: APPLE_ISSUER,
				sub: "sub-1",
				email: "alice@example.test",
			});
			expect(fake.requestsTo(APPLE.jwksUri)).toHaveLength(1);
			const { client_secret: secret, ...body } = Object.fromEntries(
				fake.lastTokenRequest()?.body ?? [],
			);
			expect(body).toEqual({
				grant_type: "authorization_code",
				code: "code-1",
				code_verifier: VERIFIER,
				redirect_uri: CALLBACK,
				client_id: "com.example.web",
			});
			if (entry.clientSecret !== undefined) {
				expect(secret).toBe(entry.clientSecret);
			} else {
				const { payload, protectedHeader } = await jwtVerify(secret ?? "", signingKey.publicKey, {
					audience: APPLE_ISSUER,
				});
				expect(protectedHeader).toMatchObject({ alg: "ES256", kid: "KEY9876543" });
				expect(payload).toMatchObject({ iss: "TEAM123456", sub: "com.example.web" });
			}

			const logout = await provider.endSession({
				idTokenHint: "id-1",
				postLogoutRedirectUri: "https://web.test/bye",
			});
			expect(logout.method).toBe("GET");
			expect(logout.url.href).toBe(
				"https://web.test/apple-logout?id_token_hint=id-1&post_logout_redirect_uri=https%3A%2F%2Fweb.test%2Fbye",
			);

			expect(policy.validateRedirect("https://web.test/welcome")).toEqual({ ok: true });
			expect(policy.validateRedirect("https://elsewhere.test/").ok).toBe(false);
			expect(policy.resolveCallbackRedirect({})).toEqual({ ok: true, value: "https://web.test/" });
			expect(policy.resolveCallbackRedirect({ redirectTo: "https://web.test/welcome" })).toEqual({
				ok: true,
				value: "https://web.test/auth/callback?redirect_to=https%3A%2F%2Fweb.test%2Fwelcome",
			});
		},
	);
});
