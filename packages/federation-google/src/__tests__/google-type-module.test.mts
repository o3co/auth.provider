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
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { googleEntrySchema } from "#/entry.mjs";
import {
	type GoogleProvider,
	type GoogleProviderConfig,
	googleFederationModule,
	googleFederationTypeModule,
} from "#/index.mjs";

/**
 * The module that handles every `core.federations` entry of type `google`,
 * through core's `createApp`: one provider and one redirect policy per
 * enabled entry, under the entry's name; the entry flat and held to a strict
 * schema; Google reached through the fetch the module was given; and the same
 * provider and policy as the deprecated fixed-name module builds for the same
 * entry.
 */

const GOOGLE = {
	issuer: "https://accounts.google.com",
	authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
	tokenEndpoint: "https://oauth2.googleapis.com/token",
	jwksUri: "https://www.googleapis.com/oauth2/v3/certs",
	userinfoEndpoint: "https://www.googleapis.com/oauth2/v3/userinfo",
};
const CALLBACK_A = "https://auth.test/session/oauth/federation/google-a/callback";
const CALLBACK_B = "https://auth.test/session/oauth/federation/google-b/callback";
const VERIFIER = "v".repeat(43);

const entryA = {
	enabled: true,
	type: "google",
	clientId: "client-a",
	clientSecret: "secret-a",
	callbackURL: CALLBACK_A,
	clientUrl: "https://app-a.test/",
};
const entryB = {
	enabled: true,
	type: "google",
	clientId: "client-b",
	clientSecret: "secret-b",
	callbackURL: CALLBACK_B,
	clientUrl: "https://app-b.test/",
	accessType: "online",
};

/** A fake Google: Google's own URLs, answered only through `idp.fetch`. */
const fakeGoogle = (clientId: string, sub?: string): Promise<FakeIdp> =>
	createFakeIdp({ ...GOOGLE, clientId, ...(sub !== undefined ? { sub } : {}) });

function configWith(federations: Record<string, unknown>): AppConfig {
	const base = makeValidAppConfig();
	return {
		...base,
		// supertest speaks plain http; a Secure cookie would never come back.
		"session-store": { ...base["session-store"], name: "auth.sid", secure: false },
		...coreConfigForTests({ declaredAbsent: ["auditSink"], federations: federations as never }),
	} as unknown as AppConfig;
}

// Requires both projections, so the boot planner materialises them into
// `handle.components`.
const activatorModule = defineModule({
	name: "test-google-activator",
	requires: ["federationProviders", "federationRedirectPolicyResolver"] as never,
	contributes: {
		routes: [
			{
				mountPath: "/__test_google_noop__",
				id: "test-google-noop",
				handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
			},
		],
	},
});

/** Supplies the deprecated module's slot, as a composition root's bridge does. */
const slotModule = (config: GoogleProviderConfig): Module =>
	defineModule({
		name: "test:google-federation-config",
		provides: { googleFederationConfig: () => config },
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
			googleFederationTypeModule(options.fetch ? { fetch: options.fetch } : {}),
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

const authorize = (provider: FederationProvider | undefined, redirectUri: string): URL => {
	if (provider === undefined) return expect.fail("no provider");
	return provider.buildAuthorizationUrl({
		redirectUri,
		state: "state-1",
		codeVerifier: VERIFIER,
		nonce: "nonce-1",
	});
};

describe("googleFederationTypeModule", () => {
	it("contributes the type google, and requires no dependency — the whole config least of all", () => {
		const module = googleFederationTypeModule();
		expect(module.name).toBe("federation-google-type");
		expect(module.requires ?? []).toEqual([]);
		expect(module.optional ?? []).toEqual([]);
		const contributes = module.contributes as Record<string, Record<string, unknown>>;
		expect(Object.keys(contributes)).toEqual(["federationTypes"]);
		expect(Object.keys(contributes.federationTypes ?? {})).toEqual(["google"]);
	});
});

describe("googleFederationTypeModule through createApp", () => {
	it("builds one provider and one redirect policy per enabled entry of type google, under the entry's name", async () => {
		const { handle } = await boot({
			"google-a": entryA,
			"google-b": entryB,
			// Not read: a disabled entry is neither parsed nor built.
			off: { enabled: false, type: "google", bogus: true },
		});

		const providers = providersOf(handle);
		expect([...providers.keys()].sort()).toEqual(["google-a", "google-b"]);
		expect(providers.get("google-a")?.name).toBe("google-a");
		expect(providers.get("google-b")?.name).toBe("google-b");
		expect([...policiesOf(handle).keys()].sort()).toEqual(["google-a", "google-b"]);

		// Each provider sends the browser to Google with its own client and its own access type.
		const urlA = authorize(providers.get("google-a"), CALLBACK_A);
		const urlB = authorize(providers.get("google-b"), CALLBACK_B);
		expect(`${urlA.origin}${urlA.pathname}`).toBe(GOOGLE.authorizationEndpoint);
		expect(urlA.searchParams.get("client_id")).toBe("client-a");
		expect(urlA.searchParams.get("access_type")).toBe("offline");
		expect(urlB.searchParams.get("client_id")).toBe("client-b");
		expect(urlB.searchParams.get("access_type")).toBeNull();

		// Each policy is its own entry's.
		expect(policiesOf(handle).get("google-a")?.resolveCallbackRedirect({})).toEqual({
			ok: true,
			value: "https://app-a.test/",
		});
		expect(policiesOf(handle).get("google-b")?.resolveCallbackRedirect({})).toEqual({
			ok: true,
			value: "https://app-b.test/",
		});
	});

	it("boots with nothing to build when the only google entry is disabled, however malformed", async () => {
		const { handle } = await boot({
			google: { enabled: false, type: "google", clientId: 42, nested: { clientSecret: [] } },
		});
		expect([...providersOf(handle).keys()]).toEqual([]);
	});

	it("logs in through the session routes: the entry's callback, the module's fetch to Google, the entry's redirect policy", async () => {
		const idp = await fakeGoogle("client-b", "google-sub-b");
		const { app, repo } = await boot(
			{ "google-a": entryA, "google-b": entryB },
			{
				fetch: idp.fetch,
				authenticateByToken: async (token) =>
					token === "google-b:google-sub-b" ? { id: "user-b", username: "bob" } : null,
			},
		);

		const agent = request.agent(app);
		const start = await agent.get("/session/oauth/federation/google-b");
		expect(start.status).toBe(302);
		const authUrl = new URL(start.headers.location ?? "");
		expect(`${authUrl.origin}${authUrl.pathname}`).toBe(GOOGLE.authorizationEndpoint);
		expect(authUrl.searchParams.get("redirect_uri")).toBe(CALLBACK_B);
		const { code, state, iss } = idp.authorize(authUrl);

		const cb = await agent
			.get("/session/oauth/federation/google-b/callback")
			.query({ code, state, iss });
		expect(cb.status).toBe(302);
		// The redirect policy built from the entry: its clientUrl.
		expect(cb.headers.location).toBe("https://app-b.test/");
		expect(repo.authenticateByToken).toHaveBeenCalledWith("google-b:google-sub-b");
		// Token, JWKS and UserInfo all went through the module's fetch.
		expect(idp.requestsTo(GOOGLE.tokenEndpoint)).toHaveLength(1);
		expect(idp.lastTokenRequest()?.body?.get("redirect_uri")).toBe(CALLBACK_B);
		expect(idp.lastTokenRequest()?.body?.get("client_id")).toBe("client-b");
		expect(idp.lastTokenRequest()?.body?.get("client_secret")).toBe("secret-b");
		expect(idp.requestsTo(GOOGLE.jwksUri)).toHaveLength(1);
		expect(idp.requestsTo(GOOGLE.userinfoEndpoint)).toHaveLength(1);
	});

	it("refuses a key the type does not read, at the entry's path", async () => {
		const err = await refusal(boot({ "google-a": { ...entryA, clientSecrte: "typo" } }));
		expect(err.reason).toBe("config-validation-failed");
		expect(issuePaths(err)).toContain("core.federations.google-a");
		expect(err.message).toMatch(/core\.federations\.google-a: .*"clientSecrte"/);
	});

	it("refuses jwksUri: Google's key set is not the configuration's to move", async () => {
		const err = await refusal(boot({ "google-a": { ...entryA, jwksUri: "https://evil.test/k" } }));
		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toMatch(/core\.federations\.google-a: .*"jwksUri"/);
	});

	it("refuses the nested google { … } shape: an entry is flat", async () => {
		const { clientId, clientSecret, callbackURL, ...outer } = entryA;
		const err = await refusal(
			boot({ "google-a": { ...outer, google: { clientId, clientSecret, callbackURL } } }),
		);
		expect(err.reason).toBe("config-validation-failed");
		const paths = issuePaths(err);
		expect(paths).toContain("core.federations.google-a.callbackURL");
		expect(paths).toContain("core.federations.google-a.clientId");
		expect(paths).toContain("core.federations.google-a.clientSecret");
		expect(err.message).toMatch(/core\.federations\.google-a: .*"google"/);
		expect(err.message).toMatch(/a dispatched entry is flat/);
	});

	it.each([
		["clientId", "core.federations.google-a.clientId"],
		["clientSecret", "core.federations.google-a.clientSecret"],
		["callbackURL", "core.federations.google-a.callbackURL"],
	])("refuses an entry without %s, at its path", async (key, path) => {
		const { [key as keyof typeof entryA]: _dropped, ...entry } = entryA;
		const err = await refusal(boot({ "google-a": entry }));
		expect(err.reason).toBe("config-validation-failed");
		expect(issuePaths(err)).toEqual([path]);
	});

	it.each([
		["clientId", ""],
		["clientSecret", ""],
		["clientId", null],
	])("refuses %s written as %j, at its path", async (key, value) => {
		const err = await refusal(boot({ "google-a": { ...entryA, [key]: value } }));
		expect(err.reason).toBe("config-validation-failed");
		expect(issuePaths(err)).toEqual([`core.federations.google-a.${key}`]);
	});

	it.each([
		["redirectAllowlist", "https://app-a.test/welcome"],
		["redirectAllowlist", [42]],
		["sessionDomain", 42],
		["authCallbackUrl", true],
		["clientUrl", ["https://app-a.test/"]],
		["endSessionEndpoint", 1],
		["requireAuthorizationResponseIss", "yes"],
		["requireAuthorizationResponseIss", ""],
		["accessType", "Offline"],
		["accessType", false],
	])("refuses %s of the wrong shape (%j), at its path", async (key, value) => {
		const err = await refusal(boot({ "google-a": { ...entryA, [key]: value } }));
		expect(err.reason).toBe("config-validation-failed");
		expect(
			issuePaths(err).every((path) => path.startsWith(`core.federations.google-a.${key}`)),
		).toBe(true);
		expect(issuePaths(err).length).toBeGreaterThan(0);
	});

	describe("a refusal never quotes the client secret", () => {
		const SECRET = "s3cret-that-must-not-be-echoed";
		const cases: readonly (readonly [string, Record<string, unknown>])[] = [
			["a clientSecret of the wrong type", { ...entryA, clientSecret: [SECRET] }],
			["a clientSecret written as an object", { ...entryA, clientSecret: { value: SECRET } }],
			["the secret under a misspelt key", { ...entryA, clientSecrte: SECRET }],
			["the secret nested under the type", { ...entryA, google: { clientSecret: SECRET } }],
			["another key wrong beside it", { ...entryA, clientSecret: SECRET, accessType: "never" }],
		];

		it.each(cases)("at boot: %s", async (_what, entry) => {
			const err = await refusal(boot({ "google-a": entry }));
			expect(err.reason).toBe("config-validation-failed");
			expect(err.message).not.toContain(SECRET);
			expect(JSON.stringify(err.details)).not.toContain(SECRET);
		});
	});

	it("refuses the deprecated module beside it for the same entry: one federation has one handler", async () => {
		const idp = await fakeGoogle("client-a");
		const err = await refusal(
			boot(
				{ google: entryA },
				{
					federationModules: [
						googleFederationTypeModule({ fetch: idp.fetch }),
						googleFederationModule,
						slotModule({ clientId: "client-a", clientSecret: "secret-a", callbackURL: CALLBACK_A }),
					],
				},
			),
		);
		expect(err.reason).toBe("duplicate-contribute");
		expect(err.message).toMatch(/"federation-google-type"/);
		expect(err.message).toMatch(/"federation-google"/);
	});
});

describe("googleEntrySchema", () => {
	const own = { clientId: "client-a", clientSecret: "secret-a" };

	it("reads requireAuthorizationResponseIss as a boolean, or as an environment variable spells one", () => {
		const read = (value: unknown) =>
			googleEntrySchema.parse({ ...own, requireAuthorizationResponseIss: value })
				.requireAuthorizationResponseIss;
		for (const value of [true, "true", "TRUE", " 1 ", "1"]) expect(read(value)).toBe(true);
		for (const value of [false, "false", "False", "0", " false "]) expect(read(value)).toBe(false);
	});

	it("reads a key written null as absent, and fills in no default", () => {
		expect(
			googleEntrySchema.parse({
				...own,
				redirectAllowlist: null,
				sessionDomain: null,
				accessType: null,
				requireAuthorizationResponseIss: null,
			}),
		).toEqual(own);
	});
});

describe("googleFederationTypeModule — parity with the deprecated module", () => {
	const options = {
		redirectAllowlist: ["https://app-a.test/welcome"],
		sessionDomain: "app-a.test",
		authCallbackUrl: "https://app-a.test/auth/callback",
		endSessionEndpoint: "https://accounts.google.test/logout",
	};
	const entries: readonly (readonly [string, Record<string, unknown>])[] = [
		["the defaults", { ...entryA }],
		["online access", { ...entryA, accessType: "online" }],
		[
			"every key",
			{ ...entryA, ...options, accessType: "offline", requireAuthorizationResponseIss: false },
		],
	];

	/** The provider and the policy one module builds for `google` from `entry`, against a fresh fake Google. */
	async function built(path: "deprecated" | "type", entry: Record<string, unknown>) {
		const idp = await fakeGoogle("client-a", "google-sub-a");
		const { enabled: _on, type: _type, ...slot } = entry;
		const { handle } = await boot(
			{ google: entry },
			{
				federationModules:
					path === "type"
						? [googleFederationTypeModule({ fetch: idp.fetch })]
						: [
								googleFederationModule,
								slotModule({ ...(slot as unknown as GoogleProviderConfig), fetch: idp.fetch }),
							],
			},
		);
		const provider = providersOf(handle).get("google") as GoogleProvider | undefined;
		const policy = policiesOf(handle).get("google");
		if (provider === undefined || policy === undefined) {
			return expect.fail(`the ${path} module built no provider or no policy for google`);
		}
		return { idp, provider, policy };
	}

	it.each(entries)(
		"builds the same provider and the same redirect policy from one entry (%s)",
		async (_what, entry) => {
			const deprecated = await built("deprecated", entry);
			const type = await built("type", entry);

			expect(type.provider.name).toBe("google");
			expect(type.provider.name).toBe(deprecated.provider.name);
			expect(type.provider.scope).toEqual(deprecated.provider.scope);
			expect(Object.keys(type.provider).sort()).toEqual(Object.keys(deprecated.provider).sort());
			expect(authorize(type.provider, CALLBACK_A).href).toBe(
				authorize(deprecated.provider, CALLBACK_A).href,
			);

			const exchange = async ({ idp, provider }: Awaited<ReturnType<typeof built>>) => {
				const url = authorize(provider, CALLBACK_A);
				const { code } = idp.authorize(url);
				// No `iss` on the callback: refused unless the entry turned the requirement off.
				const outcome = await provider
					.exchangeCode({
						code,
						codeVerifier: VERIFIER,
						redirectUri: CALLBACK_A,
						nonce: "nonce-1",
						callbackParams: {},
					})
					.then(
						(profile) => ({ sub: profile.sub, issuer: profile.issuer, email: profile.email }),
						(err: Error) => ({ refused: err.name }),
					);
				const token = idp.lastTokenRequest();
				return {
					outcome,
					authorization: token?.headers.get("authorization"),
					body: Object.fromEntries(token?.body ?? []),
				};
			};
			const exchanged = await exchange(type);
			expect(exchanged).toEqual(await exchange(deprecated));
			if (entry.requireAuthorizationResponseIss === false) {
				expect(exchanged.outcome).toEqual({
					sub: "google-sub-a",
					issuer: GOOGLE.issuer,
					email: "alice@example.test",
				});
				expect(exchanged.body.client_secret).toBe("secret-a");
			} else {
				// Refused before the token request: the callback carries no `iss`.
				expect(exchanged.outcome).toEqual({ refused: expect.any(String) });
				expect(exchanged.body).toEqual({});
			}

			const endSession = (provider: GoogleProvider) =>
				provider.endSession({ postLogoutRedirectUri: "https://app-a.test/bye", state: "s" });
			expect((await endSession(type.provider)).url.href).toBe(
				(await endSession(deprecated.provider)).url.href,
			);

			for (const url of ["https://app-a.test/welcome", "https://elsewhere.test/"]) {
				expect(type.policy.validateRedirect(url)).toEqual(deprecated.policy.validateRedirect(url));
			}
			for (const session of [{}, { redirectTo: "https://app-a.test/welcome" }]) {
				expect(type.policy.resolveCallbackRedirect(session)).toEqual(
					deprecated.policy.resolveCallbackRedirect(session),
				);
			}
		},
	);
});
