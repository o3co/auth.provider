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
import {
	oidcFederationModule,
	oidcFederationTypeModule,
	readOidcFederationConfigs,
} from "#/index.mjs";
import { createFakeIdp, type FakeIdp } from "./helpers.mjs";

/**
 * The module that handles every `core.federations` entry of type `oidc`,
 * through core's `createApp`: one provider and one redirect policy per
 * enabled entry, under the entry's name; the entry flat and held to a strict
 * schema; the upstream reached through the fetch the module was given; and
 * the same provider and policy as the per-instance module builds for the
 * same entry.
 */

const ISSUER_A = "https://idp-a.test";
const ISSUER_B = "https://idp-b.test/realms/b";
const CALLBACK_A = "https://auth.test/session/oauth/federation/idp-a/callback";
const CALLBACK_B = "https://auth.test/session/oauth/federation/idp-b/callback";

const entryA = {
	enabled: true,
	type: "oidc",
	issuer: ISSUER_A,
	clientId: "client-a",
	clientSecret: "secret-a",
	callbackURL: CALLBACK_A,
	clientUrl: "https://app-a.test/",
};
const entryB = {
	enabled: true,
	type: "oidc",
	issuer: ISSUER_B,
	clientId: "client-b",
	clientSecret: "secret-b",
	callbackURL: CALLBACK_B,
	clientUrl: "https://app-b.test/",
};

/** One fetch in front of several fake IdPs, each answering the URLs under its issuer. */
const routedFetch =
	(...idps: readonly FakeIdp[]): typeof fetch =>
	(input, init) => {
		const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
		const idp = idps.find((candidate) => url.startsWith(`${candidate.issuer}/`));
		if (idp === undefined) throw new Error(`no fake IdP answers ${url}`);
		return idp.fetch(input, init);
	};

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
	name: "test-oidc-activator",
	requires: ["federationProviders", "federationRedirectPolicyResolver"] as never,
	contributes: {
		routes: [
			{
				mountPath: "/__test_oidc_noop__",
				id: "test-oidc-noop",
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
			oidcFederationTypeModule(options.fetch ? { fetch: options.fetch } : {}),
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

/** Start the federation, hand the IdP the transaction's nonce, return what the callback needs. */
async function startLogin(agent: ReturnType<typeof request.agent>, name: string, idp: FakeIdp) {
	const start = await agent.get(`/session/oauth/federation/${name}`);
	expect(start.status).toBe(302);
	const authUrl = new URL(start.headers.location ?? "");
	idp.nonce = authUrl.searchParams.get("nonce") ?? undefined;
	return { authUrl, state: authUrl.searchParams.get("state") ?? "" };
}

describe("oidcFederationTypeModule", () => {
	it("contributes the type oidc, and requires no dependency — the whole config least of all", () => {
		const module = oidcFederationTypeModule();
		expect(module.name).toBe("federation-oidc");
		expect(module.requires ?? []).toEqual([]);
		expect(module.optional ?? []).toEqual([]);
		const contributes = module.contributes as Record<string, Record<string, unknown>>;
		expect(Object.keys(contributes)).toEqual(["federationTypes"]);
		expect(Object.keys(contributes.federationTypes ?? {})).toEqual(["oidc"]);
	});
});

describe("oidcFederationTypeModule through createApp", () => {
	it("builds one provider and one redirect policy per enabled entry of type oidc, under the entry's name", async () => {
		const idpA = await createFakeIdp({ issuer: ISSUER_A, clientId: "client-a" });
		const idpB = await createFakeIdp({ issuer: ISSUER_B, clientId: "client-b" });

		const { handle } = await boot(
			{
				"idp-a": entryA,
				"idp-b": entryB,
				// Not read: a disabled entry is neither parsed nor built.
				off: { enabled: false, type: "oidc", bogus: true },
			},
			{ fetch: routedFetch(idpA, idpB) },
		);

		const providers = providersOf(handle);
		expect([...providers.keys()].sort()).toEqual(["idp-a", "idp-b"]);
		expect(providers.get("idp-a")?.name).toBe("idp-a");
		expect(providers.get("idp-b")?.name).toBe("idp-b");
		expect([...policiesOf(handle).keys()].sort()).toEqual(["idp-a", "idp-b"]);

		// Discovery went through the module's fetch, once per entry, at boot.
		expect(idpA.requestsTo("/.well-known/openid-configuration")).toHaveLength(1);
		expect(idpB.requestsTo("/.well-known/openid-configuration")).toHaveLength(1);

		// Each provider sends the browser to its own issuer with its own client.
		const authorize = (name: string, redirectUri: string) =>
			providers.get(name)?.buildAuthorizationUrl({
				redirectUri,
				state: "s",
				codeVerifier: "v".repeat(43),
				nonce: "n",
			});
		const urlA = authorize("idp-a", CALLBACK_A);
		const urlB = authorize("idp-b", CALLBACK_B);
		expect(urlA?.href.startsWith(`${ISSUER_A}/authorize?`)).toBe(true);
		expect(urlA?.searchParams.get("client_id")).toBe("client-a");
		expect(urlB?.href.startsWith(`${ISSUER_B}/authorize?`)).toBe(true);
		expect(urlB?.searchParams.get("client_id")).toBe("client-b");
	});

	it("logs in through the session routes: the entry's callback, the module's fetch to the token endpoint, the entry's redirect policy", async () => {
		const idpA = await createFakeIdp({ issuer: ISSUER_A, clientId: "client-a", sub: "sub-a-1" });
		const idpB = await createFakeIdp({ issuer: ISSUER_B, clientId: "client-b", sub: "sub-b-1" });
		const { app, repo } = await boot(
			{ "idp-a": entryA, "idp-b": entryB },
			{
				fetch: routedFetch(idpA, idpB),
				authenticateByToken: async (token) =>
					token === "idp-b:sub-b-1" ? { id: "user-b", username: "bob" } : null,
			},
		);

		const agent = request.agent(app);
		const { authUrl, state } = await startLogin(agent, "idp-b", idpB);
		expect(`${authUrl.origin}${authUrl.pathname}`).toBe(`${ISSUER_B}/authorize`);
		expect(authUrl.searchParams.get("redirect_uri")).toBe(CALLBACK_B);

		const cb = await agent.get(
			`/session/oauth/federation/idp-b/callback?code=code-1&state=${state}`,
		);
		expect(cb.status).toBe(302);
		// The redirect policy built from the entry: its clientUrl.
		expect(cb.headers.location).toBe("https://app-b.test/");
		expect(repo.authenticateByToken).toHaveBeenCalledWith("idp-b:sub-b-1");
		expect(idpB.lastTokenRequest()?.body?.get("redirect_uri")).toBe(CALLBACK_B);
		expect(idpA.requestsTo("/token")).toHaveLength(0);
	});

	it("refuses a key the type does not read, at the entry's path", async () => {
		const err = await refusal(boot({ "idp-a": { ...entryA, clientSecrte: "typo" } }));
		expect(err.reason).toBe("config-validation-failed");
		expect(issuePaths(err)).toContain("core.federations.idp-a");
		expect(err.message).toMatch(/core\.federations\.idp-a: .*"clientSecrte"/);
	});

	it("refuses the nested oidc { … } shape: an entry is flat", async () => {
		const { issuer, clientId, clientSecret, callbackURL, ...outer } = entryA;
		const err = await refusal(
			boot({ "idp-a": { ...outer, oidc: { issuer, clientId, clientSecret, callbackURL } } }),
		);
		expect(err.reason).toBe("config-validation-failed");
		const paths = issuePaths(err);
		expect(paths).toContain("core.federations.idp-a.callbackURL");
		expect(paths).toContain("core.federations.idp-a.issuer");
		expect(paths).toContain("core.federations.idp-a.clientId");
		expect(err.message).toMatch(/core\.federations\.idp-a: .*"oidc"/);
		expect(err.message).toMatch(/a dispatched entry is flat/);
	});

	it.each([
		["issuer", "core.federations.idp-a.issuer"],
		["clientId", "core.federations.idp-a.clientId"],
		["callbackURL", "core.federations.idp-a.callbackURL"],
	])("refuses an entry without %s, at its path", async (key, path) => {
		const { [key as keyof typeof entryA]: _dropped, ...entry } = entryA;
		const err = await refusal(boot({ "idp-a": entry }));
		expect(err.reason).toBe("config-validation-failed");
		expect(issuePaths(err)).toContain(path);
	});

	it("refuses an entry that sets neither, or both, of clientSecret and privateKey", async () => {
		const { clientSecret: _dropped, ...neither } = entryA;
		const both = { ...entryA, privateKey: "-----BEGIN PRIVATE KEY-----" };
		for (const entry of [neither, both]) {
			const err = await refusal(boot({ "idp-a": entry }));
			expect(err.reason).toBe("config-validation-failed");
			expect(issuePaths(err)).toContain("core.federations.idp-a");
			expect(err.message).toMatch(/exactly one of clientSecret[\s\S]*privateKey/);
		}
	});

	it.each([
		["scopes", "openid profile", "core.federations.idp-a.scopes"],
		["discovery", "yes", "core.federations.idp-a.discovery"],
		["userInfo", 1, "core.federations.idp-a.userInfo"],
		["clockToleranceSeconds", "10", "core.federations.idp-a.clockToleranceSeconds"],
		["endpoints", { tokenEndpont: "https://x" }, "core.federations.idp-a.endpoints"],
		["endpoints", { tokenEndpoint: 1 }, "core.federations.idp-a.endpoints.tokenEndpoint"],
		["redirectAllowlist", "https://x", "core.federations.idp-a.redirectAllowlist"],
		["sessionDomain", 42, "core.federations.idp-a.sessionDomain"],
	])("refuses %s of the wrong shape (%j), at its path", async (key, value, path) => {
		const err = await refusal(boot({ "idp-a": { ...entryA, [key]: value } }));
		expect(err.reason).toBe("config-validation-failed");
		expect(issuePaths(err)).toContain(path);
	});

	it("refuses the per-instance module beside it for the same entry: one federation has one handler", async () => {
		const idpA = await createFakeIdp({ issuer: ISSUER_A, clientId: "client-a" });
		const configs = defineModule({
			name: "test:oidc-configs",
			requires: ["config"] as const,
			provides: {
				oidcFederationConfigs: ({ config }) =>
					readOidcFederationConfigs(federationsOf(config)) as never,
			},
		});
		const err = await refusal(
			boot(
				{ "idp-a": entryA },
				{
					federationModules: [
						oidcFederationTypeModule({ fetch: idpA.fetch }),
						oidcFederationModule("idp-a"),
						configs,
					],
				},
			),
		);
		expect(err.reason).toBe("duplicate-contribute");
		expect(err.message).toMatch(/federation-oidc/);
		expect(err.message).toMatch(/federation-oidc-idp-a/);
	});
});

describe("oidcFederationTypeModule — parity with the per-instance module", () => {
	const entry = {
		...entryA,
		scopes: ["openid", "email", "groups"],
		endpoints: { authorizationEndpoint: `${ISSUER_A}/oauth2/v1/authorize` },
		userInfo: false,
		clockToleranceSeconds: 10,
		redirectAllowlist: ["https://app-a.test/welcome"],
		authCallbackUrl: "https://app-a.test/auth/callback",
	};

	/** The provider and the policy one path builds for `idp-a`, from a fresh fake IdP. */
	async function built(path: "per-instance" | "type") {
		const idp = await createFakeIdp({ issuer: ISSUER_A, clientId: "client-a", sub: "sub-a-1" });
		const configs = defineModule({
			name: "test:oidc-configs",
			requires: ["config"] as const,
			provides: {
				oidcFederationConfigs: ({ config }) => {
					const read = readOidcFederationConfigs(federationsOf(config));
					return { "idp-a": { ...read["idp-a"], fetch: idp.fetch } } as never;
				},
			},
		});
		const { handle } = await boot(
			{ "idp-a": entry },
			{
				federationModules:
					path === "type"
						? [oidcFederationTypeModule({ fetch: idp.fetch })]
						: [oidcFederationModule("idp-a"), configs],
			},
		);
		const provider = providersOf(handle).get("idp-a");
		const policy = policiesOf(handle).get("idp-a");
		if (provider === undefined || policy === undefined) {
			return expect.fail(`the ${path} path built no provider or no policy for idp-a`);
		}
		return { idp, provider, policy };
	}

	it("reads every key of an entry as the deprecated reader does", () => {
		const declaration = (
			oidcFederationTypeModule().contributes as {
				federationTypes: Record<string, { entrySchema: { parse(value: unknown): unknown } }>;
			}
		).federationTypes.oidc;
		const { clientSecret: _secret, ...withoutSecret } = entryA;
		const entries = [
			{
				...entryA,
				scopes: ["openid", "groups"],
				discovery: "false",
				endpoints: {
					authorizationEndpoint: `${ISSUER_A}/authorize`,
					tokenEndpoint: `${ISSUER_A}/token`,
					jwksUri: `${ISSUER_A}/jwks`,
					userinfoEndpoint: null,
				},
				idTokenSignedResponseAlg: "RS256",
				userInfo: "true",
				clockToleranceSeconds: 10,
				redirectAllowlist: ["https://app-a.test/welcome"],
				sessionDomain: "app-a.test",
				authCallbackUrl: "https://app-a.test/auth/callback",
			},
			{
				...withoutSecret,
				privateKey: { pem: "-----BEGIN PRIVATE KEY-----", kid: "k1", alg: null },
			},
		];
		for (const { enabled: _on, type: _type, callbackURL, ...own } of entries) {
			const deprecated = readOidcFederationConfigs({
				"idp-a": { enabled: true, type: "oidc", callbackURL, ...own },
			})["idp-a"];
			expect({ ...(declaration?.entrySchema.parse(own) as object), callbackURL }).toEqual(
				deprecated,
			);
		}
	});

	it("builds the same provider and the same redirect policy from one entry", async () => {
		const perInstance = await built("per-instance");
		const type = await built("type");

		expect(type.provider.name).toBe(perInstance.provider.name);
		expect(type.provider.scope).toEqual(perInstance.provider.scope);
		expect(Object.keys(type.provider).sort()).toEqual(Object.keys(perInstance.provider).sort());

		const authorize = (provider: FederationProvider) =>
			provider.buildAuthorizationUrl({
				redirectUri: CALLBACK_A,
				state: "state-1",
				codeVerifier: "v".repeat(43),
				nonce: "nonce-1",
			}).href;
		expect(authorize(type.provider)).toBe(authorize(perInstance.provider));

		const exchange = async ({ idp, provider }: Awaited<ReturnType<typeof built>>) => {
			idp.nonce = "nonce-1";
			const profile = await provider.exchangeCode({
				code: "code-1",
				codeVerifier: "v".repeat(43),
				redirectUri: CALLBACK_A,
				nonce: "nonce-1",
			});
			const token = idp.lastTokenRequest();
			return {
				issuer: profile.issuer,
				sub: profile.sub,
				userinfoCalls: idp.requestsTo("/userinfo").length,
				authorization: token?.headers.get("authorization"),
				body: Object.fromEntries(token?.body ?? []),
			};
		};
		expect(await exchange(type)).toEqual(await exchange(perInstance));

		for (const url of ["https://app-a.test/welcome", "https://elsewhere.test/"]) {
			expect(type.policy.validateRedirect(url)).toEqual(perInstance.policy.validateRedirect(url));
		}
		for (const session of [{}, { redirectTo: "https://app-a.test/welcome" }]) {
			expect(type.policy.resolveCallbackRedirect(session)).toEqual(
				perInstance.policy.resolveCallbackRedirect(session),
			);
		}
	});
});
