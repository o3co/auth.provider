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
 * The module that handles every `core.federations` entry of type `github`,
 * through core's `createApp`: one provider and one redirect policy per
 * enabled entry, under the entry's name; the entry flat and held to a strict
 * schema; GitHub reached through the fetch the module was given; and every
 * key of the entry carried to the provider and its redirect policy.
 */

import {
	type AppConfig,
	type AppHandle,
	BootError,
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
	makeValidAppConfig,
	renamedVariableCaptures,
} from "@o3co/auth-provider-core/testing";
import {
	type FederationRedirectPolicy,
	sessionModule,
	sessionStoreModule,
} from "@o3co/auth-provider-session";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	GITHUB_FEDERATION_TYPE,
	type GithubProvider,
	githubFederationTypeModule,
} from "#/index.mjs";
import { createFakeGithub, type FakeGithub, GITHUB } from "./fake-github.mjs";

const CALLBACK_WORK = "https://auth.test/session/oauth/federation/github-work/callback";
const CALLBACK_OSS = "https://auth.test/session/oauth/federation/github-oss/callback";
const VERIFIER = "verifier-0123456789-abcdef-0123456789-abcdef-0123456789abcdef";
/** The `id` the fake GitHub's `/user` answers. */
const GITHUB_ID = "12345";

const entryWork = {
	enabled: true,
	type: "github",
	clientId: "client-work",
	clientSecret: "secret-work",
	callbackURL: CALLBACK_WORK,
	clientUrl: "https://work.test/",
};
const entryOss = {
	enabled: true,
	type: "github",
	clientId: "client-oss",
	clientSecret: "secret-oss",
	callbackURL: CALLBACK_OSS,
	clientUrl: "https://oss.test/",
};

/**
 * The fake reaches the adapter only through the module's `fetch`. The global
 * fetch is a tripwire, so a request that does not go through the option fails
 * instead of calling GitHub.
 */
const refuseNetwork = async (): Promise<Response> => {
	throw new Error(
		"the global fetch must not be reached — the module's fetch carries every request",
	);
};

let github: FakeGithub;
beforeEach(() => {
	github = createFakeGithub();
	vi.stubGlobal("fetch", refuseNetwork);
});

const handles: AppHandle[] = [];
afterEach(async () => {
	for (const handle of handles.splice(0)) await handle.dispose();
	vi.unstubAllGlobals();
});

function configWith(federations: Record<string, unknown>): AppConfig {
	const base = makeValidAppConfig();
	return {
		...base,
		// supertest speaks plain http; a Secure cookie would never come back.
		"session-store": { ...base["session-store"], name: "auth.sid", secure: false },
		...coreConfigForTests({
			declaredAbsent: ["auditSink", "rateLimiter"],
			federations: federations as never,
		}),
	} as unknown as AppConfig;
}

// Requires both projections, so the boot planner materialises them into
// `handle.components`.
const activatorModule = defineModule({
	name: "test-github-activator",
	requires: ["federationProviders", "federationRedirectPolicyResolver"] as never,
	contributes: {
		routes: [
			{
				mountPath: "/__test_github_noop__",
				id: "test-github-noop",
				handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
			},
		],
	},
});

interface BootOptions {
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
		githubFederationTypeModule({ fetch: github.fetch }),
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

/** The form body of the last request to GitHub's token endpoint. */
const lastTokenBody = (): Record<string, string> =>
	Object.fromEntries(github.requestsTo(GITHUB.tokenEndpoint).at(-1)?.body ?? []);

describe("githubFederationTypeModule", () => {
	it("contributes the type github, and requires no dependency — the whole config least of all", () => {
		const module = githubFederationTypeModule();
		expect(GITHUB_FEDERATION_TYPE).toBe("github");
		expect(module.name).toBe("federation-github-type");
		expect(module.requires ?? []).toEqual([]);
		expect(module.optional ?? []).toEqual([]);
		const contributes = module.contributes as Record<string, Record<string, unknown>>;
		expect(Object.keys(contributes)).toEqual(["federationTypes"]);
		expect(Object.keys(contributes.federationTypes ?? {})).toEqual(["github"]);
	});
});

describe("githubFederationTypeModule through createApp", () => {
	it("builds one provider and one redirect policy per enabled entry of type github, under the entry's name", async () => {
		const { handle } = await boot({
			"github-work": entryWork,
			"github-oss": entryOss,
			// Not read: a disabled entry is neither parsed nor built.
			off: { enabled: false, type: "github", bogus: true },
		});

		const providers = providersOf(handle);
		expect([...providers.keys()].sort()).toEqual(["github-oss", "github-work"]);
		expect(providers.get("github-work")?.name).toBe("github-work");
		expect(providers.get("github-oss")?.name).toBe("github-oss");
		expect([...policiesOf(handle).keys()].sort()).toEqual(["github-oss", "github-work"]);

		// Each provider sends the browser to GitHub with its own client.
		const authorize = (name: string, redirectUri: string) =>
			providers.get(name)?.buildAuthorizationUrl({
				redirectUri,
				state: "s",
				codeVerifier: VERIFIER,
				nonce: "n",
			});
		const urlWork = authorize("github-work", CALLBACK_WORK);
		const urlOss = authorize("github-oss", CALLBACK_OSS);
		expect(`${urlWork?.origin}${urlWork?.pathname}`).toBe(GITHUB.authorizationEndpoint);
		expect(urlWork?.searchParams.get("client_id")).toBe("client-work");
		expect(urlOss?.searchParams.get("client_id")).toBe("client-oss");
	});

	it("logs in through the session routes: the entry's callback, its client at the token endpoint through the module's fetch, its identity prefix and redirect policy", async () => {
		const { app, repo } = await boot(
			{ "github-work": entryWork, "github-oss": entryOss },
			{
				authenticateByToken: async (token) =>
					token === `github-oss:${GITHUB_ID}` ? { id: "user-oss", username: "octocat" } : null,
			},
		);

		const agent = request.agent(app);
		const start = await agent.get("/session/oauth/federation/github-oss");
		expect(start.status).toBe(302);
		const authUrl = new URL(start.headers.location ?? "");
		expect(`${authUrl.origin}${authUrl.pathname}`).toBe(GITHUB.authorizationEndpoint);
		expect(authUrl.searchParams.get("client_id")).toBe("client-oss");
		expect(authUrl.searchParams.get("redirect_uri")).toBe(CALLBACK_OSS);
		const state = authUrl.searchParams.get("state") ?? "";

		const cb = await agent.get(
			`/session/oauth/federation/github-oss/callback?code=code-1&state=${state}`,
		);
		expect(cb.status).toBe(302);
		// The redirect policy built from the entry: its clientUrl.
		expect(cb.headers.location).toBe("https://oss.test/");
		expect(repo.authenticateByToken).toHaveBeenCalledWith(`github-oss:${GITHUB_ID}`);

		// The token exchange, /user and /user/emails all went through the fake.
		expect(github.requestsTo(GITHUB.tokenEndpoint)).toHaveLength(1);
		expect(github.requestsTo(GITHUB.user)).toHaveLength(1);
		expect(github.requestsTo(GITHUB.emails)).toHaveLength(1);
		expect(lastTokenBody()).toMatchObject({
			client_id: "client-oss",
			client_secret: "secret-oss",
			redirect_uri: CALLBACK_OSS,
			code: "code-1",
		});
	});

	it("names the entry in a provider's refusal", async () => {
		github.user = { ...github.user, body: { login: "octocat" } };
		const { handle } = await boot({ "github-work": entryWork });
		const provider = providersOf(handle).get("github-work");
		await expect(
			provider?.exchangeCode({
				code: "code-1",
				codeVerifier: VERIFIER,
				redirectUri: CALLBACK_WORK,
				nonce: "n",
			}),
		).rejects.toThrow(/GitHub federation "github-work" received a \/user without id\/sub/);
	});

	it("reads a key written null as absent", async () => {
		const { handle } = await boot({
			"github-work": {
				...entryWork,
				redirectAllowlist: null,
				sessionDomain: null,
				authCallbackUrl: null,
				endSessionEndpoint: null,
			},
		});
		const provider = providersOf(handle).get("github-work") as GithubProvider;
		// No endSessionEndpoint: GitHub's own logout.
		const ended = await provider.endSession({});
		expect(ended.url.href).toBe("https://github.com/logout");
		expect(policiesOf(handle).get("github-work")?.validateRedirect("https://work.test/x").ok).toBe(
			false,
		);
	});

	it("refuses a key the type does not read, at the entry's path", async () => {
		const err = await refusal(boot({ "github-work": { ...entryWork, clientSecrte: "typo" } }));
		expect(err.reason).toBe("config-validation-failed");
		expect(issuePaths(err)).toContain("core.federations.github-work");
		expect(err.message).toMatch(/core\.federations\.github-work: .*"clientSecrte"/);
	});

	it("refuses the nested github { … } shape: an entry is flat", async () => {
		const { clientId, clientSecret, callbackURL, ...outer } = entryWork;
		const err = await refusal(
			boot({ "github-work": { ...outer, github: { clientId, clientSecret, callbackURL } } }),
		);
		expect(err.reason).toBe("config-validation-failed");
		const paths = issuePaths(err);
		expect(paths).toContain("core.federations.github-work.callbackURL");
		expect(paths).toContain("core.federations.github-work.clientId");
		expect(paths).toContain("core.federations.github-work.clientSecret");
		expect(err.message).toMatch(/core\.federations\.github-work: .*"github"/);
		expect(err.message).toMatch(/a dispatched entry is flat/);
	});

	it.each([
		["clientId", undefined, "core.federations.github-work.clientId"],
		["clientSecret", undefined, "core.federations.github-work.clientSecret"],
		["callbackURL", undefined, "core.federations.github-work.callbackURL"],
		["clientId", "", "core.federations.github-work.clientId"],
		["clientSecret", "", "core.federations.github-work.clientSecret"],
	])("refuses an entry without %s (%j), at its path", async (key, value, path) => {
		const { [key as keyof typeof entryWork]: _dropped, ...rest } = entryWork;
		const entry = value === undefined ? rest : { ...rest, [key]: value };
		const err = await refusal(boot({ "github-work": entry }));
		expect(err.reason).toBe("config-validation-failed");
		expect(issuePaths(err)).toContain(path);
	});

	it.each([
		["clientId", 42, "core.federations.github-work.clientId"],
		["redirectAllowlist", "https://work.test/x", "core.federations.github-work.redirectAllowlist"],
		["redirectAllowlist", [1], "core.federations.github-work.redirectAllowlist.0"],
		["sessionDomain", 42, "core.federations.github-work.sessionDomain"],
		["authCallbackUrl", ["https://x"], "core.federations.github-work.authCallbackUrl"],
		["clientUrl", { href: "https://x" }, "core.federations.github-work.clientUrl"],
		["endSessionEndpoint", true, "core.federations.github-work.endSessionEndpoint"],
	])("refuses %s of the wrong shape (%j), at its path", async (key, value, path) => {
		const err = await refusal(boot({ "github-work": { ...entryWork, [key]: value } }));
		expect(err.reason).toBe("config-validation-failed");
		expect(issuePaths(err)).toEqual([path]);
	});

	describe("a refusal never quotes the client secret", () => {
		const SECRET = "s3cret-that-must-not-be-echoed";
		const cases: readonly (readonly [string, Record<string, unknown>])[] = [
			["a clientSecret in a list", { ...entryWork, clientSecret: [SECRET] }],
			["a clientSecret in an object", { ...entryWork, clientSecret: { value: SECRET } }],
			["the secret under a misspelt key", { ...entryWork, client_secret: SECRET }],
			["the secret beside a wrong clientId", { ...entryWork, clientSecret: SECRET, clientId: 7 }],
			[
				"the secret nested under the type",
				{ enabled: true, type: "github", github: { clientSecret: SECRET } },
			],
		];

		it.each(cases)("at boot: %s", async (_what, entry) => {
			const err = await refusal(boot({ "github-work": entry }));
			expect(err.reason).toBe("config-validation-failed");
			expect(err.message).not.toContain(SECRET);
			expect(JSON.stringify(err.details)).not.toContain(SECRET);
		});
	});
});

describe("githubFederationTypeModule — every key of the entry", () => {
	const CALLBACK = "https://auth.test/session/oauth/federation/github/callback";
	const entry = {
		enabled: true,
		type: "github",
		clientId: "client-a",
		clientSecret: "secret-a",
		callbackURL: CALLBACK,
		redirectAllowlist: ["https://app.test/welcome"],
		sessionDomain: "app.test",
		authCallbackUrl: "https://app.test/auth/callback",
		clientUrl: "https://app.test/",
		endSessionEndpoint: "https://logout.test/end",
	};

	it("reaches the provider and its redirect policy", async () => {
		const { handle } = await boot({ github: entry });
		const provider = providersOf(handle).get("github") as GithubProvider;
		const policy = policiesOf(handle).get("github");

		// The provider: the entry's client, callback and logout endpoint.
		const url = provider.buildAuthorizationUrl({
			redirectUri: CALLBACK,
			state: "state-1",
			codeVerifier: VERIFIER,
			nonce: "nonce-1",
		});
		expect(url.searchParams.get("client_id")).toBe("client-a");
		expect(url.searchParams.get("redirect_uri")).toBe(CALLBACK);
		await provider.exchangeCode({
			code: "code-1",
			codeVerifier: VERIFIER,
			redirectUri: CALLBACK,
			nonce: "nonce-1",
		});
		expect(lastTokenBody()).toMatchObject({
			client_id: "client-a",
			client_secret: "secret-a",
			redirect_uri: CALLBACK,
		});
		const ended = await provider.endSession({
			postLogoutRedirectUri: "https://app.test/bye",
			state: "st",
		});
		expect(ended.url.href).toBe(
			"https://logout.test/end?post_logout_redirect_uri=https%3A%2F%2Fapp.test%2Fbye&state=st",
		);

		// The policy: the entry's allowlist, authCallbackUrl and clientUrl.
		expect(policy?.validateRedirect("https://app.test/welcome")).toEqual({
			ok: true,
			value: undefined,
		});
		expect(policy?.validateRedirect("https://elsewhere.test/")).toMatchObject({
			ok: false,
			status: 400,
			error: "invalid_redirect",
		});
		expect(policy?.resolveCallbackRedirect({})).toEqual({ ok: true, value: "https://app.test/" });
		expect(policy?.resolveCallbackRedirect({ redirectTo: "https://app.test/welcome" })).toEqual({
			ok: true,
			value: "https://app.test/auth/callback?redirect_to=https%3A%2F%2Fapp.test%2Fwelcome",
		});
	});

	it("holds the allowlist to the entry's sessionDomain", async () => {
		await expect(
			boot({ github: { ...entry, redirectAllowlist: ["https://elsewhere.test/welcome"] } }),
		).rejects.toThrow(/redirectAllowlist\[0\].*outside-session-domain/);
	});
});
