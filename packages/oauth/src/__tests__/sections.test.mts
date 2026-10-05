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
 * The package's sections: the consent page and the Client ID Metadata
 * Documents in the oauth module's `oauth {}`, the session grant's switch at
 * `oauth-session.enabled` and the other grants' under
 * `oauth-authorization.grants`, with their defaults in the package's
 * `config/reference.conf`. A path they moved from refuses boot naming the new
 * one, a variable renamed with them refuses boot unless its new name carries
 * the same value, and the authorization-code grant's `pkce` block, and its
 * variable, refuse boot as removed.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
	type AppConfig,
	BootError,
	createApp,
	createSymmetricKeyStore,
	defineModule,
	InMemoryClientRepository,
	type Module,
	moduleReferences,
} from "@o3co/auth-provider-core";
import {
	makeValidAppConfig,
	packageReferenceProblems,
	sectionStrictnessProblems,
} from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { oauthEndpointsModule, oauthSectionSchema } from "#/module.mjs";
import { oauthAuthorizationModule } from "#/oauthAuthorization.mjs";
import { oauthSessionConfigSchema, oauthSessionGrantModule } from "#/oauthSession.mjs";
import { capturing, type GrantSwitches, withGrants } from "./_helpers/sections.mjs";

/** The package's defaults, as a composition root finds them. */
const REFERENCE = new URL("../../config/reference.conf", import.meta.url);

const MARKER = "__OAUTH_REFERENCE_MARKER__";

/** Every path in `tree` whose value is the marker. */
function markedPaths(tree: unknown, prefix = ""): string[] {
	if (typeof tree === "object" && tree !== null && !Array.isArray(tree)) {
		return Object.entries(tree).flatMap(([key, value]) =>
			markedPaths(value, prefix === "" ? key : `${prefix}.${key}`),
		);
	}
	return tree === MARKER ? [prefix] : [];
}

/** Each path the file binds a variable at, as `VARIABLE at path`. */
function bindings(): string[] {
	const file = fileURLToPath(REFERENCE);
	const variables = [
		...new Set(
			[...readFileSync(file, "utf8").matchAll(/\$\{\??([A-Za-z0-9_]+)\}/g)].map((match) =>
				String(match[1]),
			),
		),
	];
	return variables.flatMap((variable) =>
		markedPaths(parseFile(file, { env: { [variable]: MARKER } }).toObject()).map(
			(path) => `${variable} at ${path}`,
		),
	);
}

/** The package's modules, built over a configuration that turns every grant on. */
const everyModule = (): Module[] => {
	const config = withGrants(makeValidAppConfig(), {
		session: true,
		authorizationCode: true,
		refreshToken: true,
		clientCredentials: true,
		jwtBearer: true,
	}) as AppConfig;
	return [oauthEndpointsModule, oauthSessionGrantModule, oauthAuthorizationModule({ config })];
};

/** The package's reference, resolved with no variable set. */
const defaults = (): Record<string, unknown> =>
	parseFile(fileURLToPath(REFERENCE), { env: {} }).toObject() as Record<string, unknown>;

describe("the package's config/reference.conf", () => {
	it("is read at each module's name: oauth, oauth-session and oauth-authorization", () => {
		const modules = everyModule();
		expect(modules.map((module) => module.name)).toEqual([
			"oauth",
			"oauth-session",
			"oauth-authorization",
		]);
		expect(modules.map((module) => module.section?.at)).toEqual([undefined, undefined, undefined]);
		expect(moduleReferences(modules).map((reference) => reference.href)).toContain(REFERENCE.href);
	});

	it("is declared by each of them and holds only their sections, which their schemas parse without losing a path", () => {
		// The issuer has no default: a deployment sets it, as here.
		const read = (path: string, env: Readonly<Record<string, string>>): unknown =>
			parseFile(path, { env: { OAUTH_JWT_ISSUER: "https://auth.test", ...env } }).toObject();
		// Built from the reference itself, as a root that layers it builds them:
		// each module's section holds the switches to what it was built with.
		const config = { ...makeValidAppConfig(), ...defaults() } as AppConfig;
		const modules = [
			oauthEndpointsModule,
			oauthSessionGrantModule,
			oauthAuthorizationModule({ config }),
		];
		expect(packageReferenceProblems({ reference: REFERENCE, modules, read })).toEqual([]);
	});

	it("ships every grant off and the consent page at /consent", () => {
		expect(defaults()).toMatchObject({
			oauth: { consentPage: { url: "/consent" }, clientIdMetadataDocuments: { enabled: false } },
			"oauth-session": { enabled: false },
			"oauth-authorization": {
				grants: {
					authorizationCode: { enabled: false },
					refreshToken: { enabled: false },
					clientCredentials: { enabled: false },
					jwtBearer: { enabled: false },
				},
			},
		});
	});

	it.each([
		["OAUTH_SESSION_ENABLED", "oauth-session.enabled"],
		[
			"OAUTH_AUTHORIZATION_GRANTS_AUTHORIZATION_CODE_ENABLED",
			"oauth-authorization.grants.authorizationCode.enabled",
		],
		[
			"OAUTH_AUTHORIZATION_GRANTS_REFRESH_TOKEN_ENABLED",
			"oauth-authorization.grants.refreshToken.enabled",
		],
		[
			"OAUTH_AUTHORIZATION_GRANTS_CLIENT_CREDENTIALS_ENABLED",
			"oauth-authorization.grants.clientCredentials.enabled",
		],
		[
			"OAUTH_AUTHORIZATION_GRANTS_JWT_BEARER_ENABLED",
			"oauth-authorization.grants.jwtBearer.enabled",
		],
		["OAUTH_CONSENT_PAGE_URL", "oauth.consentPage.url"],
		["OAUTH_CLIENT_ID_METADATA_DOCUMENTS_ENABLED", "oauth.clientIdMetadataDocuments.enabled"],
		[
			"OAUTH_CLIENT_ID_METADATA_DOCUMENTS_MAX_CONCURRENT_FETCHES",
			"oauth.clientIdMetadataDocuments.maxConcurrentFetches",
		],
	])("binds %s at %s and in its capture", (variable, path) => {
		expect(bindings().filter((binding) => binding.startsWith(`${variable} `))).toEqual([
			`${variable} at ${path}`,
			`${variable} at renamed-variables.${variable}`,
		]);
	});

	it.each([
		"OAUTH_GRANTS_SESSION_ENABLED",
		"OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED",
		"OAUTH_GRANTS_JWT_BEARER_ENABLED",
		"OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256",
		"ENDPOINTS_CONSENT_URL",
		"OAUTH_CIMD_ENABLED",
	])("binds %s in its capture alone", (variable) => {
		expect(bindings().filter((binding) => binding.startsWith(`${variable} `))).toEqual([
			`${variable} at renamed-variables.${variable}`,
		]);
	});
});

describe("the paths the settings moved from, on the manifests", () => {
	it("oauth: the consent page from endpoints.consent.url, and the Client ID Metadata Documents' variables renamed in place", () => {
		const section = everyModule()[0]?.section;
		expect(section?.relocatedFrom).toEqual({ "endpoints.consent.url": "consentPage.url" });
		expect(section?.renamedVariables).toMatchObject({
			ENDPOINTS_CONSENT_URL: "endpoints.consent.url",
			OAUTH_CIMD_ENABLED: "oauth.clientIdMetadataDocuments.enabled",
			OAUTH_CIMD_MAX_CONCURRENT_FETCHES: "oauth.clientIdMetadataDocuments.maxConcurrentFetches",
		});
		expect(Object.keys(section?.renamedVariables ?? {})).toHaveLength(13);
	});

	it("oauth-session: the switch from oauth.grants.session", () => {
		const section = oauthSessionGrantModule.section;
		expect(section?.relocatedFrom).toEqual({ "oauth.grants.session": "" });
		expect(section?.renamedVariables).toEqual({
			OAUTH_GRANTS_SESSION_ENABLED: "oauth.grants.session.enabled",
		});
		expect(section?.reference?.href).toBe(REFERENCE.href);
	});

	it("oauth-authorization: each grant's switch from oauth.grants.<grant>, and the authorization-code grant's pkce block removed", () => {
		const section = everyModule()[2]?.section;
		expect(section?.relocatedFrom).toEqual({
			"oauth.grants.authorization_code": "grants.authorizationCode",
			"oauth.grants.authorization_code.pkce": null,
			"oauth.grants.refresh_token": "grants.refreshToken",
			"oauth.grants.client_credentials": "grants.clientCredentials",
			"oauth.grants.urn:ietf:params:oauth:grant-type:jwt-bearer": "grants.jwtBearer",
		});
		expect(section?.renamedVariables).toEqual({
			OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED: "oauth.grants.authorization_code.enabled",
			OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256:
				"oauth.grants.authorization_code.pkce.requireS256",
			OAUTH_GRANTS_REFRESH_TOKEN_ENABLED: "oauth.grants.refresh_token.enabled",
			OAUTH_GRANTS_CLIENT_CREDENTIALS_ENABLED: "oauth.grants.client_credentials.enabled",
			OAUTH_GRANTS_JWT_BEARER_ENABLED:
				"oauth.grants.urn:ietf:params:oauth:grant-type:jwt-bearer.enabled",
		});
	});
});

describe("the oauth module's section, as an environment variable carries it", () => {
	it.each([
		[
			"a comma-separated string, entries trimmed and empties dropped",
			" a.example, .b.example ,",
			["a.example", ".b.example"],
		],
		["an exported-but-empty variable, as no entries", "", []],
		["a list written in configuration, as written", ["a.example"], ["a.example"]],
	] as const)("reads clientIdMetadataDocuments.allowedHosts from %s", (_what, written, read) => {
		const parsed = oauthSectionSchema.parse({
			...makeValidAppConfig().oauth,
			clientIdMetadataDocuments: { enabled: "true", allowedHosts: written },
		});
		expect(parsed.clientIdMetadataDocuments?.allowedHosts).toEqual(read);
	});
});

describe("the oauth-session section, and the switch read from it as boot parses it", () => {
	/** Whether the module is on for `section`, read as boot reads it. */
	const isEnabled = (section: unknown): unknown =>
		oauthSessionGrantModule.section?.isEnabled?.(oauthSessionConfigSchema.parse(section));

	it.each([
		[true, true],
		["true", true],
		["1", true],
		["TRUE", true],
		[false, false],
		["false", false],
		["", false],
	] as const)("oauth-session.enabled = %j is on: %j", (enabled, on) => {
		expect(isEnabled({ enabled })).toBe(on);
	});

	it("reads an absent section, and a section without enabled, as off", () => {
		expect(oauthSessionConfigSchema.parse(undefined)).toBeUndefined();
		expect(isEnabled(undefined)).toBe(false);
		expect(isEnabled({})).toBe(false);
	});

	it("resolves its default from the package's reference.conf alone, and holds none of its own", () => {
		expect(oauthSessionConfigSchema.parse(defaults()["oauth-session"])).toStrictEqual({
			enabled: false,
		});
		expect(oauthSessionConfigSchema.parse({})).toStrictEqual({});
	});

	it("refuses an unknown key in the section, at the section's root", () => {
		expect(
			sectionStrictnessProblems([oauthSessionGrantModule], {
				tree: defaults(),
				samples: { "oauth-session": [{ enabled: true }] },
			}),
		).toEqual([]);
		expect(
			oauthSessionConfigSchema
				.safeParse({ enabled: true, typo: 1 })
				.error?.issues.map((issue) => issue.path.join(".")),
		).toEqual([""]);
	});
});

describe("the grant switches, read from the configuration handed to the module", () => {
	/** The grant types a module contributes. */
	const grantsOf = (module: Module): string[] => Object.keys(module.contributes?.grants ?? {});

	it.each([
		["authorizationCode", "authorization_code"],
		["refreshToken", "refresh_token"],
		["clientCredentials", "client_credentials"],
		["jwtBearer", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
	] as const)("oauth-authorization.grants.%s.enabled registers %s, and only it", (key, grant) => {
		const off = {
			authorizationCode: false,
			refreshToken: false,
			clientCredentials: false,
			jwtBearer: false,
		};
		for (const enabled of [true, "true"]) {
			const config = withGrants(makeValidAppConfig(), { ...off, [key]: enabled }) as AppConfig;
			expect(grantsOf(oauthAuthorizationModule({ config }))).toEqual([grant]);
		}
		const config = withGrants(makeValidAppConfig(), off) as AppConfig;
		expect(grantsOf(oauthAuthorizationModule({ config }))).toEqual([]);
	});
});

describe("boot, over a configuration that captures the modules' renamed variables", () => {
	/** The package's modules, and the fixture's configuration with `change` laid over it, captured. */
	const composition = (change: (config: Record<string, unknown>) => Record<string, unknown>) => {
		const config = change(makeValidAppConfig() as unknown as Record<string, unknown>);
		const modules = [
			oauthEndpointsModule,
			oauthSessionGrantModule,
			oauthAuthorizationModule({ config: config as AppConfig }),
		];
		// What the modules require besides their sections, so a refusal names the configuration.
		const slots = defineModule({
			name: "test:slots",
			provides: {
				clientRepository: () => new InMemoryClientRepository(new Map()),
				keyStore: () => createSymmetricKeyStore("oauth-sections-test-secret.at-least-32-bytes"),
			},
		});
		return { modules: [...modules, slots], config: capturing(config, modules) };
	};

	/** What boot refused the composition with. */
	async function refusal(
		change: (config: Record<string, unknown>) => Record<string, unknown>,
		captured: Record<string, string> = {},
	): Promise<BootError> {
		const { modules, config } = composition(change);
		const withCaptures = {
			...config,
			"renamed-variables": { ...(config["renamed-variables"] as object), ...captured },
		};
		try {
			const handle = await createApp({
				modules,
				bootstrapComponents: { config: withCaptures, pathResolver: (s: string) => s } as never,
			});
			await handle.dispose();
		} catch (err) {
			expect(err).toBeInstanceOf(BootError);
			return err as BootError;
		}
		return expect.fail("boot should have been refused");
	}

	const oauthWith = (config: Record<string, unknown>, keys: Record<string, unknown>) => ({
		...config,
		oauth: { ...(config.oauth as object), ...keys },
	});

	it.each([
		[
			{ grants: { session: { enabled: true } } },
			"oauth.grants.session.enabled",
			"oauth-session.enabled",
			"OAUTH_SESSION_ENABLED",
		],
		[
			{ grants: { authorization_code: { enabled: true } } },
			"oauth.grants.authorization_code.enabled",
			"oauth-authorization.grants.authorizationCode.enabled",
			"OAUTH_AUTHORIZATION_GRANTS_AUTHORIZATION_CODE_ENABLED",
		],
		[
			{ grants: { "urn:ietf:params:oauth:grant-type:jwt-bearer": { enabled: true } } },
			"oauth.grants.urn:ietf:params:oauth:grant-type:jwt-bearer.enabled",
			"oauth-authorization.grants.jwtBearer.enabled",
			"OAUTH_AUTHORIZATION_GRANTS_JWT_BEARER_ENABLED",
		],
	])("refuses %j, naming %s's new path and its variable", async (keys, from, to, variable) => {
		const err = await refusal((config) => oauthWith(config, keys));

		expect(err.reason).toBe("config-path-relocated");
		expect(err.details).toMatchObject({
			relocated: [{ from, to, environmentVariable: variable }],
		});
	});

	it("refuses endpoints.consent.url, naming oauth.consentPage.url and OAUTH_CONSENT_PAGE_URL", async () => {
		const err = await refusal((config) => ({
			...config,
			endpoints: { ...(config.endpoints as object), consent: { url: "/old-consent" } },
		}));

		expect(err.details).toMatchObject({
			reason: "config-path-relocated",
			relocated: [
				{
					module: "oauth",
					from: "endpoints.consent.url",
					to: "oauth.consentPage.url",
					environmentVariable: "OAUTH_CONSENT_PAGE_URL",
				},
			],
		});
	});

	it("refuses the authorization-code grant's pkce block as removed", async () => {
		const err = await refusal((config) =>
			oauthWith(config, { grants: { authorization_code: { pkce: { requireS256: true } } } }),
		);

		expect(err.details).toEqual({
			reason: "config-path-relocated",
			relocated: [
				{
					module: "oauth-authorization",
					from: "oauth.grants.authorization_code.pkce.requireS256",
					to: null,
				},
			],
		});
		expect(err.message).toContain("was removed");
	});

	it("refuses OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256 set at all, as removed", async () => {
		const err = await refusal((config) => config, {
			OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256: "true",
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
		expect(err.message).toContain(
			"OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256 sets oauth.grants.authorization_code.pkce.requireS256, which was removed",
		);
	});

	it.each([
		[
			"OAUTH_GRANTS_SESSION_ENABLED",
			"OAUTH_SESSION_ENABLED",
			"oauth-session",
			"oauth-session.enabled",
		],
		[
			"OAUTH_CIMD_ENABLED",
			"OAUTH_CLIENT_ID_METADATA_DOCUMENTS_ENABLED",
			"oauth",
			"oauth.clientIdMetadataDocuments.enabled",
		],
		["ENDPOINTS_CONSENT_URL", "OAUTH_CONSENT_PAGE_URL", "oauth", "oauth.consentPage.url"],
	])("refuses %s set alone, naming %s", async (from, to, module, path) => {
		const err = await refusal((config) => config, { [from]: "true" });

		expect(err.details).toMatchObject({
			reason: "environment-variable-renamed",
			renamed: [{ module, from, to, path, state: "unset" }],
		});
	});

	it.each([
		["yes", { "oauth-session": { enabled: "yes" } }, "oauth-session.enabled"],
		[
			"on",
			{ "oauth-authorization": { grants: { clientCredentials: { enabled: "on" } } } },
			"oauth-authorization.grants.clientCredentials.enabled",
		],
	] as const)(
		"refuses a switch set to %j, naming it: it reads no guess",
		async (_value, sections, key) => {
			const err = await refusal((config) => ({ ...config, ...sections }));

			expect(err.reason).toBe("config-validation-failed");
			expect(err.message).toContain(key);
		},
	);

	it.each([
		["oauth-session", { enabeld: true }, "enabeld"],
		["oauth-authorization", { grants: { authorizationCode: { enable: true } } }, "enable"],
		["oauth-authorization", { grant: {} }, "grant"],
	] as const)("refuses a key %s does not declare, naming it", async (section, value, key) => {
		const err = await refusal((config) => ({ ...config, [section]: value }));

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain(`"${key}"`);
	});

	it("refuses a key oauth.consentPage does not declare, naming it", async () => {
		const err = await refusal((config) =>
			oauthWith(config, { consentPage: { url: "/consent", urll: "/typo" } }),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain('"urll"');
	});

	it("refuses an empty oauth.consentPage.url, naming the path", async () => {
		const err = await refusal((config) => oauthWith(config, { consentPage: { url: "" } }));

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain("oauth.consentPage.url must not be empty");
	});

	it("refuses OAUTH_CONSENT_PAGE_URL exported empty rather than reading it as unset", () => {
		const tree = parseFile(fileURLToPath(REFERENCE), {
			env: { OAUTH_JWT_ISSUER: "https://auth.test", OAUTH_CONSENT_PAGE_URL: "" },
		}).toObject() as { oauth: { consentPage: unknown } };
		expect(tree.oauth.consentPage).toEqual({ url: "" });

		const result = oauthSectionSchema.shape.consentPage.safeParse(tree.oauth.consentPage);
		expect(result.success).toBe(false);
	});

	it("refuses a key oauth.clientIdMetadataDocuments does not declare, naming it", async () => {
		const err = await refusal((config) =>
			oauthWith(config, {
				clientIdMetadataDocuments: { enabled: false, allowdHosts: ["a.example"] },
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain('"allowdHosts"');
	});

	it("refuses a key named __proto__ in oauth.clientIdMetadataDocuments, naming its path", async () => {
		const err = await refusal((config) =>
			oauthWith(config, {
				clientIdMetadataDocuments: JSON.parse(
					'{"enabled": false, "allowedHosts": ["a.example"], "__proto__": {"allowedHosts": ["b.example"]}}',
				),
			}),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain("oauth.clientIdMetadataDocuments.__proto__");
	});
});

describe("the switches the modules were built with, held to the ones boot parses", () => {
	/** Every switch off, and `change` over them. */
	const switches = (change: GrantSwitches): GrantSwitches => ({
		session: false,
		authorizationCode: false,
		refreshToken: false,
		clientCredentials: false,
		jwtBearer: false,
		...change,
	});

	/** What boot refused: the modules built from `built`'s switches, booted with `booted`'s. */
	async function refusedBuiltFrom(built: GrantSwitches, booted: GrantSwitches): Promise<BootError> {
		const base = makeValidAppConfig();
		const builtConfig = withGrants(base, switches(built)) as AppConfig;
		const modules = [oauthSessionGrantModule, oauthAuthorizationModule({ config: builtConfig })];
		// What the grants require besides their sections, so a refusal names the configuration.
		const slots = defineModule({
			name: "test:slots",
			provides: {
				clientRepository: () => new InMemoryClientRepository(new Map()),
				keyStore: () => createSymmetricKeyStore("oauth-sections-test-secret.at-least-32-bytes"),
			},
		});
		try {
			const handle = await createApp({
				modules: [...modules, slots],
				bootstrapComponents: {
					config: capturing(withGrants(base, switches(booted)), modules),
					pathResolver: (s: string) => s,
				} as never,
			});
			await handle.dispose();
		} catch (err) {
			expect(err).toBeInstanceOf(BootError);
			return err as BootError;
		}
		return expect.fail("boot should have been refused");
	}

	it.each([
		[
			"off, and boot parses it on",
			{ clientCredentials: false },
			{ clientCredentials: true },
			"off",
			"on",
		],
		[
			"on, and boot parses it off",
			{ clientCredentials: true },
			{ clientCredentials: false },
			"on",
			"off",
		],
	] as const)(
		"oauth-authorization: built with client_credentials %s: refused, naming oauth-authorization.grants.clientCredentials.enabled",
		async (_what, built, booted, decided, parsed) => {
			const err = await refusedBuiltFrom(built, booted);

			expect(err.reason).toBe("config-validation-failed");
			expect(err.message).toContain(
				`built from a configuration with grants.clientCredentials ${decided}, but the configuration createApp parsed has oauth-authorization.grants.clientCredentials.enabled ${parsed}`,
			);
		},
	);
});
