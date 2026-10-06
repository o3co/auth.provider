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
 * variable, refuse boot as removed. The refresh grant's unknown-family policy
 * sits beside its switch, moved from `oauth.refreshToken`; `legacyRtPolicy`,
 * `legacyTokenCompat` and `oauth.authorize.allowUnmarkedClients` refuse boot
 * as removed.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
	BootError,
	coreReference,
	createApp,
	createSymmetricKeyStore,
	defineModule,
	InMemoryClientRepository,
	jwksModule,
	type Module,
	moduleReferences,
} from "@o3co/auth-provider-core";
import {
	createTestApp,
	createTestOAuthTokenSettings,
	makeValidAppConfig,
	packageReferenceProblems,
	sectionStrictnessProblems,
} from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { oauthEndpointsModule, oauthSectionSchema } from "#/module.mjs";
import {
	oauthAuthorizationConfigSchema,
	oauthAuthorizationGrantsModule,
} from "#/oauthAuthorization.mjs";
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

/** The package's modules. */
const everyModule = (): Module[] => [
	oauthEndpointsModule,
	oauthSessionGrantModule,
	oauthAuthorizationGrantsModule,
];

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
		expect(modules.map((module) => Object.hasOwn(module.section ?? {}, "at"))).toEqual([
			false,
			false,
			false,
		]);
		expect(moduleReferences(modules).map((reference) => reference.href)).toContain(REFERENCE.href);
	});

	it("is declared by each of them and holds only their sections, which their schemas parse without losing a path", () => {
		// The issuer has no default: a deployment sets it, as here.
		const read = (path: string, env: Readonly<Record<string, string>>): unknown =>
			parseFile(path, { env: { OAUTH_JWT_ISSUER: "https://auth.test", ...env } }).toObject();
		expect(
			packageReferenceProblems({ reference: REFERENCE, modules: everyModule(), read }),
		).toEqual([]);
	});

	it("ships every grant off and the consent page at /consent", () => {
		expect(defaults()).toMatchObject({
			oauth: { consentPage: { url: "/consent" }, clientIdMetadataDocuments: { enabled: false } },
			"oauth-session": { enabled: false },
			"oauth-authorization": {
				grants: {
					authorizationCode: { enabled: false },
					refreshToken: { enabled: false, unknownFamilyPolicy: "reject" },
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
			"OAUTH_AUTHORIZATION_GRANTS_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY",
			"oauth-authorization.grants.refreshToken.unknownFamilyPolicy",
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
		"OAUTH_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY",
		"ENDPOINTS_CONSENT_URL",
		"OAUTH_CIMD_ENABLED",
		"OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS",
	])("binds %s in its capture alone", (variable) => {
		expect(bindings().filter((binding) => binding.startsWith(`${variable} `))).toEqual([
			`${variable} at renamed-variables.${variable}`,
		]);
	});
});

describe("the paths the settings moved from, on the manifests", () => {
	it("oauth: the consent page from endpoints.consent.url, legacyRtPolicy, legacyTokenCompat and allowUnmarkedClients removed with allowUnmarkedClients' variable, and the Client ID Metadata Documents' variables renamed in place", () => {
		const section = everyModule()[0]?.section;
		expect(section?.relocatedFrom).toEqual({
			"endpoints.consent.url": "consentPage.url",
			"oauth.refreshToken.legacyRtPolicy": null,
			"oauth.refreshToken.legacyTokenCompat": null,
			"oauth.authorize.allowUnmarkedClients": null,
		});
		expect(section?.renamedVariables).toMatchObject({
			ENDPOINTS_CONSENT_URL: "endpoints.consent.url",
			OAUTH_CIMD_ENABLED: "oauth.clientIdMetadataDocuments.enabled",
			OAUTH_CIMD_MAX_CONCURRENT_FETCHES: "oauth.clientIdMetadataDocuments.maxConcurrentFetches",
			OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS: "oauth.authorize.allowUnmarkedClients",
		});
		expect(Object.keys(section?.renamedVariables ?? {})).toHaveLength(14);
	});

	it("oauth-session: the switch from oauth.grants.session", () => {
		const section = oauthSessionGrantModule.section;
		expect(section?.relocatedFrom).toEqual({ "oauth.grants.session": "" });
		expect(section?.renamedVariables).toEqual({
			OAUTH_GRANTS_SESSION_ENABLED: "oauth.grants.session.enabled",
		});
		expect(section?.reference?.href).toBe(REFERENCE.href);
	});

	it("oauth-authorization: each grant's switch from oauth.grants.<grant>, the refresh grant's unknown-family policy from oauth.refreshToken, and the authorization-code grant's pkce block removed", () => {
		const section = everyModule()[2]?.section;
		expect(section?.relocatedFrom).toEqual({
			"oauth.grants.authorization_code": "grants.authorizationCode",
			"oauth.grants.authorization_code.pkce": null,
			"oauth.grants.refresh_token": "grants.refreshToken",
			"oauth.refreshToken.unknownFamilyPolicy": "grants.refreshToken.unknownFamilyPolicy",
			"oauth.grants.client_credentials": "grants.clientCredentials",
			"oauth.grants.urn:ietf:params:oauth:grant-type:jwt-bearer": "grants.jwtBearer",
		});
		expect(section?.renamedVariables).toEqual({
			OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED: "oauth.grants.authorization_code.enabled",
			OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256:
				"oauth.grants.authorization_code.pkce.requireS256",
			OAUTH_GRANTS_REFRESH_TOKEN_ENABLED: "oauth.grants.refresh_token.enabled",
			OAUTH_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY: "oauth.refreshToken.unknownFamilyPolicy",
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

describe("the oauth-authorization section, and the switches read from it as boot parses it", () => {
	/** The section as boot parses it. */
	const parse = (section: unknown) => oauthAuthorizationConfigSchema.parse(section);
	/** Whether the module is on for `section`, read as boot reads it. */
	const isEnabled = (section: unknown): unknown =>
		oauthAuthorizationGrantsModule.section?.isEnabled?.(parse(section));
	/** Every grant's factory, by grant type. */
	const factories = () => oauthAuthorizationGrantsModule.contributes?.grants ?? {};
	/**
	 * The grant types whose factory answers `null` for `section`: those it
	 * switches off. One switched on goes on to read the slots it needs, which
	 * these bare deps do not carry, and throws instead.
	 */
	const switchedOff = (section: unknown): string[] =>
		Object.entries(factories())
			.filter(([, factory]) => {
				try {
					return factory({ section: parse(section) } as never) === null;
				} catch {
					return false;
				}
			})
			.map(([grant]) => grant);

	const GRANTS = [
		["authorizationCode", "authorization_code"],
		["refreshToken", "refresh_token"],
		["clientCredentials", "client_credentials"],
		["jwtBearer", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
	] as const;
	const ALL_OFF = {
		authorizationCode: { enabled: false },
		refreshToken: { enabled: false },
		clientCredentials: { enabled: false },
		jwtBearer: { enabled: false },
	};
	/** What the package's reference ships: every switch off, and the refresh grant's policy reject. */
	const SHIPPED = { ...ALL_OFF, refreshToken: { enabled: false, unknownFamilyPolicy: "reject" } };

	it("is exported as a module value, and no factory builds it from a configuration", async () => {
		const entry = (await import("#/index.mjs")) as Record<string, unknown>;
		expect(entry.oauthAuthorizationGrantsModule).toBe(oauthAuthorizationGrantsModule);
		expect(entry).not.toHaveProperty("oauthAuthorizationModule");
	});

	it("is one module that contributes every grant it installs, each switched by its own key", () => {
		expect(Object.keys(factories()).sort()).toEqual(GRANTS.map(([, grant]) => grant).sort());
		expect(typeof oauthAuthorizationGrantsModule.section?.isEnabled).toBe("function");
	});

	it.each(GRANTS)(
		"oauth-authorization.grants.%s.enabled switches %s on, and only it, and the module with it",
		(key, grant) => {
			for (const enabled of [true, "true", "1", "TRUE"]) {
				const section = { grants: { ...ALL_OFF, [key]: { enabled } } };
				expect(isEnabled(section)).toBe(true);
				expect(switchedOff(section).sort()).toEqual(
					GRANTS.map(([, g]) => g)
						.filter((g) => g !== grant)
						.sort(),
				);
			}
		},
	);

	it.each([
		["an absent section", undefined],
		["a section without grants", {}],
		["grants without a switch", { grants: { authorizationCode: {} } }],
		["every switch off", { grants: ALL_OFF }],
		["every switch the string false", { grants: { clientCredentials: { enabled: "false" } } }],
	] as const)("reads %s as every grant off, and the module off", (_what, section) => {
		expect(isEnabled(section)).toBe(false);
		expect(switchedOff(section).sort()).toEqual(GRANTS.map(([, grant]) => grant).sort());
	});

	it("resolves its defaults from the package's reference.conf alone, and holds none of its own", () => {
		expect(parse(defaults()["oauth-authorization"])).toStrictEqual({ grants: SHIPPED });
		expect(parse({})).toStrictEqual({});
		expect(parse({ grants: {} })).toStrictEqual({ grants: {} });
		expect(parse(undefined)).toBeUndefined();
	});

	it("refuses an unknown key at every level of the section, at its path", () => {
		expect(
			sectionStrictnessProblems([oauthAuthorizationGrantsModule], {
				tree: defaults(),
				samples: { "oauth-authorization": [{ grants: SHIPPED }] },
			}),
		).toEqual([]);
		const pathOf = (section: unknown) =>
			oauthAuthorizationConfigSchema
				.safeParse(section)
				.error?.issues.map((issue) => issue.path.join("."));
		expect(pathOf({ grant: {} })).toEqual([""]);
		expect(pathOf({ grants: { authCode: { enabled: true } } })).toEqual(["grants"]);
		expect(pathOf({ grants: { refreshToken: { enable: true } } })).toEqual(["grants.refreshToken"]);
	});

	it.each(["accept", "reject"])("reads grants.refreshToken.unknownFamilyPolicy = %s", (policy) => {
		expect(parse({ grants: { refreshToken: { unknownFamilyPolicy: policy } } })).toStrictEqual({
			grants: { refreshToken: { unknownFamilyPolicy: policy } },
		});
	});

	it.each(["warn", "ACCEPT", "", true])(
		"refuses grants.refreshToken.unknownFamilyPolicy = %j at its path",
		(policy) => {
			expect(
				oauthAuthorizationConfigSchema
					.safeParse({ grants: { refreshToken: { unknownFamilyPolicy: policy } } })
					.error?.issues.map((issue) => issue.path.join(".")),
			).toEqual(["grants.refreshToken.unknownFamilyPolicy"]);
		},
	);

	it("holds no policy key under any other grant", () => {
		expect(
			oauthAuthorizationConfigSchema
				.safeParse({ grants: { authorizationCode: { unknownFamilyPolicy: "accept" } } })
				.error?.issues.map((issue) => issue.path.join(".")),
		).toEqual(["grants.authorizationCode"]);
	});
});

describe("boot, over a configuration that captures the modules' renamed variables", () => {
	/** The package's modules, and the fixture's configuration with `change` laid over it, captured. */
	const composition = (change: (config: Record<string, unknown>) => Record<string, unknown>) => {
		const config = change(makeValidAppConfig() as unknown as Record<string, unknown>);
		const modules = everyModule();
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
		[
			{ refreshToken: { expiresIn: 86400, unknownFamilyPolicy: "accept" } },
			"oauth.refreshToken.unknownFamilyPolicy",
			"oauth-authorization.grants.refreshToken.unknownFamilyPolicy",
			"OAUTH_AUTHORIZATION_GRANTS_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY",
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

	it.each(["reject", "accept-with-warning"])(
		"refuses oauth.refreshToken.legacyRtPolicy = %j as removed",
		async (value) => {
			const err = await refusal((config) =>
				oauthWith(config, { refreshToken: { expiresIn: 86400, legacyRtPolicy: value } }),
			);

			expect(err.details).toEqual({
				reason: "config-path-relocated",
				relocated: [{ module: "oauth", from: "oauth.refreshToken.legacyRtPolicy", to: null }],
			});
			expect(err.message).toContain("was removed");
		},
	);

	it.each([
		["refreshToken", "legacyTokenCompat", false],
		["refreshToken", "legacyTokenCompat", true],
		["authorize", "allowUnmarkedClients", false],
		["authorize", "allowUnmarkedClients", "true"],
	])(
		"refuses oauth.%s.%s = %j as removed, telling the operator to remove it",
		async (block, key, value) => {
			const err = await refusal((config) => {
				const oauth = config.oauth as Record<string, Record<string, unknown>>;
				return oauthWith(config, { [block]: { ...oauth[block], [key]: value } });
			});

			// Refused by the oauth module's own declaration, before any schema
			// parses the configuration.
			expect(err.details).toEqual({
				reason: "config-path-relocated",
				relocated: [{ module: "oauth", from: `oauth.${block}.${key}`, to: null }],
			});
			expect(err.message).toContain(
				`oauth.${block}.${key} was removed; see CHANGELOG. Remove this field from your config (or unset the environment variable that sets it).`,
			);
		},
	);

	it.each(["false", "true", ""])(
		"refuses OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS = %j exported, as the variable of a removed key",
		async (value) => {
			// No reference binds the variable at the removed key any more: the
			// package's reference captures it, and boot refuses it set at all.
			for (const reference of [coreReference(), REFERENCE]) {
				const layered = parseFile(fileURLToPath(reference), {
					env: { OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS: value },
				}).toObject() as { oauth?: { authorize?: Record<string, unknown> } };
				expect(layered.oauth?.authorize?.allowUnmarkedClients).toBeUndefined();
			}

			const err = await refusal((config) => config, {
				OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS: value,
			});

			expect(err.details).toEqual({
				reason: "environment-variable-renamed",
				renamed: [
					{
						module: "oauth",
						from: "OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS",
						to: null,
						path: null,
						state: "removed",
					},
				],
			});
			expect(err.message).toContain(
				"OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS sets oauth.authorize.allowUnmarkedClients, which was removed",
			);
			expect(err.message).not.toContain(`"${value}"`);
		},
	);

	it("boots with OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS unset, captured as null", async () => {
		// Nothing here fills the denylist or a code repository: the denylist's
		// absence is declared, and the grants are off.
		const { modules, config } = composition((c) =>
			oauthWith(
				withGrants(c as never, {
					authorizationCode: false,
					refreshToken: false,
					clientCredentials: false,
				}) as Record<string, unknown>,
				{ revocation: { accessToken: "unsupported", subject: "unsupported" } },
			),
		);
		expect(
			(config["renamed-variables"] as Record<string, unknown>)
				.OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS,
		).toBeNull();
		const handle = await createApp({
			// The JWKS module completes the discovery document an issuer turns on.
			modules: [...modules, jwksModule],
			bootstrapComponents: { config, pathResolver: (s: string) => s } as never,
		});
		await handle.dispose();
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
		[
			"OAUTH_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY",
			"OAUTH_AUTHORIZATION_GRANTS_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY",
			"oauth-authorization",
			"oauth-authorization.grants.refreshToken.unknownFamilyPolicy",
		],
	])("refuses %s set alone, naming %s", async (from, to, module, path) => {
		const err = await refusal((config) => config, { [from]: "true" });

		expect(err.details).toMatchObject({
			reason: "environment-variable-renamed",
			renamed: [{ module, from, to, path, state: "unset" }],
		});
	});

	it("refuses OAUTH_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY beside its new name set to another value", async () => {
		const err = await refusal((config) => config, {
			OAUTH_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY: "accept",
			OAUTH_AUTHORIZATION_GRANTS_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY: "reject",
		});

		expect(err.details).toEqual({
			reason: "environment-variable-renamed",
			renamed: [
				{
					module: "oauth-authorization",
					from: "OAUTH_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY",
					to: "OAUTH_AUTHORIZATION_GRANTS_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY",
					path: "oauth-authorization.grants.refreshToken.unknownFamilyPolicy",
					state: "different",
				},
			],
		});
	});

	it("boots with OAUTH_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY beside its new name set to the same value", async () => {
		const modules = [oauthAuthorizationGrantsModule];
		const slots = defineModule({
			name: "test:slots",
			provides: {
				clientRepository: () => new InMemoryClientRepository(new Map()),
				keyStore: () => createSymmetricKeyStore("oauth-sections-test-secret.at-least-32-bytes"),
			},
		});
		const config = capturing(
			withGrants(makeValidAppConfig(), {
				authorizationCode: false,
				refreshToken: false,
				clientCredentials: true,
			}),
			modules,
		) as unknown as Record<string, Record<string, unknown>>;
		const handle = await createTestApp({
			modules: [...modules, slots],
			bootstrapComponents: {
				config: {
					...config,
					"oauth-authorization": {
						grants: {
							...(config["oauth-authorization"]?.grants as object),
							refreshToken: { enabled: false, unknownFamilyPolicy: "accept" },
						},
					},
					"renamed-variables": {
						...config["renamed-variables"],
						OAUTH_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY: "accept",
						OAUTH_AUTHORIZATION_GRANTS_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY: "accept",
					},
				} as never,
				pathResolver: (s: string) => s,
				oauthTokenSettings: createTestOAuthTokenSettings(),
			},
		});
		expect(handle.inspect.grants.has("client_credentials")).toBe(true);
		await handle.dispose();
	});

	it.each([
		["warn", "warn"],
		["the right word in another case", "Accept"],
	])(
		"refuses oauth-authorization.grants.refreshToken.unknownFamilyPolicy set to %s, naming the path",
		async (_what, value) => {
			const err = await refusal((config) => ({
				...config,
				"oauth-authorization": { grants: { refreshToken: { unknownFamilyPolicy: value } } },
			}));

			expect(err.reason).toBe("config-validation-failed");
			expect(err.message).toContain("oauth-authorization.grants.refreshToken.unknownFamilyPolicy");
		},
	);

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

	it("refuses the boot with the variable captured empty, naming the path", async () => {
		const err = await refusal((config) => oauthWith(config, { consentPage: { url: "" } }), {
			OAUTH_CONSENT_PAGE_URL: "",
		});

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain("oauth.consentPage.url must not be empty");
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

describe("the switches, read from the section boot parses", () => {
	/** Every switch off, and `change` over them. */
	const switches = (change: GrantSwitches): GrantSwitches => ({
		session: false,
		authorizationCode: false,
		refreshToken: false,
		clientCredentials: false,
		jwtBearer: false,
		...change,
	});

	/** The grant types boot registers for `modules` over `booted`'s switches. */
	async function registered(modules: readonly Module[], booted: GrantSwitches): Promise<string[]> {
		// What the grants require besides their sections and the oauth module's slot.
		const slots = defineModule({
			name: "test:slots",
			provides: {
				clientRepository: () => new InMemoryClientRepository(new Map()),
				keyStore: () => createSymmetricKeyStore("oauth-sections-test-secret.at-least-32-bytes"),
			},
		});
		const handle = await createTestApp({
			modules: [...modules, slots],
			bootstrapComponents: {
				config: capturing(withGrants(makeValidAppConfig(), switches(booted)), modules),
				pathResolver: (s: string) => s,
				oauthTokenSettings: createTestOAuthTokenSettings(),
			},
		});
		try {
			return ["authorization_code", "refresh_token", "client_credentials"].filter((grant) =>
				handle.inspect.grants.has(grant),
			);
		} finally {
			await handle.dispose();
		}
	}

	it("registers the grant the booted section turns on, the module listed as it is", async () => {
		expect(await registered([oauthAuthorizationGrantsModule], { clientCredentials: true })).toEqual(
			["client_credentials"],
		);
	});
});
