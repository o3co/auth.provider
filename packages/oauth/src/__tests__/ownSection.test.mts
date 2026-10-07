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
 * The oauth module owns `oauth {}`: it is one module value whose section
 * schema declares the whole section, boot refuses a key the section does not
 * declare at its path, and what the module derives from the section — the
 * token settings it provides, the discovery slice, the router's issuer — is
 * read from the section boot handed it (`deps.section`), and what it reads of
 * the federations from core's `federationSettings` slot, never from the
 * configuration.
 */

import {
	type AppConfig,
	BootError,
	type ClientRepository,
	createApp,
	createSymmetricKeyStore,
	defineModule,
	type GrantHandlerResolver,
	InMemoryClientRepository,
	jwksModule,
	memoryAccessTokenDenylistModule,
} from "@o3co/auth-provider-core";
import {
	createTestFederationSettings,
	createTestOutboundPolicy,
	GrantRegistry,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import { describe, expect, it } from "vitest";
import { oauthEndpointsModule } from "#/module.mjs";
import { resolveRouterSettings } from "#/routerSettings.mjs";
import { createOAuthRouter } from "#/routes.mjs";
import { type OAuthSection, oauthSectionSchema } from "#/section.mjs";
import { appConfigWithOAuthModule } from "./_helpers/oauthModuleConfig.mjs";
import { withOauthCaptures } from "./_helpers/sections.mjs";

const fixture = (): AppConfig => appConfigWithOAuthModule() as AppConfig;

/** `oauth {}` as the module's schema parses it, from the fixture with `change` laid over it. */
const sectionOf = (change: Record<string, unknown> = {}): OAuthSection =>
	oauthSectionSchema.parse({
		...(fixture().oauth as object),
		consentPage: { url: "/consent" },
		clientIdMetadataDocuments: { enabled: false },
		...change,
	});

/** A configuration whose `oauth {}` says something else than any section a test hands the module. */
const misleadingConfig = (): AppConfig =>
	({
		...fixture(),
		oauth: {
			...(fixture().oauth as object),
			jwt: { issuer: "https://config.test" },
			accessToken: { defaultExpiresIn: 60 },
			revocation: { accessToken: "unsupported" },
			clientIdMetadataDocuments: { enabled: true },
			authorize: { acrValues: { "urn:from-config": ["pwd"] } },
		},
	}) as unknown as AppConfig;

describe("the oauth module is one module value", () => {
	it("named oauth, its section declared by the section schema", () => {
		expect(oauthEndpointsModule.name).toBe("oauth");
		expect(oauthEndpointsModule.section?.schema).toBe(oauthSectionSchema);
	});

	it("requires core's federationSettings and never the whole configuration", () => {
		expect(oauthEndpointsModule.requires).toContain("federationSettings");
		expect([
			...(oauthEndpointsModule.requires ?? []),
			...(oauthEndpointsModule.optional ?? []),
		]).not.toContain("config");
	});

	it("requires core's outboundPolicy, the policy every URL a client registration names is fetched under", () => {
		expect(oauthEndpointsModule.requires).toContain("outboundPolicy");
	});
});

describe("what the module derives, it derives from its section", () => {
	it("provides oauthTokenSettings from the section", async () => {
		const provide = oauthEndpointsModule.provides?.oauthTokenSettings;
		if (provide === undefined) throw new Error("the oauth module provides no oauthTokenSettings");
		const settings = await provide({
			config: misleadingConfig(),
			section: sectionOf({
				jwt: { issuer: "https://section.test" },
				accessToken: { defaultExpiresIn: 300, maxExpiresIn: 900 },
				requireEmailVerified: true,
			}),
		} as never);
		expect(settings).toEqual({
			issuer: "https://section.test",
			accessTokenLifetime: { defaultExpiresIn: 300, maxExpiresIn: 900 },
			refreshTokenExpiresIn: 86400,
			resourceIndicatorEnabled: false,
			requireEmailVerified: true,
		});
	});

	it("advertises revocation, the Client ID Metadata Documents and the acr table from the section", async () => {
		const factory = oauthEndpointsModule.contributes?.discoveryMetadata?.[0];
		if (factory === undefined) throw new Error("the oauth module contributes no discoveryMetadata");
		const grants = new Map([["authorization_code", {}]]);
		const meta = await factory({
			config: misleadingConfig(),
			section: sectionOf({
				revocation: { accessToken: "denylist" },
				clientIdMetadataDocuments: { enabled: false },
				authorize: { acrValues: { "urn:from-section": ["pwd"] } },
			}),
			grantHandlerResolver: {
				get: (grantType: string) => grants.get(grantType),
				entries: () => grants.entries(),
			} as unknown as GrantHandlerResolver,
			sessionRequirementResolver: resolverForTests([]),
			accessTokenDenylist: {},
			consentStore: {},
		} as never);
		expect(meta.endpoints).toMatchObject({ revocation_endpoint: "/oauth/revoke" });
		expect(meta.metadata).not.toHaveProperty("client_id_metadata_document_supported");
		expect(meta.metadata).toMatchObject({ acr_values_supported: ["urn:from-section"] });
	});

	it("reads which installed federation trusts its upstream amr from federationSettings, not core.federations", async () => {
		const factory = oauthEndpointsModule.contributes?.discoveryMetadata?.[0];
		if (factory === undefined) throw new Error("the oauth module contributes no discoveryMetadata");
		const grants = new Map([["authorization_code", {}]]);
		const advertised = async (trustsUpstreamAmr: boolean, config: unknown) =>
			(
				await factory({
					...(config === undefined ? {} : { config }),
					section: sectionOf({
						authorize: { acrValues: { "urn:pwd": ["pwd"], "urn:phr": [["hwk"]] } },
					}),
					federationSettings: createTestFederationSettings({
						google: { type: "google", trustsUpstreamAmr },
					}),
					federationProviders: new Map([["google", {}]]),
					grantHandlerResolver: {
						get: (grantType: string) => grants.get(grantType),
						entries: () => grants.entries(),
					} as unknown as GrantHandlerResolver,
					sessionRequirementResolver: resolverForTests([]),
				} as never)
			).metadata?.acr_values_supported;
		// A configuration whose core.federations says the opposite is unread.
		const distrusting = {
			...misleadingConfig(),
			core: { federations: { google: { type: "google", enabled: true, trustUpstreamAmr: false } } },
		};
		const trusting = {
			...misleadingConfig(),
			core: { federations: { google: { type: "google", enabled: true, trustUpstreamAmr: true } } },
		};
		expect(await advertised(true, distrusting)).toEqual(["urn:pwd", "urn:phr"]);
		expect(await advertised(false, trusting)).toEqual(["urn:pwd"]);
		expect(await advertised(true, undefined)).toEqual(["urn:pwd", "urn:phr"]);
	});

	it("builds the router's issuer from the section it is handed", () => {
		const settings = resolveRouterSettings({
			section: sectionOf({ jwt: { issuer: "https://section.test" } }),
			federationSettings: createTestFederationSettings(),
			authorizationEndpoint: false,
			requirements: resolverForTests([]),
			getFederationProviders: () => undefined,
			registeredClients: new InMemoryClientRepository(new Map()) as ClientRepository,
			consentStore: undefined,
			clientIdMetadataDocumentSeams: {},
			logger: { info() {}, warn() {}, error() {}, debug() {} } as never,
		});
		expect(settings.canonicalIssuer).toBe("https://section.test");
	});

	it("builds the router from the section it is handed, and from nothing else", async () => {
		const build = (options: { section?: OAuthSection; federationSettings?: unknown }) =>
			createOAuthRouter(express, {
				requirements: resolverForTests([]),
				registry: new GrantRegistry(),
				...(options as { section: OAuthSection; federationSettings: never }),
				outboundPolicy: createTestOutboundPolicy(),
				clientRepository: new InMemoryClientRepository(new Map()),
				keyStore: createSymmetricKeyStore("oauth-own-section-test.at-least-32-bytes"),
			});
		const federationSettings = createTestFederationSettings();
		// No section: refused, naming it — there is no configuration to fall back on.
		await expect(build({ federationSettings })).rejects.toThrow(
			/^createOAuthRouter: section is required — /,
		);
		await expect(build({ federationSettings })).rejects.toBeInstanceOf(RangeError);
		// "denylist" with no denylist wired refuses the build: read from the
		// section, while a configuration handed beside it that says
		// "unsupported" is not read.
		await expect(
			build({ section: sectionOf(), federationSettings, config: misleadingConfig() } as never),
		).rejects.toThrow(/accessTokenRevocation is "denylist"/);
		await expect(
			build({
				section: sectionOf({ revocation: { accessToken: "unsupported" } }),
				federationSettings,
			}),
		).resolves.toHaveProperty("router");
	});

	it("refuses to build without federationSettings, core's view of the federations", async () => {
		await expect(
			createOAuthRouter(express, {
				requirements: resolverForTests([]),
				registry: new GrantRegistry(),
				section: sectionOf({ revocation: { accessToken: "unsupported" } }),
				clientRepository: new InMemoryClientRepository(new Map()),
				keyStore: createSymmetricKeyStore("oauth-own-section-test.at-least-32-bytes"),
			} as never),
		).rejects.toThrow(/^createOAuthRouter: federationSettings is required — /);
	});

	it("refuses to build without outboundPolicy, core's policy for the URLs a client registration names", async () => {
		const build = createOAuthRouter(express, {
			requirements: resolverForTests([]),
			registry: new GrantRegistry(),
			section: sectionOf({ revocation: { accessToken: "unsupported" } }),
			federationSettings: createTestFederationSettings(),
			clientRepository: new InMemoryClientRepository(new Map()),
			keyStore: createSymmetricKeyStore("oauth-own-section-test.at-least-32-bytes"),
		} as never);
		await expect(build).rejects.toThrow(/^createOAuthRouter: outboundPolicy is required — /);
		await expect(build).rejects.toBeInstanceOf(RangeError);
	});
});

describe("boot refuses a key oauth {} does not declare, at its path", () => {
	const stubs = [
		defineModule({
			name: "test:slots",
			provides: {
				clientRepository: () => new InMemoryClientRepository(new Map()),
				keyStore: () => createSymmetricKeyStore("oauth-own-section-test.at-least-32-bytes"),
			},
		}),
		memoryAccessTokenDenylistModule,
		jwksModule,
	];

	const refusal = async (oauth: Record<string, unknown>): Promise<BootError> => {
		const config = { ...fixture(), oauth } as unknown as AppConfig;
		const caught = await createApp({
			modules: [oauthEndpointsModule, ...stubs],
			bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s: string) => s },
		}).then(
			async (handle) => {
				await handle.dispose();
				return undefined;
			},
			(err: unknown) => err,
		);
		if (!(caught instanceof BootError)) throw new Error(`boot was not refused: ${String(caught)}`);
		return caught;
	};

	it.each([
		["the section", (oauth: Record<string, unknown>) => ({ ...oauth, unexpected: 1 }), "oauth"],
		[
			"a nested level",
			(oauth: Record<string, unknown>) => ({ ...oauth, nonce: { maxLength: 64, unexpected: 1 } }),
			"oauth.nonce",
		],
		[
			"jwt",
			(oauth: Record<string, unknown>) => ({
				...oauth,
				jwt: { ...(oauth.jwt as object), unexpected: 1 },
			}),
			"oauth.jwt",
		],
	])("in %s", async (_level, change, path) => {
		const error = await refusal(change({ ...(fixture().oauth as object) }));
		expect(error.reason).toBe("config-validation-failed");
		expect(error.message).toContain(`${path}: Unrecognized key: "unexpected"`);
	});

	it("boots the fixture's oauth {} as it is", async () => {
		const config = fixture();
		const handle = await createApp({
			modules: [oauthEndpointsModule, ...stubs],
			bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s: string) => s },
		});
		await handle.dispose();
	});
});
