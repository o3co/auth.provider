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
 * read from the section boot handed it (`deps.section`), not from the
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
	GrantRegistry,
	makeValidAppConfig,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import { describe, expect, it } from "vitest";
import { oauthEndpointsModule, oauthModule } from "#/module.mjs";
import { resolveRouterSettings } from "#/routerSettings.mjs";
import { createOAuthRouter } from "#/routes.mjs";
import { type OAuthSection, oauthSectionSchema } from "#/section.mjs";
import { withOauthCaptures } from "./_helpers/sections.mjs";

const fixture = (): AppConfig => makeValidAppConfig() as AppConfig;

/** `oauth {}` as the module's schema parses it, from the fixture with `change` laid over it. */
const sectionOf = (change: Record<string, unknown> = {}): OAuthSection =>
	oauthSectionSchema.parse({
		...fixture().oauth,
		consentPage: { url: "/consent" },
		clientIdMetadataDocuments: { enabled: false },
		...change,
	});

/** A configuration whose `oauth {}` says something else than any section a test hands the module. */
const misleadingConfig = (): AppConfig =>
	({
		...fixture(),
		oauth: {
			...fixture().oauth,
			jwt: { issuer: "https://config.test" },
			accessToken: { expiresIn: 60 },
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

	it("is what the deprecated oauthModule answers, whatever it is handed", () => {
		expect(oauthModule({ config: fixture() })).toBe(oauthEndpointsModule);
		expect(oauthModule({ config: {} as never })).toBe(oauthEndpointsModule);
	});
});

describe("what the module derives, it derives from its section", () => {
	it("provides oauthTokenSettings from the section", async () => {
		const provide = oauthEndpointsModule.provides?.oauthTokenSettings;
		if (provide === undefined) throw new Error("the oauth module provides no oauthTokenSettings");
		const settings = await provide({
			config: misleadingConfig(),
			section: sectionOf({
				jwt: { issuer: "https://section.test", legacyTypAccept: true },
				accessToken: { defaultExpiresIn: 300, maxExpiresIn: 900 },
				requireEmailVerified: true,
			}),
		} as never);
		expect(settings).toEqual({
			issuer: "https://section.test",
			legacyTypAccept: true,
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

	it("builds the router's issuer from the section it is handed", () => {
		const settings = resolveRouterSettings({
			section: sectionOf({ jwt: { issuer: "https://section.test" } }),
			config: misleadingConfig(),
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

	it("builds the router from the section it is handed, the configuration's oauth {} unread", async () => {
		const build = (section?: OAuthSection) =>
			createOAuthRouter(express, {
				requirements: resolverForTests([]),
				registry: new GrantRegistry(),
				// No issuer here: a router that read it would refuse to build.
				config: { ...fixture(), oauth: {} } as unknown as AppConfig,
				...(section === undefined ? {} : { section }),
				clientRepository: new InMemoryClientRepository(new Map()),
				keyStore: createSymmetricKeyStore("oauth-own-section-test.at-least-32-bytes"),
			});
		await expect(build()).rejects.toThrow(/oauth\.jwt\.issuer/);
		// "denylist" with no denylist wired refuses the build: read from the
		// section too.
		await expect(build(sectionOf())).rejects.toThrow(/accessTokenRevocation is "denylist"/);
		await expect(
			build(sectionOf({ revocation: { accessToken: "unsupported" } })),
		).resolves.toHaveProperty("router");
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
		const error = await refusal(change({ ...fixture().oauth }));
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
