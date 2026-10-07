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
 * The oauth-authorization grants read their settings from slots, not from
 * the whole configuration: the issuer, the lifetimes, the resource-indicator
 * switch and `requireEmailVerified` from `oauthTokenSettings`, and the
 * refresh-token binding rule from core's `tokenBindingSettings`. A
 * composition without the oauth module fills `oauthTokenSettings` itself.
 */

import {
	BootError,
	createSymmetricKeyStore,
	defineModule,
	type GrantHandler,
	InMemoryClientRepository,
	type TokenBindingSettings,
} from "@o3co/auth-provider-core";
import {
	createTestApp,
	createTestOAuthTokenSettings,
	createTestTokenBindingSettings,
	makeValidAppConfig,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import { decodeJwt } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";
import { createClientCredentialsGrant } from "#/grants/clientCredentials.mjs";
import { createJwtBearerGrant } from "#/grants/jwtBearer.mjs";
import { createRefreshTokenGrant } from "#/grants/refreshToken.mjs";
import { oauthAuthorizationGrantsModule } from "#/oauthAuthorization.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { registeredGrants } from "./_helpers/grantRegistry.mjs";
import { capturing, withGrants } from "./_helpers/sections.mjs";

afterEach(() => {
	vi.useRealTimers();
});

const keyStore = createSymmetricKeyStore("oauth-authorization-slots-secret-32b!");

/** Only client_credentials on: the grant that needs no store beyond the client's. */
const clientCredentialsOnly = () =>
	withGrants(makeValidAppConfig(), {
		authorizationCode: false,
		refreshToken: false,
		clientCredentials: true,
		jwtBearer: false,
	});

/** What the module requires besides its section and the oauth module's slot. */
const slots = defineModule({
	name: "test:slots",
	provides: {
		clientRepository: () => new InMemoryClientRepository(new Map()),
		keyStore: () => keyStore,
	},
});

const client = {
	clientId: "m2m",
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	allowedScopes: ["read"],
	defaultScopes: ["read"],
	allowedAudiences: ["https://rs.example"],
	allowedGrantTypes: ["client_credentials"],
};

describe("a composition without the oauth module, filling oauthTokenSettings itself", () => {
	const boot = (oauthTokenSettings?: unknown) => {
		const config = clientCredentialsOnly();
		return createTestApp({
			modules: [oauthAuthorizationGrantsModule, slots],
			bootstrapComponents: {
				config: capturing(config, [oauthAuthorizationGrantsModule]),
				pathResolver: (s: string) => s,
				...(oauthTokenSettings === undefined ? {} : { oauthTokenSettings }),
			} as never,
		});
	};

	it("mints with the slot's lifetime and its resource-indicator switch, not the configuration's", async () => {
		// `expires_in` is the time left when answered: read on a frozen clock.
		vi.useFakeTimers({ toFake: ["Date"], now: Date.now() });
		// The configuration's access-token lifetime is 3600 s and its resource
		// indicators are off; the slot's lifetime is shorter, which boot
		// accepts, and its resource indicators are on.
		const handle = await boot(
			createTestOAuthTokenSettings({
				accessTokenLifetime: { defaultExpiresIn: 600, maxExpiresIn: 600 },
				resourceIndicatorEnabled: true,
			}),
		);
		try {
			const grant = handle.inspect.grants.get("client_credentials") as GrantHandler;
			const ctx = (body: Record<string, unknown>) => ({
				body: { grant_type: "client_credentials", ...body },
				session: {},
				issuer: "https://auth.test",
				metadata: {},
				authenticatedClient: client,
			});
			const { result } = await grant.handle(ctx({}));
			if (!("tokens" in result)) throw new Error(`expected tokens, got ${result.status}`);
			expect(result.tokens.expires_in).toBe(600);
			const claims = decodeJwt(result.tokens.access_token);
			expect((claims.exp as number) - (claims.iat as number)).toBe(600);

			const refused = await grant.handle(ctx({ resource: "https://other.example" }));
			expect(refused.result).toMatchObject({ status: 400, error: "invalid_target" });
		} finally {
			await handle.dispose();
		}
	});

	it("refuses boot with a grant on and no oauthTokenSettings, naming the slot", async () => {
		const err = await boot().then(
			async (handle) => {
				await handle.dispose();
				return undefined;
			},
			(caught: unknown) => caught,
		);
		expect(err).toBeInstanceOf(BootError);
		expect(String((err as BootError).message)).toContain("oauthTokenSettings");
	});

	it("requires nothing with every grant off: it boots without oauthTokenSettings, a key store or a client repository", async () => {
		const config = withGrants(makeValidAppConfig(), {
			authorizationCode: false,
			refreshToken: false,
			clientCredentials: false,
			jwtBearer: false,
		});
		const handle = await createTestApp({
			modules: [oauthAuthorizationGrantsModule],
			bootstrapComponents: {
				config: capturing(config, [oauthAuthorizationGrantsModule]),
				pathResolver: (s: string) => s,
			},
		});
		for (const grant of ["authorization_code", "refresh_token", "client_credentials"]) {
			expect(handle.inspect.grants.has(grant)).toBe(false);
		}
		await handle.dispose();
	});
});

describe("each grant refuses to be built without its settings", () => {
	const requirements = resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS });
	const clientRepository = new InMemoryClientRepository(new Map());
	const codeRepository = {
		createCode: async () => ({}) as never,
		findByCode: async () => null,
		consumeByCode: async () => null,
		removeByCode: async () => {},
	};
	const tokenBindingSettings = createTestTokenBindingSettings();
	const config = makeValidAppConfig();

	const builds: ReadonlyArray<readonly [string, (settings: unknown) => unknown]> = [
		[
			"authorization_code",
			(oauthTokenSettings) =>
				createAuthorizationGrant({
					keyStore,
					clientRepository,
					codeRepository,
					sessionRequirementResolver: requirements,
					grantHandlerResolver: registeredGrants("refresh_token"),
					oauthTokenSettings,
					tokenBindingSettings,
				} as never),
		],
		[
			"refresh_token",
			(oauthTokenSettings) =>
				createRefreshTokenGrant({
					config,
					keyStore,
					sessionRequirementResolver: requirements,
					oauthTokenSettings,
					tokenBindingSettings,
				} as never),
		],
		[
			"client_credentials",
			(oauthTokenSettings) =>
				createClientCredentialsGrant({ keyStore, oauthTokenSettings } as never),
		],
		[
			"jwt-bearer",
			(oauthTokenSettings) =>
				createJwtBearerGrant({
					keyStore,
					oauthTokenSettings,
					assertionVerifier: { kind: "test", verify: async () => null },
					userRepository: {} as never,
				} as never),
		],
	];

	it.each(builds)(
		"%s: refuses no oauthTokenSettings, or one that breaks its contract, naming the slot or the member",
		(_grant, build) => {
			expect(() => build(undefined)).toThrow(RangeError);
			expect(() => build(undefined)).toThrow(/oauthTokenSettings/);
			expect(() =>
				build({
					...createTestOAuthTokenSettings(),
					accessTokenLifetime: { defaultExpiresIn: 0, maxExpiresIn: 60 },
				}),
			).toThrow(/accessTokenLifetime/);
			expect(build(createTestOAuthTokenSettings())).toBeDefined();
		},
	);

	it.each(["authorization_code", "refresh_token"])(
		"%s: refuses a tokenBindingSettings slot whose binding rule is not a boolean, naming the slot",
		(grant) => {
			const settings = createTestOAuthTokenSettings();
			for (const tokenBindingSettings of [
				undefined,
				{ dispatchPolicy: "intent-explicit", bindConfidentialClientRefreshTokens: "true" },
				{ dispatchPolicy: "intent-explicit" },
			]) {
				const deps = {
					config,
					keyStore,
					clientRepository,
					codeRepository,
					sessionRequirementResolver: requirements,
					grantHandlerResolver: registeredGrants("refresh_token"),
					oauthTokenSettings: settings,
					tokenBindingSettings: tokenBindingSettings as TokenBindingSettings | undefined,
				};
				const build =
					grant === "authorization_code"
						? () => createAuthorizationGrant(deps as never)
						: () => createRefreshTokenGrant(deps as never);
				expect(build, JSON.stringify(tokenBindingSettings)).toThrow(/tokenBindingSettings/);
			}
		},
	);
});
