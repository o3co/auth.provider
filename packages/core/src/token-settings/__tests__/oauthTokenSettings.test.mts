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
 * The `oauthTokenSettings` slot: what other modules read of the oauth
 * module's token settings: the slot's shape, its wiring between modules,
 * and the test double. The slot's contract suite is the test kit's, and runs
 * over this double there. The token-binding settings — the dispatch policy
 * and whether a confidential client's refresh tokens are bound — are not
 * among them: they apply across core's token-binding extension point, so
 * they are core's, and core reads them itself.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import type { AccessTokenLifetime } from "#/config/application.schema.mjs";
import { createApp, defineModule, type ProviderDeps } from "#/index.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { createTestOAuthTokenSettings } from "#/testing/index.mjs";
import type { OAuthTokenSettings } from "#/token-settings/types.mjs";

describe("the oauthTokenSettings slot", () => {
	it("is optional, and holds the settings other modules read of the oauth module's", () => {
		expectTypeOf<ComponentMap["oauthTokenSettings"]>().toEqualTypeOf<
			OAuthTokenSettings | undefined
		>();
		expectTypeOf<
			ProviderDeps<"oauthTokenSettings">["oauthTokenSettings"]
		>().toEqualTypeOf<OAuthTokenSettings>();
		expectTypeOf<OAuthTokenSettings["issuer"]>().toEqualTypeOf<string>();
		expectTypeOf<OAuthTokenSettings["accessTokenLifetime"]>().toEqualTypeOf<AccessTokenLifetime>();
		expectTypeOf<OAuthTokenSettings["refreshTokenExpiresIn"]>().toEqualTypeOf<number>();
		// The token-binding settings are core's: the slot has no member for
		// either.
		expectTypeOf<OAuthTokenSettings>().not.toHaveProperty("tokenBinding");
		// A token with no `typ` header is always refused: no member switches
		// that.
		expectTypeOf<OAuthTokenSettings>().not.toHaveProperty("legacyTypAccept");
		expectTypeOf<OAuthTokenSettings>().not.toHaveProperty("dispatchPolicy");
		expectTypeOf<OAuthTokenSettings>().not.toHaveProperty("bindConfidentialClientRefreshTokens");
		expectTypeOf<OAuthTokenSettings["resourceIndicatorEnabled"]>().toEqualTypeOf<boolean>();
		expectTypeOf<OAuthTokenSettings["requireEmailVerified"]>().toEqualTypeOf<boolean>();
		expect(true).toBe(true);
	});

	it("is filled by a module, and read by another", async () => {
		const settings = createTestOAuthTokenSettings();
		let seen: OAuthTokenSettings | undefined;
		const owner = defineModule({
			name: "test:token-settings-owner",
			provides: { oauthTokenSettings: () => settings },
		});
		const reader = defineModule({
			name: "test:token-settings-reader",
			requires: ["oauthTokenSettings"] as const,
			contributes: {
				routes: [
					(deps) => {
						seen = deps.oauthTokenSettings;
						return {
							id: "test-token-settings-reader",
							mountPath: "/__test_token_settings_reader__",
							handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
						};
					},
				],
			},
		});
		const handle = await createApp({
			modules: [owner, reader],
			bootstrapComponents: {
				config: makeValidCoreConfig(),
				pathResolver: (p: string) => p,
			} as never,
		});
		try {
			expect(seen).toEqual(settings);
		} finally {
			await handle.dispose();
		}
	});
});

describe("createTestOAuthTokenSettings", () => {
	it("answers the fixture configuration's settings, resolved: nothing absent, every switch off", () => {
		expect(createTestOAuthTokenSettings()).toStrictEqual({
			issuer: "https://auth.test",
			accessTokenLifetime: { defaultExpiresIn: 3600, maxExpiresIn: 3600 },
			refreshTokenExpiresIn: 86_400,
			resourceIndicatorEnabled: false,
			requireEmailVerified: false,
		});
	});

	it("applies an override, a nested one member by member", () => {
		const settings = createTestOAuthTokenSettings({
			accessTokenLifetime: { maxExpiresIn: 7200 },
		});
		expect(settings.accessTokenLifetime).toStrictEqual({
			defaultExpiresIn: 3600,
			maxExpiresIn: 7200,
		});
	});

	it("does not check what it is handed: a test of a broken value builds it here", () => {
		expect(createTestOAuthTokenSettings({ issuer: "not a url" }).issuer).toBe("not a url");
	});
});
