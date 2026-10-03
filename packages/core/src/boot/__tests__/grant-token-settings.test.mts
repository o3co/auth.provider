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
 * A grant reads the oauth module's token settings from `GrantDependencies`'
 * `oauthTokenSettings`, not from `config`: boot hands a grant factory the
 * slot's value when its module declares the slot and the composition holds
 * it, and nothing when the composition does not.
 */

import { describe, expect, it } from "vitest";
import type { GrantDependencies, GrantHandler } from "../../grants/types.mjs";
import { createApp } from "../../index.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createTestOAuthTokenSettings } from "../../testing/slots/oauthTokenSettings.mjs";
import { checkOAuthTokenSettings } from "../../token-settings/check.mjs";
import type { OAuthTokenSettings } from "../../token-settings/types.mjs";

const GRANT_TYPE = "urn:test:token-settings";

/** A grant module whose grant records what its factory was handed. */
const grantModule = (seen: Array<OAuthTokenSettings | undefined>) => {
	const grant = (deps: Pick<GrantDependencies, "oauthTokenSettings">): GrantHandler => {
		seen.push(
			deps.oauthTokenSettings === undefined
				? undefined
				: checkOAuthTokenSettings(deps.oauthTokenSettings),
		);
		return { handle: async () => ({ result: { status: 200, tokens: {} as never } }) };
	};
	return defineModule({
		name: "test:token-settings-grant",
		optional: ["oauthTokenSettings"],
		contributes: { grants: { [GRANT_TYPE]: grant } },
	});
};

describe("a grant reads oauthTokenSettings from its dependencies", () => {
	it("is handed the slot's value when the composition holds it", async () => {
		const settings = createTestOAuthTokenSettings({ issuer: "https://auth.example.com/grant" });
		const seen: Array<OAuthTokenSettings | undefined> = [];
		const handle = await createApp({
			modules: [grantModule(seen)],
			bootstrapComponents: {
				config: makeValidCoreConfig(),
				pathResolver: (p: string) => p,
				oauthTokenSettings: settings,
			} as never,
		});
		expect(seen).toEqual([settings]);
		expect(handle.components.grantHandlerResolver?.get(GRANT_TYPE)).toBeDefined();
		await handle.dispose();
	});

	it("is handed nothing when the composition holds no slot", async () => {
		const seen: Array<OAuthTokenSettings | undefined> = [];
		const handle = await createApp({
			modules: [grantModule(seen)],
			bootstrapComponents: {
				config: makeValidCoreConfig(),
				pathResolver: (p: string) => p,
			} as never,
		});
		expect(seen).toEqual([undefined]);
		await handle.dispose();
	});
});
