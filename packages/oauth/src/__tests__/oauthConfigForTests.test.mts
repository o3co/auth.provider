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
 * `oauthConfigForTests`, on the package's testing entry: the `oauth` section
 * a test lays over a configuration, here its acr table and the access-token
 * lifetime.
 */

import { resolveAccessTokenLifetime } from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { resolveOAuthOptions } from "#/resolveOAuthOptions.mjs";
import { oauthConfigForTests } from "#/testing/index.mjs";

describe("oauthConfigForTests", () => {
	it("states no acr table unless given one", () => {
		expect(oauthConfigForTests().oauth).not.toHaveProperty("authorize");
	});

	it("lays the acr table given at oauth.authorize.acrValues, as a copy the router reads", () => {
		const alternatives = [["hwk"], ["swk"]];
		const table = { "urn:o3co:acr:mfa": ["pwd", "mfa"], "urn:o3co:acr:phr": alternatives };
		const fragment = oauthConfigForTests({ acrValues: table });
		expect(fragment.oauth.authorize).toEqual({ acrValues: table });
		expect(fragment.oauth.authorize?.acrValues["urn:o3co:acr:phr"]).not.toBe(alternatives);
		const config = { ...makeValidAppConfig(), ...fragment };
		expect(Object.keys(resolveOAuthOptions(config.oauth).acrValues)).toEqual(Object.keys(table));
	});

	it("lays accessTokenExpiresIn at oauth.accessToken.defaultExpiresIn, the lifetime every grant mints", () => {
		const fragment = oauthConfigForTests({ accessTokenExpiresIn: 900 });
		expect(fragment.oauth.accessToken).toEqual({ defaultExpiresIn: 900 });
		expect(resolveAccessTokenLifetime(fragment)).toEqual({
			defaultExpiresIn: 900,
			maxExpiresIn: 900,
		});
	});
});
