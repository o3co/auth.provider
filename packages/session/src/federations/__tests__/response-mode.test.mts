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

import { describe, expect, it } from "vitest";
import {
	DEFAULT_FEDERATION_RESPONSE_MODE,
	FEDERATION_RESPONSE_MODES,
	resolveFederationResponseMode,
} from "#/federations/response-mode.mjs";
import type { FederationProvider } from "#/federations/types.mjs";

const makeProvider = (overrides: Partial<FederationProvider> = {}): FederationProvider =>
	({
		name: "test",
		scope: ["openid"],
		buildAuthorizationUrl: () => new URL("https://idp.example.com/authorize"),
		exchangeCode: async () => ({
			issuer: "https://idp.example.com",
			sub: "s",
			expiresAt: null,
		}),
		...overrides,
	}) as FederationProvider;

describe("federation response mode", () => {
	it("names exactly the two modes the framework understands", () => {
		expect([...FEDERATION_RESPONSE_MODES]).toEqual(["query", "form_post"]);
	});

	it("defaults to 'query' so every pre-existing provider keeps the GET callback", () => {
		expect(DEFAULT_FEDERATION_RESPONSE_MODE).toBe("query");
		expect(resolveFederationResponseMode(makeProvider())).toBe("query");
	});

	it("honours a provider that declares form_post", () => {
		expect(resolveFederationResponseMode(makeProvider({ responseMode: "form_post" }))).toBe(
			"form_post",
		);
	});

	it("treats an unknown declared mode as the default rather than trusting it", () => {
		// The adapter boundary is untyped at runtime (A2 adapter contract): a
		// provider compiled against an older/newer contract must not be able to
		// push an unrecognised token into the authorization request.
		expect(resolveFederationResponseMode(makeProvider({ responseMode: "fragment" } as never))).toBe(
			"query",
		);
	});
});
