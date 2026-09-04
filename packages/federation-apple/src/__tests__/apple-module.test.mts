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
import { appleFederationModule } from "../apple.mjs";

describe("appleFederationModule const Module", () => {
	it("has the canonical module name 'federation:apple'", () => {
		expect(appleFederationModule.name).toBe("federation:apple");
	});

	it("requires appleFederationConfig", () => {
		expect(appleFederationModule.requires).toContain("appleFederationConfig");
	});

	it("contributes federations.apple as a factory", () => {
		expect(typeof appleFederationModule.contributes?.federations?.apple).toBe("function");
	});

	it("contributes federationRedirectPolicies.apple as a factory", () => {
		expect(typeof appleFederationModule.contributes?.federationRedirectPolicies?.apple).toBe(
			"function",
		);
	});

	it("produces provider.name == 'apple' (single-tenant invariant)", () => {
		// Single-tenant, as federation-google and federation-github are:
		// provider.name is fixed at "apple" and matches the contribution key,
		// which is what the route layer keys session state, callback URL and
		// redirect-policy lookup by.
		const factory = appleFederationModule.contributes?.federations?.apple;
		if (typeof factory !== "function") throw new Error("factory missing");
		const provider = factory({
			appleFederationConfig: {
				clientId: "com.example.app.service",
				clientSecret: "secret",
				callbackURL: "https://example.com/cb",
			},
		} as never) as { name: string };
		expect(provider.name).toBe("apple");
	});

	it("produces a provider that declares form_post, so the router mounts the POST callback", () => {
		const factory = appleFederationModule.contributes?.federations?.apple;
		if (typeof factory !== "function") throw new Error("factory missing");
		const provider = factory({
			appleFederationConfig: {
				clientId: "com.example.app.service",
				clientSecret: "secret",
				callbackURL: "https://example.com/cb",
			},
		} as never) as { responseMode?: string };
		expect(provider.responseMode).toBe("form_post");
	});
});
