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
import { googleFederationModule } from "../google.mjs";

describe("googleFederationModule const Module", () => {
	it("has the canonical module name 'federation:google'", () => {
		expect(googleFederationModule.name).toBe("federation:google");
	});

	it("requires googleFederationConfig", () => {
		expect(googleFederationModule.requires).toContain("googleFederationConfig");
	});

	it("contributes federations.google as a factory", () => {
		expect(typeof googleFederationModule.contributes?.federations?.google).toBe("function");
	});

	it("contributes federationRedirectPolicies.google as a factory", () => {
		expect(typeof googleFederationModule.contributes?.federationRedirectPolicies?.google).toBe(
			"function",
		);
	});

	it("produces provider.name == 'google' (single-tenant invariant)", () => {
		// v0.5.0 single-tenant: provider.name is fixed at "google", matching
		// the contribution key. The route layer keys session state / callback
		// URL / redirect-policy lookup by provider.name; no consumer-supplied
		// name can divert it. Multi-tenant support is deferred post-publish.
		const factory = googleFederationModule.contributes?.federations?.google;
		if (typeof factory !== "function") throw new Error("factory missing");
		const provider = factory({
			googleFederationConfig: {
				clientId: "abc",
				clientSecret: "xyz",
				callbackURL: "https://example.com/cb",
			},
		} as never);
		expect(provider.name).toBe("google");
	});
});
