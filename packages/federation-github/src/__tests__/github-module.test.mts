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
import { githubFederationModule } from "../github.mjs";

describe("githubFederationModule const Module", () => {
	it("has the canonical module name 'federation:github'", () => {
		expect(githubFederationModule.name).toBe("federation:github");
	});

	it("requires githubFederationConfig", () => {
		expect(githubFederationModule.requires).toContain("githubFederationConfig");
	});

	it("contributes federations.github as a factory", () => {
		expect(typeof githubFederationModule.contributes?.federations?.github).toBe("function");
	});

	it("contributes federationRedirectPolicies.github as a factory", () => {
		expect(typeof githubFederationModule.contributes?.federationRedirectPolicies?.github).toBe(
			"function",
		);
	});
});
