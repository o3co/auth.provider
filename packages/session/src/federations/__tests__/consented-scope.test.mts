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
import { consentedScope } from "../consented-scope.mjs";

describe("consentedScope (#647)", () => {
	it("takes what the upstream answered when it names a scope", () => {
		// RFC 6749 section 5.1 makes the field REQUIRED when the granted scope
		// differs from the requested one, so a named scope is what was granted.
		expect(consentedScope("openid", ["openid", "email"])).toBe("openid");
	});

	it("reads silence as the requested scope, not as no scope", () => {
		// Section 3.3 makes the answer optional ONLY when it matches the request.
		// Three of the four bundled adapters say nothing, and reading that as "no
		// scope" would leave the record with no ceiling at all.
		expect(consentedScope(undefined, ["openid", "email"])).toBe("openid email");
	});

	it.each([
		["an empty string", ""],
		["whitespace only", "   "],
		["a number", 42],
		["null", null],
		["an object", {}],
	])("claims nothing when the adapter answers %s, rather than falling back", (_label, answered) => {
		// Present is not absent, whatever it says. The upstream spoke and named
		// nothing this route can use, so reading it as silence would record every
		// REQUESTED scope as consent on a response that granted none — fail-open,
		// on the write that sets the ceiling for the life of the connection.
		// `@o3co/auth-provider-federation-oidc` keeps an empty scope on its
		// delegated exchange for the same reason.
		expect(consentedScope(answered, ["openid"])).toBeUndefined();
	});

	it("falls back only when the field is not there at all", () => {
		expect(consentedScope(undefined, ["openid"])).toBe("openid");
	});

	it("answers undefined when neither the upstream nor the provider names one", () => {
		expect(consentedScope(undefined, [])).toBeUndefined();
		expect(consentedScope("  ", undefined)).toBeUndefined();
	});

	it("answers a canonical form, so spacing and repeats cannot become the ceiling", () => {
		expect(consentedScope("  openid   email  openid ", [])).toBe("openid email");
		expect(consentedScope(undefined, ["openid", "email", "openid"])).toBe("openid email");
	});

	it("ignores an entry the requested list should not contain", () => {
		// The list is typed `readonly string[]`, but a provider is a third-party
		// extension point and the type is not a runtime guarantee — which is what
		// D5 is about. Both branches have to survive what the type forbids.
		expect(consentedScope(undefined, ["openid", "", "email"])).toBe("openid email");
		expect(consentedScope(undefined, ["openid", 42, null, {}] as unknown as string[])).toBe(
			"openid",
		);
	});

	it("parses the requested list rather than merely filtering it", () => {
		// An entry may itself be a space-delimited list, or whitespace. A rule the
		// answered branch keeps and this one drops would write a ceiling that only
		// survives because the consumer re-parses it defensively.
		expect(consentedScope(undefined, ["openid email", "openid"])).toBe("openid email");
		expect(consentedScope(undefined, ["   "])).toBeUndefined();
	});
});
