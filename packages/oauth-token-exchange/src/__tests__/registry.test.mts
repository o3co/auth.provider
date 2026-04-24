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
import { ExchangeTokenValidatorRegistry } from "#/validator/registry.mjs";
import type { ExchangeTokenValidator } from "#/validator/types.mjs";

const stubValidator = (): ExchangeTokenValidator => ({
	async validate() {
		return null;
	},
});

describe("ExchangeTokenValidatorRegistry", () => {
	it("returns undefined for unregistered token type", () => {
		const registry = new ExchangeTokenValidatorRegistry();
		expect(registry.get("urn:ietf:params:oauth:token-type:access_token")).toBeUndefined();
	});

	it("returns the registered validator by tokenType", () => {
		const registry = new ExchangeTokenValidatorRegistry();
		const v = stubValidator();
		registry.register("urn:ietf:params:oauth:token-type:access_token", v);
		expect(registry.get("urn:ietf:params:oauth:token-type:access_token")).toBe(v);
	});

	it("overwrites an existing registration on re-register", () => {
		const registry = new ExchangeTokenValidatorRegistry();
		const v1 = stubValidator();
		const v2 = stubValidator();
		registry.register("urn:ietf:params:oauth:token-type:access_token", v1);
		registry.register("urn:ietf:params:oauth:token-type:access_token", v2);
		expect(registry.get("urn:ietf:params:oauth:token-type:access_token")).toBe(v2);
	});

	it("register throws after freeze()", () => {
		const registry = new ExchangeTokenValidatorRegistry();
		registry.freeze();
		expect(() =>
			registry.register("urn:ietf:params:oauth:token-type:access_token", stubValidator()),
		).toThrow(/frozen/);
	});

	it("get() continues to work after freeze()", () => {
		const registry = new ExchangeTokenValidatorRegistry();
		const v = stubValidator();
		registry.register("urn:ietf:params:oauth:token-type:access_token", v);
		registry.freeze();
		expect(registry.get("urn:ietf:params:oauth:token-type:access_token")).toBe(v);
	});

	it("freeze() is idempotent", () => {
		const registry = new ExchangeTokenValidatorRegistry();
		registry.freeze();
		registry.freeze(); // no throw, no state change
		expect(() => registry.register("x", stubValidator())).toThrow(/frozen/);
	});
});
