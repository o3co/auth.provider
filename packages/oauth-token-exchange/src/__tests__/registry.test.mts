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
	ExchangeTokenValidatorRegistry,
	ExchangeTokenValidatorRegistryError,
} from "#/validator/registry.mjs";
import type { ExchangeTokenValidator } from "#/validator/types.mjs";

const stubValidator = (): ExchangeTokenValidator => ({
	async validate() {
		return null;
	},
});

const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

describe("ExchangeTokenValidatorRegistry — basic registration", () => {
	it("returns undefined for unregistered token type", () => {
		const registry = new ExchangeTokenValidatorRegistry();
		expect(registry.get(ACCESS_TOKEN_TYPE)).toBeUndefined();
	});

	it("returns the registered validator by tokenType", () => {
		const registry = new ExchangeTokenValidatorRegistry();
		const v = stubValidator();
		registry.register(ACCESS_TOKEN_TYPE, v);
		expect(registry.get(ACCESS_TOKEN_TYPE)).toBe(v);
	});
});

describe("ExchangeTokenValidatorRegistry.register (A6+A7 §2.1: throw on duplicate)", () => {
	it("throws ExchangeTokenValidatorRegistryError reason='duplicate' on duplicate (REGARDLESS of freeze state)", () => {
		const registry = new ExchangeTokenValidatorRegistry();
		const v1 = stubValidator();
		registry.register(ACCESS_TOKEN_TYPE, v1);
		let caught: unknown;
		try {
			registry.register(ACCESS_TOKEN_TYPE, stubValidator());
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(ExchangeTokenValidatorRegistryError);
		if (caught instanceof ExchangeTokenValidatorRegistryError) {
			expect(caught.reason).toBe("duplicate");
			expect(caught.tokenType).toBe(ACCESS_TOKEN_TYPE);
		}
		// Original registration is preserved (no silent overwrite).
		expect(registry.get(ACCESS_TOKEN_TYPE)).toBe(v1);
	});

	it("throws reason='frozen' on a frozen registry (post-freeze register attempt)", () => {
		const registry = new ExchangeTokenValidatorRegistry();
		registry.freeze();
		let caught: unknown;
		try {
			registry.register(ACCESS_TOKEN_TYPE, stubValidator());
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(ExchangeTokenValidatorRegistryError);
		if (caught instanceof ExchangeTokenValidatorRegistryError) {
			expect(caught.reason).toBe("frozen");
		}
	});
});

describe("ExchangeTokenValidatorRegistry.replace (A6+A7 §2.2: explicit override)", () => {
	it("overwrites a registered validator (happy path)", () => {
		const registry = new ExchangeTokenValidatorRegistry();
		const original = stubValidator();
		const replacement = stubValidator();
		registry.register(ACCESS_TOKEN_TYPE, original);
		registry.replace(ACCESS_TOKEN_TYPE, replacement);
		expect(registry.get(ACCESS_TOKEN_TYPE)).toBe(replacement);
	});

	it("throws reason='unknown' when name is not registered", () => {
		const registry = new ExchangeTokenValidatorRegistry();
		let caught: unknown;
		try {
			registry.replace("urn:absent", stubValidator());
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(ExchangeTokenValidatorRegistryError);
		if (caught instanceof ExchangeTokenValidatorRegistryError) {
			expect(caught.reason).toBe("unknown");
			expect(caught.tokenType).toBe("urn:absent");
			expect(caught.registered).toEqual([]);
		}
	});

	it("throws reason='frozen' on a frozen registry", () => {
		const registry = new ExchangeTokenValidatorRegistry();
		registry.register(ACCESS_TOKEN_TYPE, stubValidator());
		registry.freeze();
		let caught: unknown;
		try {
			registry.replace(ACCESS_TOKEN_TYPE, stubValidator());
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(ExchangeTokenValidatorRegistryError);
		if (caught instanceof ExchangeTokenValidatorRegistryError) {
			expect(caught.reason).toBe("frozen");
		}
	});
});

describe("ExchangeTokenValidatorRegistry.freeze (A6+A7 §2.3: activation boundary)", () => {
	it("get() continues to work after freeze()", () => {
		const registry = new ExchangeTokenValidatorRegistry();
		const v = stubValidator();
		registry.register(ACCESS_TOKEN_TYPE, v);
		registry.freeze();
		expect(registry.get(ACCESS_TOKEN_TYPE)).toBe(v);
	});

	it("freeze() is idempotent", () => {
		const registry = new ExchangeTokenValidatorRegistry();
		registry.freeze();
		expect(() => registry.freeze()).not.toThrow();
	});
});

describe("ExchangeTokenValidatorRegistryError (A6+A7 §2.4: error class shape)", () => {
	it("carries reason, tokenType, and registered snapshot", () => {
		const err = new ExchangeTokenValidatorRegistryError({
			reason: "duplicate",
			tokenType: "urn:foo",
			registered: ["urn:foo", "urn:bar"],
		});
		expect(err.reason).toBe("duplicate");
		expect(err.tokenType).toBe("urn:foo");
		expect(err.registered).toEqual(["urn:foo", "urn:bar"]);
		expect(err.name).toBe("ExchangeTokenValidatorRegistryError");
		expect(err.message).toContain("duplicate");
		expect(err.message).toContain("urn:foo");
	});

	it("formats unknown-reason message", () => {
		const err = new ExchangeTokenValidatorRegistryError({
			reason: "unknown",
			tokenType: "urn:absent",
			registered: [],
		});
		expect(err.message).toContain("unknown");
	});

	it("formats frozen-reason message", () => {
		const err = new ExchangeTokenValidatorRegistryError({
			reason: "frozen",
			tokenType: "urn:foo",
			registered: ["urn:foo"],
		});
		expect(err.message).toContain("frozen");
	});
});
