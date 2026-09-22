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
 * The test that tells the two ways of owning the contribution type apart
 * (#626 P1).
 *
 * This package peers on `@o3co/auth-provider-core` and must never acquire
 * `@o3co/auth-provider-session` — there is no session import in this file on
 * purpose. If the concrete `FederationProvider` were reached by a `declare
 * module` augmentation that session ships, this file would see `unknown`,
 * because nothing here loads session's augmentation. It sees the contract
 * because core owns it.
 */
import type { ComponentMap, FederationProvider } from "@o3co/auth-provider-core";
import { describe, expect, expectTypeOf, it } from "vitest";

describe("#626 P1: the federation contract reaches this package from core alone", () => {
	it("is not `unknown` here", () => {
		expectTypeOf<FederationProvider>().not.toEqualTypeOf<unknown>();
		expect(true).toBe(true);
	});

	it("carries what a consumer of the map reads", () => {
		expectTypeOf<FederationProvider>().toHaveProperty("name");
		expectTypeOf<FederationProvider>().toHaveProperty("scope");
		expectTypeOf<FederationProvider>().toHaveProperty("buildAuthorizationUrl");
		expectTypeOf<FederationProvider>().toHaveProperty("exchangeCode");
		expect(true).toBe(true);
	});

	it("is the value type of the `federationProviders` slot", () => {
		type Slot = NonNullable<ComponentMap["federationProviders"]>;
		expectTypeOf<Slot>().toEqualTypeOf<ReadonlyMap<string, FederationProvider>>();
		expect(true).toBe(true);
	});
});
