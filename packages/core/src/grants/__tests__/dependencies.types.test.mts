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

import { describe, expect, expectTypeOf, it } from "vitest";
import type { ComponentMap } from "../../modules/manifest/component-map.mjs";
import type { ProviderDeps } from "../../modules/manifest/provider.mjs";
import type { GrantDependencies } from "../types.mjs";

// #626 P2 (D4): `GrantDependencies` is the one statement of what a grant may
// depend on, and every entry in it is a `ComponentMap` slot carrying that
// slot's type. A grant factory narrows it with `Pick<GrantDependencies, …>`
// to the slots it reads; a module's `ProviderDeps<R, O>` has to satisfy that
// pick at the wiring, which is how "an implementation uses only what it
// declared" is checked rather than trusted. These assertions only fire under
// vitest's typecheck mode (this file is in both typecheck include lists).

/** The slots a bundled grant may read — the common set, in ComponentMap terms. */
type GrantSlots = ProviderDeps<
	"config" | "keyStore",
	| "refreshTokenFamilyRotation"
	| "refreshTokenFamilyRevocation"
	| "grantPolicy"
	| "userSessionStore"
	| "sessionRPRegistry"
	| "sessionFamilyIndex"
	| "sessionFederationIndex"
	| "subjectRevocation"
	| "logger"
>;

describe("GrantDependencies is defined on ComponentMap slots (#626 P2)", () => {
	it("is exactly ProviderDeps of the slots a grant may read", () => {
		// `.branded` because ProviderDeps is an intersection of two mapped
		// types (see modules/manifest/__tests__/provider.test.mts).
		expectTypeOf<GrantDependencies>().branded.toEqualTypeOf<GrantSlots>();
		expect(true).toBe(true);
	});

	it("types `config` as the `config` slot, not as a CoreConfig widened by an index signature", () => {
		expectTypeOf<GrantDependencies["config"]>().toEqualTypeOf<
			NonNullable<ComponentMap["config"]>
		>();
		expect(true).toBe(true);
	});

	it("carries no slot that no grant reads", () => {
		// `pathResolver` was declared here and read by no grant, so a grant
		// could have depended on it without any module declaring it.
		expectTypeOf<GrantDependencies>().not.toHaveProperty("pathResolver");
		expect(true).toBe(true);
	});

	it("is satisfied by a module declaring the same slots, and not by one declaring fewer", () => {
		expectTypeOf<GrantSlots>().toMatchTypeOf<GrantDependencies>();
		// A module that never declared `keyStore` cannot hand its deps to a grant.
		expectTypeOf<ProviderDeps<"config", "logger">>().not.toMatchTypeOf<GrantDependencies>();
		expect(true).toBe(true);
	});
});
