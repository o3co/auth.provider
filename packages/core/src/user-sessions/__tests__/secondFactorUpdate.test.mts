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
 * The step-up capability (the MFA ADR's D9): detected by method presence, as
 * `supportsSessionsOnlyRevocation` is, so a custom `UserSessionStore` written
 * without it keeps working — the MFA flow asks for a re-authentication
 * instead. The bundled memory store has it, and says so in its type. What it
 * does is the shared contract's (`userSessionStore.contract.mts`).
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import { createInMemoryUserSessionStore } from "#/user-sessions/memory/userSessionStore.mjs";
import {
	type SupportsSecondFactorUpdate,
	supportsSecondFactorUpdate,
	type UserSessionStore,
} from "#/user-sessions/types.mjs";

const base: UserSessionStore = {
	kind: "custom",
	create: async () => {},
	get: async () => null,
	delete: async () => {},
};

describe("supportsSecondFactorUpdate — the step-up capability, by method presence", () => {
	it("is false for a store written without it", () => {
		expect(supportsSecondFactorUpdate(base)).toBe(false);
	});

	it("is false for a recordSecondFactor that is not a function", () => {
		expect(
			supportsSecondFactorUpdate({
				...base,
				recordSecondFactor: true,
			} as unknown as UserSessionStore),
		).toBe(false);
	});

	it("is false for no store at all, so a slot's value can be passed straight in", () => {
		expect(supportsSecondFactorUpdate(undefined)).toBe(false);
		expect(supportsSecondFactorUpdate(null)).toBe(false);
	});

	it("is true for a store that has it, and narrows to it", () => {
		const store: UserSessionStore = {
			...base,
			recordSecondFactor: async () => null,
		} as UserSessionStore;
		expect(supportsSecondFactorUpdate(store)).toBe(true);
		if (supportsSecondFactorUpdate(store)) {
			expectTypeOf(store.recordSecondFactor).toEqualTypeOf<
				SupportsSecondFactorUpdate["recordSecondFactor"]
			>();
		}
	});

	it("is true for the bundled memory store, whose type says so", () => {
		const store = createInMemoryUserSessionStore();
		expect(supportsSecondFactorUpdate(store)).toBe(true);
		expectTypeOf(store).toMatchTypeOf<UserSessionStore & SupportsSecondFactorUpdate>();
	});
});
