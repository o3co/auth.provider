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
 * What `MfaFactorStore` requires of a store: the factor set's members
 * `listVersioned`, `createIf` and `removeIf` are part of the port, so a store
 * without one of them does not compile. These are type assertions: the file
 * is in core's typecheck list.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import type {
	ConditionalCreateAnswer,
	ConditionalSetRemoveAnswer,
	StoreGeneration,
	VersionedSet,
} from "#/adapters/conditionalWrite.mjs";
import type { MfaFactorRecord, MfaFactorStore } from "#/mfa/factorStore.mjs";
import { createMemoryMfaFactorStore } from "#/mfa/memoryFactorStore.mjs";

/** `store` where an `MfaFactorStore` is asked for. */
const asStore = (store: MfaFactorStore): MfaFactorStore => store;

describe("the MfaFactorStore port", () => {
	it("requires listVersioned, createIf and removeIf, each with its signature", () => {
		expectTypeOf<MfaFactorStore["listVersioned"]>().toEqualTypeOf<
			(subject: string) => Promise<VersionedSet<MfaFactorRecord>>
		>();
		expectTypeOf<MfaFactorStore["createIf"]>().toEqualTypeOf<
			(
				record: MfaFactorRecord,
				expected: StoreGeneration | null,
			) => Promise<ConditionalCreateAnswer>
		>();
		expectTypeOf<MfaFactorStore["removeIf"]>().toEqualTypeOf<
			(
				subject: string,
				id: string,
				expected: StoreGeneration,
			) => Promise<ConditionalSetRemoveAnswer>
		>();
		expect(asStore(createMemoryMfaFactorStore()).kind).toBe("memory");
	});

	it("refuses a store without one of the three", () => {
		// @ts-expect-error listVersioned is required
		asStore({} as Omit<MfaFactorStore, "listVersioned">);
		// @ts-expect-error createIf is required
		asStore({} as Omit<MfaFactorStore, "createIf">);
		// @ts-expect-error removeIf is required
		asStore({} as Omit<MfaFactorStore, "removeIf">);
		expect(true).toBe(true);
	});
});
