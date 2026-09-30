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
 * The session-end capability of `SessionFamilyIndex`: detected by method
 * presence, so an index written without it keeps working. What it does is the
 * shared contract's (`sessionFamilyIndex.contract.mts`).
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import { createInMemorySessionFamilyIndex } from "#/user-sessions/memory/sessionFamilyIndex.mjs";
import {
	type SessionFamilyIndex,
	type SupportsSessionEnd,
	supportsSessionEnd,
} from "#/user-sessions/types.mjs";

const base: SessionFamilyIndex = {
	kind: "custom",
	addFamilyId: async () => {},
	listFamilyIds: async () => [],
	removeBySid: async () => {},
};

describe("supportsSessionEnd — the session-end capability, by method presence", () => {
	it("is false for an index written without it", () => {
		expect(supportsSessionEnd(base)).toBe(false);
	});

	it("is false for an index with one of the two methods: both, or neither", () => {
		expect(
			supportsSessionEnd({ ...base, endSession: async () => [] } as unknown as SessionFamilyIndex),
		).toBe(false);
		expect(
			supportsSessionEnd({
				...base,
				addFamilyIdUnlessEnded: async () => "added",
			} as unknown as SessionFamilyIndex),
		).toBe(false);
	});

	it("is false for methods that are not functions", () => {
		expect(
			supportsSessionEnd({
				...base,
				endSession: true,
				addFamilyIdUnlessEnded: true,
			} as unknown as SessionFamilyIndex),
		).toBe(false);
	});

	it("is false for no index at all, so a slot's value can be passed straight in", () => {
		expect(supportsSessionEnd(undefined)).toBe(false);
		expect(supportsSessionEnd(null)).toBe(false);
	});

	it("is true for an index that has both, and narrows to it", () => {
		const index = {
			...base,
			endSession: async () => [],
			addFamilyIdUnlessEnded: async () => "added",
		} as SessionFamilyIndex;
		expect(supportsSessionEnd(index)).toBe(true);
		if (supportsSessionEnd(index)) {
			expectTypeOf(index.endSession).toEqualTypeOf<SupportsSessionEnd["endSession"]>();
			expectTypeOf(index.addFamilyIdUnlessEnded).toEqualTypeOf<
				SupportsSessionEnd["addFamilyIdUnlessEnded"]
			>();
		}
	});

	it("is true for the bundled memory index, whose type says so", () => {
		const index = createInMemorySessionFamilyIndex();
		expect(supportsSessionEnd(index)).toBe(true);
		expectTypeOf(index).toMatchTypeOf<SessionFamilyIndex & SupportsSessionEnd>();
	});

	it("answers the two outcomes of an add, and the families an end lists", () => {
		expectTypeOf<SupportsSessionEnd["endSession"]>().toEqualTypeOf<
			(sid: string, expiresAt: Date) => Promise<ReadonlyArray<string>>
		>();
		expectTypeOf<SupportsSessionEnd["addFamilyIdUnlessEnded"]>().toEqualTypeOf<
			(sid: string, familyId: string, expiresAt: Date) => Promise<"added" | "ended">
		>();
	});
});
