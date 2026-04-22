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
import { supportsLock } from "../types.mjs";

describe("supportsLock type guard", () => {
	it("returns false for null / undefined", () => {
		expect(supportsLock(null)).toBe(false);
		expect(supportsLock(undefined)).toBe(false);
	});

	it("returns false for a store without acquireLock method", () => {
		const store = {
			kind: "test",
			get: async () => null,
			attach: async () => {},
			delete: async () => {},
			update: async () => {},
			deleteBySession: async () => {},
		};
		expect(supportsLock(store as any)).toBe(false);
	});

	it("returns true for a store with acquireLock method", () => {
		const store = {
			kind: "test",
			get: async () => null,
			attach: async () => {},
			delete: async () => {},
			update: async () => {},
			deleteBySession: async () => {},
			acquireLock: async () => ({ acquired: true as const, release: async () => {} }),
		};
		expect(supportsLock(store as any)).toBe(true);
	});
});
