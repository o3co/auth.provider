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
 * What the package barrel exports of session admission (the session-admission
 * ADR's D1): the consumers' surface — the decision, the claim builders, the
 * establishment, `checkResolver` for a consumer factory built by hand, the
 * checks a store runs — and none of boot's internals: registration, the
 * seal, the continuation builders are core's own.
 */

import { describe, expect, it } from "vitest";
import * as core from "#/index.mjs";

describe("the barrel's session-admission surface", () => {
	it("exports checkResolver, so a consumer factory outside core throws on a missing or forged resolver", () => {
		expect(typeof core.checkResolver).toBe("function");
		expect(() => core.checkResolver(undefined)).toThrow(RangeError);
		expect(() =>
			core.checkResolver({ get: () => undefined, entries: () => [][Symbol.iterator]() }),
		).toThrow(RangeError);
	});

	it("does not export boot's internals: registration, the seal and the continuation builders", () => {
		for (const internal of [
			"registeredRequirement",
			"sealRegisteredReach",
			"continuationOf",
			"primaryFromDto",
			"additionsFromDto",
		]) {
			expect(Object.hasOwn(core, internal), internal).toBe(false);
		}
	});
});
