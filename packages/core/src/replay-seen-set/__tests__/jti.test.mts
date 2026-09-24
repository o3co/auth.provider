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
import { isRecordableJti, MAX_JTI_LENGTH } from "#/index.mjs";

/**
 * A `jti` is a key in the shared seen-set, kept for as long as the credential
 * it names could be replayed. A presenter chooses it, so without a bound it
 * chooses how much each record costs.
 */
describe("isRecordableJti", () => {
	it("bounds a jti at 256 characters", () => {
		expect(MAX_JTI_LENGTH).toBe(256);
	});

	it("admits a non-empty string up to the bound", () => {
		expect(isRecordableJti("j")).toBe(true);
		expect(isRecordableJti(crypto.randomUUID())).toBe(true);
		expect(isRecordableJti("a".repeat(MAX_JTI_LENGTH))).toBe(true);
	});

	it("refuses one character past the bound, the empty string, and a value that is not a string", () => {
		expect(isRecordableJti("a".repeat(MAX_JTI_LENGTH + 1))).toBe(false);
		expect(isRecordableJti("")).toBe(false);
		for (const other of [undefined, null, 42, ["j"], { jti: "j" }]) {
			expect(isRecordableJti(other)).toBe(false);
		}
	});

	it("counts UTF-16 code units, the unit the seen-set's canonical key is measured in", () => {
		// "😀" is two code units: 128 of them is 256 units, 129 is past the bound.
		expect(isRecordableJti("😀".repeat(128))).toBe(true);
		expect(isRecordableJti("😀".repeat(129))).toBe(false);
	});
});
