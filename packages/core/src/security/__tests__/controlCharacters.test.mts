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
 * `hasControlCharacter`: the one reading of "a control character" in text an
 * operator configures — an issuer, a label, a header — C0, DEL and C1, but
 * those a rule allows (a text's line breaks).
 */

import { describe, expect, it } from "vitest";
import { hasControlCharacter } from "#/index.mjs";

describe("hasControlCharacter", () => {
	it("finds a C0 control character, DEL and a C1 control character anywhere in the text", () => {
		for (const text of [
			"\u0000",
			"a\u001fb",
			"a\rb",
			"a\nb",
			"\t",
			"a\u007f",
			"\u0080b",
			"a\u009fb",
		]) {
			expect(hasControlCharacter(text), JSON.stringify(text)).toBe(true);
		}
	});

	it("finds none in printable text, a space, other Unicode or a lone surrogate", () => {
		for (const text of ["", "plain text", " ", " ", "日本語", "😀", "\ud800"]) {
			expect(hasControlCharacter(text), JSON.stringify(text)).toBe(false);
		}
	});

	it("passes over the characters a rule allows, and only those", () => {
		const layout = new Set(["\n", "\t"]);
		expect(hasControlCharacter("line\n\tnext", layout)).toBe(false);
		expect(hasControlCharacter("line\r\nnext", layout)).toBe(true);
	});
});
