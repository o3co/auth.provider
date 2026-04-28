/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import { canonicalKey } from "../canonical-key.mjs";

describe("canonicalKey", () => {
	it("encodes scope and value with length prefixes (delimiter-collision safe)", () => {
		expect(canonicalKey("ab", "cd")).toBe("2:ab|2:cd");
		expect(canonicalKey("abcd", "")).toBe("4:abcd|0:");
		expect(canonicalKey("", "abcd")).toBe("0:|4:abcd");
	});

	it("(scope='ab', value='cd') and (scope='abcd', value='') do NOT collide", () => {
		expect(canonicalKey("ab", "cd")).not.toBe(canonicalKey("abcd", ""));
	});

	it("uses JS UTF-16 code-unit length for prefixes", () => {
		// 4-byte UTF-8 characters such as `𝑥` (U+1D465) take 2 UTF-16 code units.
		expect(canonicalKey("𝑥", "")).toBe("2:𝑥|0:");
	});
});
