/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import { describe, expect, it } from "vitest";
import type { Confirmation } from "#/grants/confirmation.mjs";
import type { TokenBinding } from "#/grants/tokenBinding.mjs";

describe("Confirmation union", () => {
	it("accepts jkt variant", () => {
		const c: Confirmation = { jkt: "abc123" };
		expect("jkt" in c).toBe(true);
	});

	it("accepts x5t#S256 variant", () => {
		const c: Confirmation = { "x5t#S256": "def456" };
		expect("x5t#S256" in c).toBe(true);
	});

	it("rejects unknown confirmation keys at compile time (Confirmation is closed)", () => {
		// Compile-time guard: if someone widens Confirmation to a permissive
		// index signature, the @ts-expect-error becomes unused and this test
		// will fail to compile. Stage 1 confirmation kinds are core-owned per
		// spec §4.2 (RFC 7800 / IANA registry domain).
		// @ts-expect-error — `foo` is not a valid Confirmation variant
		const _bad: Confirmation = { foo: "bar" };
		void _bad;
	});
});

describe("TokenBinding base interface", () => {
	it("requires kind + confirmation", () => {
		const tb: TokenBinding = {
			kind: "test",
			confirmation: { jkt: "abc" },
		};
		expect(tb.kind).toBe("test");
		expect(tb.confirmation).toEqual({ jkt: "abc" });
	});

	it("supports downstream extension (extends with new kind + fields)", () => {
		interface FakeTokenBinding extends TokenBinding {
			readonly kind: "fake";
			readonly extra: string;
		}
		const tb: FakeTokenBinding = {
			kind: "fake",
			confirmation: { jkt: "xyz" },
			extra: "downstream-data",
		};
		expect(tb.kind).toBe("fake");
		expect(tb.extra).toBe("downstream-data");
	});
});
