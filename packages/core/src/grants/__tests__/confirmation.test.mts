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
