/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * Issue #297 — the optional gate. A deployment may require a verified email
 * before tokens are issued for an end-user subject. The Store still owns the
 * verification flow; this only reads the result it published.
 */

import { describe, expect, it } from "vitest";
import { isEmailVerified } from "#/grants/emailVerifiedGate.mjs";

describe("isEmailVerified", () => {
	it("accepts exactly boolean true", () => {
		expect(isEmailVerified({ id: "u", username: "u", emailVerified: true })).toBe(true);
	});

	it("rejects false", () => {
		expect(isEmailVerified({ id: "u", username: "u", emailVerified: false })).toBe(false);
	});

	it("rejects absence — a Store that does not model it has not verified anything", () => {
		expect(isEmailVerified({ id: "u", username: "u" })).toBe(false);
	});

	it("rejects a truthy non-boolean", () => {
		// The gate decides whether to issue a token. A Store reached across an
		// untyped boundary returning the string "true" must not open it.
		for (const value of ["true", "yes", 1, {}, []]) {
			expect(isEmailVerified({ id: "u", username: "u", emailVerified: value } as never)).toBe(
				false,
			);
		}
	});

	it("rejects a missing user outright", () => {
		expect(isEmailVerified(undefined)).toBe(false);
		expect(isEmailVerified(null)).toBe(false);
	});
});
