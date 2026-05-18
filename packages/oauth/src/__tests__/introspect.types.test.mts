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
import { extractConfirmation, type IntrospectResponse } from "../types/introspect.mjs";

describe("IntrospectResponse typed shape", () => {
	it("active response with no cnf", () => {
		const r: IntrospectResponse = {
			active: true,
			exp: 1700000000,
			iat: 1699999000,
			iss: "https://issuer.example",
			sub: "user-1",
			scope: "read",
			token_type: "Bearer",
		};
		expect(r.active).toBe(true);
		expect(r.cnf).toBeUndefined();
	});

	it("active response with DPoP cnf returns token_type=DPoP", () => {
		const r: IntrospectResponse = {
			active: true,
			exp: 1700000000,
			iat: 1699999000,
			iss: "https://issuer.example",
			sub: "user-1",
			scope: "read",
			token_type: "DPoP",
			cnf: { jkt: "abc123" },
		};
		expect(r.cnf).toEqual({ jkt: "abc123" });
		expect(r.token_type).toBe("DPoP");
	});

	it("active response with mTLS cnf keeps token_type=Bearer", () => {
		const r: IntrospectResponse = {
			active: true,
			cnf: { "x5t#S256": "def456" },
			token_type: "Bearer",
		};
		expect(r.cnf).toEqual({ "x5t#S256": "def456" });
		expect(r.token_type).toBe("Bearer");
	});

	it("inactive response omits everything except active=false", () => {
		const r: IntrospectResponse = { active: false };
		expect(r.active).toBe(false);
		expect(r.cnf).toBeUndefined();
		expect(r.token_type).toBeUndefined();
	});
});

describe("extractConfirmation", () => {
	it("returns jkt variant for a string jkt", () => {
		expect(extractConfirmation({ jkt: "abc" })).toEqual({ jkt: "abc" });
	});

	it("returns x5t#S256 variant for a string x5t#S256", () => {
		expect(extractConfirmation({ "x5t#S256": "def" })).toEqual({ "x5t#S256": "def" });
	});

	it("returns undefined for null / undefined / non-object", () => {
		expect(extractConfirmation(undefined)).toBeUndefined();
		expect(extractConfirmation(null)).toBeUndefined();
		expect(extractConfirmation("string")).toBeUndefined();
		expect(extractConfirmation(42)).toBeUndefined();
		expect(extractConfirmation(true)).toBeUndefined();
	});

	it("returns undefined for arrays", () => {
		expect(extractConfirmation([])).toBeUndefined();
		expect(extractConfirmation([{ jkt: "abc" }])).toBeUndefined();
	});

	it("returns undefined for an object missing both jkt and x5t#S256", () => {
		expect(extractConfirmation({})).toBeUndefined();
		expect(extractConfirmation({ other: "value" })).toBeUndefined();
	});

	it("rejects empty-string jkt (RFC 9449 §6 requires non-empty thumbprint)", () => {
		expect(extractConfirmation({ jkt: "" })).toBeUndefined();
	});

	it("rejects empty-string x5t#S256 (RFC 8705 §3 requires non-empty thumbprint)", () => {
		expect(extractConfirmation({ "x5t#S256": "" })).toBeUndefined();
	});

	it("rejects numeric jkt (malformed cnf — does not leak to RS)", () => {
		expect(extractConfirmation({ jkt: 123 })).toBeUndefined();
	});

	it("rejects numeric x5t#S256", () => {
		expect(extractConfirmation({ "x5t#S256": 456 })).toBeUndefined();
	});

	it("compound binding (both jkt and x5t#S256 valid) returns jkt — intent-explicit policy", () => {
		// Spec §1 declares compound binding out of scope for Stage 1.
		// If both are present (malformed / forged / future), jkt wins,
		// matching the intent-explicit dispatch policy (spec §3.5).
		expect(extractConfirmation({ jkt: "abc", "x5t#S256": "def" })).toEqual({ jkt: "abc" });
	});

	it("falls through to x5t#S256 when jkt is empty-string", () => {
		// jkt fails its non-empty guard, so the function continues to
		// the x5t check rather than returning undefined immediately.
		// Pins the documented fall-through behavior.
		expect(extractConfirmation({ jkt: "", "x5t#S256": "def" })).toEqual({
			"x5t#S256": "def",
		});
	});

	it("falls through to x5t#S256 when jkt is non-string", () => {
		expect(extractConfirmation({ jkt: 123, "x5t#S256": "def" })).toEqual({
			"x5t#S256": "def",
		});
	});
});
