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
import {
	extractConfirmation,
	isCompoundConfirmation,
	matchConfirmation,
	ownedConfirmation,
} from "#/grants/confirmationMatch.mjs";
import type { TokenBinding } from "#/grants/tokenBinding.mjs";

const dpopBinding = (jkt: string): TokenBinding => ({ kind: "dpop", confirmation: { jkt } });
const mtlsBinding = (thumbprint: string): TokenBinding => ({
	kind: "mtls",
	confirmation: { "x5t#S256": thumbprint },
});

describe("matchConfirmation — absent cnf (row 1/2 of each matrix)", () => {
	it("is unbound for a missing cnf, with or without a presented binding", () => {
		expect(matchConfirmation(undefined, undefined)).toEqual({ status: "unbound" });
		expect(matchConfirmation(undefined, dpopBinding("abc"))).toEqual({ status: "unbound" });
		expect(matchConfirmation(undefined, mtlsBinding("abc"))).toEqual({ status: "unbound" });
	});

	it("is unbound for a non-object cnf rather than crashing", () => {
		expect(matchConfirmation(null, undefined)).toEqual({ status: "unbound" });
		expect(matchConfirmation("cnf", undefined)).toEqual({ status: "unbound" });
		expect(matchConfirmation(42, undefined)).toEqual({ status: "unbound" });
		expect(matchConfirmation(["jkt"], dpopBinding("abc"))).toEqual({ status: "unbound" });
	});

	it("is unbound for a cnf that names no known binding member", () => {
		expect(matchConfirmation({}, undefined)).toEqual({ status: "unbound" });
		expect(matchConfirmation({ kid: "other" }, dpopBinding("abc"))).toEqual({
			status: "unbound",
		});
	});

	it("is unbound for junk members (empty-string or non-string thumbprints)", () => {
		// RFC 9449 §6 / RFC 8705 §3 define both thumbprints as non-empty
		// base64url strings; a cnf that fails that is junk, not a binding.
		expect(matchConfirmation({ jkt: "" }, undefined)).toEqual({ status: "unbound" });
		expect(matchConfirmation({ jkt: 42 }, dpopBinding("abc"))).toEqual({ status: "unbound" });
		expect(matchConfirmation({ "x5t#S256": "" }, mtlsBinding("abc"))).toEqual({
			status: "unbound",
		});
	});
});

describe("matchConfirmation — jkt member (DPoP matrix rows 3-5)", () => {
	it("is no-proof when a jkt-bound cnf meets no presented binding", () => {
		expect(matchConfirmation({ jkt: "abc" }, undefined)).toEqual({
			status: "no-proof",
			member: "jkt",
			expected: "abc",
		});
	});

	it("is no-proof when only a different mechanism's binding is presented", () => {
		expect(matchConfirmation({ jkt: "abc" }, mtlsBinding("abc"))).toEqual({
			status: "no-proof",
			member: "jkt",
			expected: "abc",
		});
	});

	it("refuses to let a third-party mechanism kind satisfy a jkt binding", () => {
		// `Confirmation` is mechanism-extensible: a mechanism of another kind
		// emitting `{ jkt }` never validated a DPoP proof, so an equal value
		// must NOT satisfy the binding (kind boundary, PR #185).
		const acme: TokenBinding = { kind: "acme", confirmation: { jkt: "abc" } };
		expect(matchConfirmation({ jkt: "abc" }, acme)).toEqual({
			status: "no-proof",
			member: "jkt",
			expected: "abc",
		});
	});

	it("is mismatch when the presented DPoP key differs (multi-key attack)", () => {
		expect(matchConfirmation({ jkt: "abc" }, dpopBinding("OTHER"))).toEqual({
			status: "mismatch",
			member: "jkt",
			expected: "abc",
		});
	});

	it("is satisfied when the presented DPoP key matches", () => {
		expect(matchConfirmation({ jkt: "abc" }, dpopBinding("abc"))).toEqual({
			status: "satisfied",
			member: "jkt",
			value: "abc",
		});
	});
});

describe("matchConfirmation — x5t#S256 member (mTLS matrix rows 3-5)", () => {
	it("is no-proof when an x5t#S256-bound cnf meets no presented binding", () => {
		expect(matchConfirmation({ "x5t#S256": "abc" }, undefined)).toEqual({
			status: "no-proof",
			member: "x5t#S256",
			expected: "abc",
		});
	});

	it("is no-proof when only a DPoP binding is presented", () => {
		expect(matchConfirmation({ "x5t#S256": "abc" }, dpopBinding("abc"))).toEqual({
			status: "no-proof",
			member: "x5t#S256",
			expected: "abc",
		});
	});

	it("is mismatch when the presented certificate differs", () => {
		expect(matchConfirmation({ "x5t#S256": "abc" }, mtlsBinding("OTHER"))).toEqual({
			status: "mismatch",
			member: "x5t#S256",
			expected: "abc",
		});
	});

	it("is satisfied when the presented certificate matches", () => {
		expect(matchConfirmation({ "x5t#S256": "abc" }, mtlsBinding("abc"))).toEqual({
			status: "satisfied",
			member: "x5t#S256",
			value: "abc",
		});
	});
});

describe("matchConfirmation — compound cnf", () => {
	it("is compound when both members are well-formed, with or without a binding", () => {
		const cnf = { jkt: "abc", "x5t#S256": "def" };
		expect(matchConfirmation(cnf, undefined)).toEqual({ status: "compound" });
		// Even a binding that would satisfy one member must not pick a
		// winner — same structural stance as the refresh grant and the
		// introspection handler.
		expect(matchConfirmation(cnf, dpopBinding("abc"))).toEqual({ status: "compound" });
		expect(matchConfirmation(cnf, mtlsBinding("def"))).toEqual({ status: "compound" });
	});

	it("treats a junk-attached second member as a single-mechanism binding", () => {
		// Matches isCompoundConfirmation: an empty-string or non-string
		// second member is junk attached to a single binding, not ambiguity.
		expect(matchConfirmation({ jkt: "abc", "x5t#S256": "" }, dpopBinding("abc"))).toEqual({
			status: "satisfied",
			member: "jkt",
			value: "abc",
		});
		expect(matchConfirmation({ jkt: "", "x5t#S256": "def" }, undefined)).toEqual({
			status: "no-proof",
			member: "x5t#S256",
			expected: "def",
		});
	});
});

describe("ownedConfirmation", () => {
	it("returns undefined when no binding is presented", () => {
		expect(ownedConfirmation(undefined)).toBeUndefined();
		expect(ownedConfirmation(null)).toBeUndefined();
	});

	it("narrows a DPoP binding to its jkt confirmation", () => {
		expect(ownedConfirmation(dpopBinding("abc"))).toEqual({ jkt: "abc" });
	});

	it("narrows an mTLS binding to its x5t#S256 confirmation", () => {
		expect(ownedConfirmation(mtlsBinding("def"))).toEqual({ "x5t#S256": "def" });
	});

	it("returns undefined for a mechanism kind that owns no known member", () => {
		const acme: TokenBinding = { kind: "acme", confirmation: { jkt: "abc" } };
		expect(ownedConfirmation(acme)).toBeUndefined();
	});

	it("returns undefined when the confirmation lacks the member the kind owns", () => {
		const crossed: TokenBinding = { kind: "dpop", confirmation: { "x5t#S256": "abc" } };
		expect(ownedConfirmation(crossed)).toBeUndefined();
	});
});

describe("extractConfirmation (moved from oauth types/introspect — #324)", () => {
	it("returns undefined for non-objects", () => {
		expect(extractConfirmation(undefined)).toBeUndefined();
		expect(extractConfirmation(null)).toBeUndefined();
		expect(extractConfirmation("jkt")).toBeUndefined();
		expect(extractConfirmation(["jkt"])).toBeUndefined();
	});

	it("narrows well-formed members", () => {
		expect(extractConfirmation({ jkt: "abc" })).toEqual({ jkt: "abc" });
		expect(extractConfirmation({ "x5t#S256": "def" })).toEqual({ "x5t#S256": "def" });
	});

	it("rejects empty-string thumbprints", () => {
		expect(extractConfirmation({ jkt: "" })).toBeUndefined();
		expect(extractConfirmation({ "x5t#S256": "" })).toBeUndefined();
	});

	it("prefers jkt when both members are well-formed (intent-explicit order)", () => {
		expect(extractConfirmation({ jkt: "abc", "x5t#S256": "def" })).toEqual({ jkt: "abc" });
	});

	it("falls through past a junk jkt to a well-formed x5t#S256", () => {
		expect(extractConfirmation({ jkt: "", "x5t#S256": "def" })).toEqual({ "x5t#S256": "def" });
	});
});

describe("isCompoundConfirmation (moved from oauth types/introspect — #324)", () => {
	it("is false for non-objects and empty objects", () => {
		expect(isCompoundConfirmation(undefined)).toBe(false);
		expect(isCompoundConfirmation(null)).toBe(false);
		expect(isCompoundConfirmation({})).toBe(false);
	});

	it("is false for a single well-formed member", () => {
		expect(isCompoundConfirmation({ jkt: "abc" })).toBe(false);
		expect(isCompoundConfirmation({ "x5t#S256": "def" })).toBe(false);
	});

	it("is true only when BOTH members are well-formed", () => {
		expect(isCompoundConfirmation({ jkt: "abc", "x5t#S256": "def" })).toBe(true);
		expect(isCompoundConfirmation({ jkt: "abc", "x5t#S256": "" })).toBe(false);
		expect(isCompoundConfirmation({ jkt: "", "x5t#S256": "def" })).toBe(false);
	});
});
