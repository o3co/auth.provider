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
import {
	composeAmr,
	EMAIL_OTP_AMR,
	FEDERATED_AMR,
	MFA_AMR,
	PASSWORD_AMR,
	RECOVERY_CODE_AMR,
	wellFormedAcr,
	wellFormedAmr,
} from "#/grants/authenticationClaims.mjs";

describe("wellFormedAmr — the amr a token may carry (#481 audit)", () => {
	it("is a non-empty array of non-empty strings, copied", () => {
		const source = ["pwd", "mfa"];
		const amr = wellFormedAmr(source);
		expect(amr).toEqual(["pwd", "mfa"]);
		expect(amr).not.toBe(source);
	});

	it.each([
		["an empty array", []],
		["an empty element", ["pwd", ""]],
		["a non-string element", ["pwd", 7]],
		["a string", "pwd"],
		["null", null],
		["undefined", undefined],
	])("is undefined for %s", (_label, value) => {
		// An `amr: []` stamped by one grant and dropped by the next is the
		// inconsistency this exists to prevent: every grant reads the same shape.
		expect(wellFormedAmr(value)).toBeUndefined();
	});
});

describe("wellFormedAcr — the acr a token may carry (#481 audit)", () => {
	it("is a non-empty string", () => {
		expect(wellFormedAcr("urn:example:mfa")).toBe("urn:example:mfa");
	});

	it.each([[""], [7], [null], [undefined], [["urn:example:mfa"]]])(
		"is undefined for %j",
		(value) => {
			expect(wellFormedAcr(value)).toBeUndefined();
		},
	);
});

describe("the amr values this provider records (the MFA ADR's D13, D14)", () => {
	it("are RFC 8176's pwd and mfa, and the deployment-defined fed, email and recovery", () => {
		// RFC 8176 registers `pwd` and `mfa`, and has no value for "through a
		// federation", "a code mailed to the account" or "a recovery code":
		// OIDC Core leaves `amr` values to the deployment, so these are
		// documented rather than borrowed.
		expect(PASSWORD_AMR).toBe("pwd");
		expect(FEDERATED_AMR).toBe("fed");
		expect(MFA_AMR).toBe("mfa");
		expect(EMAIL_OTP_AMR).toBe("email");
		expect(RECOVERY_CODE_AMR).toBe("recovery");
	});
});

describe("composeAmr — what a verified second factor adds to a session's amr (D14)", () => {
	it("appends the factor's values and then mfa: a password and a TOTP code", () => {
		expect(composeAmr(["pwd"], { amr: ["otp"], addsMfa: true })).toEqual(["pwd", "otp", "mfa"]);
	});

	it("appends a step-up to what the session holds, mfa never repeated", () => {
		expect(composeAmr(["pwd", "otp", "mfa"], { amr: ["hwk"], addsMfa: true })).toEqual([
			"pwd",
			"otp",
			"mfa",
			"hwk",
		]);
	});

	it("adds email and not mfa for an email code that does not add it (O7)", () => {
		expect(composeAmr(["pwd"], { amr: [EMAIL_OTP_AMR], addsMfa: false })).toEqual([
			"pwd",
			"email",
		]);
	});

	it("adds recovery and mfa for a recovery code", () => {
		expect(composeAmr(["pwd"], { amr: [RECOVERY_CODE_AMR], addsMfa: true })).toEqual([
			"pwd",
			"recovery",
			"mfa",
		]);
	});

	it("keeps insertion order and adds nothing the session already holds", () => {
		const held = ["pwd", "otp", "mfa"];
		const composed = composeAmr(held, { amr: ["otp"], addsMfa: true });
		expect(composed).toEqual(["pwd", "otp", "mfa"]);
		// A new array: the session record it was read from is not written through.
		expect(composed).not.toBe(held);
		expect(held).toEqual(["pwd", "otp", "mfa"]);
	});

	it("keeps each value once even when the record held it twice", () => {
		expect(composeAmr(["pwd", "pwd"], { amr: ["otp", "otp"], addsMfa: true })).toEqual([
			"pwd",
			"otp",
			"mfa",
		]);
	});

	it("refuses a factor that names mfa among its own values: mfa comes from addsMfa alone", () => {
		// Otherwise a factor that does not add `mfa` — the email code, by
		// default — could put it on a session by listing it, and meet
		// `urn:o3co:acr:mfa` with a mailbox (O7).
		expect(() => composeAmr(["pwd"], { amr: [MFA_AMR], addsMfa: false })).toThrow(RangeError);
		expect(() => composeAmr(["pwd"], { amr: ["otp", MFA_AMR], addsMfa: true })).toThrow(
			RangeError,
		);
	});

	it.each([
		["an empty value", [""]],
		["a non-string value", [7]],
	])("refuses a factor whose values hold %s", (_label, amr) => {
		expect(() => composeAmr(["pwd"], { amr: amr as string[], addsMfa: true })).toThrow(RangeError);
	});
});
