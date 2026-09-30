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
	authTimeClaim,
	composeAmr,
	EMAIL_OTP_AMR,
	FEDERATED_AMR,
	HARDWARE_KEY_AMR,
	MFA_AMR,
	OTP_AMR,
	PASSWORD_AMR,
	RECOVERY_CODE_AMR,
	SOFTWARE_KEY_AMR,
	wellFormedAcr,
	wellFormedAmr,
	wellFormedAuthTime,
} from "#/grants/authenticationClaims.mjs";

describe("wellFormedAmr — the amr a token may carry", () => {
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

describe("wellFormedAcr — the acr a token may carry", () => {
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

describe("wellFormedAuthTime — the auth_time a token may carry", () => {
	it("is a whole number of seconds since the epoch", () => {
		expect(wellFormedAuthTime(1_776_729_600)).toBe(1_776_729_600);
		expect(wellFormedAuthTime(0)).toBe(0);
	});

	it.each([
		["a fraction", 1_776_729_600.5],
		["a negative number", -1],
		["NaN", Number.NaN],
		["Infinity", Number.POSITIVE_INFINITY],
		["a number past Number.MAX_SAFE_INTEGER", 2 ** 53],
		["a numeric string", "1776729600"],
		["null", null],
		["undefined", undefined],
	])("is undefined for %s", (_label, value) => {
		expect(wellFormedAuthTime(value)).toBeUndefined();
	});
});

describe("authTimeClaim — an authentication instant as auth_time", () => {
	it("is the instant in whole seconds since the epoch, rounded down", () => {
		expect(authTimeClaim(new Date("2026-04-21T00:00:00.999Z"))).toBe(
			Date.UTC(2026, 3, 21) / 1000,
		);
	});

	it.each([
		["a Date that is not valid", new Date("not a date")],
		["an instant before the epoch", new Date(-1_500)],
	])("is undefined for %s", (_label, instant) => {
		expect(authTimeClaim(instant)).toBeUndefined();
	});
});

describe("the amr values this provider records", () => {
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

	it("include RFC 8176's otp, hwk and swk", () => {
		expect(OTP_AMR).toBe("otp");
		expect(HARDWARE_KEY_AMR).toBe("hwk");
		expect(SOFTWARE_KEY_AMR).toBe("swk");
	});
});

describe("composeAmr — what a verified second factor adds to a session's amr", () => {
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

	it("adds email and not mfa for an email code that does not add it", () => {
		expect(composeAmr(["pwd"], { amr: [EMAIL_OTP_AMR], addsMfa: false })).toEqual(["pwd", "email"]);
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
		// `urn:o3co:acr:mfa` with a mailbox (ADR
		// 2026-09-25-multi-factor-authentication, O7).
		expect(() => composeAmr(["pwd"], { amr: [MFA_AMR], addsMfa: false })).toThrow(RangeError);
		expect(() => composeAmr(["pwd"], { amr: ["otp", MFA_AMR], addsMfa: true })).toThrow(RangeError);
	});

	it.each([
		["pwd", PASSWORD_AMR],
		["fed", FEDERATED_AMR],
	])(
		"refuses a factor that names the primary marker %s: a second factor cannot forge a primary",
		(_label, marker) => {
			// The baseline is decided on the primary (ADR
			// 2026-09-25-multi-factor-authentication, D13), which the session's
			// `pwd` / `fed` say; a factor listing either would change it.
			expect(() => composeAmr(["pwd"], { amr: [marker], addsMfa: true })).toThrow(RangeError);
			expect(() => composeAmr(["fed"], { amr: ["otp", marker], addsMfa: true })).toThrow(
				RangeError,
			);
		},
	);

	it.each([
		["an empty value", [""]],
		["a non-string value", [7]],
	])("refuses a factor whose values hold %s", (_label, amr) => {
		expect(() => composeAmr(["pwd"], { amr: amr as string[], addsMfa: true })).toThrow(RangeError);
	});
});
