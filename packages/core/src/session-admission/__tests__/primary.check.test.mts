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
 * The establishment vocabulary as it is checked and copied (the
 * session-admission ADR's D5): a primary as a login route builds it, what a
 * completing requirement may add, and the continuation a requirement
 * persists. What `admitPrimary`, `resumePrimary` and the MFA transaction
 * store read through.
 */

import { describe, expect, it } from "vitest";
import {
	additionsFromDto,
	checkPrimaryAdditions,
	checkPrimaryAuthentication,
	checkPrimaryContinuation,
	continuationOf,
	primaryFromDto,
} from "#/session-admission/primary.mjs";
import {
	MFA_REQUIREMENT_NAME,
	type PrimaryAuthentication,
} from "#/session-admission/requirement.mjs";

const NOW = new Date("2026-09-28T12:00:00Z");

const primary = (over: Record<string, unknown> = {}): PrimaryAuthentication =>
	({
		subject: "user-1",
		user: { id: "user-1", groups: ["staff"], joined: new Date("2020-01-01T00:00:00Z") },
		claims: { email: "user-1@example.test", emailVerified: true, groups: ["staff"] },
		recorded: {
			amr: ["pwd"],
			authentication: {
				primary: "pwd",
				federation: undefined,
				upstreamAmr: undefined,
				mfaAt: undefined,
			},
		},
		authTime: NOW,
		redirectTo: "/after",
		request: { ip: "198.51.100.7", userAgent: "test" },
		...over,
	}) as PrimaryAuthentication;

describe("checkPrimaryAuthentication — a primary as the login route builds it", () => {
	it("answers a frozen deep copy that shares nothing with the caller's object", () => {
		const source = primary();
		const checked = checkPrimaryAuthentication(source);
		expect(checked).toEqual(source);
		expect(checked).not.toBe(source);
		expect(Object.isFrozen(checked)).toBe(true);
		expect(Object.isFrozen(checked.user)).toBe(true);
		expect(Object.isFrozen(checked.recorded.amr)).toBe(true);
		expect(checked.user).not.toBe(source.user);
		expect(checked.authTime).not.toBe(source.authTime);
		(source.user as Record<string, unknown>).id = "someone-else";
		(source.recorded.amr as string[]).push("otp");
		expect(checked.user.id).toBe("user-1");
		expect(checked.recorded.amr).toEqual(["pwd"]);
		expect(checked.user.joined).toBeInstanceOf(Date);
	});

	it("keeps a federated primary's upstream values, trusted or kept apart", () => {
		const trusted = checkPrimaryAuthentication(
			primary({
				recorded: {
					amr: ["mfa", "hwk", "fed"],
					authentication: {
						primary: "fed",
						federation: "google",
						upstreamAmr: undefined,
						mfaAt: undefined,
					},
				},
			}),
		);
		expect(trusted.recorded.amr).toEqual(["mfa", "hwk", "fed"]);
		const apart = checkPrimaryAuthentication(
			primary({
				recorded: {
					amr: ["fed"],
					authentication: {
						primary: "fed",
						federation: "google",
						upstreamAmr: ["mfa"],
						mfaAt: undefined,
					},
				},
			}),
		);
		expect(apart.recorded.authentication.upstreamAmr).toEqual(["mfa"]);
	});

	it("leaves out a request field that is absent, and keeps redirectTo undefined", () => {
		const checked = checkPrimaryAuthentication(primary({ request: {}, redirectTo: undefined }));
		expect(checked.request).toEqual({});
		expect(checked.redirectTo).toBeUndefined();
	});

	it.each([
		["not an object", "pwd"],
		["no subject", { subject: "" }],
		["a user that is not an object", { user: "alice" }],
		["a user that cannot be copied", { user: { f: () => 1 } }],
		["no recorded", { recorded: undefined }],
		["an empty amr", { recorded: { amr: [], authentication: primary().recorded.authentication } }],
		[
			"an amr holding an empty string",
			{ recorded: { amr: [""], authentication: primary().recorded.authentication } },
		],
		[
			"an authentication without a primary",
			{ recorded: { amr: ["pwd"], authentication: { primary: "" } } },
		],
		[
			"an mfaAt already set: a primary rebuilt by hand",
			{
				recorded: {
					amr: ["pwd"],
					authentication: {
						primary: "pwd",
						federation: undefined,
						upstreamAmr: undefined,
						mfaAt: NOW,
					},
				},
			},
		],
		[
			"a second-factor value beside a password primary",
			{
				recorded: {
					amr: ["pwd", "otp", "mfa"],
					authentication: {
						primary: "pwd",
						federation: undefined,
						upstreamAmr: undefined,
						mfaAt: undefined,
					},
				},
			},
		],
		["an authTime that is not a date", { authTime: "2026-09-28" }],
		["an invalid authTime", { authTime: new Date(Number.NaN) }],
		["a redirectTo that is not a string", { redirectTo: ["/"] }],
		["no claims", { claims: undefined }],
		["claims that are not an object", { claims: "email" }],
		["claims that are a list", { claims: ["email"] }],
		["no request", { request: undefined }],
		["a request whose ip is not a string", { request: { ip: 7 } }],
	])("refuses %s with a RangeError", (_label, over) => {
		expect(() =>
			checkPrimaryAuthentication(typeof over === "string" ? over : primary(over)),
		).toThrow(RangeError);
	});
});

describe("checkPrimaryAdditions — what a completing requirement may add", () => {
	it("accepts a completion that adds nothing — amr [] — which is all a requirement reaching nothing can add, and refuses an mfaAt beside it", () => {
		expect(checkPrimaryAdditions("consent", { amr: [] })).toEqual({ amr: [] });
		expect(Object.isFrozen(checkPrimaryAdditions("consent", { amr: [] }).amr)).toBe(true);
		expect(checkPrimaryAdditions(MFA_REQUIREMENT_NAME, { amr: [] })).toEqual({ amr: [] });
		expect(() => checkPrimaryAdditions(MFA_REQUIREMENT_NAME, { amr: [], mfaAt: NOW })).toThrow(
			RangeError,
		);
	});

	it("copies what the requirement named mfa adds, mfaAt included", () => {
		const adds = checkPrimaryAdditions(MFA_REQUIREMENT_NAME, { amr: ["otp", "mfa"], mfaAt: NOW });
		expect(adds).toEqual({ amr: ["otp", "mfa"], mfaAt: NOW });
		expect(Object.isFrozen(adds)).toBe(true);
		expect(adds.mfaAt).not.toBe(NOW);
		expect(checkPrimaryAdditions("risk", { amr: ["risk-ok"] })).toEqual({ amr: ["risk-ok"] });
	});

	it("refuses a second-factor value or an mfaAt under any name but mfa", () => {
		expect(() => checkPrimaryAdditions("risk", { amr: ["otp"] })).toThrow(
			/only the requirement named mfa/,
		);
		expect(() => checkPrimaryAdditions("risk", { amr: ["risk-ok"], mfaAt: NOW })).toThrow(
			/only the requirement named mfa/,
		);
	});

	it.each([
		["nothing", undefined],
		["a value that is not a string", { amr: [7] }],
		["a primary's marker", { amr: ["pwd"] }],
		["the federated marker", { amr: ["otp", "fed"] }],
		["mfa alone", { amr: ["mfa"] }],
		["an invalid mfaAt", { amr: ["otp"], mfaAt: "now" }],
	])("refuses %s with a RangeError", (_label, adds) => {
		expect(() => checkPrimaryAdditions(MFA_REQUIREMENT_NAME, adds)).toThrow(RangeError);
	});

	it("quotes nothing of what it refuses but a marker", () => {
		let refusal: unknown;
		try {
			checkPrimaryAdditions("risk", { amr: ["sentinel-value"], mfaAt: NOW });
		} catch (err) {
			refusal = err;
		}
		expect(refusal).toBeInstanceOf(RangeError);
		expect((refusal as RangeError).message).not.toContain("sentinel-value");
	});
});

describe("the continuation — what a requirement persists and presents back, as a serialisable DTO", () => {
	const dto = () => {
		const { authTime, ...fields } = primary();
		return { ...fields, authTimeMs: authTime.getTime() };
	};

	it("reads back a completion that added nothing, and refuses an mfaAtMs beside an empty amr", () => {
		const read = checkPrimaryContinuation({
			primary: dto(),
			done: [{ requirement: "consent", adds: { amr: [] } }],
		});
		expect(read.done).toEqual([{ requirement: "consent", adds: { amr: [] } }]);
		expect(() =>
			checkPrimaryContinuation({
				primary: dto(),
				done: [{ requirement: MFA_REQUIREMENT_NAME, adds: { amr: [], mfaAtMs: 1 } }],
			}),
		).toThrow(RangeError);
	});

	it("continuationOf carries the primary and every completion with epoch milliseconds, so a JSON round trip is exact", () => {
		const continuation = continuationOf(primary(), [
			{ requirement: "mfa", adds: { amr: ["otp", "mfa"], mfaAt: NOW } },
			{ requirement: "risk", adds: { amr: ["risk-ok"] } },
		]);
		expect(continuation).toEqual({
			primary: dto(),
			done: [
				{ requirement: "mfa", adds: { amr: ["otp", "mfa"], mfaAtMs: NOW.getTime() } },
				{ requirement: "risk", adds: { amr: ["risk-ok"] } },
			],
		});
		expect(Object.isFrozen(continuation)).toBe(true);
		expect(Object.isFrozen(continuation.done)).toBe(true);
		// Every instant of the continuation's own is milliseconds; what the
		// user snapshot holds is the repository's, JSON as it comes from one.
		const plain = continuationOf(primary({ user: { id: "user-1", groups: ["staff"] } }), [
			{ requirement: "mfa", adds: { amr: ["otp", "mfa"], mfaAt: NOW } },
		]);
		expect(checkPrimaryContinuation(JSON.parse(JSON.stringify(plain)))).toEqual(plain);
	});

	it("checkPrimaryContinuation answers a frozen deep copy of the DTO", () => {
		const source = {
			primary: dto(),
			done: [
				{ requirement: "mfa", adds: { amr: ["otp", "mfa"], mfaAtMs: NOW.getTime() } },
				{ requirement: "risk", adds: { amr: ["risk-ok"] } },
			],
		};
		const checked = checkPrimaryContinuation(source);
		expect(checked).toEqual(source);
		expect(Object.isFrozen(checked.done)).toBe(true);
		expect(checked.done[0]).not.toBe(source.done[0]);
		source.done.push({ requirement: "other", adds: { amr: ["x"] } });
		expect(checked.done).toHaveLength(2);
	});

	it("rehydrates: the primary's authTime and an addition's mfaAt become dates at their milliseconds", () => {
		const continuation = continuationOf(primary(), [
			{ requirement: "mfa", adds: { amr: ["otp", "mfa"], mfaAt: NOW } },
		]);
		expect(primaryFromDto(continuation.primary)).toEqual(primary());
		expect(additionsFromDto(continuation.done[0]?.adds as never)).toEqual({
			amr: ["otp", "mfa"],
			mfaAt: NOW,
		});
		expect(additionsFromDto({ amr: ["risk-ok"] })).toEqual({ amr: ["risk-ok"] });
	});

	it("refuses a continuation whose done names a requirement twice, holds a bad addition, an instant that is not epoch milliseconds, or is not a list", () => {
		expect(() =>
			checkPrimaryContinuation({
				primary: dto(),
				done: [
					{ requirement: "mfa", adds: { amr: ["otp"] } },
					{ requirement: "mfa", adds: { amr: ["hwk"] } },
				],
			}),
		).toThrow(/twice/);
		expect(() =>
			checkPrimaryContinuation({
				primary: dto(),
				done: [{ requirement: "risk", adds: { amr: ["otp"] } }],
			}),
		).toThrow(RangeError);
		expect(() =>
			checkPrimaryContinuation({
				primary: dto(),
				done: [{ requirement: "risk", adds: { amr: ["risk-ok"], mfaAtMs: NOW.getTime() } }],
			}),
		).toThrow(/only the requirement named mfa/);
		for (const bad of [NOW, "now", -1, 1.5, Number.NaN]) {
			expect(() =>
				checkPrimaryContinuation({
					primary: dto(),
					done: [{ requirement: "mfa", adds: { amr: ["otp", "mfa"], mfaAtMs: bad } }],
				}),
			).toThrow(RangeError);
			expect(() =>
				checkPrimaryContinuation({ primary: { ...dto(), authTimeMs: bad }, done: [] }),
			).toThrow(RangeError);
		}
		expect(() => checkPrimaryContinuation({ primary: primary(), done: [] })).toThrow(RangeError);
		expect(() => checkPrimaryContinuation({ primary: dto(), done: {} })).toThrow(RangeError);
		expect(() =>
			checkPrimaryContinuation({ primary: dto(), done: [{ adds: { amr: ["x"] } }] }),
		).toThrow(RangeError);
		expect(() => checkPrimaryContinuation(undefined)).toThrow(RangeError);
		expect(() => checkPrimaryContinuation({ done: [] })).toThrow(RangeError);
	});
});
