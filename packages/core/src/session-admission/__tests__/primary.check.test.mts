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

import { describe, expect, expectTypeOf, it } from "vitest";
import {
	additionsFromDto,
	type CompletingRequirement,
	checkPrimaryAdditions,
	checkPrimaryAuthentication,
	checkPrimaryContinuation,
	continuationOf,
	primaryFromDto,
} from "#/session-admission/primary.mjs";
import type {
	PrimaryAuthentication,
	RegisteredRequirement,
} from "#/session-admission/requirement.mjs";

const NOW = new Date("2026-09-28T12:00:00Z");

/** The requirement that declares the second-factor authority, under a name that is not `mfa`. */
const AUTHORITY = { name: "second", secondFactorAuthority: true } as const;

/** A requirement of `name` that does not declare the second-factor authority. */
const plain = (name: string) => ({ name, secondFactorAuthority: false }) as const;

describe("CompletingRequirement — what the addition checks read of a requirement", () => {
	it("is Pick<RegisteredRequirement, 'name' | 'secondFactorAuthority'>, the declaration a required boolean", () => {
		expectTypeOf<CompletingRequirement>().toEqualTypeOf<
			Pick<RegisteredRequirement, "name" | "secondFactorAuthority">
		>();
		expectTypeOf<CompletingRequirement["secondFactorAuthority"]>().toEqualTypeOf<boolean>();
	});
});

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
		// What core derives from that user: no witness, no address.
		enrollmentFacts: { witness: "not_enrolled", mailAddress: false },
		authTime: NOW,
		redirectTo: "/after",
		request: { ip: "198.51.100.7", userAgent: "test" },
		...over,
	}) as PrimaryAuthentication;

describe("checkPrimaryAuthentication — a primary as the login route builds it", () => {
	it("freezes user and claims deeply: a nested object or list in the copy cannot be changed either", () => {
		const checked = checkPrimaryAuthentication(
			primary({
				user: { id: "user-1", profile: { roles: ["staff"], address: { city: "x" } } },
				claims: { email: "u@example.test", groups: ["staff"], custom: { nested: [1] } },
			}),
		);
		const user = checked.user as { profile: { roles: string[]; address: object } };
		expect(Object.isFrozen(user.profile)).toBe(true);
		expect(Object.isFrozen(user.profile.roles)).toBe(true);
		expect(Object.isFrozen(user.profile.address)).toBe(true);
		const claims = checked.claims as { groups: string[]; custom: { nested: number[] } };
		expect(Object.isFrozen(claims.groups)).toBe(true);
		expect(Object.isFrozen(claims.custom)).toBe(true);
		expect(Object.isFrozen(claims.custom.nested)).toBe(true);
	});

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

/** A primary as a continuation carries it: `authTime` as epoch milliseconds. */
/** The primary as a continuation carries it: `authTimeMs`, and no enrollment facts, which a rehydration derives again. */
const dto = () => {
	const { authTime, enrollmentFacts: _derivedAgain, ...fields } = primary();
	return { ...fields, authTimeMs: authTime.getTime() };
};

describe("checkPrimaryAdditions — what a completing requirement may add, by what it declares", () => {
	it("accepts a completion that adds nothing — amr [] — which is all a requirement reaching nothing can add, from any requirement that does not declare the second-factor authority", () => {
		expect(checkPrimaryAdditions(plain("consent"), { amr: [] })).toEqual({ amr: [] });
		expect(Object.isFrozen(checkPrimaryAdditions(plain("consent"), { amr: [] }).amr)).toBe(true);
		expect(() => checkPrimaryAdditions(AUTHORITY, { amr: [], mfaAt: NOW })).toThrow(RangeError);
	});

	// resumePrimary does not ask a requirement already done again, so the
	// check fails closed on its own: a completion by the second-factor
	// authority is a verified second factor — a factor's value, `mfa` beside
	// it (unless the factor is the email code, whose `addsMfa` is off by
	// default: the MFA ADR's D14, O7), and when it was verified.
	it.each([
		["nothing", { amr: [] }],
		["a factor and mfa without mfaAt", { amr: ["otp", "mfa"] }],
		["a factor that adds mfa, without mfa", { amr: ["otp"], mfaAt: NOW }],
		["a recovery code without mfa", { amr: ["recovery"], mfaAt: NOW }],
		[
			"the email code beside a factor that adds mfa, without mfa",
			{ amr: ["email", "otp"], mfaAt: NOW },
		],
		["mfa and no second factor's value", { amr: ["mfa", "kba"], mfaAt: NOW }],
		["the email code without mfaAt", { amr: ["email"] }],
		["a value of its own and nothing verified", { amr: ["risk-ok"] }],
	])("refuses, from the second-factor authority, a completion that adds %s", (_label, adds) => {
		expect(() => checkPrimaryAdditions(AUTHORITY, adds)).toThrow(RangeError);
	});

	it.each([
		["a factor and mfa", { amr: ["otp", "mfa"], mfaAt: NOW }],
		["a recovery code and mfa", { amr: ["recovery", "mfa"], mfaAt: NOW }],
		["a synced passkey and mfa", { amr: ["swk", "mfa"], mfaAt: NOW }],
		["the email code alone (O7)", { amr: ["email"], mfaAt: NOW }],
		["the email code and mfa (addsMfa configured)", { amr: ["email", "mfa"], mfaAt: NOW }],
	])(
		"accepts, from the second-factor authority, a completion that adds %s — and reads it back from a continuation",
		(_label, adds) => {
			expect(checkPrimaryAdditions(AUTHORITY, adds)).toEqual(adds);
			const read = checkPrimaryContinuation({
				primary: dto(),
				done: [{ requirement: "second", adds: { amr: adds.amr, mfaAtMs: adds.mfaAt.getTime() } }],
				interruptedBy: "hold",
			});
			expect(read.done).toEqual([
				{ requirement: "second", adds: { amr: adds.amr, mfaAtMs: NOW.getTime() } },
			]);
		},
	);

	it("copies what the second-factor authority adds, mfaAt included", () => {
		const adds = checkPrimaryAdditions(AUTHORITY, { amr: ["otp", "mfa"], mfaAt: NOW });
		expect(adds).toEqual({ amr: ["otp", "mfa"], mfaAt: NOW });
		expect(Object.isFrozen(adds)).toBe(true);
		expect(adds.mfaAt).not.toBe(NOW);
		expect(checkPrimaryAdditions(plain("risk"), { amr: ["risk-ok"] })).toEqual({
			amr: ["risk-ok"],
		});
	});

	it("refuses a second-factor value or an mfaAt from any requirement that does not declare the second-factor authority — one named mfa among them", () => {
		for (const requirement of [plain("risk"), plain("mfa")]) {
			expect(() => checkPrimaryAdditions(requirement, { amr: ["otp"] }), requirement.name).toThrow(
				/a second-factor amr value, which only the second-factor authority may add/,
			);
			expect(
				() => checkPrimaryAdditions(requirement, { amr: ["otp", "mfa"], mfaAt: NOW }),
				requirement.name,
			).toThrow(/only the second-factor authority may add/);
			expect(
				() => checkPrimaryAdditions(requirement, { amr: ["risk-ok"], mfaAt: NOW }),
				requirement.name,
			).toThrow(/an mfaAt, which only the second-factor authority may add/);
		}
	});

	it.each([
		["nothing", undefined],
		["a value that is not a string", { amr: [7] }],
		["a primary's marker", { amr: ["pwd"] }],
		["the federated marker", { amr: ["otp", "fed"] }],
		["mfa alone", { amr: ["mfa"] }],
		["an invalid mfaAt", { amr: ["otp"], mfaAt: "now" }],
	])("refuses %s with a RangeError", (_label, adds) => {
		expect(() => checkPrimaryAdditions(AUTHORITY, adds)).toThrow(RangeError);
	});

	it("quotes nothing of what it refuses but a marker", () => {
		let refusal: unknown;
		try {
			checkPrimaryAdditions(plain("risk"), { amr: ["sentinel-value"], mfaAt: NOW });
		} catch (err) {
			refusal = err;
		}
		expect(refusal).toBeInstanceOf(RangeError);
		expect((refusal as RangeError).message).not.toContain("sentinel-value");
	});
});

describe("checkPrimaryContinuation — a done entry held to what any completion keeps, whatever its requirement declares", () => {
	// Which requirement declares the second-factor authority is the
	// registration's, which a store does not hold: `resumePrimary` holds each
	// entry read back to it. What holds for any completion is held here — a
	// second factor's evidence, whoever adds it, is a verified second factor.
	const readBack = (adds: Record<string, unknown>, requirement = "second") =>
		checkPrimaryContinuation({
			primary: dto(),
			done: [{ requirement, adds }],
			interruptedBy: "hold",
		});

	it.each([
		["a factor and mfa without mfaAt", { amr: ["otp", "mfa"] }],
		["a factor that adds mfa, without mfa", { amr: ["otp"], mfaAtMs: NOW.getTime() }],
		["a recovery code without mfa", { amr: ["recovery"], mfaAtMs: NOW.getTime() }],
		[
			"the email code beside a factor that adds mfa, without mfa",
			{ amr: ["email", "otp"], mfaAtMs: NOW.getTime() },
		],
		["mfa and no second factor's value", { amr: ["mfa", "kba"], mfaAtMs: NOW.getTime() }],
		["the email code without mfaAt", { amr: ["email"] }],
		["an mfaAt and no second factor's value", { amr: ["risk-ok"], mfaAtMs: NOW.getTime() }],
	])("refuses a done entry that adds %s, under any name", (_label, adds) => {
		for (const requirement of ["second", "risk", "mfa"]) {
			expect(() => readBack(adds, requirement), requirement).toThrow(RangeError);
		}
	});

	it("refuses a done in which more than one entry adds a second factor: only one requirement may, and it completes once", () => {
		const verified = { amr: ["otp", "mfa"], mfaAtMs: NOW.getTime() };
		expect(() =>
			checkPrimaryContinuation({
				primary: dto(),
				done: [
					{ requirement: "second", adds: verified },
					{ requirement: "other", adds: { amr: ["hwk", "mfa"], mfaAtMs: NOW.getTime() } },
				],
				interruptedBy: "hold",
			}),
		).toThrow(/more than one completion that adds a second factor/);
		// One that adds one beside others that add none reads back.
		expect(
			checkPrimaryContinuation({
				primary: dto(),
				done: [
					{ requirement: "risk", adds: { amr: [] } },
					{ requirement: "second", adds: verified },
				],
				interruptedBy: "hold",
			}).done,
		).toHaveLength(2);
	});

	it("reads back a verified second factor, and a completion that added nothing, under any name", () => {
		for (const requirement of ["second", "risk", "mfa"]) {
			expect(
				readBack({ amr: ["otp", "mfa"], mfaAtMs: NOW.getTime() }, requirement).done,
				requirement,
			).toEqual([{ requirement, adds: { amr: ["otp", "mfa"], mfaAtMs: NOW.getTime() } }]);
			expect(readBack({ amr: [] }, requirement).done, requirement).toEqual([
				{ requirement, adds: { amr: [] } },
			]);
		}
	});
});

describe("the continuation — what a requirement persists and presents back, as a serialisable DTO", () => {
	it("requires interruptedBy: the requirement whose ceremony the continuation waits on", () => {
		for (const interruptedBy of [undefined, "", 7, null]) {
			expect(
				() => checkPrimaryContinuation({ primary: dto(), done: [], interruptedBy }),
				JSON.stringify(interruptedBy),
			).toThrow(RangeError);
		}
		expect(
			checkPrimaryContinuation({ primary: dto(), done: [], interruptedBy: "mfa" }).interruptedBy,
		).toBe("mfa");
	});

	it("reads back a completion that added nothing, and refuses an mfaAtMs beside an empty amr", () => {
		const read = checkPrimaryContinuation({
			primary: dto(),
			done: [{ requirement: "consent", adds: { amr: [] } }],
			interruptedBy: "hold",
		});
		expect(read.done).toEqual([{ requirement: "consent", adds: { amr: [] } }]);
		expect(() =>
			checkPrimaryContinuation({
				primary: dto(),
				done: [{ requirement: "second", adds: { amr: [], mfaAtMs: 1 } }],
				interruptedBy: "hold",
			}),
		).toThrow(RangeError);
	});

	it("continuationOf carries the primary and every completion with epoch milliseconds, so a JSON round trip is exact", () => {
		const continuation = continuationOf(
			primary(),
			[
				{ requirement: "mfa", adds: { amr: ["otp", "mfa"], mfaAt: NOW } },
				{ requirement: "risk", adds: { amr: ["risk-ok"] } },
			],
			"hold",
		);
		expect(continuation).toEqual({
			interruptedBy: "hold",
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
		const plain = continuationOf(
			primary({ user: { id: "user-1", groups: ["staff"] } }),
			[{ requirement: "mfa", adds: { amr: ["otp", "mfa"], mfaAt: NOW } }],
			"risk",
		);
		expect(checkPrimaryContinuation(JSON.parse(JSON.stringify(plain)))).toEqual(plain);
	});

	it("checkPrimaryContinuation answers a frozen deep copy of the DTO", () => {
		const source = {
			primary: dto(),
			done: [
				{ requirement: "mfa", adds: { amr: ["otp", "mfa"], mfaAtMs: NOW.getTime() } },
				{ requirement: "risk", adds: { amr: ["risk-ok"] } },
			],
			interruptedBy: "hold",
		};
		const checked = checkPrimaryContinuation(source);
		expect(checked).toEqual(source);
		expect(Object.isFrozen(checked.done)).toBe(true);
		expect(checked.done[0]).not.toBe(source.done[0]);
		source.done.push({ requirement: "other", adds: { amr: ["x"] } });
		expect(checked.done).toHaveLength(2);
	});

	it("rehydrates: the primary's authTime and an addition's mfaAt become dates at their milliseconds", () => {
		const continuation = continuationOf(
			primary(),
			[{ requirement: "mfa", adds: { amr: ["otp", "mfa"], mfaAt: NOW } }],
			"risk",
		);
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
					{
						requirement: "mfa",
						adds: { amr: ["otp", "mfa"], mfaAtMs: NOW.getTime(), interruptedBy: "mfa" },
					},
					{ requirement: "mfa", adds: { amr: ["hwk", "mfa"], mfaAtMs: NOW.getTime() } },
				],
			}),
		).toThrow(/twice/);
		expect(() =>
			checkPrimaryContinuation({
				primary: dto(),
				done: [{ requirement: "risk", adds: { amr: ["otp"], interruptedBy: "mfa" } }],
			}),
		).toThrow(RangeError);
		expect(() =>
			checkPrimaryContinuation({
				primary: dto(),
				done: [{ requirement: "risk", adds: { amr: ["risk-ok"], mfaAtMs: NOW.getTime() } }],
				interruptedBy: "hold",
			}),
		).toThrow(/no second factor's own amr value/);
		for (const bad of [NOW, "now", -1, 1.5, Number.NaN]) {
			expect(() =>
				checkPrimaryContinuation({
					primary: dto(),
					done: [{ requirement: "mfa", adds: { amr: ["otp", "mfa"], mfaAtMs: bad } }],
				}),
			).toThrow(RangeError);
			expect(() =>
				checkPrimaryContinuation({
					primary: { ...dto(), authTimeMs: bad },
					done: [],
					interruptedBy: "mfa",
				}),
			).toThrow(RangeError);
		}
		expect(() => checkPrimaryContinuation({ primary: primary(), done: [] })).toThrow(RangeError);
		expect(() => checkPrimaryContinuation({ primary: dto(), done: {} })).toThrow(RangeError);
		expect(() =>
			checkPrimaryContinuation({
				primary: dto(),
				done: [{ adds: { amr: ["x"], interruptedBy: "mfa" } }],
			}),
		).toThrow(RangeError);
		expect(() => checkPrimaryContinuation(undefined)).toThrow(RangeError);
		expect(() => checkPrimaryContinuation({ done: [] })).toThrow(RangeError);
	});
});

describe("the refusals each field names", () => {
	const authentication = {
		primary: "pwd",
		federation: undefined,
		upstreamAmr: undefined,
		mfaAt: undefined,
	};

	it.each([
		[
			"claims that cannot be copied",
			{ claims: { hook: () => 1 } },
			/claims hold a value that cannot be copied/,
		],
		[
			"an authentication that is not an object",
			{ recorded: { amr: ["pwd"], authentication: "pwd" } },
			/recorded\.authentication must be an object/,
		],
		[
			"a federation that is not a string",
			{ recorded: { amr: ["pwd"], authentication: { ...authentication, federation: 7 } } },
			/recorded\.authentication\.federation must be a string or absent/,
		],
		[
			"an upstreamAmr that is not a list of strings",
			{ recorded: { amr: ["pwd"], authentication: { ...authentication, upstreamAmr: "hwk" } } },
			/recorded\.authentication\.upstreamAmr must be a list of strings or absent/,
		],
		[
			"a userAgent that is not a string",
			{ request: { ip: "198.51.100.7", userAgent: 7 } },
			/request\.userAgent must be a string or absent/,
		],
	] as const)("checkPrimaryAuthentication refuses %s, naming it", (_label, over, message) => {
		expect(() => checkPrimaryAuthentication(primary(over as never))).toThrow(message);
	});

	it("checkPrimaryContinuation refuses a done entry that is not an object, and additions that are not one", () => {
		const { authTime, enrollmentFacts: _derivedAgain, ...fields } = primary();
		const dto = { ...fields, authTimeMs: authTime.getTime() };
		expect(() =>
			checkPrimaryContinuation({ primary: dto, done: ["mfa"], interruptedBy: "mfa" }),
		).toThrow(/done holds an entry that is not an object/);
		expect(() =>
			checkPrimaryContinuation({
				primary: dto,
				done: [{ requirement: "risk", adds: "risk-ok" }],
				interruptedBy: "mfa",
			}),
		).toThrow(/adds something that is not an object/);
	});
});
