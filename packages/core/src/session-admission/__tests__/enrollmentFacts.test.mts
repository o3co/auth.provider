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
 * What a session records of its login's `User` for a first binding
 * (`SessionEnrollmentFacts`): derived by core's primary builders from the
 * `User` — the witness as `readMfaEnrollmentWitness` reads it, and whether
 * `user.email` is none, an address `normaliseMailAddress` reads, or one it
 * cannot — never taken from a caller's object, and never from a `User` that
 * is not plain data; and handed to a requirement as a copy in the view.
 */

import { describe, expect, it } from "vitest";
import { readAcrTable } from "#/session-admission/acr.mjs";
import {
	admitPrimary,
	admitSession,
	cookieClaim,
	establishWithoutAsking,
	passwordPrimary,
	resumePrimary,
} from "#/session-admission/admit.mjs";
import {
	checkPrimaryAuthentication,
	continuationOf,
	enrollmentFactsOfContinuation,
} from "#/session-admission/primary.mjs";
import type {
	AdmissionDeps,
	RequirementInput,
	SessionRequirement,
} from "#/session-admission/requirement.mjs";
import { resolverForTests } from "#/session-admission/testing/resolver.mjs";
import type { UserSession, UserSessionStore } from "#/user-sessions/types.mjs";
import { TEST_ACTIONS } from "./actions.fixture.mjs";

const NOW = new Date("2026-09-30T12:00:00Z");

const passwordFacts = (user: Record<string, unknown>) => ({
	subject: "user-1",
	user: { id: "user-1", ...user },
	claims: { email: "claims@example.test" },
	authTime: NOW,
	redirectTo: undefined,
	request: {},
});

const federatedLogin = (user: Record<string, unknown>) => ({
	subject: "user-1",
	user: { id: "user-1", ...user },
	claims: { email: "claims@example.test" },
	federation: "google",
	upstreamAmr: [],
	trusted: false,
	authTime: NOW,
	redirectTo: undefined,
	request: {},
});

/** `User.mfaEnrolled` as the Store answers it, and the witness it reads as. */
const WITNESSES: ReadonlyArray<readonly [string, Record<string, unknown>, string]> = [
	["true", { mfaEnrolled: true }, "enrolled"],
	["false", { mfaEnrolled: false }, "not_enrolled"],
	["absent", {}, "not_enrolled"],
	["null", { mfaEnrolled: null }, "malformed"],
	["1", { mfaEnrolled: 1 }, "malformed"],
	['"true"', { mfaEnrolled: "true" }, "malformed"],
];

/** `User.email` as the Store answers it, and what the session records of it. */
const ADDRESSES: ReadonlyArray<readonly [string, Record<string, unknown>, string]> = [
	["an address", { email: "alice@example.com" }, "address"],
	["an address in another spelling", { email: " Alice@Example.COM " }, "address"],
	["no email", {}, "none"],
	["an email that is null", { email: null }, "none"],
	["an empty email", { email: "" }, "none"],
	["an email of whitespace", { email: "   " }, "unreadable"],
	["a list", { email: "alice@example.com, bob@example.com" }, "unreadable"],
	["a display-name form", { email: "Alice Example <alice@example.com>" }, "unreadable"],
	["a comment", { email: "alice(comment)@example.com" }, "unreadable"],
	["a domain literal", { email: "alice@[192.0.2.1]" }, "unreadable"],
	["a 65-octet local part", { email: `${"a".repeat(65)}@example.com` }, "unreadable"],
	["a zero-width character", { email: "alice@example.com\u200b" }, "unreadable"],
	["a list of addresses", { email: ["alice@example.com"] }, "unreadable"],
	["a number", { email: 7 }, "unreadable"],
];

describe("the enrollment facts a primary carries — derived from its user by core's builders", () => {
	it.each(WITNESSES)(
		"reads a witness %s on the password login's user as %s",
		(_label, user, witness) => {
			expect(passwordPrimary(passwordFacts(user)).enrollmentFacts).toEqual({
				witness,
				mailAddress: "none",
			});
		},
	);

	it.each(WITNESSES)(
		"reads a witness %s on the federated login's user as %s",
		(_label, user, witness) => {
			expect(establishWithoutAsking(federatedLogin(user)).primary.enrollmentFacts).toEqual({
				witness,
				mailAddress: "none",
			});
		},
	);

	it.each(ADDRESSES)(
		"reads the user's email as none, an address or unreadable — %s is %s — on both logins",
		(_label, user, mailAddress) => {
			expect(passwordPrimary(passwordFacts(user)).enrollmentFacts).toEqual({
				witness: "not_enrolled",
				mailAddress,
			});
			expect(establishWithoutAsking(federatedLogin(user)).primary.enrollmentFacts).toEqual({
				witness: "not_enrolled",
				mailAddress,
			});
		},
	);

	it("reads the user's email, never the claims': claims with an address beside a user without one say none", () => {
		expect(passwordPrimary(passwordFacts({})).enrollmentFacts.mailAddress).toBe("none");
	});

	it("carries the two facts alone, frozen: no address, and nothing else of the user", () => {
		const facts = passwordPrimary(
			passwordFacts({ mfaEnrolled: true, email: "alice@example.com", name: "Alice" }),
		).enrollmentFacts;
		expect(Object.keys(facts).sort()).toEqual(["mailAddress", "witness"]);
		expect(JSON.stringify(facts)).not.toContain("alice");
		expect(Object.isFrozen(facts)).toBe(true);
	});

	it("keeps the derived facts when a caller hands in others that disagree with the user", () => {
		const user = { mfaEnrolled: true };
		const handed = { witness: "not_enrolled", mailAddress: "address" };
		const derived = { witness: "enrolled", mailAddress: "none" };
		expect(
			passwordPrimary({ ...passwordFacts(user), enrollmentFacts: handed } as never).enrollmentFacts,
		).toEqual(derived);
		expect(
			establishWithoutAsking({ ...federatedLogin(user), enrollmentFacts: handed } as never).primary
				.enrollmentFacts,
		).toEqual(derived);
		const built = passwordPrimary(passwordFacts(user));
		expect(
			checkPrimaryAuthentication({ ...built, enrollmentFacts: handed }).enrollmentFacts,
		).toEqual(derived);
	});
});

/** A class whose instances carry their fields as own data, as an ORM row may. */
class Row {
	id = "user-1";
	mfaEnrolled = true;
}

describe("a user that is not plain data — refused before anything is derived from it", () => {
	// A copy keeps own enumerable data alone: a field held another way would
	// be dropped from the copy, and the witness read from it as not enrolled.
	const NOT_PLAIN: ReadonlyArray<readonly [string, () => unknown]> = [
		[
			"a witness it does not enumerate",
			() => Object.defineProperty({ id: "user-1" }, "mfaEnrolled", { value: true }),
		],
		[
			"an inherited witness",
			() =>
				Object.assign(
					Object.create({
						get mfaEnrolled() {
							return true;
						},
					}),
					{ id: "user-1" },
				),
		],
		[
			"an own accessor",
			() => ({
				id: "user-1",
				get mfaEnrolled() {
					return true;
				},
			}),
		],
		["a class instance", () => new Row()],
		["a symbol key", () => ({ id: "user-1", [Symbol("witness")]: true })],
		["a nested Date", () => ({ id: "user-1", joined: new Date(0) })],
		["a nested Map", () => ({ id: "user-1", roles: new Map([["admin", true]]) })],
		["a nested typed array", () => ({ id: "user-1", key: new Uint8Array(2) })],
		["a class instance in a list", () => ({ id: "user-1", rows: [new Row()] })],
		[
			"a nested field it does not enumerate",
			() => ({
				id: "user-1",
				profile: Object.defineProperty({}, "email", { value: "a@example.com" }),
			}),
		],
		["a function", () => ({ id: "user-1", greet: () => "hi" })],
	];

	it.each(NOT_PLAIN)(
		"refuses a user with %s, on both logins, with a RangeError that quotes nothing of it",
		(_label, userOf) => {
			for (const build of [
				() => passwordPrimary({ ...passwordFacts({}), user: userOf() } as never),
				() => establishWithoutAsking({ ...federatedLogin({}), user: userOf() } as never),
			]) {
				let refusal: unknown;
				try {
					build();
				} catch (err) {
					refusal = err;
				}
				expect(refusal).toBeInstanceOf(RangeError);
				expect((refusal as Error).message).toMatch(/user must be plain data/);
				expect((refusal as Error).message).not.toContain("user-1");
			}
		},
	);

	it("takes plain data at any depth, a null prototype included, as a copy frozen at every depth", () => {
		const user = Object.assign(Object.create(null), {
			id: "user-1",
			mfaEnrolled: true,
			email: "alice@example.com",
			groups: ["staff", { team: "red" }],
			profile: { nickname: null, age: 30, admin: false },
		});
		const primary = passwordPrimary({ ...passwordFacts({}), user } as never);
		expect(primary.enrollmentFacts).toEqual({ witness: "enrolled", mailAddress: "address" });
		expect(primary.user).toEqual({
			id: "user-1",
			mfaEnrolled: true,
			email: "alice@example.com",
			groups: ["staff", { team: "red" }],
			profile: { nickname: null, age: 30, admin: false },
		});
		expect(Object.isFrozen(primary.user.groups)).toBe(true);
		expect(Object.isFrozen((primary.user.groups as unknown[])[1])).toBe(true);
		expect(Object.isFrozen(primary.user.profile)).toBe(true);
	});
});

describe("the enrollment facts across an interruption — the continuation carries none, and its rehydration derives them again", () => {
	const verifier: SessionRequirement = {
		name: "verifier",
		secondFactorAuthority: true,
		reach: new Set(["otp", "mfa"]),
		stepUpPage: { url: "/verifier", params: {} },
		remediations: [],
		hintKeys: [],
		admit: async () => ({ outcome: "met" }),
		admitPrimary: async (primary) =>
			primary.recorded.authentication.mfaAt === undefined
				? { open: async () => ({ status: 403, body: { error: "mfa_required" } }) }
				: "establish",
	};

	const deps = (): AdmissionDeps => ({
		userSessionStore: undefined,
		subjectRevocation: undefined,
		requirements: resolverForTests([verifier], { issuer: "https://auth.test" }),
		acrTable: readAcrTable({}),
		logger: undefined,
		auditSink: undefined,
		now: () => NOW,
	});

	const completion = { requirement: "verifier", adds: { amr: ["otp", "mfa"], mfaAt: NOW } };

	it("builds a continuation whose primary carries no facts", () => {
		const continuation = continuationOf(
			passwordPrimary(passwordFacts({ mfaEnrolled: true })),
			[],
			"verifier",
		);
		expect(continuation.primary).not.toHaveProperty("enrollmentFacts");
	});

	it("establishes the resumed login with the facts its continuation's user says", async () => {
		const first = await admitPrimary(
			deps(),
			passwordPrimary(passwordFacts({ mfaEnrolled: true, email: "alice@example.com" })),
		);
		if (first.outcome !== "interrupt") throw new Error("expected an interruption");
		const resumed = await resumePrimary(deps(), first.continuation, completion);
		if (resumed.outcome !== "establish") throw new Error("expected an establishment");
		expect(resumed.establishment.primary.enrollmentFacts).toEqual({
			witness: "enrolled",
			mailAddress: "address",
		});
	});

	it("reads no facts a continuation carries: the ones its user says stand", async () => {
		const first = await admitPrimary(deps(), passwordPrimary(passwordFacts({ mfaEnrolled: true })));
		if (first.outcome !== "interrupt") throw new Error("expected an interruption");
		const tampered = {
			...first.continuation,
			primary: {
				...first.continuation.primary,
				enrollmentFacts: { witness: "not_enrolled", mailAddress: "address" },
			},
		};
		const resumed = await resumePrimary(deps(), tampered, completion);
		if (resumed.outcome !== "establish") throw new Error("expected an establishment");
		expect(resumed.establishment.primary.enrollmentFacts).toEqual({
			witness: "enrolled",
			mailAddress: "none",
		});
	});
});

describe("the enrollment facts of a login's continuation — read by its holder before it resumes the login", () => {
	const interrupting: SessionRequirement = {
		name: "verifier",
		secondFactorAuthority: true,
		reach: new Set(["otp", "mfa"]),
		stepUpPage: { url: "/verifier", params: {} },
		remediations: [],
		hintKeys: [],
		admit: async () => ({ outcome: "met" }),
		admitPrimary: async (primary) =>
			primary.recorded.authentication.mfaAt === undefined
				? { open: async () => ({ status: 403, body: { error: "mfa_required" } }) }
				: "establish",
	};

	const deps = (): AdmissionDeps => ({
		userSessionStore: undefined,
		subjectRevocation: undefined,
		requirements: resolverForTests([interrupting], { issuer: "https://auth.test" }),
		acrTable: readAcrTable({}),
		logger: undefined,
		auditSink: undefined,
		now: () => NOW,
	});

	/** The continuation a password login of `user` is interrupted with. */
	const continuationFor = async (user: Record<string, unknown>) => {
		const first = await admitPrimary(deps(), passwordPrimary(passwordFacts(user)));
		if (first.outcome !== "interrupt") throw new Error("expected an interruption");
		return first.continuation;
	};

	/** The facts `resumePrimary` derives for the session it establishes from `continuation`. */
	const resumedFacts = async (continuation: unknown) => {
		const resumed = await resumePrimary(deps(), continuation as never, {
			requirement: "verifier",
			adds: { amr: ["otp", "mfa"], mfaAt: NOW },
		});
		if (resumed.outcome !== "establish") throw new Error("expected an establishment");
		return resumed.establishment.primary.enrollmentFacts;
	};

	it.each(WITNESSES)(
		"reads a witness %s on the continuation's user as the resumed login does",
		async (_label, user, witness) => {
			const continuation = await continuationFor(user);
			const facts = enrollmentFactsOfContinuation(continuation);
			expect(facts).toEqual({ witness, mailAddress: "none" });
			expect(facts).toEqual(await resumedFacts(continuation));
		},
	);

	it.each(ADDRESSES)(
		"reads the user's email — %s — as the resumed login does",
		async (_label, user, mailAddress) => {
			const continuation = await continuationFor(user);
			const facts = enrollmentFactsOfContinuation(continuation);
			expect(facts).toEqual({ witness: "not_enrolled", mailAddress });
			expect(facts).toEqual(await resumedFacts(continuation));
		},
	);

	it("reads a malformed witness beside an unreadable address together, as the resumed login does", async () => {
		const continuation = await continuationFor({ mfaEnrolled: "yes", email: "a, b@example.com" });
		const facts = enrollmentFactsOfContinuation(continuation);
		expect(facts).toEqual({ witness: "malformed", mailAddress: "unreadable" });
		expect(facts).toEqual(await resumedFacts(continuation));
	});

	it("reads no facts the continuation carries: the ones its user says stand", async () => {
		const continuation = await continuationFor({ mfaEnrolled: true });
		const tampered = {
			...continuation,
			primary: {
				...continuation.primary,
				enrollmentFacts: { witness: "not_enrolled", mailAddress: "address" },
			},
		};
		expect(enrollmentFactsOfContinuation(tampered as never)).toEqual({
			witness: "enrolled",
			mailAddress: "none",
		});
		expect(enrollmentFactsOfContinuation(tampered as never)).toEqual(await resumedFacts(tampered));
	});

	it("never reads an enrollmentFacts field the continuation or its primary carries", async () => {
		const continuation = await continuationFor({ mfaEnrolled: true });
		const primary = { ...continuation.primary };
		const carried = { ...continuation, primary };
		for (const target of [primary, carried]) {
			Object.defineProperty(target, "enrollmentFacts", {
				enumerable: true,
				get: () => {
					throw new Error("a carried enrollmentFacts was read");
				},
			});
		}
		expect(enrollmentFactsOfContinuation(carried as never)).toEqual({
			witness: "enrolled",
			mailAddress: "none",
		});
	});

	it("answers the two facts alone, frozen, and no address", async () => {
		const facts = enrollmentFactsOfContinuation(
			await continuationFor({ mfaEnrolled: true, email: "alice@example.com", name: "Alice" }),
		);
		expect(Object.keys(facts).sort()).toEqual(["mailAddress", "witness"]);
		expect(JSON.stringify(facts)).not.toContain("alice");
		expect(Object.isFrozen(facts)).toBe(true);
	});

	it.each([
		["no object", undefined],
		["a continuation without its primary", { done: [], interruptedBy: "verifier" }],
		["a user that is not plain data", "user"],
	])("refuses %s with a RangeError, as resumePrimary does", async (_label, shape) => {
		const continuation =
			shape === "user"
				? {
						...(await continuationFor({})),
						primary: {
							...(await continuationFor({})).primary,
							user: { id: "user-1", joined: new Date(0) },
						},
					}
				: shape;
		expect(() => enrollmentFactsOfContinuation(continuation as never)).toThrow(RangeError);
		await expect(resumedFacts(continuation)).rejects.toThrow(RangeError);
	});
});

describe("the enrollment facts in the view a requirement is handed", () => {
	const session = (over: Partial<UserSession> = {}): UserSession => ({
		sid: "sid-1",
		sub: "user-1",
		authTime: new Date(NOW.getTime() - 60_000),
		createdAt: new Date(NOW.getTime() - 60_000),
		expiresAt: new Date(NOW.getTime() + 3_600_000),
		claims: {},
		amr: ["pwd"],
		authentication: {
			primary: "pwd",
			federation: undefined,
			upstreamAmr: undefined,
			mfaAt: undefined,
		},
		...over,
	});

	/** What the one requirement is handed when admission reads `record`. */
	const viewOf = async (record: UserSession): Promise<RequirementInput["session"]> => {
		const seen: RequirementInput[] = [];
		const store: UserSessionStore = {
			kind: "test",
			create: async () => {},
			get: async (sid) => (sid === record.sid ? record : null),
			delete: async () => {},
		};
		await admitSession(
			{
				userSessionStore: store,
				subjectRevocation: undefined,
				requirements: resolverForTests(
					[
						{
							name: "watch",
							reach: new Set(),
							stepUpPage: undefined,
							remediations: [],
							hintKeys: [],
							admit: async (input) => {
								seen.push(input);
								return { outcome: "met" };
							},
						},
					],
					{ actions: TEST_ACTIONS },
				),
				acrTable: readAcrTable({}),
				logger: undefined,
				auditSink: undefined,
				now: () => NOW,
			},
			{
				claim: cookieClaim({
					session: { isAuthenticated: true, sid: "sid-1", user: { id: "user-1" } },
				}),
				action: "test.use",
			},
		);
		expect(seen).toHaveLength(1);
		return (seen[0] as RequirementInput).session;
	};

	it("carries a frozen copy of the facts the record holds", async () => {
		const facts = { witness: "enrolled" as const, mailAddress: "unreadable" as const };
		const view = await viewOf(session({ enrollmentFacts: facts }));
		expect(view?.enrollmentFacts).toEqual(facts);
		expect(view?.enrollmentFacts).not.toBe(facts);
		expect(Object.isFrozen(view?.enrollmentFacts)).toBe(true);
	});

	it("carries none when the record holds none", async () => {
		expect(await viewOf(session())).not.toHaveProperty("enrollmentFacts");
	});

	it.each([
		["a witness it does not know", { witness: "yes", mailAddress: "address" }],
		["no witness", { mailAddress: "address" }],
		["an address in place of the fact", { witness: "enrolled", mailAddress: "alice@example.com" }],
		["a flag in place of the fact", { witness: "enrolled", mailAddress: true }],
		["no address fact", { witness: "enrolled" }],
		["null", null],
	])(
		"carries none when the record's facts hold %s: a requirement is handed only what the type admits",
		async (_label, facts) => {
			expect(await viewOf(session({ enrollmentFacts: facts as never }))).not.toHaveProperty(
				"enrollmentFacts",
			);
		},
	);

	it("carries only the two facts, whatever else the record's facts hold", async () => {
		const view = await viewOf(
			session({
				enrollmentFacts: { witness: "not_enrolled", mailAddress: "none", email: "a@b.c" } as never,
			}),
		);
		expect(view?.enrollmentFacts).toEqual({ witness: "not_enrolled", mailAddress: "none" });
	});
});
