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
 * `user.email` is an address `normaliseMailAddress` reads — never taken from
 * a caller's object; and handed to a requirement as a copy in the view.
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
import { checkPrimaryAuthentication, continuationOf } from "#/session-admission/primary.mjs";
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

/** `User.email` as the Store answers it, and whether it is an address. */
const ADDRESSES: ReadonlyArray<readonly [string, Record<string, unknown>, boolean]> = [
	["an address", { email: "alice@example.com" }, true],
	["an address in another spelling", { email: " Alice@Example.COM " }, true],
	["none", {}, false],
	["an empty one", { email: "" }, false],
	["a list", { email: "alice@example.com, bob@example.com" }, false],
	["an angle address", { email: "Alice <alice@example.com>" }, false],
	["no string", { email: ["alice@example.com"] }, false],
];

describe("the enrollment facts a primary carries — derived from its user by core's builders", () => {
	it.each(WITNESSES)(
		"reads a witness %s on the password login's user as %s",
		(_label, user, witness) => {
			expect(passwordPrimary(passwordFacts(user)).enrollmentFacts).toEqual({
				witness,
				mailAddress: false,
			});
		},
	);

	it.each(WITNESSES)(
		"reads a witness %s on the federated login's user as %s",
		(_label, user, witness) => {
			expect(establishWithoutAsking(federatedLogin(user)).primary.enrollmentFacts).toEqual({
				witness,
				mailAddress: false,
			});
		},
	);

	it.each(ADDRESSES)(
		"says whether the user's email is an address, for %s, on both logins",
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
		expect(passwordPrimary(passwordFacts({})).enrollmentFacts.mailAddress).toBe(false);
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
		const handed = { witness: "not_enrolled", mailAddress: true };
		const derived = { witness: "enrolled", mailAddress: false };
		expect(
			passwordPrimary({ ...passwordFacts(user), enrollmentFacts: handed } as never)
				.enrollmentFacts,
		).toEqual(derived);
		expect(
			establishWithoutAsking({ ...federatedLogin(user), enrollmentFacts: handed } as never)
				.primary.enrollmentFacts,
		).toEqual(derived);
		const built = passwordPrimary(passwordFacts(user));
		expect(
			checkPrimaryAuthentication({ ...built, enrollmentFacts: handed }).enrollmentFacts,
		).toEqual(derived);
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
			mailAddress: true,
		});
	});

	it("reads no facts a continuation carries: the ones its user says stand", async () => {
		const first = await admitPrimary(deps(), passwordPrimary(passwordFacts({ mfaEnrolled: true })));
		if (first.outcome !== "interrupt") throw new Error("expected an interruption");
		const tampered = {
			...first.continuation,
			primary: {
				...first.continuation.primary,
				enrollmentFacts: { witness: "not_enrolled", mailAddress: true },
			},
		};
		const resumed = await resumePrimary(deps(), tampered, completion);
		if (resumed.outcome !== "establish") throw new Error("expected an establishment");
		expect(resumed.establishment.primary.enrollmentFacts).toEqual({
			witness: "enrolled",
			mailAddress: false,
		});
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
		const facts = { witness: "enrolled" as const, mailAddress: true };
		const view = await viewOf(session({ enrollmentFacts: facts }));
		expect(view?.enrollmentFacts).toEqual(facts);
		expect(view?.enrollmentFacts).not.toBe(facts);
		expect(Object.isFrozen(view?.enrollmentFacts)).toBe(true);
	});

	it("carries none when the record holds none", async () => {
		expect(await viewOf(session())).not.toHaveProperty("enrollmentFacts");
	});

	it.each([
		["a witness it does not know", { witness: "yes", mailAddress: true }],
		["no witness", { mailAddress: true }],
		["an address in place of the flag", { witness: "enrolled", mailAddress: "alice@example.com" }],
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
				enrollmentFacts: { witness: "not_enrolled", mailAddress: false, email: "a@b.c" } as never,
			}),
		);
		expect(view?.enrollmentFacts).toEqual({ witness: "not_enrolled", mailAddress: false });
	});
});
