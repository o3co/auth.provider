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
 * The view an admitted or `step_up` admission carries: admission's own
 * projection of the record (`viewOf`), equal to what the requirements are
 * handed, `null` without a record, and never the `User`'s address — so a
 * consumer reads a session's facts without reading the record.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import { readAcrTable } from "#/session-admission/acr.mjs";
import { admitSession, cookieClaim, tokenClaim } from "#/session-admission/admit.mjs";
import type {
	Admission,
	AdmissionDeps,
	IssuedRemediationAction,
	RequirementInput,
	RequirementVerdict,
	SessionClaim,
	SessionRequirement,
	SessionView,
} from "#/session-admission/requirement.mjs";
import { issuedRemediationActions } from "#/session-admission/requirement.mjs";
import { resolverForTests } from "#/session-admission/testing/resolver.mjs";
import type { UserSession, UserSessionStore } from "#/user-sessions/types.mjs";
import { TEST_ACTIONS } from "./actions.fixture.mjs";
import { openedLifecycleStore } from "./lifecycle.fixture.mjs";

const NOW = new Date("2026-10-01T12:00:00Z");
const ISSUER = "https://auth.test";
const ADDRESS = "alice@example.com";

const record = (over: Partial<UserSession> = {}): UserSession => ({
	sid: "sid-1",
	sub: "user-1",
	authTime: new Date(NOW.getTime() - 60_000),
	createdAt: new Date(NOW.getTime() - 60_000),
	expiresAt: new Date(NOW.getTime() + 3_600_000),
	claims: { email: ADDRESS },
	amr: ["pwd"],
	authentication: {
		primary: "pwd",
		federation: undefined,
		upstreamAmr: undefined,
		mfaAt: undefined,
	},
	enrollmentFacts: { witness: "not_enrolled", mailAddress: "address" },
	...over,
});

const holding = (session: UserSession): UserSessionStore => ({
	kind: "test",
	create: async () => {},
	get: async (sid) => (sid === session.sid ? session : null),
	delete: async () => {},
});

/**
 * `holding` with the step-up capability, and how many times admission read
 * it: `recordSecondFactor` is a getter that counts.
 */
const recording = (session: UserSession): { store: UserSessionStore; reads: () => number } => {
	let reads = 0;
	const store = Object.defineProperty(holding(session), "recordSecondFactor", {
		enumerable: true,
		get: () => {
			reads++;
			return async () => null;
		},
	});
	return { store, reads: () => reads };
};

/** A requirement that notes the view it is handed and answers `verdict`. */
const watching = (
	seen: Array<RequirementInput["session"]>,
	verdict: RequirementVerdict = { outcome: "met" },
	over: Partial<SessionRequirement> = {},
): SessionRequirement => ({
	name: "watch",
	reach: new Set(),
	stepUpPage: { url: "/step-up", params: {} },
	remediations: [],
	hintKeys: [],
	admit: async (input) => {
		seen.push(input.session);
		return verdict;
	},
	...over,
});

const deps = (
	store: UserSessionStore | undefined,
	requirements: readonly SessionRequirement[],
	acrTable: AdmissionDeps["acrTable"] = readAcrTable({}),
): AdmissionDeps => ({
	userSessionStore: store,
	sessionLifecycleStore: openedLifecycleStore(),
	subjectRevocation: undefined,
	requirements: resolverForTests(requirements, {
		issuer: ISSUER,
		actions: TEST_ACTIONS,
		allowAnyReach: true,
	}),
	acrTable,
	logger: undefined,
	auditSink: undefined,
	now: () => NOW,
});

const cookie = (): SessionClaim =>
	cookieClaim({
		session: { isAuthenticated: true, sid: "sid-1", user: { id: "user-1", email: ADDRESS } },
	});

const VIEW_KEYS = [
	"authTime",
	"enrollmentFacts",
	"expiresAt",
	"secondFactorRecordable",
	"sid",
	"sub",
];

describe("the view an admission carries", () => {
	it("is typed SessionView on a step_up, and SessionView or null on an admitted one", () => {
		expectTypeOf<
			Extract<Admission, { outcome: "admitted" }>["view"]
		>().toEqualTypeOf<SessionView | null>();
		expectTypeOf<Extract<Admission, { outcome: "step_up" }>["view"]>().toEqualTypeOf<SessionView>();
		expect(true).toBe(true);
	});

	it("admitted: equals the view the requirement was handed, and is a copy of its own", async () => {
		const seen: Array<RequirementInput["session"]> = [];
		const admission = await admitSession(deps(holding(record()), [watching(seen)]), {
			claim: cookie(),
			action: "test.use",
		});
		expect(admission.outcome).toBe("admitted");
		const { view } = admission as Extract<Admission, { outcome: "admitted" }>;
		expect(seen).toHaveLength(1);
		expect(view).not.toBeNull();
		expect(view).toEqual(seen[0]);
		expect(view).not.toBe(seen[0]);
		// The requirement's copy is its own: changing it leaves the admission's.
		const authTime = record().authTime.getTime();
		seen[0]?.authTime.setTime(0);
		expect(view?.authTime.getTime()).toBe(authTime);
		expect(view).toEqual({
			sid: "sid-1",
			sub: "user-1",
			authTime: record().authTime,
			expiresAt: record().expiresAt,
			enrollmentFacts: { witness: "not_enrolled", mailAddress: "address" },
			// `holding` has no `recordSecondFactor`.
			secondFactorRecordable: false,
		});
		expect(Object.isFrozen(view)).toBe(true);
	});

	it("is not changed by what a requirement does to the Dates of the view it is handed, nor is the next requirement's", async () => {
		const seen: Array<RequirementInput["session"]> = [];
		const original = record();
		const mutating = watching(
			seen,
			{ outcome: "met" },
			{
				name: "first",
				admit: async (input) => {
					seen.push(input.session);
					input.session?.authTime.setTime(0);
					input.session?.expiresAt.setTime(0);
					return { outcome: "met" };
				},
			},
		);
		const second = watching(seen, { outcome: "met" }, { name: "second", stepUpPage: undefined });
		const admission = await admitSession(deps(holding(original), [mutating, second]), {
			claim: cookie(),
			action: "test.use",
		});
		const { view } = admission as Extract<Admission, { outcome: "admitted" }>;
		expect(seen).toHaveLength(2);
		expect(seen[0]?.authTime.getTime()).toBe(0);
		expect(seen[1]?.authTime.getTime()).toBe(original.authTime.getTime());
		expect(seen[1]?.expiresAt.getTime()).toBe(original.expiresAt.getTime());
		expect(view?.authTime.getTime()).toBe(original.authTime.getTime());
		expect(view?.expiresAt.getTime()).toBe(original.expiresAt.getTime());
		expect(seen[1]).not.toBe(seen[0]);
	});

	it("step_up: equals the view the stepping requirement was handed", async () => {
		const seen: Array<RequirementInput["session"]> = [];
		const admission = await admitSession(
			deps(holding(record()), [
				watching(seen, { outcome: "step_up", whenStillUnmet: "reauthenticate" }),
			]),
			{ claim: cookie(), action: "test.use" },
		);
		expect(admission.outcome).toBe("step_up");
		const { view } = admission as Extract<Admission, { outcome: "step_up" }>;
		expect(seen).toHaveLength(1);
		expect(view).toEqual(seen[0]);
		expect(view).not.toBe(seen[0]);
	});

	it("is null without a session store, and for a token carrier no record was read for", async () => {
		const seen: Array<RequirementInput["session"]> = [];
		const withoutStore = await admitSession(deps(undefined, [watching(seen)]), {
			claim: cookie(),
			action: "test.use",
		});
		expect(withoutStore).toMatchObject({ outcome: "admitted", session: null, view: null });
		const token = await admitSession(deps(holding(record()), [watching(seen)]), {
			claim: tokenClaim({ sub: "user-1", amr: ["pwd"] }),
			action: "test.use",
		});
		expect(token).toMatchObject({ outcome: "admitted", session: null, view: null });
		expect(seen).toEqual([null, null]);
	});

	it("is carried for a remediation, which asks no requirement", async () => {
		const seen: Array<RequirementInput["session"]> = [];
		const owner = watching(seen, { outcome: "unmet" }, { remediations: ["watch.step_up"] });
		const registered = deps(holding(record()), [owner]);
		const issued = issuedRemediationActions(owner)?.step_up as IssuedRemediationAction;
		const admission = await admitSession(registered, { claim: cookie(), action: issued });
		expect(seen).toEqual([]);
		expect(admission).toMatchObject({
			outcome: "admitted",
			view: { sid: "sid-1", sub: "user-1" },
		});
	});

	it("carries the four fields, the facts and whether a second factor can be recorded alone: no address, claim or amr of the record", async () => {
		const seen: Array<RequirementInput["session"]> = [];
		for (const verdict of [
			{ outcome: "met" },
			{ outcome: "step_up", whenStillUnmet: "unmet" },
		] as const) {
			const admission = await admitSession(deps(holding(record()), [watching(seen, verdict)]), {
				claim: cookie(),
				action: "test.use",
			});
			const { view } = admission as { readonly view: SessionView };
			expect(Object.keys(view).sort(), verdict.outcome).toEqual(VIEW_KEYS);
			expect(JSON.stringify(view), verdict.outcome).not.toContain(ADDRESS);
			expect(view, verdict.outcome).not.toHaveProperty("amr");
			expect(view, verdict.outcome).not.toHaveProperty("claims");
		}
	});
});

/**
 * A record whose second factor cannot be recorded (`canRecordSecondFactor`
 * false): its `authentication` names a password primary, its `amr` is in a
 * shape the types do not admit. Only a custom store answers one.
 */
const unrecordable = (amr: unknown): UserSession => record({ amr: amr as never });

const UNRECORDABLE_AMRS: readonly unknown[] = [["pwd", ""], ["pwd", 1], "pwd"];

describe("secondFactorRecordable: whether a second factor can be recorded on the session", () => {
	it("is typed `boolean` on SessionView: every view says it", () => {
		expectTypeOf<SessionView["secondFactorRecordable"]>().toEqualTypeOf<boolean>();
		expect(true).toBe(true);
	});

	it("is true over a store with the step-up capability, on a record a second factor can be recorded on: the admitted view's and every requirement's", async () => {
		const seen: Array<RequirementInput["session"]> = [];
		const admission = await admitSession(
			deps(recording(record()).store, [
				watching(seen, { outcome: "met" }, { name: "first" }),
				watching(seen, { outcome: "met" }, { name: "second" }),
			]),
			{ claim: cookie(), action: "test.use" },
		);
		expect(admission).toMatchObject({
			outcome: "admitted",
			view: { secondFactorRecordable: true },
		});
		expect(seen.map((view) => view?.secondFactorRecordable)).toEqual([true, true]);
	});

	it("is false over a store without recordSecondFactor, whatever the record", async () => {
		const seen: Array<RequirementInput["session"]> = [];
		const admission = await admitSession(deps(holding(record()), [watching(seen)]), {
			claim: cookie(),
			action: "test.use",
		});
		expect(admission).toMatchObject({
			outcome: "admitted",
			view: { secondFactorRecordable: false },
		});
		expect(seen[0]?.secondFactorRecordable).toBe(false);
	});

	it("is false over a store that can record, on a record canRecordSecondFactor refuses", async () => {
		for (const amr of UNRECORDABLE_AMRS) {
			const seen: Array<RequirementInput["session"]> = [];
			const admission = await admitSession(
				deps(recording(unrecordable(amr)).store, [watching(seen)]),
				{ claim: cookie(), action: "test.use" },
			);
			expect(admission, JSON.stringify(amr)).toMatchObject({
				outcome: "admitted",
				view: { secondFactorRecordable: false },
			});
			expect(seen[0]?.secondFactorRecordable, JSON.stringify(amr)).toBe(false);
		}
	});

	it("is carried on a requirement's own step_up, equal to the copy the stepping requirement was handed", async () => {
		for (const [store, expected] of [
			[recording(record()).store, true],
			[recording(unrecordable(["pwd", ""])).store, false],
			[holding(record()), false],
		] as const) {
			const seen: Array<RequirementInput["session"]> = [];
			const admission = await admitSession(
				deps(store, [watching(seen, { outcome: "step_up", whenStillUnmet: "reauthenticate" })]),
				{ claim: cookie(), action: "test.use" },
			);
			expect(admission).toMatchObject({
				outcome: "step_up",
				view: { secondFactorRecordable: expected },
			});
			expect(seen[0]?.secondFactorRecordable).toBe(expected);
		}
	});

	it("is the record's for a token carrier whose record was read, never the token's amr", async () => {
		const seen: Array<RequirementInput["session"]> = [];
		const admission = await admitSession(
			deps(recording(unrecordable(["pwd", ""])).store, [watching(seen)]),
			{ claim: tokenClaim({ sub: "user-1", sid: "sid-1", amr: ["pwd"] }), action: "test.use" },
		);
		expect(admission).toMatchObject({
			outcome: "admitted",
			view: { secondFactorRecordable: false },
		});
		expect(seen[0]?.secondFactorRecordable).toBe(false);
	});

	it("is read off the store once per reading, however many requirements are asked and whether the merge steps up through the authority", async () => {
		const MFA = "urn:example:mfa";
		const table = readAcrTable({ [MFA]: ["mfa"] });
		const authority = (seen: Array<RequirementInput["session"]>): SessionRequirement =>
			watching(
				seen,
				{ outcome: "met" },
				{
					name: "authority",
					secondFactorAuthority: true,
					reach: new Set(["otp", "mfa"]),
					remediations: ["authority.step_up"],
				},
			);
		for (const [session, outcome] of [
			[record(), "step_up"],
			[unrecordable(["pwd", ""]), "reauthenticate"],
		] as const) {
			const seen: Array<RequirementInput["session"]> = [];
			const { store, reads } = recording(session);
			const admission = await admitSession(
				deps(
					store,
					[watching(seen, { outcome: "met" }, { name: "first" }), authority(seen)],
					table,
				),
				{ claim: cookie(), action: "test.use", asks: { acrValues: [MFA] } },
			);
			// The merge's row: what the authority alone can finish, recorded or
			// sent to log in again, from the answer the requirements were handed.
			expect(admission, outcome).toMatchObject(
				outcome === "step_up"
					? { outcome, requirement: "authority", view: { secondFactorRecordable: true } }
					: { outcome, requirement: "acr" },
			);
			expect(seen).toHaveLength(2);
			// Requirements were asked: the first reading and the last.
			expect(reads(), outcome).toBe(2);
		}
	});

	it("is unavailable (user_session) when the store's capability probe throws over a live record, and the probe is not read without one", async () => {
		let reads = 0;
		const throwing = (session: UserSession): UserSessionStore =>
			Object.defineProperty(holding(session), "recordSecondFactor", {
				get: () => {
					reads++;
					throw new Error("the probe was read");
				},
			});
		const seen: Array<RequirementInput["session"]> = [];
		for (const claim of [cookie(), tokenClaim({ sub: "user-1", sid: "sid-1", amr: ["pwd"] })]) {
			reads = 0;
			const admission = await admitSession(deps(throwing(record()), [watching(seen)]), {
				claim,
				action: "test.use",
			});
			expect(admission, claim.carrier).toEqual({ outcome: "unavailable", store: "user_session" });
			expect(reads, claim.carrier).toBe(1);
		}
		// Never a verdict: no requirement was asked.
		expect(seen).toEqual([]);
		// No live record: gone, another subject's, or no sid on a token.
		for (const [store, claim, expected] of [
			[throwing(record({ sid: "other" })), cookie(), { outcome: "not_live", reason: "gone" }],
			[
				throwing(record({ sub: "user-2" })),
				cookie(),
				{ outcome: "not_live", reason: "subject_mismatch" },
			],
			[throwing(record()), tokenClaim({ sub: "user-1", amr: ["pwd"] }), { outcome: "admitted" }],
		] as const) {
			reads = 0;
			const admission = await admitSession(deps(store, [watching(seen)]), {
				claim,
				action: "test.use",
			});
			expect(admission, JSON.stringify(expected)).toMatchObject(expected);
			expect(reads, JSON.stringify(expected)).toBe(0);
		}
	});
});
