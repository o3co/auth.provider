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
): AdmissionDeps => ({
	userSessionStore: store,
	subjectRevocation: undefined,
	requirements: resolverForTests(requirements, { issuer: ISSUER, actions: TEST_ACTIONS }),
	acrTable: readAcrTable({}),
	logger: undefined,
	auditSink: undefined,
	now: () => NOW,
});

const cookie = (): SessionClaim =>
	cookieClaim({
		session: { isAuthenticated: true, sid: "sid-1", user: { id: "user-1", email: ADDRESS } },
	});

const VIEW_KEYS = ["authTime", "enrollmentFacts", "expiresAt", "sid", "sub"];

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
		expect(view).toEqual({
			sid: "sid-1",
			sub: "user-1",
			authTime: record().authTime,
			expiresAt: record().expiresAt,
			enrollmentFacts: { witness: "not_enrolled", mailAddress: "address" },
		});
		expect(Object.isFrozen(view)).toBe(true);
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

	it("carries the four fields and the facts alone: no address, claim or amr of the record", async () => {
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
