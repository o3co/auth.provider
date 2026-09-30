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
 * The merge: the requirement rule's rows from
 * ADR 2026-09-25-multi-factor-authentication pass unchanged against
 * `admitSession` with a requirement that declares the second-factor
 * authority and whose `admit` is the MFA requirement's table, under the
 * mapping to `MfaRequirementDecision` in ADR 2026-09-28-session-admission.
 * The stand-in is not named `mfa`: the rows are the declared authority's.
 *
 * The rows are the ones the rule decided — the freshness rows (`max_age`,
 * `prompt=login`, the ask) and the `prompt=none` answers are `/authorize`'s,
 * around the admission — kept as data in `testing/merge.rows.mts`, published
 * on `@o3co/auth-provider-core/testing`, so the MFA package runs the same
 * list against the requirement it registers. After them, the merge rows the
 * MFA table alone does not reach: a step-up whose page is another
 * requirement's, and one no single requirement can finish.
 */

import { describe, expect, it } from "vitest";
import type { MfaMode } from "#/mfa/mode.mjs";
import { readAcrTable } from "#/session-admission/acr.mjs";
import { admitSession, cookieClaim } from "#/session-admission/admit.mjs";
import type {
	Admission,
	AdmissionDeps,
	SessionRequirement,
	SessionRequirementResolver,
	StepUpPage,
} from "#/session-admission/requirement.mjs";
import { ADMISSION_ACTIONS } from "#/session-admission/requirement.mjs";
import {
	MERGE_ACR,
	MERGE_ACR_TABLE,
	MERGE_REACH,
	MERGE_ROW_GROUPS,
	type MergeRow,
	mergeAdmission,
} from "#/session-admission/testing/merge.rows.mjs";
import { resolverForTests } from "#/session-admission/testing/resolver.mjs";
import type { UserSession, UserSessionStore } from "#/user-sessions/types.mjs";

const { MFA, PHR, KBA } = MERGE_ACR;

/** The issuer each page is registered on. */
const ISSUER = "https://auth.test";
const PAGE: StepUpPage = { url: "/verifier", params: {} };
/** The name the stand-in registers under: not `mfa`, since the rows are the declared authority's. */
const AUTHORITY = "verifier";

const minutesAgo = (minutes: number): Date => new Date(Date.now() - minutes * 60_000);

const passwordSession = (amr: readonly string[], mfaAt?: Date): UserSession => ({
	sid: "sid-1",
	sub: "user-1",
	authTime: minutesAgo(1),
	createdAt: minutesAgo(1),
	expiresAt: new Date(Date.now() + 3_600_000),
	claims: {},
	amr,
	authentication: { primary: "pwd", federation: undefined, upstreamAmr: undefined, mfaAt },
});

/** The primaries the baseline can judge. */
const KNOWN_PRIMARIES: ReadonlySet<string> = new Set(["pwd", "fed"]);

/**
 * A stand-in for the second-factor authority — the MFA requirement's `admit`:
 * its table for the `use` grade, under `mode` with `reach`. The MFA package's
 * own requirement runs the same rows in that package.
 */
const authority = (mode: MfaMode, reach: ReadonlySet<string>): SessionRequirement => ({
	name: AUTHORITY,
	secondFactorAuthority: true,
	reach,
	stepUpPage: reach.size > 0 ? PAGE : undefined,
	remediations: [`${AUTHORITY}.step_up`],
	hintKeys: ["enrollable", "email_proof"],
	admit: async ({ session, authentication }) => {
		if (mode !== "required") return { outcome: "met" };
		const primary = authentication?.authentication?.primary;
		if (session === null || primary === undefined || !KNOWN_PRIMARIES.has(primary)) {
			return { outcome: "reauthenticate" };
		}
		if (primary === "fed" || authentication?.authentication?.mfaAt !== undefined) {
			return { outcome: "met" };
		}
		return reach.size > 0
			? { outcome: "step_up", whenStillUnmet: "reauthenticate" }
			: { outcome: "unmet" };
	},
});

const storeOf = (session: UserSession): UserSessionStore => ({
	kind: "test",
	create: async () => {},
	get: async (sid) => (sid === session.sid ? session : null),
	delete: async () => {},
});

const claim = () =>
	cookieClaim({ session: { isAuthenticated: true, sid: "sid-1", user: { id: "user-1" } } });

/** Admission's deps over `requirements`, registered on the issuer as boot registers them. */
const depsOver = (
	session: UserSession | null,
	requirements: SessionRequirementResolver,
): AdmissionDeps => ({
	userSessionStore: session === null ? undefined : storeOf(session),
	subjectRevocation: undefined,
	requirements,
	acrTable: MERGE_ACR_TABLE,
	logger: undefined,
	auditSink: undefined,
});

/**
 * Admission's deps for the rows the MFA table does not reach, which need two
 * reaching requirements neither of which is the authority: the reach rules
 * boot holds a registration to are lifted, the snapshot kept.
 */
const deps = (session: UserSession | null, requirements: SessionRequirement[]): AdmissionDeps =>
	depsOver(session, resolverForTests(requirements, { allowAnyReach: true, issuer: ISSUER }));

/**
 * One row, decided by the stand-in registered as boot registers it (the
 * reach rules held, so it registers only as the declared authority) and
 * mapped onto the admission of that registered requirement.
 */
const decide = async (row: MergeRow): Promise<{ admission: Admission; expected: Admission }> => {
	const requirements = resolverForTests([authority(row.mode, MERGE_REACH[row.factors])], {
		issuer: ISSUER,
	});
	const registered = requirements.get(AUTHORITY);
	if (registered === undefined) throw new Error("the stand-in did not register");
	return {
		admission: await admitSession(depsOver(row.session, requirements), {
			claim: claim(),
			action: ADMISSION_ACTIONS["oauth.authorize"],
			asks: { acrValues: row.acrValues ?? [] },
		}),
		expected: mergeAdmission(row.expected, row.session, registered),
	};
};

for (const group of MERGE_ROW_GROUPS) {
	describe(group.title, () => {
		it.each(group.rows)("$row", async (row) => {
			const { admission, expected } = await decide(row);
			expect(admission).toEqual(expected);
		});
	});
}

describe("mergeAdmission — the rows are the declared authority's", () => {
	const decision = { outcome: "step_up", requirement: "baseline", acrValues: [] } as const;
	const session = passwordSession(["pwd"]);

	it("maps a row onto the registered authority's name and page", () => {
		const registered = resolverForTests([authority("required", MERGE_REACH.installed)], {
			issuer: ISSUER,
		}).get(AUTHORITY);
		expect(mergeAdmission(decision, session, registered as never)).toMatchObject({
			outcome: "step_up",
			requirement: AUTHORITY,
			page: { url: "/verifier", params: {}, href: `${ISSUER}/verifier` },
			whenStillUnmet: "reauthenticate",
		});
	});

	it("throws for a requirement that does not declare the second-factor authority, whatever its name", () => {
		for (const name of ["mfa", AUTHORITY]) {
			const plain = resolverForTests(
				[
					{
						...authority("required", new Set()),
						name,
						secondFactorAuthority: false,
						remediations: [],
					},
				],
				{ issuer: ISSUER },
			).get(name);
			expect(() => mergeAdmission(decision, session, plain as never), name).toThrow(
				/does not declare the second-factor authority/,
			);
			expect(
				() => mergeAdmission({ outcome: "met", acr: undefined }, session, plain as never),
				name,
			).toThrow(/does not declare the second-factor authority/);
		}
	});

	it("maps a row that names no requirement with no authority given — what a composition without one registers — and throws for one that names it", () => {
		expect(mergeAdmission({ outcome: "met", acr: MFA }, session, undefined)).toEqual({
			outcome: "admitted",
			session,
			acr: MFA,
		});
		expect(mergeAdmission({ outcome: "unmet", requirement: "acr" }, session, undefined)).toEqual({
			outcome: "unmet",
			requirement: "acr",
			session,
		});
		for (const named of [
			decision,
			{ outcome: "step_up", requirement: "acr", acrValues: [MFA] } as const,
			{ outcome: "unmet", requirement: "baseline" } as const,
			{ outcome: "reauthenticate" } as const,
		]) {
			expect(() => mergeAdmission(named, session, undefined), JSON.stringify(named)).toThrow(
				/names the second-factor authority, and none is given/,
			);
		}
	});

	it("throws for an object that is not a registered requirement, however it is shaped", () => {
		const copy = {
			name: AUTHORITY,
			secondFactorAuthority: true,
			stepUpPage: { ...PAGE, href: `${ISSUER}/verifier` },
		};
		expect(() => mergeAdmission(decision, session, copy as never)).toThrow(
			/not a registered requirement/,
		);
	});
});

describe("the merge — the rows the MFA table does not reach", () => {
	/** A requirement that is met, reaches `reach`, and steps up nowhere of its own. */
	const reaching = (name: string, reach: readonly string[]): SessionRequirement => ({
		name,
		reach: new Set(reach),
		stepUpPage: reach.length > 0 ? { url: `/${name}`, params: { via: name } } : undefined,
		remediations: [`${name}.step_up`],
		hintKeys: [],
		admit: async () => ({ outcome: "met" }),
	});
	const session = passwordSession(["pwd"]);
	const ask = (requirements: SessionRequirement[], acrValues: readonly string[]) =>
		admitSession(deps(session, requirements), {
			claim: claim(),
			action: ADMISSION_ACTIONS["oauth.authorize"],
			asks: { acrValues },
		});

	it("met + step_up: the page is the first requirement's whose own reach covers what one alternative of a reachable entry lacks", async () => {
		// `phr` lacks `hwk` (or `swk`); the first requirement reaches neither,
		// the second reaches `swk`: the trip is the second one's.
		const admission = await ask([reaching("risk", ["kba"]), reaching("keys", ["swk"])], [PHR]);
		expect(admission).toEqual({
			outcome: "step_up",
			requirement: "keys",
			session,
			page: { url: "/keys", params: { via: "keys" }, href: `${ISSUER}/keys?via=keys` },
			acrValues: [PHR],
			whenStillUnmet: "unmet",
		});
	});

	it("met + step_up: the first requirement in registration order wins when two could finish it", async () => {
		const admission = await ask([reaching("a", ["hwk"]), reaching("b", ["swk"])], [PHR]);
		expect(admission).toMatchObject({ outcome: "step_up", requirement: "a" });
	});

	it("met + step_up: the hint is what the chosen requirement's reach alone can finish — not every value the union reaches", async () => {
		const admission = await ask([reaching("a", ["hwk"]), reaching("b", ["mfa"])], [KBA, PHR, MFA]);
		expect(admission).toMatchObject({
			outcome: "step_up",
			requirement: "a",
			acrValues: [PHR],
		});
		// One requirement reaching both: both, in the request's order.
		expect(await ask([reaching("a", ["hwk", "mfa"])], [KBA, PHR, MFA])).toMatchObject({
			outcome: "step_up",
			requirement: "a",
			acrValues: [PHR, MFA],
		});
	});

	it("met + step_up over an entry only the union reaches → unmet (acr): no one trip can finish it", async () => {
		// `["hwk", "swk"]` as one alternative: reachable by the union, by neither alone.
		const table = readAcrTable({ "urn:example:both": ["hwk", "swk"] });
		const admission = await admitSession(
			{ ...deps(session, [reaching("a", ["hwk"]), reaching("b", ["swk"])]), acrTable: table },
			{
				claim: claim(),
				action: ADMISSION_ACTIONS["oauth.authorize"],
				asks: { acrValues: ["urn:example:both"] },
			},
		);
		expect(admission).toEqual({ outcome: "unmet", requirement: "acr", session });
	});

	it("step_up + step_up: one trip — the requirement's page, the acr hint filtered to what that requirement's reach can finish, and unmet when it comes back still unmet", async () => {
		const stepping = (reach: readonly string[]): SessionRequirement => ({
			...reaching("first", reach),
			admit: async () => ({ outcome: "step_up", whenStillUnmet: "reauthenticate" }),
		});
		// `first` reaches otp and mfa: it cannot finish phr, which wants hwk — no hint.
		expect(await ask([stepping(["otp", "mfa"]), reaching("keys", ["hwk"])], [PHR])).toEqual({
			outcome: "step_up",
			requirement: "first",
			session,
			page: { url: "/first", params: { via: "first" }, href: `${ISSUER}/first?via=first` },
			acrValues: [],
			whenStillUnmet: "unmet",
		});
		// `first` reaches hwk: its trip finishes phr — the hint.
		expect(await ask([stepping(["hwk"]), reaching("keys", ["swk"])], [PHR, MFA])).toMatchObject({
			outcome: "step_up",
			requirement: "first",
			acrValues: [PHR],
			whenStillUnmet: "unmet",
		});
	});

	it("unmet + unmet: acr's — the request first, as the rule answers today", async () => {
		const refusing: SessionRequirement = {
			...reaching("hold", []),
			admit: async () => ({ outcome: "unmet" }),
		};
		// `kba` is reached by nothing registered: the request cannot be met.
		const admission = await ask([refusing, reaching("keys", ["hwk"])], [KBA]);
		expect(admission).toEqual({ outcome: "unmet", requirement: "acr", session });
	});

	it("unmet + step_up: the requirement's own unmet, by its name", async () => {
		const refusing: SessionRequirement = {
			...reaching("hold", []),
			admit: async () => ({ outcome: "unmet" }),
		};
		const admission = await ask([refusing, reaching("keys", ["hwk"])], [PHR]);
		expect(admission).toEqual({ outcome: "unmet", requirement: "hold", session });
	});

	it("reauthenticate + step_up: a new login, by the requirement's name", async () => {
		const asking: SessionRequirement = {
			...reaching("fresh", []),
			admit: async () => ({ outcome: "reauthenticate" }),
		};
		const admission = await ask([asking, reaching("keys", ["hwk"])], [PHR]);
		expect(admission).toEqual({ outcome: "reauthenticate", requirement: "fresh", session });
	});

	it("takes the first verdict that is not met, in registration order, and asks no requirement after it", async () => {
		const asked: string[] = [];
		const answering = (name: string, verdict: "met" | "unmet"): SessionRequirement => ({
			...reaching(name, []),
			admit: async () => {
				asked.push(name);
				return { outcome: verdict };
			},
		});
		const admission = await ask(
			[answering("one", "met"), answering("two", "unmet"), answering("three", "unmet")],
			[],
		);
		expect(admission).toEqual({ outcome: "unmet", requirement: "two", session });
		expect(asked).toEqual(["one", "two"]);
	});

	it("reads a step_up answered over no session as reauthenticate: nothing can be stepped up onto no session, and a login can", async () => {
		const stepping: SessionRequirement = {
			...reaching("first", ["otp"]),
			admit: async () => ({ outcome: "step_up", whenStillUnmet: "unmet" }),
		};
		const admission = await admitSession(deps(null, [stepping]), {
			claim: claim(),
			action: ADMISSION_ACTIONS["oauth.authorize"],
		});
		expect(admission).toEqual({ outcome: "reauthenticate", requirement: "first", session: null });
	});
});
