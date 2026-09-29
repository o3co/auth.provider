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
 * The session-admission ADR's acceptance criterion 4, against the real
 * requirement: the MFA ADR's step-4 table — its D16 and D17 rows, as
 * `decideMfaRequirement` decided them — passes unchanged against core's
 * merge (`admitSession`, D2 step 7) with the `mfa` requirement this package
 * registers, under the mapping D2 states: the rule's `requirement: "acr"` is
 * `"acr"`, its `requirement: "baseline"` is `"mfa"`, and its
 * `step_up.requirement` is `whenStillUnmet` — `"acr"` → `"unmet"`,
 * `"baseline"` → the requirement's own `"reauthenticate"`.
 *
 * The rows are core's (`packages/core/src/session-admission/__tests__/
 * admit.merge.test.mts`), where they run against a stand-in written to D6's
 * table; here they run against `createMfaRequirement`, and the first case
 * holds this copy to carry every row core's file does. What the rule was
 * handed as `secondFactorMethods` is here the factors a composition enables,
 * each declaring its `amrValues` (TOTP, WebAuthn, the email code, recovery
 * codes); the reach is the requirement's own, recomputed from them. Under
 * `mfa.mode = "off"` the MFA module refuses to boot, so no requirement named
 * `mfa` is registered: those rows run against admission with none, which is
 * what a composition without MFA is.
 */

import { readFileSync } from "node:fs";
import {
	type AcrTable,
	ADMISSION_ACTIONS,
	type Admission,
	type AdmissionDeps,
	admitSession,
	cookieClaim,
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaFactor,
	type MfaMode,
	readAcrTable,
	type SessionRequirement,
	type StepUpPage,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { createMfaRequirement } from "#/requirement.mjs";
import { createLoginTransactions } from "#/transactions.mjs";
import { FACTORS, resolverOver } from "./requirementHarness.mjs";

const MFA = "urn:o3co:acr:mfa";
const PHR = "urn:o3co:acr:phr";
const PWD = "urn:example:pwd";
const KBA = "urn:example:kba";

/** The template's table (D15), `phr` uncommented, beside one entry only a password meets and one nothing installed produces. */
const TABLE: AcrTable = readAcrTable({
	[MFA]: ["mfa"],
	[PHR]: [["hwk"], ["swk"]],
	[PWD]: ["pwd"],
	[KBA]: ["kba"],
});

/**
 * The factors a composition enables, standing for what the rule was handed
 * as `secondFactorMethods`: the requirement's reach is recomputed from them.
 */
const FACTOR_SETS = {
	/** TOTP, WebAuthn and recovery codes: otp, hwk, swk, recovery, and mfa. */
	installed: () => [FACTORS.totp(), FACTORS.webauthn(), FACTORS.recovery()],
	/** TOTP and recovery codes: no factor adds hwk or swk. */
	withoutWebAuthn: () => [FACTORS.totp(), FACTORS.recovery()],
	/** The email code alone, which does not add mfa (O7). */
	emailOnly: () => [FACTORS.email()],
	/** The requirement with no factor enabled: nothing can step a session up. */
	empty: (): MfaFactor[] => [],
	/** No factor at all: nothing can step a session up. */
	none: (): MfaFactor[] => [],
} as const;

/** `endpoints.mfa.url` as core's reference.conf ships it. */
const PAGE: StepUpPage = { url: "/mfa", params: {} };

const minutesAgo = (minutes: number): Date => new Date(Date.now() - minutes * 60_000);

const record = (
	amr: readonly string[],
	authentication: UserSession["authentication"],
): UserSession => ({
	sid: "sid-1",
	sub: "user-1",
	authTime: minutesAgo(1),
	createdAt: minutesAgo(1),
	expiresAt: new Date(Date.now() + 3_600_000),
	claims: {},
	amr,
	authentication,
});

const passwordSession = (amr: readonly string[], mfaAt?: Date): UserSession =>
	record(amr, { primary: "pwd", federation: undefined, upstreamAmr: undefined, mfaAt });

const federatedSession = (amr: readonly string[], upstreamAmr?: readonly string[]): UserSession =>
	record(amr, { primary: "fed", federation: "google", upstreamAmr, mfaAt: undefined });

/** A record written before `UserSession.authentication` existed, read the one way every consumer does (D9). */
const recorded = (amr: readonly string[]): UserSession => record(amr, undefined);

/** A record whose `authentication` names a primary the baseline does not know. */
const primaryOf = (primary: string, amr: readonly string[]): UserSession =>
	record(amr, { primary, federation: undefined, upstreamAmr: undefined, mfaAt: undefined });

/** The MFA ADR's step-4 decision, as `decideMfaRequirement` answered it: the rows' expectations, unchanged. */
type LegacyDecision =
	| { readonly outcome: "met"; readonly acr: string | undefined }
	| { readonly outcome: "reauthenticate" }
	| {
			readonly outcome: "step_up";
			readonly requirement: "acr" | "baseline";
			readonly acrValues: readonly string[];
	  }
	| { readonly outcome: "unmet"; readonly requirement: "acr" | "baseline" };

interface Row {
	/** The D17 (or D16, D20) row the case pins, as the ADR words it. */
	readonly row: string;
	readonly mode: MfaMode;
	readonly session: UserSession | null;
	readonly acrValues?: readonly string[];
	readonly factors: keyof typeof FACTOR_SETS;
	readonly expected: LegacyDecision;
}

/** The requirement the MFA module registers under `mode`, over the factors of `factors`. */
const realRequirement = (
	mode: "optional" | "required",
	factors: keyof typeof FACTOR_SETS,
): SessionRequirement =>
	createMfaRequirement({
		mode,
		factors: resolverOver(FACTOR_SETS[factors]()),
		factorStore: createMemoryMfaFactorStore(),
		transactions: createLoginTransactions({
			store: createMemoryMfaTransactionStore(),
			ttlSeconds: 600,
		}),
		stepUpPage: PAGE,
		stepUpRecordable: true,
	});

const storeOf = (session: UserSession): UserSessionStore => ({
	kind: "test",
	create: async () => {},
	get: async (sid) => (sid === session.sid ? session : null),
	delete: async () => {},
});

const claim = () =>
	cookieClaim({ session: { isAuthenticated: true, sid: "sid-1", user: { id: "user-1" } } });

/** What a composition registers under `mode`: the real requirement, or — under off, which the module refuses — none. */
const deps = (row: Row): AdmissionDeps => ({
	userSessionStore: row.session === null ? undefined : storeOf(row.session),
	subjectRevocation: undefined,
	requirements: resolverForTests(
		row.mode === "off" ? [] : [realRequirement(row.mode, row.factors)],
	),
	acrTable: TABLE,
	logger: undefined,
	auditSink: undefined,
});

const decide = (row: Row): Promise<Admission> =>
	admitSession(deps(row), {
		claim: claim(),
		action: ADMISSION_ACTIONS["oauth.authorize"],
		asks: { acrValues: row.acrValues ?? [] },
	});

/** D2's stated mapping of the rule's decision onto the admission. */
const mapped = (expected: LegacyDecision, session: UserSession | null): Admission => {
	switch (expected.outcome) {
		case "met":
			return { outcome: "admitted", session, acr: expected.acr };
		case "reauthenticate":
			return { outcome: "reauthenticate", requirement: "mfa", session };
		case "step_up":
			if (session === null) throw new Error("a step-up needs a session");
			return {
				outcome: "step_up",
				requirement: "mfa",
				session,
				page: PAGE,
				acrValues: expected.acrValues,
				whenStillUnmet: expected.requirement === "acr" ? "unmet" : "reauthenticate",
			};
		case "unmet":
			return {
				outcome: "unmet",
				requirement: expected.requirement === "acr" ? "acr" : "mfa",
				session,
			};
	}
};

/** Every row's text a test file pins, as written in its source. */
const rowsIn = (source: string): string[] =>
	[...source.matchAll(/row:\s*(["'`])((?:\\.|(?!\1)[^\\])*)\1/g)].map(
		(match) => match[2] as string,
	);

describe("the copy of core's rows", () => {
	it("carries every row core's merge test pins for the MFA table, so the real requirement is held to all of them", () => {
		const core = readFileSync(
			new URL(
				"../../../core/src/session-admission/__tests__/admit.merge.test.mts",
				import.meta.url,
			),
			"utf8",
		);
		const own = readFileSync(new URL(import.meta.url), "utf8");
		const coreRows = rowsIn(core);
		expect(coreRows.length).toBeGreaterThan(40);
		expect(rowsIn(own)).toEqual(expect.arrayContaining(coreRows));
	});
});

describe("the merge — D17's rows (acceptance criterion 4)", () => {
	const rows: readonly Row[] = [
		{
			row: "nothing requested · primary pwd, mfaAt set → proceed",
			mode: "required",
			session: passwordSession(["pwd", "otp", "mfa"], minutesAgo(1)),
			factors: "installed",
			expected: { outcome: "met", acr: undefined },
		},
		{
			row: "nothing requested · primary pwd, no mfaAt, required → step-up",
			mode: "required",
			session: passwordSession(["pwd"]),
			factors: "installed",
			expected: { outcome: "step_up", requirement: "baseline", acrValues: [] },
		},
		{
			row: "nothing requested · primary fed, any upstream amr → proceed: the baseline does not apply",
			mode: "required",
			session: federatedSession(["fed"], ["pwd"]),
			factors: "installed",
			expected: { outcome: "met", acr: undefined },
		},
		{
			row: "nothing requested · session: null, required → re-authentication",
			mode: "required",
			session: null,
			factors: "installed",
			expected: { outcome: "reauthenticate" },
		},
		{
			row: "nothing requested · primary unknown, required → re-authentication",
			mode: "required",
			session: recorded(["hwk"]),
			factors: "installed",
			expected: { outcome: "reauthenticate" },
		},
		{
			row: 'nothing requested · pre-upgrade, amr ["pwd"] → step-up (primary read as pwd)',
			mode: "required",
			session: recorded(["pwd"]),
			factors: "installed",
			expected: { outcome: "step_up", requirement: "baseline", acrValues: [] },
		},
		{
			row: "nothing requested · pre-upgrade, holding fed → proceed (primary read as fed)",
			mode: "required",
			session: recorded(["hwk", "fed"]),
			factors: "installed",
			expected: { outcome: "met", acr: undefined },
		},
		{
			row: "acr_values=phr · pre-upgrade, holding fed and an upstream hwk → the hwk is not vouched for, whatever the federation (D9's split)",
			mode: "optional",
			session: recorded(["hwk", "fed"]),
			acrValues: [PHR],
			factors: "none",
			expected: { outcome: "unmet", requirement: "acr" },
		},
		{
			row: "acr_values met · D15's preference order: one the session meets wins over stepping up to an earlier one",
			mode: "optional",
			session: passwordSession(["pwd", "otp", "mfa"], minutesAgo(1)),
			acrValues: [PHR, MFA],
			factors: "installed",
			expected: { outcome: "met", acr: MFA },
		},
		{
			row: "acr_values=mfa · fed, upstream mfa, untrusted → step-up if the user holds a factor that adds mfa",
			mode: "required",
			session: federatedSession(["fed"], ["mfa"]),
			acrValues: [MFA],
			factors: "installed",
			expected: { outcome: "step_up", requirement: "acr", acrValues: [MFA] },
		},
		{
			row: "acr_values=mfa · fed, upstream mfa, untrusted, nothing to step up with → unmet",
			mode: "off",
			session: federatedSession(["fed"], ["mfa"]),
			acrValues: [MFA],
			factors: "none",
			expected: { outcome: "unmet", requirement: "acr" },
		},
		{
			row: "acr_values=mfa · fed, upstream mfa, federation trusted → proceed",
			mode: "required",
			session: federatedSession(["mfa", "fed"]),
			acrValues: [MFA],
			factors: "installed",
			expected: { outcome: "met", acr: MFA },
		},
		{
			row: "acr_values=mfa · an email-only login → step-up with a factor that adds mfa",
			mode: "required",
			session: passwordSession(["pwd", "email"], minutesAgo(1)),
			acrValues: [MFA],
			factors: "installed",
			expected: { outcome: "step_up", requirement: "acr", acrValues: [MFA] },
		},
		{
			row: "acr_values=mfa · an email-only login, and no installed factor adds mfa → unmet",
			mode: "required",
			session: passwordSession(["pwd", "email"], minutesAgo(1)),
			acrValues: [MFA],
			factors: "emailOnly",
			expected: { outcome: "unmet", requirement: "acr" },
		},
		{
			row: "nothing requested · an email-only login meets the baseline (O7)",
			mode: "required",
			session: passwordSession(["pwd", "email"], minutesAgo(1)),
			factors: "installed",
			expected: { outcome: "met", acr: undefined },
		},
		{
			row: "acr_values a step-up can meet · the user holds a qualifying factor → step-up (the trip learns whether they do)",
			mode: "optional",
			session: passwordSession(["pwd"]),
			acrValues: [PHR],
			factors: "installed",
			expected: { outcome: "step_up", requirement: "acr", acrValues: [PHR] },
		},
		{
			row: "acr_values nothing can meet · any → unmet",
			mode: "required",
			session: passwordSession(["pwd", "otp", "mfa"], minutesAgo(1)),
			acrValues: [KBA],
			factors: "installed",
			expected: { outcome: "unmet", requirement: "acr" },
		},
		{
			row: "acr_values nothing can meet · a value the table does not carry → unmet",
			mode: "required",
			session: passwordSession(["pwd", "otp", "mfa"], minutesAgo(1)),
			acrValues: ["urn:nope"],
			factors: "installed",
			expected: { outcome: "unmet", requirement: "acr" },
		},
		{
			row: "max_age within bounds · older mfaAt → proceed: acr_values is about methods, not age",
			mode: "required",
			session: passwordSession(["pwd", "otp", "mfa"], minutesAgo(24 * 60)),
			acrValues: [MFA],
			factors: "installed",
			expected: { outcome: "met", acr: MFA },
		},
	];

	it.each(rows)("$row", async (row) => {
		expect(await decide(row)).toEqual(mapped(row.expected, row.session));
	});
});

describe("the merge — the baseline beside acr_values (D16)", () => {
	const rows: readonly Row[] = [
		{
			row: "a met acr does not meet the baseline: step up for the baseline alone",
			mode: "required",
			session: passwordSession(["pwd"]),
			acrValues: [PWD],
			factors: "installed",
			expected: { outcome: "step_up", requirement: "baseline", acrValues: [] },
		},
		{
			row: "one step-up meets both: the acr a step-up can meet is the hint",
			mode: "required",
			session: passwordSession(["pwd"]),
			acrValues: [PHR],
			factors: "installed",
			expected: { outcome: "step_up", requirement: "acr", acrValues: [PHR] },
		},
		{
			row: "an acr nothing can meet is unmet, whatever the baseline needs",
			mode: "required",
			session: passwordSession(["pwd"]),
			acrValues: [KBA],
			factors: "installed",
			expected: { outcome: "unmet", requirement: "acr" },
		},
		{
			row: "the baseline with nothing to step up with is unmet",
			mode: "required",
			session: passwordSession(["pwd"]),
			factors: "none",
			expected: { outcome: "unmet", requirement: "baseline" },
		},
		{
			row: "the baseline with a coordinator but no factor enabled is unmet, never a step-up nothing can finish",
			mode: "required",
			session: passwordSession(["pwd"]),
			factors: "empty",
			expected: { outcome: "unmet", requirement: "baseline" },
		},
		{
			row: "a session of unknown primary is re-authenticated before any acr in the table is weighed",
			mode: "required",
			session: recorded(["hwk"]),
			acrValues: [PHR],
			factors: "installed",
			expected: { outcome: "reauthenticate" },
		},
		...["PWD", "", "magiclink", "hwk"].map(
			(primary): Row => ({
				row: `a primary the baseline does not know (${JSON.stringify(primary)}) is re-authenticated, never met`,
				mode: "required",
				session: primaryOf(primary, ["pwd"]),
				factors: "installed",
				expected: { outcome: "reauthenticate" },
			}),
		),
		{
			row: "a request no value of which the table carries is unmet before a missing session is re-authenticated",
			mode: "required",
			session: null,
			acrValues: ["urn:nope", "constructor"],
			factors: "installed",
			expected: { outcome: "unmet", requirement: "acr" },
		},
		{
			// The rule's row read `{ authentication: undefined, amr: ["pwd"] }`,
			// an input no record makes (D9 reads `pwd` as the primary): a record
			// whose primary cannot be told carries no primary's marker.
			row: "a request no value of which the table carries is unmet before an unknown primary is re-authenticated",
			mode: "required",
			session: recorded(["hwk"]),
			acrValues: ["urn:nope"],
			factors: "installed",
			expected: { outcome: "unmet", requirement: "acr" },
		},
		{
			row: "one value the table carries is enough to re-authenticate a missing session: a new login may meet it",
			mode: "required",
			session: null,
			acrValues: ["urn:nope", PWD],
			factors: "installed",
			expected: { outcome: "reauthenticate" },
		},
		{
			row: "optional has no baseline: a password session proceeds",
			mode: "optional",
			session: passwordSession(["pwd"]),
			factors: "installed",
			expected: { outcome: "met", acr: undefined },
		},
		{
			row: "off has no baseline: a password session proceeds (D20)",
			mode: "off",
			session: passwordSession(["pwd"]),
			factors: "none",
			expected: { outcome: "met", acr: undefined },
		},
		{
			row: "off answers acr_values needing a second factor unmet (D20)",
			mode: "off",
			session: passwordSession(["pwd"]),
			acrValues: [MFA],
			factors: "none",
			expected: { outcome: "unmet", requirement: "acr" },
		},
		{
			row: "off still meets an acr the session holds",
			mode: "off",
			session: recorded(["pwd"]),
			acrValues: [MFA, PWD],
			factors: "none",
			expected: { outcome: "met", acr: PWD },
		},
		{
			row: "session: null outside required is no baseline, and nothing to step up: an acr is unmet",
			mode: "optional",
			session: null,
			acrValues: [MFA],
			factors: "installed",
			expected: { outcome: "unmet", requirement: "acr" },
		},
		{
			row: "session: null outside required, nothing requested → proceed",
			mode: "off",
			session: null,
			factors: "none",
			expected: { outcome: "met", acr: undefined },
		},
		{
			// The rule's row read `{ authentication: undefined, amr: ["pwd", "hwk"] }`
			// (see above): a record whose primary cannot be told carries no
			// primary's marker, and its `amr` is weighed as it is.
			row: "an unknown primary outside required is weighed on its amr alone",
			mode: "optional",
			session: recorded(["kba", "hwk"]),
			acrValues: [PHR],
			factors: "installed",
			expected: { outcome: "met", acr: PHR },
		},
	];

	it.each(rows)("$row", async (row) => {
		expect(await decide(row)).toEqual(mapped(row.expected, row.session));
	});
});

describe("the merge — any-of entries and step-up targets (D15, D16)", () => {
	const rows: readonly Row[] = [
		{
			row: "one alternative of an any-of entry meets it: a synced passkey meets phr",
			mode: "optional",
			session: passwordSession(["pwd", "swk", "mfa"], minutesAgo(1)),
			acrValues: [PHR],
			factors: "installed",
			expected: { outcome: "met", acr: PHR },
		},
		{
			row: "an entry is a step-up target when one alternative lacks only values a step-up adds",
			mode: "optional",
			session: passwordSession(["pwd", "otp", "mfa"], minutesAgo(1)),
			acrValues: [PHR],
			factors: "installed",
			expected: { outcome: "step_up", requirement: "acr", acrValues: [PHR] },
		},
		{
			row: "no alternative a step-up can reach: unmet",
			mode: "optional",
			session: passwordSession(["pwd", "otp", "mfa"], minutesAgo(1)),
			acrValues: [PHR],
			factors: "withoutWebAuthn",
			expected: { outcome: "unmet", requirement: "acr" },
		},
		{
			row: "every requested value a step-up can meet is the hint, in the request's order",
			mode: "optional",
			session: passwordSession(["pwd"]),
			acrValues: [KBA, PHR, "urn:nope", MFA],
			factors: "installed",
			expected: { outcome: "step_up", requirement: "acr", acrValues: [PHR, MFA] },
		},
		{
			row: "mfa is within a step-up's reach when an installed factor adds it",
			mode: "optional",
			session: passwordSession(["pwd"]),
			acrValues: [MFA],
			factors: "withoutWebAuthn",
			expected: { outcome: "step_up", requirement: "acr", acrValues: [MFA] },
		},
		{
			row: "mfa is out of reach when no installed factor adds it, coordinator or not",
			mode: "optional",
			session: passwordSession(["pwd"]),
			acrValues: [MFA],
			factors: "emailOnly",
			expected: { outcome: "unmet", requirement: "acr" },
		},
		{
			row: "a value the step-up cannot add keeps an entry out of reach: pwd is the primary's",
			mode: "optional",
			session: federatedSession(["fed"]),
			acrValues: [PWD],
			factors: "installed",
			expected: { outcome: "unmet", requirement: "acr" },
		},
	];

	it.each(rows)("$row", async (row) => {
		expect(await decide(row)).toEqual(mapped(row.expected, row.session));
	});
});
