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
 * The second-factor authority's merge rows, as data: a request, a session,
 * whether its store can record a second factor, the `mfa.mode` and enabled
 * factors, and the expected decision in the MFA rule's vocabulary, which
 * `mergeAdmission` maps onto an `Admission` for the registered requirement
 * that declares the second-factor authority, whatever its name. Core's merge
 * test runs them against a stand-in registered as boot registers it, the MFA
 * package's against the requirement it registers, so both are held to one
 * list. Nothing here runs a test.
 */

import type { UserSession, UserSessionStore } from "../../user-sessions/types.mjs";
import { type AcrTable, readAcrTable } from "../acr.mjs";
import { viewOf } from "../admit.mjs";
import {
	type Admission,
	isRegisteredRequirement,
	type RegisteredRequirement,
} from "../requirement.mjs";

const MFA = "urn:o3co:acr:mfa";
const PHR = "urn:o3co:acr:phr";
const PWD = "urn:example:pwd";
const KBA = "urn:example:kba";

/** The `acr` values the rows ask for: the template's two, one only a password meets, and one nothing installed produces. */
export const MERGE_ACR = Object.freeze({ MFA, PHR, PWD, KBA });

/** The template's table, `phr` uncommented, beside one entry only a password meets and one nothing installed produces. */
export const MERGE_ACR_TABLE: AcrTable = readAcrTable({
	[MFA]: ["mfa"],
	[PHR]: [["hwk"], ["swk"]],
	[PWD]: ["pwd"],
	[KBA]: ["kba"],
});

/**
 * What a step-up through the second-factor authority can add under each
 * row's factors (its `reach`, the rule's `secondFactorMethods`): each
 * factor's values, and `mfa` when one of them adds it.
 */
export const MERGE_REACH = Object.freeze({
	/** TOTP, WebAuthn and recovery codes. */
	installed: new Set(["otp", "hwk", "swk", "recovery", "mfa"]) as ReadonlySet<string>,
	/** TOTP and recovery codes: no factor adds `hwk` or `swk`. */
	withoutWebAuthn: new Set(["otp", "recovery", "mfa"]) as ReadonlySet<string>,
	/** Email codes alone, which do not add `mfa`. */
	emailOnly: new Set(["email"]) as ReadonlySet<string>,
	/** The requirement with no factor enabled: nothing can step a session up. */
	empty: new Set<string>() as ReadonlySet<string>,
	/** No factor at all: nothing can step a session up. */
	none: new Set<string>() as ReadonlySet<string>,
});

/** The factors a row's composition enables, by name. */
export type MergeFactors = keyof typeof MERGE_REACH;

/** A row's expected decision, in the MFA rule's vocabulary. */
export type MergeDecision =
	| { readonly outcome: "met"; readonly acr: string | undefined }
	| { readonly outcome: "reauthenticate"; readonly requirement: "acr" | "baseline" }
	| {
			readonly outcome: "step_up";
			readonly requirement: "acr" | "baseline";
			readonly acrValues: readonly string[];
	  }
	| { readonly outcome: "unmet"; readonly requirement: "acr" | "baseline" };

/** One row: what it pins, as the ADR words it; its mode, session, request and factors; and the rule's decision. */
export interface MergeRow {
	readonly row: string;
	/** The MFA module's `mfa.mode` the row runs under. */
	readonly mode: "off" | "optional" | "required";
	/** The record admission reads, `sid-1` of `user-1`; `null` for no store. */
	readonly session: UserSession | null;
	/** `false` for a session store without the step-up capability (`recordSecondFactor`); absent, the store has it. */
	readonly storeRecords?: false;
	readonly acrValues?: readonly string[];
	readonly factors: MergeFactors;
	readonly expected: MergeDecision;
}

/** A group of rows, and the title the tests run it under. */
export interface MergeRowGroup {
	readonly title: string;
	readonly rows: readonly MergeRow[];
}

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

/**
 * A record without `UserSession.authentication`, read the way every
 * consumer reads it: `pwd` or `fed` in its `amr` names the primary, anything
 * else is a primary that cannot be told.
 */
const recorded = (amr: readonly string[]): UserSession => record(amr, undefined);

/** A record whose `authentication` names a primary the baseline does not know. */
const primaryOf = (primary: string, amr: readonly string[]): UserSession =>
	record(amr, { primary, federation: undefined, upstreamAmr: undefined, mfaAt: undefined });

/** The rows, by group: the MFA rule's decisions, the baseline beside `acr_values`, any-of entries with step-up targets, and a step-up the session cannot record. */
export const MERGE_ROW_GROUPS: readonly MergeRowGroup[] = [
	{
		title: "the merge — what the MFA rule decides for a session and a request",
		rows: [
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
				expected: { outcome: "reauthenticate", requirement: "baseline" },
			},
			{
				row: "nothing requested · primary unknown, required → re-authentication",
				mode: "required",
				session: recorded(["hwk"]),
				factors: "installed",
				expected: { outcome: "reauthenticate", requirement: "baseline" },
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
				row: "acr_values=phr · pre-upgrade, holding fed and an upstream hwk → the hwk is not vouched for, whatever the federation: a pre-upgrade federated session vouches for fed alone",
				mode: "optional",
				session: recorded(["hwk", "fed"]),
				acrValues: [PHR],
				factors: "none",
				expected: { outcome: "unmet", requirement: "acr" },
			},
			{
				row: "acr_values met · one the session meets wins over stepping up to one requested earlier",
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
				row: "nothing requested · an email-only login meets the baseline: the email code is a second factor, though it adds no mfa",
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
		],
	},
	{
		title: "the merge — the baseline beside acr_values",
		rows: [
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
				expected: { outcome: "reauthenticate", requirement: "baseline" },
			},
			...["PWD", "", "magiclink", "hwk"].map(
				(primary): MergeRow => ({
					row: `a primary the baseline does not know (${JSON.stringify(primary)}) is re-authenticated, never met`,
					mode: "required",
					session: primaryOf(primary, ["pwd"]),
					factors: "installed",
					expected: { outcome: "reauthenticate", requirement: "baseline" },
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
				// The ADR's row reads `{ authentication: undefined, amr: ["pwd"] }`,
				// an input no record makes (`pwd` names the primary): a record whose
				// primary cannot be told carries no primary's marker.
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
				expected: { outcome: "reauthenticate", requirement: "baseline" },
			},
			{
				row: "optional has no baseline: a password session proceeds",
				mode: "optional",
				session: passwordSession(["pwd"]),
				factors: "installed",
				expected: { outcome: "met", acr: undefined },
			},
			{
				row: "off has no baseline: a password session proceeds",
				mode: "off",
				session: passwordSession(["pwd"]),
				factors: "none",
				expected: { outcome: "met", acr: undefined },
			},
			{
				row: "off answers acr_values needing a second factor unmet: nothing is installed to step up with",
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
				// The ADR's row reads `{ authentication: undefined, amr: ["pwd", "hwk"] }`
				// (see above): a record whose primary cannot be told carries no
				// primary's marker, and its `amr` is weighed as it is.
				row: "an unknown primary outside required is weighed on its amr alone",
				mode: "optional",
				session: recorded(["kba", "hwk"]),
				acrValues: [PHR],
				factors: "installed",
				expected: { outcome: "met", acr: PHR },
			},
		],
	},
	{
		title: "the merge — any-of entries and step-up targets",
		rows: [
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
		],
	},
	{
		title: "the merge — a step-up the session cannot record",
		rows: [
			{
				row: "an acr only the authority's step-up can finish, onto a store that cannot record one → a new login (acr)",
				mode: "optional",
				session: passwordSession(["pwd"]),
				storeRecords: false,
				acrValues: [MFA],
				factors: "installed",
				expected: { outcome: "reauthenticate", requirement: "acr" },
			},
			{
				row: "an acr only the authority's step-up can finish, onto a pre-upgrade session whose primary cannot be told → a new login (acr)",
				mode: "optional",
				session: recorded(["kba"]),
				acrValues: [MFA],
				factors: "installed",
				expected: { outcome: "reauthenticate", requirement: "acr" },
			},
			{
				row: "a session that meets the baseline, asked an acr the store cannot record a step-up for → a new login (acr)",
				mode: "required",
				session: federatedSession(["fed"], ["mfa"]),
				storeRecords: false,
				acrValues: [MFA],
				factors: "installed",
				expected: { outcome: "reauthenticate", requirement: "acr" },
			},
			{
				row: "a pre-upgrade session read as a password login is stepped up for an acr: its primary is told",
				mode: "optional",
				session: recorded(["pwd"]),
				acrValues: [MFA],
				factors: "installed",
				expected: { outcome: "step_up", requirement: "acr", acrValues: [MFA] },
			},
			{
				row: "an acr no step-up can reach stays unmet onto a store that cannot record: a new login would not meet it either",
				mode: "optional",
				session: passwordSession(["pwd", "otp", "mfa"], minutesAgo(1)),
				storeRecords: false,
				acrValues: [PHR],
				factors: "withoutWebAuthn",
				expected: { outcome: "unmet", requirement: "acr" },
			},
			{
				row: "an acr the session meets is met onto a store that cannot record",
				mode: "optional",
				session: passwordSession(["pwd", "otp", "mfa"], minutesAgo(1)),
				storeRecords: false,
				acrValues: [MFA],
				factors: "installed",
				expected: { outcome: "met", acr: MFA },
			},
			{
				row: "the requirement's own step-up stands onto a store that cannot record: the requirement answers for it",
				mode: "required",
				session: passwordSession(["pwd"]),
				storeRecords: false,
				factors: "installed",
				expected: { outcome: "step_up", requirement: "baseline", acrValues: [] },
			},
		],
	},
];

/**
 * The ADR's mapping of a row's decision onto the admission, for `authority`,
 * the registered second-factor authority (`undefined` when none is
 * registered): `requirement: "acr"` stays `"acr"` (a `reauthenticate`'s too), `"baseline"` becomes the
 * authority's name, and a `step_up`'s requirement becomes `whenStillUnmet`
 * (`"acr"` → `"unmet"`, `"baseline"` → `"reauthenticate"`) with its
 * registered page. Throws for an `authority` that is not a registered
 * requirement declaring it, and for a row that names it when none is given.
 */
export function mergeAdmission(
	expected: MergeDecision,
	session: UserSession | null,
	authority: RegisteredRequirement | undefined,
): Admission {
	if (authority !== undefined) {
		if (!isRegisteredRequirement(authority)) {
			throw new Error("mergeAdmission: the authority is not a registered requirement");
		}
		if (authority.secondFactorAuthority !== true) {
			throw new Error(
				`mergeAdmission: "${authority.name}" does not declare the second-factor authority, whose rows these are`,
			);
		}
	}
	const named = (): RegisteredRequirement => {
		if (authority === undefined) {
			throw new Error(
				`mergeAdmission: the row's ${expected.outcome} names the second-factor authority, and none is given`,
			);
		}
		return authority;
	};
	switch (expected.outcome) {
		case "met":
			return {
				outcome: "admitted",
				session,
				view: session === null ? null : viewOf(session),
				acr: expected.acr,
			};
		case "reauthenticate":
			return {
				outcome: "reauthenticate",
				requirement: expected.requirement === "acr" ? "acr" : named().name,
				session,
			};
		case "step_up": {
			if (session === null) throw new Error("a step-up needs a session");
			const { name, stepUpPage } = named();
			if (stepUpPage === undefined) {
				throw new Error(`mergeAdmission: "${name}" registered no step-up page`);
			}
			return {
				outcome: "step_up",
				requirement: name,
				session,
				view: viewOf(session),
				page: stepUpPage,
				acrValues: expected.acrValues,
				whenStillUnmet: expected.requirement === "acr" ? "unmet" : "reauthenticate",
			};
		}
		case "unmet":
			return {
				outcome: "unmet",
				requirement: expected.requirement === "acr" ? "acr" : named().name,
				session,
			};
	}
}

/**
 * The session store a row runs over: one holding the row's record as
 * `sid-1`, with the step-up capability unless the row's `storeRecords` is
 * `false` — its `recordSecondFactor` records nothing (`null`) — and
 * `undefined` for a row with no session, a composition without a store.
 */
export function mergeSessionStore(row: MergeRow): UserSessionStore | undefined {
	const { session } = row;
	if (session === null) return undefined;
	const store: UserSessionStore = {
		kind: "merge-rows",
		create: async () => {},
		get: async (sid) => (sid === session.sid ? session : null),
		delete: async () => {},
	};
	return row.storeRecords === false
		? store
		: Object.assign(store, { recordSecondFactor: async () => null });
}
