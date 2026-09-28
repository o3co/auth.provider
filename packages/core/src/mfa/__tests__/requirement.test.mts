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
 * The requirement rule (the MFA ADR's D15, D16, D17): whether a session meets
 * the deployment's baseline and the `acr_values` a relying party asked for,
 * and if not, whether a step-up could meet them.
 *
 * The rows below are D17's table, the rows the rule decides: the freshness
 * rows (`max_age`, `prompt=login`, the ask) and the `prompt=none` answers are
 * `/authorize`'s, around the rule.
 */

import { describe, expect, it } from "vitest";
import {
	type AcrTable,
	decideMfaRequirement,
	type MfaMode,
	type MfaRequirementDecision,
	type MfaRequirementSession,
	producibleAmr,
	readAcrTable,
	selectAcr,
	vouchableAcrTable,
} from "#/mfa/requirement.mjs";
import { sessionAuthentication, vouchedAmr } from "#/user-sessions/authentication.mjs";

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
 * What the installed factors can add (`mfaCoordinator.secondFactorMethods`):
 * each factor's values, and `mfa` when one of them adds it.
 */
const FACTORS = {
	/** TOTP, WebAuthn and recovery codes. */
	installed: new Set(["otp", "hwk", "swk", "recovery", "mfa"]),
	/** TOTP and recovery codes: no factor adds `hwk` or `swk`. */
	withoutWebAuthn: new Set(["otp", "recovery", "mfa"]),
	/** Email codes alone, which do not add `mfa` (O7). */
	emailOnly: new Set(["email"]),
	/** No coordinator: nothing can step a session up. */
	none: undefined,
} as const;

const minutesAgo = (minutes: number): Date => new Date(Date.now() - minutes * 60_000);

const passwordSession = (amr: readonly string[], mfaAt?: Date): MfaRequirementSession => ({
	authentication: { primary: "pwd", federation: undefined, upstreamAmr: undefined, mfaAt },
	amr,
});

const federatedSession = (
	amr: readonly string[],
	upstreamAmr?: readonly string[],
): MfaRequirementSession => ({
	authentication: { primary: "fed", federation: "google", upstreamAmr, mfaAt: undefined },
	amr,
});

/** A record as it is stored today, read the one way every consumer reads it (D9). */
const recorded = (amr: readonly string[]): MfaRequirementSession => {
	const session = {
		sid: "sid-1",
		sub: "user-1",
		authTime: minutesAgo(1),
		createdAt: minutesAgo(1),
		expiresAt: new Date(Date.now() + 3_600_000),
		claims: {},
		amr,
	};
	return { authentication: sessionAuthentication(session), amr: vouchedAmr(session) };
};

interface Row {
	/** The D17 (or D16, D20) row the case pins, as the ADR words it. */
	readonly row: string;
	readonly mode: MfaMode;
	readonly session: MfaRequirementSession | null;
	readonly acrValues?: readonly string[];
	readonly factors: keyof typeof FACTORS;
	readonly expected: MfaRequirementDecision;
}

const decide = (row: Row): MfaRequirementDecision =>
	decideMfaRequirement({
		session: row.session,
		acrValues: row.acrValues ?? [],
		mode: row.mode,
		table: TABLE,
		secondFactorMethods: FACTORS[row.factors],
	});

describe("decideMfaRequirement — D17's rows", () => {
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
			session: { authentication: undefined, amr: ["hwk"] },
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

	it.each(rows)("$row", (row) => {
		expect(decide(row)).toEqual(row.expected);
	});
});

describe("decideMfaRequirement — the baseline beside acr_values (D16)", () => {
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
			row: "a session of unknown primary is re-authenticated before any acr in the table is weighed",
			mode: "required",
			session: { authentication: undefined, amr: ["hwk"] },
			acrValues: [PHR],
			factors: "installed",
			expected: { outcome: "reauthenticate" },
		},
		...["PWD", "", "magiclink", "hwk"].map(
			(primary): Row => ({
				row: `a primary the baseline does not know (${JSON.stringify(primary)}) is re-authenticated, never met`,
				mode: "required",
				session: {
					authentication: {
						primary,
						federation: undefined,
						upstreamAmr: undefined,
						mfaAt: undefined,
					},
					amr: ["pwd"],
				},
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
			row: "a request no value of which the table carries is unmet before an unknown primary is re-authenticated",
			mode: "required",
			session: { authentication: undefined, amr: ["pwd"] },
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
			row: "an unknown primary outside required is weighed on its amr alone",
			mode: "optional",
			session: { authentication: undefined, amr: ["pwd", "hwk"] },
			acrValues: [PHR],
			factors: "installed",
			expected: { outcome: "met", acr: PHR },
		},
	];

	it.each(rows)("$row", (row) => {
		expect(decide(row)).toEqual(row.expected);
	});
});

describe("decideMfaRequirement — any-of entries and step-up targets (D15, D16)", () => {
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

	it.each(rows)("$row", (row) => {
		expect(decide(row)).toEqual(row.expected);
	});
});

describe("selectAcr — D15's selection over what the session vouches for", () => {
	it("answers met with no acr when none was requested", () => {
		expect(selectAcr([], ["pwd"], TABLE, new Set())).toEqual({ outcome: "met", acr: undefined });
	});

	it("never reads a prototype key as an entry", () => {
		// The requested value is what an unauthenticated caller wrote; a bare
		// `table[acr]` would resolve `constructor` to `Object`.
		for (const acr of ["constructor", "toString", "__proto__", "hasOwnProperty"]) {
			expect(selectAcr([acr], ["pwd"], TABLE, new Set(["mfa"]))).toEqual({ outcome: "unmet" });
		}
		expect(selectAcr(["constructor", PWD], ["pwd"], TABLE, new Set())).toEqual({
			outcome: "met",
			acr: PWD,
		});
	});

	it("never steps up without a step-up to take: an empty reach leaves an unmet entry unmet", () => {
		expect(selectAcr([MFA], ["pwd"], TABLE, new Set())).toEqual({ outcome: "unmet" });
	});

	it("never meets, and never steps up to, an alternative that requires nothing", () => {
		// `AcrTable` is a structural type: a table built by hand rather than by
		// `readAcrTable` can hold `[]`, and `[].every(…)` is true — an entry that
		// would vouch for every session.
		const handBuilt: AcrTable = { [KBA]: [[]], [PHR]: [[], ["hwk"]] };
		expect(selectAcr([KBA], [], handBuilt, new Set(["mfa"]))).toEqual({ outcome: "unmet" });
		expect(selectAcr([KBA], ["pwd", "mfa"], handBuilt, new Set())).toEqual({ outcome: "unmet" });
		expect(selectAcr([PHR], ["pwd"], handBuilt, new Set())).toEqual({ outcome: "unmet" });
		expect(selectAcr([PHR], ["pwd"], handBuilt, new Set(["hwk"]))).toEqual({
			outcome: "step_up",
			acrValues: [PHR],
		});
		expect(selectAcr([PHR], ["hwk"], handBuilt, new Set())).toEqual({ outcome: "met", acr: PHR });
	});
});

describe("readAcrTable — `oauth.authorize.acrValues` as the rule reads it", () => {
	it("reads a list as one alternative and a list of lists as alternatives", () => {
		const table = readAcrTable({
			[PWD]: ["pwd"],
			[MFA]: ["pwd", "mfa"],
			[PHR]: [["hwk"], ["swk"]],
		});
		expect({ ...table }).toEqual({
			[PWD]: [["pwd"]],
			[MFA]: [["pwd", "mfa"]],
			[PHR]: [["hwk"], ["swk"]],
		});
	});

	it("copies what it reads, so a later change to the source does not reach it", () => {
		const source = { [PHR]: [["hwk"], ["swk"]] };
		const table = readAcrTable(source);
		source[PHR][0]?.push("kba");
		source[PHR].push(["kba"]);
		expect(table[PHR]).toEqual([["hwk"], ["swk"]]);
	});

	it.each([
		["an empty list", []],
		["an empty value", [""]],
		["a non-string value", [7]],
		["an empty alternative", [["hwk"], []]],
		["only an empty alternative", [[]]],
		["a list mixing values and alternatives", ["pwd", ["hwk"]]],
		["a string", "pwd"],
		["null", null],
	])("skips an entry that is %s: it requires nothing, or nothing it can name", (_label, entry) => {
		// A schema-validated configuration never gets here with one — the
		// schema refuses it at boot; this reads a hand-built one without
		// letting an entry that requires nothing vouch for every session.
		expect(Object.keys(readAcrTable({ [KBA]: entry, [PWD]: ["pwd"] }))).toEqual([PWD]);
	});

	it.each([
		["undefined", undefined],
		["a list", [["pwd"]]],
		["a string", "urn:x"],
	])("reads %s as no table", (_label, raw) => {
		expect(Object.keys(readAcrTable(raw))).toEqual([]);
	});

	it("builds a table with no prototype", () => {
		// `ResolvedOAuthOptions` hands the table on; a reader that forgets
		// `Object.hasOwn` still finds no `constructor` in it.
		const table = readAcrTable({ [PWD]: ["pwd"] });
		expect(Object.getPrototypeOf(table)).toBeNull();
		expect("constructor" in table).toBe(false);
	});
});

describe("producibleAmr — what something installed can put in a session's amr (D15)", () => {
	it("is pwd alone without MFA or a federation: no federation callback writes fed", () => {
		const producible = producibleAmr({
			secondFactorMethods: undefined,
			federationInstalled: false,
			trustedFederation: false,
		});
		expect(producible.anything).toBe(false);
		expect([...producible.values]).toEqual(["pwd"]);
	});

	it("adds fed once a federation is installed, and nothing else for one whose upstream amr does not count", () => {
		const producible = producibleAmr({
			secondFactorMethods: undefined,
			federationInstalled: true,
			trustedFederation: false,
		});
		expect(producible.anything).toBe(false);
		expect([...producible.values].sort()).toEqual(["fed", "pwd"]);
	});

	it("adds what the installed factors add — mfa only when the coordinator says one of them adds it", () => {
		const emailOnly = producibleAmr({
			secondFactorMethods: new Set(["email"]),
			federationInstalled: false,
			trustedFederation: false,
		});
		expect([...emailOnly.values].sort()).toEqual(["email", "pwd"]);
		const totp = producibleAmr({
			secondFactorMethods: new Set(["otp", "mfa"]),
			federationInstalled: false,
			trustedFederation: false,
		});
		expect([...totp.values].sort()).toEqual(["mfa", "otp", "pwd"]);
	});

	it("is anything once a federation whose upstream amr counts is installed", () => {
		// An upstream IdP may assert any value, and a trusted one is recorded
		// beside `fed` (D13). Until the upstream split every federation is.
		expect(
			producibleAmr({
				secondFactorMethods: undefined,
				federationInstalled: true,
				trustedFederation: true,
			}).anything,
		).toBe(true);
	});

	it("refuses a trusted federation that is not installed", () => {
		expect(() =>
			producibleAmr({
				secondFactorMethods: undefined,
				federationInstalled: false,
				trustedFederation: true,
			}),
		).toThrow(RangeError);
	});
});

describe("vouchableAcrTable — an entry nothing installed can satisfy is dropped (D15)", () => {
	const configured = readAcrTable({
		[PWD]: ["pwd"],
		"urn:example:fed": ["fed"],
		[MFA]: ["pwd", "mfa"],
		[PHR]: [["hwk"], ["swk"]],
		[KBA]: ["kba"],
	});
	const nothingInstalled = producibleAmr({
		secondFactorMethods: undefined,
		federationInstalled: false,
		trustedFederation: false,
	});

	it("keeps what pwd meets and drops the rest, saying what no module produces", () => {
		const { table, dropped } = vouchableAcrTable(configured, nothingInstalled);
		expect(Object.keys(table)).toEqual([PWD]);
		expect(dropped).toEqual([
			{ acr: "urn:example:fed", unproducible: ["fed"], forWantOfSecondFactor: false },
			{ acr: MFA, unproducible: ["mfa"], forWantOfSecondFactor: true },
			{ acr: PHR, unproducible: ["hwk", "swk"], forWantOfSecondFactor: true },
			{ acr: KBA, unproducible: ["kba"], forWantOfSecondFactor: false },
		]);
	});

	it("keeps an entry the installed factors meet, and drops one they do not", () => {
		const totpOnly = producibleAmr({
			secondFactorMethods: new Set(["otp", "recovery", "mfa"]),
			federationInstalled: false,
			trustedFederation: false,
		});
		const { table, dropped } = vouchableAcrTable(configured, totpOnly);
		expect(Object.keys(table)).toEqual([PWD, MFA]);
		expect(dropped.map((entry) => entry.acr)).toEqual(["urn:example:fed", PHR, KBA]);
	});

	it("keeps a fed entry once a federation is installed, and drops what its IdP's amr would meet when that does not count", () => {
		const untrusted = producibleAmr({
			secondFactorMethods: undefined,
			federationInstalled: true,
			trustedFederation: false,
		});
		const { table, dropped } = vouchableAcrTable(configured, untrusted);
		expect(Object.keys(table)).toEqual([PWD, "urn:example:fed"]);
		expect(dropped.map((entry) => entry.acr)).toEqual([MFA, PHR, KBA]);
	});

	it("drops nothing when an installed federation's upstream amr counts", () => {
		const { table, dropped } = vouchableAcrTable(
			configured,
			producibleAmr({
				secondFactorMethods: undefined,
				federationInstalled: true,
				trustedFederation: true,
			}),
		);
		expect({ ...table }).toEqual({ ...configured });
		expect(dropped).toEqual([]);
	});

	it("keeps an any-of entry whole when one alternative can be met", () => {
		const { table } = vouchableAcrTable(
			readAcrTable({ [KBA]: [["kba"], ["pwd"]] }),
			nothingInstalled,
		);
		expect(table[KBA]).toEqual([["kba"], ["pwd"]]);
	});

	it("drops an any-of entry no alternative of which can be met, each value named once", () => {
		const { dropped } = vouchableAcrTable(
			readAcrTable({ [KBA]: [["kba", "hwk"], ["hwk"]] }),
			nothingInstalled,
		);
		// The `hwk` alternative lacks only a value a second factor adds: MFA
		// installed would meet it, which is what decides the boot line's level.
		expect(dropped).toEqual([
			{ acr: KBA, unproducible: ["kba", "hwk"], forWantOfSecondFactor: true },
		]);
	});

	it("does not read an entry as wanting only a second factor when a value no factor adds is missing too", () => {
		const { dropped } = vouchableAcrTable(
			readAcrTable({ [KBA]: ["kba", "mfa"] }),
			nothingInstalled,
		);
		expect(dropped).toEqual([
			{ acr: KBA, unproducible: ["kba", "mfa"], forWantOfSecondFactor: false },
		]);
	});

	it("reads an alternative that requires nothing as one nothing can meet", () => {
		// A table built by hand: `readAcrTable` never makes one.
		const { table, dropped } = vouchableAcrTable(
			{ [KBA]: [[]], [PHR]: [[], ["hwk"]], [PWD]: [[], ["pwd"]] },
			nothingInstalled,
		);
		expect(Object.keys(table)).toEqual([PWD]);
		expect(dropped).toEqual([
			{ acr: KBA, unproducible: [], forWantOfSecondFactor: false },
			{ acr: PHR, unproducible: ["hwk"], forWantOfSecondFactor: true },
		]);
		// Even under a trusted federation, which can produce anything.
		const trusted = vouchableAcrTable(
			{ [KBA]: [[]] },
			producibleAmr({
				secondFactorMethods: undefined,
				federationInstalled: true,
				trustedFederation: true,
			}),
		);
		expect(Object.keys(trusted.table)).toEqual([]);
	});

	it("builds a new table with no prototype and leaves the configured one as it was", () => {
		const before = { ...configured };
		const { table } = vouchableAcrTable(configured, nothingInstalled);
		expect(Object.getPrototypeOf(table)).toBeNull();
		expect({ ...configured }).toEqual(before);
	});
});
