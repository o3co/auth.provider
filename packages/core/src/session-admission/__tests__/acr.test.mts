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
 * The provider's `acr` vocabulary (the MFA ADR's D15, the session-admission
 * ADR's D6): the table as it is read, the selection over what a session
 * vouches for, what a step-up can reach, what the composition can produce,
 * and the drop of the entries nothing installed can satisfy.
 */

import { describe, expect, it } from "vitest";
import {
	type AcrTable,
	producibleAmr,
	readAcrTable,
	SECOND_FACTOR_AMR,
	selectAcr,
	stepUpReach,
	vouchableAcrTable,
} from "#/session-admission/acr.mjs";

const MFA = "urn:o3co:acr:mfa";
const PHR = "urn:o3co:acr:phr";
const PWD = "urn:example:pwd";
const KBA = "urn:example:kba";

/** The template's table (the MFA ADR's D15), `phr` uncommented, beside one entry only a password meets and one nothing installed produces. */
const TABLE: AcrTable = readAcrTable({
	[MFA]: ["mfa"],
	[PHR]: [["hwk"], ["swk"]],
	[PWD]: ["pwd"],
	[KBA]: ["kba"],
});

const NOTHING: ReadonlySet<string> = new Set();

const reaching = (...values: string[]) => ({ reach: new Set(values) });

describe("stepUpReach — what a step-up through the registered requirements can add", () => {
	it("is the union of every requirement's reach, in registration order", () => {
		expect([...stepUpReach([reaching("otp", "mfa"), reaching("hwk", "mfa"), reaching()])]).toEqual([
			"otp",
			"mfa",
			"hwk",
		]);
	});

	it("is empty with no requirement, and with requirements that reach nothing", () => {
		expect(stepUpReach([]).size).toBe(0);
		expect(stepUpReach([reaching(), reaching()]).size).toBe(0);
	});

	it("answers a set of its own, so a caller cannot reach a requirement's reach through it", () => {
		const own = reaching("otp");
		const reach = stepUpReach([own]) as Set<string>;
		reach.add("hwk");
		expect(own.reach.has("hwk")).toBe(false);
	});
});

describe("SECOND_FACTOR_AMR — the values reserved to the requirement named mfa", () => {
	it("is the six values a second factor adds, and no primary's marker", () => {
		expect([...SECOND_FACTOR_AMR].sort()).toEqual([
			"email",
			"hwk",
			"mfa",
			"otp",
			"recovery",
			"swk",
		]);
		expect(SECOND_FACTOR_AMR.has("pwd")).toBe(false);
		expect(SECOND_FACTOR_AMR.has("fed")).toBe(false);
	});
});

describe("selectAcr — the selection over what the session vouches for", () => {
	it("answers met with no acr when none was requested", () => {
		expect(selectAcr([], ["pwd"], TABLE, NOTHING)).toEqual({ outcome: "met", acr: undefined });
	});

	it("prefers a requested value the session meets over stepping up to an earlier one", () => {
		expect(selectAcr([PHR, MFA], ["pwd", "otp", "mfa"], TABLE, new Set(["hwk"]))).toEqual({
			outcome: "met",
			acr: MFA,
		});
	});

	it("names every requested value a step-up can meet, in the request's order", () => {
		expect(selectAcr([KBA, PHR, "urn:nope", MFA], ["pwd"], TABLE, new Set(["hwk", "mfa"]))).toEqual(
			{
				outcome: "step_up",
				acrValues: [PHR, MFA],
			},
		);
	});

	it("never reads a prototype key as an entry", () => {
		// The requested value is what an unauthenticated caller wrote; a bare
		// `table[acr]` would resolve `constructor` to `Object`.
		for (const acr of ["constructor", "toString", "__proto__", "hasOwnProperty"]) {
			expect(selectAcr([acr], ["pwd"], TABLE, new Set(["mfa"]))).toEqual({ outcome: "unmet" });
		}
		expect(selectAcr(["constructor", PWD], ["pwd"], TABLE, NOTHING)).toEqual({
			outcome: "met",
			acr: PWD,
		});
	});

	it("never steps up without a step-up to take: an empty reach leaves an unmet entry unmet", () => {
		expect(selectAcr([MFA], ["pwd"], TABLE, NOTHING)).toEqual({ outcome: "unmet" });
	});

	it("keeps an entry out of reach when a value the step-up cannot add is missing: pwd is the primary's", () => {
		expect(
			selectAcr([PWD], ["fed"], TABLE, new Set(["otp", "hwk", "swk", "recovery", "mfa"])),
		).toEqual({
			outcome: "unmet",
		});
	});

	it("never meets, and never steps up to, an alternative that requires nothing", () => {
		// `AcrTable` is a structural type: a table built by hand rather than by
		// `readAcrTable` can hold `[]`, and `[].every(…)` is true — an entry that
		// would vouch for every session.
		const handBuilt: AcrTable = { [KBA]: [[]], [PHR]: [[], ["hwk"]] };
		expect(selectAcr([KBA], [], handBuilt, new Set(["mfa"]))).toEqual({ outcome: "unmet" });
		expect(selectAcr([KBA], ["pwd", "mfa"], handBuilt, NOTHING)).toEqual({ outcome: "unmet" });
		expect(selectAcr([PHR], ["pwd"], handBuilt, NOTHING)).toEqual({ outcome: "unmet" });
		expect(selectAcr([PHR], ["pwd"], handBuilt, new Set(["hwk"]))).toEqual({
			outcome: "step_up",
			acrValues: [PHR],
		});
		expect(selectAcr([PHR], ["hwk"], handBuilt, NOTHING)).toEqual({ outcome: "met", acr: PHR });
	});
});

describe("readAcrTable — `oauth.authorize.acrValues` as it is read", () => {
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

describe("producibleAmr — what something installed can put in a session's amr", () => {
	it("is pwd alone without a requirement that reaches anything or a federation: no federation callback writes fed", () => {
		const producible = producibleAmr({
			reach: NOTHING,
			federationInstalled: false,
			trustedFederation: false,
		});
		expect(producible.anything).toBe(false);
		expect([...producible.values]).toEqual(["pwd"]);
	});

	it("adds fed once a federation is installed, and nothing else for one whose upstream amr does not count", () => {
		const producible = producibleAmr({
			reach: NOTHING,
			federationInstalled: true,
			trustedFederation: false,
		});
		expect(producible.anything).toBe(false);
		expect([...producible.values].sort()).toEqual(["fed", "pwd"]);
	});

	it("adds what the registered requirements reach — mfa only when one of them reaches it", () => {
		const emailOnly = producibleAmr({
			reach: new Set(["email"]),
			federationInstalled: false,
			trustedFederation: false,
		});
		expect([...emailOnly.values].sort()).toEqual(["email", "pwd"]);
		const totp = producibleAmr({
			reach: new Set(["otp", "mfa"]),
			federationInstalled: false,
			trustedFederation: false,
		});
		expect([...totp.values].sort()).toEqual(["mfa", "otp", "pwd"]);
	});

	it("is anything once a federation whose upstream amr counts is installed", () => {
		// An upstream IdP may assert any value, and a trusted one is recorded
		// beside `fed` (the MFA ADR's D13).
		expect(
			producibleAmr({ reach: NOTHING, federationInstalled: true, trustedFederation: true })
				.anything,
		).toBe(true);
	});

	it("refuses a trusted federation that is not installed", () => {
		expect(() =>
			producibleAmr({ reach: NOTHING, federationInstalled: false, trustedFederation: true }),
		).toThrow(RangeError);
	});
});

describe("vouchableAcrTable — an entry nothing installed can satisfy is dropped", () => {
	const configured = readAcrTable({
		[PWD]: ["pwd"],
		"urn:example:fed": ["fed"],
		[MFA]: ["pwd", "mfa"],
		[PHR]: [["hwk"], ["swk"]],
		[KBA]: ["kba"],
	});
	const nothingInstalled = producibleAmr({
		reach: NOTHING,
		federationInstalled: false,
		trustedFederation: false,
	});

	it("keeps what pwd meets and drops the rest, saying what no module produces", () => {
		const { table, dropped } = vouchableAcrTable(configured, nothingInstalled);
		expect(Object.keys(table)).toEqual([PWD]);
		expect(dropped).toEqual([
			{
				acr: "urn:example:fed",
				unproducible: ["fed"],
				forWantOfSecondFactor: false,
				emptyAlternative: false,
			},
			{ acr: MFA, unproducible: ["mfa"], forWantOfSecondFactor: true, emptyAlternative: false },
			{
				acr: PHR,
				unproducible: ["hwk", "swk"],
				forWantOfSecondFactor: true,
				emptyAlternative: false,
			},
			{ acr: KBA, unproducible: ["kba"], forWantOfSecondFactor: false, emptyAlternative: false },
		]);
	});

	it("keeps an entry the registered requirements reach, and drops one they do not", () => {
		const totpOnly = producibleAmr({
			reach: new Set(["otp", "recovery", "mfa"]),
			federationInstalled: false,
			trustedFederation: false,
		});
		const { table, dropped } = vouchableAcrTable(configured, totpOnly);
		expect(Object.keys(table)).toEqual([PWD, MFA]);
		expect(dropped.map((entry) => entry.acr)).toEqual(["urn:example:fed", PHR, KBA]);
	});

	it("keeps a fed entry once a federation is installed, and drops what its IdP's amr would meet when that does not count", () => {
		const untrusted = producibleAmr({
			reach: NOTHING,
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
			producibleAmr({ reach: NOTHING, federationInstalled: true, trustedFederation: true }),
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
		// The `hwk` alternative lacks only a value a second factor adds: a
		// requirement that reaches it would meet it, which is what decides the
		// boot line's level.
		expect(dropped).toEqual([
			{
				acr: KBA,
				unproducible: ["kba", "hwk"],
				forWantOfSecondFactor: true,
				emptyAlternative: false,
			},
		]);
	});

	it("does not read an entry as wanting only a second factor when a value no factor adds is missing too", () => {
		const { dropped } = vouchableAcrTable(
			readAcrTable({ [KBA]: ["kba", "mfa"] }),
			nothingInstalled,
		);
		expect(dropped).toEqual([
			{
				acr: KBA,
				unproducible: ["kba", "mfa"],
				forWantOfSecondFactor: false,
				emptyAlternative: false,
			},
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
			{ acr: KBA, unproducible: [], forWantOfSecondFactor: false, emptyAlternative: true },
			{ acr: PHR, unproducible: ["hwk"], forWantOfSecondFactor: true, emptyAlternative: true },
		]);
		// Even under a trusted federation, which can produce anything.
		const trusted = vouchableAcrTable(
			{ [KBA]: [[]] },
			producibleAmr({ reach: NOTHING, federationInstalled: true, trustedFederation: true }),
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
