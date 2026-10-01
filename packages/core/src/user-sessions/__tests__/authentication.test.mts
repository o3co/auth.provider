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
 * How a session was established and what this provider vouches for, read the
 * one way every consumer reads them (`sessionAuthentication`, `vouchedAmr`;
 * ADR 2026-09-25-multi-factor-authentication), and how each login path
 * records itself. A session with an `authentication` key holds in its `amr`
 * only what this provider vouches for. A pre-upgrade session is split as it
 * is read: `fed` makes it federated, and every other value beside `fed` is
 * what an upstream IdP asserted — never vouched for, whether or not that
 * federation is trusted now, since the session does not say which it was.
 */

import { describe, expect, it } from "vitest";
import { DEFAULT_CLOCK_SKEW_MS } from "#/jwt/verify.mjs";
import {
	checkSecondFactorEvent,
	federatedSessionAuthentication,
	federationTrustsUpstreamAmr,
	passwordSessionAuthentication,
	recordableSessionAuthentication,
	requirementSession,
	requirementSessionFromAmr,
	sessionAfterSecondFactor,
	sessionAuthentication,
	vouchedAmr,
} from "#/user-sessions/authentication.mjs";
import type { SessionAuthentication, UserSession } from "#/user-sessions/types.mjs";

/** A pre-upgrade session: no `authentication` value. */
const session = (amr: readonly string[] | undefined): UserSession => ({
	sid: "sid-1",
	sub: "user-1",
	authTime: new Date("2026-09-28T00:00:00Z"),
	createdAt: new Date("2026-09-28T00:00:00Z"),
	expiresAt: new Date("2026-09-28T01:00:00Z"),
	claims: {},
	amr,
	authentication: undefined,
});

/** A session that says how it was established. */
const recorded = (
	amr: readonly string[] | undefined,
	authentication: SessionAuthentication,
): UserSession => ({ ...session(amr), authentication });

const FEDERATED: SessionAuthentication = {
	primary: "fed",
	federation: "google",
	upstreamAmr: ["hwk", "mfa"],
	mfaAt: undefined,
};

describe("sessionAuthentication — a session that says how it was established", () => {
	it("is what the session recorded, whatever its amr says", () => {
		// The record is the answer: an `amr` holding `pwd` does not make a
		// federated session a password one, and `mfa` in it sets no `mfaAt`.
		const mfaAt = new Date("2026-09-28T00:10:00Z");
		expect(
			sessionAuthentication(
				recorded(["pwd", "otp", "mfa"], { ...FEDERATED, upstreamAmr: undefined, mfaAt }),
			),
		).toStrictEqual({ primary: "fed", federation: "google", upstreamAmr: undefined, mfaAt });
		expect(sessionAuthentication(recorded(["pwd", "fed"], FEDERATED))).toStrictEqual(FEDERATED);
	});

	it("keeps a recorded primary it does not know as it is: the rule re-authenticates it", () => {
		const custom = { ...FEDERATED, primary: "kba", federation: undefined };
		expect(sessionAuthentication(recorded(["kba"], custom))?.primary).toBe("kba");
	});

	it("answers a copy: nothing done to it reaches the session", () => {
		const mfaAt = new Date("2026-09-28T00:10:00Z");
		const stored = recorded(["fed"], { ...FEDERATED, mfaAt });
		const read = sessionAuthentication(stored);
		(read?.upstreamAmr as string[] | undefined)?.push("phr");
		read?.mfaAt?.setTime(0);
		expect(stored.authentication?.upstreamAmr).toEqual(["hwk", "mfa"]);
		expect(stored.authentication?.mfaAt?.getTime()).toBe(mfaAt.getTime());
	});
});

describe("sessionAuthentication — a session with no authentication recorded, split from its amr as it is read", () => {
	it("reads a password login as primary pwd, with no second factor on record", () => {
		expect(sessionAuthentication(session(["pwd"]))).toStrictEqual({
			primary: "pwd",
			federation: undefined,
			upstreamAmr: undefined,
			mfaAt: undefined,
		});
	});

	it("reads a session carrying fed as federated, and every other value as what its upstream IdP asserted", () => {
		// `fed` is the marker only a federation callback records; the values
		// beside it were the upstream IdP's, `pwd` among them. Which federation
		// wrote it the session does not say.
		expect(sessionAuthentication(session(["hwk", "fed"]))).toStrictEqual({
			primary: "fed",
			federation: undefined,
			upstreamAmr: ["hwk"],
			mfaAt: undefined,
		});
		expect(sessionAuthentication(session(["pwd", "mfa", "fed"]))?.upstreamAmr).toEqual([
			"pwd",
			"mfa",
		]);
		expect(sessionAuthentication(session(["fed"]))?.upstreamAmr).toBeUndefined();
	});

	it.each([
		["no amr", undefined],
		["an empty amr", []],
		["neither pwd nor fed", ["hwk"]],
		["mfa alone", ["mfa"]],
	])("cannot tell the primary of a session with %s: undefined", (_label, amr) => {
		// Unknown is its own answer: the baseline re-authenticates such a
		// session rather than guessing which primary it had.
		expect(sessionAuthentication(session(amr))).toBeUndefined();
	});

	it("records no second factor for a session read from its amr, whatever the amr says", () => {
		// `mfaAt` is written by the verification that sets it; a session that
		// has no `authentication` key predates any such verification.
		expect(sessionAuthentication(session(["pwd", "otp", "mfa"]))?.mfaAt).toBeUndefined();
	});
});

describe("vouchedAmr — the amr this provider vouches for", () => {
	it("is a recorded session's amr, copied: the federation callback already split it", () => {
		const federated = recorded(["hwk", "fed"], { ...FEDERATED, upstreamAmr: undefined });
		const vouched = vouchedAmr(federated);
		// A trusted federation's values sit beside `fed`, and count.
		expect(vouched).toEqual(["hwk", "fed"]);
		expect(vouched).not.toBe(federated.amr);
	});

	it("is a pre-upgrade password session's amr, copied", () => {
		const password = session(["pwd"]);
		expect(vouchedAmr(password)).toEqual(["pwd"]);
		expect(vouchedAmr(password)).not.toBe(password.amr);
	});

	it("is fed alone for a pre-upgrade federated session: what its upstream IdP asserted is not vouched for", () => {
		// A pre-upgrade `["hwk", "fed"]` must never meet an `acr` that needs
		// `hwk`, nor stamp it on a token.
		expect(vouchedAmr(session(["hwk", "fed"]))).toEqual(["fed"]);
		expect(vouchedAmr(session(["pwd", "mfa", "fed"]))).toEqual(["fed"]);
	});

	it("is empty for a session that recorded no amr", () => {
		expect(vouchedAmr(session(undefined))).toEqual([]);
		expect(vouchedAmr(recorded(undefined, FEDERATED))).toEqual([]);
	});

	it.each([
		["a string", "mfa"],
		["a string holding fed", "confed"],
		["an array holding a non-string", ["pwd", 1]],
		["an array holding an empty string", ["pwd", ""]],
		["an array with a hole", Object.assign(new Array<string>(3), { 0: "pwd", 2: "mfa" })],
		["an object", { 0: "pwd", length: 1 }],
	])(
		"is empty for a session whose stored amr is %s: a custom store's record is not trusted for its shape",
		(_label, stored) => {
			// A string spread would become one-letter methods, `["m", "f", "a"]`.
			const amr = stored as unknown as readonly string[];
			expect(vouchedAmr({ ...session(undefined), amr })).toEqual([]);
			expect(vouchedAmr(recorded(amr, FEDERATED))).toEqual([]);
		},
	);
});

describe("requirementSession — the requirement rule's input, built from sessionAuthentication and vouchedAmr", () => {
	it("is sessionAuthentication and vouchedAmr of the session", () => {
		for (const s of [
			session(["pwd", "otp"]),
			session(["hwk", "fed"]),
			recorded(["fed"], FEDERATED),
		]) {
			expect(requirementSession(s)).toEqual({
				authentication: sessionAuthentication(s),
				amr: vouchedAmr(s),
			});
		}
	});

	it("carries the vouched amr, never the record's own array", () => {
		const federated = recorded(["hwk", "fed"], { ...FEDERATED, upstreamAmr: undefined });
		const input = requirementSession(federated);
		expect(input?.amr).toEqual(["hwk", "fed"]);
		expect(input?.amr).not.toBe(federated.amr);
		expect(requirementSession(session(["hwk", "fed"]))?.amr).toEqual(["fed"]);
	});

	it("keeps an unknown primary unknown", () => {
		expect(requirementSession(session(["hwk"]))).toEqual({
			authentication: undefined,
			amr: ["hwk"],
		});
	});

	it("is null for no session: no sid, or no store", () => {
		expect(requirementSession(null)).toBeNull();
	});
});

describe("requirementSessionFromAmr — what a requirement is asked about a token with no live session", () => {
	it("reads the primary from the token's amr — fed first, else pwd — with no second factor on record, and the amr as vouched", () => {
		expect(requirementSessionFromAmr(["pwd", "otp", "mfa"])).toEqual({
			authentication: {
				primary: "pwd",
				federation: undefined,
				upstreamAmr: undefined,
				mfaAt: undefined,
			},
			amr: ["pwd", "otp", "mfa"],
		});
		expect(requirementSessionFromAmr(["hwk", "fed"])).toEqual({
			authentication: {
				primary: "fed",
				federation: undefined,
				upstreamAmr: undefined,
				mfaAt: undefined,
			},
			amr: ["hwk", "fed"],
		});
		expect(requirementSessionFromAmr(["pwd", "fed"]).authentication?.primary).toBe("fed");
	});

	it("reads a token without an amr, or one naming no primary, as a primary that cannot be told", () => {
		expect(requirementSessionFromAmr(undefined)).toEqual({ authentication: undefined, amr: [] });
		expect(requirementSessionFromAmr(["otp"])).toEqual({ authentication: undefined, amr: ["otp"] });
	});

	it("copies the amr", () => {
		const amr = ["pwd"];
		const input = requirementSessionFromAmr(amr);
		amr.push("otp");
		expect(input.amr).toEqual(["pwd"]);
	});
});

describe("passwordSessionAuthentication — what POST /session/login records", () => {
	it("is amr pwd, primary pwd, every other field named and empty", () => {
		expect(passwordSessionAuthentication()).toStrictEqual({
			amr: ["pwd"],
			authentication: {
				primary: "pwd",
				federation: undefined,
				upstreamAmr: undefined,
				mfaAt: undefined,
			},
		});
	});
});

describe("federatedSessionAuthentication — what a federation callback records", () => {
	it("keeps an untrusted IdP's amr apart: amr is fed alone, and its values are kept for the record", () => {
		expect(
			federatedSessionAuthentication({
				federation: "google",
				upstreamAmr: ["hwk", "mfa"],
				trusted: false,
			}),
		).toStrictEqual({
			amr: ["fed"],
			authentication: {
				primary: "fed",
				federation: "google",
				upstreamAmr: ["hwk", "mfa"],
				mfaAt: undefined,
			},
		});
	});

	it("records a trusted IdP's amr beside fed, where it counts, and keeps nothing apart", () => {
		expect(
			federatedSessionAuthentication({
				federation: "google",
				upstreamAmr: ["hwk", "mfa", "fed"],
				trusted: true,
			}),
		).toStrictEqual({
			amr: ["hwk", "mfa", "fed"],
			authentication: {
				primary: "fed",
				federation: "google",
				upstreamAmr: undefined,
				mfaAt: undefined,
			},
		});
	});

	it("records fed alone, and nothing apart, when the IdP asserted nothing", () => {
		for (const trusted of [true, false]) {
			expect(
				federatedSessionAuthentication({ federation: "google", upstreamAmr: [], trusted }),
			).toStrictEqual({
				amr: ["fed"],
				authentication: {
					primary: "fed",
					federation: "google",
					upstreamAmr: undefined,
					mfaAt: undefined,
				},
			});
		}
	});

	it("copies what it is handed", () => {
		const upstreamAmr = ["hwk"];
		const untrusted = federatedSessionAuthentication({
			federation: "google",
			upstreamAmr,
			trusted: false,
		});
		upstreamAmr.push("mfa");
		expect(untrusted.authentication.upstreamAmr).toEqual(["hwk"]);
	});
});

describe("federationTrustsUpstreamAmr — whether an upstream IdP's amr counts", () => {
	const config = (entry: unknown) => ({ core: { federations: { google: entry } } });

	it("is false by default: an upstream IdP's word is not this provider's", () => {
		expect(federationTrustsUpstreamAmr(config({ enabled: true }), "google")).toBe(false);
		expect(federationTrustsUpstreamAmr({ core: { federations: {} } }, "google")).toBe(false);
		expect(federationTrustsUpstreamAmr({}, "google")).toBe(false);
		// The map written at the top level is not core's: boot refuses it.
		expect(
			federationTrustsUpstreamAmr(
				{ federations: { google: { enabled: true, trustUpstreamAmr: true } } },
				"google",
			),
		).toBe(false);
		expect(federationTrustsUpstreamAmr(undefined, "google")).toBe(false);
	});

	it("is true only for a federation configured with trustUpstreamAmr = true", () => {
		expect(
			federationTrustsUpstreamAmr(config({ enabled: true, trustUpstreamAmr: true }), "google"),
		).toBe(true);
		expect(
			federationTrustsUpstreamAmr(config({ enabled: true, trustUpstreamAmr: false }), "google"),
		).toBe(false);
		// Another federation's switch is not this one's.
		expect(
			federationTrustsUpstreamAmr(
				{ core: { federations: { github: { trustUpstreamAmr: true } } } },
				"google",
			),
		).toBe(false);
	});

	it("is false for a section that is not enabled, whatever its switch says: nothing signs a user in through it", () => {
		for (const enabled of [false, undefined, "true", 1]) {
			expect(
				federationTrustsUpstreamAmr(config({ enabled, trustUpstreamAmr: true }), "google"),
			).toBe(false);
		}
		expect(federationTrustsUpstreamAmr(config({ trustUpstreamAmr: true }), "google")).toBe(false);
	});

	it("still refuses an unusable switch on a section that is not enabled, and one inside its sub-section", () => {
		// Enabling the federation later must not be what first reveals it.
		expect(() =>
			federationTrustsUpstreamAmr(config({ enabled: false, trustUpstreamAmr: "yes" }), "google"),
		).toThrow(new RangeError("core.federations.google.trustUpstreamAmr must be true or false"));
		expect(() =>
			federationTrustsUpstreamAmr(
				config({ enabled: false, type: "oidc", oidc: { trustUpstreamAmr: true } }),
				"google",
			),
		).toThrow(RangeError);
	});

	it("reads the switch beside enabled in the nested shape too", () => {
		expect(
			federationTrustsUpstreamAmr(
				config({ enabled: true, type: "google", trustUpstreamAmr: true, google: {} }),
				"google",
			),
		).toBe(true);
		expect(
			federationTrustsUpstreamAmr(
				config({ enabled: true, type: "google", google: { clientId: "x" } }),
				"google",
			),
		).toBe(false);
	});

	it.each([
		[
			"a typed sub-section",
			{ okta: { enabled: true, type: "oidc", oidc: { trustUpstreamAmr: true } } },
			"okta",
			"core.federations.okta.oidc.trustUpstreamAmr",
		],
		[
			"a typed sub-section, saying false",
			{ okta: { enabled: true, type: "oidc", oidc: { trustUpstreamAmr: false } } },
			"okta",
			"core.federations.okta.oidc.trustUpstreamAmr",
		],
		[
			"the sub-section a shorthand key names",
			{ google: { enabled: true, google: { trustUpstreamAmr: true } } },
			"google",
			"core.federations.google.google.trustUpstreamAmr",
		],
	])(
		"refuses the switch inside %s, saying it belongs beside enabled, rather than ignore it",
		(_label, federations, name, placed) => {
			// Ignored there, an operator who wrote it would believe the IdP
			// trusted — or, writing false, distrusted — when neither holds.
			expect(() => federationTrustsUpstreamAmr({ core: { federations } }, name)).toThrow(
				new RangeError(
					`${placed} belongs beside enabled, as core.federations.${name}.trustUpstreamAmr`,
				),
			);
		},
	);

	it.each([
		["a string", "true"],
		["a number", 1],
		["null", null],
		["an object", {}],
	])(
		"refuses a value that is %s, naming the key, rather than read it as either answer",
		(_label, value) => {
			// A configured value that is given but unusable fails at boot; core's
			// schema coerces the spellings an environment variable delivers first.
			expect(() =>
				federationTrustsUpstreamAmr(config({ enabled: true, trustUpstreamAmr: value }), "google"),
			).toThrow(new RangeError("core.federations.google.trustUpstreamAmr must be true or false"));
		},
	);

	it("reads no inherited key: a federation named like an Object.prototype member has no switch", () => {
		expect(federationTrustsUpstreamAmr({ core: { federations: {} } }, "constructor")).toBe(false);
		expect(federationTrustsUpstreamAmr({ core: { federations: {} } }, "__proto__")).toBe(false);
	});
});

describe("checkSecondFactorEvent — what a verified second factor may add, and when", () => {
	const NOW = Date.parse("2026-09-28T12:00:00Z");

	it("accepts a factor's values, and a time up to the clock skew tolerated between hosts ahead of the store's clock", () => {
		expect(() =>
			checkSecondFactorEvent({ amr: ["otp", "mfa"], at: new Date(NOW) }, NOW),
		).not.toThrow();
		expect(() =>
			checkSecondFactorEvent({ amr: ["email"], at: new Date(NOW + DEFAULT_CLOCK_SKEW_MS) }, NOW),
		).not.toThrow();
	});

	it("refuses a time further ahead than that: no host's clock reads it", () => {
		expect(() =>
			checkSecondFactorEvent(
				{ amr: ["otp", "mfa"], at: new Date(NOW + DEFAULT_CLOCK_SKEW_MS + 1) },
				NOW,
			),
		).toThrow(RangeError);
	});

	it("refuses mfa without a factor's own value: it names no factor that was verified", () => {
		expect(() => checkSecondFactorEvent({ amr: ["mfa"], at: new Date(NOW) }, NOW)).toThrow(
			RangeError,
		);
	});
});

describe("recordableSessionAuthentication — what a session may record as authentication", () => {
	const NOW = Date.parse("2026-09-28T12:00:00Z");
	const PASSWORD = {
		primary: "pwd",
		federation: undefined,
		upstreamAmr: undefined,
		mfaAt: undefined,
	};

	it("accepts nothing recorded, and what SessionAuthentication admits", () => {
		for (const authentication of [
			undefined,
			PASSWORD,
			{ ...PASSWORD, mfaAt: new Date(NOW) },
			{ primary: "fed", federation: "google", upstreamAmr: ["hwk"], mfaAt: undefined },
			{ primary: "fed", federation: "google", upstreamAmr: [], mfaAt: undefined },
		]) {
			expect(() => recordableSessionAuthentication("sid-1", authentication, NOW)).not.toThrow();
		}
	});

	it.each([
		["a string", "pwd", "authentication"],
		["null", null, "authentication"],
		["a list", [], "authentication"],
		["no primary", { federation: undefined }, "authentication.primary"],
		["an empty primary", { ...PASSWORD, primary: "" }, "authentication.primary"],
		["a federation that is a number", { ...PASSWORD, federation: 1 }, "authentication.federation"],
		[
			"an upstreamAmr that is a string",
			{ ...PASSWORD, upstreamAmr: "hwk" },
			"authentication.upstreamAmr",
		],
		[
			"an upstreamAmr holding a number",
			{ ...PASSWORD, upstreamAmr: ["hwk", 1] },
			"authentication.upstreamAmr",
		],
		["an mfaAt that is a number", { ...PASSWORD, mfaAt: NOW }, "authentication.mfaAt"],
		["an Invalid Date mfaAt", { ...PASSWORD, mfaAt: new Date(Number.NaN) }, "authentication.mfaAt"],
		["an mfaAt before 1970", { ...PASSWORD, mfaAt: new Date(-1) }, "authentication.mfaAt"],
		[
			"an mfaAt further ahead than clocks drift",
			{ ...PASSWORD, mfaAt: new Date(NOW + DEFAULT_CLOCK_SKEW_MS + 1) },
			"authentication.mfaAt",
		],
	])(
		"refuses %s with a RangeError naming the field, and quoting nothing of the value",
		(_label, authentication, field) => {
			let thrown: unknown;
			try {
				recordableSessionAuthentication("sid-1", authentication, NOW);
			} catch (err) {
				thrown = err;
			}
			expect(thrown).toBeInstanceOf(RangeError);
			expect((thrown as Error).message).toContain(field);
			expect((thrown as Error).message).not.toMatch(/hwk|google/);
		},
	);
});

describe("never a verification time ahead of the store's clock", () => {
	const NOW = Date.parse("2026-09-28T12:00:00Z");
	const PASSWORD = {
		primary: "pwd",
		federation: undefined,
		upstreamAmr: undefined,
		mfaAt: undefined,
	};
	const recorded = (mfaAt: Date | undefined): UserSession => ({
		...session(["pwd", "otp", "mfa"]),
		authentication: { ...PASSWORD, mfaAt },
	});

	it("recordableSessionAuthentication answers what to record: a copy, its mfaAt no later than the store's clock", () => {
		const given = { ...PASSWORD, mfaAt: new Date(NOW + 60_000) };
		const toRecord = recordableSessionAuthentication("sid-1", given, NOW);
		expect(toRecord).toStrictEqual({ ...PASSWORD, mfaAt: new Date(NOW) });
		expect(toRecord).not.toBe(given);
		const past = { ...PASSWORD, mfaAt: new Date(NOW - 60_000) };
		expect(recordableSessionAuthentication("sid-1", past, NOW)).toStrictEqual(past);
		expect(recordableSessionAuthentication("sid-1", undefined, NOW)).toBeUndefined();
	});

	it("sessionAfterSecondFactor records a factor's time a little ahead as the store's now", () => {
		expect(
			sessionAfterSecondFactor(
				recorded(undefined),
				{ amr: ["otp", "mfa"], at: new Date(NOW + 60_000) },
				NOW,
			)?.authentication.mfaAt,
		).toStrictEqual(new Date(NOW));
	});

	it("sessionAfterSecondFactor brings a stored mfaAt ahead of the store's clock back to it before taking the later of the two", () => {
		// A replica whose clock ran ahead recorded it; kept as the later, it
		// would never come back, and would count as recent for as long.
		expect(
			sessionAfterSecondFactor(
				recorded(new Date(NOW + 10 * 60_000)),
				{ amr: ["otp", "mfa"], at: new Date(NOW - 1_000) },
				NOW,
			)?.authentication.mfaAt,
		).toStrictEqual(new Date(NOW));
		// One in the past stays the later when it is.
		expect(
			sessionAfterSecondFactor(
				recorded(new Date(NOW - 1_000)),
				{ amr: ["otp", "mfa"], at: new Date(NOW - 5_000) },
				NOW,
			)?.authentication.mfaAt,
		).toStrictEqual(new Date(NOW - 1_000));
	});
});
