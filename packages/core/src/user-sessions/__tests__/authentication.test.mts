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
	authenticationFreshness,
	canRecordSecondFactor,
	checkSecondFactorEvent,
	copySessionAuthentication,
	federatedSessionAuthentication,
	federationCallbackMeetsFreshness,
	federationTrustsUpstreamAmr,
	passwordSessionAuthentication,
	recordableSessionAuthentication,
	requirementSession,
	requirementSessionFromAmr,
	sessionAfterSecondFactor,
	sessionAuthentication,
	sessionFreshness,
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

	it.each([
		["an empty string", ["", "fed"]],
		["a non-string", ["fed", 1]],
	])(
		"is fed alone for a pre-upgrade federated session whose amr also holds %s: the split comes first",
		(_label, stored) => {
			// An older federation callback recorded such values beside `fed`; none
			// of them is vouched for, and `fed` still is.
			const amr = stored as unknown as readonly string[];
			expect(vouchedAmr(session(amr))).toEqual(["fed"]);
			expect(vouchedAmr(recorded(amr, FEDERATED))).toEqual([]);
		},
	);
});

describe("a pre-upgrade session whose stored amr is not well formed — its primary cannot be told", () => {
	it.each([
		["a string holding fed", "confed"],
		["a string holding pwd", "xpwdx"],
		["a string that is pwd", "pwd"],
		["an object", { 0: "pwd", length: 1 }],
		["an array holding a non-string", ["pwd", 1]],
		["an array holding an empty string", ["pwd", ""]],
		["an array with a hole", Object.assign(new Array<string>(3), { 0: "pwd", 2: "mfa" })],
	])(
		"sessionAuthentication answers undefined for an amr that is %s, and does not throw",
		(_label, stored) => {
			// The baseline re-authenticates a primary it cannot tell; a throw would
			// reach every request that admits the session instead.
			const amr = stored as unknown as readonly string[];
			expect(sessionAuthentication(session(amr))).toBeUndefined();
			expect(requirementSession(session(amr))).toEqual({ authentication: undefined, amr: [] });
		},
	);

	it.each([
		["an empty string", ["", "fed"]],
		["a non-string", ["fed", 1]],
		["a hole", Object.assign(new Array<string>(3), { 0: "fed", 2: "hwk" })],
	])(
		"reads a federated session whose amr also holds %s as federated, as vouchedAmr does, keeping no upstream value",
		(_label, stored) => {
			// The split comes first for both readers; what is beside `fed` is kept
			// for the record only when it is an amr.
			const amr = stored as unknown as readonly string[];
			expect(sessionAuthentication(session(amr))).toStrictEqual({
				primary: "fed",
				federation: undefined,
				upstreamAmr: undefined,
				mfaAt: undefined,
			});
			expect(vouchedAmr(session(amr))).toEqual(["fed"]);
		},
	);
});

describe("a session whose recorded authentication is not one SessionAuthentication admits — it cannot be told", () => {
	const PASSWORD: SessionAuthentication = {
		primary: "pwd",
		federation: undefined,
		upstreamAmr: undefined,
		mfaAt: undefined,
	};

	it.each([
		["an empty object", {}],
		["null", null],
		["a string", "pwd"],
		["a list", []],
		["a null primary", { ...PASSWORD, primary: null }],
		["an empty primary", { ...PASSWORD, primary: "" }],
		["a federation that is a number", { ...PASSWORD, federation: 1 }],
		["a null upstreamAmr", { ...PASSWORD, upstreamAmr: null }],
		["an upstreamAmr that is a string", { ...PASSWORD, upstreamAmr: "hwk" }],
		["an upstreamAmr holding a number", { ...PASSWORD, upstreamAmr: ["hwk", 1] }],
		["a null mfaAt", { ...PASSWORD, mfaAt: null }],
		["an mfaAt that is a number", { ...PASSWORD, mfaAt: Date.now() }],
		["an Invalid Date mfaAt", { ...PASSWORD, mfaAt: new Date(Number.NaN) }],
		["an mfaAt before 1970", { ...PASSWORD, mfaAt: new Date(-1) }],
	])(
		"%s: sessionAuthentication answers undefined and vouchedAmr vouches for nothing, without a throw",
		(_label, stored) => {
			// A store that maps a pre-upgrade row's empty columns to `{}` must not
			// make it read as recorded, which would vouch for an untrusted `hwk`.
			const s: UserSession = {
				...session(["fed", "hwk"]),
				authentication: stored as unknown as SessionAuthentication,
			};
			expect(sessionAuthentication(s)).toBeUndefined();
			expect(vouchedAmr(s)).toEqual([]);
			expect(requirementSession(s)).toEqual({ authentication: undefined, amr: [] });
			expect(
				sessionAfterSecondFactor(s, { amr: ["otp", "mfa"], at: new Date() }, Date.now()),
			).toBeNull();
		},
	);

	it("reads a null federation as none: a store may map an empty column to null, and the federation grants nothing", () => {
		const s: UserSession = {
			...session(["pwd"]),
			authentication: { ...PASSWORD, federation: null } as unknown as SessionAuthentication,
		};
		expect(sessionAuthentication(s)).toStrictEqual(PASSWORD);
		expect(vouchedAmr(s)).toEqual(["pwd"]);
		expect(canRecordSecondFactor(s)).toBe(true);
		expect(
			sessionAfterSecondFactor(s, { amr: ["otp", "mfa"], at: new Date() }, Date.now())
				?.authentication.federation,
		).toBeUndefined();
	});

	it("reads an mfaAt ahead of any clock as recorded: the readers hold no clock, and its consumers cap it", () => {
		const mfaAt = new Date(Date.now() + 24 * 60 * 60_000);
		expect(sessionAuthentication(recorded(["pwd"], { ...PASSWORD, mfaAt }))?.mfaAt).toStrictEqual(
			mfaAt,
		);
	});
});

describe("canRecordSecondFactor — whether a second factor can be recorded on a session", () => {
	const PASSWORD: SessionAuthentication = {
		primary: "pwd",
		federation: undefined,
		upstreamAmr: undefined,
		mfaAt: undefined,
	};
	const at = new Date("2026-09-28T00:10:00Z");
	const event = { amr: ["otp", "mfa"], at };
	const withAmr = (stored: unknown): UserSession => ({
		...session(undefined),
		amr: stored as readonly string[],
	});
	const withAuthentication = (amr: unknown, stored: unknown): UserSession => ({
		...withAmr(amr),
		authentication: stored as SessionAuthentication,
	});

	it.each([
		["a pre-upgrade password session", session(["pwd"]), true],
		["a pre-upgrade federated session", session(["hwk", "fed"]), true],
		["a pre-upgrade federated session with a non-string beside fed", withAmr(["fed", 1]), true],
		["a recorded session", recorded(["pwd"], PASSWORD), true],
		["a recorded session with no amr", recorded(undefined, PASSWORD), true],
		["a recorded session with an empty amr", recorded([], PASSWORD), true],
		["a pre-upgrade session with no amr", session(undefined), false],
		["a pre-upgrade session naming no primary", session(["hwk"]), false],
		["a pre-upgrade session whose amr is a string", withAmr("confed"), false],
		["a pre-upgrade session whose amr holds a non-string", withAmr(["pwd", 1]), false],
		["a recorded session whose amr holds an empty string", recorded(["pwd", ""], PASSWORD), false],
		["a recorded session whose amr is a string", withAuthentication("pwd", PASSWORD), false],
		["a session whose authentication is an empty object", withAuthentication(["pwd"], {}), false],
		["a session whose authentication is null", withAuthentication(["pwd"], null), false],
		[
			"a session whose authentication has a null mfaAt",
			withAuthentication(["pwd"], { ...PASSWORD, mfaAt: null }),
			false,
		],
	])("agrees with sessionAfterSecondFactor on %s", (_label, s, can) => {
		expect(canRecordSecondFactor(s)).toBe(can);
		expect(sessionAfterSecondFactor(s, event, at.getTime()) !== null).toBe(can);
	});
});

describe("sessionAfterSecondFactor — a recorded session whose stored amr is not well formed", () => {
	const PASSWORD: SessionAuthentication = {
		primary: "pwd",
		federation: undefined,
		upstreamAmr: undefined,
		mfaAt: undefined,
	};
	const at = new Date("2026-09-28T00:10:00Z");
	const event = { amr: ["otp", "mfa"], at };

	it.each([
		["a string", "pwd"],
		["an array holding an empty string", ["pwd", ""]],
		["an array holding a non-string", ["pwd", 1]],
		["an object", { 0: "pwd", length: 1 }],
	])("is null for one whose amr is %s: what it vouches for cannot be told", (_label, stored) => {
		const amr = stored as unknown as readonly string[];
		expect(sessionAfterSecondFactor(recorded(amr, PASSWORD), event, at.getTime())).toBeNull();
	});

	it("records the factor on one that recorded no amr, or an empty one", () => {
		for (const amr of [undefined, []]) {
			expect(sessionAfterSecondFactor(recorded(amr, PASSWORD), event, at.getTime())?.amr).toEqual([
				"otp",
				"mfa",
			]);
		}
	});
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

	it("still refuses an unusable switch on a section that is not enabled", () => {
		// Enabling the federation later must not be what first reveals it.
		expect(() =>
			federationTrustsUpstreamAmr(config({ enabled: false, trustUpstreamAmr: "yes" }), "google"),
		).toThrow(new RangeError("core.federations.google.trustUpstreamAmr must be true or false"));
	});

	it.each([
		[
			"a switch saying true there",
			{ enabled: true, type: "oidc", oidc: { trustUpstreamAmr: true } },
			false,
		],
		[
			"an unusable switch there",
			{ enabled: true, type: "oidc", oidc: { trustUpstreamAmr: "yes" } },
			false,
		],
		[
			"a switch saying false there, beside one saying true",
			{ enabled: true, type: "oidc", trustUpstreamAmr: true, oidc: { trustUpstreamAmr: false } },
			true,
		],
	])(
		"does not read a key named after the type, an entry being flat: %s",
		(_label, entry, trusts) => {
			expect(federationTrustsUpstreamAmr({ core: { federations: { okta: entry } } }, "okta")).toBe(
				trusts,
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

describe("federationCallbackMeetsFreshness — whether a federation's callback alone meets a freshness ask", () => {
	const config = (entry: unknown) => ({ core: { federations: { google: entry } } });

	it("is false by default: a callback with no upstream instant meets no freshness ask", () => {
		expect(federationCallbackMeetsFreshness(config({ enabled: true }), "google")).toBe(false);
		expect(federationCallbackMeetsFreshness({ core: { federations: {} } }, "google")).toBe(false);
		expect(federationCallbackMeetsFreshness({}, "google")).toBe(false);
		expect(federationCallbackMeetsFreshness(undefined, "google")).toBe(false);
		// The map written at the top level is not core's: boot refuses it.
		expect(
			federationCallbackMeetsFreshness(
				{ federations: { google: { enabled: true, callbackMeetsFreshness: true } } },
				"google",
			),
		).toBe(false);
	});

	it("is true only for an enabled federation configured with callbackMeetsFreshness = true", () => {
		expect(
			federationCallbackMeetsFreshness(
				config({ enabled: true, callbackMeetsFreshness: true }),
				"google",
			),
		).toBe(true);
		expect(
			federationCallbackMeetsFreshness(
				config({ enabled: true, callbackMeetsFreshness: false }),
				"google",
			),
		).toBe(false);
		for (const enabled of [false, undefined, "true", 1]) {
			expect(
				federationCallbackMeetsFreshness(
					config({ enabled, callbackMeetsFreshness: true }),
					"google",
				),
			).toBe(false);
		}
		// Another federation's switch is not this one's.
		expect(
			federationCallbackMeetsFreshness(
				{ core: { federations: { github: { enabled: true, callbackMeetsFreshness: true } } } },
				"google",
			),
		).toBe(false);
	});

	it("does not read a key named after the type, an entry being flat", () => {
		expect(
			federationCallbackMeetsFreshness(
				{
					core: {
						federations: {
							okta: { enabled: true, type: "oidc", oidc: { callbackMeetsFreshness: true } },
						},
					},
				},
				"okta",
			),
		).toBe(false);
	});

	it.each([
		["a string", "true"],
		["a number", 1],
		["null", null],
		["an object", {}],
	])("refuses a value that is %s, naming the key, enabled or not", (_label, value) => {
		for (const enabled of [true, false]) {
			expect(() =>
				federationCallbackMeetsFreshness(
					config({ enabled, callbackMeetsFreshness: value }),
					"google",
				),
			).toThrow(
				new RangeError("core.federations.google.callbackMeetsFreshness must be true or false"),
			);
		}
	});

	it("reads no inherited key: a federation named like an Object.prototype member has no switch", () => {
		expect(federationCallbackMeetsFreshness({ core: { federations: {} } }, "constructor")).toBe(
			false,
		);
		expect(federationCallbackMeetsFreshness({ core: { federations: {} } }, "__proto__")).toBe(
			false,
		);
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
		["a null federation", { ...PASSWORD, federation: null }, "authentication.federation"],
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
		[
			"an upstreamAmr with a hole",
			{ ...PASSWORD, upstreamAmr: Object.assign(new Array<string>(2), { 1: "hwk" }) },
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

describe("upstreamAuthTime — when the upstream last authenticated a federated session's user", () => {
	const AUTH = new Date("2026-09-28T00:00:00Z");
	const UPSTREAM = new Date("2026-09-27T23:50:00Z");
	const NOW_MS = Date.parse("2026-09-28T00:00:30Z");

	describe("federatedSessionAuthentication — what the callback records of it", () => {
		const login = { federation: "google", upstreamAmr: [], trusted: false } as const;

		it("records the upstream's instant when it showed one, as a copy", () => {
			const upstreamAuthTime = new Date(UPSTREAM.getTime());
			for (const callbackMeetsFreshness of [true, false]) {
				const { authentication } = federatedSessionAuthentication({
					...login,
					upstreamAuthTime,
					callbackMeetsFreshness,
				});
				expect(authentication.upstreamAuthTime).toEqual(UPSTREAM);
				expect(authentication.upstreamAuthTime).not.toBe(upstreamAuthTime);
			}
		});

		it("records null when the upstream showed none and the federation's callback does not meet a freshness ask", () => {
			const { authentication } = federatedSessionAuthentication({
				...login,
				callbackMeetsFreshness: false,
			});
			expect(authentication.upstreamAuthTime).toBeNull();
		});

		it("records nothing when the upstream showed none and the callback meets a freshness ask, or the caller says neither", () => {
			for (const extra of [{ callbackMeetsFreshness: true }, {}]) {
				const { authentication } = federatedSessionAuthentication({ ...login, ...extra });
				expect(Object.hasOwn(authentication, "upstreamAuthTime")).toBe(false);
			}
		});

		it("a password login records nothing of it", () => {
			expect(
				Object.hasOwn(passwordSessionAuthentication().authentication, "upstreamAuthTime"),
			).toBe(false);
		});
	});

	describe("copySessionAuthentication", () => {
		it("copies a Date and keeps null and absence", () => {
			const withDate = { ...FEDERATED, upstreamAuthTime: UPSTREAM };
			const copied = copySessionAuthentication(withDate);
			expect(copied.upstreamAuthTime).toEqual(UPSTREAM);
			expect(copied.upstreamAuthTime).not.toBe(UPSTREAM);
			expect(
				copySessionAuthentication({ ...FEDERATED, upstreamAuthTime: null }).upstreamAuthTime,
			).toBeNull();
			expect(Object.hasOwn(copySessionAuthentication(FEDERATED), "upstreamAuthTime")).toBe(false);
		});
	});

	describe("recordableSessionAuthentication — what a store records of it", () => {
		it("records a Date no later than the store's clock, null, or nothing", () => {
			expect(
				recordableSessionAuthentication(
					"sid-1",
					{ ...FEDERATED, upstreamAuthTime: UPSTREAM },
					NOW_MS,
				)?.upstreamAuthTime,
			).toEqual(UPSTREAM);
			const ahead = new Date(NOW_MS + DEFAULT_CLOCK_SKEW_MS);
			expect(
				recordableSessionAuthentication("sid-1", { ...FEDERATED, upstreamAuthTime: ahead }, NOW_MS)
					?.upstreamAuthTime,
			).toEqual(new Date(NOW_MS));
			expect(
				recordableSessionAuthentication("sid-1", { ...FEDERATED, upstreamAuthTime: null }, NOW_MS)
					?.upstreamAuthTime,
			).toBeNull();
			const none = recordableSessionAuthentication("sid-1", FEDERATED, NOW_MS);
			expect(none === undefined ? true : Object.hasOwn(none, "upstreamAuthTime")).toBe(false);
		});

		it("refuses one on a password primary, a Date or null, naming the field", () => {
			for (const upstreamAuthTime of [UPSTREAM, null]) {
				expect(() =>
					recordableSessionAuthentication(
						"sid-1",
						{ ...passwordSessionAuthentication().authentication, upstreamAuthTime },
						NOW_MS,
					),
				).toThrow(
					new RangeError(
						"UserSession sid-1: authentication.upstreamAuthTime must be a valid date at or after the epoch, no further ahead than hosts' clocks drift, null, or undefined — undefined for a password primary",
					),
				);
			}
		});

		it.each([
			["a string", UPSTREAM.toISOString()],
			["a number", UPSTREAM.getTime()],
			["an Invalid Date", new Date(Number.NaN)],
			["a date before the epoch", new Date(-1)],
			[
				"a date further ahead than hosts' clocks drift",
				new Date(NOW_MS + DEFAULT_CLOCK_SKEW_MS + 1),
			],
		])("refuses one that is %s, naming the field", (_label, upstreamAuthTime) => {
			expect(() =>
				recordableSessionAuthentication("sid-1", { ...FEDERATED, upstreamAuthTime }, NOW_MS),
			).toThrow(
				new RangeError(
					"UserSession sid-1: authentication.upstreamAuthTime must be a valid date at or after the epoch, no further ahead than hosts' clocks drift, null, or undefined — undefined for a password primary",
				),
			);
		});
	});

	describe("sessionAuthentication — as it is read", () => {
		it("reads a Date as a copy, null as null, and absence as absence", () => {
			const stored = new Date(UPSTREAM.getTime());
			const read = sessionAuthentication(
				recorded(["fed"], { ...FEDERATED, upstreamAuthTime: stored }),
			);
			expect(read?.upstreamAuthTime).toEqual(UPSTREAM);
			expect(read?.upstreamAuthTime).not.toBe(stored);
			expect(
				sessionAuthentication(recorded(["fed"], { ...FEDERATED, upstreamAuthTime: null }))
					?.upstreamAuthTime,
			).toBeNull();
			const absent = sessionAuthentication(recorded(["fed"], FEDERATED));
			expect(absent === undefined ? true : Object.hasOwn(absent, "upstreamAuthTime")).toBe(false);
		});

		it.each([
			["a string", UPSTREAM.toISOString()],
			["a number", UPSTREAM.getTime()],
			["an Invalid Date", new Date(Number.NaN)],
			["a date before the epoch", new Date(-1)],
		])("cannot tell a session whose stored one is %s", (_label, upstreamAuthTime) => {
			const session = recorded(["fed"], { ...FEDERATED, upstreamAuthTime } as never);
			expect(sessionAuthentication(session)).toBeUndefined();
			expect(vouchedAmr(session)).toEqual([]);
		});

		it("cannot tell a password session that records one, a Date or null: only a federation has an upstream", () => {
			for (const upstreamAuthTime of [UPSTREAM, null]) {
				const session = recorded(["pwd"], {
					...passwordSessionAuthentication().authentication,
					upstreamAuthTime,
				});
				expect(sessionAuthentication(session)).toBeUndefined();
				expect(vouchedAmr(session)).toEqual([]);
				expect(sessionFreshness({ ...session, authTime: AUTH })).toBeUndefined();
			}
		});

		it("keeps null in the requirement's input", () => {
			const session = recorded(["fed"], { ...FEDERATED, upstreamAuthTime: null });
			expect(requirementSession(session)?.authentication?.upstreamAuthTime).toBeNull();
		});

		it("is kept by what a second factor makes of the session, and by the requirement's input", () => {
			const session = recorded(["fed"], { ...FEDERATED, upstreamAuthTime: UPSTREAM });
			const after = sessionAfterSecondFactor(
				session,
				{ amr: ["otp", "mfa"], at: new Date(NOW_MS) },
				NOW_MS,
			);
			expect(after?.authentication.upstreamAuthTime).toEqual(UPSTREAM);
			expect(requirementSession(session)?.authentication?.upstreamAuthTime).toEqual(UPSTREAM);
			const nulled = recorded(["fed"], { ...FEDERATED, upstreamAuthTime: null });
			expect(
				sessionAfterSecondFactor(nulled, { amr: ["otp", "mfa"], at: new Date(NOW_MS) }, NOW_MS)
					?.authentication.upstreamAuthTime,
			).toBeNull();
		});
	});

	describe("authenticationFreshness — the instant a session's authentication is as fresh as", () => {
		it.each([
			["no authentication", undefined, AUTH],
			["none recorded", FEDERATED, AUTH],
			["a password login", passwordSessionAuthentication().authentication, AUTH],
			[
				"an upstream instant before authTime",
				{ ...FEDERATED, upstreamAuthTime: UPSTREAM },
				UPSTREAM,
			],
			[
				"an upstream instant after authTime",
				{ ...FEDERATED, upstreamAuthTime: new Date(AUTH.getTime() + 60_000) },
				AUTH,
			],
			["an upstream instant equal to authTime", { ...FEDERATED, upstreamAuthTime: AUTH }, AUTH],
			["null: the upstream showed none", { ...FEDERATED, upstreamAuthTime: null }, undefined],
		] as const)("answers for %s", (_label, authentication, expected) => {
			const answer = authenticationFreshness(
				AUTH,
				authentication as SessionAuthentication | undefined,
			);
			expect(answer).toEqual(expected);
			if (answer !== undefined) {
				expect(answer).not.toBe(AUTH);
				expect(answer).not.toBe(UPSTREAM);
			}
		});

		it("answers undefined for an authTime that is not a valid date: an unreadable time is stale", () => {
			expect(authenticationFreshness(new Date(Number.NaN), FEDERATED)).toBeUndefined();
			expect(authenticationFreshness(undefined as never, undefined)).toBeUndefined();
		});
	});

	describe("sessionFreshness — a session's freshness, read from its record", () => {
		const at = (authentication: unknown): UserSession =>
			({ ...session(["fed"]), authTime: AUTH, authentication }) as UserSession;

		it("is authTime for a session that records no upstream instant, or none at all", () => {
			expect(sessionFreshness(at(undefined))).toEqual(AUTH);
			expect(sessionFreshness(at(FEDERATED))).toEqual(AUTH);
		});

		it("is the earlier of authTime and the upstream instant, and undefined for null", () => {
			expect(sessionFreshness(at({ ...FEDERATED, upstreamAuthTime: UPSTREAM }))).toEqual(UPSTREAM);
			expect(sessionFreshness(at({ ...FEDERATED, upstreamAuthTime: null }))).toBeUndefined();
		});

		it("is undefined for a recorded authentication it cannot read: never fresher than it was written", () => {
			expect(
				sessionFreshness(at({ ...FEDERATED, upstreamAuthTime: "2026-09-28" })),
			).toBeUndefined();
			expect(sessionFreshness(at({ primary: "" }))).toBeUndefined();
		});
	});
});
