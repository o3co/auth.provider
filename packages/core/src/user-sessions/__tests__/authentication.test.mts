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
 * one way every consumer reads them (the MFA ADR's D9): `sessionAuthentication`
 * and `vouchedAmr`. Until the build order's step 5 gives the record its
 * `authentication` key and splits untrusted upstream values out of `amr`,
 * every session is read from its `amr`, and every federation is trusted — the
 * behaviour #481 shipped.
 */

import { describe, expect, it } from "vitest";
import {
	federationTrustsUpstreamAmr,
	requirementSession,
	sessionAuthentication,
	vouchedAmr,
} from "#/user-sessions/authentication.mjs";
import type { UserSession } from "#/user-sessions/types.mjs";

const session = (amr: readonly string[] | undefined): UserSession => ({
	sid: "sid-1",
	sub: "user-1",
	authTime: new Date("2026-09-28T00:00:00Z"),
	createdAt: new Date("2026-09-28T00:00:00Z"),
	expiresAt: new Date("2026-09-28T01:00:00Z"),
	claims: {},
	amr,
});

describe("sessionAuthentication — how a session was established (D9)", () => {
	it("reads a password login as primary pwd, with no second factor on record", () => {
		expect(sessionAuthentication(session(["pwd"]))).toEqual({
			primary: "pwd",
			federation: undefined,
			upstreamAmr: undefined,
			mfaAt: undefined,
		});
	});

	it("reads a session carrying fed as federated, whatever else it carries", () => {
		// `fed` is the marker only a federation callback records; the values
		// beside it are what the upstream IdP asserted, `pwd` among them.
		expect(sessionAuthentication(session(["pwd", "mfa", "fed"]))?.primary).toBe("fed");
		expect(sessionAuthentication(session(["hwk", "fed"]))?.primary).toBe("fed");
	});

	it.each([
		["no amr", undefined],
		["an empty amr", []],
		["neither pwd nor fed", ["hwk"]],
		["mfa alone", ["mfa"]],
	])("cannot tell the primary of a session with %s: undefined", (_label, amr) => {
		// Unknown is its own answer: the baseline re-authenticates such a
		// session rather than guessing which primary it had (D16).
		expect(sessionAuthentication(session(amr))).toBeUndefined();
	});

	it("records no second factor for a session read from its amr, whatever the amr says", () => {
		// `mfaAt` is written by the verification that sets it; a session that
		// has no `authentication` key predates any such verification.
		expect(sessionAuthentication(session(["pwd", "otp", "mfa"]))?.mfaAt).toBeUndefined();
	});
});

describe("vouchedAmr — the amr this provider vouches for (D9, D13)", () => {
	it("is the session's amr, copied", () => {
		const recorded = session(["pwd"]);
		const vouched = vouchedAmr(recorded);
		expect(vouched).toEqual(["pwd"]);
		expect(vouched).not.toBe(recorded.amr);
	});

	it("keeps the values beside fed while every federation is trusted, as #481 shipped", () => {
		expect(vouchedAmr(session(["hwk", "fed"]))).toEqual(["hwk", "fed"]);
	});

	it("is empty for a session that recorded no amr", () => {
		expect(vouchedAmr(session(undefined))).toEqual([]);
	});
});

describe("requirementSession — the requirement rule's input, built only through the D9 reading", () => {
	it("is sessionAuthentication and vouchedAmr of the session", () => {
		const recorded = session(["pwd", "otp"]);
		expect(requirementSession(recorded)).toEqual({
			authentication: sessionAuthentication(recorded),
			amr: vouchedAmr(recorded),
		});
	});

	it("carries the vouched amr, never the record's own array", () => {
		const recorded = session(["hwk", "fed"]);
		const input = requirementSession(recorded);
		expect(input?.amr).toEqual(["hwk", "fed"]);
		expect(input?.amr).not.toBe(recorded.amr);
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

describe("federationTrustsUpstreamAmr — whether an upstream IdP's amr counts (D13)", () => {
	const config = (entry: unknown) => ({ federations: { google: entry } });

	it("is false by default: an upstream IdP's word is not this provider's", () => {
		expect(federationTrustsUpstreamAmr(config({ enabled: true }), "google")).toBe(false);
		expect(federationTrustsUpstreamAmr({ federations: {} }, "google")).toBe(false);
		expect(federationTrustsUpstreamAmr({}, "google")).toBe(false);
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
				{ federations: { github: { trustUpstreamAmr: true } } },
				"google",
			),
		).toBe(false);
	});

	it("reads the switch beside enabled in the nested shape too, never inside the type's section", () => {
		expect(
			federationTrustsUpstreamAmr(
				config({ enabled: true, type: "google", google: { trustUpstreamAmr: true } }),
				"google",
			),
		).toBe(false);
		expect(
			federationTrustsUpstreamAmr(
				config({ enabled: true, type: "google", trustUpstreamAmr: true, google: {} }),
				"google",
			),
		).toBe(true);
	});

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
			).toThrow(new RangeError("federations.google.trustUpstreamAmr must be true or false"));
		},
	);

	it("reads no inherited key: a federation named like an Object.prototype member has no switch", () => {
		expect(federationTrustsUpstreamAmr({ federations: {} }, "constructor")).toBe(false);
		expect(federationTrustsUpstreamAmr({ federations: {} }, "__proto__")).toBe(false);
	});
});
