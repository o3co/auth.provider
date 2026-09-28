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
import { sessionAuthentication, vouchedAmr } from "#/user-sessions/authentication.mjs";
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
