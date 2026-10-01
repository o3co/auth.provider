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
 * The one first-binding gate (the MFA ADR's D24, D25): whether a subject
 * with no counting factor gives the account-email proof before it binds one
 * — at a login, or in a session for a passkey, a link or a factor — over
 * every input it needs, handed in: `mfa.enrollment.requireEmailProof`,
 * whether a mail sender is wired, whether the account has an address, and
 * D25's flag. A proof asked for that nobody can give is never skipped.
 */

import { describe, expect, it } from "vitest";
import {
	enrollableKinds,
	type FirstBindingGate,
	firstBindingGate,
	type MailAddressFact,
	MfaEnrollableError,
	type RequireEmailProof,
	reopenedEnrollment,
} from "#/firstBinding.mjs";
import { FACTORS, factorRecord, resolverOver, stubFactor } from "./requirementHarness.mjs";

type Row = readonly [RequireEmailProof, boolean, MailAddressFact, FirstBindingGate];

const BIND = { outcome: "bind" } as const;
const PROVE = { outcome: "prove" } as const;
const unprovable = (reason: "no_sender" | "no_address" | "unreadable_address") =>
	({ outcome: "unprovable", reason }) as const;

/** setting, a sender wired, the account's address as the session's facts say it → the gate. */
const TABLE: readonly Row[] = [
	["when-mail", true, "address", PROVE],
	["when-mail", true, "none", BIND],
	["when-mail", true, "unreadable", unprovable("unreadable_address")],
	["when-mail", false, "address", BIND],
	["when-mail", false, "none", BIND],
	["when-mail", false, "unreadable", BIND],
	["always", true, "address", PROVE],
	["always", true, "none", unprovable("no_address")],
	["always", true, "unreadable", unprovable("unreadable_address")],
	["always", false, "address", unprovable("no_sender")],
	["always", false, "none", unprovable("no_sender")],
	["always", false, "unreadable", unprovable("no_sender")],
	["never", true, "address", BIND],
	["never", true, "none", BIND],
	["never", true, "unreadable", BIND],
	["never", false, "address", BIND],
	["never", false, "none", BIND],
	["never", false, "unreadable", BIND],
];

describe("firstBindingGate", () => {
	it.each(TABLE)(
		"%s, a sender wired: %s, the address %s → %o",
		(requireEmailProof, mailWired, mailAddress, expected) => {
			expect(
				firstBindingGate({
					requireEmailProof,
					mailWired,
					mailAddress,
					requiredAtNextBinding: false,
				}),
			).toEqual(expected);
		},
	);

	it("asks for the proof whatever the setting while D25's flag stands, and never skips one nobody can give", () => {
		for (const requireEmailProof of ["when-mail", "always", "never"] as const) {
			const gate = (mailWired: boolean, mailAddress: MailAddressFact) =>
				firstBindingGate({
					requireEmailProof,
					mailWired,
					mailAddress,
					requiredAtNextBinding: true,
				});
			expect(gate(true, "address"), requireEmailProof).toEqual(PROVE);
			expect(gate(true, "none"), requireEmailProof).toEqual(unprovable("no_address"));
			expect(gate(true, "unreadable"), requireEmailProof).toEqual(unprovable("unreadable_address"));
			expect(gate(false, "address"), requireEmailProof).toEqual(unprovable("no_sender"));
			expect(gate(false, "unreadable"), requireEmailProof).toEqual(unprovable("no_sender"));
		}
	});
});

describe("reopenedEnrollment", () => {
	const factors = resolverOver([FACTORS.totp(), FACTORS.recovery()]);

	it("is allowed beside a record that may count: one of a counting kind, or of a kind no longer installed", () => {
		expect(
			reopenedEnrollment(factors, [factorRecord("u", "recovery_code", "a"), factorRecord("u")]),
		).toBe("allowed");
		expect(
			reopenedEnrollment(factors, [
				factorRecord("u", "recovery_code", "a"),
				factorRecord("u", "retired", "b"),
			]),
		).toBe("allowed");
	});

	it("is required — a first binding — over records none of which may count, or none", () => {
		expect(reopenedEnrollment(factors, [factorRecord("u", "recovery_code", "a")])).toBe("required");
		expect(reopenedEnrollment(factors, [])).toBe("required");
	});
});

describe("enrollableKinds", () => {
	it("offers the counting factors the user may enroll, in registration order", () => {
		const refusing = { ...stubFactor("email", ["email"]), enrollable: () => false };
		const factors = resolverOver([
			FACTORS.webauthn(),
			FACTORS.recovery(),
			refusing,
			FACTORS.totp(),
		]);
		expect(enrollableKinds(factors, { id: "u" })).toEqual(["webauthn", "totp"]);
	});

	it("lets a factor's enrollable throw through, naming its kind: a factor that cannot answer is an outage", () => {
		const broken = new Error("broken");
		const throwing = {
			...stubFactor("email", ["email"]),
			enrollable: () => {
				throw broken;
			},
		};
		let thrown: unknown;
		try {
			enrollableKinds(resolverOver([FACTORS.totp(), throwing]), { id: "u" });
		} catch (err) {
			thrown = err;
		}
		expect(thrown).toBeInstanceOf(MfaEnrollableError);
		expect(thrown).toMatchObject({ kind: "email", cause: broken });
	});
});
