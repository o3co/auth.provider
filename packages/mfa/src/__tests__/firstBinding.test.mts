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
import { firstBindingGate, type RequireEmailProof } from "#/firstBinding.mjs";

type Row = readonly [RequireEmailProof, boolean, boolean, ReturnType<typeof firstBindingGate>];

/** setting, a sender wired, an address on the account → the gate. */
const TABLE: readonly Row[] = [
	["when-mail", true, true, "prove"],
	["when-mail", true, false, "bind"],
	["when-mail", false, true, "bind"],
	["when-mail", false, false, "bind"],
	["always", true, true, "prove"],
	["always", true, false, "unprovable"],
	["always", false, true, "unprovable"],
	["always", false, false, "unprovable"],
	["never", true, true, "bind"],
	["never", true, false, "bind"],
	["never", false, true, "bind"],
	["never", false, false, "bind"],
];

describe("firstBindingGate", () => {
	it.each(TABLE)(
		"%s, a sender wired: %s, an address: %s → %s",
		(requireEmailProof, mailWired, hasAddress, expected) => {
			expect(
				firstBindingGate({
					requireEmailProof,
					mailWired,
					hasAddress,
					requiredAtNextBinding: false,
				}),
			).toBe(expected);
		},
	);

	it("asks for the proof whatever the setting while D25's flag stands, and never skips one nobody can give", () => {
		for (const requireEmailProof of ["when-mail", "always", "never"] as const) {
			const gate = (mailWired: boolean, hasAddress: boolean) =>
				firstBindingGate({ requireEmailProof, mailWired, hasAddress, requiredAtNextBinding: true });
			expect(gate(true, true), requireEmailProof).toBe("prove");
			expect(gate(true, false), requireEmailProof).toBe("unprovable");
			expect(gate(false, true), requireEmailProof).toBe("unprovable");
			expect(gate(false, false), requireEmailProof).toBe("unprovable");
		}
	});
});
