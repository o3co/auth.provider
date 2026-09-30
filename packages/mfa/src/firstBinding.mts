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
 * holding no counting factor gives the account-email proof before it binds a
 * way into the account — a first factor at a login or from a session, a
 * first passkey, a first linked identity.
 *
 * Every input is handed in, so each caller decides in the same place over
 * what it can read: `mfa.enrollment.requireEmailProof`, whether a mail sender
 * is wired, whether the account has an address `normaliseMailAddress` reads,
 * and D25's flag. The flag asks for the proof whatever the setting. A proof
 * asked for that nobody can give — no sender, no address — is `unprovable`:
 * the binding is refused, never let through without it.
 */

/** `mfa.enrollment.requireEmailProof`. */
export const REQUIRE_EMAIL_PROOF = ["when-mail", "always", "never"] as const;

/** One of {@link REQUIRE_EMAIL_PROOF}. */
export type RequireEmailProof = (typeof REQUIRE_EMAIL_PROOF)[number];

/** What the gate decides on. */
export interface FirstBindingGateInput {
	/** `mfa.enrollment.requireEmailProof`. */
	readonly requireEmailProof: RequireEmailProof;
	/** Whether a mail sender is wired. */
	readonly mailWired: boolean;
	/** Whether the account has an address `normaliseMailAddress` reads. */
	readonly hasAddress: boolean;
	/** D25's flag: an operator reset asked for the proof at the subject's next first binding. */
	readonly requiredAtNextBinding: boolean;
}

/**
 * `bind`: no proof is asked. `prove`: the account-email proof comes first,
 * and can be given. `unprovable`: a proof is asked that nobody can give.
 */
export type FirstBindingGate = "bind" | "prove" | "unprovable";

/** The gate over `input` (see this file's header). */
export function firstBindingGate(input: FirstBindingGateInput): FirstBindingGate {
	const { requireEmailProof, mailWired, hasAddress, requiredAtNextBinding } = input;
	const givable = mailWired && hasAddress;
	if (requiredAtNextBinding || requireEmailProof === "always") {
		return givable ? "prove" : "unprovable";
	}
	if (requireEmailProof === "never") return "bind";
	return givable ? "prove" : "bind";
}
