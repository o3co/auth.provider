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
 * is wired, the account's address as the session's enrollment facts say it
 * (core's one reading: `none`, `address` or `unreadable`), and D25's flag.
 *
 * - `never` asks for nothing, whatever the address; D25's flag asks whatever
 *   the setting; `always` asks always; `when-mail` asks when a sender is
 *   wired and the account has an address — or one it cannot read, which
 *   nobody can send the proof to.
 * - A proof asked for that nobody can give is `unprovable`, with why: the
 *   binding is refused, never let through without it.
 *
 * Whether a binding is a first one is read over the subject's records with
 * admission's presumption (`mayCount`): a record counts unless an installed
 * factor of its kind declares it does not. The same reading names the
 * binding a login reopens after a non-counting proof (`reopenedEnrollment`).
 */

import type { MailAddressFact, MfaFactorRecord, MfaFactorResolver } from "@o3co/auth-provider-core";

export type { MailAddressFact };

/**
 * Whether `record` may hold a counting factor: unless an installed factor of
 * its kind declares it does not, so a kind no longer installed counts. Right
 * for admitting, and for telling a first binding — it fails closed, a
 * password never standing in for a factor it cannot see; wrong for a
 * last-factor check or clearing the witness.
 */
export const mayCount = (
	factors: MfaFactorResolver,
	record: Pick<MfaFactorRecord, "kind">,
): boolean => factors.get(record.kind)?.counting !== false;

/**
 * The enrollment a login reopens for once a non-counting proof left its
 * subject no counting factor it can use: `allowed`, a binding beside a
 * record that may count (one whose data does not open, a kind no longer
 * installed); else `required`, a first binding.
 */
export const reopenedEnrollment = (
	factors: MfaFactorResolver,
	records: readonly Pick<MfaFactorRecord, "kind">[],
): "allowed" | "required" =>
	records.some((record) => mayCount(factors, record)) ? "allowed" : "required";

/** A factor's `enrollable` that threw: its `kind`, and the factor's error as `cause`, never quoted. */
export class MfaEnrollableError extends Error {
	constructor(
		readonly kind: string,
		cause: unknown,
	) {
		super(`the ${kind} factor could not say whether the user may enroll it`, { cause });
		this.name = "MfaEnrollableError";
	}
}

/** The kinds of the installed counting factors, in registration order. */
export const countingKinds = (factors: MfaFactorResolver): string[] =>
	[...factors.entries()].filter(([, factor]) => factor.counting).map(([kind]) => kind);

/**
 * The counting factors `user` may enroll, in registration order: what a
 * first binding offers. A factor whose `enrollable` throws cannot answer —
 * an outage, never "not offered" — so the throw goes through, as an
 * {@link MfaEnrollableError} naming its kind.
 */
export const enrollableKinds = (
	factors: MfaFactorResolver,
	user: Readonly<Record<string, unknown>>,
): string[] =>
	[...factors.entries()].flatMap(([kind, factor]) => {
		if (!factor.counting) return [];
		let offered: boolean;
		try {
			offered = factor.enrollable?.(user) ?? true;
		} catch (cause) {
			throw new MfaEnrollableError(kind, cause);
		}
		return offered ? [kind] : [];
	});

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
	/** The account's address as the session's enrollment facts say it (`SessionEnrollmentFacts.mailAddress`). */
	readonly mailAddress: MailAddressFact;
	/** D25's flag: an operator reset asked for the proof at the subject's next first binding. */
	readonly requiredAtNextBinding: boolean;
}

/** Why a proof asked for cannot be given: no sender, no address, or one no proof can be sent to. */
export type UnprovableReason = "no_sender" | "no_address" | "unreadable_address";

/**
 * `bind`: no proof is asked. `prove`: the account-email proof comes first,
 * and can be given. `unprovable`: a proof is asked that nobody can give.
 */
export type FirstBindingGate =
	| { readonly outcome: "bind" }
	| { readonly outcome: "prove" }
	| { readonly outcome: "unprovable"; readonly reason: UnprovableReason };

const BIND: FirstBindingGate = Object.freeze({ outcome: "bind" });
const PROVE: FirstBindingGate = Object.freeze({ outcome: "prove" });

/** The gate over `input` (see this file's header). */
export function firstBindingGate(input: FirstBindingGateInput): FirstBindingGate {
	const { requireEmailProof, mailWired, mailAddress, requiredAtNextBinding } = input;
	/** The proof asked for: given where it can be, else unprovable, with why. */
	const asked = (): FirstBindingGate => {
		if (!mailWired) return { outcome: "unprovable", reason: "no_sender" };
		if (mailAddress === "address") return PROVE;
		return {
			outcome: "unprovable",
			reason: mailAddress === "unreadable" ? "unreadable_address" : "no_address",
		};
	};
	if (requiredAtNextBinding || requireEmailProof === "always") return asked();
	if (requireEmailProof === "never" || !mailWired || mailAddress === "none") return BIND;
	return asked();
}
