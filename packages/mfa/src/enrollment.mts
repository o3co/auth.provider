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
 * A login's first binding (the MFA ADR's F3, D12, D24, D25): a counting
 * factor enrolled on the login's transaction, which the requirement opened
 * with `enrollment` other than `none`.
 *
 * - Nothing is bound while the transaction owes the account-email proof —
 *   D25's flag is read again at each call, so one set after the transaction
 *   opened makes it owe the proof — or once the subject holds any record:
 *   only zero records open a first binding.
 * - Only a counting factor the login's `User` may enroll is offered. Its
 *   start is kept sealed on the transaction (`o3co:mfa:enrollment`), with the
 *   digest of the address its code went to when it mailed one
 *   (`sendMfaMail`).
 * - A completion reserves an attempt before the proof is checked, seals the
 *   factor's data, and then, in this order: consumes the transaction, writes
 *   the factor (`binding` `email_proof` when the proof was given, else
 *   `password`), reads the subject's records again — it stands only when they
 *   are its own alone; otherwise another transaction bound one at once, or a
 *   reset removed its own, so it removes its own, trying three times, and the
 *   login starts again; one it cannot remove is reported standing — clears
 *   D25's flag where the proof was given,
 *   issues the recovery codes, marks the witness. So at most one first
 *   binding stands, and a lost race spends the transaction, never a factor.
 *   The caller resumes the login.
 * - A codes write or a witness mark that fails never undoes the factor:
 *   the outcome says so, and the binding stands.
 */

import { randomBytes } from "node:crypto";
import {
	isMfaFactorLabel,
	MFA_AMR,
	type MfaEnrollmentCompletion,
	type MfaEnrollmentStart,
	type MfaFactor,
	type MfaTransaction,
} from "@o3co/auth-provider-core";
import {
	type MfaCeremonyCall,
	type MfaCeremonyKit,
	type MfaCeremonySubject,
	type MfaEnrollmentBeginOutcome,
	type MfaEnrollmentCompleteOutcome,
	type MfaEnrollmentRefusal,
	type MfaFactorUnreadable,
	outage,
	UNKNOWN_TRANSACTION,
} from "./ceremony.mjs";
import { keptState, mailRefusalOf, readKeptState, sendMfaMail } from "./mail.mjs";
import { issueRecoveryCodes } from "./recovery/issue.mjs";

const NOT_OPEN = Object.freeze({ outcome: "enrollment_not_open" as const });
const PROOF_REQUIRED = Object.freeze({ outcome: "email_proof_required" as const });
const UNKNOWN_KIND = Object.freeze({ outcome: "unknown_kind" as const });
const CLOSED = Object.freeze({ outcome: "first_binding_closed" as const });
const NO_PENDING = Object.freeze({ outcome: "no_pending_enrollment" as const });

/** How many times a binding that cannot stand tries to remove its own factor before it says the factor stands. */
const REMOVAL_TRIES = 3;
const INVALID_LABEL = Object.freeze({ outcome: "invalid_label" as const });

/** A login's first binding over the coordinator's `kit` (see this file's header). */
export function createMfaEnrollment(kit: MfaCeremonyKit): {
	begin(call: MfaCeremonyCall & { readonly kind: unknown }): Promise<MfaEnrollmentBeginOutcome>;
	complete(
		call: MfaCeremonyCall & { readonly proof: unknown; readonly label: unknown },
	): Promise<MfaEnrollmentCompleteOutcome>;
} {
	const { factors, factorStore, sealing } = kit;

	/**
	 * The transaction `call` names when it is a login's first binding, with its
	 * `User`, the account-email proof given where owed — D25's flag read again,
	 * and written onto a transaction that did not owe the proof; else the
	 * refusal.
	 */
	const opened = async (
		call: MfaCeremonyCall,
	): Promise<
		| { readonly tx: MfaTransaction; readonly user: Readonly<Record<string, unknown>> }
		| MfaEnrollmentRefusal
	> => {
		const tx = await kit.bound(call);
		if (tx === null) return UNKNOWN_TRANSACTION;
		if ("outcome" in tx) return tx;
		const user = tx.continuation?.primary.user;
		if (tx.enrollment === "none" || user === undefined) return NOT_OPEN;
		if (tx.emailProof === "required") return PROOF_REQUIRED;
		if (tx.emailProof === "not_required") {
			const flagged = await kit.emailProofRequired(tx.subject);
			if (flagged !== false) {
				if (flagged !== true) return flagged;
				const owed = await kit.write(tx, { emailProof: "required" });
				return "outcome" in owed ? owed : PROOF_REQUIRED;
			}
		}
		return { tx, user };
	};

	/** The counting factor of `kind` `user` may enroll; an `enrollable` that throws offers nothing. */
	const enrollable = (
		kind: unknown,
		user: Readonly<Record<string, unknown>>,
	): MfaFactor | undefined => {
		if (typeof kind !== "string") return undefined;
		const factor = factors.get(kind);
		if (factor?.counting !== true) return undefined;
		try {
			return (factor.enrollable?.(user) ?? true) ? factor : undefined;
		} catch {
			return undefined;
		}
	};

	/** Whether `subject` holds no record: the only state a first binding may start or finish in. */
	const holdsNone = async (subject: string) => {
		const records = await kit.recordsOf(subject);
		return "outcome" in records ? records : records.length === 0;
	};

	/** This binding's factor `id` removed, tried {@link REMOVAL_TRIES} times: `undefined` once removed, else the last failure. */
	const removeOwn = async (
		subject: string,
		id: string,
	): Promise<{ readonly cause: unknown } | undefined> => {
		let standing: { readonly cause: unknown } | undefined;
		for (let tried = 0; tried < REMOVAL_TRIES; tried++) {
			try {
				await factorStore.remove(subject, id);
				return undefined;
			} catch (cause) {
				standing = { cause };
			}
		}
		return standing;
	};

	/**
	 * After this binding's factor `id` was written: `undefined` only when the
	 * records read again are its own alone. Otherwise its own is removed —
	 * another stands beside it (another transaction bound one at once), its
	 * own is gone (a reset removed it), or the records cannot be read to tell —
	 * and a factor that cannot be removed is reported standing.
	 */
	const conflict = async (
		about: MfaCeremonySubject,
		id: string,
	): Promise<MfaEnrollmentCompleteOutcome | undefined> => {
		const records = await kit.recordsOf(about.subject);
		const alone = !("outcome" in records) && records.length === 1 && records[0]?.id === id;
		if (alone) return undefined;
		const standing = await removeOwn(about.subject, id);
		if ("outcome" in records) {
			return { outcome: "first_binding_unchecked", listing: records, standing, ...about };
		}
		return { outcome: "first_binding_conflict", standing, ...about };
	};

	return {
		async begin(call) {
			const nowMs = kit.now();
			const open = await opened(call);
			if ("outcome" in open) return open;
			const { tx, user } = open;
			const factor = enrollable(call.kind, user);
			if (factor === undefined) return UNKNOWN_KIND;
			const none = await holdsNone(tx.subject);
			if (none !== true) return none === false ? CLOSED : none;
			const failed = (cause: unknown): MfaEnrollmentBeginOutcome => ({
				outcome: "enrollment_failed",
				kind: factor.kind,
				cause,
			});
			let started: MfaEnrollmentStart;
			try {
				started = await factor.beginEnrollment({
					subject: tx.subject,
					transactionId: tx.id,
					nowMs,
					request: call.request,
					digests: sealing.digestsFor(factor.kind),
					user,
					factors: [],
				});
				if (!kit.answerable(started?.response) || !kit.answerable(started.state)) {
					throw new TypeError(
						"the factor's enrollment answered a response or a state that is not an object",
					);
				}
			} catch (cause) {
				return failed(cause);
			}
			const begun: MfaEnrollmentBeginOutcome = {
				outcome: "begun",
				response: started.response as object,
				subject: tx.subject,
				kind: factor.kind,
				purpose: tx.purpose,
			};
			/** The pending enrollment, sealed with the address's digest when a code went out. */
			const pending = (
				addressDigest: Parameters<typeof keptState>[0]["addressDigest"],
				expiresAtMs: number,
			) => ({
				kind: factor.kind,
				state: sealing.sealState(
					{ transactionId: tx.id, kind: factor.kind, use: "enrollment" },
					keptState({ state: started.state, addressDigest }),
				),
				expiresAtMs,
			});

			if (started.mail !== undefined) {
				const mailed = await sendMfaMail<MfaEnrollmentBeginOutcome>({
					sender: kit.mailSender,
					mail: started.mail,
					purpose: "email_factor_enrollment",
					subject: tx.subject,
					address: user.email,
					nowMs,
					notAfterMs: tx.expiresAtMs,
					digests: sealing.digestsFor(factor.kind),
					keep: async (addressDigest, expiresAtMs) => {
						let pendingEnrollment: ReturnType<typeof pending>;
						try {
							pendingEnrollment = pending(addressDigest, expiresAtMs);
						} catch (cause) {
							return { kept: false, refusal: failed(cause) };
						}
						const kept = await kit.write(tx, { pendingEnrollment });
						if ("outcome" in kept) return { kept: false, refusal: kept };
						return { kept: true, clear: () => kit.clear(kept.written, "pendingEnrollment") };
					},
				});
				switch (mailed.outcome) {
					case "sent":
						return begun;
					case "not_kept":
						return mailed.refusal;
					case "refused_at_limit":
					case "no_sender":
					case "unavailable":
						return mailRefusalOf(mailed, "email_factor_enrollment", factor.kind);
					case "malformed":
					case "no_address":
					case "address_mismatch":
					case "key_unavailable":
						return failed(
							new TypeError(
								"the factor's enrollment asked for a mail it cannot send to this account",
							),
						);
					default:
						return mailed satisfies never;
				}
			}

			let pendingEnrollment: ReturnType<typeof pending>;
			try {
				pendingEnrollment = pending(undefined, tx.expiresAtMs);
			} catch (cause) {
				return failed(cause);
			}
			const written = await kit.write(tx, { pendingEnrollment });
			return "outcome" in written ? written : begun;
		},

		async complete(call) {
			const nowMs = kit.now();
			const open = await opened(call);
			if ("outcome" in open) return open;
			const { tx, user } = open;
			const pending = tx.pendingEnrollment;
			if (pending === undefined || pending.expiresAtMs <= nowMs) return NO_PENDING;
			const factor = enrollable(pending.kind, user);
			if (factor === undefined) return UNKNOWN_KIND;
			const label = call.label;
			if (label !== undefined && !isMfaFactorLabel(label)) return INVALID_LABEL;
			const none = await holdsNone(tx.subject);
			if (none !== true) return none === false ? CLOSED : none;

			const about: MfaCeremonySubject = {
				subject: tx.subject,
				kind: factor.kind,
				purpose: tx.purpose,
			};
			const unreadable = (
				state: "enrollment" | "key_unavailable",
				extra: { readonly keyId?: string; readonly cause?: unknown } = {},
			): MfaFactorUnreadable => ({
				outcome: "unreadable",
				kind: factor.kind,
				factorId: "",
				state,
				...extra,
			});

			const reserved = await kit.reserve(tx);
			if ("outcome" in reserved) {
				return reserved.outcome === "exhausted"
					? { outcome: "refused", reason: "exhausted", attemptsRemaining: 0, ...about }
					: reserved;
			}

			const sealed = sealing.openState(
				{ transactionId: tx.id, kind: factor.kind, use: "enrollment" },
				pending.state,
			);
			if (sealed.state === "key_unavailable") {
				return unreadable("key_unavailable", { keyId: sealed.keyId });
			}
			const kept = sealed.state === "ok" ? readKeptState(sealed.value) : undefined;
			if (kept?.state === undefined) return unreadable("enrollment");

			let completion: MfaEnrollmentCompletion;
			let amr: readonly string[] | undefined;
			try {
				completion = await factor.completeEnrollment({
					subject: tx.subject,
					transactionId: tx.id,
					nowMs,
					request: call.request,
					digests: sealing.digestsFor(factor.kind),
					user,
					factors: [],
					state: kept.state,
					...(kept.addressDigest === undefined ? {} : { addressDigest: kept.addressDigest }),
					proof: call.proof,
				});
				if (completion.ok) amr = kit.declaredAmr(factor, completion.data);
			} catch (cause) {
				return unreadable("enrollment", { cause });
			}
			if (!completion.ok) {
				return {
					outcome: "refused",
					reason: completion.reason,
					attemptsRemaining: reserved.attemptsRemaining,
					...about,
				};
			}
			if (amr === undefined) {
				return unreadable("enrollment", {
					cause: new TypeError("the factor's amrFor answered values it does not declare"),
				});
			}
			const named = label ?? (isMfaFactorLabel(completion.label) ? completion.label : undefined);
			const id = randomBytes(16).toString("base64url");
			let data: string;
			try {
				data = sealing.sealFactorData(
					{ subject: tx.subject, id, kind: factor.kind },
					completion.data,
				);
			} catch (cause) {
				return unreadable("enrollment", { cause });
			}

			// Consumed before anything is written: a lost race spends the
			// transaction, never a factor.
			const consumed = await kit.consume(tx);
			if ("outcome" in consumed) return consumed;
			const binding = typeof tx.emailProof === "object" ? "email_proof" : "password";
			try {
				await factorStore.create({
					id,
					subject: tx.subject,
					kind: factor.kind,
					label: named,
					binding,
					createdAt: new Date(nowMs),
					lastUsedAt: undefined,
					version: 0,
					data,
				});
			} catch (cause) {
				return outage("mfa_factor", "create", cause);
			}
			// Another transaction of the subject's may have bound one at once:
			// nothing follows the factor until it is known to stand alone.
			const conflicted = await conflict(about, id);
			if (conflicted !== undefined) return conflicted;
			// D25: the flag an operator reset set is cleared only once the proof was
			// given and the first counting factor written.
			const flagCleared =
				binding === "email_proof" ? await kit.consumeEmailProofRequirement(tx.subject) : undefined;
			const recoveryCodes = await issueRecoveryCodes({
				factors,
				factorStore,
				sealing,
				subject: tx.subject,
				binding,
				nowMs,
			});
			const witness = await kit.witness.mark(tx.subject);

			return {
				outcome: "enrolled",
				continuation: consumed.continuation,
				adds: {
					amr: [...new Set([...amr, ...(factor.addsMfa ? [MFA_AMR] : [])])],
					mfaAt: new Date(nowMs),
				},
				factor: { id, kind: factor.kind, ...(named === undefined ? {} : { label: named }) },
				binding,
				recoveryCodes,
				witness,
				flagUncleared: flagCleared?.failed,
				...about,
			};
		},
	};
}
