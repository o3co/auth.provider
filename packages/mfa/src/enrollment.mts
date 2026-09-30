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
 * - Nothing is bound while the transaction owes the account-email proof, or
 *   once the subject holds any record: only zero records open a first
 *   binding.
 * - Only a counting factor the login's `User` may enroll is offered. Its
 *   start is kept sealed on the transaction (`o3co:mfa:enrollment`), with the
 *   digest of the address its code went to when it mailed one
 *   (`sendMfaMail`).
 * - A completion reserves an attempt before the proof is checked, seals the
 *   factor's data, and then, in this order: consumes the transaction, writes
 *   the factor (`binding` `email_proof` when the proof was given, else
 *   `password`), issues the recovery codes, marks the witness. A lost race
 *   spends the transaction, never a factor. The caller resumes the login.
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
	type MfaFactorRecord,
	type MfaTransaction,
	type PrimaryContinuation,
} from "@o3co/auth-provider-core";
import type {
	MfaCeremonyCall,
	MfaCeremonyKit,
	MfaCeremonySubject,
	MfaFactorUnreadable,
	MfaMailRefusal,
	MfaRefusalReason,
	MfaStoreOutage,
	UnknownTransaction,
} from "./coordinator.mjs";
import { keptState, readKeptState, sendMfaMail } from "./mail.mjs";
import { generateRecoveryCodes, RECOVERY_CODE_FACTOR_KIND } from "./recovery/factor.mjs";
import type { MfaWitnessMark } from "./witness.mjs";

/** The transaction opened no enrollment, or it is not a login's first binding. */
const NOT_OPEN = Object.freeze({ outcome: "enrollment_not_open" as const });
/** The account-email proof is owed first. */
const PROOF_REQUIRED = Object.freeze({ outcome: "email_proof_required" as const });
/** No counting factor of that kind this user may enroll. */
const UNKNOWN_KIND = Object.freeze({ outcome: "unknown_kind" as const });
/** The subject holds a record now: the login starts again. */
const CLOSED = Object.freeze({ outcome: "first_binding_closed" as const });
const NO_PENDING = Object.freeze({ outcome: "no_pending_enrollment" as const });
const INVALID_LABEL = Object.freeze({ outcome: "invalid_label" as const });
const UNKNOWN_TRANSACTION = Object.freeze({ outcome: "unknown_transaction" as const });

type Refusal =
	| typeof NOT_OPEN
	| typeof PROOF_REQUIRED
	| typeof UNKNOWN_KIND
	| typeof CLOSED
	| UnknownTransaction
	| MfaStoreOutage;

export type MfaEnrollmentBeginOutcome =
	| Refusal
	| MfaMailRefusal
	/** The factor could not start its enrollment: an outage, never a refusal. */
	| { readonly outcome: "enrollment_failed"; readonly kind: string; readonly cause: unknown }
	| ({ readonly outcome: "begun"; readonly response: object } & MfaCeremonySubject);

/** The recovery codes a binding issued: none when their factor is off; not issued when their write failed. */
export type MfaIssuedRecoveryCodes =
	| { readonly issued: true; readonly codes: readonly string[] }
	| { readonly issued: false; readonly cause: unknown }
	| undefined;

export type MfaEnrollmentCompleteOutcome =
	| Refusal
	| MfaFactorUnreadable
	| typeof NO_PENDING
	| typeof INVALID_LABEL
	| { readonly outcome: "spent" }
	| ({
			readonly outcome: "refused";
			readonly reason: MfaRefusalReason | "duplicate";
			readonly attemptsRemaining: number;
	  } & MfaCeremonySubject)
	| ({
			readonly outcome: "enrolled";
			/** What the login persisted, as the store answered it at consumption. */
			readonly continuation: PrimaryContinuation | undefined;
			/** What the binding adds to the login: the factor's `amr`, `mfa` when it adds it, and when. */
			readonly adds: { readonly amr: readonly string[]; readonly mfaAt: Date };
			readonly factor: { readonly id: string; readonly kind: string; readonly label?: string };
			readonly binding: NonNullable<MfaFactorRecord["binding"]>;
			readonly recoveryCodes: MfaIssuedRecoveryCodes;
			readonly witness: MfaWitnessMark;
	  } & MfaCeremonySubject);

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
	 * `User`, the account-email proof given where owed; else the refusal.
	 */
	const opened = async (
		call: MfaCeremonyCall,
	): Promise<
		{ readonly tx: MfaTransaction; readonly user: Readonly<Record<string, unknown>> } | Refusal
	> => {
		const tx = await kit.bound(call);
		if (tx === null) return UNKNOWN_TRANSACTION;
		if ("outcome" in tx) return tx;
		const user = tx.continuation?.primary.user;
		if (tx.enrollment === "none" || user === undefined) return NOT_OPEN;
		if (tx.emailProof === "required") return PROOF_REQUIRED;
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
	const holdsNone = async (subject: string): Promise<boolean | MfaStoreOutage> => {
		const records = await kit.recordsOf(subject);
		return "outcome" in records ? records : records.length === 0;
	};

	/** The recovery codes issued beside the first counting factor, as `binding` authorized it. */
	const issueRecoveryCodes = async (
		subject: string,
		binding: NonNullable<MfaFactorRecord["binding"]>,
		nowMs: number,
	): Promise<MfaIssuedRecoveryCodes> => {
		const factor = factors.get(RECOVERY_CODE_FACTOR_KIND);
		if (factor === undefined) return undefined;
		const set = generateRecoveryCodes(factor, sealing.digestsFor(RECOVERY_CODE_FACTOR_KIND));
		if (set === undefined) return undefined;
		try {
			const id = randomBytes(16).toString("base64url");
			await factorStore.create({
				id,
				subject,
				kind: RECOVERY_CODE_FACTOR_KIND,
				label: undefined,
				binding,
				createdAt: new Date(nowMs),
				lastUsedAt: undefined,
				version: 0,
				data: sealing.sealFactorData({ subject, id, kind: RECOVERY_CODE_FACTOR_KIND }, set.data),
			});
		} catch (cause) {
			return { issued: false, cause };
		}
		return { issued: true, codes: set.codes };
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
			const about: MfaCeremonySubject = {
				subject: tx.subject,
				kind: factor.kind,
				purpose: tx.purpose,
			};
			const begun: MfaEnrollmentBeginOutcome = {
				outcome: "begun",
				response: started.response as object,
				...about,
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
						const refused = await kit.write(tx, { pendingEnrollment });
						if (refused !== undefined) return { kept: false, refusal: refused };
						return {
							kept: true,
							clear: async () => {
								await kit.transactions.update(tx.id, tx.version + 1, { pendingEnrollment: null });
							},
						};
					},
				});
				switch (mailed.outcome) {
					case "sent":
						return begun;
					case "not_kept":
						return mailed.refusal;
					case "refused_at_limit":
						return { outcome: "mail_refused_at_limit" };
					case "no_sender":
						return {
							outcome: "mail_unavailable",
							purpose: "email_factor_enrollment",
							kind: factor.kind,
							reason: "no_sender",
						};
					case "unavailable":
						return {
							outcome: "mail_unavailable",
							purpose: "email_factor_enrollment",
							kind: factor.kind,
							reason: "outage",
							cleared: mailed.cleared,
							cause: mailed.cause,
						};
					default:
						return failed(
							new TypeError(
								"the factor's enrollment asked for a mail it cannot send to this account",
							),
						);
				}
			}

			let pendingEnrollment: ReturnType<typeof pending>;
			try {
				pendingEnrollment = pending(undefined, tx.expiresAtMs);
			} catch (cause) {
				return failed(cause);
			}
			const refused = await kit.write(tx, { pendingEnrollment });
			return refused ?? begun;
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
				return { outcome: "unavailable", store: "mfa_factor", step: "create", cause };
			}
			const recoveryCodes = await issueRecoveryCodes(tx.subject, binding, nowMs);
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
				...about,
			};
		},
	};
}
