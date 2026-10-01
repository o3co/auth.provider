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
 * An enrollment (the MFA ADR's F3, F4, D12, D24, D25): a counting factor
 * bound on a login's transaction opened with `enrollment` other than `none` —
 * by the requirement, or reopened after a non-counting proof — or on an
 * `enroll` transaction a signed-in session opened once admission let it in
 * as `mfa.manage`. Either way `required` binds the subject's first counting
 * factor, and `allowed` one beside a record that may count, bound by `mfa`.
 *
 * - Nothing is bound while the transaction owes the account-email proof — a
 *   login's first binding reads D25's flag again at each call, so one set
 *   after it opened makes it owe the proof; in a session the gate is
 *   admission's — or once the subject's records no longer allow the binding
 *   it was opened for: a first binding only while no record may count,
 *   another factor only beside a record that may count and within
 *   `mfa.maxFactorsPerSubject`.
 * - Only a counting factor the `User` may enroll is offered: the login's, or
 *   the one the session's cookie holds. Its start is kept sealed on the
 *   transaction (`o3co:mfa:enrollment`), with the digest of the address its
 *   code went to when it mailed one (`sendMfaMail`); the page is then
 *   answered where it went, masked (`sent_to`), and how long it lives
 *   (`expires_in`), which is how long the enrollment can be completed.
 * - A completion reserves an attempt before the proof is checked, seals the
 *   factor's data, and then, in this order: consumes the transaction, writes
 *   the factor. Another factor then reads the subject's records again, and
 *   one past `mfa.maxFactorsPerSubject` — bindings made at once — removes
 *   its own, so the limit holds; one it cannot remove is reported standing,
 *   for the caller to audit as bound. A first binding — `binding` `email_proof` when the proof was
 *   given, on the transaction or in the session, else `password` — then
 *   reads the subject's records again: it stands only when its own is listed
 *   and is the only one that may count; otherwise another transaction bound
 *   one at once, or a reset removed its own, so it removes its own, trying
 *   three times, and the user signs in again; one it cannot remove is
 *   reported standing. It then clears D25's flag where the proof was given,
 *   issues the recovery codes — replacing the sets that stood, except that a
 *   reopened login's binding by `password` keeps them — and marks the
 *   witness. So at most one first binding stands, and a lost race
 *   spends the transaction, never a factor. The caller resumes a login; a
 *   session is left as it was.
 * - A codes write or a witness mark that fails never undoes the factor:
 *   the outcome says so, and the binding stands.
 */

import { randomBytes } from "node:crypto";
import {
	isMfaFactorLabel,
	MFA_AMR,
	type MfaEnrolledFactor,
	type MfaEnrollmentCompletion,
	type MfaEnrollmentStart,
	type MfaFactor,
	type MfaFactorRecord,
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
	type MfaStoreOutage,
	outage,
	UNKNOWN_TRANSACTION,
} from "./ceremony.mjs";
import { mayCount, reopenedEnrollment } from "./firstBinding.mjs";
import { keptState, mailedAnswer, mailRefusalOf, readKeptState, sendMfaMail } from "./mail.mjs";
import { issueRecoveryCodes } from "./recovery/issue.mjs";

const NOT_OPEN = Object.freeze({ outcome: "enrollment_not_open" as const });
const PROOF_REQUIRED = Object.freeze({ outcome: "email_proof_required" as const });
const UNKNOWN_KIND = Object.freeze({ outcome: "unknown_kind" as const });
/** The subject's records no longer allow the binding a transaction of `purpose` was opened for. */
const closed = (purpose: MfaTransaction["purpose"]) =>
	({ outcome: "first_binding_closed", purpose }) as const;
const FACTOR_LIMIT = Object.freeze({ outcome: "factor_limit" as const });
const NO_PENDING = Object.freeze({ outcome: "no_pending_enrollment" as const });

/** How many times a binding that cannot stand tries to remove its own factor before it says the factor stands. */
const REMOVAL_TRIES = 3;
const INVALID_LABEL = Object.freeze({ outcome: "invalid_label" as const });

/** Whether `tx` binds the subject's first counting factor: one opened `required`, a login's or an `enroll` one. */
const isFirstBinding = (tx: MfaTransaction): boolean => tx.enrollment === "required";

/** An enrollment over the coordinator's `kit` (see this file's header). */
export function createMfaEnrollment(kit: MfaCeremonyKit): {
	begin(call: MfaCeremonyCall & { readonly kind: unknown }): Promise<MfaEnrollmentBeginOutcome>;
	complete(
		call: MfaCeremonyCall & { readonly proof: unknown; readonly label: unknown },
	): Promise<MfaEnrollmentCompleteOutcome>;
} {
	const { factors, factorStore, sealing } = kit;

	/**
	 * The transaction `call` names when it opened an enrollment, with its
	 * `User`, the account-email proof given where owed — for a login's, D25's
	 * flag read again, and written onto a transaction that did not owe the
	 * proof; else the refusal.
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
		if (tx.purpose === "enroll") {
			// The bound read held its sid and subject to the session's.
			const sessionUser = call.session?.user;
			if (tx.enrollment === "none" || sessionUser === undefined) return NOT_OPEN;
			return tx.emailProof === "required" ? PROOF_REQUIRED : { tx, user: sessionUser };
		}
		const user = tx.continuation?.primary.user;
		if (tx.enrollment === "none" || user === undefined) return NOT_OPEN;
		if (tx.emailProof === "required") return PROOF_REQUIRED;
		// D25's flag asks at a first binding alone.
		if (tx.emailProof === "not_required" && isFirstBinding(tx)) {
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

	/**
	 * Why the subject's `records` refuse a binding now — a first one beside a
	 * record that may count, another beside none, or at the limit — else
	 * `undefined`.
	 */
	const refusedBy = (
		purpose: MfaTransaction["purpose"],
		first: boolean,
		records: readonly MfaFactorRecord[],
	): MfaEnrollmentRefusal | undefined => {
		const counted = records.some((record) => mayCount(factors, record));
		if (first) return counted ? closed(purpose) : undefined;
		if (!counted) return closed(purpose);
		return records.length < kit.maxFactorsPerSubject ? undefined : FACTOR_LIMIT;
	};

	/** The subject's factors of `kind` among `records`, opened, as a factor is handed them; one that does not open is left out. */
	const enrolledOfKind = (
		subject: string,
		kind: string,
		records: readonly MfaFactorRecord[],
	): MfaEnrolledFactor[] =>
		records
			.filter((record) => record.kind === kind)
			.flatMap((record) => {
				const data = sealing.openFactorData({ subject, id: record.id, kind }, record.data);
				return data.state === "ok"
					? [
							{
								id: record.id,
								label: record.label,
								createdAt: record.createdAt,
								lastUsedAt: record.lastUsedAt,
								data: data.value,
							},
						]
					: [];
			});

	/**
	 * The transaction a call begins on: the one it names, or — with none named,
	 * in an admitted session — a new `enroll` one of the binding the subject's
	 * records allow now; with the `User`, the factor of `kind` and the records.
	 */
	const beginning = async (
		call: MfaCeremonyCall & { readonly kind: unknown },
	): Promise<
		| {
				readonly tx: MfaTransaction;
				readonly user: Readonly<Record<string, unknown>>;
				readonly factor: MfaFactor;
				readonly records: readonly MfaFactorRecord[];
		  }
		| MfaEnrollmentRefusal
	> => {
		const session = call.session;
		if (call.transactionId === undefined && session !== undefined) {
			const factor = enrollable(call.kind, session.user);
			if (factor === undefined) return UNKNOWN_KIND;
			const records = await kit.recordsOf(session.subject);
			if ("outcome" in records) return records;
			const first = reopenedEnrollment(factors, records) === "required";
			const refused = refusedBy("enroll", first, records);
			if (refused !== undefined) return refused;
			const tx = await kit.openEnrollment(call, session, {
				enrollment: first ? "required" : "allowed",
				emailProof: "not_required",
			});
			return "outcome" in tx ? tx : { tx, user: session.user, factor, records };
		}
		const open = await opened(call);
		if ("outcome" in open) return open;
		const factor = enrollable(call.kind, open.user);
		if (factor === undefined) return UNKNOWN_KIND;
		const records = await kit.recordsOf(open.tx.subject);
		if ("outcome" in records) return records;
		const refused = refusedBy(open.tx.purpose, isFirstBinding(open.tx), records);
		return refused ?? { ...open, factor, records };
	};

	/**
	 * After another factor `id` was written beside the subject's: `undefined`
	 * while the records read again stay within `mfa.maxFactorsPerSubject`.
	 * Otherwise — past it, as bindings made at once can be, or unreadable —
	 * its own is removed, and the answer is the limit or the read's outage;
	 * one it cannot remove is reported standing, with the read's outage.
	 */
	const pastLimit = async (
		subject: string,
		id: string,
	): Promise<
		| MfaEnrollmentRefusal
		| {
				readonly listing: MfaStoreOutage | undefined;
				readonly standing: { readonly cause: unknown };
		  }
		| undefined
	> => {
		const records = await kit.recordsOf(subject);
		if (!("outcome" in records) && records.length <= kit.maxFactorsPerSubject) return undefined;
		const listing = "outcome" in records ? records : undefined;
		const standing = await removeOwn(subject, id);
		if (standing !== undefined) return { listing, standing };
		return listing ?? FACTOR_LIMIT;
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
	 * records read again list it, and it is the only one that may count.
	 * Otherwise its own is removed —
	 * another stands beside it (another transaction bound one at once), its
	 * own is gone (a reset removed it), or the records cannot be read to tell —
	 * and a factor that cannot be removed is reported standing.
	 */
	const conflict = async (
		about: MfaCeremonySubject,
		id: string,
	): Promise<MfaEnrollmentCompleteOutcome | undefined> => {
		const records = await kit.recordsOf(about.subject);
		const alone =
			!("outcome" in records) &&
			records.some((record) => record.id === id) &&
			records.every((record) => record.id === id || !mayCount(factors, record));
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
			const open = await beginning(call);
			if ("outcome" in open) return open;
			const { tx, user, factor, records } = open;
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
					factors: isFirstBinding(tx) ? [] : enrolledOfKind(tx.subject, factor.kind, records),
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
				...(tx.purpose === "enroll"
					? {
							transaction: {
								id: tx.id,
								expiresIn: Math.max(1, Math.ceil((tx.expiresAtMs - nowMs) / 1000)),
							},
						}
					: {}),
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
					case "sent": {
						// Where the code went and how long it lives, as kept: never the factor's to say.
						const answer = mailedAnswer(mailed, nowMs);
						return {
							...begun,
							response: { ...begun.response, ...answer },
							expiresIn: answer.expires_in,
						};
					}
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
			const records = await kit.recordsOf(tx.subject);
			if ("outcome" in records) return records;
			const first = isFirstBinding(tx);
			const refused = refusedBy(tx.purpose, first, records);
			if (refused !== undefined) return refused;
			// A first binding in a session is by the proof when one was given there.
			let proved = typeof tx.emailProof === "object";
			if (first && !proved && tx.purpose === "enroll") {
				const standing = await kit.provedInSession(tx.subject, tx.sid ?? "");
				if (typeof standing !== "boolean") return standing;
				proved = standing;
			}

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
					factors: first ? [] : enrolledOfKind(tx.subject, factor.kind, records),
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
			const binding: NonNullable<MfaFactorRecord["binding"]> = !first
				? "mfa"
				: proved
					? "email_proof"
					: "password";
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
			const enrolled = {
				outcome: "enrolled" as const,
				continuation: consumed.continuation,
				adds: {
					amr: [...new Set([...amr, ...(factor.addsMfa ? [MFA_AMR] : [])])],
					mfaAt: new Date(nowMs),
				},
				factor: { id, kind: factor.kind, ...(named === undefined ? {} : { label: named }) },
				binding,
				...about,
			};
			if (!first) {
				const over = await pastLimit(tx.subject, id);
				if (over !== undefined && "standing" in over) {
					return {
						outcome: "factor_standing",
						factor: enrolled.factor,
						binding,
						listing: over.listing,
						standing: over.standing,
						...about,
					};
				}
				if (over !== undefined) return over;
				return {
					...enrolled,
					recoveryCodes: undefined,
					witness: undefined,
					flagUncleared: undefined,
				};
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
				// A reopened login's first binding by `password` keeps the set that
				// stood: the owner's remaining codes stay usable (D25).
				...(tx.purpose === "login" && binding === "password"
					? { keep: "password_binding" as const }
					: {}),
			});
			const witness = await kit.witness.mark(tx.subject);

			return { ...enrolled, recoveryCodes, witness, flagUncleared: flagCleared?.failed };
		},
	};
}
