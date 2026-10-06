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
 *   the one the session's cookie holds; a factor that cannot say
 *   (`mayEnroll`) is an outage, at the start and at the completion, nothing
 *   opened or spent. Its start is kept sealed on the
 *   transaction (`o3co:mfa:enrollment`), with the digest of the address its
 *   code went to when it mailed one (`sendMfaMail`); the page is then
 *   answered where it went, masked (`sent_to`), and how long it lives
 *   (`expires_in`), which is how long the enrollment can be completed.
 * - A first binding is refused at its start and at its completion, before
 *   anything is spent or shown, when the subject's first-binding mark
 *   (`firstBindingMark.mts`) distrusts the authentication it rests on — the
 *   login's continuation, or the session's sign-in as admission read it —
 *   since its `User`'s recorded witness may be stale. A completion checks
 *   whenever the records it lists allow a first binding, whatever admission
 *   saw before it, and again under the subject's lease.
 * - The subject's generation is read where the enrollment begins — before the
 *   session's admission, or at a login's begin — and carried, sealed, in the
 *   pending enrollment (`factorSet.mts`). A completion's writes run whole
 *   under the subject's lease acquired at it, every one of them — the
 *   transaction store's included — through the writes the lease hands it,
 *   each started only with time of the lease left: a reset or a recovery
 *   since the begin refuses the binding, nothing spent but the attempt, as a
 *   binding the records no longer allow; another write holding the lease past
 *   the wait, or too little of it left before the first write, is
 *   `factors_busy`, nothing written and the transaction standing — the
 *   attempt reserved before the proof was checked counts, as any
 *   completion's does. Writes that ran out of the
 *   lease, or past it, answer what they wrote, and say so (`overran`).
 * - A factor enrolled already — a record of the subject, of its kind, answers
 *   the identity the binding would add (`MfaFactor.identity`) — is
 *   `factor_duplicate`, answered after a binding the records no longer
 *   allow and before the limit — at the start, and on the lease's read. At
 *   the start only where the identity is known before the factor begins
 *   (`enrollmentIdentity`), nothing opened or sent; at the completion once
 *   the proof was checked — the factor's own `duplicate` refusal too — on
 *   the records read before the lease and again on the lease's read, which
 *   decides: the attempt spent, nothing written, the transaction standing.
 *   The completion's read before the lease judges the limit before the
 *   proof is checked, no attempt spent, and finds a duplicate only after
 *   it: there a subject at the limit is answered the limit. For a factor
 *   without `identity`, only its own refusal finds one.
 * - A completion reserves an attempt before the proof is checked, seals the
 *   factor's data, and then, under the lease, in this order: judges the
 *   binding again on the subject's records as the lease's read gave them —
 *   a first one beside a record that may count, another beside none, a
 *   duplicate, or one past `mfa.maxFactorsPerSubject` is refused, nothing
 *   written and the transaction standing — a first one refused there
 *   beside a record the read before the lease did not find is
 *   `first_binding_conflict`, which the routes audit; for a first binding
 *   reads the subject's first-binding mark again — one that distrusts the
 *   authentication refuses it as at the start, one that cannot be read is an
 *   outage, nothing written and the transaction standing — and notes it — a
 *   note that fails refuses it, nothing more written, and so does the mark
 *   the note answers stood before it when that mark distrusts the
 *   authentication, as at the start — consumes the transaction,
 *   writes the factor. Every write of the
 *   subject's factor set is fenced on that read (`factorSet.mts`): a factor
 *   whose write finds the set changed since — another write landed, which
 *   under the lease only a writer past its own lease can make — is not
 *   written, and the binding is refused as one its records no longer allow,
 *   the transaction spent. So at most one first binding stands, one
 *   binding never passes the limit another made at once, and of two
 *   bindings of one authenticator at once one stands. A first binding —
 *   `binding` `email_proof` when the proof was given, on the transaction or
 *   in the session, else the sign-in it rests on: `federated` for a session
 *   signed in through a federation, else `password` (a login's always: only
 *   a password login is interrupted for a binding) — then clears D25's flag
 *   where the proof was given, issues the recovery codes — replacing the
 *   sets that stood, unless bound by a sign-in alone
 *   (`recovery/issue.mts`); a login's written
 *   unshown, for the answer that carries them to mark shown — and marks the
 *   witness. The caller resumes a login, or escalates the session the
 *   binding was made in by what it adds.
 * - A codes write or a witness mark that fails never undoes the factor:
 *   the outcome says so, and the binding stands.
 * - The factor's answers — its enrollment's start and end — are read once,
 *   field by field, however the factor holds them (a getter, a class's
 *   instance). The state, data and response in them are taken as their
 *   plain copy (`copyFactorValue`) where the answer is read, and that one
 *   copy is what `amrFor`, the seal and the page act on; one that is not
 *   plain JSON-shaped is the factor's failure (`503`), nothing kept or bound.
 *   A mail the start asks for is read there too (`copyAskedMail`). A
 *   completion is a binding only when its `ok` is `true` and a refusal only
 *   when it is `false` with a reason its type names: anything else is the
 *   factor's failure.
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
	type MfaEnrollmentFailed,
	type MfaEnrollmentRefusal,
	type MfaFactorUnreadable,
	outage,
	UNKNOWN_TRANSACTION,
} from "./ceremony.mjs";
import { enrollmentIdentity } from "./email/factor.mjs";
import type { MfaFactorSetCarried, MfaFactorSetWrites } from "./factorSet.mjs";
import {
	mayCount,
	mayEnroll,
	recordsAfterFirstBinding,
	reopenedEnrollment,
} from "./firstBinding.mjs";
import {
	copyAskedMail,
	keptState,
	mailedAnswer,
	mailRefusalOf,
	readKeptState,
	sendMfaMail,
} from "./mail.mjs";
import { issueRecoveryCodes, writeRecoveryCodes } from "./recovery/issue.mjs";
import { copyFactorValue } from "./sealing.mjs";

const NOT_OPEN = Object.freeze({ outcome: "enrollment_not_open" as const });
const PROOF_REQUIRED = Object.freeze({ outcome: "email_proof_required" as const });
const UNKNOWN_KIND = Object.freeze({ outcome: "unknown_kind" as const });
/** The subject's records no longer allow the binding a transaction of `purpose` was opened for. */
const closed = (purpose: MfaTransaction["purpose"]) =>
	({ outcome: "first_binding_closed", purpose }) as const;
const FACTOR_LIMIT = Object.freeze({ outcome: "factor_limit" as const });
const FACTOR_DUPLICATE = Object.freeze({ outcome: "factor_duplicate" as const });
const NO_PENDING = Object.freeze({ outcome: "no_pending_enrollment" as const });

/** What a first binding is bound by: the sign-in alone, `password` or `federated`, or `email_proof` after the account-email proof. */
type FirstBindingBy = "password" | "federated" | "email_proof";

/**
 * The binding a first binding's start counts by when the completion alone
 * will know it (a session's proof): `email_proof`, the fewest records it can
 * come to; the completion counts by the binding it makes.
 */
const UNTIL_COMPLETION: FirstBindingBy = "email_proof";

const INVALID_LABEL = Object.freeze({ outcome: "invalid_label" as const });

/** The pending enrollment as sealed: the kept state, and where the binding's writes begin (`factorSet.mts`). */
const sealedPending = (
	kept: Readonly<Record<string, unknown>>,
	carried: MfaFactorSetCarried,
): Readonly<Record<string, unknown>> => ({ ...kept, factorSet: carried });

/**
 * A sealed pending enrollment opened: its kept state, and what it carries of
 * where the binding's writes begin, unread here; `undefined` when it is not
 * what {@link sealedPending} seals.
 */
const openedPending = (
	opened: Readonly<Record<string, unknown>>,
):
	| { readonly kept: NonNullable<ReturnType<typeof readKeptState>>; readonly carried: unknown }
	| undefined => {
	const { factorSet: carried, ...rest } = opened;
	const kept = readKeptState(rest);
	return kept === undefined ? undefined : { kept, carried };
};

/** Whether `tx` binds the subject's first counting factor: one opened `required`, a login's or an `enroll` one. */
const isFirstBinding = (tx: MfaTransaction): boolean => tx.enrollment === "required";

/**
 * What a first binding on `tx` without the account-email proof is bound by:
 * the sign-in it rests on — `federated` for a session `call` was admitted in
 * that was signed in through a federation, else `password`. A login's is a
 * password's: only a password login is interrupted for a binding.
 */
const signedInBy = (tx: MfaTransaction, call: MfaCeremonyCall): "password" | "federated" =>
	tx.purpose === "enroll" && call.session?.federated === true ? "federated" : "password";

/** The authentication a binding on `tx` rests on: the login's primary, or the sign-in of the session `call` was admitted in. */
const authTimeOf = (tx: MfaTransaction, call: MfaCeremonyCall): number | undefined =>
	tx.purpose === "login" ? tx.continuation?.primary.authTimeMs : call.session?.authTimeMs;

/** The reasons an enrollment's completion may refuse with: any other is the factor's failure. */
const ENROLLMENT_REFUSALS: Readonly<
	Record<Extract<MfaEnrollmentCompletion, { readonly ok: false }>["reason"], true>
> = {
	invalid: true,
	expired: true,
	malformed: true,
	duplicate: true,
};

/** An enrollment over the coordinator's `kit` (see this file's header). */
export function createMfaEnrollment(kit: MfaCeremonyKit): {
	begin(call: MfaCeremonyCall & { readonly kind: unknown }): Promise<MfaEnrollmentBeginOutcome>;
	complete(
		call: MfaCeremonyCall & { readonly proof: unknown; readonly label: unknown },
	): Promise<MfaEnrollmentCompleteOutcome>;
} {
	const { factors, sealing, factorSet } = kit;

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

	/**
	 * The counting factor of `kind` `user` may enroll, `undefined` for none;
	 * one whose `enrollable` throws is an outage (`mayEnroll`).
	 */
	const enrollable = (
		kind: unknown,
		user: Readonly<Record<string, unknown>>,
	): MfaFactor | MfaEnrollmentFailed | undefined => {
		if (typeof kind !== "string") return undefined;
		const factor = factors.get(kind);
		if (factor?.counting !== true) return undefined;
		try {
			return mayEnroll(kind, factor, user) ? factor : undefined;
		} catch (cause) {
			return { outcome: "enrollment_failed", kind, cause };
		}
	};

	/**
	 * Why the subject's `records` refuse a binding now — a first one beside a
	 * record that may count, another beside none — then a `duplicate`, then
	 * the limit: another factor at it, or a first binding by `firstBy` whose
	 * factor and codes would pass it (`recordsAfterFirstBinding`); else
	 * `undefined`.
	 */
	const refusedBy = (
		purpose: MfaTransaction["purpose"],
		first: boolean,
		records: readonly MfaFactorRecord[],
		firstBy: FirstBindingBy,
		duplicate = false,
	): MfaEnrollmentRefusal | undefined => {
		const counted = records.some((record) => mayCount(factors, record));
		if (first ? counted : !counted) return closed(purpose);
		if (duplicate) return FACTOR_DUPLICATE;
		const after = first ? recordsAfterFirstBinding(factors, records, firstBy) : records.length + 1;
		return after <= kit.maxFactorsPerSubject ? undefined : FACTOR_LIMIT;
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
	 * Whether one of the subject's `records` of `factor`'s kind answers
	 * `identity` (`MfaFactor.identity`): the factor enrolled already. Never
	 * for no identity.
	 */
	const holdsIdentity = (
		subject: string,
		factor: MfaFactor,
		records: readonly MfaFactorRecord[],
		identity: string | undefined,
	): boolean =>
		identity !== undefined &&
		enrolledOfKind(subject, factor.kind, records).some(
			(enrolled) => kit.identityOf(factor, enrolled.data) === identity,
		);

	/**
	 * The identity `factor`'s enrollment for `user` would add, where its
	 * factor's module can tell it before the enrollment begins
	 * (`enrollmentIdentity`); else `undefined`.
	 */
	const identityAtBegin = (
		factor: MfaFactor,
		user: Readonly<Record<string, unknown>>,
	): string | undefined => enrollmentIdentity(factor, sealing.digestsFor(factor.kind), user);

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
		| MfaEnrollmentFailed
	> => {
		const session = call.session;
		if (call.transactionId === undefined && session !== undefined) {
			const factor = enrollable(call.kind, session.user);
			if (factor === undefined) return UNKNOWN_KIND;
			if ("outcome" in factor) return factor;
			const records = await kit.recordsOf(session.subject);
			if ("outcome" in records) return records;
			const first = reopenedEnrollment(factors, records) === "required";
			const refused = refusedBy(
				"enroll",
				first,
				records,
				UNTIL_COMPLETION,
				holdsIdentity(session.subject, factor, records, identityAtBegin(factor, session.user)),
			);
			if (refused !== undefined) return refused;
			if (first) {
				const distrusted = await kit.firstBindingDistrust(session.subject, session.authTimeMs);
				if (distrusted !== undefined) return distrusted;
			}
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
		if ("outcome" in factor) return factor;
		const records = await kit.recordsOf(open.tx.subject);
		if ("outcome" in records) return records;
		const refused = refusedBy(
			open.tx.purpose,
			isFirstBinding(open.tx),
			records,
			open.tx.purpose === "login"
				? typeof open.tx.emailProof === "object"
					? "email_proof"
					: "password"
				: UNTIL_COMPLETION,
			holdsIdentity(open.tx.subject, factor, records, identityAtBegin(factor, open.user)),
		);
		if (refused !== undefined) return refused;
		if (isFirstBinding(open.tx)) {
			const distrusted = await kit.firstBindingDistrust(open.tx.subject, authTimeOf(open.tx, call));
			if (distrusted !== undefined) return distrusted;
		}
		return { ...open, factor, records };
	};

	return {
		async begin(call) {
			const nowMs = kit.now();
			const open = await beginning(call);
			if ("outcome" in open) return open;
			const { tx, user, factor, records } = open;
			// Where the binding's writes begin: the session's, read before its admission, or read now.
			const start =
				tx.purpose === "enroll" && call.session?.factorSetStart !== undefined
					? call.session.factorSetStart
					: await factorSet.begin(tx.subject, "change");
			const carried = factorSet.carry(start);
			if ("outcome" in carried) return carried;
			const failed = (cause: unknown): MfaEnrollmentBeginOutcome => ({
				outcome: "enrollment_failed",
				kind: factor.kind,
				cause,
			});
			let started: {
				readonly state: MfaEnrollmentStart["state"];
				readonly response: Readonly<Record<string, unknown>>;
				readonly mail: unknown;
			};
			try {
				const answer = await factor.beginEnrollment({
					subject: tx.subject,
					transactionId: tx.id,
					nowMs,
					request: call.request,
					digests: sealing.digestsFor(factor.kind),
					user,
					factors: isFirstBinding(tx) ? [] : enrolledOfKind(tx.subject, factor.kind, records),
				});
				// The factor's answer, each field read once, however it holds them; its
				// state as the plain copy that is sealed, its response as the plain copy
				// the page is answered (`copyFactorValue`).
				started = {
					state: copyFactorValue(answer?.state),
					response: copyFactorValue(answer?.response),
					mail: copyAskedMail(answer?.mail),
				};
			} catch (cause) {
				return failed(cause);
			}
			const begun: MfaEnrollmentBeginOutcome = {
				outcome: "begun",
				response: started.response,
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
					sealedPending(keptState({ state: started.state, addressDigest }), carried),
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
			if ("outcome" in factor) return factor;
			const label = call.label;
			if (label !== undefined && !isMfaFactorLabel(label)) return INVALID_LABEL;
			const records = await kit.recordsOf(tx.subject);
			if ("outcome" in records) return records;
			const first = isFirstBinding(tx);
			// A first binding in a session is by the proof when one was given there.
			let proved = typeof tx.emailProof === "object";
			if (first && !proved && tx.purpose === "enroll") {
				const standing = await kit.provedInSession(tx.subject, tx.sid ?? "");
				if (typeof standing !== "boolean") return standing;
				proved = standing;
			}
			const firstBy: FirstBindingBy = proved ? "email_proof" : signedInBy(tx, call);
			const refused = refusedBy(tx.purpose, first, records, firstBy);
			if (refused !== undefined) return refused;
			if (first) {
				const distrusted = await kit.firstBindingDistrust(tx.subject, authTimeOf(tx, call));
				if (distrusted !== undefined) return distrusted;
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
			const pendingOpened = sealed.state === "ok" ? openedPending(sealed.value) : undefined;
			const kept = pendingOpened?.kept;
			if (pendingOpened === undefined || kept?.state === undefined) {
				return unreadable("enrollment");
			}

			let completion: MfaEnrollmentCompletion;
			let amr: readonly string[] | undefined;
			try {
				const answer = await factor.completeEnrollment({
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
				// The factor's answer, each field read once, however it holds them; its
				// data as the plain copy that is sealed (`copyFactorValue`) and that
				// `amrFor` is handed. An `ok` neither `true` nor `false`, or a refusal's
				// reason outside the contract's, is the factor's failure.
				const ok: unknown = answer.ok;
				if (ok === true) {
					const { data, label } = answer as Extract<MfaEnrollmentCompletion, { readonly ok: true }>;
					completion = { ok: true, data: copyFactorValue(data), label };
				} else if (ok === false) {
					const { reason } = answer as Extract<MfaEnrollmentCompletion, { readonly ok: false }>;
					if (typeof reason !== "string" || !Object.hasOwn(ENROLLMENT_REFUSALS, reason)) {
						throw new TypeError("the factor's enrollment refused with a reason it may not");
					}
					completion = { ok: false, reason };
				} else {
					throw new TypeError("the factor's enrollment answered an ok that is not a boolean");
				}
				if (completion.ok) amr = kit.declaredAmr(factor, completion.data);
			} catch (cause) {
				return unreadable("enrollment", { cause });
			}
			if (!completion.ok) {
				if (completion.reason === "duplicate") return FACTOR_DUPLICATE;
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
			// What the binding adds; the records read before the lease may hold it already.
			const identity = kit.identityOf(factor, completion.data);
			if (holdsIdentity(tx.subject, factor, records, identity)) return FACTOR_DUPLICATE;
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

			/** The binding's writes, run whole under the subject's lease (`factorSet.mts`). */
			const writePhase = async (
				writes: MfaFactorSetWrites,
			): Promise<MfaEnrollmentCompleteOutcome> => {
				// Judged again on the records read under the lease, before anything is
				// written: every write after is fenced on them.
				const refusedNow = refusedBy(
					tx.purpose,
					first,
					writes.factors.records,
					firstBy,
					holdsIdentity(tx.subject, factor, writes.factors.records, identity),
				);
				// A first binding closed here was let through by the read before the
				// lease, which found no record that may count: another binding landed.
				if (first && refusedNow?.outcome === "first_binding_closed") {
					return { outcome: "first_binding_conflict", ...about };
				}
				if (refusedNow !== undefined) return refusedNow;
				if (first) {
					// Read again under the lease: the read before it covers a mark noted
					// before the completion began, this one a mark noted since. A mark
					// stands more than twice a transaction's lifetime, so one noted since
					// and already lapsed means this transaction has ended too, which the
					// consumption below finds.
					let distrusted: Awaited<ReturnType<typeof kit.firstBindingDistrust>>;
					try {
						distrusted = await writes.read(() =>
							kit.firstBindingDistrust(tx.subject, authTimeOf(tx, call)),
						);
					} catch (cause) {
						return outage("mfa_transaction", "firstBindingAt", cause);
					}
					if (distrusted !== undefined) return distrusted;
					// Noted before the factor is written: a first binding the mark misses
					// would leave a stale session trusted.
					// Its answer, the mark that stood before it, covers one that landed since
					// the read above: a note given up on by its writer may land late.
					const unnoted = await writes.run(
						() => kit.noteFirstBinding(tx.subject, authTimeOf(tx, call)),
						(cause) => outage("mfa_transaction", "noteFirstBinding", cause),
					);
					if (unnoted !== undefined) return unnoted;
				}
				// Consumed before anything is written: a lost race spends the
				// transaction, never a factor.
				const consumed = await writes.run(
					() => kit.consume(tx),
					(cause) => outage("mfa_transaction", "consume", cause),
				);
				if ("outcome" in consumed) return consumed;
				const binding: NonNullable<MfaFactorRecord["binding"]> = first ? firstBy : "mfa";
				let created: "created" | "changed";
				try {
					created = await writes.factors.create({
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
				// Another write of the set landed since it was read: the binding was
				// judged on records that no longer stand. The transaction is spent.
				if (created === "changed") return closed(tx.purpose);
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
					return {
						...enrolled,
						recoveryCodes: undefined,
						witness: undefined,
						flagUncleared: undefined,
					};
				}
				// D25: the flag an operator reset set is cleared only once the proof was
				// given and the first counting factor written.
				const flagCleared =
					binding === "email_proof"
						? await writes.emailProofRequirement.consume(tx.subject).then(
								() => undefined,
								(failed: unknown) => ({ failed }),
							)
						: undefined;
				const issuing = { factors, writes, sealing, subject: tx.subject, binding, nowMs };
				// A login's answer may still be another requirement's, or a refusal: its
				// codes are marked shown by the answer that carries them.
				const recoveryCodes =
					tx.purpose === "enroll"
						? await issueRecoveryCodes(issuing)
						: await writeRecoveryCodes({ ...issuing, markedThrough: kit.factorStore });
				const witness = await writes.witness.mark(tx.subject);

				return { ...enrolled, recoveryCodes, witness, flagUncleared: flagCleared?.failed };
			};
			const bound = await factorSet.bind(
				factorSet.resume(tx.subject, pendingOpened.carried),
				tx.subject,
				writePhase,
			);
			switch (bound.outcome) {
				case "bound":
					return bound.overran === true ? { ...bound.done, overran: true } : bound.done;
				// A reset or a recovery since the begin: the records it began over are gone.
				case "changed":
					return closed(tx.purpose);
				case "busy":
					return {
						outcome: "factors_busy",
						retryAfterSeconds: bound.retryAfterSeconds,
						...(bound.overran === true ? { overran: true as const } : {}),
					};
				default:
					return {
						...outage(bound.store, bound.step, bound.cause),
						...(bound.overran === true ? { overran: true as const } : {}),
					};
			}
		},
	};
}
