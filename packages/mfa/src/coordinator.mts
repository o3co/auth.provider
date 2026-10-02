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
 * The coordinator: a login's second-factor ceremony, and an enrollment or an
 * account-email proof in a signed-in session, over the MFA stores, the key
 * ring and the installed factors — reading the transaction, issuing a
 * factor's challenge, verifying a proof — answered as outcomes the routes map
 * to HTTP. See README, "The routes", and ADR
 * 2026-09-25-multi-factor-authentication, F1, F2, F4 and D8.
 *
 * - Every operation starts with the bound read (`getBoundMfaTransaction`), and
 *   after it calls only operations that carry the version it read, and
 *   `reserveAttempt` once it held. A transaction bound to anything else,
 *   spent, expired, neither a login's nor an `enroll` or `step_up` one of
 *   the session the call was admitted in — its `sid` and subject — reads as
 *   unknown, and spends nothing. An `enroll` transaction verifies the
 *   account-email proof alone.
 * - A login's transaction is held to its subject's sessions boundary
 *   (`revokedBefore`) at every bound read: a continuation authenticated at or
 *   before it, the revocation skew allowed, is `revoked` and spends nothing;
 *   a boundary that cannot be read is an outage; none wired, none is read.
 *   The step-up reads only its session's `enroll` and `step_up`
 *   transactions, so it never reads a login's boundary. The boundary is read once per call: a
 *   revocation landing during that call can still let it bind.
 * - The step-up of a subject with no record that may count opens, or uses,
 *   an `enroll` transaction owing the account-email proof (`stepUp.mts`); a verified proof
 *   on one is recorded for its session alone, standing
 *   `mfa.manage.maxAgeSeconds`. The step-up of a subject holding one opens,
 *   or uses, a `step_up` transaction, opened only when the session store can
 *   record it.
 * - A verification reserves its attempt before the proof is checked, consumes
 *   the transaction before the factor moves on, and on a lost compare-and-set
 *   reads the factor again and checks the proof again: a code used twice at
 *   once succeeds once, and a lost race never spends a factor's state.
 * - Between the two, the subject lock (`lock.mts`): a guessable proof
 *   reserves one of its subject's attempts after the transaction's, and a
 *   hold refuses it unchecked. The attempt is settled once the verification
 *   ends: `success` once the factor was written, `void` for a right proof
 *   that completed nothing, and a failure otherwise — a refusal, an outage
 *   or a factor that throws before a verdict. An exempt proof records its
 *   success once the factor was written.
 * - A store that cannot answer, a factor whose data does not open, and a
 *   factor that throws are outages: never a wrong code, never "no factor".
 * - `factor_id: "account-email"` names the account-email proof (`proof.mts`)
 *   on a transaction that owes it; a first binding is `enrollment.mts`'s.
 *   Both are handed the coordinator's reads and writes as the kit; what the
 *   three share is `ceremony.mts`'s contract.
 * - Under `required`, a login's factor that does not count, for a subject
 *   with no counting factor it can use, completes no login: what the login
 *   reopens for — or why not — is settled before the transaction's attempt is
 *   reserved (`reopen.mts`), and settled again after a lost compare-and-set
 *   round; once the transaction is consumed and the proof spent, the login is
 *   reopened for a binding. A login transaction opened for a binding
 *   verifies no factor.
 * - A verified proof on a session's `step_up` transaction is answered
 *   `stepped_up`, naming the session and what the proof adds, dated by the
 *   verification's time: the caller records it on the session. The factor's
 *   mailed code goes to the session's own address.
 * - A verified counting factor marks the enrollment witness of a login — or
 *   a step-up's session — whose `User` does not carry it (D12), after noting the subject's first-binding
 *   mark (`firstBindingMark.mts`): a note that fails leaves the witness
 *   unmarked, so no session's recorded witness goes stale unmarked; a
 *   directory that cannot write the witness gets no note. Neither failure
 *   fails the login (`reconcileWitness`). The mark is `factorSet.mts`'s,
 *   held to the subject's generation read before the proof is checked: it
 *   reads the records first, and clears the witness again when the records
 *   read after it hold none that may count.
 * - A factor is handed its records opened and digests under the ring; it
 *   never sees a key, a store, a transaction or the mail sender. A code it
 *   asks to be mailed goes through `sendMfaMail` (`mail.mts`), to the
 *   login's address, and the digest of that address is kept with the pending
 *   challenge and handed back to the verification. The page is answered the
 *   factor's response with where the code went, masked (`sent_to`), and how
 *   long it lives (`expires_in`), as kept.
 * - What a record can do is `factorState.mts`'s one reading: what a
 *   transaction offers (`isOffered`) and what is usable are that file's.
 * - A refusal carries the factor id the factor named only when it is one of
 *   the subject's factors of the kind verified: nothing else reaches the audit.
 *   Another is dropped and flagged, never quoted.
 */

import {
	coveredByRevocationBoundary,
	DEFAULT_CLOCK_SKEW_MS,
	DEFAULT_SUBJECT_REVOCATION_SKEW_MS,
	getBoundMfaTransaction,
	isConsumedMfaTransaction,
	isMfaFactorUpdateWritten,
	type MailSender,
	MFA_AMR,
	type MfaEnrolledFactor,
	type MfaFactor,
	type MfaFactorRecord,
	type MfaFactorResolver,
	type MfaFactorState,
	type MfaFactorStore,
	type MfaKeyedDigest,
	type MfaTransaction,
	type MfaTransactionPatch,
	type MfaTransactionStore,
	type MfaVerification,
	readMfaAttemptReservation,
	readMfaSubjectCount,
	readSessionEmailProof,
	type SubjectRevocation,
} from "@o3co/auth-provider-core";
import {
	type MfaCeremonyCall,
	type MfaCeremonyKit,
	type MfaCeremonySubject,
	type MfaChallengeOutcome,
	type MfaDescribeOutcome,
	type MfaEnrollmentBeginOutcome,
	type MfaEnrollmentCompleteOutcome,
	type MfaFactorUnreadable,
	type MfaFirstBindingDistrusted,
	type MfaRefusalReason,
	type MfaStepUpOutcome,
	type MfaStoreOutage,
	type MfaVerifyOutcome,
	OUTSIDE_CONTRACT,
	outage,
	type Revoked,
	UNKNOWN_FACTOR,
	UNKNOWN_TRANSACTION,
	type UnknownTransaction,
} from "./ceremony.mjs";
import { createMfaEnrollment } from "./enrollment.mjs";
import type { MfaFactorSet } from "./factorSet.mjs";
import { holdsUsableRecord, isOffered, readFactorRecord } from "./factorState.mjs";
import type { RequireEmailProof } from "./firstBinding.mjs";
import {
	distrustedByFirstBinding,
	firstBindingRetryAfterMs,
	readFirstBindingMark,
} from "./firstBindingMark.mjs";
import { exemptKindsHeld, type MfaSubjectLock } from "./lock.mjs";
import { keptState, mailedAnswer, mailRefusalOf, readKeptState, sendMfaMail } from "./mail.mjs";
import { ACCOUNT_EMAIL_FACTOR_ID, createAccountEmailProof } from "./proof.mjs";
import { isRecoveryCodeFactor, recoveryCodesLeft, recoverySetRefusal } from "./recovery/factor.mjs";
import { createLoginReopen } from "./reopen.mjs";
import type { MfaRequirementMode } from "./requirement.mjs";
import type { MfaSealing } from "./sealing.mjs";
import { createMfaStepUp } from "./stepUp.mjs";
import { openEnrollTransaction, openLoginBinding, openStepUpTransaction } from "./transactions.mjs";
import { type MfaEnrollmentWitness, reconciles, reconcilesSession } from "./witness.mjs";

/** A transaction id as the login makes one: 32 bytes, base64url. */
const TRANSACTION_ID = /^[A-Za-z0-9_-]{43}$/;

/** How many times a verification writes a factor whose compare-and-set it keeps losing. */
const ADVANCE_ROUNDS = 3;

/** Whether `written`, what a transaction's `update` answered other than `null`, is `tx` at its next version. */
const isWrittenAt = (written: unknown, tx: MfaTransaction): boolean => {
	try {
		if (typeof written !== "object" || written === null) return false;
		const { id, version } = written as Readonly<Record<string, unknown>>;
		return id === tx.id && version === tx.version + 1;
	} catch {
		return false;
	}
};

/** Whether `amr`, what a factor's `amrFor` answered, names at least one value, and only values the factor declares. */
const declaresEach = (factor: MfaFactor, amr: unknown): amr is readonly string[] =>
	Array.isArray(amr) &&
	amr.length > 0 &&
	amr.every((value) => typeof value === "string" && factor.amrValues.includes(value));

/** What a refusal says of the factor it concerns, as the `refused` outcome carries it. */
type RefusalConcerns = Pick<
	Extract<MfaVerifyOutcome, { outcome: "refused" }>,
	"factorId" | "factorIdDropped"
>;

export interface MfaCoordinator {
	describe(call: MfaCeremonyCall): Promise<MfaDescribeOutcome>;
	challenge(call: MfaCeremonyCall & { readonly factorId: unknown }): Promise<MfaChallengeOutcome>;
	verify(
		call: MfaCeremonyCall & { readonly factorId: unknown; readonly proof: unknown },
	): Promise<MfaVerifyOutcome>;
	/** An enrollment begun — a login's first binding, or one in the session `call.session` names — the factor of `kind` started (`enrollment.mts`). */
	beginEnrollment(
		call: MfaCeremonyCall & { readonly kind: unknown },
	): Promise<MfaEnrollmentBeginOutcome>;
	/** An enrollment completed: the proof taken, the factor bound (`enrollment.mts`). */
	completeEnrollment(
		call: MfaCeremonyCall & { readonly proof: unknown; readonly label: unknown },
	): Promise<MfaEnrollmentCompleteOutcome>;
	/**
	 * The step-up of `call.session`'s subject (`stepUp.mts`): with no record
	 * that may count, the `enroll` transaction the account-email proof is
	 * owed on; holding one, the `step_up` transaction its factor is verified
	 * on, recording `acrValues` — each the one `call` names when it is that
	 * session's own and still usable, else a new one.
	 */
	stepUp(
		call: MfaCeremonyCall & { readonly acrValues: readonly string[] | undefined },
	): Promise<MfaStepUpOutcome>;
}

export interface MfaCoordinatorOptions {
	readonly factors: MfaFactorResolver;
	readonly factorStore: MfaFactorStore;
	readonly transactions: MfaTransactionStore;
	readonly sealing: MfaSealing;
	/** `mfa.maxAttemptsPerTransaction`. */
	readonly maxAttemptsPerTransaction: number;
	/** The subject lock a verification's proof is held to. */
	readonly lock: MfaSubjectLock;
	/** `mfa.mode`: under `required` a factor that does not count completes no login for a subject with no counting factor it can use. */
	readonly mode: MfaRequirementMode;
	/** Where a factor's codes are mailed; none wired, a factor that asks for one is an outage. */
	readonly mailSender?: MailSender;
	/** The enrollment witness a verified counting factor reconciles. */
	readonly witness: MfaEnrollmentWitness;
	/** The subject's records as read, the witness's reconciliation mark, and an enrollment's writes under the subject's lease (`factorSet.mts`). */
	readonly factorSet: MfaFactorSet;
	/** `mfa.transactionTtlSeconds`: how long an `enroll` transaction lives. */
	readonly transactionTtlSeconds: number;
	/** `mfa.maxFactorsPerSubject`. */
	readonly maxFactorsPerSubject: number;
	/** `mfa.enrollment.requireEmailProof`: the gate of a login reopened for a first binding. */
	readonly requireEmailProof: RequireEmailProof;
	/** `mfa.manage.maxAgeSeconds`: how long the account-email proof given in a session stands. */
	readonly sessionProofSeconds: number;
	/** How long a subject's first-binding mark stands, in milliseconds (`firstBindingMarkLifetimeMs`). */
	readonly firstBindingMarkMs: number;
	/** The subjects' sessions boundary a login's transaction is held to; none wired, none is read. */
	readonly subjectRevocation?: Pick<SubjectRevocation, "revokedBefore">;
	/** Whether the session store can record a second factor verified in a session (`supportsSecondFactorUpdate`). */
	readonly stepUpRecordable: boolean;
	/** The clock, in epoch milliseconds. Defaults to `Date.now`. */
	readonly now?: () => number;
}

/** Whether `value` is an object `res.json` answers as the factor built it: a plain object. */
const isPlainObject = (value: unknown): value is object => {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
	const prototype = Object.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
};

/** The coordinator over `options` (see this file's header). */
export function createMfaCoordinator(options: MfaCoordinatorOptions): MfaCoordinator {
	const {
		factors,
		factorStore,
		transactions,
		sealing,
		maxAttemptsPerTransaction,
		lock,
		mode,
		mailSender,
		witness,
		factorSet,
		transactionTtlSeconds,
		maxFactorsPerSubject,
		requireEmailProof,
		sessionProofSeconds,
		firstBindingMarkMs,
		subjectRevocation,
		stepUpRecordable,
	} = options;
	const now = options.now ?? (() => Date.now());

	/**
	 * Whether `tx`, a login's, was authenticated at or before its subject's
	 * sessions boundary, the revocation skew allowed — a login without a
	 * continuation is, under any boundary; a boundary that cannot be read, or
	 * a time that cannot be compared, is the boundary's outage.
	 */
	const pastSessionsBoundary = async (tx: MfaTransaction): Promise<boolean | MfaStoreOutage> => {
		if (subjectRevocation === undefined) return false;
		try {
			const boundary: unknown = await subjectRevocation.revokedBefore(tx.subject);
			if (boundary === null) return false;
			if (!(boundary instanceof Date)) {
				throw new TypeError("the sessions boundary is neither a date nor null");
			}
			// A login transaction without a continuation cannot show it began after the boundary.
			const authTimeMs = tx.continuation?.primary.authTimeMs;
			return (
				authTimeMs === undefined ||
				coveredByRevocationBoundary(
					new Date(authTimeMs),
					boundary,
					DEFAULT_SUBJECT_REVOCATION_SKEW_MS,
				)
			);
		} catch (cause) {
			return outage("revocation_boundary", "revokedBefore", cause);
		}
	};

	/**
	 * The transaction `call` names, bound to its binding: a login's, held to
	 * its subject's sessions boundary, or an `enroll` or `step_up` one
	 * recording the `sid` and subject of the session the call was admitted
	 * in; `null` when there is none to use.
	 */
	const bound = async (
		call: MfaCeremonyCall,
	): Promise<MfaTransaction | null | Revoked | MfaStoreOutage> => {
		const tx = await boundRead(call);
		if (tx === null || "outcome" in tx) return tx;
		if (tx.purpose === "login") {
			const past = await pastSessionsBoundary(tx);
			if (past === false) return tx;
			return past === true ? { outcome: "revoked", subject: tx.subject } : past;
		}
		return inSession(tx, call);
	};

	/** An `enroll` or `step_up` transaction of the session `call` was admitted in — its `sid` and subject — else none. */
	const inSession = (tx: MfaTransaction, call: MfaCeremonyCall): MfaTransaction | null => {
		const session = call.session;
		return (tx.purpose === "enroll" || tx.purpose === "step_up") &&
			session !== undefined &&
			tx.sid === session.sid &&
			tx.subject === session.subject
			? tx
			: null;
	};

	/** The transaction `call` names, bound to its binding, whatever its purpose; `null` for none. */
	const boundRead = async (
		call: MfaCeremonyCall,
	): Promise<MfaTransaction | null | MfaStoreOutage> => {
		const id = call.transactionId;
		if (id === undefined || !TRANSACTION_ID.test(id)) return null;
		let tx: MfaTransaction | null;
		try {
			tx = await getBoundMfaTransaction(transactions, id, call.binding);
		} catch (cause) {
			return outage("mfa_transaction", "get", cause);
		}
		return tx;
	};

	/** Every record of `subject`, oldest first; an outage is never "none". */
	const recordsOf = async (subject: string): Promise<MfaFactorRecord[] | MfaStoreOutage> => {
		try {
			return await factorSet.list(subject);
		} catch (cause) {
			return outage("mfa_factor", "list", cause);
		}
	};

	/** The record `factorId` names among `records`, when an installed factor verifies its kind. */
	const named = (
		records: readonly MfaFactorRecord[],
		factorId: unknown,
	): { readonly record: MfaFactorRecord; readonly factor: MfaFactor } | undefined => {
		if (typeof factorId !== "string") return undefined;
		const record = records.find((candidate) => candidate.id === factorId);
		const factor = record === undefined ? undefined : factors.get(record.kind);
		return record === undefined || factor === undefined ? undefined : { record, factor };
	};

	/** Whether `subject` holds a usable record (`factorState.mts`) — one that counts, when `options.counting` asks it. */
	const holdsUsable = (
		subject: string,
		records: readonly MfaFactorRecord[],
		options: { readonly counting: boolean },
	): boolean => holdsUsableRecord({ factors, sealing }, subject, records, options);

	/**
	 * `subject`'s recovery-set floor, for a verification of `factor` that is a
	 * recovery-code factor; `undefined` for any other, which reads none.
	 */
	const recoverySetFloorFor = async (
		subject: string,
		factor: MfaFactor,
	): Promise<number | undefined | MfaStoreOutage> => {
		if (!isRecoveryCodeFactor(factor)) return undefined;
		let floor: number | undefined;
		try {
			floor = readMfaSubjectCount(await transactions.recoverySetFloor(subject));
		} catch (cause) {
			return outage("mfa_transaction", "recoverySetFloor", cause);
		}
		return floor ?? outage("mfa_transaction", "recoverySetFloor", OUTSIDE_CONTRACT);
	};

	/**
	 * The named record and every record of its kind, opened for `subject`: the
	 * named one must open, and pass the recovery-code rule (`recoverySetRefusal`)
	 * under `floor`, the subject's recovery-set floor when one was read — a
	 * set below it is `retired`, a digest whose key left the ring unreadable
	 * naming that key; another that does not open is left out.
	 */
	const openKind = (
		subject: string,
		record: MfaFactorRecord,
		records: readonly MfaFactorRecord[],
		floor: number | undefined = undefined,
	):
		| { readonly named: MfaEnrolledFactor; readonly all: readonly MfaEnrolledFactor[] }
		| { readonly outcome: "retired" }
		| MfaFactorUnreadable => {
		const open = (candidate: MfaFactorRecord) =>
			sealing.openFactorData({ subject, id: candidate.id, kind: candidate.kind }, candidate.data);
		const enrolled = (candidate: MfaFactorRecord, data: MfaEnrolledFactor["data"]) => ({
			id: candidate.id,
			label: candidate.label,
			createdAt: candidate.createdAt,
			lastUsedAt: candidate.lastUsedAt,
			data,
		});
		const opened = open(record);
		if (opened.state !== "ok") {
			return {
				outcome: "unreadable",
				kind: record.kind,
				factorId: record.id,
				state: opened.state,
				...(opened.state === "key_unavailable" ? { keyId: opened.keyId } : {}),
			};
		}
		const factor = factors.get(record.kind);
		const refusal =
			factor === undefined || floor === undefined
				? undefined
				: recoverySetRefusal(factor, opened.value, { floor, holdsKey: sealing.holdsKey });
		if (refusal?.reason === "retired") return { outcome: "retired" };
		if (refusal?.reason === "key_unavailable") {
			return {
				outcome: "unreadable",
				kind: record.kind,
				factorId: record.id,
				state: "key_unavailable",
				keyId: refusal.keyId,
			};
		}
		const self = enrolled(record, opened.value);
		const all = records
			.filter((candidate) => candidate.kind === record.kind)
			.flatMap((candidate) => {
				if (candidate === record) return [self];
				const other = open(candidate);
				return other.state === "ok" ? [enrolled(candidate, other.value)] : [];
			});
		return { named: self, all };
	};

	/**
	 * The state a verification of `factor` is handed: the pending challenge
	 * for this factor, taken — or read, for a factor that keeps it across
	 * attempts — and opened, with the digest of the address its code went to;
	 * none when there is none, it is another factor's, or it has expired. Kept
	 * state that does not open is unreadable.
	 */
	const challengeState = async (
		tx: MfaTransaction,
		factor: MfaFactor,
		record: MfaFactorRecord,
		nowMs: number,
	): Promise<
		| {
				readonly state: MfaFactorState | undefined;
				readonly addressDigest?: MfaKeyedDigest;
		  }
		| MfaStoreOutage
		| MfaFactorUnreadable
	> => {
		if (factor.challenge === undefined) return { state: undefined };
		let pending: MfaTransaction["challenge"] | null;
		if (factor.reusableChallenge === true) {
			pending = tx.challenge;
		} else {
			try {
				pending = await transactions.takeChallenge(tx.id, tx.version);
			} catch (cause) {
				return outage("mfa_transaction", "takeChallenge", cause);
			}
		}
		if (
			pending === null ||
			pending === undefined ||
			pending.factorId !== record.id ||
			pending.kind !== record.kind ||
			pending.expiresAtMs <= nowMs
		) {
			return { state: undefined };
		}
		const opened = sealing.openState(
			{ transactionId: tx.id, kind: record.kind, use: "challenge" },
			pending.state,
		);
		const kept = opened.state === "ok" ? readKeptState(opened.value) : undefined;
		if (kept !== undefined) {
			return {
				state: kept.state,
				...(kept.addressDigest === undefined ? {} : { addressDigest: kept.addressDigest }),
			};
		}
		// Kept state that does not open is an outage, never an absent challenge.
		return {
			outcome: "unreadable",
			kind: record.kind,
			factorId: record.id,
			state: "challenge",
			...(opened.state === "key_unavailable" ? { keyId: opened.keyId } : {}),
		};
	};

	/**
	 * One of `tx`'s attempts reserved, after the bound read held: the
	 * attempts left; `exhausted` past the limit, which the store answers by
	 * deleting the transaction; unknown when none was reserved.
	 */
	const reserve = async (
		tx: MfaTransaction,
	): Promise<
		| { readonly attemptsRemaining: number }
		| { readonly outcome: "exhausted" }
		| UnknownTransaction
		| MfaStoreOutage
	> => {
		let answered: unknown;
		try {
			answered = await transactions.reserveAttempt(tx.id, maxAttemptsPerTransaction);
		} catch (cause) {
			return outage("mfa_transaction", "reserveAttempt", cause);
		}
		const reservation = readMfaAttemptReservation(answered, maxAttemptsPerTransaction);
		if (reservation === undefined) {
			return outage("mfa_transaction", "reserveAttempt", OUTSIDE_CONTRACT);
		}
		if (!reservation.ok) {
			// Past the limit the store deleted the transaction; with none reserved, it was gone.
			return reservation.attempts > 0 ? { outcome: "exhausted" } : UNKNOWN_TRANSACTION;
		}
		return { attemptsRemaining: Math.max(0, maxAttemptsPerTransaction - reservation.attempts) };
	};

	/** `tx` consumed at the version read: the record as the store answered it; `spent` when another consumed it first. */
	const consume = async (
		tx: MfaTransaction,
	): Promise<MfaTransaction | { readonly outcome: "spent" } | MfaStoreOutage> => {
		let consumed: MfaTransaction | null;
		try {
			consumed = await transactions.consume(tx.id, tx.version);
		} catch (cause) {
			return outage("mfa_transaction", "consume", cause);
		}
		if (consumed === null) return { outcome: "spent" };
		if (!isConsumedMfaTransaction(consumed, tx)) {
			return outage("mfa_transaction", "consume", OUTSIDE_CONTRACT);
		}
		return consumed;
	};

	/** `patch` written at `tx`'s version: the transaction the store answered, its id and next version checked; else why not. */
	const write = async (
		tx: MfaTransaction,
		patch: MfaTransactionPatch,
	): Promise<{ readonly written: MfaTransaction } | UnknownTransaction | MfaStoreOutage> => {
		let written: unknown;
		try {
			written = await transactions.update(tx.id, tx.version, patch);
		} catch (cause) {
			return outage("mfa_transaction", "update", cause);
		}
		if (written === null) return UNKNOWN_TRANSACTION;
		if (!isWrittenAt(written, tx)) return outage("mfa_transaction", "update", OUTSIDE_CONTRACT);
		return { written: written as MfaTransaction };
	};

	/**
	 * `subject`'s first-binding mark noted, standing its lifetime; the outage
	 * otherwise. Dated by the clock read just before the note, not the
	 * request's start: a request that stalled must not date the mark early.
	 */
	const noteFirstBinding = async (subject: string): Promise<MfaStoreOutage | undefined> => {
		const atMs = now();
		try {
			await transactions.noteFirstBinding(subject, atMs, atMs + firstBindingMarkMs);
			return undefined;
		} catch (cause) {
			return outage("mfa_transaction", "noteFirstBinding", cause);
		}
	};

	const kit: MfaCeremonyKit = {
		factors,
		factorStore,
		sealing,
		mailSender,
		witness,
		factorSet,
		now,
		maxFactorsPerSubject,
		requireEmailProof,
		bound,
		openEnrollment: async (call, session, shape) => {
			try {
				return await openEnrollTransaction(transactions, {
					sessionId: call.binding.id,
					sid: session.sid,
					subject: session.subject,
					enrollment: shape.enrollment,
					emailProof: shape.emailProof,
					nowMs: now(),
					ttlSeconds: transactionTtlSeconds,
				});
			} catch (cause) {
				return outage("mfa_transaction", "create", cause);
			}
		},
		openStepUp: async (call, session, acrValues) => {
			try {
				return await openStepUpTransaction(transactions, {
					sessionId: call.binding.id,
					sid: session.sid,
					subject: session.subject,
					acrValues,
					nowMs: now(),
					ttlSeconds: transactionTtlSeconds,
				});
			} catch (cause) {
				return outage("mfa_transaction", "create", cause);
			}
		},
		stepUpRecordable,
		holdsUsable,
		openLoginBinding: async (binding, continuation, shape) => {
			try {
				return await openLoginBinding(transactions, {
					binding,
					continuation,
					...shape,
					nowMs: now(),
					ttlSeconds: transactionTtlSeconds,
				});
			} catch (cause) {
				return outage("mfa_transaction", "create", cause);
			}
		},
		provedInSession: async (subject, sid) => {
			const nowMs = now();
			let answer: unknown;
			try {
				answer = await transactions.sessionEmailProofAt(subject, sid, nowMs);
			} catch (cause) {
				return outage("mfa_transaction", "sessionEmailProofAt", cause);
			}
			const proved = readSessionEmailProof(answer, nowMs);
			if (proved === undefined) {
				return outage("mfa_transaction", "sessionEmailProofAt", OUTSIDE_CONTRACT);
			}
			// One given longer ago than its window and the clock skew is none, whatever the store answered.
			return (
				proved !== null && proved >= nowMs - sessionProofSeconds * 1000 - DEFAULT_CLOCK_SKEW_MS
			);
		},
		recordSessionProof: async (subject, sid, provedAtMs) => {
			try {
				await transactions.recordSessionEmailProof(
					subject,
					sid,
					provedAtMs,
					provedAtMs + sessionProofSeconds * 1000,
				);
				return undefined;
			} catch (cause) {
				return outage("mfa_transaction", "recordSessionEmailProof", cause);
			}
		},
		boundInSession: async (call) => {
			const tx = await boundRead(call);
			return tx === null || "outcome" in tx ? tx : inSession(tx, call);
		},
		firstBindingDistrust: async (subject, authTimeMs) => {
			const nowMs = now();
			let mark: number | null;
			try {
				mark = readFirstBindingMark(await transactions.firstBindingAt(subject, nowMs), nowMs);
			} catch (cause) {
				return outage("mfa_transaction", "firstBindingAt", cause);
			}
			return mark !== null && distrustedByFirstBinding(authTimeMs, mark)
				? ({
						outcome: "first_binding_distrusted",
						subject,
						retryAfterMs: firstBindingRetryAfterMs(mark, nowMs),
					} satisfies MfaFirstBindingDistrusted)
				: undefined;
		},
		noteFirstBinding,
		reconcileWitness: async (subject, started) => {
			// A directory that cannot write the witness leaves no session stale: no mark is due.
			if (!witness.writable)
				return {
					witness: await factorSet.markEnrolled(started, subject),
					firstBindingUnnoted: undefined,
				};
			const unnoted = await noteFirstBinding(subject);
			return unnoted === undefined
				? {
						witness: await factorSet.markEnrolled(started, subject),
						firstBindingUnnoted: undefined,
					}
				: { witness: undefined, firstBindingUnnoted: unnoted };
		},
		recordsOf,
		reserve,
		consume,
		write,
		clear: async (written, field) => !("outcome" in (await write(written, { [field]: null }))),
		emailProofRequired: async (subject) => {
			let flagged: unknown;
			try {
				flagged = await transactions.emailProofRequiredAtNextBinding(subject);
			} catch (cause) {
				return outage("mfa_transaction", "emailProofRequiredAtNextBinding", cause);
			}
			return typeof flagged === "boolean"
				? flagged
				: outage("mfa_transaction", "emailProofRequiredAtNextBinding", OUTSIDE_CONTRACT);
		},
		consumeEmailProofRequirement: async (subject) => {
			try {
				await transactions.consumeEmailProofRequirement(subject);
				return undefined;
			} catch (failed) {
				return { failed };
			}
		},
		answerable: isPlainObject,
		declaredAmr: (factor, data) => {
			try {
				const amr: unknown = factor.amrFor(data);
				return declaresEach(factor, amr) ? amr : undefined;
			} catch {
				return undefined;
			}
		},
	};
	const enrollment = createMfaEnrollment(kit);
	const proof = createAccountEmailProof(kit);
	const stepUp = createMfaStepUp(kit);
	const reopen = createLoginReopen(kit);

	return {
		async describe(call) {
			const nowMs = now();
			const tx = await bound(call);
			if (tx === null) return UNKNOWN_TRANSACTION;
			if ("outcome" in tx) return tx;
			// An enroll transaction verifies the account-email proof alone: it lists no factor.
			const records = tx.purpose === "enroll" ? [] : await recordsOf(tx.subject);
			if ("outcome" in records) return records;
			const listed = records.flatMap((record) => {
				const read = readFactorRecord({ factors, sealing }, tx.subject, record);
				if (!isOffered(read)) return [];
				let hint: unknown;
				if (read.state === "usable") {
					try {
						hint = read.factor.describe(read.data).hint;
					} catch {
						hint = undefined;
					}
				}
				return [
					{
						id: record.id,
						kind: record.kind,
						...(typeof record.label === "string" ? { label: record.label } : {}),
						...(typeof hint === "string" ? { hint } : {}),
					},
				];
			});
			return {
				outcome: "described",
				view: {
					purpose: tx.purpose,
					factors: listed,
					enrollment: tx.enrollment,
					emailProof: tx.emailProof === "required",
					expiresIn: Math.max(1, Math.ceil((tx.expiresAtMs - nowMs) / 1000)),
					attemptsRemaining: Math.max(0, maxAttemptsPerTransaction - tx.attempts),
				},
			};
		},

		async challenge(call) {
			const nowMs = now();
			const tx = await bound(call);
			if (tx === null) return UNKNOWN_TRANSACTION;
			if ("outcome" in tx) return tx;
			if (tx.purpose === "enroll") {
				return call.factorId === ACCOUNT_EMAIL_FACTOR_ID
					? proof.challenge(tx, call.session?.user)
					: UNKNOWN_FACTOR;
			}
			if (call.factorId === ACCOUNT_EMAIL_FACTOR_ID) {
				return proof.challenge(tx, tx.continuation?.primary.user);
			}
			const records = await recordsOf(tx.subject);
			if ("outcome" in records) return records;
			const found = named(records, call.factorId);
			if (found === undefined) return UNKNOWN_FACTOR;
			const { record, factor } = found;
			if (factor.challenge === undefined) return { outcome: "none" };
			const opened = openKind(tx.subject, record, records);
			// No floor is read here: no set is retired.
			if ("outcome" in opened) return opened.outcome === "retired" ? UNKNOWN_FACTOR : opened;
			const failed = (cause: unknown): MfaChallengeOutcome => ({
				outcome: "challenge_failed",
				kind: record.kind,
				factorId: record.id,
				cause,
			});
			let issued: Awaited<ReturnType<NonNullable<MfaFactor["challenge"]>>>;
			try {
				issued = await factor.challenge({
					subject: tx.subject,
					transactionId: tx.id,
					nowMs,
					request: call.request,
					digests: sealing.digestsFor(record.kind),
					factor: opened.named,
					factors: opened.all,
				});
				if (!isPlainObject(issued?.response)) {
					throw new TypeError("the factor's challenge answered a response that is not an object");
				}
			} catch (cause) {
				return failed(cause);
			}
			const about: MfaCeremonySubject = {
				subject: tx.subject,
				kind: record.kind,
				purpose: tx.purpose,
			};
			const sent: MfaChallengeOutcome = {
				outcome: "sent",
				response: issued.response as object,
				...about,
			};
			/** The pending challenge, sealed with the address's digest when a code went out, living until `expiresAtMs`. */
			const pending = (addressDigest: MfaKeyedDigest | undefined, expiresAtMs: number) => ({
				factorId: record.id,
				kind: record.kind,
				state: sealing.sealState(
					{ transactionId: tx.id, kind: record.kind, use: "challenge" },
					keptState({ state: issued.state, addressDigest }),
				),
				expiresAtMs,
			});

			if (issued.mail !== undefined) {
				const mailed = await sendMfaMail<MfaChallengeOutcome>({
					sender: mailSender,
					mail: issued.mail,
					purpose: "login_code",
					subject: tx.subject,
					// A step-up's code goes to the session's own address; the bound read held the session to it.
					address:
						tx.purpose === "step_up"
							? call.session?.user.email
							: tx.continuation?.primary.user.email,
					nowMs,
					notAfterMs: tx.expiresAtMs,
					digests: sealing.digestsFor(record.kind),
					keep: async (addressDigest, expiresAtMs) => {
						let challenge: ReturnType<typeof pending>;
						try {
							challenge = pending(addressDigest, expiresAtMs);
						} catch (cause) {
							return { kept: false, refusal: failed(cause) };
						}
						const kept = await write(tx, { challenge });
						if ("outcome" in kept) return { kept: false, refusal: kept };
						return { kept: true, clear: () => kit.clear(kept.written, "challenge") };
					},
				});
				switch (mailed.outcome) {
					case "sent":
						// Where the code went and how long it lives, as kept: never the factor's to say.
						return {
							...sent,
							response: { ...sent.response, ...mailedAnswer(mailed, nowMs) },
						};
					case "not_kept":
						return mailed.refusal;
					case "address_mismatch":
						return { outcome: "address_mismatch", ...about };
					case "key_unavailable":
						return {
							outcome: "unreadable",
							kind: record.kind,
							factorId: record.id,
							state: "key_unavailable",
							keyId: mailed.keyId,
						};
					case "refused_at_limit":
					case "no_sender":
					case "unavailable":
						return mailRefusalOf(mailed, "login_code", record.kind);
					case "malformed":
					case "no_address":
						return failed(
							new TypeError("the factor's challenge asked for a mail that is not a login code"),
						);
					default:
						return mailed satisfies never;
				}
			}

			// The challenge lives no longer than its transaction; one without state
			// clears a pending one, which answered an earlier challenge.
			let patch: MfaTransactionPatch | undefined;
			try {
				patch =
					issued.state !== undefined
						? { challenge: pending(undefined, tx.expiresAtMs) }
						: tx.challenge !== undefined
							? { challenge: null }
							: undefined;
			} catch (cause) {
				return failed(cause);
			}
			if (patch !== undefined) {
				const written = await write(tx, patch);
				if ("outcome" in written) return written;
			}
			return sent;
		},

		async verify(call) {
			const nowMs = now();
			const tx = await bound(call);
			if (tx === null) return UNKNOWN_TRANSACTION;
			if ("outcome" in tx) return tx;
			if (call.factorId === ACCOUNT_EMAIL_FACTOR_ID) return proof.verify(call, tx);
			// A transaction opened for a binding binds; it verifies no other factor.
			if (tx.purpose === "enroll" || tx.enrollment !== "none") return UNKNOWN_FACTOR;
			let records = await recordsOf(tx.subject);
			if ("outcome" in records) return records;
			const found = named(records, call.factorId);
			if (found === undefined) return UNKNOWN_FACTOR;
			const { factor } = found;
			let { record } = found;
			const about: MfaCeremonySubject = {
				subject: tx.subject,
				kind: record.kind,
				purpose: tx.purpose,
			};
			const refused = (
				reason: MfaRefusalReason,
				attemptsRemaining: number,
				concerns: RefusalConcerns = {},
			): MfaVerifyOutcome => ({
				outcome: "refused",
				reason,
				attemptsRemaining,
				...concerns,
				...about,
			});
			const unreadable = (cause: unknown): MfaFactorUnreadable => ({
				outcome: "unreadable",
				kind: record.kind,
				factorId: record.id,
				state: "verification",
				cause,
			});

			// The factor must open, and a recovery-code set pass its rule under the
			// subject's recovery-set floor, before an attempt is spent on it: an
			// outage spends nothing, and a retired set is refused unchecked.
			const floor = await recoverySetFloorFor(tx.subject, factor);
			if (typeof floor === "object") return floor;
			const retired = () =>
				refused("invalid", Math.max(0, maxAttemptsPerTransaction - tx.attempts));
			let opened = openKind(tx.subject, record, records, floor);
			if ("outcome" in opened) return opened.outcome === "retired" ? retired() : opened;

			/**
			 * F3: under `required`, a login's factor that does not count completes
			 * no login for a subject left with no counting factor it can use over
			 * `current`; what the login reopens for, or why not, is settled before
			 * anything more is spent (`reopen.mts`).
			 */
			const planOver = (current: readonly MfaFactorRecord[]) =>
				mode === "required" &&
				tx.purpose === "login" &&
				!factor.counting &&
				!holdsUsable(tx.subject, current, { counting: true })
					? reopen.plan(tx, current)
					: undefined;
			let reopening = await planOver(records);
			if (reopening !== undefined && "outcome" in reopening) {
				return reopening.outcome === "unavailable" ? reopening : { ...reopening, ...about };
			}

			// A reconciliation's mark, where one could follow, is held to the subject's generation as it was before the proof is checked.
			const markDue =
				tx.purpose === "step_up"
					? reconcilesSession(factor, call.session?.witness)
					: reconciles(factor, tx.continuation?.primary.user);
			const started = markDue ? await factorSet.begin(tx.subject, "mark") : undefined;

			const reserved = await reserve(tx);
			if ("outcome" in reserved) {
				return reserved.outcome === "exhausted" ? refused("exhausted", 0) : reserved;
			}
			const { attemptsRemaining } = reserved;

			const entered = await lock.enter(tx.subject, factor, nowMs);
			if (entered.outcome === "unavailable") return entered;
			if (entered.outcome === "locked") {
				const { outcome: _, ...hold } = entered;
				return {
					outcome: "locked",
					...hold,
					exemptKinds: exemptKindsHeld({ records, factors }),
					attemptsRemaining,
					binding: record.binding,
					...about,
				};
			}
			// How the subject's attempt settles: a failure until the proof verifies.
			let settled: "failure" | "void" | "success" = "failure";
			try {
				const pending = await challengeState(tx, factor, record, nowMs);
				if ("outcome" in pending) return pending;

				/**
				 * The proof checked against the factor as `opened` holds it, and what
				 * the verification adds: non-empty, and only what the factor declares.
				 */
				const check = async (): Promise<
					| {
							readonly verified: MfaEnrolledFactor;
							readonly next: MfaEnrolledFactor["data"];
							/** What the verification adds: the factor's values, as it declares them. */
							readonly added: readonly string[];
					  }
					| ({ readonly reason: MfaRefusalReason } & RefusalConcerns)
					| MfaFactorUnreadable
				> => {
					if ("outcome" in opened) {
						return opened.outcome === "retired" ? { reason: "invalid" } : opened;
					}
					const { named: self, all } = opened;
					let result: MfaVerification;
					try {
						result = await factor.verify({
							subject: tx.subject,
							transactionId: tx.id,
							nowMs,
							request: call.request,
							digests: sealing.digestsFor(record.kind),
							factor: self,
							factors: all,
							state: pending.state,
							...(pending.addressDigest === undefined
								? {}
								: { addressDigest: pending.addressDigest }),
							proof: call.proof,
						});
					} catch (cause) {
						return unreadable(cause);
					}
					if (!result.ok) {
						if (result.factorId === undefined) return { reason: result.reason };
						const concerned = all.find((candidate) => candidate.id === result.factorId);
						return concerned === undefined
							? { reason: result.reason, factorIdDropped: true }
							: { reason: result.reason, factorId: concerned.id };
					}
					const verified = all.find((candidate) => candidate.id === result.factorId);
					if (verified === undefined) {
						return unreadable(
							new TypeError("the factor verified a factor id the subject does not hold"),
						);
					}
					const next = result.next ?? verified.data;
					let amr: unknown;
					try {
						amr = factor.amrFor(next);
					} catch (cause) {
						return unreadable(cause);
					}
					if (!declaresEach(factor, amr)) {
						return unreadable(
							new TypeError("the factor's amrFor answered values it does not declare"),
						);
					}
					return { verified, next, added: amr };
				};

				let checked = await check();
				if ("outcome" in checked) return checked;
				if ("reason" in checked) {
					const { reason, ...concerns } = checked;
					return refused(reason, attemptsRemaining, concerns);
				}
				// Right: from here a proof that completes nothing never counts.
				settled = "void";

				// Consumed before the factor moves on: a lost race spends the
				// transaction, never the factor's state.
				const consumed = await consume(tx);
				if ("outcome" in consumed) return consumed;

				for (let round = 1; ; round++) {
					const { verified, next } = checked;
					const target = records.find((candidate) => candidate.id === verified.id);
					if (target === undefined) return refused("invalid", 0);
					let data: string;
					try {
						// Re-sealed under the ring's first key at every use.
						data = sealing.sealFactorData(
							{ subject: tx.subject, id: target.id, kind: target.kind },
							next,
						);
					} catch (cause) {
						return unreadable(cause);
					}
					let written: unknown;
					try {
						written = await factorStore.update(tx.subject, target.id, target.version, {
							data,
							label: target.label,
							lastUsedAt: new Date(nowMs),
						});
					} catch (cause) {
						return outage("mfa_factor", "update", cause);
					}
					if (written !== null) {
						if (
							!isMfaFactorUpdateWritten(written, {
								subject: tx.subject,
								id: target.id,
								expectedVersion: target.version,
								next: { data },
							})
						) {
							return outage("mfa_factor", "update", OUTSIDE_CONTRACT);
						}
						settled = "success";
						break;
					}
					if (round === ADVANCE_ROUNDS) {
						return outage(
							"mfa_factor",
							"update",
							new Error(`the factor's compare-and-set was lost ${ADVANCE_ROUNDS} times`),
						);
					}
					// Lost: read the factor again and check the proof again against it.
					records = await recordsOf(tx.subject);
					if ("outcome" in records) return records;
					const again = records.find((candidate) => candidate.id === record.id);
					if (again === undefined) return refused("invalid", 0);
					record = again;
					opened = openKind(tx.subject, record, records, floor);
					// A set retired since is refused as the proof would be: the transaction is spent.
					if ("outcome" in opened) {
						return opened.outcome === "retired" ? refused("invalid", 0) : opened;
					}
					checked = await check();
					if ("outcome" in checked) return checked;
					if ("reason" in checked) {
						const { reason, ...concerns } = checked;
						return refused(reason, 0, concerns);
					}
					// The records moved: what the proof completes is settled again over them.
					reopening = await planOver(records);
					if (reopening !== undefined && "outcome" in reopening) {
						return reopening.outcome === "unavailable" ? reopening : { ...reopening, ...about };
					}
				}

				// The floor read again once the spend is written: a regeneration that
				// raised it meanwhile has retired this set, and its answer may be out.
				if (floor !== undefined) {
					const again = await recoverySetFloorFor(tx.subject, factor);
					if (typeof again === "object") {
						settled = "void";
						return again;
					}
					const retiredSince = recoverySetRefusal(factor, checked.next, {
						floor: again ?? floor,
						holdsKey: sealing.holdsKey,
					});
					if (retiredSince?.reason === "retired") {
						settled = "void";
						return refused("invalid", 0);
					}
				}

				if (reopening !== undefined) {
					const recoveryCodesRemaining = recoveryCodesLeft(factor, checked.next);
					const answer = await reopen.open(consumed, reopening);
					return "outcome" in answer
						? { outcome: "binding_not_reopened", outage: answer, recoveryCodesRemaining, ...about }
						: { outcome: "binding_reopened", answer, recoveryCodesRemaining, ...about };
				}

				// D12: a counting factor verified for a `User` that does not say it
				// enrolled — the login's, or the one the session recorded — marks it,
				// so a mark that failed heals here.
				const reconciled = (
					tx.purpose === "step_up"
						? reconcilesSession(factor, call.session?.witness)
						: reconciles(factor, consumed.continuation?.primary.user)
				)
					? await kit.reconcileWitness(tx.subject, started)
					: undefined;
				const verified = {
					adds: {
						amr: [...new Set([...checked.added, ...(factor.addsMfa ? [MFA_AMR] : [])])],
						mfaAt: new Date(nowMs),
					},
					witness: reconciled?.witness,
					firstBindingUnnoted: reconciled?.firstBindingUnnoted,
					recoveryCodesRemaining: recoveryCodesLeft(factor, checked.next),
					...about,
				};
				// A step-up's session is escalated by the caller; a login is resumed by it.
				if (tx.purpose === "step_up") {
					// The bound read held its sid to the session's: one without is none to escalate.
					return tx.sid === undefined
						? UNKNOWN_TRANSACTION
						: { outcome: "stepped_up", sid: tx.sid, ...verified };
				}
				return { outcome: "verified", continuation: consumed.continuation, ...verified };
			} finally {
				await entered.settle(settled);
			}
		},

		beginEnrollment: (call) => enrollment.begin(call),
		completeEnrollment: (call) => enrollment.complete(call),

		stepUp: (call) => stepUp.open(call),
	};
}
