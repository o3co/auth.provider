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
 *   spent, expired, neither a login's nor an `enroll` one of the session the
 *   call was admitted in — its `sid` and subject — reads as unknown, and
 *   spends nothing. An `enroll` transaction verifies the account-email proof
 *   alone.
 * - The step-up of a subject with no record that may count opens, or uses,
 *   an `enroll` transaction owing the account-email proof (`stepUp.mts`); a verified proof
 *   on one is recorded for its session alone, standing
 *   `mfa.manage.maxAgeSeconds`.
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
 * - A verified counting factor marks the enrollment witness of a login whose
 *   `User` does not carry it (D12); a mark that fails never fails the login.
 * - A factor is handed its records opened and digests under the ring; it
 *   never sees a key, a store, a transaction or the mail sender. A code it
 *   asks to be mailed goes through `sendMfaMail` (`mail.mts`), to the
 *   login's address, and the digest of that address is kept with the pending
 *   challenge and handed back to the verification. The page is answered the
 *   factor's response with where the code went, masked (`sent_to`), and how
 *   long it lives (`expires_in`), as kept.
 * - A refusal carries the factor id the factor named only when it is one of
 *   the subject's factors of the kind verified: nothing else reaches the audit.
 *   Another is dropped and flagged, never quoted.
 */

import {
	DEFAULT_CLOCK_SKEW_MS,
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
	readSessionEmailProof,
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
	type MfaRefusalReason,
	type MfaStepUpOutcome,
	type MfaStoreOutage,
	type MfaVerifyOutcome,
	OUTSIDE_CONTRACT,
	outage,
	UNKNOWN_FACTOR,
	UNKNOWN_TRANSACTION,
	type UnknownTransaction,
} from "./ceremony.mjs";
import { createMfaEnrollment } from "./enrollment.mjs";
import { exemptKindsHeld, type MfaSubjectLock } from "./lock.mjs";
import { keptState, mailRefusalOf, maskMailAddress, readKeptState, sendMfaMail } from "./mail.mjs";
import { ACCOUNT_EMAIL_FACTOR_ID, createAccountEmailProof } from "./proof.mjs";
import { recoveryCodesLeft } from "./recovery/factor.mjs";
import type { MfaRequirementMode } from "./requirement.mjs";
import type { MfaSealing } from "./sealing.mjs";
import { createMfaStepUp } from "./stepUp.mjs";
import { openEnrollTransaction } from "./transactions.mjs";
import { type MfaEnrollmentWitness, reconciles } from "./witness.mjs";

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
	 * The step-up of `call.session`'s subject when it holds no record that may
	 * count: the `enroll` transaction the account-email proof is owed on — the
	 * one `call` names, when it is that session's first binding's and its
	 * proof is not met, else a new one.
	 */
	stepUp(call: MfaCeremonyCall): Promise<MfaStepUpOutcome>;
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
	/** `mfa.transactionTtlSeconds`: how long an `enroll` transaction lives. */
	readonly transactionTtlSeconds: number;
	/** `mfa.maxFactorsPerSubject`. */
	readonly maxFactorsPerSubject: number;
	/** `mfa.manage.maxAgeSeconds`: how long the account-email proof given in a session stands. */
	readonly sessionProofSeconds: number;
	/** The clock, in epoch milliseconds. Defaults to `Date.now`. */
	readonly now?: () => number;
}

/** Whether `value` is an object `res.json` answers as the factor built it: a plain object. */
const isPlainObject = (value: unknown): value is object => {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
	const prototype = Object.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
};

/** The subject's records, oldest first: what the page lists and a request names. */
const byAge = (a: MfaFactorRecord, b: MfaFactorRecord): number =>
	a.createdAt.getTime() - b.createdAt.getTime() || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

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
		transactionTtlSeconds,
		maxFactorsPerSubject,
		sessionProofSeconds,
	} = options;
	const now = options.now ?? (() => Date.now());

	/**
	 * The transaction `call` names, bound to its binding: a login's, or an
	 * `enroll` one recording the `sid` and subject of the session the call was
	 * admitted in; `null` when there is none to use.
	 */
	const bound = async (call: MfaCeremonyCall): Promise<MfaTransaction | null | MfaStoreOutage> => {
		const id = call.transactionId;
		if (id === undefined || !TRANSACTION_ID.test(id)) return null;
		let tx: MfaTransaction | null;
		try {
			tx = await getBoundMfaTransaction(transactions, id, call.binding);
		} catch (cause) {
			return outage("mfa_transaction", "get", cause);
		}
		if (tx === null) return null;
		if (tx.purpose === "login") return tx;
		const session = call.session;
		return tx.purpose === "enroll" &&
			session !== undefined &&
			tx.sid === session.sid &&
			tx.subject === session.subject
			? tx
			: null;
	};

	/** Every record of `subject`, oldest first; an outage is never "none". */
	const recordsOf = async (subject: string): Promise<MfaFactorRecord[] | MfaStoreOutage> => {
		try {
			const records: unknown = await factorStore.list(subject);
			if (!Array.isArray(records)) {
				throw new TypeError("MfaFactorStore.list answered something that is not a list");
			}
			return [...(records as MfaFactorRecord[])].sort(byAge);
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

	/** Whether `subject` holds a factor that counts, of an installed kind, whose data opens. */
	const holdsUsableCounting = (subject: string, records: readonly MfaFactorRecord[]): boolean =>
		records.some(
			(candidate) =>
				factors.get(candidate.kind)?.counting === true &&
				sealing.openFactorData({ subject, id: candidate.id, kind: candidate.kind }, candidate.data)
					.state === "ok",
		);

	/**
	 * The named record and every record of its kind, opened for `subject`: the
	 * named one must open; another that does not is left out.
	 */
	const openKind = (
		subject: string,
		record: MfaFactorRecord,
		records: readonly MfaFactorRecord[],
	):
		| { readonly named: MfaEnrolledFactor; readonly all: readonly MfaEnrolledFactor[] }
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

	const kit: MfaCeremonyKit = {
		factors,
		factorStore,
		sealing,
		mailSender,
		witness,
		now,
		maxFactorsPerSubject,
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
				const factor = factors.get(record.kind);
				if (factor === undefined) return [];
				const opened = sealing.openFactorData(
					{ subject: tx.subject, id: record.id, kind: record.kind },
					record.data,
				);
				let hint: unknown;
				if (opened.state === "ok") {
					try {
						hint = factor.describe(opened.value).hint;
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
			if ("outcome" in opened) return opened;
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
					address: tx.continuation?.primary.user.email,
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
							response: {
								...sent.response,
								sent_to: maskMailAddress(mailed.to),
								expires_in: Math.max(1, Math.ceil((mailed.expiresAtMs - nowMs) / 1000)),
							},
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
			if (tx.purpose === "enroll") return UNKNOWN_FACTOR;
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

			// The factor must open before an attempt is spent on it: an outage
			// spends nothing.
			let opened = openKind(tx.subject, record, records);
			if ("outcome" in opened) return opened;

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
					if ("outcome" in opened) return opened;
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

				// F3: under `required`, a factor that does not count completes no login
				// for a subject left with no counting factor it can use.
				if (mode === "required" && !factor.counting && !holdsUsableCounting(tx.subject, records)) {
					return { outcome: "enrollment_required", ...about };
				}

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
					opened = openKind(tx.subject, record, records);
					if ("outcome" in opened) return opened;
					checked = await check();
					if ("outcome" in checked) return checked;
					if ("reason" in checked) {
						const { reason, ...concerns } = checked;
						return refused(reason, 0, concerns);
					}
				}

				// D12: a counting factor verified for a login's `User` that does not
				// say it enrolled marks it, so a mark that failed heals here.
				const user = consumed.continuation?.primary.user;
				const marked = reconciles(factor, user) ? await witness.mark(tx.subject) : undefined;

				return {
					outcome: "verified",
					continuation: consumed.continuation,
					adds: {
						amr: [...new Set([...checked.added, ...(factor.addsMfa ? [MFA_AMR] : [])])],
						mfaAt: new Date(nowMs),
					},
					witness: marked,
					recoveryCodesRemaining: recoveryCodesLeft(factor, checked.next),
					...about,
				};
			} finally {
				await entered.settle(settled);
			}
		},

		beginEnrollment: (call) => enrollment.begin(call),
		completeEnrollment: (call) => enrollment.complete(call),

		stepUp: (call) => stepUp.open(call),
	};
}
