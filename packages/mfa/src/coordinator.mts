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
 * The coordinator: a login's second-factor ceremony over the MFA stores, the
 * key ring and the installed factors — reading the transaction, issuing a
 * factor's challenge, verifying a proof — answered as outcomes the routes map
 * to HTTP. See README, "The routes", and ADR
 * 2026-09-25-multi-factor-authentication, F1 and D8.
 *
 * - Every operation starts with the bound read (`getBoundMfaTransaction`), and
 *   after it calls only operations that carry the version it read, and
 *   `reserveAttempt` once it held. A transaction bound to anything else,
 *   spent, expired, or not a login's reads as unknown, and spends nothing.
 * - A verification reserves its attempt before the proof is checked, consumes
 *   the transaction before the factor moves on, and on a lost compare-and-set
 *   reads the factor again and checks the proof again: a code used twice at
 *   once succeeds once, and a lost race never spends a factor's state.
 * - A store that cannot answer, a factor whose data does not open, and a
 *   factor that throws are outages: never a wrong code, never "no factor".
 * - A factor is handed its records opened and digests under the ring; it
 *   never sees a key, a store or a transaction.
 */

import {
	getBoundMfaTransaction,
	isConsumedMfaTransaction,
	isMfaFactorUpdateWritten,
	MFA_AMR,
	type MfaEnrolledFactor,
	type MfaFactor,
	type MfaFactorRecord,
	type MfaFactorResolver,
	type MfaFactorState,
	type MfaFactorStore,
	type MfaTransaction,
	type MfaTransactionBinding,
	type MfaTransactionPatch,
	type MfaTransactionStore,
	type MfaVerification,
	type PrimaryContinuation,
	readMfaAttemptReservation,
} from "@o3co/auth-provider-core";
import type { MfaRequirementMode } from "./requirement.mjs";
import type { MfaSealing } from "./sealing.mjs";

/** A transaction id as the login makes one: 32 bytes, base64url. */
const TRANSACTION_ID = /^[A-Za-z0-9_-]{43}$/;

/** How many times a verification writes a factor whose compare-and-set it keeps losing. */
const ADVANCE_ROUNDS = 3;

/** Why a store's answer outside its port's promise is an outage: it is never read as a verdict. */
const OUTSIDE_CONTRACT = new TypeError("the store answered outside its port's contract");

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

/** The MFA store that could not answer. */
export type MfaStoreName = "mfa_transaction" | "mfa_factor";

/** A store that could not answer: the operation, and why. */
export interface MfaStoreOutage {
	readonly outcome: "unavailable";
	readonly store: MfaStoreName;
	readonly step: string;
	readonly cause: unknown;
}

/**
 * A factor that cannot be used as stored: its data does not open
 * (`unreadable`), or opens under a key the ring lacks (`key_unavailable`,
 * naming it), or the factor threw reading it (`verification`); or its
 * pending challenge's kept state does not open (`challenge`, naming the key
 * when it is the one missing).
 */
export interface MfaFactorUnreadable {
	readonly outcome: "unreadable";
	readonly kind: string;
	readonly factorId: string;
	readonly state: "unreadable" | "key_unavailable" | "verification" | "challenge";
	readonly keyId?: string;
	readonly cause?: unknown;
}

/** Who and what an outcome concerns, for its audit event. */
export interface MfaCeremonySubject {
	readonly subject: string;
	readonly kind: string;
	readonly purpose: MfaTransaction["purpose"];
}

/** No usable transaction: unknown, foreign, spent, expired, or not a login's. */
const UNKNOWN_TRANSACTION = Object.freeze({ outcome: "unknown_transaction" as const });
/** No factor of the subject's that an installed factor verifies, by the id named. */
const UNKNOWN_FACTOR = Object.freeze({ outcome: "unknown_factor" as const });

type UnknownTransaction = typeof UNKNOWN_TRANSACTION;
type UnknownFactor = typeof UNKNOWN_FACTOR;

/** What a transaction's reader is shown of it. */
export interface MfaTransactionView {
	readonly purpose: MfaTransaction["purpose"];
	readonly factors: readonly {
		readonly id: string;
		readonly kind: string;
		readonly label?: string;
		readonly hint?: string;
	}[];
	readonly enrollment: MfaTransaction["enrollment"];
	readonly emailProof: boolean;
	readonly expiresIn: number;
	readonly attemptsRemaining: number;
}

/** A refused proof, with what is left of the transaction's attempts. */
export type MfaRefusalReason = Extract<MfaVerification, { ok: false }>["reason"] | "exhausted";

export type MfaDescribeOutcome =
	| UnknownTransaction
	| MfaStoreOutage
	| { readonly outcome: "described"; readonly view: MfaTransactionView };

export type MfaChallengeOutcome =
	| UnknownTransaction
	| UnknownFactor
	| MfaStoreOutage
	| MfaFactorUnreadable
	| { readonly outcome: "none" }
	| ({ readonly outcome: "sent"; readonly response: object } & MfaCeremonySubject)
	| {
			readonly outcome: "challenge_failed";
			readonly kind: string;
			readonly factorId: string;
			readonly cause: unknown;
	  };

export type MfaVerifyOutcome =
	| UnknownTransaction
	| UnknownFactor
	| MfaStoreOutage
	| MfaFactorUnreadable
	| ({
			readonly outcome: "refused";
			readonly reason: MfaRefusalReason;
			readonly attemptsRemaining: number;
	  } & MfaCeremonySubject)
	/** The proof was right, and another verification consumed the transaction first. */
	| { readonly outcome: "spent" }
	/** The proof was right, but it does not count and the subject holds no counting factor it can use (F3). */
	| ({ readonly outcome: "enrollment_required" } & MfaCeremonySubject)
	| ({
			readonly outcome: "verified";
			/** What the login persisted, as the store answered it at consumption. */
			readonly continuation: PrimaryContinuation | undefined;
			/** What the verification adds to the login: the factor's `amr`, `mfa` when it adds it, and when. */
			readonly adds: { readonly amr: readonly string[]; readonly mfaAt: Date };
	  } & MfaCeremonySubject);

/** One call's request: the transaction named, the binding the browser presents, and what a factor may read of the request. */
export interface MfaCeremonyCall {
	readonly transactionId: string | undefined;
	readonly binding: MfaTransactionBinding;
	readonly request: { readonly ip?: string; readonly userAgent?: string };
}

export interface MfaCoordinator {
	describe(call: MfaCeremonyCall): Promise<MfaDescribeOutcome>;
	challenge(call: MfaCeremonyCall & { readonly factorId: unknown }): Promise<MfaChallengeOutcome>;
	verify(
		call: MfaCeremonyCall & { readonly factorId: unknown; readonly proof: unknown },
	): Promise<MfaVerifyOutcome>;
}

export interface MfaCoordinatorOptions {
	readonly factors: MfaFactorResolver;
	readonly factorStore: MfaFactorStore;
	readonly transactions: MfaTransactionStore;
	readonly sealing: MfaSealing;
	/** `mfa.maxAttemptsPerTransaction`. */
	readonly maxAttemptsPerTransaction: number;
	/** `mfa.mode`: under `required` a factor that does not count completes no login for a subject with no counting factor it can use. */
	readonly mode: MfaRequirementMode;
	/** The clock, in epoch milliseconds. Defaults to `Date.now`. */
	readonly now?: () => number;
}

const outage = (store: MfaStoreName, step: string, cause: unknown): MfaStoreOutage => ({
	outcome: "unavailable",
	store,
	step,
	cause,
});

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
	const { factors, factorStore, transactions, sealing, maxAttemptsPerTransaction, mode } = options;
	const now = options.now ?? (() => Date.now());

	/** The login transaction `call` names, bound to its binding; `null` when there is none to use. */
	const bound = async (call: MfaCeremonyCall): Promise<MfaTransaction | null | MfaStoreOutage> => {
		const id = call.transactionId;
		if (id === undefined || !TRANSACTION_ID.test(id)) return null;
		let tx: MfaTransaction | null;
		try {
			tx = await getBoundMfaTransaction(transactions, id, call.binding);
		} catch (cause) {
			return outage("mfa_transaction", "get", cause);
		}
		// This build completes a login's transaction alone.
		return tx !== null && tx.purpose === "login" ? tx : null;
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
	 * attempts — and opened; none when there is none, it is another factor's,
	 * or it has expired. Kept state that does not open is unreadable.
	 */
	const challengeState = async (
		tx: MfaTransaction,
		factor: MfaFactor,
		record: MfaFactorRecord,
		nowMs: number,
	): Promise<
		{ readonly state: MfaFactorState | undefined } | MfaStoreOutage | MfaFactorUnreadable
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
		if (opened.state === "ok") return { state: opened.value };
		// Kept state that does not open is an outage, never an absent challenge.
		return {
			outcome: "unreadable",
			kind: record.kind,
			factorId: record.id,
			state: "challenge",
			...(opened.state === "key_unavailable" ? { keyId: opened.keyId } : {}),
		};
	};

	return {
		async describe(call) {
			const nowMs = now();
			const tx = await bound(call);
			if (tx === null) return UNKNOWN_TRANSACTION;
			if ("outcome" in tx) return tx;
			const records = await recordsOf(tx.subject);
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
			let sealed: string | undefined;
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
				sealed =
					issued.state === undefined
						? undefined
						: sealing.sealState(
								{ transactionId: tx.id, kind: record.kind, use: "challenge" },
								issued.state,
							);
			} catch (cause) {
				return failed(cause);
			}
			// The challenge lives no longer than its transaction; one without state
			// clears a pending one, which answered an earlier challenge.
			const patch: MfaTransactionPatch | undefined =
				sealed !== undefined
					? {
							challenge: {
								factorId: record.id,
								kind: record.kind,
								state: sealed,
								expiresAtMs: tx.expiresAtMs,
							},
						}
					: tx.challenge !== undefined
						? { challenge: null }
						: undefined;
			if (patch !== undefined) {
				let written: unknown;
				try {
					written = await transactions.update(tx.id, tx.version, patch);
				} catch (cause) {
					return outage("mfa_transaction", "update", cause);
				}
				if (written === null) return UNKNOWN_TRANSACTION;
				if (!isWrittenAt(written, tx)) {
					return outage("mfa_transaction", "update", OUTSIDE_CONTRACT);
				}
			}
			return {
				outcome: "sent",
				response: issued.response as object,
				subject: tx.subject,
				kind: record.kind,
				purpose: tx.purpose,
			};
		},

		async verify(call) {
			const nowMs = now();
			const tx = await bound(call);
			if (tx === null) return UNKNOWN_TRANSACTION;
			if ("outcome" in tx) return tx;
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
			const refused = (reason: MfaRefusalReason, attemptsRemaining: number): MfaVerifyOutcome => ({
				outcome: "refused",
				reason,
				attemptsRemaining,
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
				return reservation.attempts > 0 ? refused("exhausted", 0) : UNKNOWN_TRANSACTION;
			}
			const attemptsRemaining = Math.max(0, maxAttemptsPerTransaction - reservation.attempts);

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
				| { readonly reason: MfaRefusalReason }
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
						proof: call.proof,
					});
				} catch (cause) {
					return unreadable(cause);
				}
				if (!result.ok) return { reason: result.reason };
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
			if ("reason" in checked) return refused(checked.reason, attemptsRemaining);

			// F3: under `required`, a factor that does not count completes no login
			// for a subject left with no counting factor it can use.
			if (mode === "required" && !factor.counting && !holdsUsableCounting(tx.subject, records)) {
				return { outcome: "enrollment_required", ...about };
			}

			// Consumed before the factor moves on: a lost race spends the
			// transaction, never the factor's state.
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
				if ("reason" in checked) return refused(checked.reason, 0);
			}

			return {
				outcome: "verified",
				continuation: consumed.continuation,
				adds: {
					amr: [...new Set([...checked.added, ...(factor.addsMfa ? [MFA_AMR] : [])])],
					mfaAt: new Date(nowMs),
				},
				...about,
			};
		},
	};
}
