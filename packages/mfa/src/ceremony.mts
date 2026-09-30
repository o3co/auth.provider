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
 * The contract the MFA ceremonies share: a call, what each ceremony answers,
 * and the kit the coordinator hands the ceremonies beside a verification —
 * the first binding (`enrollment.mts`) and the account-email proof
 * (`proof.mts`). A leaf: the coordinator and both ceremonies import it, and
 * it imports none of them, so no two of them depend on each other's
 * contracts.
 */

import type {
	MailSender,
	MfaFactor,
	MfaFactorData,
	MfaFactorRecord,
	MfaFactorResolver,
	MfaFactorStore,
	MfaTransaction,
	MfaTransactionBinding,
	MfaTransactionPatch,
	MfaVerification,
	PrimaryContinuation,
} from "@o3co/auth-provider-core";
import type { MfaMailRefusal } from "./mail.mjs";
import type { MfaIssuedRecoveryCodes } from "./recovery/issue.mjs";
import type { MfaSealing } from "./sealing.mjs";
import type { MfaEnrollmentWitness, MfaWitnessMark } from "./witness.mjs";

/** The MFA store that could not answer. */
export type MfaStoreName = "mfa_transaction" | "mfa_factor";

/** A store that could not answer: the operation, and why. */
export interface MfaStoreOutage {
	readonly outcome: "unavailable";
	readonly store: MfaStoreName;
	readonly step: string;
	readonly cause: unknown;
}

/** A store's outage at `step`. */
export const outage = (store: MfaStoreName, step: string, cause: unknown): MfaStoreOutage => ({
	outcome: "unavailable",
	store,
	step,
	cause,
});

/** Why a store's answer outside its port's promise is an outage: it is never read as a verdict. */
export const OUTSIDE_CONTRACT = new TypeError("the store answered outside its port's contract");

/**
 * A factor that cannot be used as stored: its data does not open
 * (`unreadable`), or opens under a key the ring lacks (`key_unavailable`,
 * naming it), or the factor threw reading it (`verification`); or its
 * pending challenge's kept state does not open (`challenge`, naming the key
 * when it is the one missing); or a first binding's pending enrollment does
 * not open, or the factor threw completing it (`enrollment`).
 */
export interface MfaFactorUnreadable {
	readonly outcome: "unreadable";
	readonly kind: string;
	readonly factorId: string;
	readonly state: "unreadable" | "key_unavailable" | "verification" | "challenge" | "enrollment";
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
export const UNKNOWN_TRANSACTION = Object.freeze({ outcome: "unknown_transaction" as const });
/** No factor of the subject's that an installed factor verifies, by the id named. */
export const UNKNOWN_FACTOR = Object.freeze({ outcome: "unknown_factor" as const });

export type UnknownTransaction = typeof UNKNOWN_TRANSACTION;
export type UnknownFactor = typeof UNKNOWN_FACTOR;

/** One call's request: the transaction named, the binding the browser presents, and what a factor may read of the request. */
export interface MfaCeremonyCall {
	readonly transactionId: string | undefined;
	readonly binding: MfaTransactionBinding;
	readonly request: { readonly ip?: string; readonly userAgent?: string };
}

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
	| MfaMailRefusal
	| { readonly outcome: "none" }
	| ({ readonly outcome: "sent"; readonly response: object } & MfaCeremonySubject)
	/** A login code whose factor recorded another address, or none it can read: the factor is refused. */
	| ({ readonly outcome: "address_mismatch" } & MfaCeremonySubject)
	/** The account-email proof is asked for and nobody can give it: no sender, or no address. */
	| { readonly outcome: "proof_unavailable" }
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
	/** The account-email proof was given: the first binding may proceed. */
	| ({ readonly outcome: "proved" } & MfaCeremonySubject)
	/** The proof was right, but it does not count and the subject holds no counting factor it can use (F3). */
	| ({ readonly outcome: "enrollment_required" } & MfaCeremonySubject)
	| ({
			readonly outcome: "verified";
			/** What the login persisted, as the store answered it at consumption. */
			readonly continuation: PrimaryContinuation | undefined;
			/** What the verification adds to the login: the factor's `amr`, `mfa` when it adds it, and when. */
			readonly adds: { readonly amr: readonly string[]; readonly mfaAt: Date };
			/** The witness marked for a login's `User` that lacked it; `undefined` when none was due. */
			readonly witness: MfaWitnessMark | undefined;
	  } & MfaCeremonySubject);

/** Why a first binding is refused before anything is spent. */
export type MfaEnrollmentRefusal =
	| UnknownTransaction
	| MfaStoreOutage
	/** The transaction opened no enrollment, or it is not a login's first binding. */
	| { readonly outcome: "enrollment_not_open" }
	/** The account-email proof is owed first. */
	| { readonly outcome: "email_proof_required" }
	/** No counting factor of that kind this user may enroll. */
	| { readonly outcome: "unknown_kind" }
	/** The subject holds a record now: the login starts again. */
	| { readonly outcome: "first_binding_closed" };

export type MfaEnrollmentBeginOutcome =
	| MfaEnrollmentRefusal
	| MfaMailRefusal
	/** The factor could not start its enrollment: an outage, never a refusal. */
	| { readonly outcome: "enrollment_failed"; readonly kind: string; readonly cause: unknown }
	| ({ readonly outcome: "begun"; readonly response: object } & MfaCeremonySubject);

export type MfaEnrollmentCompleteOutcome =
	| MfaEnrollmentRefusal
	| MfaFactorUnreadable
	| { readonly outcome: "no_pending_enrollment" }
	| { readonly outcome: "invalid_label" }
	| { readonly outcome: "spent" }
	| ({
			readonly outcome: "refused";
			readonly reason: MfaRefusalReason | "duplicate";
			readonly attemptsRemaining: number;
	  } & MfaCeremonySubject)
	/**
	 * Once this binding's factor was written, another record stood beside it
	 * (`first_binding_conflict`), or the records could not be read again to
	 * tell (`first_binding_unchecked`, with that outage). Its own was removed
	 * — or, `standing` saying why, still stands after every try — and the
	 * login starts again.
	 */
	| ({
			readonly outcome: "first_binding_conflict";
			readonly standing: { readonly cause: unknown } | undefined;
	  } & MfaCeremonySubject)
	| ({
			readonly outcome: "first_binding_unchecked";
			readonly listing: MfaStoreOutage;
			readonly standing: { readonly cause: unknown } | undefined;
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
			/** Why D25's flag could not be cleared after the proof was given; `undefined` when it was, or none was due. */
			readonly flagUncleared: unknown;
	  } & MfaCeremonySubject);

/**
 * What the ceremonies beside a verification share of the coordinator: its
 * stores, and the reads and writes every use of a transaction goes through,
 * each answering an outage as a verification does.
 */
export interface MfaCeremonyKit {
	readonly factors: MfaFactorResolver;
	readonly factorStore: MfaFactorStore;
	readonly sealing: MfaSealing;
	readonly mailSender: MailSender | undefined;
	readonly witness: MfaEnrollmentWitness;
	readonly now: () => number;
	/** The login transaction `call` names, bound to its binding; `null` when there is none to use. */
	readonly bound: (call: MfaCeremonyCall) => Promise<MfaTransaction | null | MfaStoreOutage>;
	/** Every record of `subject`, oldest first; an outage is never "none". */
	readonly recordsOf: (subject: string) => Promise<MfaFactorRecord[] | MfaStoreOutage>;
	/** One of `tx`'s attempts reserved: the attempts left, `exhausted` past the limit, or why none was. */
	readonly reserve: (
		tx: MfaTransaction,
	) => Promise<
		| { readonly attemptsRemaining: number }
		| { readonly outcome: "exhausted" }
		| UnknownTransaction
		| MfaStoreOutage
	>;
	/** `tx` consumed at the version read, or `spent`, or the outage. */
	readonly consume: (
		tx: MfaTransaction,
	) => Promise<MfaTransaction | { readonly outcome: "spent" } | MfaStoreOutage>;
	/**
	 * `patch` written at `tx`'s version: the transaction the store answered —
	 * its id and next version checked — else why not.
	 */
	readonly write: (
		tx: MfaTransaction,
		patch: MfaTransactionPatch,
	) => Promise<{ readonly written: MfaTransaction } | UnknownTransaction | MfaStoreOutage>;
	/**
	 * `field` cleared on `written`, the transaction as a keep wrote it: `true`
	 * only once the store wrote the clear as asked — never for an answer of
	 * `null`, one outside its port, or a failure.
	 */
	readonly clear: (
		written: MfaTransaction,
		field: "challenge" | "pendingEnrollment",
	) => Promise<boolean>;
	/** D25's flag for `subject`; an outage — an answer that is not a boolean among it — otherwise. */
	readonly emailProofRequired: (subject: string) => Promise<boolean | MfaStoreOutage>;
	/** D25's flag cleared for `subject`; `failed` with why when it could not be. */
	readonly consumeEmailProofRequirement: (
		subject: string,
	) => Promise<{ readonly failed: unknown } | undefined>;
	/** Whether `value` is an object `res.json` answers as built: a plain object. */
	readonly answerable: (value: unknown) => value is object;
	/** `factor.amrFor(data)` when it names at least one value and only values the factor declares; else `undefined`. */
	readonly declaredAmr: (factor: MfaFactor, data: MfaFactorData) => readonly string[] | undefined;
}
