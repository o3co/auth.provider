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
 * The contract a second factor implements, and what the coordinator hands it
 * (ADR 2026-09-25-multi-factor-authentication).
 *
 * A factor never sees a key, a store, a transaction or the mail sender. The
 * coordinator opens the subject's records, seals and writes what the factor
 * returns, keeps per-ceremony state on the transaction, digests codes that
 * are compared but never recovered ({@link MfaDigests}), and sends the code a
 * factor asks to be mailed ({@link MfaFactorMail}). So sealing and sending
 * stay in one place and a factor package need not depend on the coordinator:
 * a factor arrives as an `mfaFactors` contribution keyed by its kind, read
 * back through the synthetic `mfaFactorResolver`.
 */

import type { MailPurpose } from "../mail/types.mjs";

/**
 * A factor's own state, as the coordinator opened it from a record's `data`.
 * The factor decides its shape. It must survive a JSON round trip: the
 * coordinator serialises it before sealing it.
 */
export type MfaFactorData = Readonly<Record<string, unknown>>;

/**
 * What a factor keeps between two requests of one ceremony (a challenge and its
 * verification, or the two halves of an enrollment). The coordinator keeps it
 * on the transaction, sealed or digested. JSON, like {@link MfaFactorData}.
 */
export type MfaFactorState = Readonly<Record<string, unknown>>;

/** One of the subject's factors of a factor's kind, as the factor sees it: its record's own fields, and its data opened. */
export interface MfaEnrolledFactor {
	readonly id: string;
	readonly label: string | undefined;
	readonly createdAt: Date;
	readonly lastUsedAt: Date | undefined;
	readonly data: MfaFactorData;
}

/** A keyed digest and the id of the ring key it was made under. */
export interface MfaKeyedDigest {
	readonly keyId: string;
	readonly digest: string;
}

/**
 * What comparing a value with a stored digest found. `key_unavailable`: the
 * digest's key has left the ring, so the value cannot be judged; the
 * coordinator answers `503` (`mfa_factor_unreadable`), never a wrong code.
 */
export type MfaDigestMatch = "match" | "mismatch" | "key_unavailable";

/**
 * Keyed digests under the MFA key ring, made by the coordinator so a factor
 * never holds a key. For codes compared but never recovered: an email code over
 * `[transactionId, factorId, code]`, a recovery code over its normalised form.
 * Each digest names its key id; a key leaves the ring only once no sealed data
 * and no stored digest names it.
 */
export interface MfaDigests {
	/**
	 * HMAC-SHA-256 under the ring's current key over `parts`, each part length
	 * prefixed, bound to the factor's kind: a digest made for one kind never
	 * matches for another.
	 */
	digest(parts: readonly string[]): MfaKeyedDigest;
	/**
	 * Whether `parts` digest to `stored` under the key `stored` names, compared
	 * in constant time. A factor treats `key_unavailable` as an outage (it
	 * throws; the coordinator answers `503`), never as `invalid`.
	 */
	matchesDigest(parts: readonly string[], stored: MfaKeyedDigest): MfaDigestMatch;
}

/** What every call to a factor is handed. */
export interface MfaCeremonyContext {
	/** The subject the ceremony is for: `User.id`. */
	readonly subject: string;
	/**
	 * The MFA transaction this call belongs to, for binding a digest to it, never
	 * for storage. A call outside a login or step-up (self-service enrollment,
	 * regenerating recovery codes) runs under an `enroll` transaction.
	 */
	readonly transactionId: string;
	/** The time the coordinator judges this request by, in epoch milliseconds. */
	readonly nowMs: number;
	readonly request: { readonly ip?: string; readonly userAgent?: string };
	/** Keyed digests under the key ring, which the factor never sees. */
	readonly digests: MfaDigests;
}

/** A challenge for the factor the request names. */
export interface MfaChallengeContext extends MfaCeremonyContext {
	/** The factor the request names. */
	readonly factor: MfaEnrolledFactor;
	/** Every factor of this kind the subject holds, the named one among them. */
	readonly factors: readonly MfaEnrolledFactor[];
}

/** A proof for the factor the request names. */
export interface MfaVerifyContext extends MfaCeremonyContext {
	/** The factor the request names. */
	readonly factor: MfaEnrolledFactor;
	/** Every factor of this kind the subject holds, the named one among them. */
	readonly factors: readonly MfaEnrolledFactor[];
	/**
	 * The state `challenge` returned for this transaction. By default it is
	 * **taken** (read and cleared in one step, so it answers one verification,
	 * as WebAuthn needs); with `reusableChallenge` it is **read** and left for
	 * the next attempt (an email code stands until a re-send or the transaction
	 * is consumed). `undefined` when none is pending or none is needed.
	 */
	readonly state: MfaFactorState | undefined;
	/** The proof as the request carried it. The factor reads it and refuses what it cannot read as `malformed`. */
	readonly proof: unknown;
}

/** The start of an enrollment. */
export interface MfaEnrollmentContext extends MfaCeremonyContext {
	/** The account being enrolled, as the Store answered for it (a `User`). */
	readonly user: Readonly<Record<string, unknown>>;
	/** The factors of this kind the subject already holds. */
	readonly factors: readonly MfaEnrolledFactor[];
}

/** The end of an enrollment: the proof of possession. */
export interface MfaEnrollmentCompletionContext extends MfaEnrollmentContext {
	/** The state `beginEnrollment` returned, from the pending enrollment. */
	readonly state: MfaFactorState;
	/** The proof as the request carried it. */
	readonly proof: unknown;
}

/**
 * A code a challenge or an enrollment asks the coordinator to mail: its
 * purpose and the code, never text. The coordinator resolves the recipient,
 * the address on the account's user record at that moment, and the expiry;
 * it keeps the state first and sends after, and a send that fails clears
 * that state and is an outage, never "sent".
 */
export interface MfaFactorMail {
	readonly purpose: MailPurpose;
	readonly code: string;
}

/** What a challenge answers: the state the coordinator keeps, if any, the page's response, and a code to mail. */
export interface MfaChallenge {
	readonly state?: MfaFactorState;
	/** What the page is answered: request options, where a code went. Never the code `mail` carries. */
	readonly response: unknown;
	readonly mail?: MfaFactorMail;
}

/** What the start of an enrollment answers; `response` and `mail` as {@link MfaChallenge}'s. */
export interface MfaEnrollmentStart {
	readonly state: MfaFactorState;
	readonly response: unknown;
	readonly mail?: MfaFactorMail;
}

/** What a verification answers. */
export type MfaVerification =
	| {
			readonly ok: true;
			/** The factor the proof verified — the named one, or another of its kind (a WebAuthn assertion names its credential). */
			readonly factorId: string;
			/** The factor's data after this use (a TOTP step, a sign count); absent when nothing changed. */
			readonly next?: MfaFactorData;
	  }
	| {
			readonly ok: false;
			/**
			 * `sign_count_regression`: a WebAuthn counter that did not increase
			 * over the stored one; a possible clone, refused and audited.
			 */
			readonly reason: "invalid" | "expired" | "replayed" | "malformed" | "sign_count_regression";
	  };

/** What the end of an enrollment answers. */
export type MfaEnrollmentCompletion =
	| { readonly ok: true; readonly data: MfaFactorData; readonly label?: string }
	| { readonly ok: false; readonly reason: "invalid" | "expired" | "malformed" | "duplicate" };

/**
 * A second factor: a verifier bound to one subject after the primary
 * authentication. One implementation serves every record of its kind.
 */
export interface MfaFactor {
	/** The kind its records carry (`MfaFactorRecord.kind`), and the key it is contributed under. */
	readonly kind: string;
	/**
	 * Every `amr` value a verification of this factor may add; `amrFor` answers a
	 * subset. Boot computes the second-factor authority's reach and drops
	 * unsatisfiable `acr` entries from it (ADR 2026-09-28-session-admission). Non-empty
	 * strings, never a primary's marker, never `mfa` (`addsMfa` says that).
	 */
	readonly amrValues: readonly string[];
	/** The `amr` values a verification adds. May depend on the factor's data: a WebAuthn credential is `hwk` or `swk`. */
	amrFor(data: MfaFactorData): readonly string[];
	/** Whether a verification also adds `mfa`. */
	readonly addsMfa: boolean;
	/** Whether holding one satisfies "this user has MFA". Recovery codes do not. */
	readonly counting: boolean;
	/** Whether a verification's proof can be guessed, and so is held to the subject lock. Enrollment proofs never are. */
	readonly guessable: boolean;
	/** What the page may show about one factor so the user can pick it (a masked address). Never a secret. */
	describe(data: MfaFactorData): { readonly hint?: string };
	/**
	 * Whether this user can enroll one (the email factor needs an address on the
	 * account); a kind a user cannot enroll is not offered. Absent: every user
	 * can. Must not throw: the coordinator reads a throw as an outage.
	 */
	enrollable?(user: Readonly<Record<string, unknown>>): boolean;
	/**
	 * Whether the pending challenge stays on the transaction across attempts
	 * until a new one replaces it (an email code). Absent or false, the
	 * fail-closed default, a verification takes it. See {@link MfaVerifyContext.state}.
	 */
	readonly reusableChallenge?: boolean;
	/** Prepare a verification: a code to mail, WebAuthn request options. Absent for a factor that needs none. */
	challenge?(ctx: MfaChallengeContext): Promise<MfaChallenge>;
	verify(ctx: MfaVerifyContext): Promise<MfaVerification>;
	beginEnrollment(ctx: MfaEnrollmentContext): Promise<MfaEnrollmentStart>;
	completeEnrollment(ctx: MfaEnrollmentCompletionContext): Promise<MfaEnrollmentCompletion>;
}
