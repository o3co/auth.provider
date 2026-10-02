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
 * coordinator serialises it before sealing it. It must be plain JSON-shaped
 * (plain objects and arrays, strings, finite numbers, booleans, `null`); a
 * field read as `undefined` is absent.
 */
export type MfaFactorData = Readonly<Record<string, unknown>>;

/**
 * What a factor keeps between two requests of one ceremony (a challenge and its
 * verification, or the two halves of an enrollment). The coordinator keeps it
 * on the transaction, sealed or digested. It must be plain JSON-shaped, like
 * {@link MfaFactorData}.
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
	/**
	 * After a challenge whose login code went out: the keyed digest, under the
	 * ring's first key, of the address that code was sent to, made when it was
	 * sent and kept with the pending challenge — never from a later read of the
	 * Store. A factor whose recorded digest names another key keeps this one in
	 * `next`, so that key can leave the ring; it records nothing else of an
	 * address.
	 */
	readonly addressDigest?: MfaKeyedDigest;
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
	/**
	 * After a start whose code went out: the keyed digest, under the ring's
	 * first key, of the address that code was sent to, made when it was sent
	 * and kept with the pending enrollment — never from a later read of the
	 * Store, so `user` may by now answer another address. The factor records
	 * this one, never a digest of `user.email` of its own; without it, it
	 * completes nothing.
	 */
	readonly addressDigest?: MfaKeyedDigest;
}

/** What a factor may ask a code to be mailed for; the account-email proof is the coordinator's own. */
export type MfaFactorMailPurpose = Exclude<MailPurpose, "account_email_proof">;

/**
 * A code a challenge or an enrollment asks the coordinator to mail: its
 * purpose, the code and, when the factor gives one, when it stops being
 * accepted — never text. The coordinator resolves the recipient when it
 * sends: the address on the account's user record at that moment, as
 * `normaliseMailAddress` spells it. In this order:
 *
 * 1. A login code: the comparison comes first, before anything is written.
 *    The address must match the digest the mail carries
 *    ({@link MfaLoginCodeMail}). On a mismatch, no address, or a digest that
 *    is `null` or no keyed digest, no code and no digest are kept, the factor
 *    is refused until the user re-enrolls it after recent MFA,
 *    `mfa.email_address_mismatch` is recorded, and nothing is sent;
 *    `key_unavailable` is an outage, and keeps nothing either. An enrollment
 *    code has nothing to compare.
 * 2. The state is kept, with the keyed digest of the address, under the
 *    ring's first key, expiring at the earlier of `expiresAtMs` and the
 *    transaction's expiry.
 * 3. The code is sent with that expiry. A send refused at a limit or failed
 *    clears the state, and is never "sent".
 *
 * The kept digest is handed back to the call that takes the code: an
 * enrollment's completion, which the factor records in its data, never the
 * address and never a digest of its own
 * ({@link MfaEnrollmentCompletionContext.addressDigest}); a verification
 * ({@link MfaVerifyContext.addressDigest}). So what a factor records is the
 * address the code went to, whatever the Store answers by then.
 */
export interface MfaFactorMail<P extends MfaFactorMailPurpose = MfaFactorMailPurpose> {
	readonly purpose: P;
	readonly code: string;
	/** Epoch milliseconds, after the call's `nowMs`; absent, the transaction's expiry. */
	readonly expiresAtMs?: number;
}

/** A login code to mail, with the keyed digest of the address the factor was enrolled with. */
export interface MfaLoginCodeMail extends MfaFactorMail<"login_code"> {
	/**
	 * The digest the factor recorded, as it was handed: over
	 * `[normaliseMailAddress(address)]`. `null` when its data holds none it can
	 * read — a mismatch, which the coordinator refuses; never a value that is
	 * no keyed digest.
	 */
	readonly addressDigest: MfaKeyedDigest | null;
}

/** What a challenge answers: the state the coordinator keeps, if any, the page's response, and a login code to mail. */
export interface MfaChallenge {
	readonly state?: MfaFactorState;
	/** What the page is answered: request options, where a code went. Never the code `mail` carries. */
	readonly response: unknown;
	readonly mail?: MfaLoginCodeMail;
}

/** What the start of an enrollment answers; `response` as {@link MfaChallenge}'s, `mail` the enrollment's code. */
export interface MfaEnrollmentStart {
	readonly state: MfaFactorState;
	readonly response: unknown;
	readonly mail?: MfaFactorMail<"email_factor_enrollment">;
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
			/**
			 * The factor the refusal concerns, when the factor can tell — for
			 * `sign_count_regression`, the one whose counter did not increase:
			 * the record id of one of the subject's factors of this kind, never a
			 * credential id, key or handle. The coordinator audits it only when it
			 * names such a record.
			 */
			readonly factorId?: string;
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
	 * A duplicate key for the authenticator `data` records, as a string stable
	 * for it: a WebAuthn credential id, the digest of the address an email
	 * factor's codes go to. Two of a subject's records of this kind with equal
	 * identities hold one authenticator enrolled twice; the coordinator
	 * compares identities only among one subject's records of one kind, to
	 * find such a duplicate.
	 *
	 * It depends on the data alone: a record answers the same whichever factor
	 * instance reads it, in whatever order, and after later enrollments; using
	 * the factor leaves it as it was, so a verification's next data answers
	 * the same. Data rewritten under another key may answer another, which
	 * only misses a duplicate.
	 *
	 * It is not an assurance signal: distinct identities do not show distinct
	 * devices or mailboxes, since one authenticator can hold two credentials
	 * (WebAuthn's `excludeCredentials` is enforced by the client).
	 *
	 * `undefined` when the data holds none the factor can read. Absent: no
	 * record of this kind is judged a duplicate of another (each TOTP
	 * enrollment makes a new secret). A record with no identity is a duplicate
	 * of none and never a distinct authenticator: a consumer that counts
	 * distinct authenticators does not count it. Never coarser than the
	 * authenticator: an identity two authenticators share (a constant, a
	 * kind-wide value) judges every second enrollment of the kind a duplicate.
	 * Never a secret, nor derived from one, since it is compared as it is.
	 *
	 * Must not throw. The coordinator reads a throw as `undefined` — the
	 * record is judged a duplicate of none — and logs it, so a broken identity
	 * never blocks an enrollment.
	 */
	identity?(data: MfaFactorData): string | undefined;
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
