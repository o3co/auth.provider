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
 * (`packages/core/docs/adr/2026-09-25-multi-factor-authentication.md`, D7).
 *
 * A factor never sees a key, a store or a transaction. The coordinator opens
 * the subject's records, hands the factor their data decoded, seals what the
 * factor returns and writes it; it keeps what a factor carries between two
 * requests of one ceremony on the transaction, sealed or digested. Where a
 * factor must keep a code it compares and never recovers (D11: an email code,
 * a recovery code), the coordinator digests it under the key ring for the
 * factor ({@link MfaDigests}), so the ring stays with the coordinator too.
 * That keeps sealing in one place, and lets a package implement a factor
 * without depending on the package that coordinates them: a factor arrives as
 * an `mfaFactors` contribution keyed by its kind, and is read back through
 * the synthetic `mfaFactorResolver`.
 */

/**
 * A factor's own state, as the coordinator opened it from a record's `data`.
 * The factor decides its shape. It must survive a JSON round trip: the
 * coordinator serialises it before sealing it.
 */
export type MfaFactorData = Readonly<Record<string, unknown>>;

/**
 * What a factor keeps between two requests of one ceremony — a challenge and
 * its verification, or the start and the end of an enrollment. The coordinator
 * keeps it on the transaction, sealed or digested. JSON, as
 * {@link MfaFactorData} is.
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

/** A keyed digest and the id of the ring key it was made under (D11). */
export interface MfaKeyedDigest {
	readonly keyId: string;
	readonly digest: string;
}

/**
 * What comparing a value with a stored digest found. `key_unavailable`: the
 * key the digest names has left the ring, so the value cannot be judged — the
 * factor is unreadable, which the coordinator answers `503` with one
 * `mfa_factor_unreadable` line (D11), never as a wrong code.
 */
export type MfaDigestMatch = "match" | "mismatch" | "key_unavailable";

/**
 * Keyed digests under the MFA key ring, made by the coordinator so that a
 * factor never holds a key (D11). A code that is compared and never recovered
 * is kept as one: an email code over `[transactionId, factorId, code]`, a
 * recovery code over its normalised form. Each digest carries its key id, so
 * rotating the ring never makes a code unverifiable while that key stays in
 * the ring — a key leaves it only once no sealed data and no stored digest
 * names it.
 */
export interface MfaDigests {
	/**
	 * HMAC-SHA-256 under the ring's current key over `parts`, each part length
	 * prefixed, bound to the factor's kind: a digest made for one kind never
	 * matches for another.
	 */
	digest(parts: readonly string[]): MfaKeyedDigest;
	/**
	 * Whether `parts` digest to `stored` under the key `stored` names,
	 * compared in constant time: `match` or `mismatch`, and `key_unavailable`
	 * when that key has left the ring — which a factor answers as an outage
	 * (it throws, and the coordinator answers `503`), never as `invalid`.
	 */
	matchesDigest(parts: readonly string[], stored: MfaKeyedDigest): MfaDigestMatch;
}

/** What every call to a factor is handed. */
export interface MfaCeremonyContext {
	/** The subject the ceremony is for: `User.id`. */
	readonly subject: string;
	/**
	 * The MFA transaction this call belongs to — to bind a digest to it (D11),
	 * never to store. Every call has one: a call outside a login or step-up —
	 * self-service enrollment, regenerating recovery codes (F4) — runs under an
	 * `enroll` transaction the coordinator opens for it.
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
	 * The state the factor's `challenge` returned for this transaction:
	 * **taken** from it — read and cleared in one step, so it answers one
	 * verification — by default (WebAuthn, F7); **read**, and left for the
	 * next attempt, for a factor whose `reusableChallenge` is true (an email
	 * code stands until a re-send replaces it or the transaction is consumed,
	 * F5). `undefined` when none is pending or the factor needs no challenge.
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
			 * over the stored one — a possible clone, refused and audited (F7, D28).
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
	/** The `amr` values a verification adds (D14). May depend on the factor's data: a WebAuthn credential is `hwk` or `swk`. */
	amrFor(data: MfaFactorData): readonly string[];
	/** Whether a verification also adds `mfa` (D14). */
	readonly addsMfa: boolean;
	/** Whether holding one satisfies "this user has MFA". Recovery codes do not. */
	readonly counting: boolean;
	/** Whether a verification's proof can be guessed, and so is held to the subject lock (D21). Enrollment proofs never are. */
	readonly guessable: boolean;
	/** What the page may show about one factor so the user can pick it (a masked address). Never a secret. */
	describe(data: MfaFactorData): { readonly hint?: string };
	/**
	 * Whether this user can enroll one — the email factor needs an address on
	 * the account (F3, F5); a kind a user cannot enroll is not offered. Absent:
	 * every user can. Answers; never throws, which the coordinator would read
	 * as an outage.
	 */
	enrollable?(user: Readonly<Record<string, unknown>>): boolean;
	/**
	 * Whether the pending challenge stays on the transaction across attempts
	 * until a new one replaces it (an email code, F5). Absent or false — the
	 * default, which fails closed — a verification takes it, so one challenge
	 * answers one verification (WebAuthn, F7). See
	 * {@link MfaVerifyContext.state}.
	 */
	readonly reusableChallenge?: boolean;
	/** Prepare a verification: send a code, answer WebAuthn request options. Absent for a factor that needs none. */
	challenge?(
		ctx: MfaChallengeContext,
	): Promise<{ readonly state?: MfaFactorState; readonly response: unknown }>;
	verify(ctx: MfaVerifyContext): Promise<MfaVerification>;
	beginEnrollment(
		ctx: MfaEnrollmentContext,
	): Promise<{ readonly state: MfaFactorState; readonly response: unknown }>;
	completeEnrollment(ctx: MfaEnrollmentCompletionContext): Promise<MfaEnrollmentCompletion>;
}
