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
 * requests of one ceremony on the transaction, sealed or digested. That keeps
 * sealing in one place, and lets a package implement a factor without
 * depending on the package that coordinates them: a factor arrives as an
 * `mfaFactors` contribution keyed by its kind, and is read back through the
 * synthetic `mfaFactorResolver`.
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

/** What every call to a factor is handed. */
export interface MfaCeremonyContext {
	/** The subject the ceremony is for: `User.id`. */
	readonly subject: string;
	/** The time the coordinator judges this request by, in epoch milliseconds. */
	readonly nowMs: number;
	readonly request: { readonly ip?: string; readonly userAgent?: string };
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
	 * The state the factor's `challenge` returned, taken from the transaction
	 * (read and cleared in one step); `undefined` when none is pending or the
	 * factor needs no challenge.
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
	| { readonly ok: false; readonly reason: "invalid" | "expired" | "replayed" | "malformed" };

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
