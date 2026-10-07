import type { MfaDigests, MfaEnrolledFactor, MfaFactor } from "../mfa/factor.mjs";
/** What the start of an enrollment answers. */
type EnrollmentStart = Awaited<ReturnType<MfaFactor["beginEnrollment"]>>;
/** What a challenge answers. */
type Challenge = Awaited<ReturnType<NonNullable<MfaFactor["challenge"]>>>;
export interface TestMfaDigestsOptions {
    /**
     * A ring whose first key is a second test key (`test-key-2`), still
     * holding the first: new digests are made under the second, and one made
     * under either matches — as after a key rotation.
     */
    readonly rotated?: boolean;
}
/**
 * Keyed digests for a factor of `kind` under a fixed test key, as the
 * coordinator makes them under the ring: HMAC-SHA-256 over the kind and the
 * parts, each length-prefixed, compared in constant time; a digest naming a
 * key the ring does not hold is `key_unavailable`. For tests only: the keys
 * are public.
 */
export declare function createTestMfaDigests(kind: string, options?: TestMfaDigestsOptions): MfaDigests;
export interface TestMfaFactorOptions {
    /** Default `test`. */
    readonly kind?: string;
    /** Default `["otp"]`; `amrFor` answers them all. */
    readonly amrValues?: readonly string[];
    /** Default true. */
    readonly addsMfa?: boolean;
    /** Default true. */
    readonly counting?: boolean;
    /** Default false. */
    readonly guessable?: boolean;
    /**
     * Answer a challenge before each verification: a nonce, kept as the
     * challenge's state and answered to the page, which the verification must
     * repeat beside the secret — as a WebAuthn assertion signs the challenge
     * it was handed. Absent: there is no challenge.
     */
    readonly challenge?: boolean;
    /**
     * Mail codes instead, and take precedence over `challenge`: the enrollment
     * asks for its code to be mailed (`email_factor_enrollment`) and each
     * challenge for another (`login_code`), each expiring ten minutes on, which
     * a verification repeats; the latest stands across attempts. Enrollable
     * only by an account whose address `normaliseMailAddress` reads. It keeps
     * the address digest its completion is handed, never the address or a
     * digest of its own, and mails it with each login code — `null` when its
     * data holds none it can read.
     */
    readonly mail?: boolean;
}
/**
 * A second factor with a trivial protocol, for tests: the enrollment answers
 * a random secret, and a verification is that secret — with `challenge`, the
 * secret and the nonce the latest challenge answered, as `secret:nonce`;
 * with `mail`, the code the latest challenge asked to be mailed.
 * {@link testMfaFactorProofs} makes the proofs. A proof that is not a string
 * is `malformed`.
 */
export declare function createTestMfaFactor(options?: TestMfaFactorOptions): MfaFactor;
/**
 * The proofs of {@link createTestMfaFactor}: the secret its enrollment
 * answered, or the code it asked to be mailed; for a verification, that
 * secret — and, after a challenge, the nonce it answered, as `secret:nonce`
 * — or the code the challenge asked to be mailed. An input to the test
 * kit's `mfaFactorContract` beside the double.
 */
export declare const testMfaFactorProofs: {
    readonly enrollmentProof: (start: EnrollmentStart) => unknown;
    readonly verificationProof: (enrolled: MfaEnrolledFactor, challenge: Challenge | undefined) => unknown;
};
export {};
//# sourceMappingURL=mfaFactor.d.mts.map