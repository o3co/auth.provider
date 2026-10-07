import { type MfaCeremonyContext, type MfaEnrolledFactor, type MfaFactor } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
/** What the start of an enrollment answers: the state the coordinator keeps, and the page's response. */
export type MfaFactorEnrollmentStart = Awaited<ReturnType<MfaFactor["beginEnrollment"]>>;
/** What a challenge answers: the state the coordinator keeps, if any, and the page's response. */
export type MfaFactorChallenge = Awaited<ReturnType<NonNullable<MfaFactor["challenge"]>>>;
export interface MfaFactorContractInput {
    /** A fresh factor for each case. */
    readonly build: () => MfaFactor;
    /** An account the factor can enroll, as the Store answers it (a `User`). */
    readonly user: Readonly<Record<string, unknown>>;
    /** The proof of possession that completes the enrollment `start` began, as a request carries it. */
    readonly enrollmentProof: (start: MfaFactorEnrollmentStart, context: MfaCeremonyContext) => unknown;
    /**
     * The proof of possession of an authenticator other than the one
     * `enrollmentProof` proves, completing the enrollment `start` began. Given
     * it, a factor with `identity` must answer the two enrolled data two
     * different identities. Distinct identities name distinct records, not
     * distinct devices.
     */
    readonly secondEnrollmentProof?: (start: MfaFactorEnrollmentStart, context: MfaCeremonyContext) => unknown;
    /**
     * A proof that verifies `enrolled` at the context's time — after `challenge`,
     * which the suite passes, when the factor has one.
     */
    readonly verificationProof: (enrolled: MfaEnrolledFactor, challenge: MfaFactorChallenge | undefined, context: MfaCeremonyContext) => unknown;
    /** Proofs the factor cannot read. Default: `undefined`, `null`, a number and an empty object. */
    readonly malformedProofs?: readonly unknown[];
}
/** The cases of the factor contract over the factors `input` builds. */
export declare function mfaFactorContract(input: MfaFactorContractInput): readonly ContractCase[];
//# sourceMappingURL=factor.contract.d.mts.map