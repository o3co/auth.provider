import { type UserRepository } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
/** A user the backend holds: its subject (`User.id`) and what each read resolves to it. */
export interface MfaEnrollmentWitnessUser {
    readonly subject: string;
    /** With `password`, what `authenticate` resolves to this user. */
    readonly username: string;
    readonly password: string;
    /** A handle `authenticateByToken` resolves to this user. */
    readonly token: string;
}
/** What one case runs over: a fresh backend and the repository under test over it. */
export interface MfaEnrollmentWitnessHarness {
    /** The repository under test. */
    readonly repository: UserRepository;
    /** Two users the backend holds, neither marked. */
    readonly users: readonly [MfaEnrollmentWitnessUser, MfaEnrollmentWitnessUser];
    /** A subject the backend does not hold. */
    readonly unknownSubject: string;
    /** Puts the backend into an outage: every later mark fails. Required by the outage case. */
    readonly outage?: () => void | Promise<void>;
    /** Releases the backend once the case ends. */
    readonly close?: () => Promise<void>;
}
export interface MfaEnrollmentWitnessContractInput {
    /** Builds a fresh harness for each case. */
    readonly build: () => Promise<MfaEnrollmentWitnessHarness>;
    /** Whether the harness can make an outage (`outage`); `true` adds the outage case. */
    readonly withOutage: boolean;
}
/** The cases of the enrollment witness's contract over the harnesses `input` builds. */
export declare function mfaEnrollmentWitnessContract(input: MfaEnrollmentWitnessContractInput): readonly ContractCase[];
//# sourceMappingURL=enrollmentWitness.contract.d.mts.map