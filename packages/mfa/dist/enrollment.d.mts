import { type MfaCeremonyCall, type MfaCeremonyKit, type MfaEnrollmentBeginOutcome, type MfaEnrollmentCompleteOutcome } from "./ceremony.mjs";
/** An enrollment over the coordinator's `kit` (see this file's header). */
export declare function createMfaEnrollment(kit: MfaCeremonyKit): {
    begin(call: MfaCeremonyCall & {
        readonly kind: unknown;
    }): Promise<MfaEnrollmentBeginOutcome>;
    complete(call: MfaCeremonyCall & {
        readonly proof: unknown;
        readonly label: unknown;
    }): Promise<MfaEnrollmentCompleteOutcome>;
};
//# sourceMappingURL=enrollment.d.mts.map