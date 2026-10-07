import { type MfaCeremonyCall, type MfaCeremonyKit, type MfaStepUpOutcome } from "./ceremony.mjs";
/** The step-up over the coordinator's `kit` (see this file's header). */
export declare function createMfaStepUp(kit: MfaCeremonyKit): {
    open(call: MfaCeremonyCall & {
        readonly acrValues: readonly string[] | undefined;
    }): Promise<MfaStepUpOutcome>;
};
//# sourceMappingURL=stepUp.d.mts.map