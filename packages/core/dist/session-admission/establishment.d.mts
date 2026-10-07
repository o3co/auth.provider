import type { AdmissionDeps, CompletedRequirement, Establishment, InterruptAdmission, PrimaryAdmission, PrimaryAuthentication, SessionRequirementResolver } from "./requirement.mjs";
/** Whether `value` is an `Establishment` one of the three built: a copy, or an object shaped like one, is not. */
export declare function isEstablishment(value: unknown): value is Establishment;
/** Whether `value` is an interruption `admitPrimary` or `resumePrimary` answered: a copy, or an object shaped like one, is not. */
export declare function isInterruptAdmission(value: unknown): value is InterruptAdmission;
/**
 * Builds and brands the `Establishment` of `primary`: the one `isEstablishment`
 * accepts. Called only by `admit.mts` (`establishWithoutAsking`) and by
 * `askEvery`, once every requirement answered `establish`.
 */
export declare const establish: (primary: PrimaryAuthentication) => Establishment;
/**
 * Asks every requirement with `admitPrimary` not in `done`, in registration
 * order, about `composed`; one that completed is not asked again in this
 * login, whatever it added. The first interruption wins, carrying the
 * continuation and an `open` that validates the answer. A throw, or an
 * answer that is neither `establish` nor an interruption, is `unavailable`.
 * Called only by `admit.mts` (`admitPrimary`, `resumePrimary`), after its
 * checks of the primary.
 */
export declare function askEvery(deps: AdmissionDeps, requirements: SessionRequirementResolver, composed: PrimaryAuthentication, primary: PrimaryAuthentication, done: readonly CompletedRequirement[]): Promise<PrimaryAdmission>;
//# sourceMappingURL=establishment.d.mts.map