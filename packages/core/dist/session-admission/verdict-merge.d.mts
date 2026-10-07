/**
 * Step 7 of `admitSession`: the requirements' verdict and the `acr`
 * selection merged by the session-admission ADR's table. The hint of a
 * `step_up` it answers lists only the entries the stepping requirement's own
 * trip can finish. In the met + step_up row, a step-up through the
 * second-factor authority is never offered for `acr_values` onto a session
 * whose view says no second factor can be recorded on it
 * (`SessionView.secondFactorRecordable`, decided by admission as it builds
 * the view): the answer is a new login (`reauthenticate`, `acr`) instead.
 */
import type { AcrSelection } from "./acr.mjs";
import type { Admission, AdmissionDeps, RegisteredRequirement } from "./requirement.mjs";
import type { LiveRecord, RequirementOutcome } from "./requirement-verdict.mjs";
export interface MergeContext {
    /** The live record and admission's view of it; `null` without one. */
    readonly live: LiveRecord | null;
    /** No requested value is in the table: no login can meet the request. */
    readonly noneConfigured: boolean;
    readonly requirements: readonly (readonly [string, RegisteredRequirement])[];
    /** The vouched `amr`. */
    readonly held: readonly string[];
    readonly table: AdmissionDeps["acrTable"];
    /** What a code minted on an admitted answer records: the answer's `codeFields`. */
    readonly codeFields: Extract<Admission, {
        readonly outcome: "admitted";
    }>["codeFields"];
}
/** The merge table of ADR 2026-09-28-session-admission: `R` the requirements' verdict, `A` the acr selection (`undefined` when nothing was asked). */
export declare function merge(R: RequirementOutcome, A: AcrSelection | undefined, context: MergeContext): Admission;
//# sourceMappingURL=verdict-merge.d.mts.map