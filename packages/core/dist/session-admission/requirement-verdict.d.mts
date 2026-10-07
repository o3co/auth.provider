/**
 * What admission's step 5 makes of the requirements: the action's effective
 * grade, each answer read once and held to the four verdicts, and a
 * `step_up` that stands only over a live session from a requirement with a
 * page. Each warning here is said once per process per name.
 */
import type { UserSession } from "../user-sessions/types.mjs";
import type { AdmissionAction } from "./actions.mjs";
import type { AdmissionDeps, RegisteredRequirement, RegisteredStepUpPage, RequirementVerdict, SessionView } from "./requirement.mjs";
/** A requirement's answer read once — `outcome` and `whenStillUnmet` — into a plain object; anything that is not an object as it is. */
export declare const copyVerdict: (answer: unknown) => unknown;
/** Whether `value` is one of the four verdicts, its `step_up` with a `whenStillUnmet` (and no page: the registered one answers). */
export declare const isVerdict: (value: unknown) => value is RequirementVerdict;
/** A live record step 2 read, beside admission's view of it. */
export interface LiveRecord {
    readonly session: UserSession;
    readonly view: SessionView;
    /** The record's renewal nonce as step 3b read it; `undefined` when it holds none. */
    readonly renewalNonce: string | undefined;
}
/**
 * Step 5's verdict, with the requirement that gave it. An outage never gets
 * here — step 5 answers `unavailable` itself — and a `step_up` carries the
 * live session it was taken over and the requirement whose reach bounds its
 * hint: `stepUpVerdict` makes one over no session `reauthenticate`.
 */
export type RequirementOutcome = {
    readonly outcome: "met";
} | {
    readonly outcome: "reauthenticate";
    readonly requirement: string;
} | {
    readonly outcome: "step_up";
    readonly requirement: string;
    readonly stepping: RegisteredRequirement;
    readonly session: UserSession;
    readonly view: SessionView;
    readonly page: RegisteredStepUpPage;
    readonly whenStillUnmet: "reauthenticate" | "unmet";
} | {
    readonly outcome: "unmet";
    readonly requirement: string;
};
/**
 * A requirement's `step_up` as admission takes it: over no session (no
 * store, or a token carrier without a record) it is `reauthenticate`, since
 * nothing can be stepped up onto no session and a login can; from a
 * requirement that registered no page it is `unmet`, since nothing could
 * finish the trip. Each is logged once per process per name. So a `step_up`
 * always carries a live session and a page.
 */
export declare function stepUpVerdict(name: string, requirement: RegisteredRequirement, whenStillUnmet: "reauthenticate" | "unmet", live: LiveRecord | null, deps: AdmissionDeps): RequirementOutcome;
/**
 * The action as the requirements see it, one frozen object every requirement
 * is handed: a registered action as registered, or the `remediation` core
 * issued to one of these requirements (the request check refuses any other),
 * which skips them.
 */
export declare function effectiveAction(asked: AdmissionAction): AdmissionAction;
//# sourceMappingURL=requirement-verdict.d.mts.map