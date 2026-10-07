import { type UserSession, type UserSessionStore } from "../../user-sessions/types.mjs";
import { type AcrTable } from "../acr.mjs";
import { type Admission, type RegisteredRequirement } from "../requirement.mjs";
/** The `acr` values the rows ask for: the template's two, one only a password meets, and one nothing installed produces. */
export declare const MERGE_ACR: Readonly<{
    MFA: "urn:o3co:acr:mfa";
    PHR: "urn:o3co:acr:phr";
    PWD: "urn:example:pwd";
    KBA: "urn:example:kba";
}>;
/** The template's table, `phr` uncommented, beside one entry only a password meets and one nothing installed produces. */
export declare const MERGE_ACR_TABLE: AcrTable;
/**
 * What a step-up through the second-factor authority can add under each
 * row's factors (its `reach`, the rule's `secondFactorMethods`): each
 * factor's values, and `mfa` when one of them adds it.
 */
export declare const MERGE_REACH: Readonly<{
    /** TOTP, WebAuthn and recovery codes. */
    installed: ReadonlySet<string>;
    /** TOTP and recovery codes: no factor adds `hwk` or `swk`. */
    withoutWebAuthn: ReadonlySet<string>;
    /** Email codes alone, which do not add `mfa`. */
    emailOnly: ReadonlySet<string>;
    /** The requirement with no factor enabled: nothing can step a session up. */
    empty: ReadonlySet<string>;
    /** No factor at all: nothing can step a session up. */
    none: ReadonlySet<string>;
}>;
/** The factors a row's composition enables, by name. */
export type MergeFactors = keyof typeof MERGE_REACH;
/** A row's expected decision, in the MFA rule's vocabulary. */
export type MergeDecision = {
    readonly outcome: "met";
    readonly acr: string | undefined;
} | {
    readonly outcome: "reauthenticate";
    readonly requirement: "acr" | "baseline";
} | {
    readonly outcome: "step_up";
    readonly requirement: "acr" | "baseline";
    readonly acrValues: readonly string[];
} | {
    readonly outcome: "unmet";
    readonly requirement: "acr" | "baseline";
};
/** One row: what it checks; its mode, session, store, request and factors; and the rule's decision. */
export interface MergeRow {
    readonly row: string;
    /** The MFA module's `mfa.mode` the row runs under. */
    readonly mode: "off" | "optional" | "required";
    /** The record admission reads, `sid-1` of `user-1`; `null` for no store. */
    readonly session: UserSession | null;
    /** `false` for a session store without the step-up capability (`recordSecondFactor`); absent, the store has it. */
    readonly storeRecords?: false;
    readonly acrValues?: readonly string[];
    readonly factors: MergeFactors;
    readonly expected: MergeDecision;
}
/** A group of rows, and the title the tests run it under. */
export interface MergeRowGroup {
    readonly title: string;
    readonly rows: readonly MergeRow[];
}
/** The rows, by group: the MFA rule's decisions, the baseline beside `acr_values`, any-of entries with step-up targets, and a step-up the session cannot record. */
export declare const MERGE_ROW_GROUPS: readonly MergeRowGroup[];
/**
 * The ADR's mapping of a row's decision onto the admission, for `authority`,
 * the registered second-factor authority (`undefined` when none is
 * registered): `requirement: "acr"` stays `"acr"` (a `reauthenticate`'s too), `"baseline"` becomes the
 * authority's name, and a `step_up`'s requirement becomes `whenStillUnmet`
 * (`"acr"` → `"unmet"`, `"baseline"` → `"reauthenticate"`) with its
 * registered page. The view is admission's over `store`, the store the
 * admission ran over (`mergeSessionStore(row)`, or the test's own), or
 * `undefined` for a row with no session, or a composition without a store,
 * its `secondFactorRecordable` included; an admitted one carries the
 * session's renewal nonce when it holds one. Throws for an `authority` that is not a registered requirement
 * declaring it, and for a row that names it when none is given.
 */
export declare function mergeAdmission(expected: MergeDecision, session: UserSession | null, authority: RegisteredRequirement | undefined, store: UserSessionStore | undefined): Admission;
/**
 * The session store a row runs over: one holding the row's record as
 * `sid-1`, with the step-up capability unless the row's `storeRecords` is
 * `false` — its `recordSecondFactor` records nothing (`null`) — and
 * `undefined` for a row with no session, a composition without a store.
 */
export declare function mergeSessionStore(row: MergeRow): UserSessionStore | undefined;
//# sourceMappingURL=merge.rows.d.mts.map