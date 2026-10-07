/**
 * Whether this browser may go on with this intent now: the claim's subject and
 * the express session first, then session admission on the cookie's claim as
 * the step's action, then the flow's own conditions. Asked at
 * every step; fails closed, so a store that cannot answer is an outage, never a yes.
 * A step-up admission asks for is a refusal at every step; at connect it also
 * carries the requirement's trip.
 * The connection pin is defined here once, for the judgement and the callback alike.
 */
import { type AdmissionDeps, type FederationGrantAcquisitionConnection, type FederationGrantBrowserBinding, type FederationGrantConnectTransaction, type FederationGrantIntent, type SessionClaim } from "@o3co/auth-provider-core";
import type { Request } from "express";
import type { FederationGrantsAdmissionAction } from "./admissionActions.mjs";
import type { FederationGrantBrowserRouterOptions, Unanswered } from "./browserFlow.mjs";
import type { FederationGrantLog } from "./log.mjs";
/** Where a requirement that asked this session to step up sends the browser. */
export interface StepUpTrip {
    readonly requirement: string;
    /** The requirement's page as admission answers it (`page.href`): no return parameter yet. */
    readonly page: string;
}
export type Judgement = {
    readonly ok: true;
    readonly binding: FederationGrantBrowserBinding;
} | {
    readonly ok: false;
    readonly status: number;
    /** A fixed identifier: what the audit carries, and what a navigation names. */
    readonly reason: "subject_mismatch" | "reauthentication_required" | "stale" | "connection_not_permitted" | "connection_changed";
    /**
     * At connect only, beside `reauthentication_required`: the step-up trip
     * admission asked for, which connect may take once instead of refusing.
     */
    readonly stepUp?: StepUpTrip;
} | {
    readonly ok: false;
    readonly status: 503;
    readonly reason: "unavailable";
    /**
     * What could not answer: the caller logs it, once. Absent when it was
     * the session's part, whose line admission wrote.
     */
    readonly unanswered?: Unanswered;
    /**
     * When it was the session's part: the store admission named, described as core's
     * `describeAdmissionOutage` does.
     */
    readonly admissionStore?: string;
};
/** The admission action of each browser step, as the module registers it. */
export declare const CONNECT: FederationGrantsAdmissionAction;
export declare const CONSENT: FederationGrantsAdmissionAction;
export declare const CALLBACK: FederationGrantsAdmissionAction;
/**
 * Whether THIS browser may go on with THIS intent now: the cookie names the
 * intent's subject, admission admits its session as `action`, the intent is still
 * the grant's current one, the client may still use the connection, and the
 * connection is unchanged since lodging. Asked at every step, so a revocation,
 * renewal or configuration change mid-flow stops a flow that has not finished.
 */
export declare function judge(options: FederationGrantBrowserRouterOptions, admission: AdmissionDeps, req: Request, claim: SessionClaim, action: FederationGrantsAdmissionAction, intent: FederationGrantIntent, now: () => Date): Promise<Judgement>;
/**
 * Whether the connection is still the one the intent was lodged against: present,
 * the same federation entry, both revisions and the callback. The name is pinned
 * because the revisions do not cover it, and boot probed the Store under the current one.
 */
export declare function pinned(connection: FederationGrantAcquisitionConnection | undefined, intent: FederationGrantIntent): connection is FederationGrantAcquisitionConnection;
/**
 * A judgement that could not be made, as one line: the client registry as
 * core's `client_repository_unavailable` with this route as its site, any
 * other store as the route's own outage.
 */
export declare const judgementUnavailable: (log: FederationGrantLog, route: "connect" | "consent", fields: Readonly<Record<string, string | undefined>>, intent: FederationGrantIntent, unanswered: Unanswered) => void;
/**
 * Check 3, asked before the exchange and again before activation with the same
 * claim: the same express session and durable session the flow started in,
 * admitted as the callback. An outage is `"unavailable"`, already logged by
 * admission.
 */
export declare function sessionHolds(admission: AdmissionDeps, req: Request, claim: SessionClaim, transaction: FederationGrantConnectTransaction): Promise<"ok" | "reauthentication_required" | "account_mismatch" | "unavailable">;
//# sourceMappingURL=browserJudgement.d.mts.map