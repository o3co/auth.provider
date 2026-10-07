/**
 * The account page's management of the signed-in subject's second factors,
 * under `/session/mfa/factors`, mounted from `routes.mts` behind its
 * `no-store`, body parsing, CSRF and flood guards, each route admitting the
 * session through `routes.mts` first.
 *
 * - `GET /factors`, admitted as `mfa.view`: every record of the subject, oldest
 *   first, with its state as `factorState.mts` reads it for the session's login
 *   address, the records read as every judgment over them reads them
 *   (`readSubjectRecords`: a recovery set below the subject's recovery-set
 *   floor `retired`) — and a usable or exhausted recovery set's codes left and
 *   whether they were ever answered (`recovery_codes_shown`); never a
 *   record's data. A record
 *   whose data or digest needs a key the ring no longer holds is said at error
 *   with that key's id.
 * - `POST /factors/rename {factor_id, label}`, admitted as `mfa.manage`: the
 *   label written by compare-and-set at the version read, the data and last use
 *   as read; a lost race is `409`, nothing retried; an answer without that label
 *   or that last use is outside the port, `503`.
 * - `POST /factors/remove {factor_id}`, admitted as `mfa.manage`, run whole by
 *   `factorSet.mts` (the read, this file's refusal, the removal, the witness),
 *   held to the start the admission carries — the subject's generation read
 *   before it — one write of the subject's at a time: another in the way past
 *   its wait is `409 mfa_factors_busy` with `Retry-After`; a recovery or a
 *   reset since it began, or another write of the subject's factors landing
 *   after the removal read them (a writer past its own lease), `409
 *   mfa_factors_changed`, nothing removed; one that
 *   ran past its hold said at error whatever it came to, a removal it made
 *   audited and answered `409 mfa_factors_changed`. Under `required`, removing
 *   an installed counting factor is refused `409` when no other usable counting
 *   record stands — one unreadable or `address_changed` does not. Audited
 *   `mfa.factor.removed`; a re-read that failed, and a witness clear that
 *   failed, are said at warn, the removal standing.
 * - A factor named that is not the subject's is `400`; a store that cannot
 *   answer, or answers outside its port's contract, is `503`, logged once.
 */
import { type AuditSink, type Logger, type MfaFactorResolver, type MfaFactorStore } from "@o3co/auth-provider-core";
import { type Request, type Response, type Router } from "express";
import type { MfaAdmissionAction } from "./admissionActions.mjs";
import { type MfaCeremonySession } from "./ceremony.mjs";
import type { MfaFactorSet, MfaFactorSetStart } from "./factorSet.mjs";
import type { MfaRequirementMode } from "./requirement.mjs";
import type { MfaSealing } from "./sealing.mjs";
/** A session admitted as `mfa.manage`: with where its factor-set write begins, taken before the admission. */
export type MfaManagingSession = MfaCeremonySession & {
    readonly factorSetStart: MfaFactorSetStart;
};
export interface MfaManagementOptions {
    readonly factors: MfaFactorResolver;
    readonly factorStore: Pick<MfaFactorStore, "update">;
    /** The subject's records as read, and their removal with the witness after it. */
    readonly factorSet: MfaFactorSet;
    readonly sealing: MfaSealing;
    /** `mfa.mode`: under `required` the last usable counting factor stays. */
    readonly mode: MfaRequirementMode;
    /** The signed-in session the request's cookie carries, admitted for `action`; `undefined` once the refusal is answered. */
    readonly admit: <Action extends MfaAdmissionAction>(req: Request, res: Response, action: Action) => Promise<(Action extends "mfa.manage" ? MfaManagingSession : MfaCeremonySession) | undefined>;
    readonly logger: Logger;
    readonly auditSink: AuditSink | undefined;
}
/** The management routes' router (see this file's header). */
export declare function createMfaManagementRouter(options: MfaManagementOptions): Router;
//# sourceMappingURL=management.d.mts.map