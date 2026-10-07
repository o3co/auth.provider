import type { FederationTokenStore } from "../federation-tokens/types.mjs";
import type { EventLogger } from "../logging/Logger.mjs";
import type { RefreshTokenFamilyRevocation } from "../refresh-token-family/types.mjs";
import { type SessionCloseCause, type SessionLifecycleStore } from "../user-sessions/lifecycle/types.mjs";
import type { RegisteredRP, SubjectSessionIndex, UserSession, UserSessionStore } from "../user-sessions/types.mjs";
import type { SessionCloseNotifier } from "./notifier.mjs";
/** The session a record is opened for: its subject and its own end. */
export interface SessionOpenRequest {
    readonly sub: string;
    /** The end the user session will carry. */
    readonly expiresAt: Date;
}
/**
 * `opened`: the session's record is active for that subject and end, written
 * now or already. `refused`: the sid holds another session's record (another
 * subject or end, or one closing or closed), or the end has passed; nothing
 * was written, and nothing is established on that sid. A store that cannot
 * answer rejects the call with its own error; nothing is established on it.
 */
export type SessionOpenOutcome = {
    readonly outcome: "opened";
} | {
    readonly outcome: "refused";
};
/** What a join adds to a session. At least one is named. */
export interface SessionJoinRequest {
    /** A relying party that completed a token exchange in the session. */
    readonly rp?: RegisteredRP;
    /** The refresh-token family issued in it. Revoked by the service when the join is refused. */
    readonly familyId?: string;
    /** An upstream federation linked to it. Its tokens are removed by the service when the join is refused. */
    readonly federation?: string;
}
/**
 * `joined`: hand out what joined. `refused`: the session is closing, closed,
 * gone or has no record; hand out nothing (the service has already revoked
 * the family and removed the federation's tokens). A store that cannot
 * answer rejects the call with its own error; hand out nothing.
 */
export type SessionJoinOutcome = {
    readonly outcome: "joined";
} | {
    readonly outcome: "refused";
};
/**
 * `done`: the session is closed and every item of its close work ran, or it
 * has no record — never opened, or lapsed at its end on the store's clock —
 * and there is nothing to run. `pending`: the closing commit has landed — no
 * liveness read answers `live` from it on and nothing joins — while work is
 * still outstanding; a later close of the session or the sweep resumes it.
 * Both carry the relying parties (`client_id`) and federations the record's
 * snapshot holds, the federations in the order they joined; none for a
 * session with no record. A run overlapping a close that completed may
 * answer `pending` once the closed record has left the store (evicted, as
 * after its retention); a subject revocation may then report that sid not
 * revoked until a retry.
 * The call rejects, with the store's own error, when the closing commit did
 * not land or whether it did could not be read.
 */
export type SessionCloseOutcome = {
    readonly outcome: "done" | "pending";
    readonly rps: readonly string[];
    readonly federations: readonly string[];
};
/**
 * `listed`: the federations a session's record holds, in the order they
 * joined — what the close that makes the closing commit answers; none for a
 * session with no record. A store that cannot answer rejects the call with
 * its own error.
 */
export type SessionFederations = {
    readonly outcome: "listed";
    readonly federations: readonly string[];
};
/**
 * `live`, with the user session, while its record is active and the user
 * session stands as admission's live read judges a record; `not_live` from
 * the closing commit on, for a session with no record, or once the user
 * session is gone or at or past its end, whatever its store still answers.
 * A store that cannot answer rejects the call with its own error.
 */
export type SessionLiveness = {
    readonly outcome: "live";
    readonly session: UserSession;
} | {
    readonly outcome: "not_live";
};
/** How many closing sessions one resumption left `done`, still `pending`, or could not read. */
export interface SessionResumeReport {
    readonly done: number;
    readonly pending: number;
    readonly unavailable: number;
}
/** The session lifecycle, filled in the `sessionLifecycle` slot. */
export interface SessionLifecycle {
    /** Opens the lifecycle of the session `sid` as it is established. Idempotent for the same subject and end. */
    open(sid: string, request: SessionOpenRequest): Promise<SessionOpenOutcome>;
    /** Adds what `request` names to the live session `sid`, only while it is not closing. */
    join(sid: string, request: SessionJoinRequest): Promise<SessionJoinOutcome>;
    /** Closes `sid` for `cause` (the first close's cause is kept), and runs or resumes its close work. */
    close(sid: string, cause: SessionCloseCause): Promise<SessionCloseOutcome>;
    /** Whether `sid` is live: `not_live` for a sid the port cannot hold, which names no session. */
    liveness(sid: string): Promise<SessionLiveness>;
    /**
     * The federations `sid` joined, before it is closed: what a logout reads to
     * end the first one upstream with the tokens a close removes. None for a
     * sid the port cannot hold, which names no session.
     */
    federations(sid: string): Promise<SessionFederations>;
    /** Runs the close work of every closing session. Rejects when the closing listing cannot be read. */
    resumePending(): Promise<SessionResumeReport>;
}
export interface SessionLifecycleOptions {
    readonly store: SessionLifecycleStore;
    readonly userSessionStore: UserSessionStore;
    readonly refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation;
    readonly federationTokenStore: FederationTokenStore;
    /** Absent: a close removes no subject index entry. */
    readonly subjectSessionIndex?: SubjectSessionIndex;
    /**
     * How to read the notifier when a close runs: at the closing commit and
     * when it tells. Absent, or answering `undefined`: a close tells no relying
     * party.
     */
    readonly notifier?: () => SessionCloseNotifier | undefined;
    /**
     * How long a closing record is kept from its closing commit, in whole
     * milliseconds from 0 to a year: the longest refresh-token lifetime, so
     * pending close work outlives every token it revokes.
     */
    readonly retainMs: number;
    /** Defaults to `consoleLogger`. */
    readonly logger?: EventLogger;
}
export declare function createSessionLifecycle(options: SessionLifecycleOptions): SessionLifecycle;
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        readonly sessionLifecycle?: SessionLifecycle;
    }
}
//# sourceMappingURL=service.d.mts.map