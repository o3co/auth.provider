import { type UserSession, type UserSessionStore } from "../user-sessions/types.mjs";
import type { CheckedRequest } from "./request-check.mjs";
import type { Admission } from "./requirement.mjs";
/**
 * What steps 1 to 4 end in: the answer, when one of them gave it; else the
 * live record, or `null` when there is no store or a token carrier has no
 * `sid`, with whether the store it was read from has the step-up capability
 * (`supportsSecondFactorUpdate`, read once, over a live record alone;
 * `false` without one).
 */
export type LiveSession = {
    readonly answer: Admission;
} | {
    readonly session: UserSession | null;
    readonly storeRecords: boolean;
    /** The record's renewal nonce, read once; `undefined` without a record or one that holds none. */
    readonly renewalNonce: string | undefined;
};
/**
 * Whether a record a store answered stands as a session at `now`: it names a
 * subject, holds a valid `authTime`, and ends after `now`. The port does not
 * promise that `get` filters expiry, so a store that keeps a row until a sweep
 * answers one past its end, which is no session; a record missing what it
 * declares is none either. The live read below and the session lifecycle's
 * liveness judge a record by this rule alone.
 */
export declare const isLiveRecord: (record: UserSession | null | undefined, now: Date) => record is UserSession;
/** The one read of a session record admission makes: the store's answer, or its rejection. */
export declare const readRecord: (store: UserSessionStore, sid: string) => Promise<UserSession | null | undefined>;
/** Reads the session `checked.claim` names, as `admitSession`'s steps 1 to 4. */
export declare function readLiveSession(checked: CheckedRequest, unavailable: (store: string, err: unknown) => Admission): Promise<LiveSession>;
//# sourceMappingURL=live-session.d.mts.map