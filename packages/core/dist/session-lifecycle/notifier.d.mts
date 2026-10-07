/**
 * The contract the session lifecycle tells a relying party through that a
 * session it joined has closed. Core decides when and for which cause; the
 * module that issues to relying parties implements it and decides how a
 * notice is delivered.
 */
import type { SessionCloseCause } from "../user-sessions/lifecycle/types.mjs";
/** One relying party to tell that one session has closed. */
export interface SessionCloseNotice {
    readonly sid: string;
    readonly sub: string;
    /** The relying party's `client_id`, as it joined the session. */
    readonly clientId: string;
    /** Why the session closed: its first close's cause. */
    readonly cause: SessionCloseCause;
}
/**
 * Tells relying parties that a session they joined has closed. Contributed
 * under `sessionCloseNotifiers`, at most one per composition; a composition
 * with relying parties must contribute it.
 */
export interface SessionCloseNotifier {
    /**
     * Tells `notice.clientId` that the session closed. Resolves once the
     * notice is settled: delivered, or given up by the notifier's own policy
     * (a relying party with nowhere to tell, or one that answered it will not
     * take it). Rejects only when it should be tried again: the work stays
     * pending, and a later close of the session or the sweep calls it again.
     * It may be called more than once for one notice, concurrently too.
     */
    notify(notice: SessionCloseNotice): Promise<void>;
}
//# sourceMappingURL=notifier.d.mts.map