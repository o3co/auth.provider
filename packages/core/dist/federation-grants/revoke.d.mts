import type { FederationGrantAuditEvent } from "./retrieve.mjs";
import type { FederationGrantStore, FederationGrantWrite } from "./store.mjs";
import type { FederationGrant, FederationGrantRevokedBy } from "./types.mjs";
/**
 * The correlation ID an operation's events carry (#618): the caller's, when it
 * gave one that is not empty, and otherwise one generated for the operation —
 * an empty string correlates nothing, and is not a value a caller means.
 * Called once per operation, so that everything the operation audits shares
 * the one ID.
 */
export declare function federationGrantCorrelationId(given: string | undefined): string;
export interface FederationGrantAdministrationDeps {
    readonly store: FederationGrantStore;
    /** Sampled at the write, never once per batch. */
    now(): Date;
    /**
     * Told what was ended, after it was ended. A sink that throws changes
     * nothing: the record is already revoked, and reporting otherwise would be
     * worse than not reporting at all.
     */
    audit?(event: FederationGrantAuditEvent): void | Promise<void>;
    /**
     * What correlates this call's events with the caller's own record of it —
     * a request ID, a job ID. Absent, the events get one of their own (#618):
     * a correlation ID that is empty correlates nothing, and an operator
     * reading the sink still has to tell one pass from another.
     */
    readonly correlationId?: string;
}
/**
 * End one grant.
 *
 * It calls the store's own atomic, always-winning write and **does not read
 * the record first**. A read in front of this would refuse exactly the cleanup
 * an operator needs most: the Redis store deliberately allows revoking a
 * record whose credential cannot be decoded, and a record nobody can decode is
 * one that must still be endable.
 *
 * `{ ok: false }` is not a failure. It means the write changed nothing —
 * because the grant is already revoked, or is not there — and a Store retrying
 * after a timeout must be able to tell that from an outage. An outage rejects.
 */
export declare function revokeFederationGrant(deps: FederationGrantAdministrationDeps, grantId: string, by: FederationGrantRevokedBy): Promise<FederationGrantWrite>;
/**
 * Every record this subject has, in no particular order — `pending` ones and
 * retained terminal ones included.
 *
 * A page that listed only active grants would hide the authorization a user is
 * in the middle of giving, and the one they are wondering why they lost.
 *
 * An outage rejects rather than answering `[]`. "You have no connected
 * applications" is a sentence a user acts on.
 */
export declare function listFederationGrantsForSubject(deps: FederationGrantAdministrationDeps, subject: string): Promise<readonly FederationGrant[]>;
//# sourceMappingURL=revoke.d.mts.map