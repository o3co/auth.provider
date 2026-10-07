/**
 * What an audit event says about the grant it concerns (#593, D18).
 *
 * Its own module because three emitters need the same answer and they cannot
 * import each other: core's retrieval, core's revocation library call, and —
 * through the package boundary — the routes. A helper living in any one of
 * them would be the copy the other two drift from, which is what happened
 * before this existed.
 */
import type { FederationGrantAuditEvent } from "./retrieve.mjs";
import { type FederationGrant } from "./types.mjs";
/**
 * What an event can say about the grant it ended (D18).
 *
 * D18 carries the caller, the owner, the upstream subject, the connection, the
 * resource and the scopes **where they have been established** — and for a
 * revocation they are, because the record the write returned is the
 * establishment. Leaving them out made the revocation events the only ones in
 * the family that did not say *what access ended*: an operator reading
 * `federation.grant.revoked` got a grant id and a connection name, and had to
 * go and look up the upstream account and the scopes that had just been taken
 * away — at exactly the moment the record may be a tombstone.
 *
 * A grant revoked while `pending` has none of it, and that absence is the
 * honest answer rather than a blank: nothing was ever authorized.
 *
 * Copies, so that a sink which holds its argument cannot be handed a reference
 * into a record the caller is still working with.
 */
export declare function federationGrantAuditMetadata(grant: FederationGrant): Pick<FederationGrantAuditEvent, "connection" | "upstream" | "resource" | "scopes">;
//# sourceMappingURL=auditMetadata.d.mts.map