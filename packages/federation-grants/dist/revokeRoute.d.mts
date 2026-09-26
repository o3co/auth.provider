/**
 * `POST /oauth/federation-grants/:grantId/revoke` — the owning client ends its
 * own grant (#593, D9, D13).
 *
 * The route a backend calls when the integration is removed on its side: the
 * user disconnected the calendar, the workspace was deleted, the agent is
 * being decommissioned. Without it the only way to end a grant is a
 * subject-wide revocation, which ends everything else the user has too.
 *
 * **Ownership is the whole check.** The grant is this client's and this
 * subject's, or it is not there — and after that nothing else is consulted: no
 * connection allowlist, no current connection configuration, no revision, no
 * eligibility, no expiry, no boundary. Every one of those exists to decide
 * whether a credential may be *disclosed*, and none of them is a reason to
 * refuse a withdrawal. A grant whose connection was removed from the
 * configuration, whose encryption key is out of the ring, or which expired
 * last week and is still retained, is exactly the grant an operator most needs
 * to be able to end.
 *
 * It reads with `find` and not `open` or `inspect`: ownership lives on the
 * record, and a credential that will not open is not a reason to keep a grant
 * alive.
 *
 * **204, and nothing in the body.** A withdrawal has no result to report: the
 * grant is over. A second call answers 204 as well — the record is retained as
 * a tombstone for the status route, and a client retrying after a timeout must
 * not be told the second attempt failed.
 *
 * What it does NOT do: stamp either subject boundary, cascade sessions, touch
 * the subject's other grants, call the upstream, take the refresh lock, or
 * compute an effective status. Ending a grant here is a local fact about one
 * record. Revoking the upstream's own refresh token is the upstream's API and
 * a different failure domain — making a withdrawal depend on it would mean a
 * user cannot disconnect while somebody else's service is down.
 */
import { type AuditSink, type FederationGrantStore, type Logger } from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
import type { FederationGrantBackground } from "./background.mjs";
export interface FederationGrantRevokeHandlerOptions {
    readonly store: FederationGrantStore;
    readonly background: FederationGrantBackground;
    readonly now?: () => Date;
    readonly auditSink?: AuditSink;
    readonly logger?: Logger;
}
export declare function createFederationGrantRevokeHandler(options: FederationGrantRevokeHandlerOptions): RequestHandler;
//# sourceMappingURL=revokeRoute.d.mts.map