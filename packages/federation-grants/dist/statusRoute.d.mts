/**
 * `POST /oauth/federation-grants/:grantId/status` (#593, D9).
 *
 * Status describes a grant's lifecycle. Token answers an issuance request.
 * Keeping them apart is what this file is:
 *
 *  - **`inspect` only.** Never `open`, never a refresh, never the refresh
 *    lock, never `touch`. Calling retrieval from here would rotate a
 *    credential at an upstream because somebody opened a dashboard, and
 *    `lastUsedAt` would record a look as a use.
 *  - **200 for every effective status**, including expired and revoked. A
 *    successful inspection of a grant that has ended is a successful
 *    inspection; answering the token route's 410 would make a dashboard read
 *    "this call failed" for a grant that is simply over.
 *  - **It is not a health check for `/token`.** `inspect` reports whether the
 *    credential authenticates, not whether the upstream will issue something
 *    usable — so `active` does not promise a token, and an ineligible status
 *    can coexist with a perfectly usable cached one.
 *
 * Two things it does write. A backstop it finds is written down, because a
 * revocation only computed would be computed again by every later reader and
 * would vanish the day the boundary is lost. And that write is audited.
 */
import { type AuditSink, type FederationGrantConnection, type FederationGrantRetrievalLimits, type FederationGrantStore, type Logger } from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
import type { FederationGrantBackground } from "./background.mjs";
export interface FederationGrantStatusHandlerOptions {
    readonly store: FederationGrantStore;
    readonly connections: ReadonlyMap<string, FederationGrantConnection>;
    readonly grantsBoundary: (subject: string) => Promise<Date | null>;
    readonly limits: FederationGrantRetrievalLimits;
    readonly background: FederationGrantBackground;
    readonly now?: () => Date;
    readonly auditSink?: AuditSink;
    readonly logger?: Logger;
}
export declare function createFederationGrantStatusHandler(options: FederationGrantStatusHandlerOptions): RequestHandler;
//# sourceMappingURL=statusRoute.d.mts.map