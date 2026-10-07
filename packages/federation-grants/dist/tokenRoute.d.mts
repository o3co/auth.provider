/**
 * `POST /oauth/federation-grants/:grantId/token` (#593, D9–D12).
 *
 * A shell around `retrieveFederationGrantToken`, and deliberately nothing
 * more. It adds transport, authentication, serialization, correlation and
 * audit; every decision about the grant itself is core's.
 *
 * ### What this must not do
 *
 * The mistake this design expects is an "obvious" authorization check placed
 * in FRONT of core — rejecting a client with no connection allowlist, or a
 * grant whose connection an operator removed, or one carrying an
 * ineligibility marker, before the retrieval is called. Each of those reads
 * as a tightening and each changes a settled answer:
 *
 *   - a revoked grant answers 410 whether or not the client may use its
 *     connection, because the user revoking it is the more useful truth; an
 *     allowlist check in front turns that into 403, which tells a caller the
 *     grant would work if their registration changed;
 *   - a grant with an ineligibility marker still has a usable cached token,
 *     and core serves it; refusing here withholds a token nothing is wrong
 *     with.
 *
 * Nor does it retry a denial (a "helpful" second attempt can cost a second
 * upstream rotation), recompute `expires_in`, turn an unmet `min_ttl` into an
 * error, reclassify an upstream's refusal, manage locks, add a timeout that
 * abandons the retrieval's worker, delete a credential it could not read, or
 * look in another grant or in the session-bound token store.
 *
 * It does not read `lastLook` either. That is core's private orchestration.
 */
import { type AuditSink, type FederationGrantConnection, type FederationGrantRefresher, type FederationGrantRetrievalLimits, type FederationGrantStore, type Logger } from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
import type { FederationGrantBackground } from "./background.mjs";
export interface FederationGrantTokenHandlerOptions {
    readonly store: FederationGrantStore;
    /** The connections as they are configured NOW; a removed one is simply absent. */
    readonly connections: ReadonlyMap<string, FederationGrantConnection>;
    readonly refresher: (connection: FederationGrantConnection) => FederationGrantRefresher | undefined;
    /**
     * The subject's grants boundary (D13). Throwing is the honest answer when
     * the deployment has no subject-revocation capability: `null` would say
     * "nothing was revoked", which is not something an absent boundary knows.
     */
    readonly grantsBoundary: (subject: string) => Promise<Date | null>;
    readonly limits: FederationGrantRetrievalLimits;
    readonly background: FederationGrantBackground;
    readonly now?: () => Date;
    readonly auditSink?: AuditSink;
    readonly logger?: Logger;
}
export declare function createFederationGrantTokenHandler(options: FederationGrantTokenHandlerOptions): RequestHandler;
//# sourceMappingURL=tokenRoute.d.mts.map