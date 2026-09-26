/**
 * Core's audit events carried to the deployment's sink (#593, D18).
 *
 * **The sink's promise is returned, not detached.** `emitAuditEvent` — which
 * every other module-side emission goes through — calls `sink.record(event)`
 * and swallows the promise. That is right where the emitter is answering a
 * request and will be gone before the sink settles; it is wrong here, because
 * core bounds its own audit waits and hands them to the background registry,
 * and a promise nobody holds is one a shutdown cannot drain. The event most
 * often lost that way is the audit of a refresh that landed after the
 * response — the one an operator goes looking for.
 *
 * **Core's omissions are preserved.** For a grant that is unknown to the
 * caller, or one that was never authorized, core supplies no connection, no
 * upstream and no scopes. This does not read them: for the never-authorized
 * case there is nothing to read, and for the unknown-grant case a read would
 * answer the question that the identical 404 exists to refuse.
 *
 * The outcome is copied as core built it. It needs no sanitizing here because
 * core no longer builds one from an unchecked stored code — the allow-list is
 * applied where the reason is constructed (D11), which is the only place a
 * mutation pass can hold it.
 */
import type { AuditSink, FederationGrantAuditEvent } from "@o3co/auth-provider-core";
export interface FederationGrantAuditBridgeOptions {
    /** Absent on a deployment that declared `audit.sink.type = "none"`. */
    readonly sink?: AuditSink;
    readonly ip?: string;
    readonly userAgent?: string;
    /** Which route the event came from: status writes a backstop revocation too. */
    readonly operation: "token" | "status" | "revoke" | "request" | "connect";
    /** Sampled when the event is handed over, not when the request arrived. */
    readonly now: () => Date;
}
/**
 * The `audit` seam of `RetrieveFederationGrantTokenDeps`, and what the status
 * route's backstop write goes through.
 */
export declare function createFederationGrantAuditBridge(options: FederationGrantAuditBridgeOptions): (event: FederationGrantAuditEvent) => Promise<void>;
export interface RouteDeniedEventInput {
    /**
     * Defaults to the token route's. A refused withdrawal is its own type: a
     * dashboard counting denied disclosures would otherwise count them
     * together, and they mean opposite things — one is a credential not handed
     * out, the other a credential still live that somebody tried to end.
     */
    readonly type?: "federation.grant.token.denied" | "federation.grant.revoke.denied" | "federation.grant.request.denied" | "federation.grant.authorization_failed";
    readonly correlationId: string;
    readonly grantId: string;
    /** A fixed identifier: `invalid_request`, `invalid_client`, `rate_limited/provider`, … */
    readonly outcome: string;
    /** Only once client authentication has established it. */
    readonly clientId?: string;
    /** Only once the body has been parsed; it is an assertion, not an identity. */
    readonly subject?: string;
    /** Slice 6: the connection a connect flow was for, once its intent is known. */
    readonly connection?: string;
}
/**
 * A `.token.denied` for an exit that never reached core: a body that would not
 * parse, an authentication that failed, this provider's own throttle, a
 * request admitted as the process began to shut down.
 *
 * `clientId` and `subject` are empty until each has been established. Before
 * authentication there is a Basic username and an assertion `iss` on the
 * request, and neither has been verified — promoting one into `clientId` puts
 * an unauthenticated caller's claim into the field an operator reads as "this
 * client did it".
 */
export declare function routeDeniedEvent(input: RouteDeniedEventInput): FederationGrantAuditEvent;
//# sourceMappingURL=audit.d.mts.map