/**
 * `POST /oauth/federation-grants` and `POST /oauth/federation-grants/:grantId/reauthorize`
 * (#593, D6, slice 6) — a confidential client lodging an intent: a first grant,
 * or a renewal of one it holds.
 *
 * A shell around core's lodging, as the token route is around the retrieval. It
 * adds transport, client authentication (the router's), serialization,
 * correlation and audit, and decides nothing core decides: which connections a
 * client may use, what a redirect URI must be, which scopes an intent may ask
 * for, the lifetime, the bound, the order of the two writes, the backstop.
 *
 * What it does NOT do: look up or provision a local user — `sub` is an
 * assertion until a browser session proves it (D7) — contact the upstream,
 * create a consent, write a credential, establish a session, or activate
 * anything. The answer is where to send the user, and nothing more.
 */
import { type AuditSink, type FederationGrantAcquisitionConnection, type FederationGrantIntentStore, type FederationGrantStore, type Logger } from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
import type { FederationGrantBackground } from "./background.mjs";
/** What the router is given to mount the two lodging routes. */
export interface FederationGrantAcquisitionRouteOptions {
    readonly intentStore: FederationGrantIntentStore;
    /** Every configured connection, each with its callback. */
    readonly connections: ReadonlyMap<string, FederationGrantAcquisitionConnection>;
    /** From `resolveFederationGrantAcquisitionLimits`. */
    readonly limits: {
        readonly defaultLifetimeMs: number;
        readonly maxLifetimeMs: number;
    };
}
export interface FederationGrantLodgeHandlerOptions {
    readonly store: FederationGrantStore;
    readonly acquisition: FederationGrantAcquisitionRouteOptions;
    /** The subject's GRANTS boundary (D13). */
    readonly grantsBoundary: (subject: string) => Promise<Date | null>;
    readonly limits: {
        readonly maxExpiresInMs: number;
        readonly revocationSkewMs: number;
    };
    readonly background: FederationGrantBackground;
    /** `oauth.jwt.issuer`: `connect_uri` is built on it, never on a Host header a caller chose. */
    readonly issuer: string;
    readonly now?: () => Date;
    readonly auditSink?: AuditSink;
    readonly logger?: Logger;
}
/** Where the browser starts: the connect route, on the issuer, carrying the handle. */
export declare function federationGrantConnectUri(issuer: string, handle: string): string;
export declare function createFederationGrantCreateHandler(options: FederationGrantLodgeHandlerOptions): RequestHandler;
export declare function createFederationGrantReauthorizeHandler(options: FederationGrantLodgeHandlerOptions): RequestHandler;
//# sourceMappingURL=lodgeRoute.d.mts.map