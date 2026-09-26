import { type FederationGrantIntentStore } from "./intentStore.mjs";
import type { FederationGrantStore } from "./store.mjs";
import type { FederationGrant, FederationGrantConnection, FederationGrantExpiredReason, FederationGrantIneligibilityReason, FederationGrantRevokedBy } from "./types.mjs";
/** A connection as acquisition needs it: with the callback its flow returns to. */
export interface FederationGrantAcquisitionConnection extends FederationGrantConnection {
    /** `federationGrants.connections.<name>.callbackURL`, exactly as configured. */
    readonly callbackUri: string;
}
/** What lodging needs of the client that asked, as it was authenticated. */
export interface FederationGrantLodgingClient {
    readonly clientId: string;
    readonly allowedFederationGrantConnections?: readonly string[];
    readonly federationGrantRedirectUris?: readonly string[];
}
export interface FederationGrantLodgingDeps {
    readonly grantStore: FederationGrantStore;
    readonly intentStore: FederationGrantIntentStore;
    /** Every configured connection, by name. */
    readonly connections: ReadonlyMap<string, FederationGrantAcquisitionConnection>;
    /** Milliseconds. From `resolveFederationGrantAcquisitionLimits`. */
    readonly limits: {
        readonly defaultLifetimeMs: number;
        readonly maxLifetimeMs: number;
    };
    /** Sampled at every write, not once per request: the race across a deadline depends on it. */
    readonly now?: () => Date;
    /** 256 bits, base64url. A seam for tests; the default is `randomBytes(32)`. */
    readonly randomId?: () => string;
    /** The subject's GRANTS boundary (D13) — never the sessions one. */
    readonly grantsRevokedBefore: (subject: string) => Promise<Date | null>;
    readonly revocationSkewMs: number;
    /** `federationGrants.maxExpiresIn`, in milliseconds, as retrieval reads it. */
    readonly maxExpiresInMs: number;
}
interface CommonRequest {
    readonly client: FederationGrantLodgingClient;
    readonly subject: string;
    readonly redirectUri: string;
    readonly clientState: string;
    /** Omitted means the connection's full set. */
    readonly scopes?: readonly string[];
    /** Omitted means the default. Clamped to the maximum, never refused for being large. */
    readonly requestedLifetimeMs?: number;
    readonly upstreamSubject?: string;
    readonly correlationId: string;
}
export interface FederationGrantLodgingRequest extends CommonRequest {
    readonly connection: string;
}
export interface FederationGrantReauthorizationRequest extends CommonRequest {
    readonly grantId: string;
    /**
     * The connection the caller believes the grant is on — an assertion, as on
     * the token route, and never a way to move the grant to another one.
     */
    readonly connection?: string;
}
/** Why a request was refused before anything was written, or why a write failed. */
export type FederationGrantLodgingRefusal = "connection_not_permitted" | "connection_not_configured" | "redirect_uri_not_registered" | "redirect_uri_invalid" | "redirect_uri_reserved_parameter" | "scope_exceeded" | "openid_required" | "offline_access_required" | "scope_subsets_not_allowed" | "expires_in_out_of_range" | "intent_limit" | "storage";
export interface FederationGrantLodged {
    readonly ok: true;
    readonly grantId: string;
    /** What `connect_uri` carries. Single-use, 256 bits. */
    readonly handle: string;
    /** The flow's one deadline. */
    readonly intentExpiresAt: Date;
    /** The grant lifetime that applied, after the clamp. */
    readonly lifetimeMs: number;
    /** What was lodged, for the audit of it: the connection, the resolved scopes, the resource. */
    readonly connection: string;
    readonly scopes: readonly string[];
    readonly resource?: string;
}
export type FederationGrantLodgingResult = FederationGrantLodged | {
    readonly ok: false;
    readonly reason: FederationGrantLodgingRefusal;
};
export type FederationGrantReauthorizationResult = (FederationGrantLodged & {
    /**
     * The grant's effective status, unchanged: a renewal does not make it
     * pending, and does not end a starvation — `upstream_token_ineligible`
     * is what a grant admitted for `scope_exceeded` still reads (#616).
     */
    readonly status: FederationGrantRenewableStatus;
}) | {
    readonly ok: false;
    readonly reason: FederationGrantLodgingRefusal;
} | {
    readonly ok: false;
    readonly reason: "grant_not_found" | "authorization_pending" | "connection_mismatch";
} | {
    readonly ok: false;
    readonly reason: "connection_identity_changed";
} | {
    readonly ok: false;
    readonly reason: "grant_revoked";
    readonly revokedBy: FederationGrantRevokedBy;
    /** Whether THIS call wrote the revocation — what decides whether it is audited. */
    readonly revokedNow: boolean;
    /** The record the write returned, when `revokedNow`: what the audit of it describes (D18). */
    readonly revoked?: FederationGrant;
} | {
    readonly ok: false;
    readonly reason: "grant_expired";
    readonly expiredBy: FederationGrantExpiredReason;
} | {
    readonly ok: false;
    readonly reason: "upstream_token_ineligible";
    readonly ineligibleBy: FederationGrantIneligibilityReason;
} | {
    readonly ok: false;
    readonly reason: "key_unavailable";
};
/**
 * The reserved result parameter a redirect URI already carries, if any.
 *
 * Exported so that where the URI is REGISTERED can refuse it too — at boot, for
 * a deployment whose clients are configured — and lodging keeps refusing it as
 * the belt for a repository that validates nothing.
 */
export declare function federationGrantRedirectUriReservedParameter(uri: string): string | undefined;
/**
 * Lodges a first-time intent: validates what the client asked for, admits the
 * intent, and creates the `pending` grant that names it (D6, D16).
 */
export declare function lodgeFederationGrantIntent(deps: FederationGrantLodgingDeps, request: FederationGrantLodgingRequest): Promise<FederationGrantLodgingResult>;
/**
 * Lodges a renewal of an existing grant (D6): ownership, then the revocation
 * backstop before anything else is asked of it (D13), then what a renewal can
 * and cannot mend, then the client's current permission and its request — and
 * only then the two writes.
 */
export declare function lodgeFederationGrantReauthorization(deps: FederationGrantLodgingDeps, request: FederationGrantReauthorizationRequest): Promise<FederationGrantReauthorizationResult>;
/** The statuses a renewal is admitted from, which its 201 reports unchanged (D6, #616). */
export type FederationGrantRenewableStatus = "active" | "reauthorization_required" | "upstream_token_ineligible";
export {};
//# sourceMappingURL=lodge.d.mts.map