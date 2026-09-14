import { type ClientRepository, type Logger, type PublicClient } from "@o3co/auth-provider-core";
export interface ClientIdMetadataDocumentOptions {
    /** Scopes any such client may obtain — the ceiling its document's `scope` is intersected with. Empty admits none. */
    readonly allowedScopes: readonly string[];
    /** Audiences (resource servers) any such client may mint for. Empty admits only the client id. */
    readonly allowedAudiences: readonly string[];
    /** Hosts a document may live on: exact, or a `.suffix` for a domain and its subdomains. Empty admits any public host. */
    readonly allowedHosts?: readonly string[];
    /** Hosts refused even when allowed above; same forms. */
    readonly deniedHosts?: readonly string[];
    /** Byte cap on the document. Default 5120, the draft's recommendation. */
    readonly maxBytes?: number;
    /** Fetch timeout. Default 5000 ms. */
    readonly timeoutMs?: number;
    /** Upper bound on how long a valid document is served from cache. Default 10 minutes. */
    readonly cacheMaxAgeMs?: number;
    /** Bound on remembered documents. Default {@link DEFAULT_CIMD_MAX_CACHE_ENTRIES}. */
    readonly maxCacheEntries?: number;
    /**
     * How long a cached registration may still be served after a
     * revalidation that failed for a reason that is not the document's.
     * Default {@link DEFAULT_CIMD_STALE_IF_ERROR_MS}. Zero disables it.
     */
    readonly staleIfErrorMs?: number;
    /**
     * How long a refusal is remembered, so the same id is not fetched again
     * on every request. Default {@link DEFAULT_CIMD_NEGATIVE_CACHE_MS}.
     */
    readonly negativeCacheMs?: number;
    /**
     * How many documents may be in flight at once, across every client id.
     * Default {@link DEFAULT_CIMD_MAX_CONCURRENT_FETCHES}.
     */
    readonly maxConcurrentFetches?: number;
    readonly logger?: Logger;
    /** Test seams. */
    readonly fetch?: typeof fetch;
    readonly lookup?: (hostname: string) => Promise<readonly string[]>;
    readonly now?: () => number;
}
export declare const DEFAULT_CIMD_MAX_BYTES: number;
/**
 * How many documents the resolver remembers at once. An unauthenticated
 * caller chooses the keys — any URL that serves a valid document is a
 * `client_id` — so the map is bounded, like the CRL and OCSP caches.
 */
export declare const DEFAULT_CIMD_MAX_CACHE_ENTRIES = 256;
export declare const DEFAULT_CIMD_TIMEOUT_MS = 5000;
export declare const DEFAULT_CIMD_CACHE_MAX_AGE_MS: number;
/**
 * Whether `clientId` has the shape of a Client ID Metadata Document URL
 * (draft §3.1): `https`, a path, no fragment, no credentials, no dot segments,
 * no query string, and a host that is a name rather than an address.
 *
 * Shape only — the host policy and the resolution check are the resolver's.
 * Exported so `/authorize` and the token endpoint can tell "not a client at
 * all" from "a document URL we could not honour" in their logs.
 */
export declare function isClientIdMetadataDocumentUrl(clientId: string): boolean;
/**
 * How long a cached registration outlives a revalidation this server could
 * not complete — a DNS blip, a 5xx, a timeout.
 *
 * The distinction #408 draws, applied to the cache: refusing a client
 * because someone else's server is down tells the caller their credential
 * is bad when the truth is an outage. On a cold lookup there is nothing to
 * serve and `null` is the only answer; on a warm one the registration this
 * server already validated is a better answer than breaking a working
 * client. A document the server **rejected** is not this: that client
 * stopped being a client, and its entry goes immediately.
 */
export declare const DEFAULT_CIMD_STALE_IF_ERROR_MS: number;
/**
 * How long a refusal is remembered.
 *
 * Failures were never cached, so every distinct URL-shaped `client_id` cost
 * a DNS resolution, a TLS handshake and a GET on **every** request: an
 * unauthenticated caller could pin sockets against a tarpit of its own, or
 * point this server's address at a third party and have it re-fetch a 404
 * indefinitely. Short, because a client that fixes its document must not be
 * locked out for the life of the process.
 */
export declare const DEFAULT_CIMD_NEGATIVE_CACHE_MS: number;
/**
 * How many documents may be fetched at once, across every client id.
 *
 * De-duplication was per URL, so distinct ids fanned out without limit and
 * N slow hosts held N sockets for the whole timeout each. The cap makes the
 * outbound cost of an unauthenticated request bounded rather than
 * proportional to how many ids the caller can invent.
 */
export declare const DEFAULT_CIMD_MAX_CONCURRENT_FETCHES = 8;
/**
 * Whether `client` was resolved from a Client ID Metadata Document, as opposed
 * to a pre-registered client whose id merely looks like a URL
 * (`withClientIdMetadataDocuments` answers those from the inner repository
 * first). For a document client, the host its `client_id` names is the one
 * fact about it this server verified; its `client_name` is the document
 * author's claim.
 */
export declare function isClientIdMetadataDocumentClient(client: PublicClient | null | undefined): boolean;
export interface ClientIdMetadataDocumentResolver {
    /** The registration the document at `clientId` describes, or `null` when there is none to honour. */
    resolve(clientId: string): Promise<PublicClient | null>;
}
export declare function createClientIdMetadataDocumentResolver(opts: ClientIdMetadataDocumentOptions): ClientIdMetadataDocumentResolver;
/**
 * A {@link ClientRepository} that answers pre-registered clients from `inner`
 * first and Client ID Metadata Documents second (#529). `authenticate` is
 * `inner`'s alone: a document never carries a secret.
 */
export declare function withClientIdMetadataDocuments(inner: ClientRepository, opts: ClientIdMetadataDocumentOptions): ClientRepository;
//# sourceMappingURL=clientIdMetadataDocument.d.mts.map