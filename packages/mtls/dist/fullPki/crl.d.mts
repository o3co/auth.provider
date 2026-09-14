import * as pkijs from "pkijs";
import type { GuardedFetch } from "./fetchGuard.mjs";
export type CrlUnavailableReason = "no_distribution_point" | "fetch_failed" | "unparseable" | "no_next_update" | "stale" | "bad_signature";
export type CrlLookup = {
    readonly ok: true;
    readonly crls: readonly pkijs.CertificateRevocationList[];
} | {
    readonly ok: false;
    readonly reason: CrlUnavailableReason;
    readonly detail: string;
};
/**
 * How long a distribution point that could not be used is remembered as
 * unavailable, in milliseconds.
 *
 * Not a configuration knob, deliberately. The window exists to absorb a
 * burst — a cache expiry or an outage must not turn into one fetch per
 * request, each waiting up to `fetch-timeout-ms` on the token endpoint's
 * critical path — not to remember the outage: a CA that comes back must be
 * noticed in seconds, not in the hours `cache-ttl-seconds` is measured in.
 */
export declare const CRL_NEGATIVE_CACHE_TTL_MS = 30000;
/**
 * Collect the HTTP(S) distribution-point URLs a certificate advertises.
 *
 * A `DistributionPoint` can also carry a `cRLIssuer` or name the CRL by a
 * relative name; both are ignored here. Anything not expressible as a
 * fetchable absolute URI produces no URL, which the caller sees as
 * `no_distribution_point` — an honest "cannot check" rather than a silent
 * pass.
 */
export declare const crlDistributionUrls: (certificate: pkijs.Certificate) => readonly string[];
export interface CrlResolverOptions {
    readonly fetch: GuardedFetch;
    /**
     * Upper bound on how long a CRL is reused, in seconds. The CRL's own
     * `nextUpdate` still wins when it is sooner — this only stops a CA that
     * publishes a year-long `nextUpdate` from pinning a stale answer in memory
     * for a year.
     */
    readonly cacheTtlSeconds: number;
    /** Bound on cache size, so a large trust set cannot grow it without limit. */
    readonly maxCacheEntries?: number;
}
export interface CrlResolver {
    /**
     * Fetch (or reuse) the CRLs covering `certificate`, verified against
     * `issuer` — the certificate that issued it, i.e. the next element up the
     * validated path. Only a CRL whose signature verifies against `issuer`'s
     * key is ever returned or cached. Concurrent calls for the same
     * distribution point share one fetch, and a distribution point that could
     * not be used is not retried within `CRL_NEGATIVE_CACHE_TTL_MS`.
     */
    resolve(certificate: pkijs.Certificate, issuer: pkijs.Certificate, now: Date): Promise<CrlLookup>;
    /** Entry count, usable and remembered-unavailable alike — for tests and for a future metric. */
    size(): number;
}
export declare const createCrlResolver: (options: CrlResolverOptions) => CrlResolver;
//# sourceMappingURL=crl.d.mts.map