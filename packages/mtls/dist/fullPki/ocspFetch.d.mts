/**
 * Asking a responder: the DER request POSTed through the guarded fetch, which holds the deadline,
 * the size cap and the no-redirect rule. A fetch that fails is `fetch_failed`, and an outage when
 * the source failed (`isSourceFailure`).
 */
import { type GuardedFetch } from "./fetchGuard.mjs";
/** What asking a responder gave: the bytes it answered, or why there are none. */
export type OcspFetched = {
    readonly ok: true;
    readonly bytes: Uint8Array;
} | {
    readonly ok: false;
    readonly reason: "fetch_failed";
    readonly detail: string;
    readonly cause?: unknown;
    readonly outage?: true;
};
/** POST `der` to `url` through `options.fetch`, expecting an OCSP response back. */
export declare const fetchResponse: (options: {
    readonly fetch: GuardedFetch;
}, url: string, der: Uint8Array) => Promise<OcspFetched>;
//# sourceMappingURL=ocspFetch.d.mts.map