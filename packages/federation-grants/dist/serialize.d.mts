/**
 * Core's result union as HTTP (#593, D11).
 *
 * The route adds transport; this is the whole of what it decides about an
 * answer, which is why it is one exhaustive switch in one file. `code` is
 * never widened and `reason` is never turned into prose: within this package
 * `error_description` is a stable identifier a client may switch on, not a
 * sentence — prose is what clients end up parsing when nothing else is
 * offered, and then it can no longer be reworded.
 */
import type { FederationGrantReauthorizationResult, FederationGrantTokenResult } from "@o3co/auth-provider-core";
export interface SerializedFederationGrantResponse {
    readonly status: number;
    readonly body: Readonly<Record<string, unknown>>;
    /**
     * `Retry-After`, when the union said when to come back. Carried for 502
     * and 503 as well as 429: an ineligible upstream token and a lock that
     * timed out both know, and a client told only by the throttle retries the
     * others immediately and for ever.
     */
    readonly retryAfterSeconds?: number;
}
export declare function serializeFederationGrantTokenResult(result: FederationGrantTokenResult): SerializedFederationGrantResponse;
type LodgingRefusal = Exclude<FederationGrantReauthorizationResult, {
    ok: true;
}>;
/** Exhaustive: a new refusal is a compile error here, not a 500 in production. */
export declare function serializeFederationGrantLodgingRefusal(result: LodgingRefusal): SerializedFederationGrantResponse;
export {};
//# sourceMappingURL=serialize.d.mts.map