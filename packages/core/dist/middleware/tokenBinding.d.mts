import type { Request, RequestHandler } from "express";
import type { TokenBinding } from "../grants/tokenBinding.mjs";
import type { Logger } from "../logging/Logger.mjs";
import "./express.mjs";
/**
 * One concrete binding mechanism (DPoP, mTLS, etc.). See Wave 2
 * Token-binding Cluster spec §4.7.
 */
export interface TokenBindingMechanism {
    readonly kind: string;
    /**
     * `true` when the mechanism's intent signal is an explicit application-
     * layer construction (e.g. a DPoP proof header). `false` when the
     * signal can be an ambient transport artifact (e.g. an mTLS cert
     * injected by a reverse proxy regardless of client intent).
     */
    readonly intentExplicit: boolean;
    /**
     * Return a `TokenBinding` of this mechanism's kind, `null` when the
     * intent signal is absent, or throw a structured error when the signal
     * is present but the proof / cert is invalid. The thrown value MAY
     * carry a `code: string` field matching `/^[a-z][a-z0-9_]*$/` — that
     * code is forwarded as the OAuth `error` field of the 400 response.
     * Errors without a snake_case `code` fall back to
     * `invalid_<kind>_proof` so infrastructure-layer codes (e.g. Node
     * `ECONNREFUSED`) do not leak through the public error envelope.
     */
    extract(req: Request): Promise<TokenBinding | null>;
}
/**
 * How `tokenBindingMw` resolves a single `TokenBinding` when multiple
 * registered mechanisms succeed on the same request.
 *
 * `"intent-explicit"` (default): explicit-intent mechanisms (DPoP) win
 * over ambient-intent mechanisms (mTLS); ≥2 explicit mechanisms
 * succeeding → 400 `invalid_request`. See spec §3.5.
 *
 * `"strict-mutual-exclusion"`: any 2+ succeeding mechanisms → 400
 * `invalid_request`. Used by deployments that want a hard mutex.
 *
 * Closed union by design — the spec went through 8 rounds of review
 * (FCoT-verified, Codex-confirmed) and intentionally bounds dispatch to
 * these two strategies as the canonical resolution policies. Adding a
 * new strategy is a core semver-minor change. Downstream consumers who
 * need a different resolution rule today should compose a thin wrapper
 * around `tokenBindingMw` that observes `req.tokenBinding` post-dispatch.
 */
export type DispatchPolicy = "intent-explicit" | "strict-mutual-exclusion";
export interface TokenBindingMiddlewareOptions {
    readonly mechanisms: readonly TokenBindingMechanism[];
    readonly dispatchPolicy: DispatchPolicy;
    readonly logger?: Logger;
}
export declare const tokenBindingMw: ({ mechanisms, dispatchPolicy, logger, }: TokenBindingMiddlewareOptions) => RequestHandler;
//# sourceMappingURL=tokenBinding.d.mts.map