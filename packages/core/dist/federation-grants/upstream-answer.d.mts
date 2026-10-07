import { type StoredAccessToken, type WrittenAccessToken } from "./held-token.mjs";
import type { FederationGrantIneligibilityReason } from "./types.mjs";
export interface FederationGrantUpstreamAnswerContext {
    /** Epoch ms: when the upstream was asked. A finite lifetime is dated from here. */
    readonly calledAt: number;
    /** Epoch ms: when its answer arrived. A token with no life left by then is refused. */
    readonly receivedAt: number;
    /** What an answer that names no scope carries: what the request asked for (RFC 6749 §5.1). */
    readonly requestedScopes: readonly string[];
    /** What the user consented to: a token that carries more is refused as `scope_exceeded`. */
    readonly consentedScopes: readonly string[];
    /** Seconds: the connection's current maximum. */
    readonly maxAccessTokenLifetime: number;
    /**
     * The access token the grant holds. An answer that carries the same value
     * never ends it later than it ends now: at `effectiveExpiresAt`, or without
     * one at `obtainedAt` + `issuedLifetime`. Ignored when its dates hold no instant.
     */
    readonly held?: Pick<StoredAccessToken, "value" | "obtainedAt" | "issuedLifetime" | "effectiveExpiresAt">;
}
export interface FederationGrantUpstreamAnswer {
    /** `undefined` when the answer carries none that is a non-empty string, or its read threw. */
    readonly refreshToken: string | undefined;
    readonly accessToken: {
        readonly eligible: true;
        readonly token: WrittenAccessToken;
    } | {
        readonly eligible: false;
        readonly reason: FederationGrantIneligibilityReason;
    };
}
/**
 * Reads an upstream token answer once, and judges its access token: eligible,
 * with the token to store, or refused with the ineligibility reason. The
 * refresh token is read whatever else is wrong with the answer.
 *
 * - `token_type` is required (RFC 6749 §5.1): an answer without one is malformed.
 * - The scope is read by RFC 6749 §3.3's grammar (`parseScopeTokens`). Absent
 *   or blank means `requestedScopes`; named but naming no scope-token is
 *   malformed. More than `consentedScopes` is `scope_exceeded`, judged before
 *   the token type.
 * - Only a lifetime both `expiresIn` and `expiresAt` state, with life left at
 *   `receivedAt`, is finite (`readUpstreamTokenLifetime`).
 * - The same access token as `held` ends no later than `held` does: a
 *   re-answer never lengthens a token's life.
 *
 * Throws a `RangeError` only for a clock that is not a finite instant.
 */
export declare function readFederationGrantUpstreamAnswer(answer: unknown, context: FederationGrantUpstreamAnswerContext): FederationGrantUpstreamAnswer;
//# sourceMappingURL=upstream-answer.d.mts.map