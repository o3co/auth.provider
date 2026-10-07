import { type Logger, type PublicClient, type ReplaySeenSet } from "@o3co/auth-provider-core";
/**
 * `private_key_jwt` client authentication (RFC 7523 §2.2 / OIDC Core §9, #484).
 *
 * A confidential client proves it is who it says by signing a short-lived
 * JWT with its own private key; the provider verifies it under the public
 * keys the client registered (`jwks`) or publishes (`jwksUri`). Nothing
 * shared has to be distributed to the client's replicas or rotated
 * everywhere at once, and every assertion carries a `jti` that is spent
 * exactly once.
 *
 * This verifier is the whole of the trust decision — which client the
 * assertion names, whose keys it must verify under, what the claims must
 * say, and that the `jti` is fresh. The middleware around it only decides
 * how to answer, and that no second method rides along on the request.
 */
export declare const JWT_BEARER_CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/**
 * The JWS algorithms an assertion may be signed with: asymmetric only. A
 * shared secret is exactly what this method exists to avoid, and `none` is
 * never a signature.
 */
export declare const CLIENT_ASSERTION_ALGORITHMS: readonly ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"];
/**
 * How far ahead `exp` may be. RFC 7523 requires `exp` but bounds nothing;
 * client libraries mint assertions that live a minute or ten, and an hour
 * leaves room for a client whose clock runs ahead while keeping the
 * replay record — which lives until `exp` — small.
 */
export declare const MAX_CLIENT_ASSERTION_LIFETIME_SECONDS = 3600;
/** The replay-record scope is per client: `client-assertion:<client_id>`. */
export declare const CLIENT_ASSERTION_REPLAY_SCOPE_PREFIX = "client-assertion:";
export interface ClientAssertionVerifierOptions {
    /** The issuer identifier — accepted as `aud` (RFC 7523 §3). */
    readonly issuer?: string;
    /** The absolute token endpoint URL — also accepted as `aud`. */
    readonly tokenEndpoint?: string;
    /** Where `jti` values are spent. Absent → assertions are answered `server_error`. */
    readonly replaySeenSet?: ReplaySeenSet;
    readonly logger?: Logger;
    /** Clock tolerance on `exp` / `nbf` / `iat`, in seconds. Default 30. `iat` is also held to the lifetime ceiling. */
    readonly clockToleranceSeconds?: number;
    /** The fetch used for `jwksUri`. A proxy, or a test seam. */
    readonly fetch?: typeof fetch;
    /** Test seam. */
    readonly now?: () => number;
}
export type ClientAssertionOutcome = 
/** No `client_assertion` in the request — the other methods apply. */
{
    readonly kind: "absent";
} | {
    readonly kind: "refused";
    readonly status: 400 | 401 | 500 | 503;
    readonly error: "invalid_request" | "invalid_client" | "server_error" | "temporarily_unavailable";
    readonly description?: string;
} | {
    readonly kind: "ok";
    readonly client: PublicClient;
};
export interface ClientAssertionVerifier {
    verify(body: Record<string, unknown> | undefined, findClient: (clientId: string) => Promise<PublicClient | null>): Promise<ClientAssertionOutcome>;
}
/** Whether the request carries either half of a client assertion. */
export declare const hasClientAssertion: (body: Record<string, unknown> | undefined) => boolean;
export declare function createClientAssertionVerifier(options: ClientAssertionVerifierOptions): ClientAssertionVerifier;
//# sourceMappingURL=clientAssertion.d.mts.map