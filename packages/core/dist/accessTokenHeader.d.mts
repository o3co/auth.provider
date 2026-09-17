import { BINDING_PROFILES } from "./grants/confirmationMatch.mjs";
/** An auth scheme that carries an access token, lowercased. */
export type AccessTokenScheme = "bearer" | (typeof BINDING_PROFILES)[keyof typeof BINDING_PROFILES]["scheme"];
export interface AccessTokenAuthorization {
    readonly scheme: AccessTokenScheme;
    readonly token: string;
}
/**
 * Split an `Authorization` header value into the (lowercased) access-token
 * scheme and the token it carries, or `null` when the header carries no
 * access token — absent, malformed, a different scheme (`Basic` client
 * authentication is the case that occurs), or a scheme with an empty
 * credential.
 *
 * The scheme is matched as a whole token, not as a prefix: `BearerToken
 * xyz` is a different scheme and returns `null`, where
 * `startsWith("Bearer ")` would have been fooled by `Bearer` + any suffix
 * only if it also matched the space — but the surrounding endpoints
 * previously used both `startsWith` and case-insensitive regexes, so
 * pinning one behaviour in one place removes the drift.
 *
 * Callers that only need the token use {@link parseAccessTokenHeader};
 * this variant exists for `protectedResourceBindingMw`, which must also
 * check the scheme against the binding the token's `cnf` names.
 */
export declare const parseAccessTokenAuthorization: (authorization: string | undefined) => AccessTokenAuthorization | null;
/**
 * Extract the access token from an `Authorization` header value, or `null`
 * when the header carries no access token. See
 * {@link parseAccessTokenAuthorization} for the exact parsing contract.
 */
export declare const parseAccessTokenHeader: (authorization: string | undefined) => string | null;
//# sourceMappingURL=accessTokenHeader.d.mts.map