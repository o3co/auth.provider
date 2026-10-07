/** The `verifyJwt` options that bind a token to the client it names. */
export type OwnAccessTokenPins = {
    readonly expectedAudience: string;
    readonly expectedAzp: string;
} | {
    readonly expectedAudience: readonly [];
};
/**
 * The pins for an access token presented by the client it was issued to: its
 * `aud` must contain that client's id, and its `azp` must be that id.
 *
 * Nothing else on such a request names the client, so its id is read from the
 * token's own `azp` before verification. Core's verifier then checks both
 * pins against the signed payload, so the audience check runs and an `azp`
 * the signature does not cover never passes.
 *
 * An `azp` claim that is present but not a non-empty string names no client
 * the token can be bound to: it is pinned to an audience nothing matches, so
 * the verifier refuses it. `null` for a token with no `azp` claim, or one
 * that cannot be decoded: no client to pin to, which each route answers.
 */
export declare const ownAccessTokenPins: (token: string) => OwnAccessTokenPins | null;
//# sourceMappingURL=ownAccessToken.d.mts.map